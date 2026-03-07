use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{self, GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use rumqttc::{AsyncClient, EventLoop, MqttOptions, QoS, Event, Packet};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::crypto::PacketCipher;

const MAX_RETRIES: u32 = 10;

const BASE64_ENCODE: GeneralPurpose = general_purpose::STANDARD;
const BASE64_DECODE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Serializable wrapper for exchanging SDP + ICE candidates via copy-paste signaling.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignalMessage {
    pub sdp: String,
    pub sdp_type: String,
}

impl SignalMessage {
    pub fn from_sdp(sdp: &RTCSessionDescription) -> Self {
        Self {
            sdp: sdp.sdp.clone(),
            sdp_type: sdp.sdp_type.to_string(),
        }
    }

    /// Encode as compressed base64: JSON → deflate → base64.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_string(self)?;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(json.as_bytes())?;
        let compressed = encoder.finish()?;
        Ok(BASE64_ENCODE.encode(&compressed))
    }

    /// Decode from base64, trying compressed (deflate) first, then plain JSON
    /// for backward compatibility.
    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = BASE64_DECODE.decode(encoded.trim())?;

        if let Ok(msg) = Self::decode_compressed(&bytes) {
            return Ok(msg);
        }

        let json_str = String::from_utf8(bytes)?;
        let msg: SignalMessage = serde_json::from_str(&json_str)?;
        Ok(msg)
    }

    fn decode_compressed(bytes: &[u8]) -> Result<Self> {
        let mut decoder = DeflateDecoder::new(bytes);
        let mut json_str = String::new();
        decoder.read_to_string(&mut json_str)?;
        let msg: SignalMessage = serde_json::from_str(&json_str)?;
        Ok(msg)
    }

    pub fn to_rtc_session_description(&self) -> Result<RTCSessionDescription> {
        let desc = match self.sdp_type.as_str() {
            "offer" => RTCSessionDescription::offer(self.sdp.clone()),
            "answer" => RTCSessionDescription::answer(self.sdp.clone()),
            "pranswer" => RTCSessionDescription::pranswer(self.sdp.clone()),
            other => anyhow::bail!("Unknown SDP type: {}", other),
        };

        Ok(desc?)
    }
}

// ---------------------------------------------------------------------------
// MQTT-based automatic signaling
// ---------------------------------------------------------------------------

fn derive_room_id(shared_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(shared_key);
    hasher.update(b"qanah-signaling-room-v1");
    let hash = hasher.finalize();
    hash[..16].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_signal_server(server: &str) -> (&str, u16) {
    if let Some((host, port_str)) = server.rsplit_once(':') {
        if let Ok(port) = port_str.parse() {
            return (host, port);
        }
    }
    (server, 1883)
}

pub struct SignalingClient {
    client: AsyncClient,
    eventloop: EventLoop,
    room_id: String,
    cipher: PacketCipher,
}

impl SignalingClient {
    pub fn new(shared_key: &[u8; 32], broker_host: &str, broker_port: u16) -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let room_id = derive_room_id(shared_key);
        let client_id = format!(
            "qanah-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % 100_000
        );

        let mut opts = MqttOptions::new(&client_id, broker_host, broker_port);
        opts.set_keep_alive(Duration::from_secs(30));

        let (client, eventloop) = AsyncClient::new(opts, 10);
        let cipher = PacketCipher::new(shared_key);

        info!(
            broker = format!("{broker_host}:{broker_port}"),
            room = %room_id,
            "Connecting to signaling server"
        );

        Ok(Self { client, eventloop, room_id, cipher })
    }

    fn offer_topic(&self) -> String {
        format!("qanah/{}/offer", self.room_id)
    }

    fn answer_topic(&self) -> String {
        format!("qanah/{}/answer", self.room_id)
    }

    /// Poll the MQTT event loop until we get an incoming Publish on `topic`.
    /// Retries through transient connection errors (rumqttc reconnects automatically).
    async fn recv_on(&mut self, topic: &str) -> Result<Vec<u8>> {
        let mut retries = 0u32;
        loop {
            match self.eventloop.poll().await {
                Ok(event) => {
                    retries = 0;
                    if let Event::Incoming(Packet::Publish(p)) = event {
                        if p.topic == topic {
                            return Ok(p.payload.to_vec());
                        }
                    }
                }
                Err(e) => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        anyhow::bail!("Signaling connection failed after {MAX_RETRIES} retries: {e}");
                    }
                    warn!("Signaling connection error (retry {retries}/{MAX_RETRIES}): {e}");
                    tokio::time::sleep(Duration::from_secs(1.min(retries as u64))).await;
                }
            }
        }
    }

    /// Ensure at least one outgoing publish is acknowledged.
    async fn flush_pub(&mut self) -> Result<()> {
        let mut retries = 0u32;
        loop {
            match self.eventloop.poll().await {
                Ok(event) => {
                    retries = 0;
                    if let Event::Incoming(Packet::PubAck(_)) = event {
                        return Ok(());
                    }
                }
                Err(e) => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        anyhow::bail!("Signaling connection failed after {MAX_RETRIES} retries: {e}");
                    }
                    warn!("Signaling connection error (retry {retries}/{MAX_RETRIES}): {e}");
                    tokio::time::sleep(Duration::from_secs(1.min(retries as u64))).await;
                }
            }
        }
    }

    /// Offerer: publish the offer and wait for the answer.
    pub async fn offer(&mut self, offer_sdp: &str) -> Result<String> {
        let answer_topic = self.answer_topic();
        let offer_topic = self.offer_topic();

        self.client.subscribe(&answer_topic, QoS::AtLeastOnce).await
            .context("Failed to subscribe to answer topic")?;

        let encrypted = self.cipher.encrypt(offer_sdp.as_bytes())?;
        self.client.publish(&offer_topic, QoS::AtLeastOnce, true, encrypted).await
            .context("Failed to publish offer")?;

        info!("Offer published, waiting for peer answer...");

        let payload = self.recv_on(&answer_topic).await?;
        let decrypted = self.cipher.decrypt(&payload)?;
        let answer = String::from_utf8(decrypted)?;

        info!("Received answer via signaling server");
        Ok(answer)
    }

    /// Answerer: wait for the offer.
    pub async fn wait_offer(&mut self) -> Result<String> {
        let offer_topic = self.offer_topic();

        self.client.subscribe(&offer_topic, QoS::AtLeastOnce).await
            .context("Failed to subscribe to offer topic")?;

        info!("Waiting for peer offer...");

        let payload = self.recv_on(&offer_topic).await?;
        let decrypted = self.cipher.decrypt(&payload)?;
        let offer = String::from_utf8(decrypted)?;

        info!("Received offer via signaling server");
        Ok(offer)
    }

    /// Answerer: publish the answer (blocks until broker acknowledges).
    pub async fn answer(&mut self, answer_sdp: &str) -> Result<()> {
        let answer_topic = self.answer_topic();

        let encrypted = self.cipher.encrypt(answer_sdp.as_bytes())?;
        self.client.publish(&answer_topic, QoS::AtLeastOnce, true, encrypted).await
            .context("Failed to publish answer")?;

        self.flush_pub().await?;
        info!("Answer published via signaling server");
        Ok(())
    }

    /// Clear retained messages and disconnect (best-effort).
    pub async fn close(mut self) {
        let offer_topic = self.offer_topic();
        let answer_topic = self.answer_topic();

        let _ = self.client.publish(offer_topic, QoS::AtLeastOnce, true, Vec::<u8>::new()).await;
        let _ = self.client.publish(answer_topic, QoS::AtLeastOnce, true, Vec::<u8>::new()).await;

        // pump the event loop briefly to flush cleanup messages
        for _ in 0..10 {
            match tokio::time::timeout(Duration::from_millis(200), self.eventloop.poll()).await {
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }

        let _ = self.client.disconnect().await;
    }
}
