use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::RTCPeerConnection;

use crate::signaling::SignalMessage;

pub struct TurnConfig {
    pub url: String,
    pub username: String,
    pub credential: String,
}

pub struct VpnPeer {
    pub peer_connection: Arc<RTCPeerConnection>,
    pub packet_tx: mpsc::Sender<Vec<u8>>,
    pub packet_rx: mpsc::Receiver<Vec<u8>>,
}

impl VpnPeer {
    pub async fn new(turn: Option<TurnConfig>) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let mut ice_servers = vec![
            RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_string()],
                ..Default::default()
            },
            RTCIceServer {
                urls: vec!["stun:stun1.l.google.com:19302".to_string()],
                ..Default::default()
            },
        ];

        if let Some(turn) = turn {
            ice_servers.push(RTCIceServer {
                urls: vec![turn.url],
                username: turn.username,
                credential: turn.credential,
                ..Default::default()
            });
        }

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        peer_connection.on_peer_connection_state_change(Box::new(
            move |state: RTCPeerConnectionState| {
                match state {
                    RTCPeerConnectionState::Connected => info!("Peer connected!"),
                    RTCPeerConnectionState::Disconnected => warn!("Peer disconnected"),
                    RTCPeerConnectionState::Failed => error!("Peer connection failed"),
                    RTCPeerConnectionState::Closed => info!("Peer connection closed"),
                    _ => info!("Peer connection state: {state}"),
                }
                Box::pin(async {})
            },
        ));

        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(1024);

        Ok(Self {
            peer_connection,
            packet_tx,
            packet_rx,
        })
    }

    /// Create an offer (initiator/server side).
    /// Returns the data channel and the base64-encoded offer to share with the peer.
    pub async fn create_offer(&self) -> Result<(Arc<RTCDataChannel>, String)> {
        let data_channel = self
            .peer_connection
            .create_data_channel("vpn-tunnel", None)
            .await?;

        let offer = self.peer_connection.create_offer(None).await?;
        let mut gather_complete = self.peer_connection.gathering_complete_promise().await;
        self.peer_connection.set_local_description(offer).await?;
        let _ = gather_complete.recv().await;

        let local_desc = self
            .peer_connection
            .local_description()
            .await
            .ok_or_else(|| anyhow::anyhow!("No local description after gathering"))?;

        let signal = SignalMessage::from_sdp(&local_desc);
        let encoded = signal.encode()?;

        Ok((data_channel, encoded))
    }

    /// Accept an offer from a remote peer, create an answer.
    /// Returns the data channel receiver and the base64-encoded answer.
    pub async fn accept_offer(&self, offer_encoded: &str) -> Result<String> {
        let signal = SignalMessage::decode(offer_encoded)?;
        let remote_desc = signal.to_rtc_session_description()?;
        self.peer_connection
            .set_remote_description(remote_desc)
            .await?;

        let answer = self.peer_connection.create_answer(None).await?;
        let mut gather_complete = self.peer_connection.gathering_complete_promise().await;
        self.peer_connection.set_local_description(answer).await?;
        let _ = gather_complete.recv().await;

        let local_desc = self
            .peer_connection
            .local_description()
            .await
            .ok_or_else(|| anyhow::anyhow!("No local description after gathering"))?;

        let signal = SignalMessage::from_sdp(&local_desc);
        let encoded = signal.encode()?;

        Ok(encoded)
    }

    /// Apply a received answer (initiator side).
    pub async fn apply_answer(&self, answer_encoded: &str) -> Result<()> {
        let signal = SignalMessage::decode(answer_encoded)?;
        let remote_desc = signal.to_rtc_session_description()?;
        self.peer_connection
            .set_remote_description(remote_desc)
            .await?;
        Ok(())
    }

    /// Set up the data channel to forward received packets into packet_tx.
    pub fn setup_data_channel_handler(
        data_channel: &Arc<RTCDataChannel>,
        tx: mpsc::Sender<Vec<u8>>,
    ) {
        let tx = tx.clone();
        data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = tx.clone();
            Box::pin(async move {
                if let Err(e) = tx.send(msg.data.to_vec()).await {
                    warn!("Failed to forward packet from data channel: {e}");
                }
            })
        }));

        data_channel.on_open(Box::new(|| {
            info!("Data channel opened - VPN tunnel is active");
            Box::pin(async {})
        }));

        data_channel.on_close(Box::new(|| {
            info!("Data channel closed");
            Box::pin(async {})
        }));
    }
}
