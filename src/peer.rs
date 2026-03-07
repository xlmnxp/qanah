use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{mpsc, Notify};
use tracing::{error, info, warn};
use webrtc::data_channel::RTCDataChannel;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
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
    /// Notified when the peer connection enters Disconnected, Failed, or Closed state.
    pub disconnected: Arc<Notify>,
}

impl VpnPeer {
    /// Create a new VPN peer. `peer_label` is used in log messages (e.g. "Peer 2 (abc12345…)").
    pub async fn new(
        stun_urls: Option<Vec<String>>,
        turn: Option<&TurnConfig>,
        peer_label: Option<Arc<str>>,
    ) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let stun_list = stun_urls.unwrap_or_else(|| {
            vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ]
        });

        let mut ice_servers: Vec<RTCIceServer> = stun_list
            .into_iter()
            .map(|url| RTCIceServer {
                urls: vec![url],
                ..Default::default()
            })
            .collect();

        if let Some(turn) = turn {
            ice_servers.push(RTCIceServer {
                urls: vec![turn.url.clone()],
                username: turn.username.clone(),
                credential: turn.credential.clone(),
                ..Default::default()
            });
        }

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        let disconnected = Arc::new(Notify::new());
        let disconnect_notify = disconnected.clone();
        let label = peer_label.clone();

        peer_connection.on_peer_connection_state_change(Box::new(
            move |state: RTCPeerConnectionState| {
                let peer = label.as_deref().unwrap_or("(unknown peer)");
                match state {
                    RTCPeerConnectionState::Connected => {
                        info!(peer = %peer, "WebRTC connection established");
                    }
                    RTCPeerConnectionState::Disconnected => {
                        warn!(peer = %peer, "WebRTC disconnected (may reconnect)");
                        disconnect_notify.notify_one();
                    }
                    RTCPeerConnectionState::Failed => {
                        error!(peer = %peer, "WebRTC connection failed");
                        disconnect_notify.notify_one();
                    }
                    RTCPeerConnectionState::Closed => {
                        info!(peer = %peer, "WebRTC connection closed");
                        disconnect_notify.notify_one();
                    }
                    RTCPeerConnectionState::Connecting => {
                        info!(peer = %peer, "WebRTC connecting...");
                    }
                    other => {
                        tracing::debug!(peer = %peer, state = ?other, "Peer connection state");
                    }
                }
                Box::pin(async {})
            },
        ));

        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(1024);

        Ok(Self {
            peer_connection,
            packet_tx,
            packet_rx,
            disconnected,
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
    /// Returns a `Notify` that is triggered when the data channel opens.
    /// `peer_label` is used in log messages (e.g. "Peer 2 (abc12345…)").
    pub fn setup_data_channel_handler(
        data_channel: &Arc<RTCDataChannel>,
        tx: mpsc::Sender<Vec<u8>>,
        peer_label: Option<Arc<str>>,
    ) -> Arc<Notify> {
        let open_notify = Arc::new(Notify::new());

        let tx = tx.clone();
        data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = tx.clone();
            Box::pin(async move {
                if let Err(e) = tx.send(msg.data.to_vec()).await {
                    warn!("Data channel packet forward failed: {e}");
                }
            })
        }));

        let notify = open_notify.clone();
        let label_open = peer_label.clone();
        data_channel.on_open(Box::new(move || {
            let peer = label_open.as_deref().unwrap_or("(unknown peer)");
            info!(peer = %peer, "Tunnel data channel ready — traffic can flow");
            notify.notify_one();
            Box::pin(async {})
        }));

        let label_close = peer_label.clone();
        data_channel.on_close(Box::new(move || {
            let peer = label_close.as_deref().unwrap_or("(unknown peer)");
            info!(peer = %peer, "Tunnel data channel closed");
            Box::pin(async {})
        }));

        open_notify
    }
}
