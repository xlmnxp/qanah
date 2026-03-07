mod config;
mod crypto;
mod peer;
mod signaling;
mod tunnel;

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use webrtc::data_channel::RTCDataChannel;

use config::WgConfig;
use crypto::{DerivedKeys, PacketCipher};
use peer::{TurnConfig, VpnPeer};
use signaling::SignalingClient;
use tunnel::{PeerRoute, RoutingTable};

#[derive(Parser)]
#[command(name = "qanah")]
#[command(about = "A WebRTC-based VPN with WebAssembly support — tunnel anywhere")]
struct Cli {
    /// Path to WireGuard config file
    #[arg(short, long)]
    config: PathBuf,

    /// STUN server URLs (can be specified multiple times; defaults to Google STUN servers)
    #[arg(long = "stun")]
    stun_urls: Vec<String>,

    /// TURN server URL (e.g. turn:turn.example.com:3478)
    #[arg(long)]
    turn_url: Option<String>,

    /// TURN server username
    #[arg(long, requires = "turn_url")]
    turn_username: Option<String>,

    /// TURN server credential
    #[arg(long, requires = "turn_url")]
    turn_credential: Option<String>,

    /// MQTT signaling server (host:port) for automatic SDP exchange
    #[arg(long, default_value = "broker.emqx.io:1883")]
    signal_server: String,

    /// Disable relaying: only send to directly connected peers; packets with no direct route are dropped
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_relay: bool,

    #[command(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Start as the offering peer (initiator) — for manual signaling
    Offer,
    /// Start as the answering peer (responder) — for manual signaling
    Answer,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("qanah=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let wg_config = WgConfig::from_file(&cli.config)?;

    let addresses_display: Vec<String> = wg_config
        .interface
        .addresses
        .iter()
        .map(|a| a.to_string())
        .collect();
    let config_path = cli.config.display().to_string();
    info!(
        config = %config_path,
        addresses = %addresses_display.join(", "),
        peer_count = wg_config.peers.len(),
        "Loaded config — starting VPN"
    );

    if wg_config.peers.is_empty() {
        anyhow::bail!("No [Peer] sections found in config");
    }

    let turn_config: Option<Arc<TurnConfig>> = cli.turn_url.map(|url| {
        let tc = TurnConfig {
            url,
            username: cli.turn_username.unwrap_or_default(),
            credential: cli.turn_credential.unwrap_or_default(),
        };
        info!(url = %tc.url, username = %tc.username, "Using TURN server");
        Arc::new(tc)
    });

    let stun_urls: Option<Arc<Vec<String>>> = if cli.stun_urls.is_empty() {
        None
    } else {
        Some(Arc::new(cli.stun_urls))
    };

    let our_public_key = crypto::derive_public_key(&wg_config.interface.private_key)?;

    // Create TUN device immediately
    info!("Creating TUN device and setting up routing...");
    let tun_dev = tunnel::create_tun_device(&wg_config)?;
    let (tun_writer, tun_reader) = tun_dev
        .split()
        .map_err(|e| anyhow::anyhow!("Failed to split TUN device: {e}"))?;

    let tun_writer = Arc::new(Mutex::new(tun_writer));
    let routing_table = Arc::new(RoutingTable::new());

    // Start TUN reader immediately — packets to peers not yet connected are dropped
    let rt = routing_table.clone();
    let send_task = tokio::spawn(async move {
        tunnel::tun_to_peers(tun_reader, rt).await;
    });

    info!(
        "VPN tunnel is up (ChaCha20-Poly1305). Connecting to {} peer(s). Press Ctrl+C to stop.",
        wg_config.peers.len()
    );

    let private_key = wg_config.interface.private_key.clone();
    let signal_server = cli.signal_server.clone();
    let manual_mode = cli.mode;

    let no_relay = cli.no_relay;

    // Spawn each peer connection concurrently
    for (i, peer_config) in wg_config.peers.iter().enumerate() {
        let peer_idx = i + 1;
        let private_key = private_key.clone();
        let peer_public_key = peer_config.public_key.clone();
        let allowed_ips = peer_config.allowed_ips.clone();
        let stun_urls = stun_urls.clone();
        let turn_config = turn_config.clone();
        let signal_server = signal_server.clone();
        let routing_table = routing_table.clone();
        let tun_writer = tun_writer.clone();
        let our_public_key = our_public_key;

        tokio::spawn(async move {
            peer_connection_loop(
                peer_idx,
                private_key,
                peer_public_key,
                our_public_key,
                allowed_ips,
                manual_mode,
                signal_server,
                stun_urls,
                turn_config,
                routing_table,
                tun_writer,
                no_relay,
            )
            .await;
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("Shutting down — closing tunnel and disconnecting peers...");
    send_task.abort();

    Ok(())
}

/// Reconnect loop: keeps trying to connect to a peer, removes from routing
/// on disconnect, waits, and retries.
async fn peer_connection_loop(
    peer_idx: usize,
    private_key: String,
    peer_public_key: String,
    our_public_key: [u8; 32],
    allowed_ips: Vec<config::CidrAddress>,
    manual_mode: Option<Mode>,
    signal_server: String,
    stun_urls: Option<Arc<Vec<String>>>,
    turn_config: Option<Arc<TurnConfig>>,
    routing_table: Arc<RoutingTable>,
    tun_writer: Arc<Mutex<tun::DeviceWriter>>,
    no_relay: bool,
) {
    const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
    let mut first_attempt = true;

    loop {
        if !first_attempt {
            let key_preview = peer_public_key.chars().take(8).collect::<String>();
            info!(
                peer = peer_idx,
                public_key = %format!("{}…", key_preview),
                delay_secs = RECONNECT_DELAY.as_secs(),
                "Peer disconnected — reconnecting"
            );
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
        first_attempt = false;

        match connect_peer(
            peer_idx,
            &private_key,
            &peer_public_key,
            our_public_key,
            allowed_ips.clone(),
            manual_mode,
            &signal_server,
            stun_urls.as_deref().cloned(),
            turn_config.as_deref(),
            routing_table.clone(),
            tun_writer.clone(),
            no_relay,
        )
        .await
        {
            Ok(()) => {
                let key_preview = peer_public_key.chars().take(8).collect::<String>();
                warn!(
                    peer = peer_idx,
                    public_key = %format!("{}…", key_preview),
                    "Peer disconnected — will retry"
                );
            }
            Err(e) => {
                let key_preview = peer_public_key.chars().take(8).collect::<String>();
                error!(
                    peer = peer_idx,
                    public_key = %format!("{}…", key_preview),
                    error = %e,
                    "Peer connection failed"
                );
            }
        }

        // Ensure the peer is removed from routing on any exit
        routing_table.remove_peer(&peer_public_key).await;
    }
}

/// Determine whether we are the offerer for a given peer pair.
/// The peer with the lexicographically greater public key always offers.
/// This ensures both sides independently agree on roles.
fn is_offerer_for_peer(our_public_key: &[u8; 32], peer_public_key_b64: &str) -> Result<bool> {
    use base64::Engine;
    let peer_pub_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(peer_public_key_b64.trim())
        .map_err(|e| anyhow::anyhow!("Invalid base64 in peer PublicKey: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("PublicKey must be 32 bytes, got {}", v.len()))?;

    Ok(our_public_key > &peer_pub_bytes)
}

/// Set up a single peer connection: signaling, WebRTC, register in routing table,
/// then wait until the peer disconnects.
async fn connect_peer(
    peer_idx: usize,
    private_key: &str,
    peer_public_key: &str,
    our_public_key: [u8; 32],
    allowed_ips: Vec<config::CidrAddress>,
    manual_mode: Option<Mode>,
    signal_server: &str,
    stun_urls: Option<Vec<String>>,
    turn_config: Option<&TurnConfig>,
    routing_table: Arc<RoutingTable>,
    tun_writer: Arc<Mutex<tun::DeviceWriter>>,
    no_relay: bool,
) -> Result<()> {
    let is_offerer = match manual_mode {
        Some(Mode::Offer) => true,
        Some(Mode::Answer) => false,
        None => is_offerer_for_peer(&our_public_key, peer_public_key)?,
    };

    let key_preview = peer_public_key.chars().take(8).collect::<String>();
    let peer_label: Arc<str> = Arc::from(format!("Peer {} ({}…)", peer_idx, key_preview));
    let role = if is_offerer { "offerer" } else { "answerer" };
    info!(
        peer = %peer_label,
        role = role,
        "Initiating connection"
    );

    let shared_key = crypto::derive_shared_key(private_key, peer_public_key)?;
    let keys = DerivedKeys::new(&shared_key, is_offerer);
    let encrypt_cipher = PacketCipher::new(&keys.tunnel_send);
    let decrypt_cipher = PacketCipher::new(&keys.tunnel_recv);

    let vpn_peer = VpnPeer::new(stun_urls, turn_config, Some(peer_label.clone())).await?;

    let data_channel = match manual_mode {
        Some(_) => connect_manual(peer_idx, &vpn_peer, is_offerer).await?,
        None => {
            let (host, port) = signaling::parse_signal_server(signal_server);
            let sig = SignalingClient::new(&keys.signaling, host, port)?;
            connect_auto(peer_idx, &vpn_peer, is_offerer, sig).await?
        }
    };

    // Wait for data channel to open, then register in routing table
    let dc_open = VpnPeer::setup_data_channel_handler(
        &data_channel,
        vpn_peer.packet_tx.clone(),
        Some(peer_label.clone()),
    );
    dc_open.notified().await;

    routing_table
        .add_peer(PeerRoute {
            peer_key: peer_public_key.to_string(),
            allowed_ips,
            can_relay: !no_relay,
            data_channel: data_channel.clone(),
            encrypt_cipher,
        })
        .await;

    let disconnected = vpn_peer.disconnected.clone();
    let routing_table_recv = routing_table.clone();

    // Run the receive loop (peer → TUN) until the peer disconnects
    let recv_task = tokio::spawn(async move {
        tunnel::peer_to_tun(tun_writer, vpn_peer.packet_rx, decrypt_cipher, routing_table_recv).await;
    });

    // Wait for the WebRTC connection to drop
    disconnected.notified().await;

    recv_task.abort();
    let _ = data_channel.close().await;

    Ok(())
}

async fn connect_auto(
    peer_idx: usize,
    vpn_peer: &VpnPeer,
    is_offerer: bool,
    mut sig: SignalingClient,
) -> Result<Arc<RTCDataChannel>> {
    if is_offerer {
        let (dc, offer_encoded) = vpn_peer.create_offer().await?;
        let answer_encoded = sig.offer(&offer_encoded).await?;
        sig.close().await;
        vpn_peer.apply_answer(&answer_encoded).await?;
        info!("Signaling complete — answer applied");
        Ok(dc)
    } else {
        let offer_encoded = sig.wait_offer().await?;

        let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<Arc<RTCDataChannel>>(1);
        vpn_peer.peer_connection.on_data_channel(Box::new(
            move |dc: Arc<RTCDataChannel>| {
                let dc_tx = dc_tx.clone();
                Box::pin(async move {
                    let _ = dc_tx.send(dc).await;
                })
            },
        ));

        let answer_encoded = vpn_peer.accept_offer(&offer_encoded).await?;
        sig.answer(&answer_encoded).await?;
        sig.close().await;

        info!("Signaling complete — waiting for data channel from peer");
        dc_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Data channel not received for peer {peer_idx}"))
    }
}

async fn connect_manual(
    peer_idx: usize,
    vpn_peer: &VpnPeer,
    is_offerer: bool,
) -> Result<Arc<RTCDataChannel>> {
    if is_offerer {
        let (dc, offer_encoded) = vpn_peer.create_offer().await?;

        println!("\n===== OFFER for peer {peer_idx} (copy and send to peer) =====");
        println!("{offer_encoded}");
        println!("===== END OFFER =====\n");

        let answer_encoded = read_signal(&format!("Paste the ANSWER from peer {peer_idx}: "))?;
        vpn_peer.apply_answer(&answer_encoded).await?;
        info!("Manual signaling complete — answer applied");
        Ok(dc)
    } else {
        let offer_encoded = read_signal(&format!("Paste the OFFER from peer {peer_idx}: "))?;

        let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<Arc<RTCDataChannel>>(1);
        vpn_peer.peer_connection.on_data_channel(Box::new(
            move |dc: Arc<RTCDataChannel>| {
                let dc_tx = dc_tx.clone();
                Box::pin(async move {
                    let _ = dc_tx.send(dc).await;
                })
            },
        ));

        let answer_encoded = vpn_peer.accept_offer(&offer_encoded).await?;

        println!("\n===== ANSWER for peer {peer_idx} (copy and send to peer) =====");
        println!("{answer_encoded}");
        println!("===== END ANSWER =====\n");

        info!("Waiting for data channel from peer");
        dc_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Data channel not received for peer {peer_idx}"))
    }
}

/// Reads a base64-encoded signal message from stdin using non-canonical
/// (raw) terminal mode to bypass the Linux N_TTY 4096-byte buffer limit.
fn read_signal(msg: &str) -> Result<String> {
    print!("{msg}");
    io::stdout().flush()?;

    let fd = io::stdin().as_raw_fd();
    let mut original_termios: libc::termios = unsafe { std::mem::zeroed() };
    let is_tty = unsafe { libc::tcgetattr(fd, &mut original_termios) } == 0;

    if is_tty {
        let mut raw = original_termios;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) };
    }

    let result = read_until_newline();

    if is_tty {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original_termios) };
        eprintln!();
    }

    result
}

fn read_until_newline() -> Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let mut stdin = io::stdin().lock();

    loop {
        match stdin.read(&mut byte)? {
            0 => break,
            _ => {
                if byte[0] == b'\n' || byte[0] == b'\r' {
                    break;
                }
                buf.push(byte[0]);
            }
        }
    }

    Ok(String::from_utf8(buf)?.trim().to_string())
}
