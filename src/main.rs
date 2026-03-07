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
use tracing::info;
use webrtc::data_channel::RTCDataChannel;

use config::WgConfig;
use crypto::{DerivedKeys, PacketCipher};
use peer::{TurnConfig, VpnPeer};
use signaling::SignalingClient;

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
    #[arg(long, default_value = "broker.hivemq.com:1883")]
    signal_server: String,

    /// Use manual copy-paste signaling instead of MQTT
    #[arg(long)]
    manual: bool,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Start as the offering peer (initiator)
    Offer,
    /// Start as the answering peer (responder)
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
    info!(
        addresses = %addresses_display.join(", "),
        peers = wg_config.peers.len(),
        "Loaded WireGuard config"
    );

    let turn_config = cli.turn_url.map(|url| {
        let tc = TurnConfig {
            url,
            username: cli.turn_username.unwrap_or_default(),
            credential: cli.turn_credential.unwrap_or_default(),
        };
        info!(url = %tc.url, username = %tc.username, "Using TURN server");
        tc
    });

    let peer_public_key = wg_config
        .peers
        .first()
        .map(|p| p.public_key.as_str())
        .ok_or_else(|| anyhow::anyhow!("No [Peer] section found — need peer PublicKey for encryption"))?;

    let shared_key = crypto::derive_shared_key(&wg_config.interface.private_key, peer_public_key)?;
    info!("Derived shared encryption key from PrivateKey + peer PublicKey (ChaCha20-Poly1305)");

    let stun_urls = if cli.stun_urls.is_empty() {
        None
    } else {
        Some(cli.stun_urls)
    };

    let vpn_peer = VpnPeer::new(stun_urls, turn_config).await?;

    let is_offerer = matches!(cli.mode, Mode::Offer);
    let keys = DerivedKeys::new(&shared_key, is_offerer);
    let encrypt_cipher = PacketCipher::new(&keys.tunnel_send);
    let decrypt_cipher = PacketCipher::new(&keys.tunnel_recv);

    if cli.manual {
        match cli.mode {
            Mode::Offer => run_offer_manual(vpn_peer, wg_config, encrypt_cipher, decrypt_cipher).await?,
            Mode::Answer => run_answer_manual(vpn_peer, wg_config, encrypt_cipher, decrypt_cipher).await?,
        }
    } else {
        let (host, port) = signaling::parse_signal_server(&cli.signal_server);
        let signaling = SignalingClient::new(&keys.signaling, host, port)?;
        match cli.mode {
            Mode::Offer => run_offer(vpn_peer, wg_config, encrypt_cipher, decrypt_cipher, signaling).await?,
            Mode::Answer => run_answer(vpn_peer, wg_config, encrypt_cipher, decrypt_cipher, signaling).await?,
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Automatic signaling (MQTT)
// ---------------------------------------------------------------------------

async fn run_offer(
    vpn_peer: VpnPeer,
    wg_config: WgConfig,
    encrypt_cipher: PacketCipher,
    decrypt_cipher: PacketCipher,
    mut signaling: SignalingClient,
) -> Result<()> {
    let (data_channel, offer_encoded) = vpn_peer.create_offer().await?;

    let answer_encoded = signaling.offer(&offer_encoded).await?;
    signaling.close().await;

    vpn_peer.apply_answer(&answer_encoded).await?;
    info!("Answer applied, waiting for connection...");

    start_tunnel(data_channel, vpn_peer, wg_config, encrypt_cipher, decrypt_cipher).await
}

async fn run_answer(
    vpn_peer: VpnPeer,
    wg_config: WgConfig,
    encrypt_cipher: PacketCipher,
    decrypt_cipher: PacketCipher,
    mut signaling: SignalingClient,
) -> Result<()> {
    let offer_encoded = signaling.wait_offer().await?;

    let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<Arc<RTCDataChannel>>(1);

    vpn_peer.peer_connection.on_data_channel(Box::new(
        move |dc: Arc<RTCDataChannel>| {
            let dc_tx = dc_tx.clone();
            Box::pin(async move {
                info!(label = %dc.label(), "Received data channel");
                let _ = dc_tx.send(dc).await;
            })
        },
    ));

    let answer_encoded = vpn_peer.accept_offer(&offer_encoded).await?;
    signaling.answer(&answer_encoded).await?;
    signaling.close().await;

    info!("Waiting for data channel from offering peer...");

    let data_channel = dc_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("Data channel was not received"))?;

    start_tunnel(data_channel, vpn_peer, wg_config, encrypt_cipher, decrypt_cipher).await
}

// ---------------------------------------------------------------------------
// Manual copy-paste signaling (--manual)
// ---------------------------------------------------------------------------

async fn run_offer_manual(
    vpn_peer: VpnPeer,
    wg_config: WgConfig,
    encrypt_cipher: PacketCipher,
    decrypt_cipher: PacketCipher,
) -> Result<()> {
    let (data_channel, offer_encoded) = vpn_peer.create_offer().await?;

    println!("\n===== OFFER (copy and send to peer) =====");
    println!("{offer_encoded}");
    println!("===== END OFFER =====\n");

    let answer_encoded = read_signal("Paste the ANSWER from the remote peer: ")?;
    vpn_peer.apply_answer(&answer_encoded).await?;

    info!("Answer applied, waiting for connection...");

    start_tunnel(data_channel, vpn_peer, wg_config, encrypt_cipher, decrypt_cipher).await
}

async fn run_answer_manual(
    vpn_peer: VpnPeer,
    wg_config: WgConfig,
    encrypt_cipher: PacketCipher,
    decrypt_cipher: PacketCipher,
) -> Result<()> {
    let offer_encoded = read_signal("Paste the OFFER from the remote peer: ")?;

    let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<Arc<RTCDataChannel>>(1);

    vpn_peer.peer_connection.on_data_channel(Box::new(
        move |dc: Arc<RTCDataChannel>| {
            let dc_tx = dc_tx.clone();
            Box::pin(async move {
                info!(label = %dc.label(), "Received data channel");
                let _ = dc_tx.send(dc).await;
            })
        },
    ));

    let answer_encoded = vpn_peer.accept_offer(&offer_encoded).await?;

    println!("\n===== ANSWER (copy and send to peer) =====");
    println!("{answer_encoded}");
    println!("===== END ANSWER =====\n");

    info!("Waiting for data channel from offering peer...");

    let data_channel = dc_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("Data channel was not received"))?;

    start_tunnel(data_channel, vpn_peer, wg_config, encrypt_cipher, decrypt_cipher).await
}

// ---------------------------------------------------------------------------
// Tunnel setup (shared by both modes)
// ---------------------------------------------------------------------------

async fn start_tunnel(
    data_channel: Arc<RTCDataChannel>,
    vpn_peer: VpnPeer,
    wg_config: WgConfig,
    encrypt_cipher: PacketCipher,
    decrypt_cipher: PacketCipher,
) -> Result<()> {
    let dc_open = VpnPeer::setup_data_channel_handler(&data_channel, vpn_peer.packet_tx.clone());

    info!("Creating TUN device...");
    let tun_dev = tunnel::create_tun_device(&wg_config)?;
    let (tun_writer, tun_reader) = tun_dev
        .split()
        .map_err(|e| anyhow::anyhow!("Failed to split TUN device: {e}"))?;

    info!("VPN tunnel active (encrypted with ChaCha20-Poly1305). Press Ctrl+C to stop.");

    let dc = data_channel.clone();
    let tun_to_dc = tokio::spawn(async move {
        tunnel::tun_to_webrtc(tun_reader, dc, encrypt_cipher, dc_open).await;
    });

    let dc_to_tun = tokio::spawn(async move {
        tunnel::webrtc_to_tun(tun_writer, vpn_peer.packet_rx, decrypt_cipher).await;
    });

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    tun_to_dc.abort();
    dc_to_tun.abort();

    data_channel.close().await?;
    vpn_peer.peer_connection.close().await?;

    Ok(())
}

/// Reads a base64-encoded signal message from stdin using non-canonical
/// (raw) terminal mode to bypass the Linux N_TTY 4096-byte buffer limit
/// that silently discards characters on long pastes.
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
