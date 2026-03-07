mod config;
mod crypto;
mod peer;
mod signaling;
mod tunnel;

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::io::split;
use tracing::info;
use webrtc::data_channel::RTCDataChannel;

use config::WgConfig;
use crypto::PacketCipher;
use peer::{TurnConfig, VpnPeer};

#[derive(Parser)]
#[command(name = "qanah")]
#[command(about = "A WebRTC-based VPN with WebAssembly support — tunnel anywhere")]
struct Cli {
    /// Path to WireGuard config file
    #[arg(short, long)]
    config: PathBuf,

    /// TURN server URL (e.g. turn:turn.example.com:3478)
    #[arg(long)]
    turn_url: Option<String>,

    /// TURN server username
    #[arg(long, requires = "turn_url")]
    turn_username: Option<String>,

    /// TURN server credential
    #[arg(long, requires = "turn_url")]
    turn_credential: Option<String>,

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
    let cipher = PacketCipher::new(&shared_key);
    info!("Derived shared encryption key from PrivateKey + peer PublicKey (ChaCha20-Poly1305)");

    let vpn_peer = VpnPeer::new(turn_config).await?;

    match cli.mode {
        Mode::Offer => run_offer(vpn_peer, wg_config, cipher).await?,
        Mode::Answer => run_answer(vpn_peer, wg_config, cipher).await?,
    }

    Ok(())
}

async fn run_offer(vpn_peer: VpnPeer, wg_config: WgConfig, cipher: PacketCipher) -> Result<()> {
    let (data_channel, offer_encoded) = vpn_peer.create_offer().await?;

    println!("\n===== OFFER (copy and send to peer) =====");
    println!("{offer_encoded}");
    println!("===== END OFFER =====\n");

    let answer_encoded = prompt("Paste the ANSWER from the remote peer: ")?;
    vpn_peer.apply_answer(&answer_encoded).await?;

    info!("Answer applied, waiting for connection...");

    start_tunnel(data_channel, vpn_peer, wg_config, cipher).await
}

async fn run_answer(vpn_peer: VpnPeer, wg_config: WgConfig, cipher: PacketCipher) -> Result<()> {
    let offer_encoded = prompt("Paste the OFFER from the remote peer: ")?;

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

    start_tunnel(data_channel, vpn_peer, wg_config, cipher).await
}

async fn start_tunnel(
    data_channel: Arc<RTCDataChannel>,
    vpn_peer: VpnPeer,
    wg_config: WgConfig,
    cipher: PacketCipher,
) -> Result<()> {
    VpnPeer::setup_data_channel_handler(&data_channel, vpn_peer.packet_tx.clone());

    info!("Creating TUN device...");
    let tun_dev = tunnel::create_tun_device(&wg_config)?;
    let (tun_reader, tun_writer) = split(tun_dev);

    info!("VPN tunnel active (encrypted with ChaCha20-Poly1305). Press Ctrl+C to stop.");

    let dc = data_channel.clone();
    let encrypt_cipher = cipher.clone();
    let tun_to_dc = tokio::spawn(async move {
        tunnel::tun_to_webrtc(tun_reader, dc, encrypt_cipher).await;
    });

    let decrypt_cipher = cipher;
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

fn prompt(msg: &str) -> Result<String> {
    print!("{msg}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
