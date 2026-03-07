use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use webrtc::data_channel::RTCDataChannel;

use crate::config::WgConfig;
use crate::crypto::PacketCipher;

/// Create and configure a TUN device based on the WireGuard config.
/// Supports IPv4, IPv6, and dual-stack addresses.
pub fn create_tun_device(config: &WgConfig) -> Result<tun::AsyncDevice> {
    let mtu = config.interface.mtu.unwrap_or(1400);

    let ipv4_addrs: Vec<_> = config
        .interface
        .addresses
        .iter()
        .filter(|a| a.is_ipv4())
        .collect();
    let ipv6_addrs: Vec<_> = config
        .interface
        .addresses
        .iter()
        .filter(|a| a.is_ipv6())
        .collect();

    let mut tun_config = tun::Configuration::default();
    tun_config.mtu(mtu as u16).up();

    if let Some(v4) = ipv4_addrs.first() {
        match v4.addr {
            IpAddr::V4(ipv4) => {
                let netmask = prefix_to_netmask(v4.prefix);
                tun_config.address(ipv4).netmask(netmask);
            }
            _ => unreachable!(),
        }
    }

    let device = tun::create(&tun_config).context("Failed to create TUN device")?;

    let dev_name = {
        use tun::AbstractDevice;
        device.tun_name().context("Failed to get TUN device name")?
    };

    info!(device = %dev_name, mtu = mtu, "TUN device created");

    // Add any additional IPv4 addresses beyond the first
    for v4 in ipv4_addrs.iter().skip(1) {
        add_address_via_ip(&dev_name, v4.addr, v4.prefix)?;
    }

    // Add all IPv6 addresses via `ip` (the tun crate only supports IPv4 natively)
    for v6 in &ipv6_addrs {
        add_address_via_ip(&dev_name, v6.addr, v6.prefix)?;
    }

    for addr in &config.interface.addresses {
        info!(address = %addr, "Configured address on {}", dev_name);
    }

    let async_device =
        tun::AsyncDevice::new(device).context("Failed to create async TUN device")?;

    Ok(async_device)
}

fn prefix_to_netmask(prefix: u8) -> std::net::Ipv4Addr {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    std::net::Ipv4Addr::from(mask)
}

/// Add an IP address to a network device using the `ip` command.
fn add_address_via_ip(dev_name: &str, addr: IpAddr, prefix: u8) -> Result<()> {
    let family = if addr.is_ipv6() { "-6" } else { "-4" };
    let cidr = format!("{addr}/{prefix}");

    let output = std::process::Command::new("ip")
        .args([family, "addr", "add", &cidr, "dev", dev_name])
        .output()
        .with_context(|| format!("Failed to run `ip {family} addr add {cidr} dev {dev_name}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "RTNETLINK answers: File exists" means the address is already assigned
        if stderr.contains("File exists") {
            info!(address = %cidr, device = %dev_name, "Address already assigned");
            return Ok(());
        }
        anyhow::bail!(
            "Failed to add {cidr} to {dev_name}: {}",
            stderr.trim()
        );
    }

    Ok(())
}

/// Read packets from TUN, encrypt them, and send over the WebRTC data channel.
pub async fn tun_to_webrtc(
    mut tun_reader: tokio::io::ReadHalf<tun::AsyncDevice>,
    data_channel: Arc<RTCDataChannel>,
    cipher: PacketCipher,
) {
    let mut buf = vec![0u8; 65535];

    loop {
        match tun_reader.read(&mut buf).await {
            Ok(0) => {
                info!("TUN device closed");
                break;
            }
            Ok(n) => {
                let encrypted = match cipher.encrypt(&buf[..n]) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to encrypt packet: {e}");
                        continue;
                    }
                };
                let packet = bytes::Bytes::from(encrypted);
                if let Err(e) = data_channel.send(&packet).await {
                    error!("Failed to send packet over data channel: {e}");
                    break;
                }
            }
            Err(e) => {
                error!("Error reading from TUN: {e}");
                break;
            }
        }
    }
}

/// Receive encrypted packets from WebRTC data channel, decrypt, and write to TUN.
pub async fn webrtc_to_tun(
    mut tun_writer: tokio::io::WriteHalf<tun::AsyncDevice>,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    cipher: PacketCipher,
) {
    while let Some(packet) = packet_rx.recv().await {
        let plaintext = match cipher.decrypt(&packet) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to decrypt packet: {e}");
                continue;
            }
        };
        if let Err(e) = tun_writer.write_all(&plaintext).await {
            error!("Failed to write packet to TUN: {e}");
            break;
        }
    }

    info!("Packet receiver closed, stopping TUN writer");
}
