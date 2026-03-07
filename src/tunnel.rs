use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{error, info, warn};
use webrtc::data_channel::RTCDataChannel;

use crate::config::{CidrAddress, WgConfig};
use crate::crypto::PacketCipher;

// Relay envelope: first byte 0x01 = relay, then 1 byte addr family (4 or 6), then 4 or 16 bytes dst IP, then inner packet.
// Any other first byte (e.g. 0x45 IPv4, 0x60 IPv6) = direct IP packet.
const RELAY_TYPE_RELAY: u8 = 0x01;
const ADDR_FAMILY_IPV4: u8 = 4;
const ADDR_FAMILY_IPV6: u8 = 6;

/// Encodes a relay envelope: type byte, addr family, dst IP bytes, then inner packet.
pub fn encode_relay_envelope(dst: IpAddr, inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 + inner.len());
    out.push(RELAY_TYPE_RELAY);
    match dst {
        IpAddr::V4(ip) => {
            out.push(ADDR_FAMILY_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ADDR_FAMILY_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(inner);
    out
}

/// Decoded packet: either a direct IP packet or a relay envelope (final_dst, inner payload).
#[derive(Debug)]
pub enum DecodedPacket<'a> {
    Direct(&'a [u8]),
    Relay(IpAddr, &'a [u8]),
}

/// If the decrypted payload starts with RELAY_TYPE_RELAY, parse envelope and return Relay(dst, inner).
/// Otherwise return Direct(whole payload).
pub fn decode_packet(pkt: &[u8]) -> Option<DecodedPacket<'_>> {
    if pkt.is_empty() {
        return None;
    }
    if pkt[0] != RELAY_TYPE_RELAY {
        return Some(DecodedPacket::Direct(pkt));
    }
    if pkt.len() < 2 {
        return None;
    }
    let family = pkt[1];
    let (dst, inner_start) = match family {
        ADDR_FAMILY_IPV4 if pkt.len() >= 2 + 4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&pkt[2..6]);
            (IpAddr::V4(Ipv4Addr::from(octets)), 6)
        }
        ADDR_FAMILY_IPV6 if pkt.len() >= 2 + 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[2..18]);
            (IpAddr::V6(Ipv6Addr::from(octets)), 18)
        }
        _ => return None,
    };
    Some(DecodedPacket::Relay(dst, &pkt[inner_start..]))
}

/// A single peer's data channel + encrypt cipher for outbound routing.
pub struct PeerRoute {
    pub peer_key: String,
    pub allowed_ips: Vec<CidrAddress>,
    /// When true, this peer can be used to relay packets when no direct route exists.
    pub can_relay: bool,
    pub data_channel: Arc<RTCDataChannel>,
    pub encrypt_cipher: PacketCipher,
}

/// Dynamic routing table that maps destination IPs to the correct peer.
/// Peers are added/removed at runtime as they connect/disconnect.
pub struct RoutingTable {
    peers: RwLock<Vec<PeerRoute>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(Vec::new()),
        }
    }

    pub async fn add_peer(&self, route: PeerRoute) {
        let key_preview = route.peer_key.chars().take(8).collect::<String>();
        let routes: Vec<String> = route.allowed_ips.iter().map(|c| c.to_string()).collect();
        info!(
            peer = %format!("{}…", key_preview),
            routes = %routes.join(", "),
            can_relay = route.can_relay,
            "Peer connected — added to routing table"
        );
        self.peers.write().await.push(route);
    }

    pub async fn remove_peer(&self, peer_key: &str) {
        let mut peers = self.peers.write().await;
        let before = peers.len();
        peers.retain(|p| p.peer_key != peer_key);
        if peers.len() < before {
            let key_preview = peer_key.chars().take(8).collect::<String>();
            info!(
                peer = %format!("{}…", key_preview),
                "Peer disconnected — removed from routing table"
            );
        }
    }

    /// Find the peer whose AllowedIPs match the given destination IP (longest-prefix match)
    /// and send the encrypted packet through its data channel. If no direct route exists and
    /// `allow_relay` is true, send the packet to the first relay-capable peer wrapped in a
    /// relay envelope.
    pub async fn route_packet(&self, pkt: &[u8], allow_relay: bool) {
        let dst = match packet_dst_ip(pkt) {
            Some(ip) => ip,
            None => return,
        };

        let peers = self.peers.read().await;

        let mut best: Option<(u8, usize)> = None;
        for (i, peer) in peers.iter().enumerate() {
            for cidr in &peer.allowed_ips {
                if cidr_contains(cidr, dst) {
                    match best {
                        Some((best_prefix, _)) if cidr.prefix <= best_prefix => {}
                        _ => best = Some((cidr.prefix, i)),
                    }
                }
            }
        }

        let (peer_idx, to_send, is_relay) = match best {
            Some((_, i)) => (i, pkt.to_vec(), false),
            None if allow_relay => {
                // No direct route: try relaying via first peer that can relay
                let relay_idx = peers.iter().position(|p| p.can_relay);
                match relay_idx {
                    Some(i) => {
                        let envelope = encode_relay_envelope(dst, pkt);
                        (i, envelope, true)
                    }
                    None => return,
                }
            }
            None => return,
        };

        let peer = &peers[peer_idx];
        let encrypted = match peer.encrypt_cipher.encrypt(&to_send) {
            Ok(data) => data,
            Err(e) => {
                error!(dst = %dst, error = %e, "Failed to encrypt packet — dropping");
                return;
            }
        };
        let packet = bytes::Bytes::from(encrypted);
        if is_relay {
            tracing::debug!(dst = %dst, relay_via = %&peer.peer_key[..8], "Relaying packet via peer");
        }
        if let Err(e) = peer.data_channel.send(&packet).await {
            error!(dst = %dst, error = %e, "Failed to send packet over data channel");
        }
    }
}

fn cidr_contains(cidr: &CidrAddress, addr: IpAddr) -> bool {
    match (cidr.addr, addr) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = if cidr.prefix == 0 { 0u32 } else { !0u32 << (32 - cidr.prefix) };
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = if cidr.prefix == 0 { 0u128 } else { !0u128 << (128 - cidr.prefix) };
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

fn packet_dst_ip(pkt: &[u8]) -> Option<IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 if pkt.len() >= 20 => {
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            Some(IpAddr::V4(dst))
        }
        6 if pkt.len() >= 40 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Create and configure a TUN device based on the WireGuard config.
pub fn create_tun_device(config: &WgConfig) -> Result<tun::AsyncDevice> {
    let mtu = config.interface.mtu.unwrap_or(1400);

    let ipv4_address: Vec<_> = config
        .interface
        .addresses
        .iter()
        .filter(|a| a.is_ipv4())
        .collect();
    let ipv6_address: Vec<_> = config
        .interface
        .addresses
        .iter()
        .filter(|a| a.is_ipv6())
        .collect();

    let mut tun_config = tun::Configuration::default();
    tun_config.mtu(mtu as u16).up();

    if let Some(v4) = ipv4_address.first() {
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

    info!(
        device = %dev_name,
        mtu = mtu,
        "TUN device created and ready"
    );

    for v4 in ipv4_address.iter().skip(1) {
        add_address_via_ip(&dev_name, v4.addr, v4.prefix)?;
    }

    for v6 in &ipv6_address {
        add_address_via_ip(&dev_name, v6.addr, v6.prefix)?;
    }

    for addr in &config.interface.addresses {
        info!(device = %dev_name, address = %addr, "Interface address configured");
    }

    disable_rp_filter(&dev_name);

    for peer in &config.peers {
        for allowed_ip in &peer.allowed_ips {
            add_route(&dev_name, allowed_ip);
        }
    }

    let async_device =
        tun::AsyncDevice::new(device).context("Failed to create async TUN device")?;

    Ok(async_device)
}

fn disable_rp_filter(dev_name: &str) {
    for path in [
        format!("/proc/sys/net/ipv4/conf/{dev_name}/rp_filter"),
        "/proc/sys/net/ipv4/conf/all/rp_filter".to_string(),
    ] {
        if std::fs::write(&path, "0").is_ok() {
            tracing::debug!(path = %path, "Disabled reverse path filter");
        }
    }
}

fn add_route(dev_name: &str, cidr: &CidrAddress) {
    let family = if cidr.is_ipv6() { "-6" } else { "-4" };
    let dest = format!("{}/{}", cidr.addr, cidr.prefix);

    match std::process::Command::new("ip")
        .args([family, "route", "add", &dest, "dev", dev_name])
        .output()
    {
        Ok(output) if output.status.success() => {
            info!(route = %dest, device = %dev_name, "Route added");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") {
                tracing::debug!(route = %dest, device = %dev_name, "Route already exists");
            } else {
                warn!(route = %dest, device = %dev_name, error = %stderr.trim(), "Failed to add route");
            }
        }
        Err(e) => {
            warn!(route = %dest, device = %dev_name, error = %e, "Failed to run ip route add");
        }
    }
}

fn prefix_to_netmask(prefix: u8) -> std::net::Ipv4Addr {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    std::net::Ipv4Addr::from(mask)
}

fn add_address_via_ip(dev_name: &str, addr: IpAddr, prefix: u8) -> Result<()> {
    let family = if addr.is_ipv6() { "-6" } else { "-4" };
    let cidr = format!("{addr}/{prefix}");

    let output = std::process::Command::new("ip")
        .args([family, "addr", "add", &cidr, "dev", dev_name])
        .output()
        .with_context(|| format!("Failed to run `ip {family} addr add {cidr} dev {dev_name}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            tracing::debug!(address = %cidr, device = %dev_name, "Address already assigned");
            return Ok(());
        }
        anyhow::bail!(
            "Failed to add {cidr} to {dev_name}: {}",
            stderr.trim()
        );
    }

    Ok(())
}

/// Read packets from TUN and route each to the correct peer via the routing table.
/// Starts immediately — packets to peers not yet connected are silently dropped.
pub async fn tun_to_peers(
    mut tun_reader: tun::DeviceReader,
    routing_table: Arc<RoutingTable>,
) {
    info!("TUN → WebRTC forwarding started (outbound traffic)");

    let mut buf = vec![0u8; 65535];

    loop {
        match tun_reader.read(&mut buf).await {
            Ok(0) => {
                info!("TUN device closed — stopping forwarder");
                break;
            }
            Ok(n) => {
                routing_table.route_packet(&buf[..n], true).await;
            }
            Err(e) => {
                error!(error = %e, "Error reading from TUN — stopping forwarder");
                break;
            }
        }
    }
}

/// Receive encrypted packets from a single peer's WebRTC data channel,
/// decrypt, and either write to TUN (direct) or forward via routing table (relay).
pub async fn peer_to_tun(
    tun_writer: Arc<Mutex<tun::DeviceWriter>>,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    cipher: PacketCipher,
    routing_table: Arc<RoutingTable>,
) {
    while let Some(packet) = packet_rx.recv().await {
        let plaintext = match cipher.decrypt(&packet) {
            Ok(data) => data,
            Err(e) => {
                tracing::debug!(error = %e, "Dropping packet: decrypt failed");
                continue;
            }
        };
        let decoded = match decode_packet(&plaintext) {
            Some(d) => d,
            None => continue,
        };
        match decoded {
            DecodedPacket::Direct(payload) => {
                let mut writer = tun_writer.lock().await;
                if let Err(e) = writer.write_all(payload).await {
                    error!(error = %e, "Failed to write to TUN — stopping receiver");
                    break;
                }
            }
            DecodedPacket::Relay(_dst, inner) => {
                // Forward without allowing further relay to avoid loops
                routing_table.route_packet(inner, false).await;
            }
        }
    }

    info!("Peer packet stream ended — TUN writer stopped");
}
