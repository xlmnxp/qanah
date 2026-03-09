# Qanah

A peer-to-peer VPN that uses WireGuard configuration files and establishes encrypted tunnels over WebRTC data channels, secured with ChaCha20-Poly1305 and X25519 key exchange.

*Qanah (قَناة) — "tunnel" in Arabic.*

Instead of the traditional WireGuard UDP transport, Qanah creates a TUN device from the WireGuard config (using the interface address/netmask) and tunnels raw IP packets over a WebRTC data channel. This enables NAT traversal via ICE/STUN without needing a public IP, port forwarding, or control of your upstream network (e.g. when you’re behind CGNAT).

Qanah supports mesh networking, allowing multiple peers to connect simultaneously based on the WireGuard configuration. When there is no direct connection to a destination (e.g. that peer is offline or not in config), traffic can be routed over another connected peer in a single relay hop. Relaying can be disabled with `--no-relay` so that only direct peer routes are used.

## Use Cases

- **Remote access behind CGNAT** — Connect to your home lab, NAS, or dev machine from anywhere, even if your ISP puts you behind CGNAT. No need to open ports or run a central VPN server; WebRTC/ICE handles NAT traversal.
- **Mesh VPN for small teams** — Give each team member a peer config so everyone can reach each other’s machines (e.g. SSH, RDP, internal services) over an encrypted mesh, without a dedicated VPN server.
- **Works when WireGuard/UDP VPNs are blocked** — If the WireGuard protocol (or outbound UDP) is blocked by your ISP/country/network, Qanah can still work by carrying packets over WebRTC/ICE (often over standard ports) while using the same WireGuard-style configs.
- **Site-to-site over restrictive networks** — Link two networks (e.g. office and colo) when only outbound HTTPS or MQTT is allowed. Signaling over MQTT and WebRTC over standard ports can work where classic VPNs are blocked.
- **Temporary secure links** — Spin up a tunnel for a one-off session (pair programming, support access, demos) using manual signaling (`offer`/`answer`) and existing WireGuard keys; no long-lived VPN infrastructure.
- **Development and testing** — Run multiple peers locally or in CI with different configs to test routing, relaying, and NAT scenarios without real hardware.

## Building

```bash
cargo build --release
```

## Usage

Each peer needs a WireGuard-style config file. The `[Interface]` section provides the local address and keys, while the `[Peer]` sections provide the remote peers' public keys and allowed IPs.

By default, Qanah uses an MQTT broker to automatically exchange WebRTC signaling data (offer/answer), so peers just run one command each and connections are established automatically.

### Automatic Signaling (Default)

```bash
# Peer 1
sudo ./target/release/qanah --config examples/peer1.conf

# Peer 2
sudo ./target/release/qanah --config examples/peer2.conf

# Peer 3
sudo ./target/release/qanah --config examples/peer3.conf
```

The peers discover each other via the MQTT signaling server and establish direct WebRTC connections automatically.

### Manual Signaling

If you prefer to exchange signaling data manually (copy-paste), use the subcommands:

```bash
# Peer 1 (Initiator)
sudo ./target/release/qanah --config examples/peer1.conf offer
# Copy the printed OFFER and send it to other peers

# Peer 2 (Responder)
sudo ./target/release/qanah --config examples/peer2.conf answer
# Paste the OFFER, then copy the printed ANSWER and send it back to Peer 1

# Peer 3 (Responder)
sudo ./target/release/qanah --config examples/peer3.conf answer
# Paste the OFFER, then copy the printed ANSWER and send it back to Peer 1
```

### Testing Connectivity

```bash
# From Peer 1
ping 10.0.0.2   # to Peer 2
ping 10.0.0.3   # to Peer 3
ping6 fd00::2   # to Peer 2 (IPv6)
ping6 fd00::3   # to Peer 3 (IPv6)

# From Peer 2
ping 10.0.0.1   # to Peer 1
ping 10.0.0.3   # to Peer 3
ping6 fd00::1   # to Peer 1 (IPv6)
ping6 fd00::3   # to Peer 3 (IPv6)

# From Peer 3
ping 10.0.0.1   # to Peer 1
ping 10.0.0.2   # to Peer 2
ping6 fd00::1   # to Peer 1 (IPv6)
ping6 fd00::2   # to Peer 2 (IPv6)
```

## CLI Options

```
qanah [OPTIONS] --config <CONFIG> [COMMAND]
```

### Commands

| Command | Description |
|---------|-------------|
| `offer` | Start as the offering peer (initiator) — enables manual signaling |
| `answer` | Start as the answering peer (responder) — enables manual signaling |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config <CONFIG>` | Path to WireGuard config file | *(required)* |
| `--stun <URL>` | STUN server URL (can be specified multiple times) | `stun:stun.l.google.com:19302`, `stun:stun1.l.google.com:19302` |
| `--turn-url <URL>` | TURN server URL (e.g. `turn:turn.example.com:3478`) | *(none)* |
| `--turn-username <USERNAME>` | TURN server username (requires `--turn-url`) | *(none)* |
| `--turn-credential <CREDENTIAL>` | TURN server credential (requires `--turn-url`) | *(none)* |
| `--signal-server <HOST:PORT>` | MQTT signaling server for automatic SDP exchange | `broker.emqx.io:1883` |
| `--no-relay` | Disable relaying: only use direct peer routes; packets with no direct route are dropped | relaying enabled |
| `-h, --help` | Print help | |

### Examples

```bash
# Basic usage with defaults
sudo ./target/release/qanah -c peer1.conf

# Custom STUN servers
sudo ./target/release/qanah -c peer1.conf \
  --stun stun:stun.example.com:3478 \
  --stun stun:stun2.example.com:19302

# With TURN relay
sudo ./target/release/qanah -c peer1.conf \
  --turn-url turn:turn.example.com:3478 \
  --turn-username myuser \
  --turn-credential mypassword \

# Custom MQTT signaling server
sudo ./target/release/qanah -c peer1.conf \
  --signal-server mqtt.example.com:1883 \

# Disable relaying (only direct peer routes; no traffic via intermediate peers)
sudo ./target/release/qanah -c peer1.conf --no-relay

# Manual signaling with custom STUN and TURN
sudo ./target/release/qanah -c examples/peer1.conf \
  --stun stun:mystun.io:3478 \
  --turn-url turn:myturn.io:3478 \
  --turn-username user \
  --turn-credential pass \
  offer

sudo ./target/release/qanah -c peer1.conf \
  --stun stun:mystun.io:3478 \
  --turn-url turn:myturn.io:3478 \
  --turn-username user \
  --turn-credential pass \
  answer
```

## How It Works

1. Parses a WireGuard `.conf` file to extract the interface address, keys, and peer info
2. Derives a shared secret from your X25519 PrivateKey and the peer's PublicKey
3. Derives independent keys for tunnel encryption (per-direction) and signaling
4. Exchanges WebRTC signaling data via MQTT (or manual copy-paste when using subcommands)
5. Establishes a WebRTC peer connection with ICE/STUN/TURN for NAT traversal
6. Creates a TUN device with the configured IP address and netmask
7. Opens a WebRTC data channel labeled `vpn-tunnel`
8. Encrypts all IP packets with ChaCha20-Poly1305 before sending over the data channel
9. Forwards encrypted packets bidirectionally between the TUN device and the data channel
10. If no peer has the destination in its AllowedIPs (no direct route), sends the packet to the first connected peer as a relay envelope; that peer decrypts and routes the inner packet (direct or to its TUN), so traffic can reach destinations via one relay hop

## Requirements

- Linux (TUN device support)
- Root/sudo privileges (for creating TUN devices)
- Two peers that can reach at least one common STUN server

## Configuration

The tool reads standard WireGuard config files. Relevant fields:

| Field | Section | Description |
|-------|---------|-------------|
| `Address` | `[Interface]` | Comma-separated CIDR addresses for the TUN device (e.g. `10.0.0.1/24, fd00::1/64`) |
| `MTU` | `[Interface]` | MTU for the TUN device (default: `1400`) |
| `PrivateKey` | `[Interface]` | X25519 private key used for shared secret derivation |
| `PublicKey` | `[Peer]` | Peer's X25519 public key used for shared secret derivation |
| `AllowedIPs` | `[Peer]` | CIDR ranges to route through the tunnel (e.g. `10.0.0.2/32, fd00::2/128`) |

Multiple `[Peer]` sections are supported for mesh networking.

### Example Config

```ini
[Interface]
PrivateKey = <base64-encoded-x25519-private-key>
Address = 10.0.0.1/24, fd00::1/64

[Peer]
PublicKey = <base64-encoded-x25519-public-key-peer2>
AllowedIPs = 10.0.0.2/32, fd00::2/128

[Peer]
PublicKey = <base64-encoded-x25519-public-key-peer3>
AllowedIPs = 10.0.0.3/32, fd00::3/128
```

## License
GPLv2 License. See [LICENSE](LICENSE) for details.