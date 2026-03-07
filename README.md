# Qanah

A peer-to-peer VPN that uses WireGuard configuration files and establishes encrypted tunnels over WebRTC data channels, secured with ChaCha20-Poly1305 and X25519 key exchange.

*Qanah (قَناة) — "tunnel" in Arabic.*

Instead of the traditional WireGuard UDP transport, Qanah creates a TUN device from the WireGuard config (using the interface address/netmask) and tunnels raw IP packets over a WebRTC data channel. This enables NAT traversal via ICE/STUN without needing a public IP or port forwarding.

## Building

```bash
cargo build --release
```

## Usage

Both peers need a WireGuard-style config file (only the `[Interface]` section's `Address` and `MTU` are used for TUN device configuration).

### Peer 1 (Initiator)

```bash
sudo ./target/release/qanah --config examples/peer1.conf offer
```

This prints a base64-encoded **OFFER**. Copy it and send it to Peer 2.

### Peer 2 (Responder)

```bash
sudo ./target/release/qanah --config examples/peer2.conf answer
```

Paste the **OFFER** from Peer 1. This prints a base64-encoded **ANSWER**. Copy it and send it back to Peer 1.

### Back on Peer 1

Paste the **ANSWER** from Peer 2. The WebRTC connection is established and the VPN tunnel is active.

### Testing connectivity

```bash
# IPv4
ping 10.0.0.2   # from Peer 1
ping 10.0.0.1   # from Peer 2

# IPv6
ping6 fd00::2   # from Peer 1
ping6 fd00::1   # from Peer 2
```

### TURN Server (optional)

If STUN-only connectivity isn't enough (e.g. symmetric NATs on both sides), you can provide a TURN server via CLI flags:

```bash
sudo ./target/release/qanah \
  --config examples/peer1.conf \
  --turn-url turn:turn.example.com:3478 \
  --turn-username myuser \
  --turn-credential mypassword \
  offer
```

| Flag | Description |
|------|-------------|
| `--turn-url` | TURN server URL (e.g. `turn:turn.example.com:3478` or `turns:turn.example.com:5349`) |
| `--turn-username` | Username for TURN authentication |
| `--turn-credential` | Credential/password for TURN authentication |

Both `--turn-username` and `--turn-credential` require `--turn-url` to be set.

## How It Works

1. Parses a WireGuard `.conf` file to extract the interface address and network settings
2. Derives a shared secret from your X25519 PrivateKey and the peer's PublicKey
3. Creates a TUN device with the configured IP address and netmask
4. Establishes a WebRTC peer connection using copy-paste signaling (offer/answer exchange)
5. Opens a WebRTC data channel labeled `vpn-tunnel`
6. Encrypts all IP packets with ChaCha20-Poly1305 before sending over the data channel
7. Forwards encrypted packets bidirectionally between the TUN device and the data channel

## Requirements

- Linux (TUN device support)
- Root/sudo privileges (for creating TUN devices)
- Two peers that can reach at least one common STUN server

## Configuration

The tool reads standard WireGuard config files. Relevant fields:

| Field | Section | Description |
|-------|---------|-------------|
| `Address` | `[Interface]` | Comma-separated CIDR addresses for the TUN device. Supports IPv4, IPv6, or both (e.g. `10.0.0.1/24, fd00::1/64`) |
| `MTU` | `[Interface]` | MTU for the TUN device (default: 1400) |
| `PrivateKey` | `[Interface]` | X25519 private key used for ChaCha20-Poly1305 traffic encryption |
| `PublicKey` | `[Peer]` | Peer's X25519 public key used for ChaCha20-Poly1305 traffic encryption |
| `AllowedIPs` | `[Peer]` | Parsed for future routing support |

## Logging

Set the `RUST_LOG` environment variable for more verbose output:

```bash
RUST_LOG=qanah=debug sudo -E ./target/release/qanah --config peer.conf offer
```
