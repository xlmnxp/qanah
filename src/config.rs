use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

/// A parsed CIDR address (e.g. `10.0.0.1/24` or `fd00::1/64`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrAddress {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl std::fmt::Display for CidrAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl CidrAddress {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (addr_str, prefix_str) = s
            .split_once('/')
            .context("Address must be in CIDR notation (e.g. 10.0.0.1/24 or fd00::1/64)")?;

        let addr: IpAddr = addr_str
            .parse()
            .with_context(|| format!("Invalid IP address: {addr_str}"))?;

        let default_prefix = if addr.is_ipv4() { 24 } else { 64 };
        let prefix: u8 = if prefix_str.is_empty() {
            default_prefix
        } else {
            prefix_str
                .parse()
                .with_context(|| format!("Invalid prefix length: {prefix_str}"))?
        };

        Ok(CidrAddress { addr, prefix })
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub addresses: Vec<CidrAddress>,
    pub listen_port: Option<u16>,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<CidrAddress>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub preshared_key: Option<String>,
}

impl WgConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).context("Failed to read WireGuard config file")?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self> {
        let mut interface = None;
        let mut peers = Vec::new();
        let mut current_section: Option<&str> = None;
        let mut current_map: HashMap<String, Vec<String>> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.eq_ignore_ascii_case("[Interface]") {
                if let Some(section) = current_section {
                    Self::finalize_section(section, &current_map, &mut interface, &mut peers)?;
                }
                current_section = Some("Interface");
                current_map.clear();
                continue;
            }

            if line.eq_ignore_ascii_case("[Peer]") {
                if let Some(section) = current_section {
                    Self::finalize_section(section, &current_map, &mut interface, &mut peers)?;
                }
                current_section = Some("Peer");
                current_map.clear();
                continue;
            }

            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim().to_lowercase();
                let value = line[pos + 1..].trim().to_string();
                current_map.entry(key).or_default().push(value);
            }
        }

        if let Some(section) = current_section {
            Self::finalize_section(section, &current_map, &mut interface, &mut peers)?;
        }

        let interface = interface.context("Missing [Interface] section in WireGuard config")?;

        Ok(WgConfig { interface, peers })
    }

    /// Get the first (and typically only) value for a single-value key.
    fn get_first(map: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
        map.get(key).and_then(|v| v.last().cloned())
    }

    /// Collect all comma-separated values across all occurrences of a key.
    /// Handles both repeated lines and comma-separated values on a single line.
    fn get_all_csv(map: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
        map.get(key)
            .map(|values| {
                values
                    .iter()
                    .flat_map(|v| v.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn finalize_section(
        section: &str,
        map: &HashMap<String, Vec<String>>,
        interface: &mut Option<InterfaceConfig>,
        peers: &mut Vec<PeerConfig>,
    ) -> Result<()> {
        match section {
            "Interface" => {
                let private_key = Self::get_first(map, "privatekey")
                    .context("Missing PrivateKey in [Interface]")?;

                let address_parts = Self::get_all_csv(map, "address");
                if address_parts.is_empty() {
                    anyhow::bail!("Missing Address in [Interface]");
                }

                let addresses: Vec<CidrAddress> = address_parts
                    .iter()
                    .map(|s| CidrAddress::parse(s))
                    .collect::<Result<Vec<_>>>()?;

                let listen_port = Self::get_first(map, "listenport")
                    .and_then(|v| v.parse::<u16>().ok());

                let dns = Self::get_first(map, "dns");
                let mtu = Self::get_first(map, "mtu").and_then(|v| v.parse::<u16>().ok());

                *interface = Some(InterfaceConfig {
                    private_key,
                    addresses,
                    listen_port,
                    dns,
                    mtu,
                });
            }
            "Peer" => {
                let public_key = Self::get_first(map, "publickey")
                    .context("Missing PublicKey in [Peer]")?;

                let allowed_ip_parts = Self::get_all_csv(map, "allowedips");
                let allowed_ips: Vec<CidrAddress> = allowed_ip_parts
                    .iter()
                    .map(|s| CidrAddress::parse(s))
                    .collect::<Result<Vec<_>>>()?;

                let endpoint = Self::get_first(map, "endpoint")
                    .and_then(|v| v.parse().ok());

                let persistent_keepalive = Self::get_first(map, "persistentkeepalive")
                    .and_then(|v| v.parse::<u16>().ok());

                let preshared_key = Self::get_first(map, "presharedkey");

                peers.push(PeerConfig {
                    public_key,
                    allowed_ips,
                    endpoint,
                    persistent_keepalive,
                    preshared_key,
                });
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_only() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24
ListenPort = 51820
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
Endpoint = 192.168.1.1:51820
PersistentKeepalive = 25
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 1);
        assert!(config.interface.addresses[0].is_ipv4());
        assert_eq!(config.interface.addresses[0].prefix, 24);
        assert_eq!(config.interface.listen_port, Some(51820));
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].allowed_ips.len(), 1);
        assert!(config.peers[0].allowed_ips[0].is_ipv4());
    }

    #[test]
    fn test_parse_dual_stack_comma_separated() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24, fd00::1/64

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0, ::/0
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 2);
        assert!(config.interface.addresses[0].is_ipv4());
        assert!(config.interface.addresses[1].is_ipv6());
        assert_eq!(config.interface.addresses[1].prefix, 64);
        assert_eq!(
            config.interface.addresses[1].addr,
            "fd00::1".parse::<IpAddr>().unwrap()
        );

        assert_eq!(config.peers[0].allowed_ips.len(), 2);
        assert!(config.peers[0].allowed_ips[0].is_ipv4());
        assert!(config.peers[0].allowed_ips[1].is_ipv6());
    }

    #[test]
    fn test_parse_dual_stack_separate_lines() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24
Address = fd00::1/64

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 2);
        assert!(config.interface.addresses[0].is_ipv4());
        assert!(config.interface.addresses[1].is_ipv6());

        assert_eq!(config.peers[0].allowed_ips.len(), 2);
        assert!(config.peers[0].allowed_ips[0].is_ipv4());
        assert!(config.peers[0].allowed_ips[1].is_ipv6());
    }

    #[test]
    fn test_parse_mixed_multiline_and_csv() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24, 10.0.1.1/24
Address = fd00::1/64

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.0.0.0/24, 10.0.1.0/24
AllowedIPs = fd00::/64
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 3);
        assert!(config.interface.addresses[0].is_ipv4());
        assert!(config.interface.addresses[1].is_ipv4());
        assert!(config.interface.addresses[2].is_ipv6());

        assert_eq!(config.peers[0].allowed_ips.len(), 3);
        assert!(config.peers[0].allowed_ips[0].is_ipv4());
        assert!(config.peers[0].allowed_ips[1].is_ipv4());
        assert!(config.peers[0].allowed_ips[2].is_ipv6());
    }

    #[test]
    fn test_parse_ipv6_only() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = fd00::1/64

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = ::/0
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 1);
        assert!(config.interface.addresses[0].is_ipv6());
        assert_eq!(config.interface.addresses[0].prefix, 64);

        assert_eq!(config.peers[0].allowed_ips.len(), 1);
        assert!(config.peers[0].allowed_ips[0].is_ipv6());
        assert_eq!(config.peers[0].allowed_ips[0].prefix, 0);
    }

    #[test]
    fn test_parse_multiple_ipv4_addresses() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24
Address = 172.16.0.1/16

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.0.0.0/24
AllowedIPs = 172.16.0.0/16
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 2);
        assert!(config.interface.addresses[0].is_ipv4());
        assert!(config.interface.addresses[1].is_ipv4());
        assert_eq!(config.interface.addresses[0].prefix, 24);
        assert_eq!(config.interface.addresses[1].prefix, 16);

        assert_eq!(config.peers[0].allowed_ips.len(), 2);
    }

    #[test]
    fn test_parse_multiple_ipv6_addresses() {
        let config_str = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = fd00::1/64, fd01::1/48

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = fd00::/64, fd01::/48
"#;

        let config = WgConfig::parse(config_str).unwrap();
        assert_eq!(config.interface.addresses.len(), 2);
        assert!(config.interface.addresses[0].is_ipv6());
        assert!(config.interface.addresses[1].is_ipv6());
        assert_eq!(config.interface.addresses[0].prefix, 64);
        assert_eq!(config.interface.addresses[1].prefix, 48);

        assert_eq!(config.peers[0].allowed_ips.len(), 2);
        assert!(config.peers[0].allowed_ips[0].is_ipv6());
        assert!(config.peers[0].allowed_ips[1].is_ipv6());
    }
}
