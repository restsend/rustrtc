pub mod dtls;
pub mod ice;
pub mod rtp;
pub mod sctp;

use async_trait::async_trait;
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};

#[async_trait]
pub trait PacketReceiver: Send + Sync {
    async fn receive(&self, packet: Bytes, addr: SocketAddr);
}

pub fn get_local_ip() -> Result<IpAddr, anyhow::Error> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    if let Ok(interfaces) = NetworkInterface::show() {
        // Score function to prioritize interfaces
        // Higher score = better choice

        // Collect all IPv4 addresses with their scores
        let mut candidates: Vec<(std::net::Ipv4Addr, i32, String)> = Vec::new();

        for interface in interfaces.iter() {
            for addr in &interface.addr {
                if let network_interface::Addr::V4(ipv4) = addr {
                    let ip = ipv4.ip;
                    let score = interface_priority(&interface.name, &ip);
                    if score > -1000 {
                        // Only consider non-disqualified interfaces
                        candidates.push((ip, score, interface.name.clone()));
                    }
                }
            }
        }

        // Sort by score (highest first) and return the best one
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        if let Some((ip, score, name)) = candidates.first() {
            tracing::trace!(
                "Selected network interface: {} (IP: {}, score: {})",
                name,
                ip,
                score
            );
            return Ok(IpAddr::V4(*ip));
        }
    }

    Err(anyhow::anyhow!("No suitable network interface found"))
}

fn interface_priority(name: &str, ip: &std::net::Ipv4Addr) -> i32 {
    let mut score = 0;

    // Prefer non-loopback (essential)
    if name == "lo0" || ip.is_loopback() {
        return -1000; // Disqualify loopback
    }

    // Prefer physical interfaces (en*, wlan*, eth*, etc.)
    if name.starts_with("en") || name.starts_with("wlan") || name.starts_with("eth") {
        score += 100;
    } else if name.starts_with("utun")
        || name.starts_with("bridge")
        || name.starts_with("gif")
        || name.starts_with("stf")
        || name.starts_with("awdl")
        || name.starts_with("llw")
    {
        // Virtual/tunnel interfaces get lower priority
        score -= 50;
    }

    // Prefer private network IPs (RFC 1918)
    let octets = ip.octets();
    if octets[0] == 192 && octets[1] == 168 {
        // 192.168.0.0/16 - most common home network
        score += 50;
    } else if octets[0] == 10 {
        // 10.0.0.0/8 - corporate networks
        score += 40;
    } else if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        // 172.16.0.0/12 - corporate networks
        score += 40;
    } else if !ip.is_private() {
        // Public IPs are less preferred (might be VPN)
        score -= 30;
    }

    // Avoid link-local (169.254.x.x)
    if octets[0] == 169 && octets[1] == 254 {
        score -= 100;
    }

    score
}
