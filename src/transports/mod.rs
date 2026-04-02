pub mod datachannel;
pub mod dtls;
pub mod ice;
pub mod rtp;
pub mod sctp;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_LOCAL_IP_CACHE_TTL: Duration = Duration::from_secs(5);
const LOCAL_IP_CACHE_TTL_ENV: &str = "RUSTRTC_LOCAL_IP_CACHE_TTL_SECS";

#[derive(Clone, Copy)]
struct LocalIpCacheEntry {
    ip: IpAddr,
    expires_at: Instant,
}

static LOCAL_IP_CACHE: OnceLock<Mutex<Option<LocalIpCacheEntry>>> = OnceLock::new();

#[async_trait]
pub trait PacketReceiver: Send + Sync {
    async fn receive(&self, packet: Bytes, addr: SocketAddr);
}

pub fn get_local_ip() -> Result<IpAddr, anyhow::Error> {
    let ttl = local_ip_cache_ttl();
    if ttl.is_zero() {
        return resolve_local_ip_uncached();
    }

    let cache = LOCAL_IP_CACHE.get_or_init(|| Mutex::new(None));

    {
        let cache_guard = cache.lock();
        if let Some(entry) = *cache_guard
            && Instant::now() < entry.expires_at
        {
            return Ok(entry.ip);
        }
    }

    let ip = resolve_local_ip_uncached()?;

    {
        let mut cache_guard = cache.lock();
        *cache_guard = Some(LocalIpCacheEntry {
            ip,
            expires_at: Instant::now() + ttl,
        });
    }

    Ok(ip)
}

fn local_ip_cache_ttl() -> Duration {
    static TTL: OnceLock<Duration> = OnceLock::new();

    *TTL.get_or_init(|| match std::env::var(LOCAL_IP_CACHE_TTL_ENV) {
        Ok(value) => match value.parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => {
                tracing::warn!(
                    "Invalid {} value '{}', fallback to {}s",
                    LOCAL_IP_CACHE_TTL_ENV,
                    value,
                    DEFAULT_LOCAL_IP_CACHE_TTL.as_secs()
                );
                DEFAULT_LOCAL_IP_CACHE_TTL
            }
        },
        Err(_) => DEFAULT_LOCAL_IP_CACHE_TTL,
    })
}

fn resolve_local_ip_uncached() -> Result<IpAddr, anyhow::Error> {
    use local_ip_address::list_afinet_netifas;
    if let Ok(interfaces) = list_afinet_netifas() {
        // Score function to prioritize interfaces
        // Higher score = better choice

        // Collect all IPv4 addresses with their scores
        let mut candidates: Vec<(std::net::Ipv4Addr, i32, String)> = Vec::new();

        for (name, addr) in &interfaces {
            if let IpAddr::V4(ip) = addr {
                let ip = *ip;
                let score = interface_priority(name, &ip);
                if score > -1000 {
                    // Only consider non-disqualified interfaces
                    candidates.push((ip, score, name.clone()));
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
