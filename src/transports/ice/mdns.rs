//! Minimal mDNS responder for ICE candidate obfuscation.
//!
//! Implements just enough of RFC 6762/6763 to make WebRTC mDNS candidates
//! work (the browser `xxx.local` host-candidate scheme): listen for mDNS
//! queries on 224.0.0.251:5353 and answer A (IPv4) / AAAA (IPv6) lookups for
//! one obfuscated hostname with the local addresses we advertise.
//!
//! The responder binds with `SO_REUSEADDR`/`SO_REUSEPORT` so it coexists with
//! system mDNS stacks (Avahi, macOS `mDNSResponder`, Windows `Dnscache`) and
//! with other rustrtc `PeerConnection`s in the same process.
//!
//! Resolution of *remote* `.local` candidates is intentionally out of scope:
//! as an SFU/answerer, connectivity works through the peer's server-reflexive
//! candidates, matching the common deployment.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, trace};

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

/// A running mDNS responder answering A/AAAA queries for one hostname.
pub struct MdnsResponder {
    hostname: String,
    stop: Arc<Notify>,
    done: Arc<Notify>,
    _task: JoinHandle<()>,
}

impl Drop for MdnsResponder {
    fn drop(&mut self) {
        // Signal the loop to exit; the task detaches and finishes on its own.
        self.stop.notify_waiters();
    }
}

impl MdnsResponder {
    /// Generate an obfuscated hostname (`<random>.local`).
    pub fn generate_hostname() -> String {
        use crate::transports::ice::stun::random_u32;
        format!("{:08x}{:08x}.local", random_u32(), random_u32())
    }

    /// Start answering queries for `hostname` with `addresses` (A records for
    /// IPv4, AAAA for IPv6; loopback addresses are never advertised).
    pub fn start(hostname: String, addresses: Vec<IpAddr>) -> Result<Self> {
        let socket = bind_mdns_socket().context("binding mDNS socket")?;
        let stop = Arc::new(Notify::new());
        let done = Arc::new(Notify::new());
        let stop_rx = stop.clone();
        let done_tx = done.clone();
        let task_hostname = hostname.clone();

        let task = tokio::spawn(async move {
            run_responder(Arc::new(socket), task_hostname, addresses, stop_rx).await;
            done_tx.notify_waiters();
        });

        Ok(Self {
            hostname,
            stop,
            done,
            _task: task,
        })
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Stop the responder and wait for its task to release the socket.
    pub async fn stop(self) {
        self.stop.notify_waiters();
        self.done.notified().await;
        debug!("mDNS responder stopped ({})", self.hostname);
    }
}

fn bind_mdns_socket() -> Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // Coexist with system mDNS stacks and other responders in this process.
    let _ = socket.set_reuse_address(true);
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket.set_multicast_loop_v4(true)?;
    socket.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;
    // Join the group on the wildcard plus every local IPv4 interface — the
    // kernel only delivers multicast to sockets that joined on the interface
    // the packet arrived on (mDNS daemons do the same).
    let _ = socket.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED);
    use local_ip_address::list_afinet_netifas;
    if let Ok(interfaces) = list_afinet_netifas() {
        for (_name, addr) in interfaces {
            if let IpAddr::V4(v4) = addr {
                let _ = socket.join_multicast_v4(&MDNS_GROUP, &v4);
            }
        }
    }

    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    Ok(tokio::net::UdpSocket::from_std(std_socket)?)
}

async fn run_responder(
    socket: Arc<tokio::net::UdpSocket>,
    hostname: String,
    addresses: Vec<IpAddr>,
    stop: Arc<Notify>,
) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            _ = stop.notified() => return,
            res = socket.recv_from(&mut buf) => {
                let (len, from) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        trace!("mDNS recv error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if let Some(response) = handle_mdns_packet(&buf[..len], &hostname, &addresses) {
                    // mDNS responses go to the multicast group, plus unicast
                    // to legacy queriers (RFC 6762 §6.7: questions sent from
                    // a source port other than 5353 expect unicast replies).
                    let mut targets: Vec<SocketAddr> =
                        vec![SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, MDNS_PORT))];
                    if from.port() != MDNS_PORT {
                        targets.push(from);
                    }
                    for dest in targets {
                        if let Err(e) = socket.send_to(&response, dest).await {
                            trace!("mDNS send error: {e}");
                        } else {
                            debug!("mDNS: answered query for {} via {}", hostname, dest);
                        }
                    }
                }
            }
        }
    }
}

/// Parse an mDNS query; if it asks for our hostname (A or AAAA), build a
/// response carrying every advertised address of the matching family.
fn handle_mdns_packet(packet: &[u8], hostname: &str, addresses: &[IpAddr]) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if qdcount == 0 {
        return None;
    }

    // Parse the first question's QNAME.
    let mut idx = 12usize;
    let mut labels: Vec<Vec<u8>> = Vec::new();
    loop {
        let len = *packet.get(idx)? as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            // Compression pointer in a question name — non-standard; bail.
            return None;
        }
        let label = packet.get(idx..idx + len)?;
        labels.push(label.to_vec());
        idx += len;
        if labels.len() > 8 {
            return None; // absurd name
        }
    }
    if idx + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    let qclass = u16::from_be_bytes([packet[idx + 2], packet[idx + 3]]);
    idx += 4;

    if qclass != QCLASS_IN {
        return None;
    }

    // Case-insensitive name match.
    let query_name = labels
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(".");
    if query_name != hostname.to_ascii_lowercase() {
        return None;
    }

    let record_type = match qtype {
        QTYPE_A => QTYPE_A,
        QTYPE_AAAA => QTYPE_AAAA,
        _ => return None, // ANY etc. not answered
    };
    let matched: Vec<&IpAddr> = addresses
        .iter()
        .filter(|ip| match record_type {
            QTYPE_A => ip.is_ipv4(),
            _ => ip.is_ipv6(),
        })
        .collect();
    if matched.is_empty() {
        return None;
    }

    Some(build_response(packet, idx, qtype, &matched))
}

/// Build an mDNS response: echo the question, then one answer record per
/// address (name compressed to offset 12 via pointer 0xC00C).
fn build_response(query: &[u8], question_end: usize, qtype: u16, addresses: &[&IpAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + (question_end - 12) + 16 * addresses.len());
    // Header: ID=0 (mDNS), QR|AA, zero counts except QD/AN.
    out.extend_from_slice(&query[..2]); // echo transaction ID (legacy query)
    out.extend_from_slice(&0x8400u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(addresses.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // NSCOUNT/ARCOUNT

    // Echo the question section verbatim.
    out.extend_from_slice(&query[12..question_end]);

    // Answer records.
    for ip in addresses {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name ptr → offset 12
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&0x8001u16.to_be_bytes()); // IN | cache-flush
        out.extend_from_slice(&120u32.to_be_bytes()); // TTL 2 min
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_query(name: &str) -> Vec<u8> {
        let mut q = vec![0u8; 12];
        q[4] = 0;
        q[5] = 1; // QDCOUNT = 1
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&QTYPE_A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn responds_to_own_hostname_a_query() {
        let hostname = "abc12345def67890.local";
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V6("fe80::1".parse().unwrap()),
        ];
        let resp = handle_mdns_packet(&a_query(hostname), hostname, &addrs).unwrap();
        // QR + AA flags
        assert_eq!(&resp[2..4], &0x8400u16.to_be_bytes());
        // One answer record: the A query only yields the IPv4 address.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert!(resp.windows(4).any(|w| w == [192, 168, 1, 10]));
    }

    #[test]
    fn ignores_other_names_and_ptr_queries() {
        let hostname = "abc12345def67890.local";
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))];
        // Different name → no response.
        assert!(handle_mdns_packet(&a_query("other123456789.local"), hostname, &addrs).is_none());

        // Case-insensitive match still answers.
        assert!(handle_mdns_packet(&a_query("ABC12345DEF67890.LOCAL"), hostname, &addrs).is_some());

        // PTR query (type 12) is not answered.
        let mut q = a_query(hostname);
        let qtype_off = q.len() - 4;
        q[qtype_off] = 0;
        q[qtype_off + 1] = 12;
        assert!(handle_mdns_packet(&q, hostname, &addrs).is_none());
    }

    #[test]
    fn truncated_packets_do_not_panic() {
        let hostname = "abc12345def67890.local";
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))];
        let full = a_query(hostname);
        for cut in 0..full.len() {
            let _ = handle_mdns_packet(&full[..cut], hostname, &addrs); // must not panic
        }
    }
}
