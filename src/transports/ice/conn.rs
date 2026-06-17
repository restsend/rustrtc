use super::{IceSocketWrapper, should_drop_packet};
use crate::errors::RtcResult;
use crate::stats::{StatsEntry, StatsId, StatsKind, StatsProvider};
use crate::transports::PacketReceiver;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Per-source-address state tracked during the latching probation period.
///
/// After `enable_latch_on_rtp()` is called, the first few RTP packets from
/// potentially multiple source ports are observed before committing to a
/// remote address.  This handles the common case where a stale NAT binding
/// or a brief port-glitch delivers one or two packets from the wrong port
/// before the real media stream settles.
///
/// Decision rules (evaluated in order on every new RTP packet):
///
/// 1. **Marker flush**: a candidate that has sent a packet with `marker=true`
///    and has the lowest `first_seq` among candidates with a marker is
///    selected immediately — the marker bit signals the first packet of a
///    talkspurt and is a strong indicator of the real source.
/// 2. **Consecutive dominance**: a candidate with `consecutive_count >= 2`
///    that also has accumulated `>= 3` total packets across all observed
///    candidates is selected.  Two sequential packets from the same port is
///    a reliable signal.
/// 3. **Timeout fallback**: after observing `max_packets` RTP
///    packets without a clear winner, the candidate with the highest
///    `packet_count` wins (ties broken by lowest `first_seq`).
///
/// Once latched the `probation` field is set to `None` so the `Mutex` is
/// never locked again during the steady-state forwarding path.
#[derive(Debug)]
struct RtpCandidateState {
    addr: SocketAddr,
    #[allow(dead_code)]
    ssrc: u32,
    first_seq: u16,
    last_seq: u16,
    first_ts: u32,
    packet_count: u8,
    /// Number of RTP packets received with `seq == last_seq + 1`.
    consecutive_count: u8,
    has_marker: bool,
}

/// State held while we are in the probation / candidate-selection phase.
#[derive(Debug)]
struct RtpProbationState {
    candidates: Vec<RtpCandidateState>,
    total_packets: u8,
    /// Maximum total observed packets before forcing a decision
    /// (≈ 80 ms at 20 ms ptime when set to 6).
    max_packets: u8,
}

pub struct IceConn {
    pub socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    rtcp_socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    pub remote_addr: RwLock<SocketAddr>,
    pub remote_rtcp_addr: RwLock<Option<SocketAddr>>,
    pub dtls_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub rtp_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub latch_on_rtp: AtomicBool,
    pub rtp_latched: AtomicBool,
    pub rtcp_latched: AtomicBool,
    pub expected_ssrc: AtomicU32,
    pub rtp_rx_count: AtomicU64,
    pub label: Option<String>,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    /// Candidate state during the brief probation window before latch commits.
    /// Set to `Some` when `latch_on_rtp` is enabled, `None` once latched
    /// (or when not using probation-mode latching).
    probation: Mutex<Option<RtpProbationState>>,
    /// Maximum packets to observe during probation.  `0` means "no probation"
    /// — first SSRC-matching RTP latches immediately (legacy behaviour).
    probation_max_packets: AtomicU8,
}

impl IceConn {
    pub fn new(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
        label: Option<String>,
    ) -> Arc<Self> {
        Self::new_with_rtcp(socket_rx.clone(), socket_rx, remote_addr, label, None)
    }

    pub(crate) fn new_with_rtcp(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        rtcp_socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
        label: Option<String>,
        probation_max_packets: Option<u8>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket_rx,
            rtcp_socket_rx,
            remote_addr: RwLock::new(remote_addr),
            remote_rtcp_addr: RwLock::new(None),
            dtls_receiver: RwLock::new(None),
            rtp_receiver: RwLock::new(None),
            latch_on_rtp: AtomicBool::new(false),
            rtp_latched: AtomicBool::new(false),
            rtcp_latched: AtomicBool::new(false),
            expected_ssrc: AtomicU32::new(0),
            rtp_rx_count: AtomicU64::new(0),
            label,
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            probation: Mutex::new(None),
            probation_max_packets: AtomicU8::new(probation_max_packets.unwrap_or(0)),
        })
    }

    pub fn set_probation_max_packets(&self, max: Option<u8>) {
        self.probation_max_packets
            .store(max.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn enable_latch_on_rtp(&self) {
        self.latch_on_rtp.store(true, Ordering::Relaxed);
        let max = self.probation_max_packets.load(Ordering::Relaxed);
        if max > 0 {
            // Initialise the probation state so candidate observation begins.
            let mut p = self.probation.lock();
            if p.is_none() {
                *p = Some(RtpProbationState {
                    candidates: Vec::new(),
                    total_packets: 0,
                    max_packets: max,
                });
            }
        } else {
            // max == 0 → immediate latch, no probation state
            self.probation.lock().take();
        }
    }

    /// Set the expected SSRC from the remote answer SDP.
    /// When set, RTP latching uses SSRC match instead of source-address
    /// mismatch, allowing latch to succeed even when NAT changes the port.
    pub fn set_expected_ssrc(&self, ssrc: u32) {
        self.expected_ssrc.store(ssrc, Ordering::Relaxed);
    }

    pub fn set_remote_rtcp_addr(&self, addr: Option<SocketAddr>) {
        *self.remote_rtcp_addr.write() = addr;
        self.rtcp_latched.store(false, Ordering::Relaxed);
    }

    pub(crate) fn set_remote_addr_from_signaling(&self, addr: SocketAddr, reason: &'static str) {
        let current = *self.remote_addr.read();
        if self.latch_on_rtp.load(Ordering::Relaxed)
            && self.rtp_latched.load(Ordering::Relaxed)
            && current != addr
        {
            warn!(
                "IceConn: preserving latched RTP remote {} instead of signaling remote {} ({})",
                current, addr, reason
            );
            return;
        }

        *self.remote_addr.write() = addr;
    }

    /// Reset latching state (called on re-INVITE so a new source can be
    /// selected).  Clears both the latch flag and any in-progress probation.
    pub fn reset_latch(&self) {
        self.rtp_latched.store(false, Ordering::Relaxed);
        self.rtcp_latched.store(false, Ordering::Relaxed);
        let max = self.probation_max_packets.load(Ordering::Relaxed);
        *self.probation.lock() = if self.latch_on_rtp.load(Ordering::Relaxed) && max > 0 {
            Some(RtpProbationState {
                candidates: Vec::new(),
                total_packets: 0,
                max_packets: max,
            })
        } else {
            None
        };
    }

    pub fn set_dtls_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.dtls_receiver.write() = Some(Arc::downgrade(&receiver));
    }

    pub fn set_rtp_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.rtp_receiver.write() = Some(Arc::downgrade(&receiver));
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        if should_drop_packet() {
            return Ok(buf.len());
        }
        let socket_rx = self.socket_rx.clone();
        let socket_opt = socket_rx.borrow().clone();

        if let Some(socket) = socket_opt {
            let remote = *self.remote_addr.read();
            if remote.port() == 0 {
                return Err(anyhow::anyhow!("Remote address not set"));
            }
            let n = socket.send_to(buf, remote).await?;
            let tx_pkts = self.tx_packets.fetch_add(1, Ordering::Relaxed) + 1;
            let tx_bytes = self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
            let is_rtp = buf.first().is_some_and(|b| (128..192).contains(b));
            // RTP/RTCP might not be easy to identify reliably from the first byte.
            // For TCP ICE debugging we log the first few outbound packets from the RTP
            // path so we can confirm on-wire packet layout.
            if tx_pkts <= 50 || (is_rtp && tx_pkts % 50 == 0) {
                info!(
                    label = ?self.label,
                    socket = %socket.diag(),
                    remote = %remote,
                    len = buf.len(),
                    is_rtp,
                    first_byte = buf.first().copied().unwrap_or(0),
                    tx_pkts,
                    tx_bytes,
                    "IceConn: sent outbound packet"
                );
            }
            Ok(n)
        } else {
            // Fallback: try to update if None
            let mut socket_rx = self.socket_rx.clone();
            let socket_opt = socket_rx.borrow_and_update().clone();
            if let Some(socket) = socket_opt {
                let remote = *self.remote_addr.read();
                if remote.port() == 0 {
                    return Err(anyhow::anyhow!("Remote address not set"));
                }
                let n = socket.send_to(buf, remote).await?;
                let tx_pkts = self.tx_packets.fetch_add(1, Ordering::Relaxed) + 1;
                let tx_bytes = self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                let is_rtp = buf.first().is_some_and(|b| (128..192).contains(b));
                if tx_pkts <= 50 || (is_rtp && tx_pkts % 50 == 0) {
                    info!(
                        label = ?self.label,
                        socket = %socket.diag(),
                        remote = %remote,
                        len = buf.len(),
                        is_rtp,
                        first_byte = buf.first().copied().unwrap_or(0),
                        tx_pkts,
                        tx_bytes,
                        fallback_socket = true,
                        "IceConn: sent outbound packet"
                    );
                }
                Ok(n)
            } else {
                tracing::warn!("IceConn: send failed - no selected socket");
                Err(anyhow::anyhow!("No selected socket"))
            }
        }
    }

    /// Send multiple DTLS records. On TCP, each record is RFC 4571-framed and all
    /// frames are written in one syscall (avoids Chrome seeing a partial flight).
    pub async fn send_dtls_record_batch(&self, records: &[Vec<u8>]) -> Result<usize> {
        if records.is_empty() {
            return Ok(0);
        }
        if should_drop_packet() {
            return Ok(records.iter().map(|r| r.len()).sum());
        }

        let remote = *self.remote_addr.read();
        if remote.port() == 0 {
            return Err(anyhow::anyhow!("Remote address not set"));
        }

        let socket_rx = self.socket_rx.clone();
        let mut socket_opt = socket_rx.borrow().clone();
        if socket_opt.is_none() {
            let mut rx = self.socket_rx.clone();
            socket_opt = rx.borrow_and_update().clone();
        }

        let Some(socket) = socket_opt else {
            tracing::warn!("IceConn: send_dtls_record_batch failed - no selected socket");
            return Err(anyhow::anyhow!("No selected socket"));
        };

        let total_payload: usize = records.iter().map(|r| r.len()).sum();
        let prev_tx_pkts = self.tx_packets.load(Ordering::Relaxed);
        let tx_pkts = self.tx_packets.fetch_add(records.len() as u64, Ordering::Relaxed) + records.len() as u64;

        match &socket {
            IceSocketWrapper::TcpStream(_, write, _) => {
                let mut framed = Vec::new();
                for record in records {
                    if record.len() > 0xFFFF {
                        return Err(anyhow::anyhow!("DTLS record too large for TCP framing"));
                    }
                    framed.extend_from_slice(&(record.len() as u16).to_be_bytes());
                    framed.extend_from_slice(record);
                }
                super::tcp_write_all(write, &framed).await?;
                let tx_bytes = self.tx_bytes.fetch_add(framed.len() as u64, Ordering::Relaxed) + framed.len() as u64;
                if prev_tx_pkts < 5 {
                    info!(
                        label = ?self.label,
                        socket = %socket.diag(),
                        remote = %remote,
                        records = records.len(),
                        framed_len = framed.len(),
                        tx_pkts,
                        tx_bytes,
                        "IceConn: sent outbound DTLS record batch"
                    );
                }
                Ok(total_payload)
            }
            _ => {
                let mut total = 0usize;
                for record in records {
                    total += self.send(record).await?;
                }
                Ok(total)
            }
        }
    }

    pub async fn send_rtcp(&self, buf: &[u8]) -> Result<usize> {
        let rtcp_addr = *self.remote_rtcp_addr.read();
        let remote = if let Some(rtcp_addr) = rtcp_addr {
            rtcp_addr
        } else {
            *self.remote_addr.read()
        };

        if remote.port() == 0 {
            return Err(anyhow::anyhow!("Remote address not set"));
        }

        let mut socket_rx = if rtcp_addr.is_some() {
            self.rtcp_socket_rx.clone()
        } else {
            self.socket_rx.clone()
        };
        let mut socket_opt = socket_rx.borrow().clone();
        if socket_opt.is_none() {
            socket_opt = socket_rx.borrow_and_update().clone();
        }

        if socket_opt.is_none() && rtcp_addr.is_some() {
            let mut fallback_rx = self.socket_rx.clone();
            socket_opt = fallback_rx.borrow().clone();
            if socket_opt.is_none() {
                socket_opt = fallback_rx.borrow_and_update().clone();
            }
        }

        if let Some(socket) = socket_opt {
            let n = socket.send_to(buf, remote).await?;
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        } else {
            tracing::debug!("IceConn: send_rtcp failed - no selected socket");
            Err(anyhow::anyhow!("No selected socket"))
        }
    }
}

#[async_trait]
impl PacketReceiver for IceConn {
    async fn receive(&self, packet: Bytes, addr: SocketAddr) {
        if packet.is_empty() {
            return;
        }

        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        let rx_pkts = self.rx_packets.load(Ordering::Relaxed);

        let first_byte = packet[0];
        // Scope for read lock
        let current_remote = *self.remote_addr.read();

        // Passive ICE-TCP: the browser often omits TCP candidates in SDP and
        // connects inbound. Latch the real peer from the first packet on the
        // accepted stream so DTLS/RTP replies use the correct destination.
        let socket_is_inbound_tcp = {
            let socket_rx = self.socket_rx.clone();
            matches!(
                socket_rx.borrow().as_ref(),
                Some(IceSocketWrapper::TcpStream(_, _, _))
            )
        };
        if socket_is_inbound_tcp
            && (current_remote.port() == 0 || current_remote != addr)
        {
            *self.remote_addr.write() = addr;
        } else if current_remote.port() == 0 {
            *self.remote_addr.write() = addr;
        } else if addr != current_remote {
            // Note: We no longer automatically switch the remote address just by receiving
            // a packet from a new source (e.g. DTLS). This prevents "path flapping"
            // that can confuse the transport Layer. The remote address should only
            // be updated via the ICE nomination process.
            tracing::trace!(
                "IceConn: Received packet from new address {:?} (byte={}) - ignoring address change",
                addr,
                first_byte
            );
        }

        if (20..64).contains(&first_byte) {
            // DTLS
            if rx_pkts <= 3 {
                info!(
                    label = ?self.label,
                    from = %addr,
                    len = packet.len(),
                    rx_pkts,
                    "IceConn: received DTLS packet"
                );
            }
            let receiver = {
                let rx_lock = self.dtls_receiver.read();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                // tracing::trace!("IceConn: Forwarding DTLS packet to receiver");
                strong_rx.receive(packet, addr).await;
            } else {
                debug!("IceConn: Received DTLS packet but no receiver registered");
            }
        } else if (128..192).contains(&first_byte) {
            // RTP / RTCP
            let is_rtcp = packet.len() >= 2 && (200..=211).contains(&packet[1]);
            if !is_rtcp && rx_pkts <= 5 {
                info!(
                    label = ?self.label,
                    from = %addr,
                    len = packet.len(),
                    rx_pkts,
                    "IceConn: received RTP packet"
                );
            }

            if self.latch_on_rtp.load(Ordering::Relaxed) {
                if is_rtcp {
                    // RTCP may teach the RTCP destination in non-mux mode, but it must
                    // never override the RTP remote address.
                    let mut remote_rtcp_addr = self.remote_rtcp_addr.write();
                    if let Some(current_rtcp_remote) = *remote_rtcp_addr
                        && addr != current_rtcp_remote
                        && !self.rtcp_latched.load(Ordering::Relaxed)
                    {
                        *remote_rtcp_addr = Some(addr);
                        self.rtcp_latched.store(true, Ordering::Relaxed);
                    }
                } else if !self.rtp_latched.load(Ordering::Relaxed) {
                    if packet.len() >= 12 {
                        let expected = self.expected_ssrc.load(Ordering::Relaxed);
                        let pkt_ssrc =
                            u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

                        let ssrc_ok = expected == 0 || pkt_ssrc == expected;

                        if ssrc_ok {
                            let seq = u16::from_be_bytes([packet[2], packet[3]]);
                            let ts =
                                u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
                            let marker = (packet[1] & 0x80) != 0;

                            let mut probation_guard = self.probation.lock();
                            if let Some(ref mut prob) = *probation_guard {
                                prob.total_packets = prob.total_packets.saturating_add(1);

                                let pos = prob.candidates.iter().position(|c| c.addr == addr);
                                if let Some(i) = pos {
                                    let c = &mut prob.candidates[i];
                                    if seq == c.last_seq.wrapping_add(1) {
                                        c.consecutive_count = c.consecutive_count.saturating_add(1);
                                    } else {
                                        // Non-sequential — reset run
                                        c.consecutive_count = 0;
                                    }
                                    c.last_seq = seq;
                                    c.packet_count = c.packet_count.saturating_add(1);
                                    if marker {
                                        c.has_marker = true;
                                    }
                                    if ts < c.first_ts {
                                        c.first_ts = ts;
                                    }
                                    if seq < c.first_seq {
                                        c.first_seq = seq;
                                    }
                                } else {
                                    prob.candidates.push(RtpCandidateState {
                                        addr,
                                        ssrc: pkt_ssrc,
                                        first_seq: seq,
                                        last_seq: seq,
                                        first_ts: ts,
                                        packet_count: 1,
                                        consecutive_count: 0,
                                        has_marker: marker,
                                    });
                                }

                                if addr != current_remote {
                                    *self.remote_addr.write() = addr;
                                }

                                let total = prob.total_packets;
                                let winner: Option<SocketAddr>;

                                // Rule 1: candidate with marker=true and the
                                // lowest first_seq wins immediately.
                                let marker_winner = prob
                                    .candidates
                                    .iter()
                                    .filter(|c| c.has_marker)
                                    .min_by_key(|c| c.first_seq);

                                if let Some(mw) = marker_winner {
                                    winner = Some(mw.addr);
                                } else if total >= prob.max_packets {
                                    // Rule 3 (timeout fallback): pick the
                                    // candidate with the most packets; break
                                    // ties by lowest first_seq.
                                    winner = prob
                                        .candidates
                                        .iter()
                                        .max_by(|a, b| {
                                            a.packet_count
                                                .cmp(&b.packet_count)
                                                .then(b.first_seq.cmp(&a.first_seq))
                                        })
                                        .map(|c| c.addr);
                                } else {
                                    // Rule 2: consecutive dominance — at
                                    // least 2 consecutive packets from one
                                    // source and at least 3 total observed.
                                    winner = if total >= 3 {
                                        prob.candidates
                                            .iter()
                                            .find(|c| c.consecutive_count >= 2)
                                            .map(|c| c.addr)
                                    } else {
                                        None
                                    };
                                }

                                if let Some(win_addr) = winner {
                                    // Commit the latch.
                                    *probation_guard = None; // drop state
                                    drop(probation_guard);

                                    if win_addr != current_remote {
                                        *self.remote_addr.write() = win_addr;
                                    }
                                    self.rtp_latched.store(true, Ordering::Relaxed);
                                    tracing::info!(
                                        "IceConn: RTP latched to {} after probation \
                                         (expected_ssrc={}, total_obs={})",
                                        win_addr,
                                        expected,
                                        total
                                    );
                                }
                            } else {
                                // No probation state — immediate latch
                                // (legacy path for callers that never called
                                // `enable_latch_on_rtp`).
                                if addr != current_remote {
                                    *self.remote_addr.write() = addr;
                                }
                                self.rtp_latched.store(true, Ordering::Relaxed);
                                tracing::info!(
                                    "IceConn: RTP latched to {} immediately \
                                     (expected_ssrc={})",
                                    addr,
                                    expected
                                );
                            }
                        }
                    }
                }
            }
            let receiver = {
                let rx_lock = self.rtp_receiver.read();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                // Log once per connection when the first RTP packet arrives.
                let prev = self.rtp_rx_count.fetch_add(1, Ordering::Relaxed);
                if prev == 0 {
                    let label_str = self.label.as_deref().unwrap_or("unknown");
                    tracing::debug!(
                        "IceConn: first {} packet ({} bytes) from {} label={} — forwarding to RTP receiver",
                        if is_rtcp { "RTCP" } else { "RTP" },
                        packet.len(),
                        addr,
                        label_str,
                    );
                }
                strong_rx.receive(packet, addr).await;
            } else {
                tracing::debug!(
                    "IceConn: No RTP receiver registered for packet from {}",
                    addr
                );
            }
        }
    }
}

#[async_trait]
impl StatsProvider for IceConn {
    async fn collect(&self) -> RtcResult<Vec<StatsEntry>> {
        let rx_packets = self.rx_packets.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_packets = self.tx_packets.load(Ordering::Relaxed);
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let label = self.label.as_deref().unwrap_or("unknown");
        let id = StatsId::new(format!("ice-conn-{}", label));
        let entry = StatsEntry::new(id, StatsKind::Transport)
            .with_value("label", json!(label))
            .with_value("rxPackets", json!(rx_packets))
            .with_value("rxBytes", json!(rx_bytes))
            .with_value("txPackets", json!(tx_packets))
            .with_value("txBytes", json!(tx_bytes));
        Ok(vec![entry])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_ice_conn_send_rtcp_mux() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(Arc::new(socket));
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let conn = IceConn::new(rx, receiver_addr, None);

        // Send RTCP (via send_rtcp) -> should go to receiver_addr (default)
        conn.send_rtcp(b"hello").await.unwrap();

        let mut buf = [0u8; 1024];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[tokio::test]
    async fn test_ice_conn_send_rtcp_no_mux() {
        let rtp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rtp_socket_addr = rtp_socket.local_addr().unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(rtp_socket);
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let rtcp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rtcp_socket_addr = rtcp_socket.local_addr().unwrap();
        let rtcp_socket_wrapper = IceSocketWrapper::Udp(rtcp_socket);
        let (_rtcp_tx, rtcp_rx) = watch::channel(Some(rtcp_socket_wrapper));

        let rtp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_addr = rtp_receiver.local_addr().unwrap();

        let rtcp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtcp_addr = rtcp_receiver.local_addr().unwrap();

        let conn = IceConn::new_with_rtcp(rx, rtcp_rx, rtp_addr, None, None);
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        // Send RTP (via send) -> should go to rtp_addr
        conn.send(b"rtp").await.unwrap();
        let mut buf = [0u8; 1024];
        let (len, rtp_src) = rtp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtp");
        assert_eq!(rtp_src, rtp_socket_addr);

        // Send RTCP (via send_rtcp) -> should go to rtcp_addr from the RTCP socket.
        conn.send_rtcp(b"rtcp").await.unwrap();
        let (len, rtcp_src) = rtcp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtcp");
        assert_eq!(rtcp_src, rtcp_socket_addr);
    }

    struct NoopReceiver;

    #[async_trait]
    impl PacketReceiver for NoopReceiver {
        async fn receive(&self, _packet: Bytes, _addr: SocketAddr) {}
    }

    #[tokio::test]
    async fn test_ice_conn_latches_remote_addr_on_rtp() {
        let (_tx, rx) = watch::channel(None);
        let initial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let latched_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let conn = IceConn::new(rx, initial_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Use a valid 12-byte RTP packet with marker=true (bit 7 of byte 1).
        let pkt = Bytes::from_static(&[
            0x80, 0x80, // V=2, M=1 (marker set)
            0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0x01, // ts=1
            0x00, 0x00, 0x00, 0x01, // ssrc=1
        ]);
        conn.receive(pkt, latched_addr).await;

        assert_eq!(*conn.remote_addr.read(), latched_addr);
    }

    #[tokio::test]
    async fn test_rtcp_does_not_override_rtp_remote_addr() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let rtcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        // Use a valid 12-byte RTP packet with marker=true so probation resolves.
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        conn.receive(rtp_pkt, rtp_src).await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtcp_src)
            .await;

        assert_eq!(
            *conn.remote_addr.read(),
            rtp_src,
            "RTCP should not override RTP remote address"
        );
    }

    #[tokio::test]
    async fn test_rtcp_latches_rtcp_addr_in_non_mux_mode() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let initial_rtcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(initial_rtcp_addr));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        conn.receive(rtp_pkt, rtp_src).await;

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtcp_src)
            .await;

        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(rtcp_src),
            "RTCP should latch its own destination"
        );
        assert!(conn.rtcp_latched.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_rtcp_does_not_re_latch_after_locked() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001)));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        conn.receive(rtp_pkt, rtp_src).await;

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtcp_src)
            .await;
        assert_eq!(*conn.remote_rtcp_addr.read(), Some(rtcp_src));

        let rogue_rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6001);
        conn.receive(
            Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]),
            rogue_rtcp_src,
        )
        .await;

        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(rtcp_src),
            "RTCP should not re-latch after already latched"
        );
    }

    #[tokio::test]
    async fn test_rtcp_ignored_in_mux_mode() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        conn.receive(rtp_pkt, rtp_src).await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);

        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtp_src)
            .await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);
        assert!(
            conn.remote_rtcp_addr.read().is_none(),
            "RTCP address should remain None in mux mode"
        );
    }

    #[tokio::test]
    async fn test_ssrc_based_latch_ignores_port_mismatch() {
        // Simulates the VoLTE/NAT scenario: the answer SDP advertises
        // remote port 4162, but real RTP arrives from port 17687.
        // Latching should succeed because the SSRC matches.
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.17.230.54:4162".parse().unwrap();
        let real_addr: SocketAddr = "112.96.43.157:17687".parse().unwrap();
        let expected_ssrc: u32 = 787_088_145;

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(expected_ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Build a minimal 12-byte RTP packet with the matching SSRC.
        let mut pkt = vec![0x80u8, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0];
        pkt.extend_from_slice(&expected_ssrc.to_be_bytes()); // bytes 8-11

        // Send a second packet (seq=0x1099) to get consecutive_count=1,
        // then a third to trigger consecutive_count>=2 with total>=3.
        let mut pkt2 = vec![0x80u8, 0x00, 0x10, 0x99, 0x00, 0x00, 0x00, 0xa1];
        pkt2.extend_from_slice(&expected_ssrc.to_be_bytes());
        conn.receive(Bytes::from(pkt.clone()), real_addr).await;
        conn.receive(Bytes::from(pkt2.clone()), real_addr).await;

        // Third packet: seq=0x109a
        let mut pkt3 = vec![0x80u8, 0x00, 0x10, 0x9a, 0x00, 0x00, 0x00, 0xa2];
        pkt3.extend_from_slice(&expected_ssrc.to_be_bytes());
        conn.receive(Bytes::from(pkt3), real_addr).await;

        assert_eq!(
            *conn.remote_addr.read(),
            real_addr,
            "Should latch to real NAT address when SSRC matches"
        );
        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "rtp_latched should be set after SSRC match"
        );
    }

    #[tokio::test]
    async fn test_ssrc_based_latch_ignores_wrong_ssrc() {
        // A stray packet with a different SSRC should not trigger latching.
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.17.230.54:4162".parse().unwrap();
        let rogue_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let expected_ssrc: u32 = 787_088_145;
        let wrong_ssrc: u32 = 99_999_999;

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(expected_ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut pkt = vec![0x80u8, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0];
        pkt.extend_from_slice(&wrong_ssrc.to_be_bytes());

        conn.receive(Bytes::from(pkt), rogue_addr).await;

        assert_eq!(
            *conn.remote_addr.read(),
            sdp_addr,
            "Should NOT latch when SSRC does not match"
        );
        assert!(
            !conn.rtp_latched.load(Ordering::Relaxed),
            "rtp_latched should remain false for wrong SSRC"
        );
    }

    #[tokio::test]
    async fn test_address_based_latch_fallback_when_no_expected_ssrc() {
        // When no expected SSRC is configured, latching falls back to
        // the original address-mismatch logic (current behaviour).
        let (_tx, rx) = watch::channel(None);
        let initial_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let new_addr: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        let conn = IceConn::new(rx, initial_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        // expected_ssrc stays 0 — no SDP SSRC hint

        // Send 3 sequential packets to trigger consecutive_count >= 2
        for seq in 1u16..=3 {
            let pkt = Bytes::from(vec![
                0x80,
                0x00,
                (seq >> 8) as u8,
                seq as u8,
                0x00,
                0x00,
                0x00,
                seq as u8,
                0x00,
                0x00,
                0x01,
                0x23,
            ]);
            conn.receive(pkt, new_addr).await;
        }

        assert_eq!(*conn.remote_addr.read(), new_addr);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));
    }

    // ── Probation-specific tests ───────────────────────────────────────────

    /// Reproduce the Wireshark scenario: port 4114 sends seq=21466 first,
    /// then port 4014 sends seq=21465 with marker=true.  The latch MUST
    /// resolve to port 4014.
    #[tokio::test]
    async fn test_probation_marker_wins_over_first_arriving_packet() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "223.104.80.120:4000".parse().unwrap();
        let port_4114: SocketAddr = "223.104.80.120:4114".parse().unwrap();
        let port_4014: SocketAddr = "223.104.80.120:4014".parse().unwrap();
        let ssrc: u32 = 0x6c0d_1ca5;

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Frame 508072: port 4114, seq=21466, marker=false  (arrives first)
        let mut pkt_4114 = vec![0x80u8, 0x08, 0x53, 0xCA, 0x00, 0x00, 0x00, 0xA0];
        pkt_4114.extend_from_slice(&ssrc.to_be_bytes());
        conn.receive(Bytes::from(pkt_4114), port_4114).await;

        // Latch should NOT have fired yet (only 1 packet, no marker)
        assert!(
            !conn.rtp_latched.load(Ordering::Relaxed),
            "Should not latch after just one packet with no marker"
        );

        // Frame 508078: port 4014, seq=21465 (lower!), marker=true  (real start)
        let mut pkt_4014 = vec![0x80u8, 0x88, 0x53, 0xC9, 0x00, 0x00, 0x00, 0xA0];
        pkt_4014.extend_from_slice(&ssrc.to_be_bytes());
        conn.receive(Bytes::from(pkt_4014), port_4014).await;

        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "Should latch after marker packet"
        );
        assert_eq!(
            *conn.remote_addr.read(),
            port_4014,
            "Should latch to port 4014 (marker=true), not port 4114 (first arrived)"
        );
    }

    /// When a single source sends consecutively, it wins by dominance rule
    /// even without a marker bit.
    #[tokio::test]
    async fn test_probation_consecutive_dominance() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let real_src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let stray_src: SocketAddr = "10.0.0.1:5001".parse().unwrap();

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // One stray packet from a different port
        let stray = Bytes::from(vec![
            0x80, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02,
        ]);
        conn.receive(stray, stray_src).await;

        // Three consecutive packets from real source (seq 1,2,3)
        for seq in 1u16..=3 {
            let pkt = Bytes::from(vec![
                0x80, 0x00, 0x00, seq as u8, 0x00, 0x00, 0x00, seq as u8, 0x00, 0x00, 0x00, 0x01,
            ]);
            conn.receive(pkt, real_src).await;
        }

        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "Should latch after consecutive dominance"
        );
        assert_eq!(
            *conn.remote_addr.read(),
            real_src,
            "Should latch to the source with consecutive packets"
        );
    }

    /// After PROBATION_MAX_PACKETS total observations with no clear winner,
    /// the candidate with most packets wins (fallback rule).
    #[tokio::test]
    async fn test_probation_timeout_fallback_selects_dominant() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let dominant: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let minor: SocketAddr = "10.0.0.1:5001".parse().unwrap();

        let probation_max = 6u8;
        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(probation_max));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Send 1 non-sequential packet from the minor source
        let minor_pkt = Bytes::from(vec![
            0x80, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02,
        ]);
        conn.receive(minor_pkt, minor).await;

        // Send (probation_max - 1) non-sequential packets from dominant
        for i in 0..(probation_max - 1) {
            // Use non-sequential seq values (skip every other) to avoid
            // triggering the consecutive-dominance rule.
            let seq = (i * 2 + 10) as u8;
            let pkt = Bytes::from(vec![
                0x80, 0x00, 0x00, seq, 0x00, 0x00, 0x00, seq, 0x00, 0x00, 0x00, 0x01,
            ]);
            conn.receive(pkt, dominant).await;
        }

        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "Should latch after PROBATION_MAX_PACKETS total packets"
        );
        assert_eq!(
            *conn.remote_addr.read(),
            dominant,
            "Should latch to source with most packets"
        );
    }

    /// Once latched, subsequent packets from a different address must NOT
    /// change the latched remote.  Latch is sticky until reset_latch().
    #[tokio::test]
    async fn test_probation_latch_is_sticky_after_commit() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let good_src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let rogue_src: SocketAddr = "10.0.0.1:6000".parse().unwrap();

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Latch to good_src via marker
        let pkt = Bytes::from(vec![
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        conn.receive(pkt, good_src).await;
        assert!(conn.rtp_latched.load(Ordering::Relaxed));
        assert_eq!(*conn.remote_addr.read(), good_src);

        // Rogue source sends packets — addr must not change
        for seq in 2u8..=5 {
            let rogue_pkt = Bytes::from(vec![
                0x80, 0x00, 0x00, seq, 0x00, 0x00, 0x00, seq, 0x00, 0x00, 0x00, 0x99,
            ]);
            conn.receive(rogue_pkt, rogue_src).await;
        }
        assert_eq!(
            *conn.remote_addr.read(),
            good_src,
            "Latched address must not change after latch is committed"
        );
    }

    /// reset_latch() clears the latch so a new source can be selected
    /// (used on re-INVITE).
    #[tokio::test]
    async fn test_reset_latch_allows_re_latching() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first_src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let second_src: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let pkt = Bytes::from(vec![
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        conn.receive(pkt.clone(), first_src).await;
        assert_eq!(*conn.remote_addr.read(), first_src);

        conn.reset_latch();
        assert!(!conn.rtp_latched.load(Ordering::Relaxed));

        // After reset, the new source with marker should win
        let pkt2 = Bytes::from(vec![
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
        ]);
        conn.receive(pkt2, second_src).await;
        assert_eq!(
            *conn.remote_addr.read(),
            second_src,
            "Should re-latch to new source after reset_latch()"
        );
    }
}
