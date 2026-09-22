use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::net::UdpSocket;

/// Configuration for UDPTL transport.
#[derive(Debug, Clone)]
pub struct UdtlConfig {
    /// Maximum number of redundant packets to include (FEC depth).
    pub redundancy_depth: u8,
    /// Even-parity FEC group size (0 = redundancy mode, 2-4 = FEC mode).
    pub fec_group: u8,
    /// Maximum buffer size for received out-of-order packets.
    pub max_buffer: u16,
    /// Maximum datagram size in bytes.
    pub max_datagram: u16,
}

impl Default for UdtlConfig {
    fn default() -> Self {
        Self {
            redundancy_depth: 2,
            fec_group: 0,
            max_buffer: 1024,
            max_datagram: 1400,
        }
    }
}

/// UDPTL transport for T.38 fax (RFC 3362).
///
/// Implements the UDP Transport Layer with redundancy-based error correction.
pub struct UdtlTransport {
    socket: Arc<UdpSocket>,
    local_seq: AtomicU16,
    remote_addr: std::sync::Mutex<SocketAddr>,
    config: UdtlConfig,
    /// History of sent IFP packets for generating redundancy.
    send_history: tokio::sync::Mutex<VecDeque<SentPacket>>,
    /// Pending FEC group: (seq, data) pairs awaiting parity emission.
    fec_group: tokio::sync::Mutex<Vec<(u16, Bytes)>>,
}

struct SentPacket {
    #[allow(dead_code)]
    seq: u16,
    data: Bytes,
}

impl UdtlTransport {
    /// Create a new UDPTL transport bound to a local socket for communication
    /// with the given remote address.
    pub fn new(socket: Arc<UdpSocket>, remote_addr: SocketAddr) -> Self {
        Self {
            socket,
            local_seq: AtomicU16::new(1),
            remote_addr: std::sync::Mutex::new(remote_addr),
            config: UdtlConfig::default(),
            send_history: tokio::sync::Mutex::new(VecDeque::new()),
            fec_group: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Create a UDPTL transport with a custom config.
    pub fn with_config(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        config: UdtlConfig,
    ) -> Self {
        Self {
            socket,
            local_seq: AtomicU16::new(1),
            remote_addr: std::sync::Mutex::new(remote_addr),
            config,
            send_history: tokio::sync::Mutex::new(VecDeque::new()),
            fec_group: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Send an IFP packet to the remote peer with redundancy.
    pub async fn send(&self, ifp_data: &[u8]) -> Result<(), crate::errors::RtcError> {
        if ifp_data.len() > 255 {
            return Err(crate::errors::RtcError::Transport(format!(
                "IFP packet too large for UDPTL: {} bytes",
                ifp_data.len()
            )));
        }
        let seq = self.local_seq.fetch_add(1, Ordering::SeqCst);

        // Single allocation: header + primary + redundancy. The history entry
        // is a zero-copy slice of this buffer.
        let mut packet = BytesMut::with_capacity(ifp_data.len() + 8);
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[ifp_data.len() as u8]);
        let primary_start = packet.len();
        packet.extend_from_slice(ifp_data);
        let primary_end = packet.len();

        let fec_mode = self.config.fec_group >= 2;
        let mut history = self.send_history.lock().await;
        let mut fec_group = self.fec_group.lock().await;
        if fec_mode {
            while fec_group.len() >= self.config.fec_group as usize {
                fec_group.remove(0);
            }
            fec_group.push((seq, Bytes::copy_from_slice(ifp_data)));
            if fec_group.len() == self.config.fec_group as usize {
                let parity = parity_frame(&fec_group.iter().map(|(_, d)| d).collect::<Vec<_>>());
                packet.extend_from_slice(&[0x80]);
                packet.extend_from_slice(&seq.to_be_bytes());
                packet.extend_from_slice(&[self.config.fec_group]);
                packet.extend_from_slice(&parity);
            }
        } else {
            while history.len() as u8 > self.config.redundancy_depth {
                history.pop_front();
            }
            if !history.is_empty() {
                packet.extend_from_slice(&[0x00, history.len() as u8]);
                for sent in history.iter() {
                    packet.extend_from_slice(&[sent.data.len() as u8]);
                    packet.extend_from_slice(&sent.data);
                }
            }
        }

        let frozen = packet.freeze();
        let primary = frozen.slice(primary_start..primary_end);
        history.push_back(SentPacket { seq, data: primary });

        let remote_addr = *self.remote_addr.lock().unwrap_or_else(|p| p.into_inner());
        self.socket
            .send_to(&frozen, remote_addr)
            .await
            .map_err(|e| crate::errors::RtcError::Transport(format!("UDPTL send failed: {e}")))?;

        Ok(())
    }

    /// Update the remote address (e.g. once the answer SDP carries the
    /// peer's media address).
    pub fn set_remote_addr(&self, addr: SocketAddr) {
        *self.remote_addr.lock().unwrap_or_else(|p| p.into_inner()) = addr;
    }

    /// Receive a UDPTL packet, returning the primary IFP data after
    /// attempting to recover from packet loss.
    pub async fn recv(
        &self,
        recv_buf: &mut UdtlReceiveBuffer,
    ) -> Result<Option<Bytes>, crate::errors::RtcError> {
        if let Some(data) = recv_buf.take_ready() {
            return Ok(Some(data));
        }

        let mut buf = vec![0u8; self.config.max_datagram as usize];
        let (n, _from) =
            self.socket.recv_from(&mut buf).await.map_err(|e| {
                crate::errors::RtcError::Transport(format!("UDPTL recv failed: {e}"))
            })?;

        if n < 3 {
            return Ok(None);
        }

        // One copy from the kernel buffer; everything downstream slices it.
        let datagram = Bytes::copy_from_slice(&buf[..n]);

        let mut pos = 0usize;
        let seq = u16::from_be_bytes([datagram[0], datagram[1]]);
        pos += 2;

        let primary_len = datagram[pos] as usize;
        pos += 1;
        if pos + primary_len > n {
            return Ok(None);
        }
        let primary_data = datagram.slice(pos..pos + primary_len);
        pos += primary_len;

        let mut redundant: Vec<(u16, Bytes)> = Vec::new();
        if pos < n {
            let indicator = datagram[pos];
            pos += 1;
            if indicator == 0x00 {
                let count = if pos < n {
                    let c = datagram[pos] as usize;
                    pos += 1;
                    c
                } else {
                    0
                };
                if count > 0 {
                    let first_seq = seq.wrapping_sub(count as u16);
                    for (i, slot) in redundant.iter_mut().enumerate() {
                        if pos >= n {
                            break;
                        }
                        let len = datagram[pos] as usize;
                        pos += 1;
                        if pos + len > n {
                            break;
                        }
                        slot.0 = first_seq.wrapping_add(i as u16);
                        slot.1 = datagram.slice(pos..pos + len);
                        pos += len;
                    }
                }
            } else if indicator == 0x80 && pos + 3 <= n {
                let fec = FecData {
                    highest_seq: u16::from_be_bytes([datagram[pos], datagram[pos + 1]]),
                    count: datagram[pos + 2],
                    parity: datagram.slice(pos + 3..n),
                };
                recv_buf.try_deliver_fec(fec);
            }
        }

        recv_buf.try_deliver(seq, primary_data, redundant)
    }

    /// Return the local socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, crate::errors::RtcError> {
        self.socket
            .local_addr()
            .map_err(|e| crate::errors::RtcError::Transport(format!("local_addr failed: {e}")))
    }

    /// Current sequence number (for stats/diagnostics).
    pub fn current_seq(&self) -> u16 {
        self.local_seq.load(Ordering::SeqCst)
    }

    /// Set the config (useful for renegotiation).
    pub fn set_config(&mut self, config: UdtlConfig) {
        self.config = config;
    }

    /// Get the socket reference.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

fn parity_frame(frames: &[&Bytes]) -> Bytes {
    let max_len = frames.iter().map(|f| f.len()).max().unwrap_or(0);
    let mut parity = vec![0u8; max_len];
    for f in frames {
        for (i, byte) in f.iter().enumerate() {
            parity[i] ^= byte;
        }
    }
    Bytes::from(parity)
}

fn last_delivered_covers(high: u16, last_delivered: Option<u16>) -> bool {
    match last_delivered {
        None => false,
        Some(d) => high.wrapping_sub(d) < 0x8000 && d < high,
    }
}

/// FEC group descriptor carried in a UDPTL packet with the 0x80 indicator.
pub struct FecData {
    /// The sequence number of the highest frame in the group.
    pub highest_seq: u16,
    /// The number of frames in the group.
    pub count: u8,
    /// The even-parity frame over the group.
    pub parity: Bytes,
}

/// Packet grouping for receive buffering.
#[derive(Debug)]
pub struct UdtlReceiveBuffer {
    /// Expected next sequence number.
    expected_seq: u16,
    /// Buffer for out-of-order packets: seq -> data.
    buffer: std::collections::BTreeMap<u16, Bytes>,
    /// Packets recovered from redundancy, awaiting delivery.
    ready: std::collections::VecDeque<Bytes>,
    /// Received primary frames of the current FEC group.
    fec_received: std::collections::BTreeMap<u16, Bytes>,
    /// The latest FEC parity frame.
    fec_parity: Option<(u16, u8, Bytes)>,
    /// Maximum buffer size.
    max_size: u16,
    /// Statistics
    pub packets_received: u64,
    pub packets_lost: u64,
    pub packets_recovered: u64,
    /// Last successfully delivered seq
    pub last_delivered_seq: Option<u16>,
}

impl Default for UdtlReceiveBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl UdtlReceiveBuffer {
    pub fn new() -> Self {
        Self {
            expected_seq: 1,
            buffer: std::collections::BTreeMap::new(),
            ready: std::collections::VecDeque::new(),
            fec_received: std::collections::BTreeMap::new(),
            fec_parity: None,
            max_size: 128,
            packets_received: 0,
            packets_lost: 0,
            packets_recovered: 0,
            last_delivered_seq: None,
        }
    }

    pub fn with_max_size(max_size: u16) -> Self {
        Self {
            max_size,
            ..Self::new()
        }
    }

    /// Record the parity frame of an FEC group.
    pub fn try_deliver_fec(&mut self, fec: FecData) {
        self.fec_parity = Some((fec.highest_seq, fec.count, fec.parity));
    }

    /// Try to deliver a packet, possibly using redundant packets to fill gaps.
    /// Returns the next available IFP data, or None if no complete data is available.
    pub fn try_deliver(
        &mut self,
        seq: u16,
        primary: Bytes,
        redundant: Vec<(u16, Bytes)>,
    ) -> Result<Option<Bytes>, crate::errors::RtcError> {
        self.packets_received += 1;
        self.fec_received.insert(seq, primary.clone());
        if let Some((high, count, parity)) = self.fec_parity.clone() {
            let first = high.wrapping_sub(count as u16 - 1);
            let last = high;
            let in_group = self
                .fec_received
                .range(first..=last)
                .map(|(s, d)| (*s, d.clone()))
                .collect::<Vec<_>>();
            let received_count = in_group.len();
            if received_count + 1 >= count as usize
                && last_delivered_covers(last, self.last_delivered_seq)
            {
                let mut acc: Option<Bytes> = None;
                for (_, d) in &in_group {
                    acc = Some(match acc {
                        None => d.clone(),
                        Some(prev) => {
                            let len = prev.len().max(d.len());
                            let mut x = vec![0u8; len];
                            for (i, byte) in prev.iter().enumerate() {
                                x[i] ^= byte;
                            }
                            for (i, byte) in d.iter().enumerate() {
                                x[i] ^= byte;
                            }
                            Bytes::from(x)
                        }
                    });
                }
                if let Some(acc) = acc {
                    for s in first..=last {
                        if !in_group.iter().any(|(rs, _)| *rs == s) {
                            let mut rec: Vec<u8> = parity
                                .iter()
                                .chain(std::iter::repeat(&0u8))
                                .take(acc.len())
                                .copied()
                                .collect();
                            for (i, byte) in acc.iter().enumerate() {
                                rec[i] ^= byte;
                            }
                            self.ready.push_back(Bytes::from(rec));
                            self.packets_recovered += 1;
                            break;
                        }
                    }
                    self.fec_received.retain(|s, _| *s > last);
                }
            }
        }

        let first_ever =
            self.last_delivered_seq.is_none() && self.buffer.is_empty() && self.ready.is_empty();
        if first_ever {
            self.expected_seq = seq;
        }

        for (rseq, data) in redundant {
            if !self.is_past(rseq)
                && !self.buffer.contains_key(&rseq)
                && (self.buffer.len() as u16) < self.max_size
            {
                self.buffer.insert(rseq, data);
            }
        }

        if self.is_past(seq) {
            return Ok(None);
        }

        if !self.buffer.contains_key(&seq) && (self.buffer.len() as u16) < self.max_size {
            self.buffer.insert(seq, primary);
        }

        let mut delivered: Option<Bytes> = None;
        while let Some(data) = self.buffer.remove(&self.expected_seq) {
            if delivered.is_none() {
                delivered = Some(data);
            } else {
                self.ready.push_back(data);
                self.packets_recovered += 1;
            }
            self.expected_seq = self.expected_seq.wrapping_add(1);
            self.last_delivered_seq = Some(self.expected_seq.wrapping_sub(1));
        }

        self.cleanup_stale();
        Ok(delivered)
    }

    fn is_past(&self, seq: u16) -> bool {
        let diff = self.expected_seq.wrapping_sub(seq);
        diff != 0 && diff < 32768
    }

    pub fn take_ready(&mut self) -> Option<Bytes> {
        self.ready.pop_front()
    }

    /// Remove stale entries and count gaps as lost.
    fn cleanup_stale(&mut self) {
        let max_gap = 32u16;
        let mut early = Vec::new();
        for (&seq, _) in self.buffer.range(self.expected_seq..) {
            let gap = seq.wrapping_sub(self.expected_seq);
            if gap >= max_gap && gap < 32768 {
                early.push(seq);
            }
        }
        for seq in early {
            self.buffer.remove(&seq);
            self.packets_lost += 1;
        }
    }

    /// Reset the buffer with a new expected sequence number.
    pub fn reset(&mut self, expected_seq: u16) {
        self.expected_seq = expected_seq;
        self.buffer.clear();
        self.ready.clear();
        self.last_delivered_seq = None;
    }

    /// Current expected sequence number.
    pub fn expected_seq(&self) -> u16 {
        self.expected_seq
    }

    /// Number of buffered out-of-order packets.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}

unsafe impl Send for UdtlTransport {}
unsafe impl Sync for UdtlTransport {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udtl_receive_buffer_in_order() {
        let mut buf = UdtlReceiveBuffer::new();
        let result = buf
            .try_deliver(1, Bytes::from(vec![0x01, 0x02]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from_static(&[0x01, 0x02])));
        assert_eq!(buf.expected_seq, 2);
    }

    #[test]
    fn test_udtl_receive_buffer_out_of_order() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, Bytes::from(vec![0x01, 0x02]), vec![])
            .unwrap();
        let result = buf
            .try_deliver(3, Bytes::from(vec![0x05, 0x06]), vec![])
            .unwrap();
        assert_eq!(result, None);
        assert_eq!(buf.buffered_count(), 1);

        let result = buf
            .try_deliver(2, Bytes::from(vec![0x03, 0x04]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from(vec![0x03, 0x04])));
        assert_eq!(buf.take_ready(), Some(Bytes::from_static(&[0x05, 0x06])));
        assert_eq!(buf.expected_seq, 4);
        assert_eq!(buf.buffered_count(), 0);
    }

    #[test]
    fn test_udtl_receive_buffer_duplicate() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap();
        // Same seq again
        let result = buf
            .try_deliver(1, Bytes::from_static(&[0x02]), vec![])
            .unwrap();
        assert_eq!(result, None);
        assert_eq!(buf.expected_seq, 2);
    }

    #[test]
    fn test_udtl_receive_buffer_too_old() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(5, Bytes::from_static(&[0x05]), vec![])
            .unwrap();
        assert_eq!(buf.expected_seq, 6);

        let result = buf
            .try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap();
        assert_eq!(result, None);
        assert_eq!(buf.expected_seq, 6);
    }

    #[test]
    fn test_udtl_receive_buffer_gap_recovery() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap();
        assert_eq!(buf.expected_seq, 2);

        // Deliver 3 (skip 2)
        buf.try_deliver(3, Bytes::from_static(&[0x03]), vec![])
            .unwrap();
        assert_eq!(buf.buffered_count(), 1);

        // Deliver 2
        let result = buf
            .try_deliver(2, Bytes::from_static(&[0x02]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from_static(&[0x02])));
        // After receiving 2, we should flush 3 too
        assert_eq!(buf.expected_seq, 4);
        assert_eq!(buf.buffered_count(), 0);
    }

    #[test]
    fn test_udtl_sequence_wrapping() {
        let mut buf = UdtlReceiveBuffer::with_max_size(256);
        buf.expected_seq = 65530;
        buf.last_delivered_seq = Some(65529);

        // In-order: 65530
        let result = buf
            .try_deliver(65530, Bytes::from_static(&[0x01]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from_static(&[0x01])));
        assert_eq!(buf.expected_seq, 65531);

        // Next: 65531
        let result = buf
            .try_deliver(65531, Bytes::from_static(&[0x02]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from_static(&[0x02])));
        assert_eq!(buf.expected_seq, 65532);

        // Now wrap around: 65532 -> 0 (via wrapping_add)
        // Actually, wrapping_add(65532, 1) = 65533, wrapping_add(65535, 1) = 0
        // Let me send a few more
        buf.expected_seq = 65535;
        let result = buf
            .try_deliver(65535, Bytes::from_static(&[0x03]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from_static(&[0x03])));

        // Now expected should wrap to 0
        assert_eq!(buf.expected_seq, 0);

        // Deliver seq 0
        let result = buf
            .try_deliver(0, Bytes::from_static(&[0x04]), vec![])
            .unwrap();
        assert_eq!(result, Some(Bytes::from_static(&[0x04])));
        assert_eq!(buf.expected_seq, 1);
    }

    #[test]
    fn test_send_history_pruning() {
        // This test checks the send history logic without actual network I/O
        let config = UdtlConfig {
            redundancy_depth: 2,
            ..UdtlConfig::default()
        };

        let mut history: VecDeque<SentPacket> = VecDeque::new();

        for i in 0..5u16 {
            // Simulate the send history pruning
            while history.len() as u8 > config.redundancy_depth {
                history.pop_front();
            }
            history.push_back(SentPacket {
                seq: i,
                data: Bytes::from(vec![i as u8]),
            });
        }

        assert_eq!(history.len(), 3); // last 3 should remain (depth 2 means keep 2 + current)
        assert_eq!(history[0].seq, 2);
        assert_eq!(history[1].seq, 3);
        assert_eq!(history[2].seq, 4);
    }

    #[test]
    fn test_cleanup_stale_removes_old_packets() {
        let mut buf = UdtlReceiveBuffer::new();

        // Deliver some in-order packets first to advance expected_seq
        buf.try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap();
        assert_eq!(buf.expected_seq, 2);
        buf.try_deliver(2, Bytes::from_static(&[0x02]), vec![])
            .unwrap();
        buf.try_deliver(3, Bytes::from_static(&[0x03]), vec![])
            .unwrap();
        buf.try_deliver(4, Bytes::from_static(&[0x04]), vec![])
            .unwrap();
        assert_eq!(buf.expected_seq, 5);

        // Buffer packet 100 (gap of 95, way beyond max_gap of 32)
        buf.try_deliver(100, Bytes::from_static(&[0x64]), vec![])
            .unwrap();
        assert_eq!(buf.buffered_count(), 0);
        assert_eq!(buf.packets_lost, 1);

        buf.try_deliver(5, Bytes::from_static(&[0x05]), vec![])
            .unwrap();
        assert_eq!(buf.expected_seq, 6);
        assert_eq!(buf.buffered_count(), 0);
    }

    #[test]
    fn test_reset_buffer() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap();
        buf.try_deliver(3, Bytes::from_static(&[0x03]), vec![])
            .unwrap();
        assert_eq!(buf.buffered_count(), 1);

        buf.reset(10);
        assert_eq!(buf.expected_seq, 10);
        assert_eq!(buf.buffered_count(), 0);
    }

    #[test]
    fn test_packet_stats_tracking() {
        let mut buf = UdtlReceiveBuffer::new();

        buf.try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap(); // delivered
        buf.try_deliver(3, Bytes::from_static(&[0x03]), vec![])
            .unwrap(); // buffered
        buf.try_deliver(2, Bytes::from_static(&[0x02]), vec![])
            .unwrap(); // delivered (and flushes seq 3)
        buf.try_deliver(1, Bytes::from_static(&[0x01]), vec![])
            .unwrap(); // duplicate - ignored

        assert_eq!(buf.packets_received, 4);
        assert_eq!(buf.last_delivered_seq, Some(3));
    }
}

#[cfg(test)]
mod fec_tests {
    use super::*;

    #[test]
    fn parity_frame_xor() {
        let f1 = Bytes::from(vec![0x0F, 0x00, 0xAA]);
        let f2 = Bytes::from(vec![0xF0, 0x0F, 0xAA]);
        let f3 = Bytes::from(vec![0x00, 0xFF, 0x00]);
        let p = parity_frame(&[&f1, &f2, &f3]);
        assert_eq!(p.as_ref(), &[0xFF, 0xF0, 0x00]);
    }

    #[tokio::test]
    async fn fec_group_send_shape() {
        let remote: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut cfg = UdtlConfig::default();
        cfg.fec_group = 3;
        cfg.redundancy_depth = 0;
        let transport = UdtlTransport::with_config(socket, remote, cfg);

        for i in 0..3u8 {
            transport.send(&vec![0xA0 + i; 6]).await.unwrap();
        }

        let group = transport.fec_group.lock().await;
        assert_eq!(group.len(), 3);
        assert_eq!(group[0].0, 1);
        let frames: Vec<&Bytes> = group.iter().map(|(_, d)| d).collect();
        let parity = parity_frame(&frames);
        assert_eq!(parity.as_ref(), vec![0xA0 ^ 0xA1 ^ 0xA2; 6].as_slice());
    }

    #[tokio::test]
    async fn fec_recovers_single_loss() {
        let f1 = Bytes::from(vec![0x11, 0x22]);
        let f2 = Bytes::from(vec![0xAA, 0xBB]);
        let f3 = Bytes::from(vec![0x33, 0x44]);
        let parity = parity_frame(&[&f1, &f2, &f3]);
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver_fec(FecData {
            highest_seq: 3,
            count: 3,
            parity: parity.clone(),
        });
        assert!(
            buf.try_deliver(1, f1.clone(), Vec::new())
                .unwrap()
                .is_some()
        );
        let mid = buf.try_deliver(3, f3.clone(), Vec::new()).unwrap();
        assert!(mid.is_none(), "seq 3 arrives early, must buffer");
        let first = buf.take_ready();
        assert_eq!(first.as_ref(), Some(&f2), "recovered missing f2");
        let mut buf = buf;
        let _ = buf;
    }

    #[tokio::test]
    async fn fec_mode_no_redundancy_indicator() {
        let remote: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut cfg = UdtlConfig::default();
        cfg.fec_group = 2;
        cfg.redundancy_depth = 0;
        let transport = UdtlTransport::with_config(socket, remote, cfg);

        transport.send(&[1, 2, 3]).await.unwrap();
        transport.send(&[4, 5, 6]).await.unwrap();

        let group = transport.fec_group.lock().await;
        assert_eq!(group.len(), 2);
        assert_eq!(group[0].1.as_ref(), &[1, 2, 3]);
        assert_eq!(group[1].1.as_ref(), &[4, 5, 6]);
    }
}
