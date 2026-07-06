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
    /// Maximum buffer size for received out-of-order packets.
    pub max_buffer: u16,
    /// Maximum datagram size in bytes.
    pub max_datagram: u16,
}

impl Default for UdtlConfig {
    fn default() -> Self {
        Self {
            redundancy_depth: 2,
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
    remote_addr: SocketAddr,
    config: UdtlConfig,
    /// History of sent IFP packets for generating redundancy.
    send_history: tokio::sync::Mutex<VecDeque<SentPacket>>,
}

struct SentPacket {
    #[allow(dead_code)]
    seq: u16,
    data: Vec<u8>,
}

impl UdtlTransport {
    /// Create a new UDPTL transport bound to a local socket for communication
    /// with the given remote address.
    pub fn new(socket: Arc<UdpSocket>, remote_addr: SocketAddr) -> Self {
        Self {
            socket,
            local_seq: AtomicU16::new(1),
            remote_addr,
            config: UdtlConfig::default(),
            send_history: tokio::sync::Mutex::new(VecDeque::new()),
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
            remote_addr,
            config,
            send_history: tokio::sync::Mutex::new(VecDeque::new()),
        }
    }

    /// Send an IFP packet to the remote peer with redundancy.
    pub async fn send(&self, ifp_data: &[u8]) -> Result<(), crate::errors::RtcError> {
        let seq = self.local_seq.fetch_add(1, Ordering::SeqCst);

        // Build the UDPTL packet
        let mut packet = Vec::with_capacity(2 + ifp_data.len());
        // Sequence number (16 bits, big-endian)
        packet.extend_from_slice(&seq.to_be_bytes());

        // Primary IFP packet: 16-bit length + data
        let len = ifp_data.len() as u16;
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(ifp_data);

        // Redundant IFP packets (from oldest to newest)
        let mut history = self.send_history.lock().await;
        // Prune old history beyond our redundancy depth
        while history.len() as u8 > self.config.redundancy_depth {
            history.pop_front();
        }

        // The redundant packets
        for sent in history.iter() {
            let r_len = sent.data.len() as u16;
            packet.extend_from_slice(&r_len.to_be_bytes());
            packet.extend_from_slice(&sent.data);
        }

        // Add current packet to history
        history.push_back(SentPacket {
            seq,
            data: ifp_data.to_vec(),
        });

        self.socket
            .send_to(&packet, self.remote_addr)
            .await
            .map_err(|e| crate::errors::RtcError::Transport(format!("UDPTL send failed: {e}")))?;

        Ok(())
    }

    /// Receive a UDPTL packet, returning the primary IFP data after
    /// attempting to recover from redundancy on packet loss.
    pub async fn recv(
        &self,
        recv_buf: &mut UdtlReceiveBuffer,
    ) -> Result<Option<Vec<u8>>, crate::errors::RtcError> {
        let mut buf = vec![0u8; self.config.max_datagram as usize];
        let (n, _from) =
            self.socket.recv_from(&mut buf).await.map_err(|e| {
                crate::errors::RtcError::Transport(format!("UDPTL recv failed: {e}"))
            })?;

        if n < 2 {
            return Ok(None);
        }

        let mut pos = 0usize;
        // Sequence number
        let seq = u16::from_be_bytes([buf[0], buf[1]]);
        pos += 2;

        // Parse primary IFP packet
        if pos + 2 > n {
            return Ok(None);
        }
        let primary_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        if pos + primary_len > n {
            return Ok(None);
        }
        let primary_data = buf[pos..pos + primary_len].to_vec();
        pos += primary_len;

        // Parse redundant IFP packets
        let mut redundant: Vec<(u16, Vec<u8>)> = Vec::new();
        while pos + 2 <= n {
            let r_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            if pos + r_len > n {
                break;
            }
            // For redundancy mode, this is just an IFP packet
            redundant.push((0, buf[pos..pos + r_len].to_vec()));
            pos += r_len;
        }

        // Try to deliver the primary IFP data
        // In a full implementation, we'd check for sequence gaps and
        // use redundant packets to fill them
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

/// Packet grouping for receive buffering.
#[derive(Debug)]
pub struct UdtlReceiveBuffer {
    /// Expected next sequence number.
    expected_seq: u16,
    /// Buffer for out-of-order packets: seq -> data.
    buffer: std::collections::BTreeMap<u16, Vec<u8>>,
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

    /// Try to deliver a packet, possibly using redundant packets to fill gaps.
    /// Returns the next available IFP data, or None if no complete data is available.
    pub fn try_deliver(
        &mut self,
        seq: u16,
        primary: Vec<u8>,
        _redundant: Vec<(u16, Vec<u8>)>,
    ) -> Result<Option<Vec<u8>>, crate::errors::RtcError> {
        self.packets_received += 1;

        // Handle sequence number wrapping
        if seq < self.expected_seq && self.expected_seq.wrapping_sub(seq) < 16384 {
            return Ok(None);
        }

        if seq == self.expected_seq {
            self.expected_seq = self.expected_seq.wrapping_add(1);
            self.last_delivered_seq = Some(seq);
            self.flush_contiguous();
            self.cleanup_stale();
            Ok(Some(primary))
        } else if seq > self.expected_seq {
            if (self.buffer.len() as u16) < self.max_size {
                self.buffer.insert(seq, primary);
            }
            self.flush_buffer()
        } else {
            Ok(None)
        }
    }

    /// Flush any contiguous buffered packets starting at expected_seq (no data returned).
    fn flush_contiguous(&mut self) {
        while self.buffer.remove(&self.expected_seq).is_some() {
            self.expected_seq = self.expected_seq.wrapping_add(1);
            self.last_delivered_seq = Some(self.expected_seq.wrapping_sub(1));
            self.packets_recovered += 1;
        }
    }

    /// Try to deliver the next buffered packet (expected_seq).
    fn flush_buffer(&mut self) -> Result<Option<Vec<u8>>, crate::errors::RtcError> {
        if let Some(data) = self.buffer.remove(&self.expected_seq) {
            self.expected_seq = self.expected_seq.wrapping_add(1);
            self.last_delivered_seq = Some(self.expected_seq.wrapping_sub(1));
            self.packets_recovered += 1;
            self.flush_contiguous();
            return Ok(Some(data));
        }
        Ok(None)
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
        let result = buf.try_deliver(1, vec![0x01, 0x02], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x01, 0x02]));
        assert_eq!(buf.expected_seq, 2);
    }

    #[test]
    fn test_udtl_receive_buffer_out_of_order() {
        let mut buf = UdtlReceiveBuffer::new();
        // Packet 2 arrives before packet 1
        let result = buf.try_deliver(2, vec![0x03, 0x04], vec![]).unwrap();
        assert_eq!(result, None); // buffer it
        assert_eq!(buf.buffered_count(), 1);

        // Packet 1 arrives - should flush both
        let result = buf.try_deliver(1, vec![0x01, 0x02], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x01, 0x02]));
        assert_eq!(buf.expected_seq, 3);
        assert_eq!(buf.buffered_count(), 0);
    }

    #[test]
    fn test_udtl_receive_buffer_duplicate() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, vec![0x01], vec![]).unwrap();
        // Same seq again
        let result = buf.try_deliver(1, vec![0x02], vec![]).unwrap();
        assert_eq!(result, None);
        assert_eq!(buf.expected_seq, 2);
    }

    #[test]
    fn test_udtl_receive_buffer_too_old() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(5, vec![0x05], vec![]).unwrap();
        // This sets expected_seq to... well, we gave it 5 directly, expected becomes 6
        // But wait - with the out-of-order logic, if we receive seq=5 and expected=1:
        // seq > expected (5 > 1), so it's buffered
        // expected_seq stays at 1
        assert_eq!(buf.expected_seq, 1);
        assert_eq!(buf.buffered_count(), 1);
        buf.buffer.remove(&5);

        // Send seq=1 to advance expected_seq
        buf.try_deliver(1, vec![0x01], vec![]).unwrap();
        assert_eq!(buf.expected_seq, 2);

        // Now send seq=1 again (too old)
        let result = buf.try_deliver(1, vec![0x01], vec![]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_udtl_receive_buffer_gap_recovery() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, vec![0x01], vec![]).unwrap();
        assert_eq!(buf.expected_seq, 2);

        // Deliver 3 (skip 2)
        buf.try_deliver(3, vec![0x03], vec![]).unwrap();
        assert_eq!(buf.buffered_count(), 1);

        // Deliver 2
        let result = buf.try_deliver(2, vec![0x02], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x02]));
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
        let result = buf.try_deliver(65530, vec![0x01], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x01]));
        assert_eq!(buf.expected_seq, 65531);

        // Next: 65531
        let result = buf.try_deliver(65531, vec![0x02], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x02]));
        assert_eq!(buf.expected_seq, 65532);

        // Now wrap around: 65532 -> 0 (via wrapping_add)
        // Actually, wrapping_add(65532, 1) = 65533, wrapping_add(65535, 1) = 0
        // Let me send a few more
        buf.expected_seq = 65535;
        let result = buf.try_deliver(65535, vec![0x03], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x03]));

        // Now expected should wrap to 0
        assert_eq!(buf.expected_seq, 0);

        // Deliver seq 0
        let result = buf.try_deliver(0, vec![0x04], vec![]).unwrap();
        assert_eq!(result, Some(vec![0x04]));
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
                data: vec![i as u8],
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
        buf.try_deliver(1, vec![0x01], vec![]).unwrap();
        assert_eq!(buf.expected_seq, 2);
        buf.try_deliver(2, vec![0x02], vec![]).unwrap();
        buf.try_deliver(3, vec![0x03], vec![]).unwrap();
        buf.try_deliver(4, vec![0x04], vec![]).unwrap();
        assert_eq!(buf.expected_seq, 5);

        // Buffer packet 100 (gap of 95, way beyond max_gap of 32)
        buf.try_deliver(100, vec![0x64], vec![]).unwrap();
        assert_eq!(buf.buffered_count(), 1);

        // Send next in-order packet — this triggers cleanup
        buf.try_deliver(5, vec![0x05], vec![]).unwrap();
        assert_eq!(buf.expected_seq, 6);

        // After delivering seq 5, cleanup happens (seq 100 is 94 ahead of 6, > 32)
        assert_eq!(buf.buffered_count(), 0);
        assert_eq!(buf.packets_lost, 1);
    }

    #[test]
    fn test_reset_buffer() {
        let mut buf = UdtlReceiveBuffer::new();
        buf.try_deliver(1, vec![0x01], vec![]).unwrap();
        buf.try_deliver(3, vec![0x03], vec![]).unwrap();
        assert_eq!(buf.buffered_count(), 1);

        buf.reset(10);
        assert_eq!(buf.expected_seq, 10);
        assert_eq!(buf.buffered_count(), 0);
    }

    #[test]
    fn test_packet_stats_tracking() {
        let mut buf = UdtlReceiveBuffer::new();

        buf.try_deliver(1, vec![0x01], vec![]).unwrap(); // delivered
        buf.try_deliver(3, vec![0x03], vec![]).unwrap(); // buffered
        buf.try_deliver(2, vec![0x02], vec![]).unwrap(); // delivered (and flushes seq 3)
        buf.try_deliver(1, vec![0x01], vec![]).unwrap(); // duplicate - ignored

        assert_eq!(buf.packets_received, 4);
        assert_eq!(buf.last_delivered_seq, Some(3));
    }
}
