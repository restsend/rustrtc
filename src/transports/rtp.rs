use crate::rtp::{RtcpPacket, RtpPacket, is_rtcp, marshal_rtcp_packets, parse_rtcp_packets};
use crate::srtp::SrtpSession;
use crate::transports::PacketReceiver;
use crate::transports::ice::conn::IceConn;
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

const EXT_ID_NONE: u8 = 0;

#[inline]
fn encode_ext_id(id: Option<u8>) -> u8 {
    id.unwrap_or(EXT_ID_NONE)
}

#[inline]
fn decode_ext_id(raw: u8) -> Option<u8> {
    if raw == EXT_ID_NONE { None } else { Some(raw) }
}

async fn try_send_with_fallback<T>(
    tx: &mpsc::Sender<T>,
    value: T,
) -> Result<(), mpsc::error::SendError<T>> {
    match tx.try_send(value) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(value)) => tx.send(value).await,
        Err(mpsc::error::TrySendError::Closed(value)) => Err(mpsc::error::SendError(value)),
    }
}

fn try_send_dropping<T>(
    tx: &mpsc::Sender<T>,
    value: T,
) -> Result<(), mpsc::error::TrySendError<T>> {
    tx.try_send(value)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RtpRewriteBridgeParams {
    pub ssrc_offset: u32,
    pub payload_type: Option<u8>,
    pub initial_sequence_number: Option<u16>,
    pub initial_timestamp_offset: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct StreamRewriteState {
    out_ssrc: u32,
    next_sequence_number: u16,
    last_source_timestamp: Option<u32>,
    timestamp_offset: u32,
}

struct RewriteBridge {
    target_ice_conn: Arc<IceConn>,
    params: RtpRewriteBridgeParams,
    streams: RefCell<HashMap<u32, StreamRewriteState>>,
}

impl RewriteBridge {
    fn new(target: Arc<RtpTransport>, params: RtpRewriteBridgeParams) -> Self {
        Self {
            target_ice_conn: target.ice_conn(),
            params,
            streams: RefCell::new(HashMap::new()),
        }
    }

    fn rewrite_packet(&self, packet: &mut RtpPacket) {
        let params = self.params;
        let src_ssrc = packet.header.ssrc;
        let src_timestamp = packet.header.timestamp;
        let mut streams = self.streams.borrow_mut();
        let state = streams
            .entry(src_ssrc)
            .or_insert_with(|| StreamRewriteState {
                out_ssrc: src_ssrc.wrapping_add(params.ssrc_offset),
                next_sequence_number: params
                    .initial_sequence_number
                    .unwrap_or(random_u32() as u16),
                last_source_timestamp: None,
                timestamp_offset: params.initial_timestamp_offset.unwrap_or_else(random_u32),
            });

        if let Some(payload_type) = params.payload_type {
            packet.header.payload_type = payload_type;
        }
        packet.header.ssrc = state.out_ssrc;

        if let Some(last_src) = state.last_source_timestamp {
            let delta = src_timestamp.wrapping_sub(last_src);
            if delta < 0x8000_0000 {
                if delta > 900_000 {
                    state.timestamp_offset = last_src
                        .wrapping_add(state.timestamp_offset)
                        .wrapping_add(3000)
                        .wrapping_sub(src_timestamp);
                }
                state.last_source_timestamp = Some(src_timestamp);
            }
        } else {
            state.last_source_timestamp = Some(src_timestamp);
        }

        packet.header.timestamp = src_timestamp.wrapping_add(state.timestamp_offset);
        packet.header.sequence_number = state.next_sequence_number;
        state.next_sequence_number = state.next_sequence_number.wrapping_add(1);
    }
}

#[derive(Default)]
struct ListenerRegistry {
    by_ssrc: HashMap<u32, mpsc::Sender<(RtpPacket, SocketAddr)>>,
    by_rid: HashMap<String, mpsc::Sender<(RtpPacket, SocketAddr)>>,
    by_mid: HashMap<String, mpsc::Sender<(RtpPacket, SocketAddr)>>,
    routes: Vec<ListenerRoute>,
}

#[derive(Clone)]
struct ListenerRoute {
    mid: Option<String>,
    payload_types: Vec<u8>,
    tx: mpsc::Sender<(RtpPacket, SocketAddr)>,
    provisional: bool,
}

impl ListenerRegistry {
    fn route_for_sender_mut(
        &mut self,
        tx: &mpsc::Sender<(RtpPacket, SocketAddr)>,
    ) -> &mut ListenerRoute {
        if let Some(index) = self
            .routes
            .iter()
            .position(|route| route.tx.same_channel(tx))
        {
            return &mut self.routes[index];
        }

        self.routes.push(ListenerRoute {
            mid: None,
            payload_types: Vec::new(),
            tx: tx.clone(),
            provisional: false,
        });
        self.routes.last_mut().unwrap()
    }

    fn register_mid(&mut self, mid: String, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        self.by_mid.insert(mid.clone(), tx.clone());
        self.route_for_sender_mut(&tx).mid = Some(mid);
    }

    fn register_payload_types(
        &mut self,
        payload_types: Vec<u8>,
        tx: mpsc::Sender<(RtpPacket, SocketAddr)>,
    ) {
        let route = self.route_for_sender_mut(&tx);
        route.payload_types.clear();
        for pt in payload_types {
            if !route.payload_types.contains(&pt) {
                route.payload_types.push(pt);
            }
        }
    }

    fn register_payload_type(&mut self, pt: u8, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let route = self.route_for_sender_mut(&tx);
        if !route.payload_types.contains(&pt) {
            route.payload_types.push(pt);
        }
    }

    fn register_provisional(&mut self, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        self.route_for_sender_mut(&tx).provisional = true;
    }

    fn by_mid(&self, mid: &str) -> Option<mpsc::Sender<(RtpPacket, SocketAddr)>> {
        self.by_mid.get(mid).cloned()
    }

    fn unique_by_pt(&self, pt: u8) -> Option<mpsc::Sender<(RtpPacket, SocketAddr)>> {
        let mut selected: Option<&mpsc::Sender<(RtpPacket, SocketAddr)>> = None;

        for route in self
            .routes
            .iter()
            .filter(|route| route.payload_types.contains(&pt))
        {
            if let Some(existing) = selected {
                if !existing.same_channel(&route.tx) {
                    return None;
                }
            } else {
                selected = Some(&route.tx);
            }
        }

        selected.cloned()
    }

    fn single_provisional(&self) -> Option<mpsc::Sender<(RtpPacket, SocketAddr)>> {
        let mut selected: Option<&mpsc::Sender<(RtpPacket, SocketAddr)>> = None;

        for route in self.routes.iter().filter(|route| route.provisional) {
            if let Some(existing) = selected {
                if !existing.same_channel(&route.tx) {
                    return None;
                }
            } else {
                selected = Some(&route.tx);
            }
        }

        selected.cloned()
    }

    fn bind_ssrc_route(&mut self, ssrc: u32, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        self.by_ssrc.insert(ssrc, tx);
    }

    fn remove_sender(&mut self, tx: &mpsc::Sender<(RtpPacket, SocketAddr)>) {
        self.by_ssrc
            .retain(|_, existing| !existing.same_channel(tx));
        self.by_rid.retain(|_, existing| !existing.same_channel(tx));
        self.by_mid.retain(|_, existing| !existing.same_channel(tx));
        self.routes.retain(|route| !route.tx.same_channel(tx));
    }
}

pub struct RtpTransport {
    transport: Arc<IceConn>,
    srtp_session: Mutex<Option<Arc<Mutex<SrtpSession>>>>,
    listeners: Mutex<ListenerRegistry>,
    rtcp_listener: Mutex<Option<mpsc::Sender<Vec<RtcpPacket>>>>,
    rid_extension_id: AtomicU8,
    sdes_mid_extension_id: AtomicU8,
    abs_send_time_extension_id: AtomicU8,
    rewrite_bridge: Mutex<Option<Box<RewriteBridge>>>,
    has_bridge: AtomicBool,
    srtp_required: bool,
    has_sent_first_packet: AtomicBool,
    /// Cumulative count of inbound RTP packets accepted at the transport
    /// layer (after successful parse, before any forwarding/relay). This is
    /// the common chokepoint that all downstream paths (rewrite-bridge
    /// fast-path, listener/track chain) share, so it can be polled to detect
    /// RTP inactivity regardless of the active forwarding mode.
    received_rtp_packets: AtomicU64,
}

impl RtpTransport {
    pub fn new(transport: Arc<IceConn>, srtp_required: bool) -> Self {
        Self::new_with_ssrc_change(transport, srtp_required, false)
    }

    pub fn new_with_ssrc_change(
        transport: Arc<IceConn>,
        srtp_required: bool,
        _allow_ssrc_change: bool,
    ) -> Self {
        Self {
            transport,
            srtp_session: Mutex::new(None),
            listeners: Mutex::new(ListenerRegistry::default()),
            rtcp_listener: Mutex::new(None),
            rid_extension_id: AtomicU8::new(EXT_ID_NONE),
            sdes_mid_extension_id: AtomicU8::new(EXT_ID_NONE),
            abs_send_time_extension_id: AtomicU8::new(EXT_ID_NONE),
            rewrite_bridge: Mutex::new(None),
            has_bridge: AtomicBool::new(false),
            srtp_required,
            has_sent_first_packet: AtomicBool::new(false),
            received_rtp_packets: AtomicU64::new(0),
        }
    }

    /// Cumulative count of inbound RTP packets accepted at the transport
    /// layer. Monotonically increasing; safe to poll concurrently.
    pub fn received_rtp_packets(&self) -> u64 {
        self.received_rtp_packets.load(Ordering::Relaxed)
    }

    pub fn ice_conn(&self) -> Arc<IceConn> {
        self.transport.clone()
    }

    pub fn start_srtp(&self, srtp_session: SrtpSession) {
        let mut session = self.srtp_session.lock();
        *session = Some(Arc::new(Mutex::new(srtp_session)));
    }

    pub fn register_listener_sync(&self, ssrc: u32, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let mut listeners = self.listeners.lock();
        listeners.by_ssrc.insert(ssrc, tx);
    }

    pub fn has_listener(&self, ssrc: u32) -> bool {
        let listeners = self.listeners.lock();
        listeners.by_ssrc.contains_key(&ssrc)
    }

    pub fn register_rid_listener(&self, rid: String, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let mut listeners = self.listeners.lock();
        listeners.by_rid.insert(rid, tx);
    }

    pub fn register_mid_listener(&self, mid: String, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let mut listeners = self.listeners.lock();
        listeners.register_mid(mid, tx);
    }

    pub fn register_pt_listener(&self, pt: u8, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let mut listeners = self.listeners.lock();
        listeners.register_payload_type(pt, tx);
    }

    pub fn register_payload_list_listener(
        &self,
        payload_types: Vec<u8>,
        tx: mpsc::Sender<(RtpPacket, SocketAddr)>,
    ) {
        let mut listeners = self.listeners.lock();
        listeners.register_payload_types(payload_types, tx);
    }

    pub fn register_provisional_listener(&self, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let mut listeners = self.listeners.lock();
        listeners.register_provisional(tx);
    }

    pub fn set_rid_extension_id(&self, id: Option<u8>) {
        self.rid_extension_id
            .store(encode_ext_id(id), Ordering::Relaxed);
    }

    pub fn set_sdes_mid_extension_id(&self, id: Option<u8>) {
        self.sdes_mid_extension_id
            .store(encode_ext_id(id), Ordering::Relaxed);
    }

    pub fn set_abs_send_time_extension_id(&self, id: Option<u8>) {
        self.abs_send_time_extension_id
            .store(encode_ext_id(id), Ordering::Relaxed);
    }

    /// Returns the remote peer's socket address (the nominated ICE candidate
    /// or the configured RTP destination).
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        *self.transport.remote_addr.read()
    }

    /// Returns the local socket address (the ICE socket's bind address).
    /// Returns `0.0.0.0:0` when the socket is not yet available.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.transport.local_addr()
    }

    pub fn register_rtcp_listener(&self, tx: mpsc::Sender<Vec<RtcpPacket>>) {
        let mut listener = self.rtcp_listener.lock();
        *listener = Some(tx);
    }

    pub fn bridge_rewrite_to(&self, dst: Arc<RtpTransport>, params: RtpRewriteBridgeParams) {
        *self.rewrite_bridge.lock() = Some(Box::new(RewriteBridge::new(dst, params)));
        self.has_bridge.store(true, Ordering::Release);
    }

    pub fn clear_bridge_rewrite(&self) {
        *self.rewrite_bridge.lock() = None;
        self.has_bridge.store(false, Ordering::Release);
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let protected = {
            let session_guard = self.srtp_session.lock();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock();
                let mut packet = RtpPacket::parse(buf)?;

                // Inject abs-send-time if enabled
                if let Some(id) =
                    decode_ext_id(self.abs_send_time_extension_id.load(Ordering::Relaxed))
                {
                    let abs_send_time =
                        crate::rtp::calculate_abs_send_time(std::time::SystemTime::now());
                    let data = abs_send_time.to_be_bytes();
                    packet.header.set_extension(id, &data[1..4])?;
                }

                srtp.protect_rtp(&mut packet)?;
                packet.marshal()?
            } else {
                if self.srtp_required {
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                buf.to_vec()
            }
        };
        self.transport.send(&protected).await
    }

    pub async fn send_rtp(&self, mut packet: RtpPacket) -> Result<usize> {
        let is_first = !self.has_sent_first_packet.load(Ordering::Relaxed);
        if is_first {
            self.has_sent_first_packet.store(true, Ordering::Relaxed);
            packet.header.marker = true;
        }

        // Inject abs-send-time if enabled (non-fatal: header may lack room on small payloads).
        if let Some(id) = decode_ext_id(self.abs_send_time_extension_id.load(Ordering::Relaxed)) {
            let abs_send_time = crate::rtp::calculate_abs_send_time(std::time::SystemTime::now());
            let data = abs_send_time.to_be_bytes();
            if let Err(e) = packet.header.set_extension(id, &data[1..4]) {
                trace!("RtpTransport: abs-send-time extension skipped: {}", e);
            }
        }

        let protected = {
            let session_guard = self.srtp_session.lock();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock();
                srtp.protect_rtp(&mut packet)?;
                packet.marshal()?
            } else {
                if self.srtp_required {
                    warn!("RtpTransport: SRTP required but session not ready, dropping RTP send");
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                packet.marshal()?
            }
        };
        match self.transport.send(&protected).await {
            Ok(n) => {
                if is_first {
                    info!(
                        "RtpTransport: first SRTP packet sent ({} bytes)",
                        protected.len()
                    );
                }
                Ok(n)
            }
            Err(e) => {
                warn!(
                    "RtpTransport: failed to send SRTP packet ({} bytes): {}",
                    protected.len(),
                    e
                );
                Err(e)
            }
        }
    }

    pub async fn send_rtcp(&self, packets: &[RtcpPacket]) -> Result<usize> {
        let mut raw = marshal_rtcp_packets(packets)?;
        let protected = {
            let session_guard = self.srtp_session.lock();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock();
                srtp.protect_rtcp(&mut raw)?;
                raw
            } else {
                if self.srtp_required {
                    tracing::warn!("Failed to send PLI: SRTP required but session not ready");
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                raw
            }
        };
        self.transport.send_rtcp(&protected).await
    }

    fn try_bridge_rewrite_rtp(
        &self,
        mut packet: RtpPacket,
        marshal_buf: &mut Vec<u8>,
    ) -> Option<RtpPacket> {
        if !self.has_bridge.load(Ordering::Acquire) {
            return Some(packet);
        }
        let mut guard = self.rewrite_bridge.lock();
        let Some(bridge) = guard.as_mut() else {
            return Some(packet);
        };

        bridge.rewrite_packet(&mut packet);
        packet.marshal_into(marshal_buf);
        let _ = bridge.target_ice_conn.try_send(marshal_buf);
        None
    }

    /// Clear all listeners to stop receiving packets.
    /// This is called when PeerConnection is closed to prevent audio bleeding into new connections.
    pub fn clear_listeners(&self) -> usize {
        let mut count = 0;

        // Clear SSRC listeners
        {
            let mut listeners = self.listeners.lock();
            count += listeners.by_ssrc.len();
            listeners.by_ssrc.clear();
            count += listeners.by_rid.len();
            listeners.by_rid.clear();
            count += listeners.routes.len();
            listeners.routes.clear();
        }

        // Clear RTCP listener
        {
            let mut rtcp_listener = self.rtcp_listener.lock();
            if rtcp_listener.is_some() {
                *rtcp_listener = None;
                count += 1;
            }
        }

        count
    }
}

#[async_trait]
impl PacketReceiver for RtpTransport {
    async fn receive(&self, packet: Bytes, addr: SocketAddr, marshal_buf: &mut Vec<u8>) {
        let is_rtcp_packet = is_rtcp(&packet);

        if is_rtcp_packet {
            let unprotected = {
                let session_guard = self.srtp_session.lock();
                if let Some(session) = &*session_guard {
                    let mut srtp = session.lock();
                    let mut buf = packet.to_vec();
                    match srtp.unprotect_rtcp(&mut buf) {
                        Ok(_) => buf,
                        Err(e) => {
                            tracing::warn!("SRTP unprotect RTCP failed: {}", e);
                            return;
                        }
                    }
                } else {
                    if self.srtp_required {
                        trace!("Dropping packet because SRTP is required but session is not ready");
                        return;
                    }
                    packet.to_vec()
                }
            };

            let listener = {
                let guard = self.rtcp_listener.lock();
                guard.clone()
            };
            if let Some(tx) = listener {
                match parse_rtcp_packets(&unprotected, Some(addr)) {
                    Ok(packets) => {
                        if try_send_with_fallback(&tx, packets).await.is_err() {
                            let mut guard = self.rtcp_listener.lock();
                            *guard = None;
                        }
                    }
                    Err(e) => {
                        trace!("RTCP parse failed: {}", e);
                    }
                }
            } else {
                trace!(
                    "No RTCP listener, dropping {} bytes from {}",
                    unprotected.len(),
                    addr
                );
            }
        } else {
            let rtp_packet = {
                let session_guard = self.srtp_session.lock();
                if let Some(session) = &*session_guard {
                    let mut srtp = session.lock();
                    // SRTP path: keep a borrowed parse (crypto materializes a
                    // mutable copy itself, so no benefit from zero-copy here).
                    match RtpPacket::parse(&packet) {
                        Ok(mut rtp_packet) => match srtp.unprotect_rtp(&mut rtp_packet) {
                            Ok(_) => rtp_packet,
                            Err(_) => return,
                        },
                        Err(e) => {
                            trace!("RTP parse failed: {}", e);
                            return;
                        }
                    }
                } else {
                    if self.srtp_required {
                        trace!("Dropping packet because SRTP is required but session is not ready");
                        return;
                    }
                    // Plain-RTP fast path: zero-copy parse — the packet's
                    // payload/extension are cheap `Bytes` slices of the
                    // already-owned receive buffer instead of fresh Vec copies.
                    match RtpPacket::parse_bytes(packet.clone()) {
                        Ok(rtp_packet) => rtp_packet,
                        Err(e) => {
                            trace!("RTP parse failed: {}", e);
                            return;
                        }
                    }
                }
            };

            // Count every accepted inbound RTP packet at the transport layer.
            // This runs before the rewrite-bridge fast-path early-return, so
            // the counter advances for both relayed and depacketized packets.
            self.received_rtp_packets.fetch_add(1, Ordering::Relaxed);

            let Some(rtp_packet) = self.try_bridge_rewrite_rtp(rtp_packet, marshal_buf) else {
                return;
            };

            let ssrc = rtp_packet.header.ssrc;
            let pt = rtp_packet.header.payload_type;

            let listener = {
                let rid_id = decode_ext_id(self.rid_extension_id.load(Ordering::Relaxed));
                let mid_id = decode_ext_id(self.sdes_mid_extension_id.load(Ordering::Relaxed));
                let mut listeners = self.listeners.lock();
                let mut selected = None;
                let mut bind_ssrc = false;

                if let Some(id) = rid_id
                    && let Some(rid) = rtp_packet.header.get_extension(id)
                    && let Ok(rid_str) = std::str::from_utf8(&rid)
                {
                    selected = listeners.by_rid.get(rid_str).cloned();
                    bind_ssrc = selected.is_some();
                }

                if selected.is_none()
                    && let Some(id) = mid_id
                    && let Some(mid) = rtp_packet.header.get_extension(id)
                    && let Ok(mid_str) = std::str::from_utf8(&mid)
                {
                    selected = listeners.by_mid(mid_str);
                    bind_ssrc = selected.is_some();
                }

                if selected.is_none() {
                    selected = listeners.by_ssrc.get(&ssrc).cloned();
                    bind_ssrc = false;
                }

                if selected.is_none() {
                    selected = listeners.unique_by_pt(pt);
                    bind_ssrc = selected.is_some();
                }

                if selected.is_none() {
                    selected = listeners.single_provisional();
                    bind_ssrc = false;
                }

                if let Some(tx) = selected.as_ref()
                    && bind_ssrc
                {
                    listeners.bind_ssrc_route(ssrc, tx.clone());
                }

                selected
            };

            if let Some(tx) = listener {
                match try_send_dropping(&tx, (rtp_packet, addr)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        let mut listeners = self.listeners.lock();
                        listeners.by_ssrc.remove(&ssrc);
                        listeners.remove_sender(&tx);
                    }
                }
            } else {
                trace!(
                    "No listener found for packet SSRC: {} PT: {} from {}",
                    ssrc, pt, addr
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::ice::conn::IceConn;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_specific_listener_isolation() {
        use crate::transports::ice::IceSocketWrapper;
        use bytes::Bytes;
        use tokio::sync::watch;

        let (_ice_tx, ice_rx) = watch::channel(None::<IceSocketWrapper>);
        let ice_conn = IceConn::new(ice_rx, "127.0.0.1:1234".parse().unwrap(), None);
        let transport = RtpTransport::new(ice_conn, false);

        let (tx, mut rx) = mpsc::channel(10);
        // Register listener for specific SSRC
        transport.register_listener_sync(100, tx);

        // First packet with SSRC 100
        let header1 = crate::rtp::RtpHeader::new(0, 1, 0, 100);
        let packet1 = crate::rtp::RtpPacket::new(header1, vec![1u8; 160]);
        let mut marshal_buf = Vec::new();
        transport
            .receive(
                Bytes::from(packet1.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        let received1 = rx.recv().await.expect("First packet should be received");
        assert_eq!(received1.0.header.ssrc, 100);

        // Second packet with different SSRC 200 but same PT
        let header2 = crate::rtp::RtpHeader::new(0, 2, 160, 200);
        let packet2 = crate::rtp::RtpPacket::new(header2, vec![2u8; 160]);
        transport
            .receive(
                Bytes::from(packet2.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        // With default settings (allow_ssrc_change=false), new SSRC should be dropped
        tokio::time::timeout(tokio::time::Duration::from_millis(50), rx.recv())
            .await
            .expect_err(
                "Second packet with new SSRC should be dropped when allow_ssrc_change=false",
            );

        // Verify new SSRC is not automatically bound
        assert!(!transport.has_listener(200));
    }

    #[tokio::test]
    async fn test_provisional_listener_promiscuous_mode() {
        use crate::transports::ice::IceSocketWrapper;
        use bytes::Bytes;
        use tokio::sync::watch;

        // Setup RtpTransport with a mock/dummy IceConn
        let (_ice_tx, ice_rx) = watch::channel(None::<IceSocketWrapper>);
        let ice_conn = IceConn::new(ice_rx, "127.0.0.1:1234".parse().unwrap(), None);
        let transport = RtpTransport::new(ice_conn, false);

        // Register a provisional listener
        let (tx, mut rx) = mpsc::channel(100);
        transport.register_provisional_listener(tx);

        let addr = "127.0.0.1:5000".parse().unwrap();

        // 1. Send Packet 1 with SSRC 1111
        let ssrc1 = 1111u32;
        let header1 = crate::rtp::RtpHeader::new(0, 1, 0, ssrc1);
        let packet1 = crate::rtp::RtpPacket::new(header1, vec![0u8; 160]);
        let bytes1 = packet1.marshal().unwrap();
        let mut marshal_buf = Vec::new();
        transport
            .receive(Bytes::from(bytes1), addr, &mut marshal_buf)
            .await;

        let received1 = rx.recv().await.expect("Should receive packet 1");
        assert_eq!(received1.0.header.ssrc, ssrc1);

        // Verify SSRC is NOT bound (promiscuous mode)
        assert!(
            !transport.has_listener(ssrc1),
            "SSRC should NOT be bound in promiscuous mode"
        );

        // 2. Send Packet 2 with SSRC 2222 (Simulate Stream Switch)
        // In previous 'strict' provisional mode, this would be dropped because provisional was consumed.
        // In 'promiscuous' mode, it should be received.
        let ssrc2 = 2222u32;
        let header2 = crate::rtp::RtpHeader::new(0, 2, 160, ssrc2);
        let packet2 = crate::rtp::RtpPacket::new(header2, vec![1u8; 160]);
        let bytes2 = packet2.marshal().unwrap();

        transport
            .receive(Bytes::from(bytes2), addr, &mut marshal_buf)
            .await;

        let received2 = rx.recv().await.expect("Should receive packet 2 (new SSRC)");
        assert_eq!(received2.0.header.ssrc, ssrc2);

        // 3. Send Packet 3 with SSRC 3333 with different PT
        let ssrc3 = 3333u32;
        let header3 = crate::rtp::RtpHeader::new(8, 3, 320, ssrc3); // PT 8
        let packet3 = crate::rtp::RtpPacket::new(header3, vec![2u8; 160]);
        let bytes3 = packet3.marshal().unwrap();

        transport
            .receive(Bytes::from(bytes3), addr, &mut marshal_buf)
            .await;

        let received3 = rx
            .recv()
            .await
            .expect("Should receive packet 3 (New PT/SSRC)");
        assert_eq!(received3.0.header.ssrc, ssrc3);
        assert_eq!(received3.0.header.payload_type, 8);
    }

    #[tokio::test]
    async fn test_ambiguous_payload_type_without_mid_or_ssrc_is_dropped() {
        use crate::transports::ice::IceSocketWrapper;
        use bytes::Bytes;
        use tokio::sync::watch;

        let (_ice_tx, ice_rx) = watch::channel(None::<IceSocketWrapper>);
        let ice_conn = IceConn::new(ice_rx, "127.0.0.1:1234".parse().unwrap(), None);
        let transport = RtpTransport::new(ice_conn, false);

        let (audio_tx, mut audio_rx) = mpsc::channel(10);
        transport.register_provisional_listener(audio_tx.clone());
        transport.register_payload_list_listener(vec![96], audio_tx);

        let (video_tx, mut video_rx) = mpsc::channel(10);
        transport.register_provisional_listener(video_tx.clone());
        transport.register_payload_list_listener(vec![96], video_tx);

        let header = crate::rtp::RtpHeader::new(96, 1, 0, 4444);
        let packet = crate::rtp::RtpPacket::new(header, vec![0u8; 160]);
        let mut marshal_buf = Vec::new();
        transport
            .receive(
                Bytes::from(packet.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        tokio::time::timeout(tokio::time::Duration::from_millis(50), audio_rx.recv())
            .await
            .expect_err("ambiguous packet should not be routed to audio");
        tokio::time::timeout(tokio::time::Duration::from_millis(50), video_rx.recv())
            .await
            .expect_err("ambiguous packet should not be routed to video");
        assert!(!transport.has_listener(4444));
    }

    #[tokio::test]
    async fn test_mid_routes_and_binds_ssrc_when_payload_type_is_ambiguous() {
        use crate::transports::ice::IceSocketWrapper;
        use bytes::Bytes;
        use tokio::sync::watch;

        let (_ice_tx, ice_rx) = watch::channel(None::<IceSocketWrapper>);
        let ice_conn = IceConn::new(ice_rx, "127.0.0.1:1234".parse().unwrap(), None);
        let transport = RtpTransport::new(ice_conn, false);
        transport.set_sdes_mid_extension_id(Some(1));

        let (audio_tx, mut audio_rx) = mpsc::channel(10);
        transport.register_mid_listener("as".to_string(), audio_tx.clone());
        transport.register_payload_list_listener(vec![96], audio_tx);

        let (video_tx, mut video_rx) = mpsc::channel(10);
        transport.register_mid_listener("vs".to_string(), video_tx.clone());
        transport.register_payload_list_listener(vec![96], video_tx);

        let mut header = crate::rtp::RtpHeader::new(96, 1, 0, 5555);
        header.set_extension(1, b"vs").unwrap();
        let packet = crate::rtp::RtpPacket::new(header, vec![0u8; 160]);
        let mut marshal_buf = Vec::new();
        transport
            .receive(
                Bytes::from(packet.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        let received = video_rx
            .recv()
            .await
            .expect("packet with video MID should route to video");
        assert_eq!(received.0.header.ssrc, 5555);
        tokio::time::timeout(tokio::time::Duration::from_millis(50), audio_rx.recv())
            .await
            .expect_err("packet with video MID should not route to audio");
        assert!(transport.has_listener(5555));

        let header = crate::rtp::RtpHeader::new(96, 2, 160, 5555);
        let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
        transport
            .receive(
                Bytes::from(packet.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        let received = video_rx
            .recv()
            .await
            .expect("bound SSRC should route without MID");
        assert_eq!(received.0.header.sequence_number, 2);
    }

    #[tokio::test]
    async fn test_mid_route_overrides_existing_ssrc_mapping() {
        use crate::transports::ice::IceSocketWrapper;
        use bytes::Bytes;
        use tokio::sync::watch;

        let (_ice_tx, ice_rx) = watch::channel(None::<IceSocketWrapper>);
        let ice_conn = IceConn::new(ice_rx, "127.0.0.1:1234".parse().unwrap(), None);
        let transport = RtpTransport::new(ice_conn, false);
        transport.set_sdes_mid_extension_id(Some(1));

        let (audio_tx, mut audio_rx) = mpsc::channel(10);
        transport.register_listener_sync(6666, audio_tx.clone());
        transport.register_mid_listener("as".to_string(), audio_tx);

        let (video_tx, mut video_rx) = mpsc::channel(10);
        transport.register_mid_listener("vs".to_string(), video_tx);

        let mut header = crate::rtp::RtpHeader::new(96, 1, 0, 6666);
        header.set_extension(1, b"vs").unwrap();
        let packet = crate::rtp::RtpPacket::new(header, vec![0u8; 160]);
        let mut marshal_buf = Vec::new();
        transport
            .receive(
                Bytes::from(packet.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        let received = video_rx
            .recv()
            .await
            .expect("MID should override stale SSRC mapping");
        assert_eq!(received.0.header.ssrc, 6666);
        tokio::time::timeout(tokio::time::Duration::from_millis(50), audio_rx.recv())
            .await
            .expect_err("stale SSRC mapping should not receive the MID packet");

        let header = crate::rtp::RtpHeader::new(96, 2, 160, 6666);
        let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
        transport
            .receive(
                Bytes::from(packet.marshal().unwrap()),
                "127.0.0.1:5000".parse().unwrap(),
                &mut marshal_buf,
            )
            .await;

        let received = video_rx
            .recv()
            .await
            .expect("corrected SSRC mapping should receive packets without MID");
        assert_eq!(received.0.header.sequence_number, 2);
    }

    #[tokio::test]
    async fn test_rewrite_bridge_rewrites_packet_fields() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let src_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_src_tx, src_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(src_socket))));
        let src_conn = IceConn::new(src_rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = RtpTransport::new(src_conn, false);

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        src_transport.bridge_rewrite_to(
            dst_transport.clone(),
            RtpRewriteBridgeParams {
                ssrc_offset: 900,
                payload_type: Some(96),
                initial_sequence_number: Some(32000),
                initial_timestamp_offset: Some(12345),
            },
        );

        let mut guard = src_transport.rewrite_bridge.lock();
        let bridge = guard.as_mut().expect("rewrite bridge should be configured");

        let mut packet = RtpPacket::new(crate::rtp::RtpHeader::new(0, 7, 1111, 100), vec![1u8; 32]);
        bridge.rewrite_packet(&mut packet);
        drop(guard);

        assert_eq!(packet.header.ssrc, 1000);
        assert_eq!(packet.header.payload_type, 96);
        assert_eq!(packet.header.sequence_number, 32000);
        assert_eq!(packet.header.timestamp, 1111 + 12345);
    }

    #[tokio::test]
    async fn test_received_rtp_packets_counter_advances_on_slow_path() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
        let transport = RtpTransport::new(conn, false);

        let mut marshal_buf = Vec::with_capacity(1500);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        assert_eq!(transport.received_rtp_packets(), 0, "counter starts at zero");

        for seq in 1..=3u16 {
            let header = crate::rtp::RtpHeader::new(0, seq, 160, 1234);
            let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
            transport
                .receive(Bytes::from(packet.marshal().unwrap()), addr, &mut marshal_buf)
                .await;
        }

        assert_eq!(
            transport.received_rtp_packets(),
            3,
            "counter must advance by one per accepted inbound RTP packet"
        );
    }

    /// Critical regression: when the rewrite-bridge fast-path relay is active,
    /// inbound packets are forwarded directly and the receive() path
    /// early-returns BEFORE dispatching to listeners (and therefore before the
    /// PeerConnection track/depacketizer interceptor chain). The transport
    /// counter must still advance so the host can detect RTP inactivity.
    #[tokio::test]
    async fn test_received_rtp_packets_counter_advances_on_fast_path_relay() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        // Source transport (where packets arrive) with a registered listener.
        let src_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_src_tx, src_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(src_socket))));
        let src_conn = IceConn::new(src_rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let ssrc = 4242u32;
        let (listener_tx, mut listener_rx) = mpsc::channel::<(RtpPacket, SocketAddr)>(8);
        src_transport.register_listener_sync(ssrc, listener_tx);

        // Destination transport (rewrite-bridge target).
        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        // Activate the fast-path rewrite bridge (this is the wholesale
        // zero-CPU relay path).
        src_transport.bridge_rewrite_to(
            dst_transport.clone(),
            RtpRewriteBridgeParams {
                ssrc_offset: 0,
                payload_type: None,
                initial_sequence_number: None,
                initial_timestamp_offset: None,
            },
        );
        assert!(src_transport.has_bridge.load(Ordering::SeqCst));

        assert_eq!(src_transport.received_rtp_packets(), 0);
        assert_eq!(dst_transport.received_rtp_packets(), 0);

        let mut marshal_buf = Vec::with_capacity(1500);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        // Feed two RTP packets into the source transport.
        for seq in 1..=2u16 {
            let header = crate::rtp::RtpHeader::new(0, seq, 160, ssrc);
            let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
            src_transport
                .receive(
                    Bytes::from(packet.marshal().unwrap()),
                    addr,
                    &mut marshal_buf,
                )
                .await;
        }

        // (1) The counter on the source transport advanced even though the
        //     fast-path relay consumed the packet. This is the guarantee the
        //     host relies on for rtp-timeout detection.
        assert_eq!(
            src_transport.received_rtp_packets(),
            2,
            "source counter must advance on the fast-path relay"
        );

        // (2) The destination transport did NOT count the relayed packet,
        //     because it arrived via its own ICE socket (outbound), not via
        //     receive(). This confirms the counter only measures *inbound*
        //     packets accepted at the transport layer.
        assert_eq!(
            dst_transport.received_rtp_packets(),
            0,
            "relayed packet must not be counted as inbound on the destination"
        );

        // (3) The registered listener must NOT have received anything: the
        //     fast-path relay early-returns before listener dispatch. This is
        //     exactly why the PeerConnection interceptor chain (which lives on
        //     the listener/track path) cannot observe fast-path packets, and
        //     why the transport counter is required.
        let attempt = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            listener_rx.recv(),
        )
        .await;
        assert!(
            attempt.is_err(),
            "listener must NOT receive on the fast-path relay (interceptor path is bypassed)"
        );
    }
}
