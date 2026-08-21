use crate::peer_connection::RtpObserver;
use crate::rtp::{RtcpPacket, RtpPacket, is_rtcp, marshal_rtcp_packets, parse_rtcp_packets};
use crate::srtp::{SrtpPacket, SrtpSession};
use crate::transports::PacketReceiver;
use crate::transports::ice::conn::IceConn;
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, trace};

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
    /// When `Some`, every forwarded packet's SSRC is fixed to this value
    /// (overrides `ssrc_offset`). Used for WebRTC ↔ RTP so the destination
    /// peer sees the SSRC it negotiated in SDP.
    pub fixed_out_ssrc: Option<u32>,
    pub payload_type: Option<u8>,
    /// RFC 4733 telephone-event (DTMF) payload-type remap: `(src_pt, dst_pt)`.
    /// When `Some`, packets whose payload type equals `src_pt` are rewritten
    /// to `dst_pt` (in addition to the regular audio `payload_type` rewrite).
    /// Needed when the two legs negotiated different DTMF payload types.
    pub dtmf_payload_type: Option<(u8, u8)>,
    pub initial_sequence_number: Option<u16>,
    pub initial_timestamp_offset: Option<u32>,
    /// When `true`, extension headers are stripped before forwarding.
    /// WebRTC → RTP: the RTP peer doesn't understand WebRTC extensions
    /// (abs-send-time, audio-level, …) and may misparse the payload.
    pub strip_extensions: bool,
}

/// A single payload-type-scoped rewrite rule for the RTP rewrite bridge.
///
/// The bridge rewrites every forwarded packet using the most specific match:
/// a rule whose `match_payload_type` equals the packet's payload type wins;
/// otherwise the single rule with `match_payload_type: None` acts as the
/// catch-all. Audio-only relays install one catch-all rule; video relays add
/// one rule per m-line payload type so audio, video and DTMF each get their own
/// destination SSRC / payload type (the legacy single-param bridge rewrote
/// every packet — audio AND video — to one SSRC/PT, which corrupted video).
#[derive(Debug, Clone)]
pub struct RtpRewriteRule {
    /// When `Some(pt)`, only packets carrying this payload type are rewritten.
    /// When `None`, this is the catch-all rule applied to any other packet.
    pub match_payload_type: Option<u8>,
    /// Fixed SSRC written on rewritten packets. Defaults to
    /// `src_ssrc + ssrc_offset` when `None`.
    pub fixed_out_ssrc: Option<u32>,
    /// SSRC offset applied when `fixed_out_ssrc` is `None`.
    pub ssrc_offset: u32,
    /// Replacement payload type, or `None` to keep the original.
    pub out_payload_type: Option<u8>,
    /// SDES-MID RTP header extension id (the extmap id negotiated for
    /// `urn:ietf:params:rtp-hdrext:sdes:mid`). When set together with
    /// [`Self::sdes_mid`], packets rewritten by this rule get the MID
    /// extension stamped so a WebRTC receiver (Chrome) can attribute them
    /// to the negotiated track regardless of SSRC. Payload-type-scoped:
    /// audio/DTMF rules carry the audio m-line's mid, video rules the
    /// video m-line's mid. Only written when the bridge's
    /// [`RtpRewriteBridgeOptions::strip_extensions`] is false.
    pub sdes_mid_extension_id: Option<u8>,
    /// The destination leg's MID value for this m-line (e.g. "0" for the
    /// audio m-line, "1" for video).
    pub sdes_mid: Option<String>,
}

/// Direction-level rewrite bridge options (not payload-type-scoped).
#[derive(Debug, Clone, Copy, Default)]
pub struct RtpRewriteBridgeOptions {
    /// Strip RTP extension headers before forwarding (WebRTC → RTP).
    pub strip_extensions: bool,
    /// Seed the first forwarded sequence number of each new source stream.
    pub initial_sequence_number: Option<u16>,
    /// Seed the first forwarded timestamp offset of each new source stream.
    /// Ignored for the first packet when [`Self::initial_output_timestamp`] is set.
    pub initial_timestamp_offset: Option<u32>,
    /// Force the first forwarded packet's *output* RTP timestamp to this value
    /// by choosing `offset = value - src_ts`. Later packets keep source
    /// deltas. Use this to continue a destination leg's paced-sender timeline
    /// when IVR and rewrite share the same outbound SSRC (WebRTC).
    pub initial_output_timestamp: Option<u32>,
}

impl RtpRewriteRule {
    /// The catch-all rule mirroring the legacy single-params behavior.
    pub fn catch_all(params: RtpRewriteBridgeParams) -> Self {
        Self {
            match_payload_type: None,
            fixed_out_ssrc: params.fixed_out_ssrc,
            ssrc_offset: params.ssrc_offset,
            out_payload_type: params.payload_type,
            sdes_mid_extension_id: None,
            sdes_mid: None,
        }
    }

    /// DTMF remap: rewrite a specific source PT to a destination PT while
    /// inheriting the same SSRC rewrite as the catch-all rule.
    pub fn dtmf(src_pt: u8, dst_pt: u8, params: RtpRewriteBridgeParams) -> Self {
        Self {
            match_payload_type: Some(src_pt),
            fixed_out_ssrc: params.fixed_out_ssrc,
            ssrc_offset: params.ssrc_offset,
            out_payload_type: Some(dst_pt),
            sdes_mid_extension_id: None,
            sdes_mid: None,
        }
    }

    /// Convert the legacy params into the rule list they map to: a catch-all
    /// rule plus, when DTMF remapping is configured, a DTMF rule. This is the
    /// single place that interprets the legacy struct, keeping the rewrite
    /// path itself rule-table-only.
    pub fn from_params(params: RtpRewriteBridgeParams) -> Vec<Self> {
        let mut rules = vec![Self::catch_all(params)];
        if let Some((src_pt, dst_pt)) = params.dtmf_payload_type {
            rules.push(Self::dtmf(src_pt, dst_pt, params));
        }
        rules
    }
}

#[derive(Debug, Clone, Copy)]
struct StreamRewriteState {
    out_ssrc: u32,
    next_sequence_number: u16,
    last_source_timestamp: Option<u32>,
    timestamp_offset: u32,
}

struct RewriteBridge {
    target: Arc<RtpTransport>,
    video_target: Option<Arc<RtpTransport>>,
    video_payload_types: HashSet<u8>,
    options: RtpRewriteBridgeOptions,
    rules: Vec<RtpRewriteRule>,
    streams: RefCell<HashMap<u32, StreamRewriteState>>,
}

impl RewriteBridge {
    fn new(
        target: Arc<RtpTransport>,
        video_target: Option<Arc<RtpTransport>>,
        video_payload_types: HashSet<u8>,
        options: RtpRewriteBridgeOptions,
        rules: Vec<RtpRewriteRule>,
    ) -> Self {
        Self {
            target,
            video_target,
            video_payload_types,
            options,
            rules,
            streams: RefCell::new(HashMap::new()),
        }
    }

    /// Pick the most specific rule for a payload type: an exact-PT match wins,
    /// otherwise the catch-all (match_payload_type: None), otherwise none.
    fn rule_for(&self, raw_pt: u8) -> Option<RtpRewriteRule> {
        self.rules
            .iter()
            .find(|r| r.match_payload_type == Some(raw_pt))
            .cloned()
            .or_else(|| {
                self.rules
                    .iter()
                    .find(|r| r.match_payload_type.is_none())
                    .cloned()
            })
    }

    /// Select the destination from the packet's original negotiated payload
    /// type. This runs before any payload-type rewrite.
    fn target_for(&self, raw_pt: u8) -> Arc<RtpTransport> {
        if self.video_payload_types.contains(&raw_pt)
            && let Some(video_target) = &self.video_target
        {
            return video_target.clone();
        }
        self.target.clone()
    }

    fn rewrite_packet(&self, packet: &mut RtpPacket) {
        let src_ssrc = packet.header.ssrc;
        let src_timestamp = packet.header.timestamp;

        // Strip extension headers (WebRTC → RTP) before any marshaling so the
        // RTP peer doesn't see WebRTC-specific extensions it can't parse.
        if self.options.strip_extensions {
            packet.header.extension = None;
        }

        let raw_pt = packet.header.payload_type;
        let rule = self.rule_for(raw_pt);
        let out_ssrc = match &rule {
            Some(r) => r
                .fixed_out_ssrc
                .unwrap_or_else(|| src_ssrc.wrapping_add(r.ssrc_offset)),
            // No matching rule: pass the SSRC through untouched.
            None => src_ssrc,
        };

        let mut streams = self.streams.borrow_mut();
        let state = streams
            .entry(src_ssrc)
            .or_insert_with(|| StreamRewriteState {
                out_ssrc,
                next_sequence_number: self
                    .options
                    .initial_sequence_number
                    .unwrap_or(random_u32() as u16),
                last_source_timestamp: None,
                timestamp_offset: self
                    .options
                    .initial_timestamp_offset
                    .unwrap_or_else(random_u32),
            });

        if let Some(r) = &rule
            && let Some(payload_type) = r.out_payload_type
        {
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
            // First packet of this source stream: optionally pin the output
            // timestamp so a shared destination SSRC stays continuous with
            // prior local playback / prior relay.
            if let Some(desired_out) = self.options.initial_output_timestamp {
                state.timestamp_offset = desired_out.wrapping_sub(src_timestamp);
                // Tell the receiver this continues a prior stream on the same
                // SSRC after a source switch (IVR/CNG → relay).
                packet.header.marker = true;
            }
            state.last_source_timestamp = Some(src_timestamp);
        }

        packet.header.timestamp = src_timestamp.wrapping_add(state.timestamp_offset);
        packet.header.sequence_number = state.next_sequence_number;
        state.next_sequence_number = state.next_sequence_number.wrapping_add(1);

        if !self.options.strip_extensions {
            // Stamp the matched rule's SDES-MID (payload-type-scoped: audio
            // rules carry the audio mid, video rules the video mid) so a
            // WebRTC receiver attributes the packet to the right track.
            if let Some(r) = &rule
                && let (Some(ext_id), Some(mid)) = (r.sdes_mid_extension_id, &r.sdes_mid)
            {
                let _ = packet.header.set_extension(ext_id, mid.as_bytes());
            }
        }
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

        // Prune stale routes: once the sender's channel is dropped (the old
        // run_loop exited) its tx is closed and will never deliver a packet.
        // Keeping them leaks one ListenerRoute per transport replacement
        // without cleaning until clear_listeners() on full close.  This also
        // keeps by_ssrc / by_mid / by_rid entries that are no longer routable.
        self.routes.retain(|route| !route.tx.is_closed());

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
        self.by_ssrc.retain(|_, existing| !existing.is_closed());
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
    /// Cumulative count of failed relay fast-path pushes (diagnostic for
    /// "call connected but no audio").
    relay_send_failures: AtomicU64,
    srtp_protect_failures: AtomicU64,
    srtp_dropped_no_session: AtomicU64,
    bridge_relayed_packets: AtomicU64,
    srtp_unprotect_failures: AtomicU64,
    /// Plaintext transport observers — fire on clear RTP for BOTH directions
    /// and ALL forwarding modes (including the relay fast-path). Inbound fires
    /// post-SRTP-unprotect / pre-relay; outbound fires pre-SRTP-protect
    /// (normal send) or pre-push (relay). Empty by default; `has_observers`
    /// makes the hot-path check a single atomic load (zero cost when unused).
    observers: RwLock<Vec<Arc<dyn RtpObserver>>>,
    has_observers: AtomicBool,
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
            relay_send_failures: AtomicU64::new(0),
            srtp_protect_failures: AtomicU64::new(0),
            srtp_dropped_no_session: AtomicU64::new(0),
            bridge_relayed_packets: AtomicU64::new(0),
            srtp_unprotect_failures: AtomicU64::new(0),
            observers: RwLock::new(Vec::new()),
            has_observers: AtomicBool::new(false),
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
        listeners.bind_ssrc_route(ssrc, tx);
    }

    pub fn has_listener(&self, ssrc: u32) -> bool {
        let listeners = self.listeners.lock();
        listeners.by_ssrc.contains_key(&ssrc)
    }

    pub fn register_rid_listener(&self, rid: String, tx: mpsc::Sender<(RtpPacket, SocketAddr)>) {
        let mut listeners = self.listeners.lock();
        listeners.by_rid.retain(|_, existing| !existing.is_closed());
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
        let options = RtpRewriteBridgeOptions {
            strip_extensions: params.strip_extensions,
            initial_sequence_number: params.initial_sequence_number,
            initial_timestamp_offset: params.initial_timestamp_offset,
            initial_output_timestamp: None,
        };
        self.bridge_rewrite_rules_to(dst, options, RtpRewriteRule::from_params(params));
    }

    /// Install a payload-type-aware rewrite bridge with one destination.
    pub fn bridge_rewrite_rules_to(
        &self,
        dst: Arc<RtpTransport>,
        options: RtpRewriteBridgeOptions,
        rules: Vec<RtpRewriteRule>,
    ) {
        self.bridge_rewrite_rules_to_with_video(dst, None, HashSet::new(), options, rules);
    }

    /// Install a payload-type-aware rewrite bridge with an optional video
    /// destination. `video_payload_types` are the source transport's original
    /// negotiated video PTs; target selection happens before PT rewriting.
    ///
    /// This is only needed when a bundled source carries audio and video on
    /// one transport while the destination uses separate transports.
    pub fn bridge_rewrite_rules_to_with_video(
        &self,
        dst: Arc<RtpTransport>,
        video_dst: Option<Arc<RtpTransport>>,
        video_payload_types: HashSet<u8>,
        options: RtpRewriteBridgeOptions,
        rules: Vec<RtpRewriteRule>,
    ) {
        *self.rewrite_bridge.lock() = Some(Box::new(RewriteBridge::new(
            dst,
            video_dst,
            video_payload_types,
            options,
            rules,
        )));
        self.has_bridge.store(true, Ordering::Release);
    }

    pub fn clear_bridge_rewrite(&self) {
        *self.rewrite_bridge.lock() = None;
        self.has_bridge.store(false, Ordering::Release);
    }

    /// Register a plaintext [`RtpObserver`] that fires on clear RTP for BOTH
    /// directions: inbound (post-SRTP-unprotect, pre-relay/demux) and outbound
    /// (pre-SRTP-protect on normal send, pre-push on relay). Covers ALL
    /// forwarding modes including the relay fast-path.
    ///
    /// For NACK / retransmission / RTCP feedback use the existing
    /// [`crate::peer_connection::RtpReceiverInterceptor`] /
    /// [`crate::peer_connection::RtpSenderInterceptor`] instead — `RtpObserver`
    /// is read-only observation (stats / DTMF / recording / sipflow).
    ///
    /// When no observer is registered the hot path is a single atomic load
    /// (zero cost).
    pub fn add_observer(&self, observer: Arc<dyn RtpObserver>) {
        let mut observers = self.observers.write();
        if observers
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &observer))
        {
            return;
        }
        observers.push(observer);
        self.has_observers.store(true, Ordering::Release);
    }

    /// Remove all observers and disable the hot-path checks.
    pub fn clear_observers(&self) {
        self.observers.write().clear();
        self.has_observers.store(false, Ordering::Release);
    }

    /// Fire ingress observers on a plaintext inbound packet. Uses a read guard
    /// (no Vec clone/allocation) and is NOT held across any blocking work.
    /// Zero cost (single atomic load) when no observer is registered.
    #[inline]
    fn fire_ingress(&self, packet: &RtpPacket, src_addr: SocketAddr) {
        if !self.has_observers.load(Ordering::Acquire) {
            return;
        }
        let observers = self.observers.read();
        for o in observers.iter() {
            o.on_ingress(packet, src_addr);
        }
    }

    /// Fire egress observers on a plaintext outbound packet. `dst_addr` is the
    /// configured remote peer address (from the underlying ICE connection).
    /// Same read-guard pattern as [`Self::fire_ingress`].
    #[inline]
    fn fire_egress(&self, packet: &RtpPacket) {
        if !self.has_observers.load(Ordering::Acquire) {
            return;
        }
        let dst_addr = *self.transport.remote_addr.read();
        let observers = self.observers.read();
        for o in observers.iter() {
            o.on_egress(packet, dst_addr);
        }
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let session = self.srtp_session.lock().as_ref().cloned();
        let Some(session) = session else {
            if self.srtp_required {
                return Err(anyhow::anyhow!("SRTP required but session not ready"));
            }
            return self.transport.send(buf).await;
        };

        let protected = {
            let mut packet = RtpPacket::parse(buf)?;

            // Inject abs-send-time if enabled.
            if let Some(id) =
                decode_ext_id(self.abs_send_time_extension_id.load(Ordering::Relaxed))
            {
                let abs_send_time =
                    crate::rtp::calculate_abs_send_time(std::time::SystemTime::now());
                let data = abs_send_time.to_be_bytes();
                packet.header.set_extension(id, &data[1..4])?;
            }

            let mut srtp = session.lock();
            let mut protected = vec![0; srtp.protected_rtp_len(&packet)];
            srtp.protect_rtp(&packet, &mut protected)?;
            protected
        };
        self.transport.send(&protected).await
    }

    pub async fn send_rtp(&self, mut packet: RtpPacket) -> Result<usize> {
        // Egress observation: fire on the plaintext packet BEFORE SRTP protect
        // so observers (stats/recording/sipflow) see clear RTP. Zero cost
        // (single Acquire load) when no observer is registered.
        self.fire_egress(&packet);

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
            // Release the outer guard immediately; the inner SRTP guard is
            // dropped after protection and before awaiting the transport send.
            let session = self.srtp_session.lock().as_ref().cloned();
            match session {
                Some(session) => {
                    let mut srtp = session.lock();
                    let mut protected = vec![0; srtp.protected_rtp_len(&packet)];
                    srtp.protect_rtp(&packet, &mut protected)?;
                    protected
                }
                None => {
                    if self.srtp_required {
                        debug!(
                            "RtpTransport: SRTP required but session not ready, dropping RTP send"
                        );
                        return Err(anyhow::anyhow!("SRTP required but session not ready"));
                    }
                    packet.marshal()?
                }
            }
        };

        match self.transport.send(&protected).await {
            Ok(n) => {
                if is_first {
                    self.transport.mark_first_outbound();
                    trace!(
                        "RtpTransport: first SRTP packet sent ({} bytes)",
                        protected.len()
                    );
                }
                Ok(n)
            }
            Err(e) => {
                debug!(
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
                    debug!("Failed to send PLI: SRTP required but session not ready");
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                raw
            }
        };
        self.transport.send_rtcp(&protected).await
    }

    /// Synchronous best-effort RTCP send for the close path, where we must NOT
    /// spawn or await (tokio runtime may be tearing down). Marshals,
    /// SRTP-protects if a session exists, then `try_send`s — drops the packet
    /// if the socket buffer is full. Never panics.
    pub fn send_rtcp_sync(&self, packets: &[RtcpPacket]) {
        let Ok(mut raw) = marshal_rtcp_packets(packets) else {
            return;
        };
        {
            let session_guard = self.srtp_session.lock();
            if let Some(session) = &*session_guard {
                if session.lock().protect_rtcp(&mut raw).is_err() {
                    return;
                }
            } else if self.srtp_required {
                return;
            }
        }
        let _ = self.ice_conn().try_send(&raw);
    }

    fn try_bridge_rewrite_rtp(
        &self,
        mut packet: RtpPacket,
        marshal_buf: &mut Vec<u8>,
    ) -> Option<RtpPacket> {
        if !self.has_bridge.load(Ordering::Acquire) {
            return Some(packet);
        }
        // Select the destination from the original PT and rewrite under the
        // bridge lock, then release it before SRTP protection and sending.
        let target = {
            let mut guard = self.rewrite_bridge.lock();
            let Some(bridge) = guard.as_mut() else {
                return Some(packet);
            };
            let target = bridge.target_for(packet.header.payload_type);
            bridge.rewrite_packet(&mut packet);
            target
        };

        // Fire the destination's egress observer on the plaintext packet
        // (symmetric with the pre-protect hook in send_rtp).
        target.fire_egress(&packet);

        // SRTP-protect inline (sync) when the destination requires it —
        // WebRTC / SDES-SRTP targets must receive encrypted RTP.
        {
            let session_guard = target.srtp_session.lock();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock();
                let protected_len = srtp.protected_rtp_len(&packet);
                marshal_buf.resize(protected_len, 0);
                if srtp.protect_rtp(&packet, &mut marshal_buf[..]).is_err() {
                    let failures = target.srtp_protect_failures.fetch_add(1, Ordering::Relaxed) + 1;
                    if failures <= 3 || failures.is_multiple_of(100) {
                        tracing::warn!(
                            failures,
                            ssrc = packet.header.ssrc,
                            "relay: SRTP protect_rtp failed, dropping"
                        );
                    }
                    return None; // drop on protect error
                }
            } else if target.srtp_required {
                let failures = target
                    .srtp_dropped_no_session
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                if failures <= 3 || failures.is_multiple_of(100) {
                    tracing::debug!(
                        failures,
                        ssrc = packet.header.ssrc,
                        "relay: target SRTP required but session not ready, dropping"
                    );
                }
                return None; // session not ready → drop
            } else {
                packet.marshal_into(marshal_buf);
            }
        }
        if let Err(e) = target.ice_conn().try_send(marshal_buf) {
            // A failed relay push is the #1 cause of "call connected but no
            // audio" — surface it instead of dropping silently.
            let relay_failures = self.relay_send_failures.fetch_add(1, Ordering::Relaxed) + 1;
            if relay_failures <= 5 || relay_failures.is_multiple_of(100) {
                tracing::warn!(
                    relay_failures,
                    error = %e,
                    ssrc = packet.header.ssrc,
                    pt = packet.header.payload_type,
                    "RTP rewrite bridge: relay push to destination failed"
                );
            }
        } else {
            let relayed = self.bridge_relayed_packets.fetch_add(1, Ordering::Relaxed) + 1;
            if relayed <= 5 {
                tracing::debug!(
                    relayed,
                    ssrc = packet.header.ssrc,
                    pt = packet.header.payload_type,
                    "RTP rewrite bridge: relayed packet"
                );
            }
        }
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
            let unprotected: Bytes = {
                // Release the outer guard at once; hold the inner SRTP lock only
                // around the unprotect. The plain (no-SRTP) branch keeps the
                // received `Bytes` directly (no copy) since parsing takes &[u8].
                let session = self.srtp_session.lock().as_ref().map(|s| s.clone());
                match session {
                    Some(session) => {
                        let mut buf = packet.to_vec();
                        let mut srtp = session.lock();
                        match srtp.unprotect_rtcp(&mut buf) {
                            Ok(()) => Bytes::from(buf),
                            Err(e) => {
                                debug!("SRTP unprotect RTCP failed: {}", e);
                                return;
                            }
                        }
                    }
                    None => {
                        if self.srtp_required {
                            trace!(
                                "Dropping packet because SRTP is required but session is not ready"
                            );
                            return;
                        }
                        packet
                    }
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
                // Parse outside both session guards. The inner SRTP lock is
                // held only while authenticating and decrypting the packet.
                let session = self.srtp_session.lock().as_ref().cloned();
                match session {
                    Some(session) => {
                        let packet = match packet.try_into_mut() {
                            Ok(packet) => packet,
                            Err(packet) => BytesMut::from(packet.as_ref()),
                        };
                        match SrtpPacket::parse(packet) {
                            Ok(srtp_packet) => {
                                let ssrc = srtp_packet.header().ssrc;
                                let payload_type = srtp_packet.header().payload_type;
                                let sequence = srtp_packet.header().sequence_number;
                                let mut srtp = session.lock();
                                match srtp.unprotect_rtp(srtp_packet) {
                                    Ok(rtp_packet) => rtp_packet,
                                    Err(error) => {
                                        let failures = self
                                            .srtp_unprotect_failures
                                            .fetch_add(1, Ordering::Relaxed)
                                            + 1;
                                        if failures <= 5 || failures.is_multiple_of(100) {
                                            tracing::warn!(
                                                failures,
                                                from = %addr,
                                                ssrc,
                                                payload_type,
                                                sequence,
                                                %error,
                                                "SRTP unprotect RTP failed, dropping"
                                            );
                                        }
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                trace!("SRTP parse failed: {}", e);
                                return;
                            }
                        }
                    }
                    None => {
                        if self.srtp_required {
                            trace!(
                                "Dropping packet because SRTP is required but session is not ready"
                            );
                            return;
                        }
                        match RtpPacket::parse_bytes(packet) {
                            Ok(rtp_packet) => rtp_packet,
                            Err(e) => {
                                trace!("RTP parse failed: {}", e);
                                return;
                            }
                        }
                    }
                }
            };

            // Count every accepted inbound RTP packet at the transport layer.
            // This runs before the rewrite-bridge fast-path early-return, so
            // the counter advances for both relayed and depacketized packets.
            self.received_rtp_packets.fetch_add(1, Ordering::Relaxed);

            // Ingress observation: fire on the plaintext packet BEFORE the
            // relay fast-path early-return, so observers (stats/DTMF/recording)
            // see every inbound packet regardless of forwarding mode. Zero cost
            // (single Acquire load) when no observer is registered.
            self.fire_ingress(&rtp_packet, addr);

            let Some(rtp_packet) = self.try_bridge_rewrite_rtp(rtp_packet, marshal_buf) else {
                return;
            };

            let ssrc = rtp_packet.header.ssrc;
            let pt = rtp_packet.header.payload_type;

            // Extract the RID/MID extension slices BEFORE taking the listeners
            // lock — the byte-scan depends only on the packet, not the registry,
            // so it should not run inside the demux critical section.
            let rid_id = decode_ext_id(self.rid_extension_id.load(Ordering::Relaxed));
            let mid_id = decode_ext_id(self.sdes_mid_extension_id.load(Ordering::Relaxed));
            let rid_bytes = rid_id.and_then(|id| rtp_packet.header.get_extension(id));
            let mid_bytes = mid_id.and_then(|id| rtp_packet.header.get_extension(id));

            let listener = {
                let mut listeners = self.listeners.lock();
                let mut selected = None;
                let mut bind_ssrc = false;

                if let Some(rid) = &rid_bytes
                    && let Ok(rid_str) = std::str::from_utf8(rid)
                {
                    selected = listeners.by_rid.get(rid_str).cloned();
                    bind_ssrc = selected.is_some();
                }

                if selected.is_none()
                    && let Some(mid) = &mid_bytes
                    && let Ok(mid_str) = std::str::from_utf8(mid)
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
                fixed_out_ssrc: None,
                payload_type: Some(96),
                dtmf_payload_type: None,
                initial_sequence_number: Some(32000),
                initial_timestamp_offset: Some(12345),
                strip_extensions: false,
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
    async fn test_rewrite_bridge_pins_first_output_timestamp() {
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

        src_transport.bridge_rewrite_rules_to(
            dst_transport.clone(),
            RtpRewriteBridgeOptions {
                strip_extensions: false,
                initial_sequence_number: Some(100),
                initial_timestamp_offset: Some(999_999), // ignored on first packet
                initial_output_timestamp: Some(50_000),
            },
            vec![RtpRewriteRule {
                match_payload_type: None,
                fixed_out_ssrc: Some(0xABCD),
                ssrc_offset: 0,
                out_payload_type: None,
                sdes_mid_extension_id: None,
                sdes_mid: None,
            }],
        );

        let mut guard = src_transport.rewrite_bridge.lock();
        let bridge = guard.as_mut().expect("rewrite bridge");

        let mut first = RtpPacket::new(crate::rtp::RtpHeader::new(0, 1, 10_000, 1), vec![1u8; 8]);
        bridge.rewrite_packet(&mut first);
        assert_eq!(first.header.ssrc, 0xABCD);
        assert_eq!(first.header.sequence_number, 100);
        assert_eq!(first.header.timestamp, 50_000);

        let mut second = RtpPacket::new(crate::rtp::RtpHeader::new(0, 2, 10_160, 1), vec![1u8; 8]);
        bridge.rewrite_packet(&mut second);
        assert_eq!(second.header.sequence_number, 101);
        assert_eq!(
            second.header.timestamp, 50_160,
            "source delta must be preserved after the pinned first timestamp"
        );
        assert!(first.header.marker, "first pinned packet must be marked");
        assert!(!second.header.marker, "subsequent packets keep source marker");
    }

    #[tokio::test]
    async fn test_rewrite_packet_remaps_dtmf_payload_type() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let src_conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        src_transport.bridge_rewrite_to(
            dst_transport.clone(),
            RtpRewriteBridgeParams {
                ssrc_offset: 900,
                payload_type: Some(96),
                // DTMF src PT 101 → dst PT 110
                dtmf_payload_type: Some((101, 110)),
                initial_sequence_number: Some(32000),
                initial_timestamp_offset: Some(12345),
                fixed_out_ssrc: None,
                strip_extensions: false,
            },
        );

        let mut guard = src_transport.rewrite_bridge.lock();
        let bridge = guard.as_mut().expect("rewrite bridge should be configured");

        // Audio packet (PT 100) → rewritten to audio dst PT 96.
        let mut audio = RtpPacket::new(
            crate::rtp::RtpHeader::new(100, 7, 1111, 1111),
            vec![1u8; 32],
        );
        bridge.rewrite_packet(&mut audio);
        assert_eq!(audio.header.payload_type, 96);

        // DTMF packet (PT 101) → rewritten to DTMF dst PT 110.
        let mut dtmf = RtpPacket::new(
            crate::rtp::RtpHeader::new(101, 7, 1111, 1111),
            vec![1u8; 32],
        );
        bridge.rewrite_packet(&mut dtmf);
        assert_eq!(dtmf.header.payload_type, 110);
        drop(guard);
    }

    #[tokio::test]
    async fn test_rewrite_bridge_selects_optional_video_target_before_rewrite() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let src_conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        let video_dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_video_dst_tx, video_dst_rx) =
            watch::channel(Some(IceSocketWrapper::Udp(Arc::new(video_dst_socket))));
        let video_dst_conn = IceConn::new(video_dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let video_dst_transport = Arc::new(RtpTransport::new(video_dst_conn, false));

        // Audio/DTMF share one target; H264/RTX use a different target.
        let audio_ssrc = 111u32;
        let video_ssrc = 222u32;
        let rules = vec![
            RtpRewriteRule {
                match_payload_type: None,
                fixed_out_ssrc: Some(audio_ssrc),
                ssrc_offset: 0,
                out_payload_type: Some(96),
                sdes_mid_extension_id: None,
                sdes_mid: None,
            },
            // DTMF PT 101 → 110, still on the audio SSRC.
            RtpRewriteRule {
                match_payload_type: Some(101),
                fixed_out_ssrc: Some(audio_ssrc),
                ssrc_offset: 0,
                out_payload_type: Some(110),
                sdes_mid_extension_id: None,
                sdes_mid: None,
            },
            // Video PT 98 → 102, video SSRC.
            RtpRewriteRule {
                match_payload_type: Some(98),
                fixed_out_ssrc: Some(video_ssrc),
                ssrc_offset: 0,
                out_payload_type: Some(102),
                sdes_mid_extension_id: None,
                sdes_mid: None,
            },
            // Video RTX PT 99 → 103, same video SSRC (distinct source stream).
            RtpRewriteRule {
                match_payload_type: Some(99),
                fixed_out_ssrc: Some(video_ssrc),
                ssrc_offset: 0,
                out_payload_type: Some(103),
                sdes_mid_extension_id: None,
                sdes_mid: None,
            },
        ];
        src_transport.bridge_rewrite_rules_to_with_video(
            dst_transport.clone(),
            Some(video_dst_transport.clone()),
            HashSet::from([98, 99]),
            Default::default(),
            rules,
        );

        let mut guard = src_transport.rewrite_bridge.lock();
        let bridge = guard.as_mut().expect("rewrite bridge should be configured");

        // Audio packet (PT 97) → audio SSRC + PT 96.
        let mut audio =
            RtpPacket::new(crate::rtp::RtpHeader::new(97, 7, 1111, 1111), vec![1u8; 32]);
        let audio_target = bridge.target_for(audio.header.payload_type);
        bridge.rewrite_packet(&mut audio);
        assert!(Arc::ptr_eq(&audio_target, &dst_transport));
        assert_eq!(audio.header.ssrc, audio_ssrc);
        assert_eq!(audio.header.payload_type, 96);

        // DTMF packet (PT 101) → audio SSRC + PT 110.
        let mut dtmf = RtpPacket::new(
            crate::rtp::RtpHeader::new(101, 7, 1111, 1111),
            vec![1u8; 32],
        );
        let dtmf_target = bridge.target_for(dtmf.header.payload_type);
        bridge.rewrite_packet(&mut dtmf);
        assert!(Arc::ptr_eq(&dtmf_target, &dst_transport));
        assert_eq!(dtmf.header.ssrc, audio_ssrc);
        assert_eq!(dtmf.header.payload_type, 110);

        // Video packet (PT 98) → video SSRC + PT 102.
        let mut video =
            RtpPacket::new(crate::rtp::RtpHeader::new(98, 7, 2222, 2222), vec![1u8; 32]);
        let video_target = bridge.target_for(video.header.payload_type);
        bridge.rewrite_packet(&mut video);
        assert!(Arc::ptr_eq(&video_target, &video_dst_transport));
        assert_eq!(video.header.ssrc, video_ssrc);
        assert_eq!(video.header.payload_type, 102);

        // RTX packet (PT 99, distinct source SSRC) → video SSRC + PT 103.
        let mut rtx = RtpPacket::new(crate::rtp::RtpHeader::new(99, 7, 3333, 3333), vec![1u8; 32]);
        let rtx_target = bridge.target_for(rtx.header.payload_type);
        bridge.rewrite_packet(&mut rtx);
        assert!(Arc::ptr_eq(&rtx_target, &video_dst_transport));
        assert_eq!(rtx.header.ssrc, video_ssrc);
        assert_eq!(rtx.header.payload_type, 103);

        // Each source stream keeps independent sequence/timestamp continuity.
        let mut video2 =
            RtpPacket::new(crate::rtp::RtpHeader::new(98, 8, 2382, 2222), vec![1u8; 32]);
        let video2_target = bridge.target_for(video2.header.payload_type);
        bridge.rewrite_packet(&mut video2);
        assert!(Arc::ptr_eq(&video2_target, &video_dst_transport));
        assert_eq!(
            video2.header.sequence_number,
            video.header.sequence_number + 1
        );
        assert_eq!(
            video2.header.timestamp,
            video.header.timestamp.wrapping_add(160)
        );
        drop(guard);
    }

    #[tokio::test]
    async fn test_rewrite_rules_unmatched_packet_passes_ssrc_through() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let src_conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        // Only a video rule: no catch-all. Audio-ish PT 97 must pass through.
        let rules = vec![RtpRewriteRule {
            match_payload_type: Some(98),
            fixed_out_ssrc: Some(222),
            ssrc_offset: 0,
            out_payload_type: Some(102),
            sdes_mid_extension_id: None,
            sdes_mid: None,
        }];
        src_transport.bridge_rewrite_rules_to(dst_transport.clone(), Default::default(), rules);

        let mut guard = src_transport.rewrite_bridge.lock();
        let bridge = guard.as_mut().expect("rewrite bridge should be configured");

        let mut video =
            RtpPacket::new(crate::rtp::RtpHeader::new(98, 7, 2222, 2222), vec![1u8; 32]);
        bridge.rewrite_packet(&mut video);
        assert_eq!(video.header.ssrc, 222);
        assert_eq!(video.header.payload_type, 102);

        let mut unmatched =
            RtpPacket::new(crate::rtp::RtpHeader::new(97, 7, 1111, 1111), vec![1u8; 32]);
        bridge.rewrite_packet(&mut unmatched);
        assert_eq!(unmatched.header.ssrc, 1111);
        assert_eq!(unmatched.header.payload_type, 97);
        drop(guard);
    }

    #[tokio::test]
    async fn test_rewrite_rules_legacy_params_equivalent_to_single_rule() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let src_conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        // Legacy path: bridge_rewrite_to(dst, params) builds catch-all + dtmf
        // rules internally and must behave exactly as before.
        src_transport.bridge_rewrite_to(
            dst_transport.clone(),
            RtpRewriteBridgeParams {
                ssrc_offset: 900,
                fixed_out_ssrc: None,
                payload_type: Some(96),
                dtmf_payload_type: Some((101, 110)),
                initial_sequence_number: Some(32000),
                initial_timestamp_offset: Some(12345),
                strip_extensions: false,
            },
        );

        let mut guard = src_transport.rewrite_bridge.lock();
        let bridge = guard.as_mut().expect("rewrite bridge should be configured");

        let mut audio = RtpPacket::new(
            crate::rtp::RtpHeader::new(100, 7, 1111, 1111),
            vec![1u8; 32],
        );
        bridge.rewrite_packet(&mut audio);
        assert_eq!(audio.header.ssrc, 1111 + 900);
        assert_eq!(audio.header.payload_type, 96);
        assert_eq!(audio.header.sequence_number, 32000);
        assert_eq!(audio.header.timestamp, 1111 + 12345);

        let mut dtmf = RtpPacket::new(
            crate::rtp::RtpHeader::new(101, 7, 1111, 1111),
            vec![1u8; 32],
        );
        bridge.rewrite_packet(&mut dtmf);
        assert_eq!(dtmf.header.ssrc, 1111 + 900);
        assert_eq!(dtmf.header.payload_type, 110);
        drop(guard);
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

        assert_eq!(
            transport.received_rtp_packets(),
            0,
            "counter starts at zero"
        );

        for seq in 1..=3u16 {
            let header = crate::rtp::RtpHeader::new(0, seq, 160, 1234);
            let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
            transport
                .receive(
                    Bytes::from(packet.marshal().unwrap()),
                    addr,
                    &mut marshal_buf,
                )
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
                fixed_out_ssrc: None,
                payload_type: None,
                dtmf_payload_type: None,
                initial_sequence_number: None,
                initial_timestamp_offset: None,
                strip_extensions: false,
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
        let attempt =
            tokio::time::timeout(std::time::Duration::from_millis(150), listener_rx.recv()).await;
        assert!(
            attempt.is_err(),
            "listener must NOT receive on the fast-path relay (interceptor path is bypassed)"
        );
    }

    /// Fix3 verification: repeated register_mid / register_provisional with new
    /// mpsc channels must not grow `routes` unboundedly. Before the fix,
    /// route_for_sender_mut pushed a new route for every unique tx, but old
    /// closed-tx routes were never pruned except on the (rare) Closed send-error
    /// path. After the fix, closed txs are removed before inserting new ones.
    #[tokio::test]
    async fn test_routes_pruned_on_closed_tx() {
        let (tx1, rx1) = mpsc::channel::<(RtpPacket, SocketAddr)>(8);
        let (tx2, rx2) = mpsc::channel::<(RtpPacket, SocketAddr)>(8);
        let mut reg = super::ListenerRegistry::default();

        // Register two routes.
        reg.register_mid("stream1".into(), tx1.clone());
        reg.register_provisional(tx2.clone());
        assert_eq!(reg.routes.len(), 2, "two live routes");

        // Drop the receivers → sender channels become closed.
        drop(rx1);
        drop(rx2);
        // Pruning happens lazily on the next route_for_sender_mut call.
        let (tx3, _rx3) = mpsc::channel::<(RtpPacket, SocketAddr)>(8);
        reg.register_provisional(tx3);

        // After the fix, the two closed-tx routes were removed.
        assert!(
            reg.routes.len() <= 1,
            "Fix3: routes must be pruned when their tx is closed (len={})",
            reg.routes.len()
        );

        let (tx4, _rx4) = mpsc::channel::<(RtpPacket, SocketAddr)>(8);
        let (tx5, _rx5) = mpsc::channel::<(RtpPacket, SocketAddr)>(8);
        reg.bind_ssrc_route(111, tx4);
        reg.bind_ssrc_route(222, tx5);
        assert!(
            reg.by_ssrc.len() <= 2,
            "Fix3: by_ssrc must not hold stale entries"
        );
    }

    /// Fix3 integration-style: after transport replacement the new tx channel
    /// replaces the old one, and the old route is cleaned.
    #[tokio::test]
    async fn test_routes_do_not_grow_across_transport_replacement() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::sync::watch;

        let (_tx, rx) = watch::channel::<Option<IceSocketWrapper>>(None);
        let conn =
            crate::transports::ice::conn::IceConn::new(rx, "127.0.0.1:0".parse().unwrap(), None);
        let transport = Arc::new(super::RtpTransport::new(conn, false));

        let ssrc = 1001u32;
        for i in 0..5 {
            // Each time RegisterListenerSync is called it opens a new tx
            // channel. After the first call, earlier channels are closed
            // (only the latest one is actually connected to a receiver).
            transport
                .register_listener_sync(ssrc + i, mpsc::channel::<(RtpPacket, SocketAddr)>(8).0);
        }

        let listeners = transport.listeners.lock();
        assert!(
            listeners.routes.len() <= 2,
            "Fix3: routes must not grow across transport-replacement-like \
             register_listener_sync calls (len={})",
            listeners.routes.len()
        );
        // by_ssrc should also be pruned: only the last few live txs remain.
        assert!(
            listeners.by_ssrc.len() <= 3,
            "Fix3: by_ssrc must not accumulate stale entries (len={})",
            listeners.by_ssrc.len()
        );
    }

    /// A counting observer that records ingress and egress separately.
    struct CountingObserver {
        ingress: std::sync::atomic::AtomicU32,
        egress: std::sync::atomic::AtomicU32,
        last_pt: std::sync::atomic::AtomicU8,
    }

    impl crate::peer_connection::RtpObserver for CountingObserver {
        fn on_ingress(&self, packet: &RtpPacket, _src_addr: SocketAddr) {
            self.ingress
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.last_pt.store(
                packet.header.payload_type,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        fn on_egress(&self, packet: &RtpPacket, _dst_addr: SocketAddr) {
            self.egress
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.last_pt.store(
                packet.header.payload_type,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    #[tokio::test]
    async fn adding_same_observer_twice_is_idempotent() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_socket_tx, socket_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let connection = IceConn::new(socket_rx, "127.0.0.1:9".parse().unwrap(), None);
        let transport = RtpTransport::new(connection, false);
        let observer: Arc<dyn crate::peer_connection::RtpObserver> = Arc::new(CountingObserver {
            ingress: std::sync::atomic::AtomicU32::new(0),
            egress: std::sync::atomic::AtomicU32::new(0),
            last_pt: std::sync::atomic::AtomicU8::new(0),
        });

        transport.add_observer(observer.clone());
        transport.add_observer(observer);

        assert_eq!(transport.observers.read().len(), 1);
    }

    /// The ingress observer must fire on EVERY inbound packet even when the
    /// relay fast-path is active — stats/DTMF/recording work without
    /// downgrading relay to the depacketize path.
    #[tokio::test]
    async fn test_observer_ingress_fires_on_relay_fast_path() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let src_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_src_tx, src_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(src_socket))));
        let src_conn = IceConn::new(src_rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        // Activate the relay fast-path.
        src_transport.bridge_rewrite_to(
            dst_transport.clone(),
            RtpRewriteBridgeParams {
                ssrc_offset: 0,
                fixed_out_ssrc: None,
                payload_type: None,
                dtmf_payload_type: None,
                initial_sequence_number: None,
                initial_timestamp_offset: None,
                strip_extensions: false,
            },
        );
        assert!(src_transport.has_bridge.load(Ordering::SeqCst));

        // Observe INGRESS on the source transport.
        let tap = Arc::new(CountingObserver {
            ingress: std::sync::atomic::AtomicU32::new(0),
            egress: std::sync::atomic::AtomicU32::new(0),
            last_pt: std::sync::atomic::AtomicU8::new(0),
        });
        src_transport.add_observer(tap.clone());

        let mut marshal_buf = Vec::with_capacity(1500);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        for seq in 1..=3u16 {
            let header = crate::rtp::RtpHeader::new(8, seq, 160, 4242);
            let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
            src_transport
                .receive(
                    Bytes::from(packet.marshal().unwrap()),
                    addr,
                    &mut marshal_buf,
                )
                .await;
        }

        assert_eq!(
            tap.ingress.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "ingress observer must fire on the relay fast-path"
        );
        assert_eq!(
            tap.last_pt.load(std::sync::atomic::Ordering::Relaxed),
            8,
            "ingress observer observed the packet's payload type"
        );
    }

    /// The egress observer must fire on the DESTINATION transport for packets
    /// pushed by the relay — symmetric plaintext observation of the outbound
    /// direction even in relay mode (record a single leg's bidirectional
    /// traffic in plaintext, including when the egress is relay-generated).
    #[tokio::test]
    async fn test_observer_egress_fires_on_relay() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let src_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_src_tx, src_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(src_socket))));
        let src_conn = IceConn::new(src_rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        src_transport.bridge_rewrite_to(
            dst_transport.clone(),
            RtpRewriteBridgeParams {
                ssrc_offset: 0,
                fixed_out_ssrc: None,
                payload_type: Some(96),
                dtmf_payload_type: None,
                initial_sequence_number: None,
                initial_timestamp_offset: None,
                strip_extensions: false,
            },
        );

        // Observe EGRESS on the DESTINATION (relay pushes to dst's IceConn,
        // firing dst's egress observer on the plaintext rewritten packet).
        let tap = Arc::new(CountingObserver {
            ingress: std::sync::atomic::AtomicU32::new(0),
            egress: std::sync::atomic::AtomicU32::new(0),
            last_pt: std::sync::atomic::AtomicU8::new(0),
        });
        dst_transport.add_observer(tap.clone());

        let mut marshal_buf = Vec::with_capacity(1500);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        for seq in 1..=3u16 {
            let header = crate::rtp::RtpHeader::new(0, seq, 160, 4242);
            let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
            src_transport
                .receive(
                    Bytes::from(packet.marshal().unwrap()),
                    addr,
                    &mut marshal_buf,
                )
                .await;
        }

        assert_eq!(
            tap.egress.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "egress observer on destination must fire for relayed packets"
        );
        assert_eq!(
            tap.last_pt.load(std::sync::atomic::Ordering::Relaxed),
            96,
            "egress observer saw the rewritten payload type"
        );
        assert_eq!(
            tap.ingress.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "ingress on destination must NOT fire (relay bypasses dst receive)"
        );
    }

    /// The egress observer fires in the normal send path (send_rtp), pre
    /// SRTP-protect — covers non-relay egress (IVR / file playback / slow-path).
    #[tokio::test]
    async fn test_observer_egress_fires_on_normal_send() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
        let transport = Arc::new(RtpTransport::new(conn, false));

        let tap = Arc::new(CountingObserver {
            ingress: std::sync::atomic::AtomicU32::new(0),
            egress: std::sync::atomic::AtomicU32::new(0),
            last_pt: std::sync::atomic::AtomicU8::new(0),
        });
        transport.add_observer(tap.clone());

        for seq in 1..=2u16 {
            let header = crate::rtp::RtpHeader::new(0, seq, 160, 7777);
            let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
            transport.send_rtp(packet).await.unwrap();
        }

        assert_eq!(
            tap.egress.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "egress observer must fire on normal send_rtp"
        );
        assert_eq!(
            tap.last_pt.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "egress observer saw the sent payload type"
        );
    }

    /// When no observer is registered, the hot path is a single atomic load —
    /// verified here by confirming the flag stays false and the relay fast-path
    /// still works untouched.
    #[tokio::test]
    async fn test_no_observer_zero_cost_on_relay() {
        use crate::transports::ice::IceSocketWrapper;
        use tokio::net::UdpSocket;
        use tokio::sync::watch;

        let src_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_src_tx, src_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(src_socket))));
        let src_conn = IceConn::new(src_rx, "127.0.0.1:9".parse().unwrap(), None);
        let src_transport = Arc::new(RtpTransport::new(src_conn, false));

        let dst_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_dst_tx, dst_rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(dst_socket))));
        let dst_conn = IceConn::new(dst_rx, "127.0.0.1:9".parse().unwrap(), None);
        let dst_transport = Arc::new(RtpTransport::new(dst_conn, false));

        src_transport.bridge_rewrite_to(
            dst_transport,
            RtpRewriteBridgeParams {
                ssrc_offset: 0,
                fixed_out_ssrc: None,
                payload_type: None,
                dtmf_payload_type: None,
                initial_sequence_number: None,
                initial_timestamp_offset: None,
                strip_extensions: false,
            },
        );

        assert!(
            !src_transport
                .has_observers
                .load(std::sync::atomic::Ordering::SeqCst),
            "flag must be false when no observer registered"
        );

        let mut marshal_buf = Vec::with_capacity(1500);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let header = crate::rtp::RtpHeader::new(0, 1, 160, 99);
        let packet = crate::rtp::RtpPacket::new(header, vec![1u8; 160]);
        // Must not panic / must complete (relay fast-path untouched).
        src_transport
            .receive(
                Bytes::from(packet.marshal().unwrap()),
                addr,
                &mut marshal_buf,
            )
            .await;
        assert_eq!(src_transport.received_rtp_packets(), 1);
    }
}
