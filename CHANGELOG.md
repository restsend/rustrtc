# Changelog

## 0.6.8 — 2026-11-23

Control-plane refinements: DTMF/control packets ride media sequences without
stealing playout time, and a local re-offer can be rolled back before the
answer lands.

### Added

- **Local re-offer rollback** (`PeerConnection::rollback_local_offer`,
  `set_local_description(rollback)`): cancels a pending local re-offer on an
  established session and restores the previous SDP and transceiver state.
  Local-only: refused once a remote answer has begun applying, and not
  supported for initial offers, ICE restarts or transport/topology changes.
- **Shared outbound sequence for control packets**
  (`OutboundTimeline::write_control`): locally generated control packets
  (e.g. RFC 4733 telephone events) take the next sequence on the media
  timeline while keeping their own payload-clock timestamp; the next peer
  frame continues after them.
- **RTP observer callbacks**: `RtpObserver::on_ingress_parse_error` (inbound
  RTP/SRTP datagram failed header parsing) and `on_send_complete` (awaited
  send finished with bytes written). Both have default no-op impls; existing
  observers are unaffected.

### Fixed

- **JitterBuffer control packets** (`push_control`): negotiated control
  packets sharing the media SSRC are buffered in sequence order but no
  longer consume playout duration, skew `last_delivered_timestamp`, or
  trigger spurious timestamp-discontinuity resets; capacity is enforced on
  media duration, not packet count.
- **Peer event stream**: closing the connection no longer blocks concurrent
  `recv()` waiters on an internal mutex — waiters share the queued backlog
  and all wake on close; queued events keep weak references so a backlog
  cannot pin the transceiver graph.
- **Unsequenced video fragments**: locally packetized video frames without
  RTP sequence numbers now get distinct, continuous sequence numbers on the
  outbound timeline instead of failing the peer mapping and being dropped.
- **BUNDLE tag re-selection**: when the offered BUNDLE tag's m-line is
  rejected (port 0), the answer re-selects the tag among the remaining
  bundled members even if they are bundle-only (wire port 0, RFC 9143
  §7.3.3) — previously the whole group was dropped and no
  `a=group:BUNDLE` line was emitted.
- **First nomination follows immediately**: a controlled agent adopts the
  controlling peer's nominated pair at once even when its own check round
  already committed a best-effort pair (e.g. a relay pair that raced
  ahead). Previously the first nomination was downgraded to a deferred
  verification while the PC reported connected, leaving both sides on
  different 5-tuples until the verification landed (RFC 8445
  §7.3.1.5/§8.1.2). Later nominations keep the defer+verify switching
  protection.
- The pion interop example now negotiates `transport-cc` rtcp-fb so TWCC
  feedback (and the GCC estimator it feeds) is actually exercised.

No breaking API changes.

## 0.6.7 — 2026-11-20

### Added

- **RFC 4588 RTX relay**: retransmission-stream relay with FID source/RTX
  stream tracking and dynamic video payload capabilities negotiated after
  construction.

### Fixed

- Late pre-anchor peer RTP packets on a fresh source are dropped instead of
  re-anchoring the timeline mid-run.
- RTCP: unsupported feedback formats are skipped instead of blocking the
  compound packet; the direct UDP receive buffer is raised.
- ICE: the unlatched RTCP source IP is synced when RTP latches first behind
  NAT (asymmetric port rebinding).

## 0.6.6 — 2026-11-19

H.265/HEVC payloads, faster SRTP, and a leaner SCTP send path.

### Added

- **H.265/HEVC RTP payload (RFC 7798)**: `H265Payloader`, `H265Packetizer` /
  `H265Fragments` and `H265Depacketizer` handle Single NAL, AP (type 48) and
  FU (type 49) with sequence/timestamp continuity checks;
  `VideoCapability::h265()`, `h265_with_rtx(pt)` and
  `h265_with_param_sets(vps, sps, pps)` (base64 `sprop-*` fmtp) advertise it
  in SDP. No DONL (`sprop-max-don-diff=0`, the WebRTC default).

### Changed

- **SRTP AES-GCM now uses `ring` by default** (`srtp-ring`, part of the
  default feature set): the 1200-byte protect path drops from ~628 ns to
  ~306 ns per packet (1.8 → 3.7 GB/s). The wire format is unchanged (RFC 3711
  vectors pass on both backends); `no_std` and
  `--no-default-features --features std` keep the pure-Rust RustCrypto path.
- **SCTP send path**: the DTLS hand-off is inline (the pump task/queue is
  gone), and isolated small messages flush from the sender instead of waking
  the run loop; large/batched sends keep the batched path.

### Performance

- Standalone libwebrtc (M150) vs rustrtc on the same host — data channels
  (SCTP over DTLS): RTT p50 445–459 vs 326–376 µs; 64 KB throughput 59 vs
  157–164 MB/s; 1 KB message rate 28.6k vs 140k msg/s; setup 126–131 vs
  5–15 ms; PSS 13–18 vs 9–10 MB.
- SRTP AES-GCM (protect/roundtrip, 1200 B, single core) against libsrtp (the
  engine libwebrtc wraps): 3762/1645 vs 2724/1295 MB/s (1.38×/1.27×); 200 B
  1.41×/1.47×; 64 B 2.06×/1.68×.
- Known gap: AES-CM/HMAC-SHA1 at 1200 B is still ~0.68× of libsrtp on hosts
  without SHA-NI (Coffee Lake); browsers/libwebrtc negotiate AES-GCM.

No breaking API changes.

## 0.6.5 — 2026-11-19

Idle `PeerConnection` teardown is deterministic.

### Changed

- `PeerConnection::recv()` now ends when the connection is closed: events
  queued before `close()` are still delivered, then `None` is returned, and
  later calls return `None` immediately. A call that is already blocked wakes
  on close. This makes `while let Some(event) = pc.recv().await` terminate on
  its own, so tasks holding a `PeerConnection` handle no longer pin the
  connection (and its per-call state) forever. `Failed` keeps the stream open
  so ICE restarts and renegotiation can still be observed. Regression guards:
  `tests/recv_closed.rs`, `tests/resource_reclaim_test.rs`.

### Fixed

- **ICE runner release on close.** `IceTransportRunner::run` drives its arms
  through a hand-rolled `poll_fn` that rebuilds — and therefore drops — its
  sub-futures on every poll, so the waker registered by
  `watch::Receiver::changed()` does not survive a `Pending`. `stop()` only
  flipped the state to `Closed`, so a runner closed before it carried any
  traffic stayed parked until the next 1 s keepalive tick, keeping the whole
  `IceTransportInner` (≈20 KB plus its sockets) alive per closed connection;
  sustained connection churn accumulated them. `stop()` now also sends
  `IceCommand::Shutdown` over the command channel, whose waker is owned by the
  receiver, so the runner returns immediately. Regression guard:
  `transports::ice::tests::stop_wakes_the_runner_promptly`.
- `run_gathering_loop` checks for a terminal ICE state when it starts, so a
  loop first polled after `stop()` can no longer miss `Closed` and park
  forever waiting for the next update.

No compile-time API changes. `recv()` terminates on close now; see the
behaviour note above.

## 0.6.4 — 2026-11-09

no_std GCC/TWCC congestion control + an injectable hardware clock.

### Added

- `platform::time::set_now_fn(fn() -> u64)`: embedders inject a hardware
  monotonic millisecond clock. Without it the no_std logical clock only moves
  when `advance_ms` is called, which freezes every `Instant`-delta consumer
  (GCC trendline, retransmit timers, TWCC cadence) on real hardware.
- GCC and TWCC now compile and run without `std`:
  - `media::gcc` / `media::twcc_feedback` lose their `std` module gates.
  - `parking_lot::Mutex` → `platform::sync::Mutex` (parking_lot-compatible
    guard API on both backends).
  - `tokio::sync::watch` → `platform::sync::watch`.
  - `tokio::time::interval` → `platform::task::interval_after` (the mock
    executor drives it through the injected sleep factory).
  - `std::time::Instant` → `platform::time::Instant`.
  - `std::collections::HashMap` → `alloc::collections::BTreeMap`;
    `AtomicU64` → `platform::atomic64::AtomicU64` (RV32/Xtensa have no 64-bit
    atomics); `std::net::SocketAddr` → `core::net::SocketAddr`.
  - Removed the inert `std_gated` GCC/TWCC stubs from `peer_connection`.
  - `RtpSender::target_bitrate()` / `subscribe_target_bitrate()` and the
    `as_gcc_stats` downcast are available on every target.
- `tests/time_now_seam.rs`: injected clock drives `Instant::now()` deltas.
- The no_std WebRTC e2e asserts `transport-cc` negotiation and the sender's
  GCC estimator/watch; `scripts/check-no_std.sh` runs the clock-seam test.

No API-breaking changes.

## 0.6.3 — 2026-11-09

Patch release: no_std SCTP data channels are now usable end to end.

### Added

- `no_std` DataChannel API. `PeerConnection::create_data_channel`,
  `send_data`, `send_text`, `sctp_buffered_amount`,
  `sctp_diagnostic_info`, and `sctp_link_stats` are available without the
  `std` feature; `DataChannel`, `DataChannelConfig`, `DataChannelEvent`,
  `DataChannelState`, and `SctpLinkStats` are re-exported from the crate
  root on every target.
- `tests/no_std_datachannel_e2e.rs`: two no_std `PeerConnection`s on the
  mock embedded runtime negotiate `m=application`, run ICE + DTLS + SCTP,
  exchange DCEP OPEN/ACK for two channels, and carry binary messages in both
  directions.
- `scripts/check-no_std.sh` now also runs the no_std WebRTC and data-channel
  end-to-end suites.

### Fixed

- Embedded mpsc `try_recv` was `unimplemented!`; the SCTP runner's batch
  drain after a wake therefore panicked on the first data packet. It now
  pops the queue and reports an empty closed channel as `Ok(None)`.
- Unit tests that fabricate timer deadlines now start the std test clock at
  a non-zero base, so `now - 1.5 s` no longer saturates at zero and makes
  the fabricated TSN look newer than the RTO deadline.
- `test_slower_higher_priority_pair_upgrades_after_nomination` pins the ICE
  agents to loopback and derives the slow candidate priority from the
  controlled host candidates, removing multi-interface/clock flakiness.
- `direct_av_offer_proposes_bundle_with_a_port_per_mline` no longer assumes
  the RTCP port is exactly `RTP + 1` (parallel tests can take the adjacent
  port); it asserts a distinct, non-zero reservation per m-line instead.

No API-breaking changes.
