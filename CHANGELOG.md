# Changelog

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
