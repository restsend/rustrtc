# Changelog

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
