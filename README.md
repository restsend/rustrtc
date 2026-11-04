# rustrtc

[![Crates.io](https://img.shields.io/crates/v/rustrtc.svg)](https://crates.io/crates/rustrtc)
[![Documentation](https://docs.rs/rustrtc/badge.svg)](https://docs.rs/rustrtc)

A high-performance, full-stack real-time communication library — **WebRTC, RTP/SRTP, T.38 Fax, and UPnP NAT traversal** — all through a **unified `PeerConnection` API**.

## Features

- **High performance** — ~3.9× faster than `webrtc-rs` and ~3.7× faster than `pion` (Go) in throughput, with ~52% less memory than `webrtc-rs` (see the benchmark below).
- **Full protocol stack** — WebRTC, RTP, SRTP, and **T.38 fax** in a single library, plus **UPnP IGD** NAT traversal. Few moving parts, no missing pieces.
- **Unified `PeerConnection` API** — one interface for every transport combination (any `Connectivity` × any `Keying`, plus T.38). No fragmented APIs.
- **WebRTC compliant** — interoperable with Chrome/WebRTC and pion; offer/answer, renegotiation, rollback, and standard SDP attributes.
- **ICE restart** — `restart_ice()` for network migration / re-INVITE flows, with automatic detection of remote-initiated restarts (RFC 8445 §9).
- **Complete media pipeline** — packetizer/depacketizer (VP8, VP9, H264, Opus, G.711/G.722/G.729), jitter buffer, NACK/RTX, FIR/PLI, TWCC, and REMB for audio and video.
- **Bandwidth estimation (GCC)** — generates TWCC receiver feedback, stamps transport-wide sequence numbers on outbound RTP, and exposes a live `target_bitrate` estimate for encoder adaptation (`RtpSender::subscribe_target_bitrate`).
- **Full ICE** — STUN, TURN (UDP + TCP), ICE Lite, ICE TCP (RFC 6544), single-port UDP mux for SFU/WHEP deployments, and **mDNS candidate obfuscation** (`enable_mdns`).
- **NAT traversal & deployment** — RTP latching, UPnP IGD port mapping, and firewall-friendly port ranges (`rtp_start_port`/`rtp_end_port`).
- **`no_std` / embassy-ready** — the full ICE/STUN/TURN + DTLS-SRTP + SDES media stack (any `Connectivity` × any `Keying`) runs on any executor behind seven injected platform seams, end-to-end tested against a mock embedded runtime (`scripts/check-no_std.sh`).
- **Production extras** — RTP rewrite bridge (SSRC/PT/sequence remapping) and a WebRTC-compatible stats model.

## no_std / Embedded Support

rustrtc builds without `std` (`alloc`-only) and runs its embedded delivery
surface entirely on top of platform seams that the embedder implements
(embassy, esp-rtos, or any executor).

**Embedded delivery surface:**

- Full **ICE/STUN/TURN** stack, RTP/RTX, **SDP**
- `PeerConnection` with **full ICE + DTLS-SRTP** and with
  **SDES-SRTP or plain RTP over a direct transport**:
  offer/answer, media send/receive
- Self-contained **DTLS 1.2** implementation behind the crypto seam
  (ECDSA-P256 + ECDH), with a pure-Rust `crypto-p256` reference backend
- Media pipeline: packetizers/depacketizers, jitter buffer, NACK/RTX

DTLS keying on no_std requires a pre-provisioned DTLS certificate
(`RtcConfiguration::dtls_certificate` — DER leaf + PKCS#8 key, e.g.
factory-provisioned); there is no certificate generation without `std`.

This surface is covered by end-to-end tests against a mock embedded runtime
(`tests/no_std_ice_e2e.rs`, `no_std_dtls_e2e.rs`, `no_std_pc_srtp_e2e.rs`):
two no_std `PeerConnection`s negotiate SDES via offer/answer, connect over a
loopback network, and exchange SRTP media with payload-order verification; a
no_std DTLS 1.2 handshake runs against the `crypto-p256` reference backend.
A full-WebRTC-mode integration suite (`no_std_pc_webrtc_e2e.rs`) drives the
same flow through `PeerConnection` and is landing alongside executor-fidelity
work in the test harness.

**Still std-only:** T.38/UDPTL, GCC/TWCC bandwidth estimation (the media
modules compile, the PC pipeline uses a stub), ICE-TCP, UPnP, mDNS, and
certificate *generation* (use `dtls_certificate` instead). SCTP/DataChannel
compiles under no_std; its runtime e2e lands with the test-executor
fidelity work in progress.

### Gates

```bash
sh scripts/check-no_std.sh
```

runs the full no_std gate suite: host `--no-default-features` check, a
cross-check for `riscv32imac-unknown-none-elf` (ESP32-C3 core; exercises the
64-bit-atomic fallback), all seam/e2e suites, a DTLS e2e with the
`crypto-p256` backend, and the std matrix guard. For Xtensa targets
(`xtensa-esp32s3-none-elf`) install `espup` and build the same way with
`-Zbuild-std=core,alloc`.

### Platform seams

The library is backend-free under `no_std`: every runtime capability is an
injection point in `src/platform.rs` that the embedder wires once at boot.

| Seam | Wire it to | Contract |
|---|---|---|
| `platform::task::set_sleep_fn` | embassy-time `Timer::after` | Panic if unset — no hidden fallbacks |
| `platform::task::set_spawn_fn` / `set_spawner` | your executor's spawner | Panic if unset |
| `platform::rng::set_fill_fn` | TRNG (e.g. `esp_hal::rng::Rng`) | Panic if unset — never zeros |
| `platform::net::set_udp_bind_fn` | embassy-net UDP (+ demux) | First bind backend; tokio under std |
| `transports::set_local_ip_fn` | station IP (WiFi up) | Error until wired |
| `platform::dns::set_resolver` | embassy-net DNS | Error until wired |
| `platform::crypto::set_crypto` | optional: `crypto-p256` reference or hw-accel | Built-in fallback with the feature |

A boot sequence looks like this (the complete, runnable shape lives in
`tests/no_std_pc_srtp_e2e.rs`):

```rust,ignore
// CSPRNG — REQUIRED before any key material exists (ICE/DTLS/SDES).
rustrtc::platform::rng::set_fill_fn(trng_fill);            // esp-hal TRNG
// Timers — embassy-time (handshake retransmits, keepalives, RTCP).
rustrtc::platform::task::set_sleep_fn(|dur| {
    Box::pin(embassy_time::Timer::after(embassy_time::Duration::from_millis(
        dur.as_millis() as u64,
    ))) as Pin<Box<dyn Future<Output = ()> + Send>>
});
// Executor — spawn ICE/PC tasks onto esp-rtos/embassy.
rustrtc::platform::task::set_spawn_fn(|fut| spawner.spawn(fut).ok());
// UDP — embassy-net socket factory behind ICE candidates / direct RTP.
rustrtc::platform::net::set_udp_bind_fn(embassy_udp_bind);
// Network identity — once WiFi/DHCP is up.
rustrtc::transports::set_local_ip_fn(|| Some(sta_ip));
```

The no_std wall clock is a logical clock (`platform::time::advance_ms` /
`set_now_ms`); tick it from a periodic task if uptime-based accounting or
`Instant::elapsed()` matter to you. The DTLS certificate is flash-provisioned
DER (`Certificate::from_pkcs8_der`) — there is no certificate generation
without `std`.

## Benchmark (rustrtc vs webrtc-rs & pion) in 0.5.0

**CPU:** `Intel(R) Core(TM) i7-9700T CPU @ 2.00GHz` (8 cores)  
**OS:** `Debian 13, 6.12.101+deb13-amd64`  
**Compiler:** `rustc 1.99.0`, `go version go1.24.4 linux/amd64`  
**Method:** `cargo run -r --example benchmark`, median of 3 runs (the host is a
shared CI box, so the per-run `rustrtc/webrtc` ratio is the load-independent
signal). Same host, script and peers as the 0.3.141 numbers published earlier.

```shell
Comparison (Baseline: webrtc) — median of 3
Metric               | webrtc     | rustrtc    | pion      
--------------------------------------------------------------------------------
Setup Latency (ms)   | 2.14       | 0.61       | 4.00      
Throughput (MB/s)    | 104.28     | 504.51     | 132.57    
Msg Rate (msg/s)     | 106783.25  | 516615.42  | 135748.96 
CPU Usage (%)        | 487.40     | 580.55     | 547.40    
Memory (MB)          | 42.00      | 21.00      | 47.00     
--------------------------------------------------------------------------------
```

**Key Findings:**

- **Throughput**: `rustrtc` is ~4.8× faster than `webrtc-rs` and ~3.8× faster than
  `pion` (per-run ratios: 3.87–5.12× and 3.05–3.84×).
- **Memory**: `rustrtc` uses ~50% less memory than both peers.
- **Setup latency**: 0.61 ms — ~3.5× faster than `webrtc-rs` (2.14 ms) and ~6.6×
  faster than `pion` (4.0 ms).
- **Efficiency per CPU**: 0.87 MB/s per CPU-percent vs 0.24 (pion) and 0.21
  (webrtc-rs) — `rustrtc` delivers ~3.6× more throughput per unit of CPU.
- **Stable across releases**: the `webrtc-rs` ratio series is 2.95× (0.3.114) →
  3.3× (0.3.141) → **3.9× (0.5.0)**, with the TWCC/GCC pipeline active in every run.

### What changed under the hood in 0.5.0

- **SRTP GCM on aarch64 runs hardware AES now**: `aes-gcm` was pinned to `aes 0.8`,
  which has no aarch64 hardware backend — every GCM packet ran fixslice software AES
  on ARM. On Apple Silicon the SRTP AES-GCM roundtrip went from 112k to 2076k ops/s
  (18.5×); x86_64 already had runtime AES-NI detection and gains are instead ~+13%
  median throughput from the allocation/lock cleanup below.
- **Zero-allocation hot paths**: per-packet vectors on the SRTP protect/unprotect
  paths are gone (caller-owned buffers: `RtpTransport::send_rtp_into`), SRTCP GCM
  encrypts/decrypts in place, and `RtpTransport::with_srtp_session` amortizes the
  session lock across a whole frame.
- **Anti-replay window** (RFC 3711 §3.3.2): duplicates and out-of-window packets are
  rejected before any crypto work (`SrtpError::ReplayRejected`), with the window
  committed only after authentication so forged indices cannot poison it. Overhead
  below measurement noise.
- **Datachannel throughput doubled** on this host: SCTP benchmark 102 → 201 MB/s
  (1 GB over a loopback WebRTC association), from the same record-layer crypto fix.
- **Connection setup**: the DTLS certificate is generated once per process
  (was per PeerConnection) — 0.38 ms → 8.8 µs per connection (43×).

Micro-benchmarks live in `examples/`: `gcm_backend_bench` (SRTP crypto backends,
session roundtrip, frame batch), `sctp_benchmark` (datachannel throughput),
`cert_cache_bench` (setup), `aes_block_probe` / `dual_stack_probe` (platform probes).
## Usage

Here is a simple example of how to create a `PeerConnection` and handle an offer:

```rust
use rustrtc::{PeerConnection, RtcConfiguration};

#[tokio::main]
async fn main() {
    let config = RtcConfiguration::webrtc();
    let pc = PeerConnection::new(config);

    // Create a Data Channel
    let dc = pc.create_data_channel("data", None).unwrap();

    // Handle received messages
    let dc_clone = dc.clone();
    tokio::spawn(async move {
        while let Some(event) = dc_clone.recv().await {
            if let rustrtc::DataChannelEvent::Message(data) = event {
                println!("Received: {:?}", String::from_utf8_lossy(&data));
            }
        }
    });

    // Create an offer
    let offer = pc.create_offer().await.unwrap();
    pc.set_local_description(offer).unwrap();

    // Wait for ICE gathering to complete
    pc.wait_for_gathering_complete().await;

    // Get the complete SDP with candidates
    let complete_offer = pc.local_description().unwrap();
    println!("Offer SDP: {}", complete_offer.to_sdp_string());
}
```

## Configuration

All configuration goes through `RtcConfiguration` (or its builder `RtcConfigurationBuilder`). There is no default: start from the kind of peer, `RtcConfiguration::webrtc()` or `RtcConfiguration::sip()` (`RtcConfigurationBuilder::webrtc()` / `::sip()`), then change what you need. The two differ only in these fields:

| Field | `webrtc()` | `sip()` |
|---|---|---|
| `connectivity` | `Ice` | `Sdp` |
| `keying` | `Dtls` | `None` |
| `webrtc_extensions` | `true` | `false` |
| `rtcp_mux_policy` | `Require` | `Negotiate` |
| `bundle_policy` | `MaxBundle` | `Balanced` |

| Peer | Start from | Then |
|---|---|---|
| Browser, SFU (WebRTC) | `webrtc()` | |
| SIP trunk, plain RTP | `sip()` | |
| SIP trunk, SDES-SRTP | `sip()` | `keying = Keying::Sdes` |
| SIP phone with ICE (e.g. Linphone) | `sip()` | `connectivity = Connectivity::IceLite`, `keying = Keying::Sdes` |

### Transport & Network
- **`connectivity`** — How the media path is found: `Connectivity::Ice` (full ICE), `Connectivity::IceLite` (ICE-lite, RFC 8445 §2.5), or `Connectivity::Sdp` (the `c=`/`m=` address of the peer's SDP, no ICE).
- **`keying`** — How the SRTP keys are exchanged: `Keying::Dtls` (DTLS-SRTP), `Keying::Sdes` (`a=crypto`, RFC 4568), or `Keying::None` (plain RTP). Any keying works with any connectivity; data channels need `Keying::Dtls`.
- **`webrtc_extensions`** — The peer is a WebRTC endpoint: offers claim rid and abs-send-time (and with `enable_gcc`, transport-cc) header extensions, and descriptions carry `msid`. SIP peers do not use them.
- **`bundle_policy`** — Which m-lines of an offer have a transport of their own (RFC 9429 §4.1.1). An offer with two or more m-lines proposes BUNDLE (RFC 8843), with the `sdes:mid` header extension; when the answer accepts it, all m-lines share one transport. The policy decides what a peer without BUNDLE gets: `Balanced` gives a transport to the first m-line of each kind, `MaxCompat` to every m-line, `MaxBundle` to the first only; the others are offered bundle-only (port 0). An answer to an offer without BUNDLE rejects the m-lines that the policy gives no transport. Full ICE always works as `MaxBundle`.
- **`rtcp_mux_policy`** — RTP/RTCP multiplexing (RFC 5761). `Negotiate` offers `a=rtcp-mux` and reserves an RTCP port (`a=rtcp`) for an answer that refuses it; many SIP peers do. `Require` also offers `a=rtcp-mux-only` (RFC 8858) and makes a remote description without `a=rtcp-mux` an error. Answers multiplex when the offer does. Full ICE always works as `Require`.

Migration from `TransportMode`: `WebRtc` is `webrtc()`; `Rtp` is `sip()`; `Srtp` is `sip()` with `Keying::Sdes`. `enable_ice_lite = true` is `Connectivity::IceLite`. `RtcConfiguration::default()` is `webrtc()`, `RtcConfigurationBuilder::new()` is `RtcConfigurationBuilder::webrtc()`. `SdpCompatibilityMode::LegacySip` is gone: SIP peers ignore BUNDLE and `a=mid` when they do not support them.
- **`ice_servers`** — STUN/TURN server list.
- **`ice_transport_policy`** — `All` or `Relay`.
- **`rtp_start_port` / `rtp_end_port`** — Restrict RTP/ICE to a port range.
- **`external_ips`** — Public addresses to advertise instead of the local ones (1:1 NAT, a router that forwards the RTP ports), at most one per family (IPv4 + IPv6). A candidate takes the external address of its family, and so do `c=` and `o=`; a family with none advertises the local address.
- **`external_ip_candidate_type`** — How ICE advertises `external_ips`: `Host` (default) replaces the host candidate's address; `ServerReflexive` keeps the host candidate and adds the external address as a srflx candidate on the same socket (1:1 NAT, RFC 8445 §5.1.1.2). Full ICE only.
- **`bind_ips`** — Local addresses to bind media sockets on, one socket each (e.g. `["::"]` for one dual-stack socket, or `["127.0.0.1", "::1"]` for one socket per family). Empty: chosen automatically (full ICE: every interface; a direct transport (`Connectivity::Sdp` / `Connectivity::IceLite`): the address of the default route).
- **`external_port`** — Advertise this fixed port in the SDP `m=` line and candidates instead of the local bind port (NAT port forwarding: external 30000 → local 20000). Works alone or with `external_ips`. Direct transports only; not used with full ICE.
- **`disable_ipv6`** — Disable IPv6 candidate gathering.
- **`ice_tcp_policy`** — `IceTcpPolicy::Disabled` (default), `IceTcpPolicy::Enabled`, or `IceTcpPolicy::PassiveOnly`. Controls ICE TCP candidate support per RFC 6544.
- **`ice_udp_mux`** / **`ice_udp_mux_port`** — Share a single UDP socket across many `PeerConnection`s (single-port multiplexing for SFU/WHEP). Set `ice_udp_mux = true` and `ice_udp_mux_port = <port>`; incoming packets are demuxed by the server ufrag in the STUN Binding Request, then by remote source address.
- **`enable_mdns`** — Advertise host candidates via mDNS (`<random>.local` hostnames instead of local IPs, draft-ietf-rtcweb-mdns). A built-in mDNS responder answers A/AAAA lookups; real addresses are kept internally so connectivity is unaffected. Default: `false`.

### SDES Keying (`Keying::Sdes`)
Re-INVITE renegotiation keeps the call keyed without restarting media:
- **Answers keep our key** — a re-INVITE answer reuses the key we are already sending with, so the peer does not drop our audio mid-call. A new key is generated only when the crypto suite changes.
- **Peer key changes are applied** — if the peer offers a new key at the same suite, the SRTP/SRTCP sessions are re-keyed once the offer/answer exchange completes (signaling back at `Stable`); packets in flight under the old key may be dropped during the switchover.

### Bandwidth Estimation (GCC)
- **`enable_gcc`** — TWCC + GCC loop (default: `true`): outbound RTP is stamped with transport-cc sequence numbers, TWCC feedback is generated for inbound streams, and each `RtpSender` publishes a bandwidth estimate. The library does not throttle sends itself — drive your encoder from `RtpSender::subscribe_target_bitrate()`:

```rust
let mut rx = sender.subscribe_target_bitrate().unwrap();
while let Ok(new_bps) = rx.changed().await {
    encoder.set_bitrate(*rx.borrow());
}
```

### ICE Restart
```rust
pc.restart_ice().await?;      // rolls fresh ICE credentials (RFC 8445 §9)
let offer = pc.create_offer().await?;  // carries the new ice-ufrag/pwd
```
Remote-initiated restarts (peer offers new credentials) are detected and mirrored automatically. DTLS/SRTP survive across the restart.

### UPnP
- **`enable_upnp`** — Auto-map ports via UPnP IGD.
- **`upnp_lease_duration`** — UPnP port mapping lease duration in seconds (default: 3600).

### DTLS
- **`dtls_certificate`** — Pre-provisioned DTLS certificate (DER leaf + PKCS#8 key) for DTLS keying. Optional on `std` (a self-signed certificate is generated per connection); **required on no_std**, where certificates cannot be generated. `Debug` output is redacted; the field is `serde`-skipped so key material never enters serialized configs.

```rust,ignore
let cert = rustrtc::transports::dtls::Certificate::from_pkcs8_der(cert_der, key_der)?;
let config = RtcConfigurationBuilder::webrtc()
    .dtls_certificate(Arc::new(cert))
    .build();
```

### RTP Latching
- **`enable_latching`** — Enable dynamic remote address detection on direct transports (`Connectivity::Sdp` / `Connectivity::IceLite`).
- **`probation_max_packets`** — Number of packets to observe before committing a latched address. A single packet (marker or not) never moves the egress address: candidates win by consecutive sequence numbers with a consistent SSRC, or by the observation-budget fallback.

After the initial latch, the connection supports **competitive re-latch** for NAT rebinding (the peer switching networks without a re-INVITE): a new source takes over the egress path only after 4 consecutive-sequence packets carrying one SSRC within a 2 s window. Switches are rate-limited (10 s cooldown, max 4 per session, frozen afterwards until a new SDP retargets). Two RTCP packets are required to move a non-mux RTCP destination.

Every latch commit and re-latch is observable:
- **`RtpObserver::on_source_change(&SourceChange)`** — `from`/`to` addresses, driving SSRC, and the switch index (0 = initial latch). Register via `PeerConnection::add_observer`.
- **Stats** — `srcAddr` (current egress target) and `relatchCount` on the `ice-conn` stats entry.
- **Logs** — latch commits at `INFO`, suppressed probes (cooldown/budget exhausted) at `DEBUG`/`WARN`.

Note: persistence-based latching is accident-robustness (stale NAT bindings, port reuse, stray packets), not a security boundary — keep SDP/confidential signaling as the outer defense.

### Media Capabilities
- **`media_capabilities`** — Configure audio/video/image (T.38) codecs and SCTP port via `MediaCapabilities`. Video presets: `VideoCapability::default()` (VP8), `VideoCapability::vp9()` / `vp9_with_rtx(pt)` (RFC 9628), `VideoCapability::h264()`.
- **`ssrc_start`** — Starting SSRC value for local tracks (later tracks count up from it). Random by default per RFC 3550 §8.1; pin it only if your deployment needs deterministic SSRCs. Note: two configs from the same constructor therefore never compare equal via `PartialEq`.
- **`depacketizer_strategy`** — Pluggable per-kind depacketizer (e.g. `Vp9Depacketizer` for RFC 9628 VP9 reassembly).

### SCTP (Data Channels)
Defaults from `RtcConfiguration::webrtc()` / `::sip()`:
- `sctp_rto_initial` — initial retransmission timeout, 3 s
- `sctp_rto_min` / `sctp_rto_max` — retransmission-timeout bounds, 200 ms / 60 s
- `sctp_max_association_retransmits` — INIT/HEARTBEAT retransmits before abort, 20
- `sctp_receive_window` — advertised receive window, 128 KB
- `sctp_heartbeat_interval` / `sctp_max_heartbeat_failures` — idle-association probing, 15 s / 4 misses
- `sctp_max_tsn_retransmits` — per-chunk retransmit limit before abort, 8
- `sctp_max_burst` — packets per burst (0 = built-in heuristic)
- `sctp_max_cwnd` — congestion-window ceiling, 256 KB
- `sctp_max_buffered_amount` — per-channel send gate, 256 KB (0 = unbounded)

### RTP Buffer
- `rtp_buffer_capacity` — Per-SSRC receive buffer capacity.
- `buffer_drop_strategy` — `DropNew` or `DropOldest` when buffer is full.

```rust
use rustrtc::{
    PeerConnection, RtcConfiguration, RtcConfigurationBuilder,
    IceServer, Keying, config::T38Capability,
};

// Using builder
let config = RtcConfigurationBuilder::sip()
    .enable_latching(true)
    .probation_max_packets(Some(5))
    .rtp_port_range(50000, 50100)
    .enable_upnp(true)
    .ice_tcp_policy(config::IceTcpPolicy::Enabled)
    .ice_server(IceServer::new(vec!["stun:stun.l.google.com:19302"]))
    .build();

let pc = PeerConnection::new(config);
```

```rust
// Direct field access
let mut config = RtcConfiguration::sip();
config.keying = Keying::Sdes;
config.enable_latching = true;
config.rtp_start_port = Some(50000);
config.rtp_end_port = Some(50100);
config.enable_upnp = true;
```

## T.38 fax

The `t38` feature provides a complete T.38 v3 terminal: IFP wire codec, UDPTL
transport (with redundancy and gap recovery), a T.30 session engine
(CED/DIS → DCS/TCF → CFR → page → EOP/MCF → DCN, with timers and retries),
and V.21/V.27ter DSP for audio-gateway use.

```rust
use rustrtc::t38::endpoint::{FaxEndpoint, ReceiveCodec};
use rustrtc::t38::t30::{T30FaxConfig, T30Role, T30Session};

let mut session = T30Session::new(T30FaxConfig::default());
session.role = T30Role::Callee;
let endpoint = FaxEndpoint::from_socket(socket, remote, session);
endpoint.set_codec(ReceiveCodec::Wire);
let events = endpoint.run_call(60_000).await; // drives the whole fax session
```

### spandsp interop e2e

`tests/t38_spandsp_interop.rs` runs real fax sessions against a spandsp-based
T.38 terminal (`tools/t38-peer/t38_peer.py`, ctypes over the system
libspandsp). Both directions are covered: rustrtc-caller→spandsp-callee
(pixel-exact page verification) and spandsp-caller→rustrtc-callee.

```
# requires: python3 + PIL, and libspandsp (brew install spandsp)
cargo test --features t38,t38-interop --test t38_spandsp_interop
```

Without the `t38-interop` feature the tests compile to nothing; with the
feature but without python3/libspandsp they skip at runtime.

## Examples

You can run the examples provided in the repository.

### SFU (Selective Forwarding Unit)

A multi-user video conferencing server. It receives media from each participant and forwards it to others.

1. Run the server:

    ```bash
    cargo run --example rustrtc_sfu
    ```

2. Open your browser and navigate to `http://127.0.0.1:8081`. Open multiple tabs/windows to simulate multiple users.

![rustrtcsfu](./rustrtc_sfu.png)

### Echo Server

The echo server example demonstrates how to accept a WebRTC connection, receive data on a data channel, and echo it back. It also supports video playback if an IVF file is provided.

1. Run the server:

    ```bash
    cargo run --example echo_server
    ```

2. Open your browser and navigate to `http://127.0.0.1:3000`.

### DataChannel Chat

A multi-user chat room using WebRTC DataChannels.

1. Run the server:

    ```bash
    cargo run --example datachannel_chat
    ```

2. Open your browser and navigate to `http://127.0.0.1:3000`. Open multiple tabs to chat between them.

### Audio Saver

Records audio from the browser's microphone and saves it to a file (`output.ulaw`) on the server.

1. Run the server:

    ```bash
    cargo run --example audio_saver
    ```

2. Open your browser and navigate to `http://127.0.0.1:3000`. Click "Start" to begin recording.

### RTP Play (FFmpeg)

Streams a video file (`examples/static/output.ivf`) via RTP to a UDP port, which can be played back using `ffplay`.

1. Run the server:

    ```bash
    cargo run --example rtp_play
    ```

2. In a separate terminal, run `ffplay` (requires ffmpeg installed):

    ```bash
    ffplay -protocol_whitelist file,udp,rtp -i examples/rtp_play.sdp
    ```

## License

This project is licensed under the MIT License.
