# rustrtc

[![Crates.io](https://img.shields.io/crates/v/rustrtc.svg)](https://crates.io/crates/rustrtc)
[![Documentation](https://docs.rs/rustrtc/badge.svg)](https://docs.rs/rustrtc)

A high-performance, full-stack real-time communication library — **WebRTC, RTP/SRTP, T.38 Fax, and UPnP NAT traversal** — all through a **unified `PeerConnection` API**.

## Features

- **High performance** — ~3.3× faster than `webrtc-rs` and ~3.2× faster than `pion` (Go) in throughput, with ~52% less memory than `webrtc-rs` (see the benchmark below).
- **Full protocol stack** — WebRTC, RTP, SRTP, and **T.38 fax** in a single library, plus **UPnP IGD** NAT traversal. Few moving parts, no missing pieces.
- **Unified `PeerConnection` API** — one interface for every transport mode (`WebRtc` ICE/DTLS/SRTP, `Srtp`, `Rtp`, and T.38). No fragmented APIs.
- **WebRTC compliant** — interoperable with Chrome/WebRTC and pion; offer/answer, renegotiation, rollback, and standard SDP attributes.
- **ICE restart** — `restart_ice()` for network migration / re-INVITE flows, with automatic detection of remote-initiated restarts (RFC 8445 §9).
- **Complete media pipeline** — packetizer/depacketizer (VP8, VP9, H264, Opus, G.711/G.722/G.729), jitter buffer, NACK/RTX, FIR/PLI, TWCC, and REMB for audio and video.
- **Bandwidth estimation (GCC)** — generates TWCC receiver feedback, stamps transport-wide sequence numbers on outbound RTP, and exposes a live `target_bitrate` estimate for encoder adaptation (`RtpSender::subscribe_target_bitrate`).
- **Full ICE** — STUN, TURN (UDP + TCP), ICE Lite, ICE TCP (RFC 6544), single-port UDP mux for SFU/WHEP deployments, and **mDNS candidate obfuscation** (`enable_mdns`).
- **NAT traversal & deployment** — RTP latching, UPnP IGD port mapping, and firewall-friendly port ranges (`rtp_start_port`/`rtp_end_port`).
- **`no_std` / embassy-ready** — the full ICE/STUN/TURN + DTLS-SRTP + SDES media stack (WebRtc, Srtp, and Rtp transport modes) runs on any executor behind seven injected platform seams, end-to-end tested against a mock embedded runtime (`scripts/check-no_std.sh`).
- **Production extras** — RTP rewrite bridge (SSRC/PT/sequence remapping) and a WebRTC-compatible stats model.

## no_std / Embedded Support

rustrtc builds without `std` (`alloc`-only) and runs its embedded delivery
surface entirely on top of platform seams that the embedder implements
(embassy, esp-rtos, or any executor).

**Embedded delivery surface:**

- Full **ICE/STUN/TURN** stack, RTP/RTX, **SDP**
- `PeerConnection` in **`WebRtc` mode** (ICE + DTLS-SRTP) and in
  **`Rtp`/`Srtp` mode** (SDES-SRTP over a direct transport):
  offer/answer, media send/receive
- Self-contained **DTLS 1.2** implementation behind the crypto seam
  (ECDSA-P256 + ECDH), with a pure-Rust `crypto-p256` reference backend
- Media pipeline: packetizers/depacketizers, jitter buffer, NACK/RTX

WebRtc mode on no_std requires a pre-provisioned DTLS certificate
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

**Still std-only:** SCTP/DataChannel, T.38/UDPTL, GCC/TWCC bandwidth
estimation (the media modules compile, the PC pipeline uses a stub),
ICE-TCP, UPnP, mDNS, and certificate *generation* (use
`dtls_certificate` instead).

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

## Benchmark (rustrtc vs webrtc-rs & pion) in 0.3.141

**CPU:** `Intel(R) Core(TM) i7-9700T CPU @ 2.00GHz` (8 cores)  
**OS:** `Debian 13, 6.12.101+deb13-amd64`  
**Compiler:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `go version go1.24.4 linux/amd64`

```shell
cargo run -r --example benchmark

Comparison (Baseline: webrtc)
Metric               | webrtc     | rustrtc    | pion      
--------------------------------------------------------------------------------
Duration (s)         | 10.07      | 10.24      | 10.07     
Setup Latency (ms)   | 25.64      | 0.45       | 3.00      
Throughput (MB/s)    | 165.98     | 549.04     | 169.58    
Msg Rate (msg/s)     | 169967.13  | 562214.36  | 173647.96 
CPU Usage (%)        | 677.95     | 739.62     | 555.20    
Memory (MB)          | 44.00      | 21.00      | 48.00     
--------------------------------------------------------------------------------

Performance Charts
==================

Throughput (MB/s) (Higher is better)
webrtc     | ████████████                             165.98
rustrtc    | ████████████████████████████████████████ 549.04
pion       | ████████████                             169.58

Message Rate (msg/s) (Higher is better)
webrtc     | ████████████                             169967.13
rustrtc    | ████████████████████████████████████████ 562214.36
pion       | ████████████                             173647.96

Setup Latency (ms) (Lower is better)
webrtc     | ████████████████████████████████████████ 25.64
rustrtc    |                                          0.45
pion       | ████                                     3.00

CPU Usage (%) (Lower is better)
webrtc     | ████████████████████████████████████     677.95
rustrtc    | ████████████████████████████████████████ 739.62
pion       | ████████████████████████████████████████ 555.20

Memory (MB) (Lower is better)
webrtc     | ████████████████████████████████████████ 44.00
rustrtc    | █████████████████                        21.00
pion       | ████████████████████████████████████████ 48.00
```

**Key Findings:**

- **Throughput**: `rustrtc` is ~3.3× faster than `webrtc-rs` and ~3.2× faster than `pion`.
- **Memory**: `rustrtc` uses ~52% less memory than `webrtc-rs` and ~56% less than `pion`.
- **Setup latency**: 0.45 ms — orders of magnitude faster than `webrtc-rs` (25.6 ms) and ~6.7×
  faster than `pion` (3.0 ms).
- **Efficiency per CPU**: 0.74 MB/s per CPU-percent vs 0.31 (pion) and 0.24 (webrtc-rs) —
  `rustrtc` delivers ~2.3× more throughput per unit of CPU.

**No regression with the new stack:** this run has the TWCC/GCC pipeline **active**
(`enable_gcc = true`: transport-cc sequence stamping on every outbound packet plus
receiver-side TWCC feedback generation), and throughput still holds 3.3× / 3.2× over
`webrtc-rs` / `pion`. ICE restart, mDNS candidate obfuscation, and the VP9 codec are
likewise pure add-ons — the ratios above are the stable signal across releases
(0.3.114: 2.95× / 2.7×; 0.3.141: 3.3× / 3.2×).

## Usage

Here is a simple example of how to create a `PeerConnection` and handle an offer:

```rust
use rustrtc::{PeerConnection, RtcConfiguration, SessionDescription, SdpType};

#[tokio::main]
async fn main() {
    let config = RtcConfiguration::default();
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
    let offer = pc.create_offer().unwrap();
    pc.set_local_description(offer).unwrap();

    // Wait for ICE gathering to complete
    pc.wait_for_gathering_complete().await;

    // Get the complete SDP with candidates
    let complete_offer = pc.local_description().unwrap();
    println!("Offer SDP: {}", complete_offer.to_sdp_string());
}
```

## Configuration

All configuration goes through `RtcConfiguration` (or its builder `RtcConfigurationBuilder`):

### Transport & Network
- **`transport_mode`** — `TransportMode::WebRtc` (default), `TransportMode::Srtp`, or `TransportMode::Rtp`.
- **`ice_servers`** — STUN/TURN server list.
- **`ice_transport_policy`** — `All` or `Relay`.
- **`rtp_start_port` / `rtp_end_port`** — Restrict RTP/ICE to a port range.
- **`external_ip`** — Override the external IP for ICE candidates (NAT scenarios).
- **`external_ip_candidate_type`** — How ICE advertises `external_ip`: `Host` (default) replaces the host candidate's address; `ServerReflexive` keeps the host candidate and adds `external_ip` as a srflx candidate on the same socket (1:1 NAT, RFC 8445 §5.1.1.2). WebRTC mode only.
- **`bind_ip`** — Bind to a specific local IP.
- **`disable_ipv6`** — Disable IPv6 candidate gathering.
- **`enable_ice_lite`** — Enable ICE Lite mode.
- **`ice_tcp_policy`** — `IceTcpPolicy::Disabled` (default), `IceTcpPolicy::Enabled`, or `IceTcpPolicy::PassiveOnly`. Controls ICE TCP candidate support per RFC 6544.
- **`ice_udp_mux`** / **`ice_udp_mux_port`** — Share a single UDP socket across many `PeerConnection`s (single-port multiplexing for SFU/WHEP). Set `ice_udp_mux = true` and `ice_udp_mux_port = <port>`; incoming packets are demuxed by the server ufrag in the STUN Binding Request, then by remote source address.
- **`enable_mdns`** — Advertise host candidates via mDNS (`<random>.local` hostnames instead of local IPs, draft-ietf-rtcweb-mdns). A built-in mDNS responder answers A/AAAA lookups; real addresses are kept internally so connectivity is unaffected. Default: `false`.

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
- **`dtls_certificate`** — Pre-provisioned DTLS certificate (DER leaf + PKCS#8 key) for WebRtc mode. Optional on `std` (a self-signed certificate is generated per connection); **required on no_std**, where certificates cannot be generated. `Debug` output is redacted; the field is `serde`-skipped so key material never enters serialized configs.

```rust,ignore
let cert = rustrtc::transports::dtls::Certificate::from_pkcs8_der(cert_der, key_der)?;
let config = RtcConfigurationBuilder::new()
    .transport_mode(TransportMode::WebRtc)
    .dtls_certificate(Arc::new(cert))
    .build();
```

### RTP Latching
- **`enable_latching`** — Enable dynamic remote address detection for RTP-only mode.
- **`probation_max_packets`** — Number of packets to observe before committing a latched address.

### Media Capabilities
- **`media_capabilities`** — Configure audio/video/image (T.38) codecs and SCTP port via `MediaCapabilities`. Video presets: `VideoCapability::default()` (VP8), `VideoCapability::vp9()` / `vp9_with_rtx(pt)` (RFC 9628), `VideoCapability::h264()`.
- **`ssrc_start`** — Starting SSRC value for local tracks.
- **`depacketizer_strategy`** — Pluggable per-kind depacketizer (e.g. `Vp9Depacketizer` for RFC 9628 VP9 reassembly).

### SCTP (Data Channels)
- `sctp_rto_initial`, `sctp_rto_min`, `sctp_rto_max`, `sctp_max_association_retransmits`, `sctp_receive_window`, `sctp_heartbeat_interval`, `sctp_max_heartbeat_failures`, `sctp_max_burst`, `sctp_max_cwnd`

### RTP Buffer
- `rtp_buffer_capacity` — Per-SSRC receive buffer capacity.
- `buffer_drop_strategy` — `DropNew` or `DropOldest` when buffer is full.

```rust
use rustrtc::{
    PeerConnection, RtcConfiguration, RtcConfigurationBuilder,
    IceServer, TransportMode, config::T38Capability,
};

// Using builder
let config = RtcConfigurationBuilder::new()
    .transport_mode(TransportMode::Rtp)
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
let mut config = RtcConfiguration::default();
config.transport_mode = TransportMode::WebRtc;
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
