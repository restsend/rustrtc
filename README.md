# rustrtc

[![Crates.io](https://img.shields.io/crates/v/rustrtc.svg)](https://crates.io/crates/rustrtc)
[![Documentation](https://docs.rs/rustrtc/badge.svg)](https://docs.rs/rustrtc)

A high-performance, full-featured real-time communication library — **WebRTC, RTP/SRTP, T.38 Fax**, and **RTP Latching** — all through a **unified `PeerConnection` API**.

## Features

- ** Unified API** — A single `PeerConnection` interface for all transport modes: WebRTC (ICE/DTLS/SRTP), raw RTP, SRTP-only, and T.38 fax. No fragmented APIs.
- ** High performance** — ~2.8x faster than `pion` (Go) and ~2.8x faster than `webrtc-rs` in throughput benchmarks. ~48% less memory than `webrtc-rs`.
- ** WebRTC Compliant** — Full compliance with Chrome/WebRTC. Supports offer/answer, renegotiation, and all standard SDP attributes.
- ** Media Support** — RTP/SRTP handling for audio and video with packetizer, depacketizer, jitter buffer, NACK/FIR/PLI, TWCC, and REMB.
- ** ICE/STUN/TURN** — Full ICE implementation with STUN, TURN (UDP + TCP), ICE Lite, ICE TCP (RFC 6544), and nominated pair management.
- ** T.38 Fax** — Fax over IP via T.38 (UDPTL, IFP ASN.1 PER encoding, T.30 state machine). Gated behind `features = ["t38"]`.
- ** RTP Latching** — Dynamic remote address detection for RTP-only NAT traversal. Probation-based candidate selection with configurable observation window.
- ** Transport Modes** — `TransportMode::WebRtc` (full ICE/DTLS), `TransportMode::Srtp` (SRTP without ICE), `TransportMode::Rtp` (raw RTP without encryption).
- ** UPnP IGD** — Automatic port mapping via UPnP for NAT traversal without STUN/TURN.
- ** Port Range Control** — Restrict RTP/ICE ports to a specific range (`rtp_start_port`/`rtp_end_port`) for firewall-friendly deployment.
- ** RTP Rewrite Bridge** — Transparent RTP proxy/rewrite between `PeerConnection` instances (SSRC offset, PT remap, sequence rewriting).
- ** Built-in Stats** — WebRTC-compatible stats model: inbound/outbound RTP, transport, candidate pair, and data channel stats.

## Benchmark game (rustrtc vs webrtc-rs & pion) in 0.2.28

**CPU:**  `AMD Ryzen 7 5700X 8-Core Processor`
**OS** `5.15.0-118-generic #128-Ubuntu`  
**Compiler** `rustc 1.91.0 (f8297e351 2025-10-28)`,  `go version go1.23.0 linux/amd64`

```shell
nice@miuda.ai rustrtc % cargo run -r --example benchmark

Comparison (Baseline: webrtc)
Metric               | webrtc     | rustrtc    | pion      
--------------------------------------------------------------------------------
Duration (s)         | 10.07      | 10.02      | 10.13     
Setup Latency (ms)   | 1.36       | 0.22       | 0.90      
Throughput (MB/s)    | 254.55     | 713.66     | 309.11    
Msg Rate (msg/s)     | 260659.38  | 730788.92  | 316533.37 
CPU Usage (%)        | 1480.45    | 1497.50    | 1121.20   
Memory (MB)          | 29.00      | 15.00      | 44.00     
--------------------------------------------------------------------------------

Performance Charts
==================

Throughput (MB/s) (Higher is better)
webrtc     | ██████████████                           254.55
rustrtc    | ████████████████████████████████████████ 713.66
pion       | █████████████████                        309.11

Message Rate (msg/s) (Higher is better)
webrtc     | ██████████████                           260659.38
rustrtc    | ████████████████████████████████████████ 730788.92
pion       | █████████████████                        316533.37

Setup Latency (ms) (Lower is better)
webrtc     | ████████████████████████████████████████ 1.36
rustrtc    | ██████                                   0.22
pion       | ██████████████████████████               0.90

CPU Usage (%) (Lower is better)
webrtc     | ███████████████████████████████████████  1480.45
rustrtc    | ████████████████████████████████████████ 1497.50
pion       | █████████████████████████████            1121.20

Memory (MB) (Lower is better)
webrtc     | ██████████████████████████               29.00
rustrtc    | █████████████                            15.00
pion       | ████████████████████████████████████████ 44.00
```

**Key Findings:**

- **Throughput**: `rustrtc` is ~2.8x faster than `webrtc-rs` and ~2.3x faster than `pion`.
- **Memory**: `rustrtc` uses ~48% less memory than `webrtc-rs` and ~66% less than `pion`.
- **Setup Latency**: Significantly faster connection setup (0.22ms vs 1.36ms/0.90ms).

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
- **`bind_ip`** — Bind to a specific local IP.
- **`disable_ipv6`** — Disable IPv6 candidate gathering.
- **`enable_ice_lite`** — Enable ICE Lite mode.
- **`ice_tcp_policy`** — `IceTcpPolicy::Disabled` (default), `IceTcpPolicy::Enabled`, or `IceTcpPolicy::PassiveOnly`. Controls ICE TCP candidate support per RFC 6544.

### UPnP
- **`enable_upnp`** — Auto-map ports via UPnP IGD.
- **`upnp_lease_duration`** — UPnP port mapping lease duration in seconds (default: 3600).

### RTP Latching
- **`enable_latching`** — Enable dynamic remote address detection for RTP-only mode.
- **`probation_max_packets`** — Number of packets to observe before committing a latched address.

### Media Capabilities
- **`media_capabilities`** — Configure audio/video/image (T.38) codecs and SCTP port via `MediaCapabilities`.
- **`ssrc_start`** — Starting SSRC value for local tracks.

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
