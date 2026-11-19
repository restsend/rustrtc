# rustrtc vs libwebrtc — performance comparison

Standalone **libwebrtc (M150, C++ SDK)** against **rustrtc 0.6.6**, same host,
same topology. Data channels (SCTP over DTLS) and SRTP are measured
separately, because they are different data planes: WebRTC data channels run
SCTP over DTLS (no SRTP), while media runs SRTP.

**TL;DR** — on the same host:

| Path | Metric | libwebrtc | rustrtc | rustrtc |
|---|---|---:|---:|---:|
| SCTP | RTT p50 / p99 | 452 / 830 µs | **326–376 / 419–462 µs** | 1.3× / 1.9× faster |
| SCTP | 64 KB throughput | 59 MB/s | **157–164 MB/s** | 2.7× |
| SCTP | 1 KB message rate | 28.6k msg/s | **140k msg/s** | 4.9× |
| SCTP | setup (offer → DC open) | 126–131 ms | **5–15 ms** | ~10× |
| SCTP | PSS at 1 connection | 13–18 MB | **9–10 MB** | 1.5–1.9× lower |
| SRTP | AES-GCM protect (1200 B) | 2724 MB/s* | **3762 MB/s** | 1.38× |
| SRTP | AES-GCM roundtrip (1200 B) | 1295 MB/s* | **1645 MB/s** | 1.27× |
| SRTP | AES-GCM protect (200 B / 64 B) | 755 / 287 MB/s* | **1066 / 591 MB/s** | 1.41× / 2.06× |

\* libsrtp 2.6.0 (the SRTP engine libwebrtc vendors) with OpenSSL 3.5;
see [SRTP](#srtp) for the exact methodology.

## Test environment

| | |
|---|---|
| CPU | Intel Core i7-9700T @ 2.00 GHz, 8 cores (Coffee Lake, **no SHA-NI**) |
| OS / kernel | Debian 13, Linux 6.12.101 |
| rustrtc | 0.6.6, `--release` (fat LTO, 1 CGU) |
| libwebrtc | M150.7871.06, standalone prebuilt C++ SDK (`webrtc-sdk`), no Chrome |
| SRTP engine | libsrtp 2.6.0 (OpenSSL 3.5 backend), the engine libwebrtc vendors |
| Topology | two peers in one process, loopback UDP, `taskset` pinned cores |
| SCTP window | 4 MB in-flight on both sides |
| RTT | 300 sequential 65-byte pings, echo, 1 ms gap, measured at echo receipt |
| Setup | non-trickle (full ICE gathering) |
| CPU / memory | process-wide CPU over the measurement window (100 % = 1 core), PSS from `smaps_rollup` |

No Chrome is involved: earlier browser-based numbers (1.1–1.6 ms RTT) include
Blink/V8 and the renderer↔network-service IPC and therefore do not describe
the libwebrtc stack itself. This document uses the standalone C++ library.

## SCTP (data channels)

4 pinned cores, two peers in one process, unidirectional bulk transfer.

| Metric | libwebrtc M150 | rustrtc 0.6.6 |
|---|---:|---:|
| Setup, offer → data-channel open | 125.6–131.5 ms | **5.0–14.5 ms** |
| RTT p50 / p90 / p99 | 445–459 / 523–560 / 779–882 µs | **326–376 / 396–427 / 419–462 µs** |
| 64 KB payload (256 MB) | 58.8–59.3 MB/s, 940–949 msg/s | **156.7–163.8 MB/s**, 2507–2620 msg/s |
| 　CPU / PSS | 102.5–102.7 % / 18.2 MB | 314–318 % / 9.6–9.8 MB |
| 1 KB payload (64 MB) | 27.4–28.0 MB/s, 28.1–28.6k msg/s | **130.8–136.9 MB/s**, 133.9–140.1k msg/s |
| 　CPU / PSS | 119 % / 13.1–13.3 MB | 300–312 % / 9.5–9.8 MB |
| 200 B payload (64 MB) | 5.54 MB/s, 29.0–29.1k msg/s | **40.5–41.9 MB/s**, 212.3–219.4k msg/s |
| 　CPU / PSS | 120 % / 13.3–13.4 MB | 252–253 % / 9.8–9.9 MB |
| RTT-phase CPU | 34–35 % | 28–35 % |

Single core (`taskset -c 0`) isolates per-core efficiency:

| Metric (1 core) | libwebrtc | rustrtc |
|---|---:|---:|
| 64 KB throughput / CPU | 54.0 MB/s @ 99.3 % | **137.6–140.2 MB/s @ 98.6–98.9 %** |
| 200 B throughput / message rate | 8.0–8.1 MB/s / 41.9–42.4k msg/s | **73.0–74.4 MB/s / 382.7–389.8k msg/s** |
| Setup | ~127 ms | **~3.8 ms** |

Notes:

- libwebrtc is roughly single-core bound here (CPU ≈ 100 % at both 59 MB/s on
  four cores and 54 MB/s on one core). rustrtc scales across cores through
  the tokio pipeline and still delivers 2.6× its own single-core throughput.
- libwebrtc's small-message rate plateaus at ~29k msg/s; rustrtc reaches
  212–219k msg/s at 200 B (7.3×) and 383–390k msg/s single-core (9.1×).
- Setup: libwebrtc waits for ICE gathering completion (the ~120 ms is not
  DTLS/SCTP); rustrtc's full-gather path is 5–15 ms. Both sides use the same
  non-trickle signalling shape.

## SRTP

Two different measurements:

1. **Crypto path** (engine-level): protect and protect+unprotect roundtrips
   over 1200/200/64-byte payloads, 100k/200k iterations, pinned to one core.
   rustrtc uses its `SrtpSession` transport API; libwebrtc's SRTP is libsrtp,
   built here as libsrtp 2.6.0 + OpenSSL 3.5. The standalone libwebrtc SDK
   exposes no SRTP-level API and its media path needs a camera/desktop
   capturer (unavailable in the headless test environment), so libsrtp is the
   closest faithful stand-in: it is the engine libwebrtc wraps with
   `SrtpSession`.
2. **End-to-end SRTP** (rustrtc): raw RTP over a loopback `PeerConnection`
   pair, with one-way latency from a payload-embedded timestamp.

### AES-GCM (the profile browsers and libwebrtc negotiate)

MB/s, protect / protect+unprotect roundtrip:

| Payload | libsrtp | rustrtc | ratio |
|---|---:|---:|---:|
| 1200 B | 2724 / 1295 | **3762 / 1645** | **1.38× / 1.27×** |
| 200 B | 755 / 360 | **1066 / 529** | **1.41× / 1.47×** |
| 64 B | 287 / 132 | **591 / 221** | **2.06× / 1.68×** |

The rustrtc transport path (`SrtpSession::protect_rtp`, 1200 B) is
**306 ns/packet (3.7 GB/s)** with the `ring` backend, down from 628 ns/packet
(1.8 GB/s) with the RustCrypto `aes-gcm` backend. Wire format is unchanged
(RFC 3711 test vectors pass on both backends).

### AES-CM / HMAC-SHA1 (legacy fallback)

| Payload | libsrtp | rustrtc | ratio |
|---|---:|---:|---:|
| 1200 B | 679 / 343 | 462 / 232 | 0.68× |
| 200 B | 310 / 149 | 311 / 149 | 1.00× |
| 64 B | 127 / 64 | 162 / 74 | 1.28× / 1.17× |

The 1200-byte gap is the SHA-1 implementation on this host: Coffee Lake has no
SHA-NI, and OpenSSL's AVX SHA-1 assembly is faster than RustCrypto's fallback.
Browsers and libwebrtc negotiate `SRTP_AEAD_AES_128_GCM`, so this only affects
legacy SDES/CM peers. At 200 B rustrtc is at parity and at 64 B it is ahead.

### End-to-end SRTP (rustrtc, 1200 B unless noted)

| Target | Achieved | pps | Loss | One-way p50 / p99 | CPU | PSS |
|---|---:|---:|---:|---|---:|---:|
| 200 Mbps | 23.8 MB/s | 20.8k | 0 % | 76 / 165 µs | 95 % | 9.2 MB |
| 400 Mbps | 47.7 MB/s | 41.7k | 0 % | 44 / 117 µs | 100 % | 10.2 MB |
| 800 Mbps | 95.4 MB/s | 83.3k | 0 % | 19 / 71 µs | 100 % | 11.9 MB |
| 1200 Mbps | 143 MB/s | 125k | 0 % | 19 / 63 µs | 139 % | 13.9 MB |
| 1600 Mbps | 190.7 MB/s | 166.6k | 0 % | 12–15 / 34–47 µs | 180–191 % | 11.2–15.9 MB |
| 2400 Mbps | 217.7 MB/s | 190k | 0 % | 16–19 / 49–55 µs | 202–203 % | 11.3 MB |
| 200 B @ 800 Mbps | 51.7 MB/s | 271k | 0 % | 8 / 28 µs | 196 % | 11.1 MB |
| 64 B @ 200 Mbps | 20 MB/s | 327k | 0 % | 16 / 59 µs | 200 % | 11.1 MB |

Latency at very low rates (50 Mbps: p50 ≈ 94 µs) is dominated by receiver
task wake-up granularity; the steady-state numbers above are the relevant
ones. End-to-end setup is ~12–15 ms.

## Caveats

- Both peers run in one process; CPU is process-wide (both directions), so
  compare CPU between rows, not as per-thread cost. PSS excludes shared pages
  double-counting.
- RTT is an end-to-end property of the pair. The peer echoes the ping, so the
  measured value includes the peer's receive/echo path; this is intentional
  and identical on both sides.
- libsrtp was built with OpenSSL; libwebrtc ships BoringSSL. Both use AES-NI
  for GCM, but they are not byte-identical implementations.
- `roundtrip` for rustrtc includes `SrtpPacket::parse` and one allocation per
  iteration; libsrtp operates in place. The protect-only column is the
  cleanest engine comparison.
- The standalone libwebrtc media path (VP8 encode + SRTP) could not be driven
  headlessly: the SDK's custom-video-source entry point crashes and there is
  no capture device. The SRTP section therefore compares the SRTP engine, not
  a full media pipeline.
- Reproduce the rustrtc side with:
  `cargo run --release --example sctp_benchmark`,
  `cargo run --release --example gcm_backend_bench`,
  `cargo run --release --example dtls_srtp_bench srtp`.
  The standalone libwebrtc and libsrtp harnesses used for this document are
  not part of the crate.
