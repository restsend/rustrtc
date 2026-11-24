# WebRTC data-channel performance: rustrtc vs libwebrtc, pion, webrtc-rs (and libpeer / MetaRTC)

A like-for-like data-channel benchmark across WebRTC implementations, run on
one machine with one scenario. The goal is an honest matrix: where rustrtc
wins, where it does not, and which libraries could not be measured — with the
reasons and reproduction steps.

> Scope: **SCTP data channels** (reliable, ordered) over DTLS, which is the
> common data plane every implementation below exposes. SRTP (media) is a
> different plane (SCTP is not carried over SRTP) and is covered separately in
> [PERFORMANCE-VS-LIBWEBRTC.md](PERFORMANCE-VS-LIBWEBRTC.md) — see
> [SRTP](#srtp) below for the summary.

## TL;DR

Same host, two peers in one process, four pinned cores, medians of 3–5 runs
(ranges in parentheses where the host was noisy):

| Implementation | RTT p50 / p99 | 64 KiB throughput | 200 B msg rate | Setup | PSS |
|---|---:|---:|---:|---:|---:|
| **rustrtc 0.6.6** | **0.34 / 0.44 ms** | **158 MB/s** | **201k msg/s** | 3–15 ms | 9–10 MB |
| libwebrtc M150 | 0.45 / 0.83 ms | 59 MB/s | 29k msg/s | 126–131 ms | 13–18 MB |
| pion 3.3.6 | 0.46 / 0.58 ms | 97 MB/s (62–120) | 102k msg/s (100–329k) | 4–24 ms | 33–41 MB |
| webrtc-rs 0.17.1 | 0.83 / 1.00 ms | 48 MB/s | 189k msg/s | 4–21 ms | 7–11 MB |

- **rustrtc** has the lowest RTT and is the fastest at 64 KiB and 1 KiB; it is
  roughly level with webrtc-rs for 200 B and ahead of pion's median (pion's
  200 B runs are bimodal, 100–329k).
- **pion** is competitive for medium messages on multiple cores but far behind
  per core and on memory.
- **libwebrtc** is mid-pack on RTT/throughput, pays a ~120 ms non-trickle
  gathering cost, and stays near one core of CPU.
- **webrtc-rs** has the highest RTT and the lowest memory.
- **libpeer** and **MetaRTC** could not be measured in this scenario; see
  [Not measured](#not-measured).

## Test environment

| | |
|---|---|
| CPU | Intel Core i7-9700T @ 2.00 GHz, 8 cores (Coffee Lake) |
| OS / kernel | Debian 13, Linux 6.12.101 |
| rustrtc | 0.6.6, release (fat LTO, 1 CGU) |
| libwebrtc | M150.7871.06, standalone C++ SDK (webrtc-sdk wrapper), no Chrome |
| pion | v3.3.6 (`github.com/pion/webrtc/v3`), Go 1.24.4 |
| webrtc-rs | 0.17.1 (`webrtc` crate), release (fat LTO, 1 CGU) |
| Topology | two peers in one process, loopback UDP, `taskset` pinned cores |
| Data channel | reliable + ordered, 4 MB in-flight window |
| RTT | 300 sequential 65-byte pings, echo, 1 ms gap |
| Setup | non-trickle (wait for full ICE gathering) |
| CPU / memory | process-wide CPU over the phase (100 % = 1 core), PSS from `/proc/self/smaps_rollup` |

Every harness uses the same wire protocol (`0x02` ping / `0x82` echo,
`0x03` bulk), the same offer/answer shape, and the same window. Each library
was measured with its own native API; no library was patched. The host is
shared and noisy; medians are shown and ranges are reported where run-to-run
spread was significant. **Treat ratios below ~1.5× as within host noise.**

## SCTP data channels — 4 cores

Bulk totals: 128 MiB at 64 KiB, 32 MiB at 1 KiB and 200 B. The 64 KiB cases use
65536-byte messages for rustrtc/libwebrtc and **65535** for pion/webrtc-rs
(both stall on exactly 65536; see [Implementation notes](#implementation-notes)).

| Metric | rustrtc | libwebrtc | pion | webrtc-rs |
|---|---:|---:|---:|---:|
| Setup (offer → DC open) | 3–15 ms | 126–131 ms | 4–24 ms | 4–21 ms |
| RTT p50 / p90 / p99 | **0.34 / 0.40 / 0.44 ms** | 0.45 / 0.53 / 0.83 ms | 0.46 / 0.50 / 0.58 ms | 0.83 / 0.92 / 1.00 ms |
| RTT-phase CPU / PSS | 28–35 % / 8.6–8.7 MB | 34–35 % / 12.8–13.1 MB | 46–59 % / 15.0 MB | 40 % / 6.9–7.0 MB |
| **64 KiB** MB/s | **158** (151–160) | 59 | 97 (62–120) | 48 (48–51) |
| **64 KiB** msg/s | **2537** | 945 | 1552 (995–1924) | 775 |
| 　CPU / PSS | 315 % / 9.6 MB | 103 % / 18.2 MB | 255 % / 35 MB | 234 % / 8.9 MB |
| **1 KiB** MB/s | **135** (127–137) | 28 | 109 (40–114) | 44 (43–45) |
| **1 KiB** msg/s | **138.7k** | 28.4k | 111.9k (41k–116k) | 45.1k |
| 　CPU / PSS | 300 % / 9.5 MB | 119 % / 13.2 MB | 306 % / 33 MB | 238 % / 7.8 MB |
| **200 B** MB/s | 38.4 (37.9–39.2) | 5.5 | 19.5 (19–63) | 36.0 (31–37) |
| **200 B** msg/s | **201k** | 29k | 102k (100k–329k) | 189k |
| 　CPU / PSS | 250 % / 9.6 MB | 120 % / 13.4 MB | 212 % / 41 MB | 252 % / 10.5 MB |

### Single core (`taskset -c 0`)

| Metric | rustrtc | libwebrtc | pion | webrtc-rs |
|---|---:|---:|---:|---:|
| 64 KiB MB/s @ CPU | **137.6–140.2 @ 98.6–98.9 %** | 54.0 @ 99.3 % | 10.6 @ 25.4 % | 17.5 @ 48.6 % |
| 200 B MB/s @ CPU | **73.0–74.4 @ 95.8–97.6 %** | 8.0 @ 99.6 % | 7.3 @ 38.7 % | 5.9 @ 65.1 % |
| 200 B msg/s | **383–390k** | 42k | 38k | 31k |

Single-core numbers are the cleanest cross-implementation signal because they
remove scheduling/parallelism choices. rustrtc delivers 2.5× libwebrtc's 64 KiB
throughput on one core and ~9× its 200 B message rate; pion and webrtc-rs fall
far behind when confined to one core.

## What the numbers say

- **RTT**: rustrtc has the lowest p50 (0.34 ms) and p99 (0.44 ms); libwebrtc
  0.45/0.83, pion 0.46/0.58, webrtc-rs 0.83/1.00. The p50 differences among
  rustrtc/libwebrtc/pion (0.34–0.46 ms) are close; rustrtc's p99 advantage is
  outside host noise.
- **64 KiB bulk**: rustrtc 158 MB/s vs pion 97 (62–120), libwebrtc 59,
  webrtc-rs 48 — 1.6× pion, 2.7× libwebrtc, 3.3× webrtc-rs on medians.
- **1 KiB**: rustrtc 135 vs pion 109 (median), webrtc-rs 44, libwebrtc 28.
  pion's 1 KiB runs were bimodal (40–114), so the rustrtc–pion gap is
  modest.
- **200 B**: rustrtc 201k msg/s vs webrtc-rs 189k (level), pion median 102k
  (pion's high runs reach 329k), libwebrtc 29k. pion is *not* consistently
  faster for tiny messages; its scheduler produces two regimes.
- **Single core**: rustrtc is 2.5× libwebrtc at 64 KiB and ~9× at 200 B, and
  an order of magnitude ahead of pion/webrtc-rs. This is the most
  architecture-independent result.
- **Setup**: pion/webrtc-rs/rustrtc complete non-trickle gather in 3–24 ms;
  libwebrtc's ~120 ms is waiting for ICE gathering completion, not DTLS/SCTP.
- **CPU**: libwebrtc stays near one core at 59 MB/s; rustrtc spends ~3 cores
  to reach 158 MB/s, but per-core efficiency is still rustrtc's
  (140 MB/s/core vs libwebrtc's 54, pion's 10.6, webrtc-rs's 17.5).
- **Memory**: webrtc-rs is the smallest (7–11 MB), rustrtc close behind
  (9–10 MB), libwebrtc 13–18 MB, pion 33–41 MB.

## SRTP

SRTP is the media plane; data channels do not use it (SCTP runs over DTLS).
The engine-level and end-to-end SRTP comparison (rustrtc vs libsrtp, the engine
libwebrtc vendors, plus end-to-end raw RTP over a PeerConnection) is in
[PERFORMANCE-VS-LIBWEBRTC.md](PERFORMANCE-VS-LIBWEBRTC.md). Headline:

| AES-GCM 1200 B, single core | libsrtp (libwebrtc engine) | rustrtc |
|---|---:|---:|
| protect | 2724 MB/s | **3762 MB/s** (1.38×) |
| protect + unprotect | 1295 MB/s | **1645 MB/s** (1.27×) |
| protect, 200 B / 64 B | 755 / 287 MB/s | **1066 / 591 MB/s** |

rustrtc's end-to-end SRTP sustains 24–218 MB/s with zero loss and 12–23 µs
one-way latency (p50) on loopback. The legacy AES-CM/HMAC-SHA1 profile at
1200 B is still ~0.68× of libsrtp on this no-SHA-NI host; browsers and
libwebrtc negotiate AES-GCM.

## Not measured

Two requested libraries could not be measured in this scenario. This is a
coverage gap, not a claim about their performance.

**libpeer** (`sepfy/libpeer`, main): built successfully (mbedtls 3.6.2 with
DTLS-SRTP enabled, libsrtp, usrsctp; AES-NI disabled to avoid a mbedtls 3.6.2 +
GCC 14 crash). A direct in-process offer/answer pair reaches ICE candidate
selection, but the DTLS handshake fails with
`MBEDTLS_ERR_SSL_CONN_EOF` (-0x7280) on both sides, so no data channel opens.
libpeer's documented signaling path is WHIP over HTTP (`peer_signaling`, which
needs coreHTTP/coreMQTT); a faithful libpeer test should use that flow and
likely one peer per process. No numbers are reported.

**MetaRTC** (`metartc/metaRTC`, main): `Yang_Enable_Datachannel` and
`createDataChannel` exist, but the peer connection is tied to MetaRTC's media
session (`YangPeerConnection8`), the demos are player/pusher applications, and
there is no standalone headless data-channel example. Building it pulls the
full media stack (libyangutil8 / libmetartccore8 / libyangwhip8 / libmetartc8,
OpenSSL, SRTP and codec dependencies), which was out of scope for this run. No
numbers are reported.

If you need those two in the matrix, the honest next step is their native
signaling flows (WHIP for libpeer; MetaRTC's session/demo) with one process per
peer — not an in-process pair.

## Implementation notes

- **pion / webrtc-rs 64 KiB**: both stall when a message is exactly 65536
  bytes (a few messages are sent, then the window never drains). 65535-byte
  messages work, which is what the table uses. This is a limitation of the
  shared pion/SCTP stack, not of the benchmark.
- **pion variance**: pion's 200 B runs split into ~100k and ~300k msg/s
  regimes (and 1 KiB runs into ~40 and ~110 MB/s). The table reports medians
  and ranges; do not read a single pion run as a stable number.
- **rustrtc 200 B on four cores** is slower than on one core (201k vs
  383–390k msg/s): the tokio multi-worker pipeline's window checks and task
  scheduling add overhead for very small messages. The single-core figure is
  the higher-throughput result and is reported separately.
- **Non-trickle setup** includes full ICE gathering on every implementation.
  libwebrtc's gathering-complete wait dominates its 126–131 ms.
- **CPU** is the whole process (sender + receiver); the two peers share it.
  Compare CPU between rows, not as a per-thread figure.
- The libwebrtc numbers use the standalone C++ SDK, not Chrome. Browser
  numbers are higher (Blink/V8/renderer↔network-service IPC) and are not used
  here.
- Single-core runs pin the process, but runtimes with fixed thread pools
  (Go's GOMAXPROCS, tokio workers) are not tuned for one CPU; the numbers show
  behavior under that constraint, not a theoretical maximum.

## Reproduce

rustrtc:

```shell
cargo run --release --example sctp_benchmark          # bulk throughput
cargo run --release --example gcm_backend_bench      # SRTP crypto
cargo run --release --example dtls_srtp_bench srtp   # SRTP protect/unprotect
```

The pion, webrtc-rs, libwebrtc and libsrtp harnesses used for this document are
standalone test programs (two peers in one process, 4 MB window, same wire
protocol) and are not part of the crate. The scenario is fully described above
so it can be reproduced against any implementation with its native API.
