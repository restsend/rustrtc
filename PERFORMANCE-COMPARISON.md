# WebRTC data-channel performance: rustrtc vs libwebrtc, pion, webrtc-rs, libpeer and MetaRTC

A like-for-like data-channel benchmark across WebRTC implementations, run on
one machine with one scenario. The goal is an honest matrix: where rustrtc
wins, where it does not, and what had to be fixed in each library to get a
number at all.

> Scope: **SCTP data channels** (reliable, ordered) over DTLS, which is the
> common data plane every implementation below exposes. SRTP (media) is a
> different plane (SCTP is not carried over SRTP) and is covered separately in
> [PERFORMANCE-VS-LIBWEBRTC.md](PERFORMANCE-VS-LIBWEBRTC.md) — see
> [SRTP](#srtp) below for the summary.

## TL;DR

Same host, four pinned cores, same wire protocol, medians of 3–5 runs (ranges in
parentheses). rustrtc, libwebrtc, pion and webrtc-rs run two peers in one
process; **libpeer runs one peer per process** (its native topology) and
MetaRTC runs two peers in one process.

| Implementation | RTT p50 / p99 | 64 KiB throughput | 1 KiB throughput | 200 B msg rate | Setup | PSS |
|---|---:|---:|---:|---:|---:|---:|
| **rustrtc 0.6.8** | **0.34 / 0.44 ms** | **158 MB/s** | **135 MB/s** | **201k msg/s** | 3–15 ms | 9–10 MB |
| libpeer (usrsctp) | 0.36 / 0.42 ms | 117 MB/s (75–118) | 24 MB/s | 30k msg/s | 77–97 ms | 1.2–8.6 MB¹ |
| MetaRTC | 0.37 / 0.55 ms | 60 MB/s (54–61) | 47 MB/s | 105k msg/s (69–156k) | 108–131 ms | 5.9–6.9 MB |
| libwebrtc M150 | 0.45 / 0.83 ms | 59 MB/s | 28 MB/s | 29k msg/s | 126–131 ms | 13–18 MB |
| pion 3.3.6 | 0.46 / 0.58 ms | 97 MB/s (62–120) | 109 MB/s (40–114) | 102k msg/s (100–329k) | 4–24 ms | 33–41 MB |
| webrtc-rs 0.17.1 | 0.83 / 1.00 ms | 48 MB/s | 44 MB/s | 189k msg/s | 4–21 ms | 7–11 MB |

¹ libpeer is two processes; PSS is for the sending process only.

- **rustrtc** has the lowest RTT p50 and the highest 64 KiB and 1 KiB
  throughput. libpeer's p99 (0.42 ms) is statistically level with rustrtc's
  (0.44 ms); its p50 is 0.02 ms higher.
- **libpeer** is the second-fastest at 64 KiB (117 MB/s) but falls to
  24 MB/s at 1 KiB and 30k msg/s at 200 B — its per-message path is the
  slowest of the six.
- **MetaRTC** is mid-pack on bulk (60 / 47 MB/s), competitive on tiny
  messages (105k msg/s), has a very low RTT (0.37 ms) and the smallest
  in-process memory (5.9–6.9 MB for both peers).
- **pion** is strong at 1 KiB and 200 B on multiple cores but bimodal and
  memory-hungry (33–41 MB).
- **libwebrtc** is mid-pack on RTT/throughput, pays a ~120 ms non-trickle
  gathering cost, and stays near one core of CPU.
- **webrtc-rs** has the highest RTT, the lowest 64 KiB throughput, and low
  memory (7–11 MB).

## Test environment

| | |
|---|---|
| CPU | Intel Core i7-9700T @ 2.00 GHz, 8 cores (Coffee Lake) |
| OS / kernel | Debian 13, Linux 6.12.101 |
| rustrtc | 0.6.8, release (fat LTO, 1 CGU); data-plane numbers measured on 0.6.6 and re-verified on 0.6.8 |
| libwebrtc | M150.7871.06, standalone C++ SDK (webrtc-sdk wrapper), no Chrome |
| pion | v3.3.6 (`github.com/pion/webrtc/v3`), Go 1.24.4 |
| webrtc-rs | 0.17.1 (`webrtc` crate), release (fat LTO, 1 CGU) |
| libpeer | `sepfy/libpeer` main, mbedtls 3.6.2, libsrtp 2.6, usrsctp (pinned commit), C |
| MetaRTC | `metartc/metaRTC` main, OpenSSL 3.5, libsrtp, usrsctp |
| Topology | two peers on loopback UDP, `taskset` pinned cores; libpeer: one peer per process |
| Data channel | reliable + ordered, 4 MB in-flight window |
| RTT | 300 sequential 65-byte pings, echo, 1 ms gap |
| Setup | non-trickle (wait for full ICE gathering) |
| CPU / memory | process-wide CPU over the phase (100 % = 1 core), PSS from `/proc/self/smaps_rollup` |

Every harness uses the same wire protocol (`0x02` ping / `0x82` echo,
`0x03` bulk), the same offer/answer shape, and the same 4 MB in-flight budget.
Each library was driven with its own native API. The host is shared and noisy;
medians are shown and ranges are reported where run-to-run spread was
significant. **Treat ratios below ~1.5× as within host noise.**

**Both libpeer and MetaRTC needed patches to work at all** in a local
peer-to-peer data-channel scenario. The patches fix protocol/correctness bugs
(server-side SCTP listen/accept, INIT timing, DTLS thread safety, dropped
`EAGAIN`); they do not tune the data path. They are listed in
[Patches required](#patches-required) so the numbers can be judged with that
in mind. rustrtc, libwebrtc, pion and webrtc-rs were not patched.

## SCTP data channels — 4 cores

Bulk totals: 128 MiB at 64 KiB, 32 MiB at 1 KiB and 200 B. The 64 KiB cases use
65536-byte messages for rustrtc/libwebrtc/libpeer/MetaRTC and **65535** for
pion/webrtc-rs (both stall on exactly 65536; see
[Implementation notes](#implementation-notes)).

| Metric | rustrtc | libpeer | MetaRTC | libwebrtc | pion | webrtc-rs |
|---|---:|---:|---:|---:|---:|---:|
| Setup (offer → DC open) | **3–15 ms** | 77–97 ms | 108–131 ms | 126–131 ms | 4–24 ms | 4–21 ms |
| RTT p50 / p90 / p99 | **0.34 / 0.40 / 0.44 ms** | 0.36 / 0.41 / 0.42 ms | 0.37 / 0.42 / 0.55 ms | 0.45 / 0.53 / 0.83 ms | 0.46 / 0.50 / 0.58 ms | 0.83 / 0.92 / 1.00 ms |
| RTT-phase CPU / PSS | 28–35 % / 8.6–8.7 MB | 14–16 % / 1.2 MB¹ | 24–25 % / 5.9 MB | 34–35 % / 12.8–13.1 MB | 46–59 % / 15.0 MB | 40 % / 6.9–7.0 MB |
| **64 KiB** MB/s | **158** (151–160) | 117 (75–118) | 60.2 (53.9–60.6) | 59 | 97 (62–120) | 48 (48–51) |
| **64 KiB** msg/s | **2537** | 1874 (1203–1894) | 963 (863–969) | 945 | 1552 (995–1924) | 775 |
| 　CPU / PSS | 315 % / 9.6 MB | 105 % / 6.5 MB¹ | 45–49 % / 6.2 MB | 103 % / 18.2 MB | 255 % / 35 MB | 234 % / 8.9 MB |
| **1 KiB** MB/s | **135** (127–137) | 23.9 (23.2–24.1) | 47.2 (45.6–51.4) | 28 | 109 (40–114) | 44 (43–45) |
| **1 KiB** msg/s | **138.7k** | 24.5k | 48.3k (46.7–52.6k) | 28.4k | 111.9k (41k–116k) | 45.1k |
| 　CPU / PSS | 300 % / 9.5 MB | 32 % / 7.1 MB¹ | 21.5 % / 5.9 MB | 119 % / 13.2 MB | 306 % / 33 MB | 238 % / 7.8 MB |
| **200 B** MB/s | 38.4 (37.9–39.2) | 5.7 (4.8–5.7) | 19.9 (13.2–29.7) | 5.5 | 19.5 (19–63) | 36.0 (31–37) |
| **200 B** msg/s | **201k** | 29.7k (25.1–29.8k) | 105k (69–156k) | 29k | 102k (100k–329k) | 189k |
| 　CPU / PSS | 250 % / 9.6 MB | 14 % / 7.7 MB¹ | 31 % / 6.8 MB | 120 % / 13.4 MB | 212 % / 41 MB | 252 % / 10.5 MB |

¹ libpeer is two processes. CPU is the sending process; PSS is that process
too, so it is not directly comparable with the two-peers-in-one-process rows.
The single-core runs below were not repeated for libpeer/MetaRTC.

### Single core (`taskset -c 0`)

| Metric | rustrtc | libwebrtc | pion | webrtc-rs |
|---|---:|---:|---:|---:|
| 64 KiB MB/s @ CPU | **137.6–140.2 @ 98.6–98.9 %** | 54.0 @ 99.3 % | 10.6 @ 25.4 % | 17.5 @ 48.6 % |
| 200 B MB/s @ CPU | **73.0–74.4 @ 95.8–97.6 %** | 8.0 @ 99.6 % | 7.3 @ 38.7 % | 5.9 @ 65.1 % |
| 200 B msg/s | **383–390k** | 42k | 38k | 31k |

Single-core numbers are the cleanest cross-implementation signal because they
remove scheduling/parallelism choices. rustrtc delivers 2.5× libwebrtc's 64 KiB
throughput on one core and ~9× its 200 B message rate; pion and webrtc-rs fall
far behind when confined to one core. libpeer and MetaRTC were not run on one
core in this round.

## What the numbers say

- **RTT**: rustrtc 0.34/0.44 ms, libpeer 0.36/0.42, MetaRTC 0.37/0.55,
  libwebrtc 0.45/0.83, pion 0.46/0.58, webrtc-rs 0.83/1.00. The top three are
  within host noise of each other; libpeer's p99 is marginally lower than
  rustrtc's, rustrtc's p50 is marginally lower than libpeer's.
- **64 KiB bulk**: rustrtc 158 MB/s, libpeer 117, pion 97 (62–120), MetaRTC
  60, libwebrtc 59, webrtc-rs 48. rustrtc is 1.35× libpeer and 1.6× pion on
  medians; the rustrtc–libpeer gap is close to the noise threshold, the gap to
  the rest is not.
- **1 KiB**: rustrtc 135, pion 109 (median), MetaRTC 47, webrtc-rs 44,
  libwebrtc 28, libpeer 24. pion's 1 KiB runs are bimodal (40–114), so its
  median flatters it.
- **200 B**: rustrtc 201k msg/s, webrtc-rs 189k, MetaRTC 105k (69–156k),
  pion 102k (100–329k), libpeer 30k, libwebrtc 29k. pion and MetaRTC both have
  wide tiny-message ranges; rustrtc and webrtc-rs are the only ones that are
  consistently above 180k.
- **Single core**: rustrtc is 2.5× libwebrtc at 64 KiB and ~9× at 200 B, and
  an order of magnitude ahead of pion/webrtc-rs.
- **Setup**: rustrtc/pion/webrtc-rs complete non-trickle gather in 3–24 ms.
  libpeer's 77–97 ms includes SDP exchange through files and a 5 ms poll
  interval; MetaRTC (108–131 ms) and libwebrtc (126–131 ms) wait for full ICE
  gathering.
- **CPU**: rustrtc and pion spend ~3 cores to reach their peak; libwebrtc and
  MetaRTC stay under half a core-to-one core, libpeer ~1 core.
- **Memory**: libpeer is tiny per process (1.2 MB during RTT, 6.5–8.6 MB during
  bulk); MetaRTC holds both peers in 5.9–6.9 MB; webrtc-rs 7–11 MB; rustrtc
  9–10 MB; libwebrtc 13–18 MB; pion 33–41 MB.

## Patches required

These are the upstream defects that had to be fixed to obtain a number. They
are correctness fixes; none of them changes how bytes are copied, encrypted or
scheduled on the fast path (the 4 MB socket buffer is set for parity with the
other harnesses).

### libpeer (`sepfy/libpeer` main)

1. **Server-side SCTP accept.** libpeer calls `usrsctp_connect()` on both
   peers, regardless of DTLS role. RFC 8831 says the DTLS client initiates the
   SCTP association, so the DTLS server must `listen()`/`accept()`. Without
   this the association never comes up.
2. **Start the SCTP association after DTLS.** `peer_init()` (which calls
   `usrsctp_init`) was missing from the direct-pair flow; also, the initial
   INIT was emitted before the send hook was installed, so it was dropped.
3. **Path MTU 1200.** usrsctp defaults to a 1280-byte SCTP packet, which
   becomes a ~1317-byte DTLS record and is truncated by libpeer's fixed
   1300-byte UDP receive buffer. 1200 + overhead fits.
4. **SCTP timer pump.** libpeer never calls `usrsctp_handle_timers()`, so a
   lost fragment of a multi-datagram message is never retransmitted. The
   harness pumps it.
5. **4 MB socket buffers** (`LIBPEER_SCTP_BUF_KB`), matching the 4 MB in-flight
   budget of the other harnesses.
6. The harness runs `peer_connection_loop()` in a dedicated thread and queues
   echoes out of the receive callback, because libpeer's built-in SCTP output
   buffer is not re-entrant from inside `onmessage`.

Measured with usrsctp (`CONFIG_USE_USRSCTP=1`), one peer per process, SDP
exchanged through files (libpeer's native signaling is WHIP over HTTP; this is
the same signaling content without the HTTP server).

### MetaRTC (`metartc/metaRTC` main)

1. **Deferred association start.** `yang_create_sctp()` connects as soon as
   `createDataChannel()` is called, before the DTLS handshake has keys, so the
   INIT is silently dropped. The association is now started explicitly after
   DTLS is up.
2. **Server-side listen/accept** based on `isControlled`, as above.
3. **One `usrsctp_init()` per process** (two peers in one process).
4. **DTLS thread safety.** MetaRTC uses the same OpenSSL `SSL*` from the UDP
   receive thread (`SSL_read`, `SSL_do_handshake`) and from the SCTP send path
   (`SSL_write`). OpenSSL requires external serialization; without it the
   process dies with heap corruption (`double free`, `BUF_MEM_grow_clean`).
   A recursive mutex now covers the SSL calls.
5. **Dispatch outside the DTLS lock.** Decrypted records are queued and handed
   to usrsctp after the lock is released; dispatching inside it deadlocks
   against usrsctp's own timer thread (SCTP lock → DTLS lock vs DTLS lock →
   SCTP lock).
6. **Propagate `EAGAIN`.** `yang_sctp_sendData()` ignores `usrsctp_sendv()`
   errors; upstream silently drops messages when the SCTP send buffer is full.
   The harness now retries on `EAGAIN`.

Measured with two peers in one process (MetaRTC's supported topology) and SDP
exchanged in memory.

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

## Implementation notes

- **pion / webrtc-rs 64 KiB**: both stall when a message is exactly 65536
  bytes (a few messages are sent, then the window never drains). 65535-byte
  messages work, which is what the table uses. This is a limitation of the
  shared pion/SCTP stack, not of the benchmark.
- **Bimodal implementations**: pion's 200 B runs split into ~100k and ~300k
  msg/s regimes (and 1 KiB runs into ~40 and ~110 MB/s); MetaRTC's 200 B runs
  split into ~70k and ~150k. The table reports medians and ranges; do not read
  a single run as a stable number.
- **rustrtc 200 B on four cores** is slower than on one core (201k vs
  383–390k msg/s): the tokio multi-worker pipeline's window checks and task
  scheduling add overhead for very small messages. The single-core figure is
  the higher-throughput result and is reported separately.
- **Non-trickle setup** includes full ICE gathering on every implementation.
  MetaRTC's and libwebrtc's gathering-complete waits dominate their ~110–130 ms.
- **CPU** for rustrtc/libwebrtc/pion/webrtc-rs/MetaRTC is the whole process
  (sender + receiver); the two peers share it. libpeer is two processes, so its
  CPU/PSS are for the sending process only.
- **Memory** is PSS. libpeer's two-process total is roughly 2× the reported
  number; MetaRTC's 5.9–6.9 MB already covers both peers.
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

The pion, webrtc-rs, libwebrtc, libsrtp, libpeer and MetaRTC harnesses used
for this document are standalone test programs (same wire protocol, same
4 MB budget) and are not part of the crate. The scenario is fully described
above, including the patches, so it can be reproduced against any
implementation with its native API.
