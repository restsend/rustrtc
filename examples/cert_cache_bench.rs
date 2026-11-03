//! Certificate cache benchmark: the old behavior (fresh ECDSA keypair +
//! self-sign per call, i.e. `generate_unique_certificate`) vs the new
//! process-wide cache (`generate_certificate` after the first call).
//!
//! Run: cargo run --release --example cert_cache_bench

use rustrtc::transports::dtls::{generate_certificate, generate_unique_certificate};
use std::time::Instant;

fn main() {
    // Warmup: populate the process-wide cache.
    let cached = generate_certificate().unwrap();
    let fp = rustrtc::transports::dtls::fingerprint(&cached);
    println!("shared fingerprint: {fp}");

    let iters = 20;
    let start = Instant::now();
    for _ in 0..iters {
        let c = generate_unique_certificate().unwrap();
        std::hint::black_box(&c);
    }
    let fresh = start.elapsed();

    let start = Instant::now();
    for _ in 0..iters {
        let c = generate_certificate().unwrap();
        std::hint::black_box(&c);
    }
    let cached_t = start.elapsed();

    println!(
        "  fresh keypair per call:   {:>8.2?} total  {:>8.2} ms/call",
        fresh,
        fresh.as_secs_f64() * 1000.0 / iters as f64
    );
    println!(
        "  cached (generate_certificate): {:>8.2?} total  {:>8.3} ms/call",
        cached_t,
        cached_t.as_secs_f64() * 1000.0 / iters as f64
    );
}
