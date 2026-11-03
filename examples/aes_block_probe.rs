//! Isolate the AES core vs full GCM cost for the `aes`/`aes-gcm` crates.
//! Hardware AES on aarch64: ~1-2 ns/block; software: ~25-30 ns/block.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use std::hint::black_box;
use std::time::Instant;

const BLOCKS: usize = 75; // ≈ 1200 bytes
const ITERS: u32 = 200_000;

fn main() {
    let key = [0x2bu8; 16];
    let aes = aes::Aes128::new_from_slice(&key).unwrap();

    // Single block
    let mut block = aes::Block::clone_from_slice(&[0u8; 16]);
    let start = Instant::now();
    for _ in 0..ITERS {
        aes.encrypt_block(&mut block);
        black_box(&block);
    }
    let single = start.elapsed();
    println!(
        "aes::Aes128 encrypt_block        {:>8.1} ns/block",
        single.as_nanos() as f64 / ITERS as f64
    );

    // 75 blocks in one call (≈1200 B payload)
    let mut blocks = vec![aes::Block::clone_from_slice(&[0u8; 16]); BLOCKS];
    let start = Instant::now();
    for _ in 0..ITERS {
        aes.encrypt_blocks(&mut blocks);
        black_box(&blocks);
    }
    let many = start.elapsed();
    let per_payload = many.as_nanos() as f64 / ITERS as f64;
    println!(
        "aes::Aes128 encrypt_blocks x{:<3} {:>8.1} ns/payload ({BLOCKS} blocks ≈ {}B)",
        BLOCKS, per_payload, BLOCKS * 16
    );
    println!(
        "  → implied throughput: {:.2} MB/s",
        (BLOCKS * 16 * ITERS as usize) as f64 / 1024.0 / 1024.0 / many.as_secs_f64()
    );
}
