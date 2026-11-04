//! AES-128-GCM backend comparison: `aes-gcm` crate (what rustrtc's SRTP uses)
//! vs `ring::aead` (what rustls/ring-backed QUIC stacks use).
//!
//! Mirrors the real SRTP hot-path shape: one cipher instance reused across
//! packets (cached context), per-packet 12-byte nonce, 12-byte AAD (RTP
//! header), 1200-byte payload, 16-byte tag, encrypt in place.
//!
//! Note: the decrypt loops clone the input buffer inside the timed region
//! (in-place ops consume it). The clone cost is identical on both backends,
//! so the comparison stays fair; absolute ns/op includes that memcpy.
//!
//! Run: cargo run --release --example gcm_backend_bench

use std::hint::black_box;
use std::time::Instant;

const PAYLOAD: usize = 1200;
const ITERS: u32 = 100_000;
const AAD_LEN: usize = 12; // RTP header size

fn report(name: &str, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    let ns_per_op = elapsed.as_nanos() as f64 / ITERS as f64;
    let mb = (PAYLOAD as u64 * ITERS as u64) as f64 / 1024.0 / 1024.0;
    println!(
        "  {:<28} {:>8.2} MB/s  {:>10.0} ops/s  {:>8.1} ns/op",
        name,
        mb / secs,
        ITERS as f64 / secs,
        ns_per_op
    );
}

fn aes_gcm_crate(key: &[u8; 16]) {
    use aes_gcm::aead::{AeadInOut, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce};
    use rustrtc::rtp::{RtpHeader, RtpPacket};

    let cipher = Aes128Gcm::new_from_slice(key).unwrap();
    let aad = [0u8; AAD_LEN];

    // Warmup + roundtrip correctness check.
    {
        let mut buf = vec![0u8; PAYLOAD];
        let nonce = Nonce::from([7u8; 12]);
        let tag = cipher
            .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
            .unwrap();
        assert_eq!(tag.len(), 16);
        cipher
            .decrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into(), &tag)
            .unwrap();
        assert_eq!(buf.len(), PAYLOAD);
    }

    // Encrypt (protect): fresh buffer per iteration, in place, per-packet nonce.
    let start = Instant::now();
    for i in 0..ITERS {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&(i as u64).to_be_bytes());
        let mut buf = black_box(vec![0u8; PAYLOAD]);
        let tag = cipher
            .encrypt_inout_detached(&Nonce::from(nonce), &aad, (&mut buf[..]).into())
            .unwrap();
        black_box(&tag);
        black_box(buf.len());
    }
    let enc = start.elapsed();

    // Decrypt (unprotect): fixed nonce, real tag, in place on a cloned input.
    let mut base = vec![0u8; PAYLOAD];
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from([7u8; 12]), &aad, (&mut base[..]).into())
        .unwrap();
    let start = Instant::now();
    for _ in 0..ITERS {
        let mut buf = black_box(base.clone());
        cipher
            .decrypt_inout_detached(&Nonce::from([7u8; 12]), &aad, (&mut buf[..]).into(), &tag)
            .unwrap();
        black_box(buf.len());
    }
    let dec = start.elapsed();

    println!("--- aes-gcm 0.10 (rustrtc SRTP path) ---");
    report("encrypt_inout_detached", enc);
    report("decrypt_inout_detached", dec);

    // Session-level path: SrtpSession::protect_rtp/unprotect_rtp (what
    // rtp_transport actually calls — includes context lookup, MKI handling,
    // stats timestamps). This is where wrapper overhead shows up.
    use rustrtc::srtp::{SrtpKeyingMaterial, SrtpProfile, SrtpSession};
    let keying = SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]);
    let mut session = SrtpSession::new(SrtpProfile::AeadAes128Gcm, keying.clone(), keying).unwrap();
    let mut hdr = RtpHeader::new(96, 0, 0, 1234);
    let mut plain = RtpPacket::new(hdr.clone(), vec![0u8; PAYLOAD]);
    // Warmup + correctness via session API.
    let mut out = bytes::BytesMut::zeroed(session.protected_rtp_len(&plain));
    session.protect_rtp(&plain, &mut out).unwrap();
    let srv = rustrtc::srtp::SrtpPacket::parse(out.clone()).unwrap();
    let _ = session.unprotect_rtp(srv).unwrap();

    let start = Instant::now();
    // Start at seq 1: seq 0 was consumed by the warmup roundtrip above, and
    // the replay window now (correctly) rejects reused indices.
    for i in 1..=ITERS {
        hdr.sequence_number = i as u16;
        plain.header = hdr.clone();
        let mut out = black_box(bytes::BytesMut::zeroed(session.protected_rtp_len(&plain)));
        session.protect_rtp(&plain, &mut out).unwrap();
        let srv = rustrtc::srtp::SrtpPacket::parse(out).unwrap();
        let rt = session.unprotect_rtp(srv).unwrap();
        black_box(rt.payload.len());
    }
    let roundtrip = start.elapsed();
    println!(
        "  {:<28} {:>10.0} ops/s  {:>8.1} ns/roundtrip",
        "session protect+unprotect (alloc/iter)",
        ITERS as f64 / roundtrip.as_secs_f64(),
        roundtrip.as_nanos() as f64 / ITERS as f64
    );

    // Zero-alloc TX: one reused buffer, protect only (mirrors
    // RtpTransport::send_rtp_into filling a sendmmsg iov slot).
    let mut scratch = bytes::BytesMut::zeroed(session.protected_rtp_len(&plain));
    let start = Instant::now();
    for i in 1..=ITERS {
        hdr.sequence_number = i as u16;
        plain.header = hdr.clone();
        session.protect_rtp(&plain, &mut scratch).unwrap();
        black_box(&scratch[..]);
    }
    let protect_only = start.elapsed();
    println!(
        "  {:<28} {:>10.0} ops/s  {:>8.1} ns/packet",
        "session protect_into (reused)",
        ITERS as f64 / protect_only.as_secs_f64(),
        protect_only.as_nanos() as f64 / ITERS as f64
    );

    // Frame-scoped batch: 16 packets per frame, one session handle for the
    // whole frame (mirrors with_srtp_session + sendmmsg slot filling).
    const FRAME: usize = 16;
    let frames = ITERS as usize / FRAME;
    let start = Instant::now();
    let mut seq: u32 = 1;
    for _ in 0..frames {
        // One "lock" per frame — the session handle IS the lock scope.
        for _ in 0..FRAME {
            seq = seq.wrapping_add(1);
            hdr.sequence_number = seq as u16;
            plain.header = hdr.clone();
            session.protect_rtp(&plain, &mut scratch).unwrap();
            black_box(&scratch[..]);
        }
    }
    let batch = start.elapsed();
    let batch_packets = (frames * FRAME) as f64;
    println!(
        "  {:<28} {:>10.0} ops/s  {:>8.1} ns/packet (frame={FRAME})",
        "session batch protect",
        batch_packets / batch.as_secs_f64(),
        batch.as_nanos() as f64 / batch_packets
    );
}

fn ring_backend(key: &[u8; 16]) {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

    let unbound = UnboundKey::new(&AES_128_GCM, key).unwrap();
    let sealing = LessSafeKey::new(unbound);
    let aad = Aad::from([0u8; AAD_LEN]);

    // Warmup + roundtrip correctness check.
    {
        let mut buf = vec![0u8; PAYLOAD];
        let tag = sealing
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key([7u8; 12]), aad.clone(), &mut buf)
            .unwrap();
        assert_eq!(tag.as_ref().len(), 16);
        let mut joint = vec![0u8; PAYLOAD + 16];
        joint[..PAYLOAD].copy_from_slice(&buf);
        joint[PAYLOAD..].copy_from_slice(tag.as_ref());
        let plain = sealing
            .open_in_place(Nonce::assume_unique_for_key([7u8; 12]), aad.clone(), &mut joint)
            .unwrap();
        assert_eq!(plain.len(), PAYLOAD);
    }

    // Encrypt (protect): fresh buffer per iteration, in place, per-packet nonce.
    let start = Instant::now();
    for i in 0..ITERS {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&(i as u64).to_be_bytes());
        let mut buf = black_box(vec![0u8; PAYLOAD]);
        let tag = sealing
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                aad.clone(),
                &mut buf,
            )
            .unwrap();
        black_box(&tag);
        black_box(buf.len());
    }
    let enc = start.elapsed();

    // Decrypt (unprotect): ciphertext||tag in one buffer, in place.
    let mut joint_base = vec![0u8; PAYLOAD + 16];
    {
        let mut buf = vec![0u8; PAYLOAD];
        let tag = sealing
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key([7u8; 12]), aad.clone(), &mut buf)
            .unwrap();
        joint_base[..PAYLOAD].copy_from_slice(&buf);
        joint_base[PAYLOAD..].copy_from_slice(tag.as_ref());
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        let mut buf = black_box(joint_base.clone());
        let plain = sealing
            .open_in_place(Nonce::assume_unique_for_key([7u8; 12]), aad.clone(), &mut buf)
            .unwrap();
        black_box(plain.len());
    }
    let dec = start.elapsed();

    println!("--- ring 0.17 (rustls / QUIC path) ---");
    report("seal_in_place_separate_tag", enc);
    report("open_in_place", dec);
}

fn main() {
    println!(
        "AES-128-GCM backend comparison: {}B payload, {} iters, in-place, AAD={AAD_LEN}B, tag=16B",
        PAYLOAD, ITERS
    );
    let key = [0x2bu8; 16];
    aes_gcm_crate(&key);
    println!();
    ring_backend(&key);
}
