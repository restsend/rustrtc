#![cfg(feature = "t38")]

mod t38_mh;

use rustrtc::t38::wire::{T38CoreRx, decode_wire, encode_wire_data, encode_wire_indicator};
use serde::Deserialize;

#[derive(Deserialize)]
struct SessionFixture {
    ecm: bool,
    page_count: u32,
    tx_page_rows: u32,
    tx_page_cols: u32,
    phase_e_caller: i32,
    phase_e_callee: i32,
    caller_fcfs: Vec<u8>,
    callee_fcfs: Vec<u8>,
    t4_stream_len: usize,
    t4_stream_sha256: String,
    packets: Vec<SessionPacket>,
}

#[derive(Deserialize)]
struct SessionPacket {
    dir: u8,
    seq: u16,
    hex: String,
    peer_ret: i32,
    tap_ok: bool,
    reencode_ok: bool,
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while !(msg.len() + 8).is_multiple_of(64) {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.iter().enumerate() {
            w[i / 4] = (w[i / 4] << 8) | *b as u32;
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn expected_page(page: usize, page_rows: usize, cols: usize) -> Vec<Vec<u8>> {
    (0..page_rows)
        .map(|r| {
            let rr = r + page * page_rows;
            let mut row = Vec::with_capacity(cols);
            for i in 0..cols.div_ceil(8) {
                let col = i * 8;
                let black = rr >= 4
                    && ((rr / 4 + col / 48).is_multiple_of(2))
                    && (rr % 4 < 2 || col % 64 < 32);
                row.extend(std::iter::repeat_n(if black { 1u8 } else { 0u8 }, 8));
            }
            row
        })
        .collect()
}

fn replay(name: &str, assert_pages: bool) {
    let path = format!(
        "{}/tests/fixtures/t38_session_{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let fixture: SessionFixture =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    assert_eq!(fixture.phase_e_caller, 0, "{name}: caller incomplete");
    assert_eq!(fixture.phase_e_callee, 0, "{name}: callee incomplete");

    let mut tap_ab = T38CoreRx::new(3);
    let mut tap_ba = T38CoreRx::new(3);
    let mut hdlc: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut frames: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut t4_bits: Vec<u8> = Vec::new();
    let mut indicators: [Vec<i32>; 2] = [Vec::new(), Vec::new()];

    for p in &fixture.packets {
        let bytes = from_hex(&p.hex);
        assert_eq!(
            p.peer_ret, 0,
            "{name}: peer rejected dir={} seq={}",
            p.dir, p.seq
        );
        assert!(
            p.tap_ok && p.reencode_ok,
            "{name}: capture diverged dir={} seq={}",
            p.dir,
            p.seq
        );
        let tap = if p.dir == 0 { &mut tap_ab } else { &mut tap_ba };
        tap.feed(p.seq, &bytes).unwrap_or_else(|e| {
            panic!("{name}: decoder rejected dir={} seq={}: {e}", p.dir, p.seq)
        });

        match decode_wire(&bytes).unwrap_or_else(|e| panic!("{name}: decode dir={}: {e}", p.seq)) {
            rustrtc::t38::wire::WirePacket::Indicator(v) => {
                let enc = encode_wire_indicator(3, v[0] as i32).unwrap();
                assert_eq!(enc, bytes, "{name}: indicator round-trip seq={}", p.seq);
                indicators[p.dir as usize].push(v[0] as i32);
            }
            rustrtc::t38::wire::WirePacket::Data { data_type, fields } => {
                let enc = encode_wire_data(3, data_type as i32, &fields).unwrap();
                assert_eq!(enc, bytes, "{name}: data round-trip seq={}", p.seq);
                let dir = p.dir as usize;
                for f in fields {
                    if data_type == 0 {
                        match f.field_type {
                            0 => hdlc[dir].extend_from_slice(&f.data),
                            2 | 4 | 5 => {
                                hdlc[dir].extend_from_slice(&f.data);
                                if hdlc[dir].len() >= 3 {
                                    frames[dir].push(hdlc[dir][2]);
                                }
                                hdlc[dir].clear();
                            }
                            1 => hdlc[dir].clear(),
                            _ => {}
                        }
                    } else if dir == 0 && data_type >= 1 {
                        if fixture.ecm && f.field_type == 0 && f.data.first() == Some(&0xFF) {
                            let mut v = 0u16;
                            let mut taken = 0usize;
                            let mut cut = None;
                            'outer: for (bi, &by) in f.data.iter().enumerate() {
                                for k in (0..8).rev() {
                                    v = (v << 1) | u16::from((by >> k) & 1);
                                    taken += 1;
                                    if taken >= 12 && v == 0x001 {
                                        cut = Some(bi * 8 + k + 1 - 12);
                                        break 'outer;
                                    }
                                }
                            }
                            if let Some(cut) = cut {
                                for bi in cut..f.data.len() * 8 {
                                    let byte = bi / 8;
                                    let k = 7 - (bi % 8);
                                    t4_bits.push((f.data[byte] >> k) & 1);
                                }
                            }
                        } else if matches!(f.field_type, 0 | 2 | 4 | 6) {
                            for &by in &f.data {
                                for k in (0..8).rev() {
                                    t4_bits.push((by >> k) & 1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    assert_eq!(frames[1], fixture.callee_fcfs, "{name}: callee dialogue");
    assert_eq!(frames[0], fixture.caller_fcfs, "{name}: caller dialogue");
    assert!(indicators[0].contains(&1), "{name}: CNG");
    assert!(indicators[1].contains(&2), "{name}: CED");

    let t4: Vec<u8> = t4_bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b))
        .collect();
    assert_eq!(t4.len(), fixture.t4_stream_len, "{name}: stream length");
    assert_eq!(
        sha256_hex(&t4),
        fixture.t4_stream_sha256,
        "{name}: stream hash"
    );

    if assert_pages {
        let width = fixture.tx_page_cols as usize;
        let page_rows = fixture.tx_page_rows as usize;
        let mut pages = t38_mh::decode_t4_pages(&t4, width)
            .unwrap_or_else(|e| panic!("{name}: T.4 decode: {e}"));
        pages.retain(|pg| pg.height >= page_rows / 2);
        assert_eq!(
            pages.len(),
            fixture.page_count as usize,
            "{name}: page count"
        );
        let max_bad_rows = if fixture.ecm { 2 } else { 0 };
        for (p, page) in pages.iter().enumerate() {
            assert_eq!(page.width, width, "{name}: page {p} width");
            let min_height = if fixture.ecm {
                page_rows * 2 / 3
            } else {
                page_rows
            };
            assert!(
                page.height >= min_height,
                "{name}: page {p} height {}",
                page.height
            );
            let want = expected_page(p, page_rows, width);
            let compare = |shift: isize| -> usize {
                let mut bad = 0;
                for r in 0..page.height {
                    let wr = r as isize + shift;
                    if wr < 0 || wr >= want.len() as isize {
                        bad += 1;
                        continue;
                    }
                    if page.rows[r] != want[wr as usize] {
                        bad += 1;
                    }
                }
                bad
            };
            let (bad, height_checked) = if fixture.ecm {
                let best = (-4..=4).map(compare).min().unwrap_or(usize::MAX);
                (best, page.height)
            } else {
                (compare(0), page.height)
            };
            let limit = if fixture.ecm {
                height_checked / 2 + 2
            } else {
                max_bad_rows
            };
            assert!(
                bad <= limit,
                "{name}: page {p} has {bad} imperfect rows (max {limit})"
            );
            if !fixture.ecm {
                let pbm = t38_mh::to_pbm(page);
                let out = format!(
                    "{}/target/t38_session_{}_page{p}.pbm",
                    env!("CARGO_MANIFEST_DIR"),
                    name
                );
                std::fs::write(&out, &pbm).unwrap();
            }
        }
    }

    println!(
        "{name}: {} packets, {} fcfs caller={:02x?}, stream {} bytes, {} pages decoded",
        fixture.packets.len(),
        frames[0].len(),
        fixture.caller_fcfs,
        t4.len(),
        fixture.page_count
    );
}

#[test]
fn replay_fax_sessions_pure_rust() {
    replay("v3", true);
    replay("fine2p", true);
    replay("ecm", true);
    replay("v27", true);
}
