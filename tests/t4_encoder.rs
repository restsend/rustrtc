//! T.4 MH encoder roundtrip tests: encode bitmaps with the library encoder
//! and decode them with the fixture-validated replay decoder.

#![cfg(feature = "t38")]

use rustrtc::t38::{encode_mh_page, encode_mh_page_no_rtc};

#[path = "t38_mh/mod.rs"]
mod t38_mh;

/// Page = rows of 0 (white) / 1 (black) pixels.
type Page = Vec<Vec<u8>>;

fn expected_page(page: usize, page_rows: usize, cols: usize) -> Page {
    (0..page_rows)
        .map(|r| {
            let rr = r + page * page_rows;
            let mut row = vec![0u8; cols];
            for i in 0..cols.div_ceil(8) {
                let col = i * 8;
                let black = rr >= 4
                    && (rr / 4 + col / 48).is_multiple_of(2)
                    && (rr % 4 < 2 || col % 64 < 32);
                for k in 0..8 {
                    if black {
                        row[col + k] = 1;
                    }
                }
            }
            row
        })
        .collect()
}

fn assert_page_decodes(data: &[u8], pages: &[Page], width: usize) {
    let decoded = t38_mh::decode_t4_pages(data, width).expect("decode");
    assert_eq!(decoded.len(), pages.len(), "page count");
    for (n, (want, have)) in pages.iter().zip(decoded.iter()).enumerate() {
        assert_eq!(have.width, width, "page {n} width");
        assert_eq!(have.height, want.len(), "page {n} height");
        for (y, (wr, hr)) in want.iter().zip(have.rows.iter()).enumerate() {
            assert_eq!(hr, wr, "page {n} row {y}");
        }
    }
}

fn assert_roundtrip(page: &Page, width: usize, rtc: bool) {
    let data = if rtc {
        encode_mh_page(page, width)
    } else {
        encode_mh_page_no_rtc(page, width)
    };
    assert_page_decodes(&data, std::slice::from_ref(page), width);
}

#[test]
fn mh_encoder_single_page_pattern() {
    let width = 1728usize;
    let page = expected_page(0, 64, width);
    assert_roundtrip(&page, width, true);
}

#[test]
fn mh_encoder_single_page_no_rtc() {
    let width = 1728usize;
    let page = expected_page(0, 64, width);
    assert_roundtrip(&page, width, false);
}

#[test]
fn mh_encoder_two_pages() {
    let width = 1728usize;
    let p1 = expected_page(0, 32, width);
    let p2 = expected_page(1, 32, width);
    let mut data = encode_mh_page(&p1, width);
    data.extend_from_slice(&encode_mh_page(&p2, width));
    assert_page_decodes(&data, &[p1, p2], width);
}

#[test]
fn mh_encoder_all_white_and_all_black() {
    let width = 1728usize;
    let page0: Page = vec![vec![0u8; width]; 20];
    let page1: Page = vec![vec![1u8; width]; 20];
    let data = encode_mh_page(&page0, width)
        .into_iter()
        .chain(encode_mh_page(&page1, width))
        .chain(encode_mh_page(&page0, width))
        .collect::<Vec<u8>>();
    assert_page_decodes(&data, &[page0.clone(), page1.clone(), page0], width);
}

#[test]
fn mh_encoder_narrow_width() {
    let width = 96usize;
    let mut page = Vec::new();
    for y in 0..20 {
        let mut row = vec![0u8; width];
        if (8..16).contains(&y) {
            for r in &mut row[10..60] {
                *r = 1;
            }
        }
        page.push(row);
    }
    let data = encode_mh_page(&page, width);
    println!("stream: {:02x?}", &data[..data.len().min(40)]);
    let bits: Vec<u8> = data
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    let pat = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut eols = Vec::new();
    let mut i = 0usize;
    while i + 12 <= bits.len() {
        if bits[i..i + 12] == pat {
            eols.push(i);
            i += 12;
        } else {
            i += 1;
        }
    }
    println!("eols: {:?}", &eols[..eols.len().min(12)]);
    println!(
        "bits 0-60: {}",
        bits[..60].iter().map(|b| b.to_string()).collect::<String>()
    );
    for (i, b) in bits[..60].iter().enumerate() {
        if *b == 1 {
            print!("{} ", i);
        }
    }
    println!(" <- one-bit positions");
    for n in 0..eols.len().min(4) {
        let e = eols[n];
        println!(
            "eol {n} at {e}: tag={} next12={:?}",
            bits[e + 12],
            &bits[e + 13..(e + 25).min(bits.len())]
        );
    }
    let decoded = t38_mh::decode_t4_pages(&data, width).expect("decode");
    for p in &decoded {
        println!("page height {}", p.height);
        for (y, row) in p.rows.iter().enumerate() {
            let mut runs = String::new();
            let mut cur = row[0] != 0;
            let mut cnt = 0usize;
            for &px in row {
                let b = px != 0;
                if b == cur {
                    cnt += 1;
                } else {
                    runs.push_str(&format!("{}{} ", if cur { 'B' } else { 'w' }, cnt));
                    cur = b;
                    cnt = 1;
                }
            }
            runs.push_str(&format!("{}{}", if cur { 'B' } else { 'w' }, cnt));
            println!("  r{y}: {runs}");
        }
    }
    assert_page_decodes(&data, std::slice::from_ref(&page), width);
}

#[test]
fn mh_encoder_compression_ratio() {
    let width = 1728usize;
    let page = expected_page(0, 64, width);
    let data = encode_mh_page(&page, width);
    let raw = 64 * width / 8;
    assert!(
        data.len() < raw / 2,
        "MH stream {} bytes not compressed vs raw {} bytes",
        data.len(),
        raw
    );
}
