//! T.38 hot-path benchmark. Run with:
//!   cargo run --release --features t38 --example t38_bench

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use rustrtc::t38::endpoint::{FaxEndpoint, ReceiveCodec};
use rustrtc::t38::ifp::DataFieldType;
use rustrtc::t38::t30::{T30FaxConfig, T30Role, T30Session};
use rustrtc::t38::wire::{WireDataField, decode_wire, decode_wire_bytes, encode_wire_data};
use rustrtc::t38::{T30Indicator, encode_mh_page};
use rustrtc::transports::udptl::UdtlTransport;

const ITER: usize = 20_000;
const PAYLOAD: usize = 54;

fn sample_fields(n: usize) -> Vec<WireDataField> {
    (0..n)
        .map(|i| {
            let mut data = Vec::with_capacity(PAYLOAD);
            for j in 0..PAYLOAD {
                data.push(((i + j) & 0xFF) as u8);
            }
            WireDataField::new(6, data)
        })
        .collect()
}

fn bench_wire_encode() {
    let fields = sample_fields(1);
    let start = Instant::now();
    let mut total = 0usize;
    for i in 0..ITER {
        let pkt = encode_wire_data(3, 7, black_box(&fields)).unwrap();
        total += pkt.len();
        black_box(pkt);
        let _ = i;
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "wire_encode:        {:>9.0} pkt/s  {:>8.2} MB/s  ({} B/pkt)",
        ITER as f64 / elapsed,
        total as f64 / elapsed / 1e6,
        total / ITER
    );
}

fn bench_wire_decode() {
    let fields = sample_fields(1);
    let pkt = encode_wire_data(3, 7, &fields).unwrap();
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..ITER {
        let decoded = decode_wire(black_box(&pkt)).unwrap();
        if let rustrtc::t38::wire::WirePacket::Data { fields, .. } = &decoded {
            total += fields.iter().map(|f| f.data.len()).sum::<usize>();
        }
        black_box(decoded);
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "wire_decode:        {:>9.0} pkt/s  {:>8.2} MB/s  ({} B/pkt)",
        ITER as f64 / elapsed,
        total as f64 / elapsed / 1e6,
        total / ITER
    );
}

fn build_dis() -> Vec<u8> {
    rustrtc::t38::t30::HdlcFrame::with_fif(
        rustrtc::t38::t30::HdlcFrameType::Dis,
        false,
        vec![0x04, 0x0A, 0x00, 0x00],
    )
    .to_bytes()
}

fn bench_wire_decode_bytes() {
    let fields = sample_fields(1);
    let pkt = encode_wire_data(3, 7, &fields).unwrap();
    let datagram = Bytes::copy_from_slice(&pkt);
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..ITER {
        let decoded = decode_wire_bytes(black_box(datagram.clone())).unwrap();
        if let rustrtc::t38::wire::WirePacket::Data { fields, .. } = &decoded {
            total += fields.iter().map(|f| f.data.len()).sum::<usize>();
        }
        black_box(decoded);
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "wire_decode_bytes:  {:>9.0} pkt/s  {:>8.2} MB/s  ({} B/pkt, zero-copy fields)",
        ITER as f64 / elapsed,
        total as f64 / elapsed / 1e6,
        total / ITER
    );
}

fn bench_endpoint_rx_flow() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b.local_addr().unwrap();
        let mut session = T30Session::new(T30FaxConfig::default());
        session.role = T30Role::Callee;
        session.start_at(0);
        let callee = FaxEndpoint::new(
            Arc::new(UdtlTransport::new(Arc::new(b), a.local_addr().unwrap())),
            session,
        );
        callee.set_codec(ReceiveCodec::Wire);
        let tx = Arc::new(UdtlTransport::new(Arc::new(a), b_addr));

        // Pre-build the page-data packets the way the caller would.
        let chunks = 24usize;
        let mut packets = Vec::new();
        packets.push((T30Indicator::V27Ter4800Preamble as u8, None));
        for i in 0..chunks {
            let data: Vec<u8> = (0..54u32)
                .map(|j| ((i as u32 * 7 + j) & 0xFF) as u8)
                .collect();
            let pkt = encode_wire_data(
                3,
                7,
                &[WireDataField::new(DataFieldType::T4NonEcm as i32, data)],
            )
            .unwrap();
            packets.push((0, Some(pkt)));
        }

        const ROUNDS: usize = 60;
        let npackets = packets.len() * ROUNDS;
        let start = Instant::now();
        let mut decoded_bytes = 0usize;
        for _ in 0..ROUNDS {
            for (ind, pkt) in &packets {
                match pkt {
                    None => {
                        tx.send(&[*ind]).await.unwrap();
                    }
                    Some(p) => {
                        tx.send(p).await.unwrap();
                    }
                }
            }
            // Drain everything that arrived.
            loop {
                match callee
                    .recv_timeout(std::time::Duration::from_millis(1))
                    .await
                {
                    Some(packet) => {
                        for (ft, data) in packet.data_fields() {
                            if ft == DataFieldType::T4NonEcm as u8 {
                                decoded_bytes += data.len();
                                black_box(data);
                            }
                        }
                    }
                    None => break,
                }
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "endpoint_rx_flow:   {:>9.0} pkt/s  {:>8.2} MB/s  ({} packets)",
            npackets as f64 / elapsed,
            decoded_bytes as f64 / elapsed / 1e6,
            npackets
        );
    });
}

fn a_socket_addr(a: &tokio::net::UdpSocket) -> std::net::SocketAddr {
    a.local_addr().unwrap()
}

fn bench_session_page_flow() {
    let page: Vec<u8> = (0..3064).map(|i| (i * 31 & 0xFF) as u8).collect();
    let mut session = T30Session::new(T30FaxConfig::default());
    session.role = T30Role::Callee;
    session.start_at(0);
    session.state = rustrtc::t38::t30::T30State::WaitingPage;
    let chunk = 54usize;
    let rounds = 200usize;
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..rounds {
        let mut pos = 0usize;
        while pos < page.len() {
            let end = (pos + chunk).min(page.len());
            session.on_data(7, 6, &page[pos..end]);
            pos = end;
        }
        session.on_data(7, 7, &[]);
        total += page.len();
        black_box(session.page_data.len());
        session.page_data.clear();
        session.page_number = 0;
        session.state = rustrtc::t38::t30::T30State::WaitingPage;
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "session_page_flow:  {:>9.0} chunk/s  {:>8.2} MB/s  ({} B/page)",
        (total / chunk) as f64 / elapsed,
        total as f64 / elapsed / 1e6,
        page.len()
    );
}

fn bench_mh_encode() {
    let width = 1728usize;
    let mut page = Vec::new();
    for y in 0..64 {
        let mut row = vec![0u8; width];
        if y >= 4 {
            for i in 0..width.div_ceil(8) {
                let col = i * 8;
                let black = (y / 4 + col / 48).is_multiple_of(2) && (y % 4 < 2 || col % 64 < 32);
                if black {
                    for k in 0..8 {
                        row[col + k] = 1;
                    }
                }
            }
        }
        page.push(row);
    }
    let rounds = 2000usize;
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..rounds {
        let data = encode_mh_page(black_box(&page), width);
        total += data.len();
        black_box(data);
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "mh_encode:          {:>9.0} page/s  {:>8.2} MB/s  ({} B/page)",
        rounds as f64 / elapsed,
        total as f64 / elapsed / 1e6,
        total / rounds
    );
}

fn main() {
    println!("=== T.38 bench (ITER={ITER}, payload={PAYLOAD}B) ===");
    bench_wire_encode();
    bench_wire_decode();
    bench_wire_decode_bytes();
    bench_endpoint_rx_flow();
    bench_session_page_flow();
    bench_mh_encode();
}
