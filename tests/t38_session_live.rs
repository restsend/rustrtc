use std::sync::Arc;

use rustrtc::t38::endpoint::{FaxEndpoint, ReceiveCodec};
use rustrtc::t38::ifp::T30Indicator;
use rustrtc::t38::t30::{T30Event, T30FaxConfig, T30Role, T30Session, T30State};
use rustrtc::transports::udptl::UdtlTransport;

mod t38_mh;

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

struct Fixture {
    packets: Vec<(u8, Vec<u8>)>,
    t4_stream_len: usize,
    tx_page_rows: usize,
    tx_page_cols: usize,
}

fn load_fixture(name: &str) -> Fixture {
    #[derive(serde::Deserialize)]
    struct Pkt {
        dir: u8,
        hex: String,
    }
    #[derive(serde::Deserialize)]
    struct Raw {
        t4_stream_len: usize,
        tx_page_rows: usize,
        tx_page_cols: usize,
        packets: Vec<Pkt>,
    }
    let path = format!(
        "{}/tests/fixtures/t38_session_{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let raw: Raw = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    Fixture {
        packets: raw
            .packets
            .iter()
            .map(|p| (p.dir, from_hex(&p.hex)))
            .collect(),
        t4_stream_len: raw.t4_stream_len,
        tx_page_rows: raw.tx_page_rows,
        tx_page_cols: raw.tx_page_cols,
    }
}

fn extract_t4_stream(fx: &Fixture) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::new();
    for (dir, bytes) in &fx.packets {
        if *dir != 0 {
            continue;
        }
        if let Ok(rustrtc::t38::wire::WirePacket::Data { data_type, fields }) =
            rustrtc::t38::wire::decode_wire(bytes)
        {
            if data_type == 0 {
                continue;
            }
            for f in fields {
                if f.field_type == 6 {
                    for &by in &f.data {
                        for k in (0..8).rev() {
                            bits.push((by >> k) & 1);
                        }
                    }
                }
            }
        }
    }
    bits.chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b))
        .collect()
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

fn make_endpoint(
    socket: tokio::net::UdpSocket,
    remote: std::net::SocketAddr,
    role: T30Role,
) -> FaxEndpoint {
    let mut session = T30Session::new(T30FaxConfig::default());
    session.role = role;
    FaxEndpoint::new(
        Arc::new(UdtlTransport::new(Arc::new(socket), remote)),
        session,
    )
}

async fn pair() -> (FaxEndpoint, FaxEndpoint) {
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();
    let caller = make_endpoint(a, b_addr, T30Role::Caller);
    let callee = make_endpoint(b, a_addr, T30Role::Callee);
    caller.set_codec(ReceiveCodec::Wire);
    callee.set_codec(ReceiveCodec::Wire);
    (caller, callee)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_v27ter_4800_full_page() {
    let fx = load_fixture("v3");
    let page = extract_t4_stream(&fx);
    assert_eq!(page.len(), fx.t4_stream_len);

    let (caller, callee) = pair().await;
    caller.session.lock().await.set_tx_page(page.clone());
    caller.session.lock().await.set_two_dim_coding(true);

    let (ce, fe) = tokio::join!(caller.run_call(60_000), callee.run_call(60_000));

    let caller_final = caller.session.lock().await.state;
    let callee_final = callee.session.lock().await.state;
    assert_eq!(caller_final, T30State::Complete, "caller events: {ce:?}");
    assert_eq!(callee_final, T30State::Complete, "callee events: {fe:?}");

    let all: Vec<&T30Event> = ce.iter().chain(fe.iter()).collect();
    for ev in [
        &T30Event::DisReceived,
        &T30Event::DcsReceived,
        &T30Event::TrainingOk,
        &T30Event::CfrReceived,
        &T30Event::EopReceived,
        &T30Event::McfReceived,
        &T30Event::DcnReceived,
    ] {
        assert!(
            all.contains(&ev),
            "missing {ev:?} in dialogue\n caller: {ce:?}\n callee: {fe:?}"
        );
    }
    assert!(all.contains(&&T30Event::PageTransferred {
        page: 1,
        size: page.len()
    }));
    assert!(all.contains(&&T30Event::PageReceived {
        page: 1,
        size: page.len()
    }));

    let received = callee.session.lock().await.take_page_data();
    assert_eq!(received, page, "received T.4 stream differs");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_page_decodes_to_expected_image() {
    let fx = load_fixture("v3");
    let page = extract_t4_stream(&fx);

    let (caller, callee) = pair().await;
    caller.session.lock().await.set_tx_page(page.clone());
    caller.session.lock().await.set_two_dim_coding(true);

    let _ = tokio::join!(caller.run_call(60_000), callee.run_call(60_000));

    let received = callee.session.lock().await.take_page_data();
    let mut pages = t38_mh::decode_t4_pages(&received, fx.tx_page_cols).unwrap();
    pages.retain(|p| p.height >= fx.tx_page_rows / 2);
    assert_eq!(pages.len(), 1, "expected exactly one decoded page");
    let pg = &pages[0];
    assert_eq!(pg.width, fx.tx_page_cols);
    assert!(pg.height >= fx.tx_page_rows, "height {}", pg.height);

    let want = expected_page(0, fx.tx_page_rows, fx.tx_page_cols);
    for (y, row) in want.iter().enumerate().take(pg.height.min(want.len())) {
        for x in 0..fx.tx_page_cols {
            assert_eq!(pg.rows[y][x], row[x], "pixel mismatch at row {y} col {x}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_caller_times_out_without_callee() {
    let (caller, _callee) = {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b.local_addr().unwrap();
        let caller = make_endpoint(a, b_addr, T30Role::Caller);
        caller.session.lock().await.set_t1_max_ms(1500);
        (caller, b)
    };
    let events = caller.run_call(20_000).await;
    let state = caller.session.lock().await.state;
    assert_eq!(state, T30State::Failed);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, T30Event::Error(msg) if msg.contains("DIS")))
    );
}

#[tokio::test]
async fn loopback_indicator_passthrough_still_works() {
    let (caller, callee) = pair().await;
    let _ = caller.send_indicator(T30Indicator::Cng).await;
    let pkt = tokio::time::timeout(std::time::Duration::from_secs(2), callee.recv())
        .await
        .unwrap()
        .expect("packet");
    assert_eq!(pkt.indicators(), &[T30Indicator::Cng]);
}
