#![cfg(not(feature = "std"))]

//! no_std SCTP data-channel e2e: two `PeerConnection`s on the mock embedded
//! runtime negotiate an `m=application` section, run ICE + DTLS, establish
//! the SCTP association, exchange DCEP OPEN/ACK for `ctl`/`cmd`, and carry
//! binary messages in both directions.
//!
//! This is the regression that would have caught the `mpsc::try_recv`
//! unimplemented panic: the SCTP runner batch-drains queued packets after the
//! select that woke it.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::{drive, drive_until, install_mock_platform, keep_task_labeled};
use rustrtc::config::{ApplicationCapability, MediaCapabilities, RtcConfiguration};
use rustrtc::peer_connection::{PeerConnection, PeerConnectionEvent};
use rustrtc::transports::dtls::Certificate;
use rustrtc::{DataChannel, DataChannelConfig, DataChannelEvent};

const CERT_DER: &[u8] = include_bytes!("fixtures/dtls_cert.der");
const KEY_DER: &[u8] = include_bytes!("fixtures/dtls_key.der");

fn agent(label: &str, start: u16, end: u16) -> PeerConnection {
    let mut config = RtcConfiguration::webrtc();
    config.label = Some(label.to_string());
    config.bind_ips = vec!["127.0.0.1".parse().unwrap()];
    config.rtp_start_port = Some(start);
    config.rtp_end_port = Some(end);
    config.media_capabilities = Some(MediaCapabilities {
        application: Some(ApplicationCapability { sctp_port: 5000 }),
        ..Default::default()
    });
    let cert = Certificate::from_pkcs8_der(CERT_DER.to_vec(), KEY_DER.to_vec())
        .expect("fixture certificate");
    config.dtls_certificate = Some(Arc::new(cert));
    PeerConnection::new(config)
}

fn channel(label: &str) -> DataChannelConfig {
    match label {
        "ctl" => DataChannelConfig {
            ordered: false,
            max_retransmits: Some(0),
            ..Default::default()
        },
        _ => DataChannelConfig {
            ordered: true,
            ..Default::default()
        },
    }
}

fn spawn_reader(dc: Arc<DataChannel>, opened: Arc<AtomicUsize>, rx: Arc<Mutex<Vec<Vec<u8>>>>) {
    keep_task_labeled(
        "dc-reader",
        Box::new(async move {
            while let Some(event) = dc.recv().await {
                match event {
                    DataChannelEvent::Open => {
                        opened.fetch_add(1, Ordering::SeqCst);
                    }
                    DataChannelEvent::Message(data) => {
                        rx.lock().unwrap().push(data.to_vec());
                    }
                    DataChannelEvent::Close => break,
                    DataChannelEvent::BufferedAmountLow(_) => {}
                }
            }
        }),
    );
}

#[test]
fn two_no_std_pcs_exchange_data_channels() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    install_mock_platform();

    let pc1 = agent("dc-pc1", 62_000, 62_020);
    let pc2 = agent("dc-pc2", 63_000, 63_020);

    // The offerer creates both channels; the answerer adopts them from DCEP.
    let ctl1 = pc1
        .create_data_channel("ctl", Some(channel("ctl")))
        .expect("ctl");
    let cmd1 = pc1
        .create_data_channel("cmd", Some(channel("cmd")))
        .expect("cmd");

    let opened1 = Arc::new(AtomicUsize::new(0));
    let rx1 = Arc::new(Mutex::new(Vec::new()));
    spawn_reader(ctl1.clone(), opened1.clone(), rx1.clone());
    spawn_reader(cmd1.clone(), opened1.clone(), rx1.clone());

    // Answerer: adopt the remote channels and read their events.
    let opened2 = Arc::new(AtomicUsize::new(0));
    let rx2 = Arc::new(Mutex::new(Vec::new()));
    let cmd_id2 = Arc::new(AtomicUsize::new(u16::MAX as usize));
    {
        let pc2 = pc2.clone();
        let opened2 = opened2.clone();
        let rx2 = rx2.clone();
        let cmd_id2 = cmd_id2.clone();
        keep_task_labeled(
            "dc-events",
            Box::new(async move {
                while let Some(event) = pc2.recv().await {
                    if let PeerConnectionEvent::DataChannel(dc) = event {
                        if dc.label == "cmd" {
                            cmd_id2.store(dc.id as usize, Ordering::SeqCst);
                        }
                        spawn_reader(dc, opened2.clone(), rx2.clone());
                    }
                    if opened2.load(Ordering::SeqCst) >= 2 {
                        break;
                    }
                }
            }),
        );
    }

    // Offer / answer.
    let _ = drive(pc1.create_offer(), 5_000).expect("trigger offer");
    drive(pc1.wait_for_gathering_complete(), 10_000).expect("gather offer");
    let offer = drive(pc1.create_offer(), 5_000)
        .expect("offer")
        .expect("offer result");
    let offer_sdp = offer.to_sdp_string();
    assert!(
        offer_sdp.contains("m=application")
            && offer_sdp.contains("webrtc-datachannel")
            && offer_sdp.contains("a=sctp-port:5000"),
        "offer must carry the data-channel section:\n{offer_sdp}"
    );
    pc1.set_local_description(offer.clone())
        .expect("local offer");
    drive(pc2.set_remote_description(offer), 5_000)
        .expect("remote offer")
        .expect("remote offer result");

    let _ = drive(pc2.create_answer(), 5_000).expect("trigger answer");
    drive(pc2.wait_for_gathering_complete(), 10_000).expect("gather answer");
    let answer = drive(pc2.create_answer(), 5_000)
        .expect("answer")
        .expect("answer result");
    let answer_sdp = answer.to_sdp_string();
    assert!(
        answer_sdp.contains("m=application") && answer_sdp.contains("a=sctp-port:5000"),
        "answer must carry the data-channel section:\n{answer_sdp}"
    );
    pc2.set_local_description(answer.clone())
        .expect("local answer");
    drive(pc1.set_remote_description(answer), 5_000)
        .expect("remote answer")
        .expect("remote answer result");

    // Both sides must see both channels OPEN (DCEP OPEN/ACK).
    let opened = drive_until(
        || opened1.load(Ordering::SeqCst) >= 2 && opened2.load(Ordering::SeqCst) >= 2,
        60_000,
    );
    eprintln!(
        "datachannel e2e: opened1={} opened2={} clock={}ms",
        opened1.load(Ordering::SeqCst),
        opened2.load(Ordering::SeqCst),
        common::clock()
    );
    assert!(
        opened,
        "both sides must open ctl+cmd (local={}, remote={})",
        opened1.load(Ordering::SeqCst),
        opened2.load(Ordering::SeqCst)
    );

    // PC1 -> PC2 on ctl.
    drive(pc1.send_data(ctl1.id, b"pc1-ctl"), 5_000)
        .expect("send ctl")
        .expect("ctl send result");
    // PC1 -> PC2 on cmd.
    drive(pc1.send_data(cmd1.id, b"pc1-cmd"), 5_000)
        .expect("send cmd")
        .expect("cmd send result");

    let got = drive_until(|| rx2.lock().unwrap().len() >= 2, 30_000);
    let received = rx2.lock().unwrap().clone();
    eprintln!("datachannel e2e: pc2 received {:?}", received);
    assert!(got, "pc2 must receive both messages, got {received:?}");
    assert!(
        received.iter().any(|m| m == b"pc1-ctl"),
        "pc2 missing ctl payload: {received:?}"
    );
    assert!(
        received.iter().any(|m| m == b"pc1-cmd"),
        "pc2 missing cmd payload: {received:?}"
    );

    // PC2 -> PC1 on cmd (the answerer's adopted channel id).
    let cmd2 = cmd_id2.load(Ordering::SeqCst) as u16;
    assert_ne!(cmd2, u16::MAX, "answerer never installed the cmd channel");
    drive(pc2.send_data(cmd2, b"pc2-cmd"), 5_000)
        .expect("send reverse cmd")
        .expect("reverse cmd result");
    let got = drive_until(
        || rx1.lock().unwrap().iter().any(|m| m == b"pc2-cmd"),
        30_000,
    );
    assert!(got, "pc1 must receive the reverse cmd payload");
}
