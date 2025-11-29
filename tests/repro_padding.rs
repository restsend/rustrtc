use anyhow::Result;
use bytes::Bytes;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{MediaSample, VideoFrame, VideoPixelFormat};
use rustrtc::transports::ice::IceGathererState;
use rustrtc::{MediaKind, RtcConfiguration};
use rustrtc::{PeerConnection, TransceiverDirection};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_padding_packet_drop() -> Result<()> {
    println!("Start test");
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create PC1 (Client)
    println!("Create PC1");
    let config1 = RtcConfiguration::default();
    let pc1 = PeerConnection::new(config1);

    // 2. Create PC2 (Server)
    println!("Create PC2");
    let config2 = RtcConfiguration::default();
    let pc2 = PeerConnection::new(config2);

    // Setup Sending on PC1 (Before Negotiation)
    let (client_source, client_track) =
        rustrtc::media::sample_track(rustrtc::media::MediaKind::Video, 96);

    // PC1 adds transceiver with sender
    let t1 = pc1.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

    let s1 = Arc::new(rustrtc::peer_connection::RtpSender::new(
        client_track,
        11111,
    ));
    s1.set_params(rustrtc::peer_connection::RtpCodecParameters {
        payload_type: 96,
        clock_rate: 90000,
        channels: 0,
    });
    t1.set_sender(Some(s1.clone()));

    // 3. Negotiate
    // PC1 Create Offer
    println!("PC1 Create Offer");
    let _ = pc1.create_offer().await?; // Trigger gathering
    println!("PC1 Wait Gathering");
    wait_for_gathering(&pc1).await;
    println!("PC1 Create Offer 2");
    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;

    // PC2 Set Remote Offer
    println!("PC2 Set Remote Offer");
    pc2.set_remote_description(offer).await?;

    // Setup Echo on PC2 (Before Answer)
    // Get the transceiver created by set_remote_description
    let t2 = pc2.get_transceivers().first().unwrap().clone();

    // Create a sender for PC2 to echo back
    let (sample_source, outgoing_track) =
        rustrtc::media::sample_track(rustrtc::media::MediaKind::Video, 96);
    let s2 = Arc::new(rustrtc::peer_connection::RtpSender::new(
        outgoing_track,
        55555,
    ));
    s2.set_params(rustrtc::peer_connection::RtpCodecParameters {
        payload_type: 96,
        clock_rate: 90000,
        channels: 0,
    });
    t2.set_sender(Some(s2));

    // PC2 Create Answer
    println!("PC2 Create Answer");
    let _ = pc2.create_answer().await?; // Trigger gathering
    println!("PC2 Wait Gathering");
    wait_for_gathering(&pc2).await;
    println!("PC2 Create Answer 2");
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;

    // PC1 Set Remote Answer
    println!("PC1 Set Remote Answer");
    pc1.set_remote_description(answer).await?;

    // 4. Start Echo Loop on PC2
    let r2 = t2.receiver().unwrap();
    let track2 = r2.track();

    tokio::spawn(async move {
        loop {
            match track2.recv().await {
                Ok(sample) => {
                    // Echo the sample
                    let _ = sample_source.send(sample).await;
                }
                Err(_) => break,
            }
        }
    });

    // 6. Send Packets from PC1
    println!("PC1 Wait Connection");
    pc1.wait_for_connection().await?;
    println!("PC2 Wait Connection");
    pc2.wait_for_connection().await?;

    // Packet 1: Valid
    println!("Sending P1");
    let f1 = VideoFrame {
        timestamp: Duration::from_millis(0),
        rtp_timestamp: Some(1000),
        width: 0,
        height: 0,
        format: VideoPixelFormat::Unspecified,
        rotation_deg: 0,
        is_last_packet: false,
        data: Bytes::from(vec![0x90, 0x80, 0x01]),
        header_extension: None,
        csrcs: Vec::new(),
        sequence_number: None,
        payload_type: None,
    };
    client_source.send_video(f1).await?;
    println!("Sent P1");

    // Packet 2: Empty (Padding)
    println!("Sending P2");
    let f2 = VideoFrame {
        timestamp: Duration::from_millis(0),
        rtp_timestamp: Some(1000),
        width: 0,
        height: 0,
        format: VideoPixelFormat::Unspecified,
        rotation_deg: 0,
        is_last_packet: false,
        data: Bytes::new(), // Empty
        header_extension: None,
        csrcs: Vec::new(),
        sequence_number: None,
        payload_type: None,
    };
    client_source.send_video(f2).await?;
    println!("Sent P2");

    // Packet 3: Valid
    println!("Sending P3");
    let f3 = VideoFrame {
        timestamp: Duration::from_millis(33),
        rtp_timestamp: Some(4000),
        width: 0,
        height: 0,
        format: VideoPixelFormat::Unspecified,
        rotation_deg: 0,
        is_last_packet: true,
        data: Bytes::from(vec![0x90, 0x80, 0x02]),
        header_extension: None,
        csrcs: Vec::new(),
        sequence_number: None,
        payload_type: None,
    };
    client_source.send_video(f3).await?;
    println!("Sent P3");

    // 7. Verify Reception on PC1
    let r1 = t1.receiver().unwrap();
    let track1 = r1.track();

    // Expect P1
    let s1_recv = timeout(Duration::from_secs(5), track1.recv())
        .await?
        .unwrap();
    if let MediaSample::Video(f) = s1_recv {
        println!("Received P1: len={}", f.data.len());
        assert!(!f.data.is_empty());
    } else {
        panic!("Expected Video sample");
    }

    // Expect P2 (Empty - Padding/Keepalive)
    let s2_recv = timeout(Duration::from_secs(5), track1.recv())
        .await?
        .unwrap();
    if let MediaSample::Video(f) = s2_recv {
        println!("Received P2: len={}", f.data.len());
        assert!(f.data.is_empty());
    } else {
        panic!("Expected Video sample");
    }

    // Expect P3
    let s3_recv = timeout(Duration::from_secs(5), track1.recv())
        .await?
        .unwrap();
    if let MediaSample::Video(f) = s3_recv {
        println!("Received P3: len={}", f.data.len());
        assert!(!f.data.is_empty());
    } else {
        panic!("Expected Video sample");
    }

    // Ensure no more packets
    let res = timeout(Duration::from_millis(500), track1.recv()).await;
    assert!(res.is_err(), "Should not receive a 3rd packet");

    pc1.close();
    pc2.close();

    Ok(())
}

async fn wait_for_gathering(pc: &PeerConnection) {
    loop {
        if pc.ice_transport().gather_state().await == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
