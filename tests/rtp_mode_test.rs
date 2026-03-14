use anyhow::Result;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::{
    MediaKind, PeerConnection, PeerConnectionEvent, RtcConfiguration, RtpCodecParameters,
    TransceiverDirection, TransportMode,
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_rtp_mode_peer_connection() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // PC1: Publisher (RTP Mode)
    let mut config1 = RtcConfiguration::default();
    config1.transport_mode = TransportMode::Rtp;
    config1.bind_ip = Some("127.0.0.1".to_string());
    let pc1 = PeerConnection::new(config1);

    // PC2: Receiver (RTP Mode)
    let mut config2 = RtcConfiguration::default();
    config2.transport_mode = TransportMode::Rtp;
    config2.bind_ip = Some("127.0.0.1".to_string());
    let pc2 = PeerConnection::new(config2);

    // PC1 adds a track
    let (source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::frame::MediaKind::Video, 100);
    let source = Arc::new(source);
    let params = RtpCodecParameters {
        payload_type: 96,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        channels: 0,
        fmtp: None,
        rtcp_fbs: Vec::new(),
    };
    let _sender = pc1.add_track(track.clone(), params.clone())?;

    // PC2 adds a transceiver to receive
    pc2.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    let (track_tx, mut track_rx) = tokio::sync::mpsc::unbounded_channel();
    let pc2_clone = pc2.clone();
    tokio::spawn(async move {
        while let Some(event) = pc2_clone.recv().await {
            if let PeerConnectionEvent::Track(transceiver) = event {
                let _ = track_tx.send(transceiver);
            }
        }
    });

    // Exchange SDP
    // 1. PC1 Create Offer
    // Trigger gathering
    let _ = pc1.create_offer().await?;
    // Wait for gathering
    pc1.wait_for_gathering_complete().await;

    let offer = pc1.create_offer().await?;
    println!("Offer SDP:\n{}", offer.to_sdp_string());

    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;

    // 2. PC2 Create Answer
    // Trigger gathering
    let _ = pc2.create_answer().await?;
    // Wait for gathering
    pc2.wait_for_gathering_complete().await;

    let answer = pc2.create_answer().await?;
    println!("Answer SDP:\n{}", answer.to_sdp_string());

    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    // Wait for connection
    let t1 = pc1.wait_for_connected();
    let t2 = pc2.wait_for_connected();

    // Add a timeout to avoid hanging if connection fails
    let connect_future = async { tokio::try_join!(t1, t2) };

    match tokio::time::timeout(Duration::from_secs(10), connect_future).await {
        Ok(Ok(_)) => println!("Connected!"),
        Ok(Err(e)) => panic!("Connection failed: {}", e),
        Err(_) => panic!("Connection timed out"),
    }

    // Start sending data from PC1
    let source_clone = source.clone();
    let send_task = tokio::spawn(async move {
        let mut seq = 0;
        // Send enough packets to ensure reception
        for _ in 0..100 {
            let frame = VideoFrame {
                rtp_timestamp: seq * 3000,
                data: bytes::Bytes::from(vec![seq as u8; 100]), // Use seq as data to verify
                is_last_packet: true,
                ..Default::default()
            };
            let sample = MediaSample::Video(frame);

            if source_clone.send(sample).await.is_err() {
                break;
            }
            seq += 1;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // RTP mode only exposes a stable remote track after the receiver latches the
    // first incoming SSRC and emits the Track event.
    let transceiver = tokio::time::timeout(Duration::from_secs(5), track_rx.recv())
        .await?
        .expect("PC2 should emit a Track event after RTP starts flowing");
    let receiver = transceiver
        .receiver()
        .expect("track event should include receiver");
    let track_remote = receiver.track();

    // Read a few packets
    let mut received_packets = 0;
    let mut last_seq = -1;

    let read_task = tokio::spawn(async move {
        while let Ok(sample) = track_remote.recv().await {
            if let MediaSample::Video(frame) = sample {
                let data = frame.data;
                if !data.is_empty() {
                    let seq = data[0] as i32;
                    // println!("Received packet seq: {}", seq);
                    if last_seq != -1 && seq > last_seq {
                        // Good
                    }
                    last_seq = seq;
                }
            }

            received_packets += 1;
            if received_packets >= 10 {
                break;
            }
        }
        received_packets
    });

    let received_count = match tokio::time::timeout(Duration::from_secs(5), read_task).await {
        Ok(Ok(count)) => count,
        Ok(Err(e)) => panic!("Read task failed: {}", e),
        Err(_) => 0, // Timeout
    };

    send_task.abort();

    println!("Received {} packets", received_count);
    assert!(received_count >= 10, "Should receive at least 10 packets");

    Ok(())
}
