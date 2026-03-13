use anyhow::Result;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::{
    MediaKind, PeerConnection, RtcConfiguration, RtpCodecParameters, TransceiverDirection,
    TransportMode,
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_remote_addr_and_raw_packet() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // PC1: Publisher (RTP Mode)
    let mut config1 = RtcConfiguration::default();
    config1.transport_mode = TransportMode::Rtp;
    let pc1 = PeerConnection::new(config1);

    // PC2: Receiver (RTP Mode)
    let mut config2 = RtcConfiguration::default();
    config2.transport_mode = TransportMode::Rtp;
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

    // Exchange SDP
    // 1. PC1 Create Offer
    let _ = pc1.create_offer().await?;
    pc1.wait_for_gathering_complete().await;
    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;

    // 2. PC2 Create Answer
    let _ = pc2.create_answer().await?;
    pc2.wait_for_gathering_complete().await;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    // Wait for connection
    let t1 = pc1.wait_for_connected();
    let t2 = pc2.wait_for_connected();
    tokio::try_join!(t1, t2).expect("Failed to connect");

    // Start sending data from PC1
    let source_clone = source.clone();
    let _send_task = tokio::spawn(async move {
        let mut seq: u32 = 0;
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

    // Check if PC2 receives data
    let transceivers = pc2.get_transceivers();
    assert!(!transceivers.is_empty());
    let receiver = transceivers[0]
        .receiver()
        .expect("Expected receiver in transceiver")
        .clone();
    let track = receiver.track();

    // Verify received frame
    // We try to receive a few samples
    let sample = track.recv().await?;

    // Check if populated!
    match sample {
        MediaSample::Video(frame) => {
            // Check remote_addr
            assert!(
                frame.source_addr.is_some(),
                "remote_addr should be populated"
            );
            println!("Received from: {:?}", frame.source_addr);

            // Check raw_packet
            assert!(frame.raw_packet.is_some(), "raw_packet should be populated");
            let raw = frame.raw_packet.unwrap();

            // Verify payload (RTP packet payload match frame data if simple packetization)
            // Note: frame.data contains the payload (without header). raw.payload is also the payload.
            assert_eq!(raw.payload, frame.data, "Payload should match");

            println!(
                "Received RTP packet with Sequence Number: {}",
                raw.header.sequence_number
            );
        }
        _ => panic!("Expected Video frame"),
    }

    Ok(())
}
