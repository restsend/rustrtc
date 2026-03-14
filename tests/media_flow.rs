use anyhow::Result;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::{
    MediaKind, PeerConnection, RtcConfiguration, RtpCodecParameters, TransceiverDirection,
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_media_flow_and_pli() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // PC1: Publisher
    let config1 = RtcConfiguration::default();
    let pc1 = PeerConnection::new(config1);

    // PC2: Receiver (SFU)
    let config2 = RtcConfiguration::default();
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
    // Trigger gathering
    let _ = pc1.create_offer().await?;
    // Wait for gathering
    pc1.wait_for_gathering_complete().await;

    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;

    // 2. PC2 Create Answer
    // Trigger gathering
    let _ = pc2.create_answer().await?;
    // Wait for gathering
    pc2.wait_for_gathering_complete().await;

    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    // Wait for connection
    let t1 = pc1.wait_for_connected();
    let t2 = pc2.wait_for_connected();
    tokio::try_join!(t1, t2)?;

    println!("Connected!");

    // Start sending data from PC1
    let source_clone = source.clone();
    let send_task = tokio::spawn(async move {
        let mut seq = 0;
        loop {
            let frame = VideoFrame {
                rtp_timestamp: seq * 3000,
                data: bytes::Bytes::from(vec![0u8; 100]),
                is_last_packet: true,
                ..Default::default()
            };
            let sample = MediaSample::Video(frame);

            if source_clone.send(sample).await.is_err() {
                break;
            }
            seq += 1;
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
    });

    // Check if PC2 receives data
    let transceivers = pc2.get_transceivers();
    let receiver = transceivers[0].receiver().unwrap();
    let track_remote = receiver.track();

    // Read a few packets
    let mut received_packets = 0;

    let read_task = tokio::spawn(async move {
        while let Ok(_sample) = track_remote.recv().await {
            received_packets += 1;
            if received_packets >= 50 {
                break;
            }
        }
        received_packets
    });

    // Wait a bit
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Try to send PLI from PC2
    println!("Sending PLI...");
    receiver.request_key_frame().await?;

    // Wait more
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check if we are still receiving
    let count = read_task.await?;
    println!("Received {} packets", count);
    assert!(count >= 50);

    send_task.abort();

    Ok(())
}
