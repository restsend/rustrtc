use rustrtc::RtcConfiguration;
use rustrtc::media::frame::{AudioFrame, MediaKind};
use rustrtc::media::track::sample_track;
use rustrtc::peer_connection::PeerConnection;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    // 1. Create PeerConnection
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // 2. Create a media track (Audio)
    let (source, track) = sample_track(MediaKind::Audio, 10);

    // 3. Add track to PeerConnection
    let _sender = pc.add_track(track).await.expect("failed to add track");

    println!("Track added, sender created.");

    // 4. Create Offer
    let _offer = pc.create_offer().await.expect("failed to create offer");
    println!("Offer created.");

    // 5. Send media
    tokio::spawn(async move {
        loop {
            let frame = AudioFrame {
                timestamp: Duration::from_millis(0),
                sample_rate: 48000,
                channels: 2,
                samples: 960,
                format: Default::default(),
                data: bytes::Bytes::from_static(&[0u8; 100]),
            };
            if let Err(e) = source.send_audio(frame).await {
                eprintln!("Failed to send audio: {:?}", e);
                break;
            }
            println!("Sent audio frame");
            sleep(Duration::from_millis(20)).await;
        }
    });

    // Keep alive
    sleep(Duration::from_secs(5)).await;
}
