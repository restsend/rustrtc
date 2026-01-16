use indicatif::{ProgressBar, ProgressStyle};
use rustrtc::media::MediaKind;
use rustrtc::media::track::sample_track;
use rustrtc::{PeerConnection, RtcConfiguration};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    // You can enable tracing to debug if needed
    // tracing_subscriber::fmt::init();

    let count = 50;
    println!(
        "Running latency optimization test with {} iterations...",
        count
    );

    let mut latencies = Vec::with_capacity(count);

    let pb = ProgressBar::new(count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    for _ in 0..count {
        let latency = run_single_iteration().await;
        if let Some(l) = latency {
            latencies.push(l);
        }
        pb.inc(1);
    }
    pb.finish_with_message("Done");

    if latencies.is_empty() {
        println!("No successful connections.");
        return;
    }

    let sum: u128 = latencies.iter().sum();
    let avg = sum as f64 / latencies.len() as f64;
    let min = latencies.iter().min().unwrap();
    let max = latencies.iter().max().unwrap();

    println!("\nResults:");
    println!("  Count: {}", latencies.len());
    println!("  Avg:   {:.2} ms", avg);
    println!("  Min:   {} ms", min);
    println!("  Max:   {} ms", max);
}

async fn run_single_iteration() -> Option<u128> {
    let config = RtcConfiguration::default();
    let pc1 = PeerConnection::new(config.clone());
    let pc2 = PeerConnection::new(config);

    // Add audio track
    let (_source, track, _) = sample_track(MediaKind::Audio, 100);
    let params = rustrtc::RtpCodecParameters {
        payload_type: 111,
        clock_rate: 48000,
        channels: 2,
    };
    let _ = pc1.add_track(track, params);

    let _ = pc1.create_data_channel("bench", None);

    // Exchange SDP
    let offer = match pc1.create_offer().await {
        Ok(o) => o,
        Err(_) => return None,
    };
    if pc1.set_local_description(offer.clone()).is_err() {
        return None;
    }
    pc1.wait_for_gathering_complete().await;
    let offer = match pc1.local_description() {
        Some(o) => o,
        None => return None,
    };

    if pc2.set_remote_description(offer).await.is_err() {
        return None;
    }

    let answer = match pc2.create_answer().await {
        Ok(a) => a,
        Err(_) => return None,
    };
    if pc2.set_local_description(answer.clone()).is_err() {
        return None;
    }
    pc2.wait_for_gathering_complete().await;
    let answer = match pc2.local_description() {
        Some(a) => a,
        None => return None,
    };

    if pc1.set_remote_description(answer).await.is_err() {
        return None;
    }

    // Wait for connection
    let conn_start = Instant::now();

    let fut1 = pc1.wait_for_connected();
    let fut2 = pc2.wait_for_connected();

    let res = tokio::join!(
        tokio::time::timeout(Duration::from_secs(5), fut1),
        tokio::time::timeout(Duration::from_secs(5), fut2)
    );

    match res {
        (Ok(Ok(_)), Ok(Ok(_))) => {
            let latency = conn_start.elapsed().as_millis();

            // Cleanup
            pc1.close();
            pc2.close();

            Some(latency)
        }
        _ => {
            pc1.close();
            pc2.close();
            None
        }
    }
}
