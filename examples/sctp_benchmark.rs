use rustrtc::{PeerConnection, RtcConfiguration, SdpType, SessionDescription};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

// Run with: cargo run --release --example sctp_benchmark -- [bytes]
// Default bytes: 1GB (1073741824)

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args: Vec<String> = std::env::args().collect();
    let total_bytes = if args.len() > 1 {
        args[1].parse::<usize>().unwrap_or(1024 * 1024 * 1024)
    } else {
        1024 * 1024 * 1024 // 1GB
    };
    let chunk_size = 64 * 1024; // 64KB chunks

    println!("Starting SCTP Benchmark");
    println!(
        "Total Data: {} GB",
        total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!("Chunk Size: {} KB", chunk_size / 1024);

    // 1. Create PeerConnections
    let config = RtcConfiguration::default();
    let pc1 = PeerConnection::new(config.clone());
    let pc2 = PeerConnection::new(config);

    // 2. Create DataChannel on PC1
    let dc1 = pc1.create_data_channel(
        "benchmark",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    // 3. Create DataChannel on PC2 (negotiated)
    let dc2 = pc2.create_data_channel(
        "benchmark",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    // 4. Exchange SDP
    // PC1 creates offer
    let _ = pc1.create_offer().await?;
    // Wait for gathering to complete
    loop {
        if pc1.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let offer = pc1.create_offer().await?; // Re-create with candidates
    pc1.set_local_description(offer.clone())?;

    // PC2 receives offer
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &offer.to_sdp_string())?;
    pc2.set_remote_description(offer_sdp).await?;

    // PC2 creates answer
    let _ = pc2.create_answer().await?;
    // Wait for gathering
    loop {
        if pc2.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let answer = pc2.create_answer().await?; // Re-create with candidates
    pc2.set_local_description(answer.clone())?;

    // PC1 receives answer
    let answer_sdp = SessionDescription::parse(SdpType::Answer, &answer.to_sdp_string())?;
    pc1.set_remote_description(answer_sdp).await?;

    // Wait for connection
    println!("Waiting for connection...");
    pc1.wait_for_connected().await?;
    pc2.wait_for_connected().await?;
    println!("Connected!");

    // 5. Setup Receiver on DC2
    let done = Arc::new(Notify::new());
    let done_clone = done.clone();

    let start_time = Arc::new(tokio::sync::Mutex::new(None::<Instant>));
    let start_time_clone = start_time.clone();

    let received_bytes_total = Arc::new(AtomicU64::new(0));
    let received_bytes_clone = received_bytes_total.clone();

    let mut received_bytes = 0;
    let mut last_print = Instant::now();

    let dc2_clone = dc2.clone();

    tokio::spawn(async move {
        while let Some(msg) = dc2_clone.recv().await {
            if let rustrtc::DataChannelEvent::Message(data) = msg {
                if data.len() == 1 {
                    // EOF
                    done_clone.notify_one();
                    break;
                }

                let mut start = start_time_clone.lock().await;
                if start.is_none() {
                    *start = Some(Instant::now());
                    println!("First packet received, timer started.");
                }

                received_bytes += data.len();
                received_bytes_clone.store(received_bytes as u64, Ordering::Relaxed);

                if last_print.elapsed() >= Duration::from_secs(1) {
                    let mb = received_bytes as f64 / 1024.0 / 1024.0;
                    println!("Received: {:.2} MB", mb);
                    last_print = Instant::now();
                }
            }
        }
        // Notify done if channel closed or EOF received
        done_clone.notify_one();
    });

    // 6. Send Data from DC1
    println!("Sending data...");
    let data = vec![0u8; chunk_size];
    let mut sent_bytes = 0;

    // Wait a bit for everything to be ready
    tokio::time::sleep(Duration::from_secs(1)).await;

    let send_start = Instant::now();
    let max_duration = Duration::from_secs(10);

    while sent_bytes < total_bytes {
        if send_start.elapsed() >= max_duration {
            println!("Time limit reached (10s)");
            break;
        }

        // We need to handle backpressure or just blast it?
        // SCTP should handle flow control, but if we fill the buffer too fast we might get errors or block.
        // rustrtc's send might be async or blocking?
        // Let's check the API.
        match pc1.send_data(dc1.id, &data).await {
            Ok(_) => {
                sent_bytes += data.len();
            }
            Err(e) => {
                // If buffer is full, we might need to wait.
                // For now, let's just print error and break or retry.
                println!("Send error: {}", e);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    println!("Finished sending {} bytes", sent_bytes);
    // Send EOF
    let _ = pc1.send_data(dc1.id, &[0u8]).await;

    // Wait for receiver to finish
    done.notified().await;

    let duration = start_time.lock().await.unwrap().elapsed();
    let seconds = duration.as_secs_f64();
    let received_total = received_bytes_total.load(Ordering::Relaxed);
    let mb = received_total as f64 / 1024.0 / 1024.0;
    let throughput = mb / seconds;

    println!("\n------------------------------------------------");
    println!("Benchmark Results");
    println!("------------------------------------------------");
    println!("Total Data:          {:.2} MB", mb);
    println!("Time:                {:.2} s", seconds);
    println!("Throughput:          {:.2} MB/s", throughput);
    println!("------------------------------------------------");

    Ok(())
}
