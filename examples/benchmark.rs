use indicatif::{ProgressBar, ProgressStyle};
use std::env;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::time::sleep;

// rustrtc imports
use rustrtc::media::MediaKind;
use rustrtc::media::track::sample_track;
use rustrtc::{DataChannelEvent, PeerConnection, PeerConnectionEvent, RtcConfiguration};

// webrtc imports
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

struct BenchResult {
    mode: String,
    duration: Duration,
    dc_latency: f64,
    bytes: u64,
    msgs: u64,
    cpu_usage: f64,
    memory_rss: u64,
}

impl BenchResult {
    fn print(&self) {
        println!("\n------------------------------------------------");
        println!("Benchmark Results ({})", self.mode);
        println!("------------------------------------------------");
        println!("Total Duration:      {:.2?}", self.duration);
        println!("Setup Latency:       {:.2} ms (avg)", self.dc_latency);
        println!(
            "Total Data:          {:.2} MB",
            self.bytes as f64 / 1024.0 / 1024.0
        );
        println!("Total Messages:      {}", self.msgs);
        println!("Throughput:          {:.2} MB/s", self.throughput());
        println!("Message Rate:        {:.2} msg/s", self.msg_rate());
        println!("Avg CPU Usage:       {:.2}%", self.cpu_usage);
        println!("Peak Memory RSS:     {} MB", self.memory_rss);
        println!("------------------------------------------------");
    }

    fn throughput(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            (self.bytes as f64 / 1024.0 / 1024.0) / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }

    fn msg_rate(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.msgs as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        println!("No arguments provided. Running comparison mode (count=10).");

        let exe = env::current_exe().expect("Failed to get current executable path");
        let mut results = Vec::new();

        println!("\nPausing for 3 seconds...");
        sleep(Duration::from_secs(3)).await;

        // Run webrtc in subprocess
        println!("\nRunning webrtc benchmark...");
        let webrtc_output = Command::new(&exe)
            .arg("webrtc")
            .arg("10")
            .output()
            .expect("Failed to run webrtc benchmark");

        let webrtc_stdout = String::from_utf8_lossy(&webrtc_output.stdout);
        println!("{}", webrtc_stdout);
        if let Some(res) = parse_output(&webrtc_stdout, "webrtc") {
            results.push(res);
        }

        println!("\nPausing for 3 seconds...");
        sleep(Duration::from_secs(3)).await;

        // Run rustrtc in subprocess
        println!("\nRunning rustrtc benchmark...");
        let rustrtc_output = Command::new(&exe)
            .arg("rustrtc")
            .arg("10")
            .output()
            .expect("Failed to run rustrtc benchmark");

        let rustrtc_stdout = String::from_utf8_lossy(&rustrtc_output.stdout);
        println!("{}", rustrtc_stdout);
        if let Some(res) = parse_output(&rustrtc_stdout, "rustrtc") {
            results.push(res);
        }

        // Check for Go and run Pion benchmark
        if check_go_installed() {
            println!("\nGo compiler found. Building and running Pion benchmark...");
            if let Some(pion_exe) = build_go_benchmark() {
                println!("\nPausing for 3 seconds...");
                sleep(Duration::from_secs(3)).await;
                println!("\nRunning Pion benchmark...");
                let pion_output = Command::new(&pion_exe)
                    .arg("10")
                    .output()
                    .expect("Failed to run Pion benchmark");

                let pion_stdout = String::from_utf8_lossy(&pion_output.stdout);
                println!("{}", pion_stdout);
                if let Some(res) = parse_output(&pion_stdout, "pion") {
                    results.push(res);
                }

                // Cleanup
                let _ = std::fs::remove_file(pion_exe);
            }
        } else {
            println!("\nGo compiler not found. Skipping Pion benchmark.");
        }

        if !results.is_empty() {
            print_comparison_table(&results);
            print_bar_charts(&results);
        }
    } else {
        let mode = args.get(1).map(|s| s.as_str()).unwrap();
        let count = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
        run_benchmark(mode, count).await.print();
    }
}

fn parse_output(output: &str, mode: &str) -> Option<BenchResult> {
    let mut duration = Duration::from_secs(0);
    let mut dc_latency = 0.0;
    let mut bytes = 0;
    let mut msgs = 0;
    let mut cpu_usage = 0.0;
    let mut memory_rss = 0;

    for line in output.lines() {
        if line.starts_with("Total Duration:") {
            // Format: Total Duration:      10.02s
            if let Some(val) = line.split_whitespace().nth(2) {
                // Remove 's'
                let s = val.trim_end_matches('s');
                if let Ok(secs) = s.parse::<f64>() {
                    duration = Duration::from_secs_f64(secs);
                }
            }
        } else if line.starts_with("Setup Latency:") {
            // Format: Setup Latency:       4.00 ms (avg)
            if let Some(val) = line.split_whitespace().nth(2) {
                if let Ok(v) = val.parse::<f64>() {
                    dc_latency = v;
                }
            }
        } else if line.starts_with("Total Data:") {
            // Format: Total Data:          1379.16 MB
            if let Some(val) = line.split_whitespace().nth(2) {
                if let Ok(v) = val.parse::<f64>() {
                    bytes = (v * 1024.0 * 1024.0) as u64;
                }
            }
        } else if line.starts_with("Total Messages:") {
            // Format: Total Messages:      1412263
            if let Some(val) = line.split_whitespace().nth(2) {
                if let Ok(v) = val.parse::<u64>() {
                    msgs = v;
                }
            }
        } else if line.starts_with("Avg CPU Usage:") {
            // Format: Avg CPU Usage:       842.49%
            if let Some(val) = line.split_whitespace().nth(3) {
                let s = val.trim_end_matches('%');
                if let Ok(v) = s.parse::<f64>() {
                    cpu_usage = v;
                }
            }
        } else if line.starts_with("Peak Memory RSS:") {
            // Format: Peak Memory RSS:     26 MB
            if let Some(val) = line.split_whitespace().nth(3) {
                if let Ok(v) = val.parse::<u64>() {
                    memory_rss = v;
                }
            }
        }
    }

    Some(BenchResult {
        mode: mode.to_string(),
        duration,
        dc_latency,
        bytes,
        msgs,
        cpu_usage,
        memory_rss,
    })
}

async fn run_benchmark(mode: &str, count: usize) -> BenchResult {
    println!("Starting benchmark: mode={}, count={}", mode, count);

    let (peak_rss, avg_cpu, cpu_samples, running) = start_resource_monitor();

    let start = Instant::now();
    let (dc_latency, bytes, msgs) = match mode {
        "rustrtc" => run_rustrtc(count).await,
        "webrtc" => run_webrtc(count).await,
        _ => panic!("Unknown mode. Use 'rustrtc' or 'webrtc'"),
    };
    let duration = start.elapsed();

    running.store(false, Ordering::Relaxed);

    let samples = cpu_samples.load(Ordering::Relaxed);
    let avg_cpu_val = if samples > 0 {
        avg_cpu.load(Ordering::Relaxed) as f64 / samples as f64 / 100.0
    } else {
        0.0
    };

    BenchResult {
        mode: mode.to_string(),
        duration,
        dc_latency,
        bytes,
        msgs,
        cpu_usage: avg_cpu_val,
        memory_rss: peak_rss.load(Ordering::Relaxed),
    }
}

fn start_resource_monitor() -> (
    Arc<AtomicU64>,
    Arc<AtomicU64>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
) {
    let pid = std::process::id();
    let peak_rss = Arc::new(AtomicU64::new(0));
    let avg_cpu = Arc::new(AtomicU64::new(0));
    let cpu_samples = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let peak_rss_clone = peak_rss.clone();
    let avg_cpu_clone = avg_cpu.clone();
    let cpu_samples_clone = cpu_samples.clone();
    let running_clone = running.clone();

    tokio::spawn(async move {
        while running_clone.load(Ordering::Relaxed) {
            let output = Command::new("ps")
                .args(&["-o", "rss,%cpu", "-p", &pid.to_string()])
                .output();

            if let Ok(output) = output {
                let s = String::from_utf8_lossy(&output.stdout);
                // Skip header
                if let Some(line) = s.lines().nth(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(rss) = parts[0].parse::<u64>() {
                            // RSS is in KB
                            let current_rss = rss / 1024; // MB
                            let peak = peak_rss_clone.load(Ordering::Relaxed);
                            if current_rss > peak {
                                peak_rss_clone.store(current_rss, Ordering::Relaxed);
                            }
                        }
                        if let Ok(cpu) = parts[1].parse::<f64>() {
                            let current_cpu = (cpu * 100.0) as u64; // Store as fixed point
                            avg_cpu_clone.fetch_add(current_cpu, Ordering::Relaxed);
                            cpu_samples_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    });

    (peak_rss, avg_cpu, cpu_samples, running)
}

fn check_go_installed() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn build_go_benchmark() -> Option<String> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let go_bench_dir = std::path::Path::new(&manifest_dir).join("examples/go_bench");
    let output_exe = std::path::Path::new(&manifest_dir).join("benchmark_go");

    let status = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&output_exe)
        .current_dir(&go_bench_dir)
        .status()
        .ok()?;

    if status.success() {
        Some(output_exe.to_string_lossy().to_string())
    } else {
        None
    }
}

fn print_comparison_table(results: &[BenchResult]) {
    if results.is_empty() {
        return;
    }

    // Find baseline (webrtc)
    let baseline = results
        .iter()
        .find(|r| r.mode == "webrtc")
        .unwrap_or(&results[0]);

    println!("\nComparison (Baseline: {})", baseline.mode);

    // Header
    print!("{:<20}", "Metric");
    for res in results {
        print!(" | {:<10}", res.mode);
    }
    println!();
    println!("{:-<80}", "");

    let metrics = [
        (
            "Duration (s)",
            Box::new(|r: &BenchResult| r.duration.as_secs_f64())
                as Box<dyn Fn(&BenchResult) -> f64>,
        ),
        (
            "Setup Latency (ms)",
            Box::new(|r: &BenchResult| r.dc_latency),
        ),
        (
            "Throughput (MB/s)",
            Box::new(|r: &BenchResult| r.throughput()),
        ),
        ("Msg Rate (msg/s)", Box::new(|r: &BenchResult| r.msg_rate())),
        ("CPU Usage (%)", Box::new(|r: &BenchResult| r.cpu_usage)),
        (
            "Memory (MB)",
            Box::new(|r: &BenchResult| r.memory_rss as f64),
        ),
    ];

    for (name, getter) in metrics.iter() {
        print!("{:<20}", name);
        for res in results {
            let val = getter(res);
            print!(" | {:<10.2}", val);
        }
        println!();
    }
    println!("{:-<80}", "");
}

fn print_bar_charts(results: &[BenchResult]) {
    println!("\nPerformance Charts");
    println!("==================");

    let metrics = [
        (
            "Throughput (MB/s)",
            true,
            Box::new(|r: &BenchResult| r.throughput()) as Box<dyn Fn(&BenchResult) -> f64>,
        ),
        (
            "Message Rate (msg/s)",
            true,
            Box::new(|r: &BenchResult| r.msg_rate()),
        ),
        (
            "Setup Latency (ms)",
            false,
            Box::new(|r: &BenchResult| r.dc_latency),
        ),
        (
            "CPU Usage (%)",
            false,
            Box::new(|r: &BenchResult| r.cpu_usage),
        ),
        (
            "Memory (MB)",
            false,
            Box::new(|r: &BenchResult| r.memory_rss as f64),
        ),
    ];

    for (name, higher_is_better, getter) in metrics.iter() {
        let remark = if *higher_is_better {
            "Higher is better"
        } else {
            "Lower is better"
        };
        println!("\n{} ({})", name, remark);
        let max_val = results.iter().map(|r| getter(r)).fold(0.0, f64::max);

        for res in results {
            let val = getter(res);
            let bar_len = if max_val > 0.0 {
                (val / max_val * 40.0) as usize
            } else {
                0
            };

            let color = match res.mode.as_str() {
                "rustrtc" => "\x1b[32m", // Green
                "webrtc" => "\x1b[34m",  // Blue
                "pion" => "\x1b[36m",    // Cyan
                _ => "\x1b[0m",
            };
            let reset = "\x1b[0m";

            let bar: String = std::iter::repeat("█").take(bar_len).collect();
            println!(
                "{:<10} | {}{:<40}{} {:.2}",
                res.mode, color, bar, reset, val
            );
        }
    }
    println!();
}

async fn run_rustrtc(count: usize) -> (f64, u64, u64) {
    let mut handles = vec![];
    let total_bytes = Arc::new(AtomicU64::new(0));
    let total_msgs = Arc::new(AtomicU64::new(0));
    let total_dc_latency = Arc::new(AtomicU64::new(0)); // in micros

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
        let total_bytes = total_bytes.clone();
        let total_msgs = total_msgs.clone();
        let total_dc_latency = total_dc_latency.clone();
        let pb = pb.clone();

        handles.push(tokio::spawn(async move {
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
            pc1.add_track(track, params).unwrap();

            let dc1 = pc1.create_data_channel("bench", None).unwrap();

            // Exchange SDP
            let offer = pc1.create_offer().unwrap();
            pc1.set_local_description(offer.clone()).unwrap();
            pc1.wait_for_gathering_complete().await;
            let offer = pc1.local_description().unwrap();

            pc2.set_remote_description(offer).await.unwrap();

            let answer = pc2.create_answer().unwrap();
            pc2.set_local_description(answer.clone()).unwrap();
            pc2.wait_for_gathering_complete().await;
            let answer = pc2.local_description().unwrap();

            pc1.set_remote_description(answer).await.unwrap();

            // Wait for connection
            if let Err(_) =
                tokio::time::timeout(Duration::from_secs(10), pc1.wait_for_connected()).await
            {
                // println!("Timeout waiting for pc1 connection");
                return;
            }
            if let Err(_) =
                tokio::time::timeout(Duration::from_secs(10), pc2.wait_for_connected()).await
            {
                // println!("Timeout waiting for pc2 connection");
                return;
            }

            // Wait for DC1 open
            let dc_wait_start = Instant::now();
            let mut dc1_open = false;
            while let Some(event) = dc1.recv().await {
                if let DataChannelEvent::Open = event {
                    dc1_open = true;
                    break;
                }
            }
            if !dc1_open {
                // println!("Failed to open data channel");
                pb.inc(1);
                return;
            }
            let dc_latency = dc_wait_start.elapsed().as_micros() as u64;
            total_dc_latency.fetch_add(dc_latency, Ordering::Relaxed);

            // Get DC2
            let mut dc2 = None;
            let start_wait = Instant::now();
            while start_wait.elapsed() < Duration::from_secs(5) {
                if let Ok(Some(event)) =
                    tokio::time::timeout(Duration::from_secs(1), pc2.recv()).await
                {
                    match event {
                        PeerConnectionEvent::DataChannel(dc) => {
                            dc2 = Some(dc);
                            break;
                        }
                        _ => {}
                    }
                }
            }

            if dc2.is_none() {
                // println!("Failed to get data channel");
                pb.inc(1); // Mark as done even if failed, to advance progress
                return;
            }
            let dc2 = dc2.unwrap();

            // Send data
            let data = vec![0u8; 1024]; // 1KB

            // Receiver loop
            let dc2_clone = dc2.clone();
            let total_bytes_clone = total_bytes.clone();
            let total_msgs_clone = total_msgs.clone();
            let done = Arc::new(Notify::new());
            let done_clone = done.clone();

            tokio::spawn(async move {
                loop {
                    if let Some(event) = dc2_clone.recv().await {
                        match event {
                            DataChannelEvent::Message(msg) => {
                                total_bytes_clone.fetch_add(msg.len() as u64, Ordering::Relaxed);
                                total_msgs_clone.fetch_add(1, Ordering::Relaxed);
                            }
                            DataChannelEvent::Close => {
                                break;
                            }
                            _ => {}
                        }
                    } else {
                        break;
                    }
                }
                done_clone.notify_one();
            });

            // Sender loop (10 seconds)
            let start_send = Instant::now();
            let duration = Duration::from_secs(10);
            while start_send.elapsed() < duration {
                if let Err(_) = pc1.send_data(dc1.id, &data).await {
                    break;
                }
            }

            // Close connections
            pc1.close();
            pc2.close();

            // Wait for receiver to finish (it will finish when channel closes)
            let _ = tokio::time::timeout(Duration::from_secs(5), done.notified()).await;
            pb.inc(1);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    pb.finish_with_message("Done");

    (
        total_dc_latency.load(Ordering::Relaxed) as f64 / count as f64 / 1000.0,
        total_bytes.load(Ordering::Relaxed),
        total_msgs.load(Ordering::Relaxed),
    )
}

async fn run_webrtc(count: usize) -> (f64, u64, u64) {
    let mut handles = vec![];
    let total_bytes = Arc::new(AtomicU64::new(0));
    let total_msgs = Arc::new(AtomicU64::new(0));
    let total_dc_latency = Arc::new(AtomicU64::new(0));

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
        let total_bytes = total_bytes.clone();
        let total_msgs = total_msgs.clone();
        let total_dc_latency = total_dc_latency.clone();
        let pb = pb.clone();

        handles.push(tokio::spawn(async move {
            let mut m1 = MediaEngine::default();
            m1.register_default_codecs().unwrap();
            let r1 = Registry::new();
            let api1 = APIBuilder::new()
                .with_media_engine(m1)
                .with_interceptor_registry(r1)
                .build();

            let mut m2 = MediaEngine::default();
            m2.register_default_codecs().unwrap();
            let r2 = Registry::new();
            let api2 = APIBuilder::new()
                .with_media_engine(m2)
                .with_interceptor_registry(r2)
                .build();

            let config = RTCConfiguration::default();
            let pc1 = api1.new_peer_connection(config.clone()).await.unwrap();
            let pc2 = api2.new_peer_connection(config).await.unwrap();

            // Add audio track
            let track = Arc::new(TrackLocalStaticSample::new(
                RTCRtpCodecCapability {
                    mime_type: "audio/opus".to_owned(),
                    ..Default::default()
                },
                "audio".to_string(),
                "webrtc-rs".to_string(),
            ));
            pc1.add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
                .await
                .unwrap();

            let dc1 = pc1.create_data_channel("bench", None).await.unwrap();

            let done = Arc::new(Notify::new());
            let done_clone = done.clone();
            let total_bytes_clone = total_bytes.clone();

            pc2.on_data_channel(Box::new(move |dc2| {
                let done_clone = done_clone.clone();
                let total_bytes_clone = total_bytes_clone.clone();
                let total_msgs_clone = total_msgs.clone();
                Box::pin(async move {
                    let done_clone2 = done_clone.clone();
                    dc2.on_message(Box::new(move |msg: DataChannelMessage| {
                        let total_bytes_clone = total_bytes_clone.clone();
                        let total_msgs_clone = total_msgs_clone.clone();
                        Box::pin(async move {
                            total_bytes_clone.fetch_add(msg.data.len() as u64, Ordering::Relaxed);
                            total_msgs_clone.fetch_add(1, Ordering::Relaxed);
                        })
                    }));
                    dc2.on_close(Box::new(move || {
                        let done_clone2 = done_clone2.clone();
                        Box::pin(async move {
                            done_clone2.notify_one();
                        })
                    }));
                })
            }));

            let offer = pc1.create_offer(None).await.unwrap();
            let mut gather_complete = pc1.gathering_complete_promise().await;
            pc1.set_local_description(offer.clone()).await.unwrap();
            let _ = gather_complete.recv().await;

            let offer = pc1.local_description().await.unwrap();

            pc2.set_remote_description(offer).await.unwrap();
            let answer = pc2.create_answer(None).await.unwrap();
            let mut gather_complete2 = pc2.gathering_complete_promise().await;
            pc2.set_local_description(answer.clone()).await.unwrap();
            let _ = gather_complete2.recv().await;

            let answer = pc2.local_description().await.unwrap();
            pc1.set_remote_description(answer).await.unwrap();

            // Wait for connection
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let tx = Arc::new(tx);
            let tx_clone = tx.clone();
            pc1.on_peer_connection_state_change(Box::new(move |s: webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState| {
                let tx_clone = tx_clone.clone();
                Box::pin(async move {
                    if s == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connected {
                        let _ = tx_clone.send(()).await;
                    }
                })
            }));
            let _ = rx.recv().await;

            // Wait for open
            let dc_wait_start = Instant::now();
            let (tx_open, mut rx_open) = tokio::sync::mpsc::channel(1);
            dc1.on_open(Box::new(move || {
                Box::pin(async move {
                    let _ = tx_open.send(()).await;
                })
            }));

            let _ = rx_open.recv().await;
            let dc_latency = dc_wait_start.elapsed().as_micros() as u64;
            total_dc_latency.fetch_add(dc_latency, Ordering::Relaxed);

            let data = bytes::Bytes::from(vec![0u8; 1024]);
            let start_send = Instant::now();
            while start_send.elapsed() < Duration::from_secs(10) {
                if let Err(_) = dc1.send(&data).await {
                    break;
                }
                // tokio::task::yield_now().await;
            }

            pc1.close().await.unwrap();
            pc2.close().await.unwrap();
            done.notified().await;
            pb.inc(1);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    pb.finish_with_message("Done");

    (
        total_dc_latency.load(Ordering::Relaxed) as f64 / count as f64 / 1000.0,
        total_bytes.load(Ordering::Relaxed),
        total_msgs.load(Ordering::Relaxed),
    )
}
