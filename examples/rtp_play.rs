use async_trait::async_trait;
use rustrtc::media::{
    MediaError, MediaKind, MediaResult, MediaSample, MediaSource, Packetizer, VideoFrame,
    Vp8Payloader,
};
use rustrtc::{PeerConnection, RtcConfiguration, SdpType, SessionDescription, TransportMode};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::Interval;
use webrtc::media::io::ivf_reader::IVFReader;

#[tokio::main]
async fn main() {
    let target_addr = "127.0.0.1:5004";
    println!("RTP Sender started.");
    println!("Sending VP8 RTP to {}", target_addr);
    println!("Use the following SDP with ffplay:");
    println!("------------------------------------------------");
    println!("v=0");
    println!("o=- 0 0 IN IP4 127.0.0.1");
    println!("s=RustRTC RTP Example");
    println!("c=IN IP4 127.0.0.1");
    println!("t=0 0");
    println!("m=video 5004 RTP/AVP 96");
    println!("a=rtpmap:96 VP8/90000");
    println!("------------------------------------------------");
    println!("Command: ffplay -protocol_whitelist file,udp,rtp -i examples/rtp_play.sdp");

    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);

    let (sample_source, track, _) = rustrtc::media::sample_track(MediaKind::Video, 100);
    let params = rustrtc::RtpCodecParameters {
        payload_type: 96,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        channels: 0,
        fmtp: None,
        rtcp_fbs: Vec::new(),
    };
    pc.add_track(track, params).expect("failed to add track");

    let offer = pc.create_offer().await.expect("failed to create offer");
    pc.set_local_description(offer)
        .expect("failed to set local description");

    let remote_sdp_str = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=video 5004 RTP/AVP 96\r\n\
         a=rtpmap:96 VP8/90000\r\n"
    );
    let remote_sdp = SessionDescription::parse(SdpType::Answer, &remote_sdp_str)
        .expect("failed to parse remote sdp");
    pc.set_remote_description(remote_sdp)
        .await
        .expect("failed to set remote description");

    let file = File::open("examples/static/output.ivf").expect("failed to open output.ivf");
    let reader = BufReader::new(file);
    let (ivf, header) = IVFReader::new(reader).expect("failed to create IVF reader");

    let ivf_header = IvfHeader {
        width: header.width,
        height: header.height,
        num_frames: header.num_frames,
        timebase_numerator: header.timebase_numerator,
        timebase_denominator: header.timebase_denominator,
    };

    let last_timestamp = Arc::new(AtomicU32::new(0));
    let source = Box::new(IvfSource::new(ivf, ivf_header, 0, last_timestamp.clone()));

    let mut packetizer = Packetizer::new(source, 1200, Box::new(Vp8Payloader));

    loop {
        match packetizer.next_sample().await {
            Ok(sample) => {
                if let Err(e) = sample_source.send(sample).await {
                    eprintln!("Failed to send sample to track: {}", e);
                    break;
                }
            }
            Err(MediaError::EndOfStream) => {
                println!("End of stream");
                break;
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
                break;
            }
        }
    }
}

// --- Copied from echo_server.rs ---

struct IvfHeader {
    #[allow(unused)]
    width: u16,
    #[allow(unused)]
    height: u16,
    #[allow(unused)]
    num_frames: u32,
    timebase_numerator: u32,
    timebase_denominator: u32,
}

struct IvfSource {
    reader: IVFReader<BufReader<File>>,
    header: IvfHeader,
    interval: Interval,
    rtp_timestamp_offset: u32,
    last_timestamp_state: Arc<AtomicU32>,
}

impl IvfSource {
    fn new(
        reader: IVFReader<BufReader<File>>,
        header: IvfHeader,
        rtp_timestamp_offset: u32,
        last_timestamp_state: Arc<AtomicU32>,
    ) -> Self {
        let mut interval = tokio::time::interval(Duration::from_millis(33));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Self {
            reader,
            header,
            interval,
            rtp_timestamp_offset,
            last_timestamp_state,
        }
    }
}

#[async_trait]
impl MediaSource for IvfSource {
    fn id(&self) -> &str {
        "ivf-source"
    }
    fn kind(&self) -> MediaKind {
        MediaKind::Video
    }
    async fn next_sample(&mut self) -> MediaResult<MediaSample> {
        self.interval.tick().await;
        match self.reader.parse_next_frame() {
            Ok((frame, meta)) => {
                let timestamp_sec = meta.timestamp as f64 * self.header.timebase_numerator as f64
                    / self.header.timebase_denominator as f64;
                let rtp_samples = (timestamp_sec * 90000.0) as u32;
                let current_rtp_time = self.rtp_timestamp_offset.wrapping_add(rtp_samples);

                self.last_timestamp_state
                    .store(current_rtp_time, Ordering::SeqCst);

                let vf = VideoFrame {
                    rtp_timestamp: current_rtp_time,
                    data: frame.freeze(),
                    ..Default::default()
                };
                Ok(MediaSample::Video(vf))
            }
            Err(_) => Err(MediaError::EndOfStream),
        }
    }
}
