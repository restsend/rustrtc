#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rustrtc::media::frame::{AudioFrame, MediaKind};
    use rustrtc::media::track::sample_track;
    use rustrtc::peer_connection::{RtpCodecParameters, RtpSender};
    use rustrtc::transports::ice::IceSocketWrapper;
    use rustrtc::transports::ice::conn::IceConn;
    use rustrtc::transports::rtp::RtpTransport;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::watch;

    #[tokio::test]
    async fn rtp_sender_rewrites_sequence_numbers() {
        // 1. Setup dummy transport
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(Arc::new(socket));
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        // Receiver socket to verify packets
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();

        let ice_conn = IceConn::new(rx, receiver_addr);
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn, false));

        // 2. Create a track and source
        let (source, track, _) = sample_track(MediaKind::Audio, 10);

        // 3. Create RtpSender
        let params = RtpCodecParameters {
            payload_type: 111,
            codec_name: "opus".to_string(),
            clock_rate: 48000,
            channels: 2,
            fmtp: Some("minptime=10;useinbandfec=1".to_string()),
            rtcp_fbs: Vec::new(),
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("stream".to_string())
            .params(params)
            .build();
        sender.set_transport(rtp_transport);

        // 4. Send samples with non-continuous sequence numbers
        let mut buf = [0u8; 1500];

        // Sample 1: Seq 100
        source
            .send_audio(AudioFrame {
                sequence_number: Some(100),
                data: Bytes::from_static(&[1, 2, 3]),
                ..AudioFrame::default()
            })
            .await
            .unwrap();

        // Receive Packet 1
        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet1 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let seq1 = packet1.header.sequence_number;

        // Sample 2: Seq 200 (Gap in source)
        source
            .send_audio(AudioFrame {
                sequence_number: Some(200),
                data: Bytes::from_static(&[4, 5, 6]),
                ..AudioFrame::default()
            })
            .await
            .unwrap();

        // Receive Packet 2
        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet2 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let seq2 = packet2.header.sequence_number;

        // Verify continuity
        assert_eq!(
            seq2,
            seq1.wrapping_add(1),
            "Sequence numbers should be continuous despite source gap"
        );
        assert_ne!(seq1, 100, "Sequence number should not match source");
    }

    #[tokio::test]
    async fn rtp_sender_rewrites_timestamps() {
        // 1. Setup dummy transport
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(Arc::new(socket));
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        // Receiver socket to verify packets
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();

        let ice_conn = IceConn::new(rx, receiver_addr);
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn, false));

        // 2. Create a track and source
        let (source, track, _) = sample_track(MediaKind::Video, 90000);

        // 3. Create RtpSender
        let params = RtpCodecParameters {
            payload_type: 96,
            codec_name: "VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
            fmtp: None,
            rtcp_fbs: Vec::new(),
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("stream".to_string())
            .params(params)
            .build();
        sender.set_transport(rtp_transport);

        let mut buf = [0u8; 1500];

        // Sample 1: TS 1000
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                rtp_timestamp: 1000,
                data: Bytes::from_static(&[1]),
                ..rustrtc::media::frame::VideoFrame::default()
            })
            .await
            .unwrap();

        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet1 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let ts1 = packet1.header.timestamp;

        // Sample 2: TS 4000 (Delta 3000 - normal)
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                rtp_timestamp: 4000,
                data: Bytes::from_static(&[2]),
                ..rustrtc::media::frame::VideoFrame::default()
            })
            .await
            .unwrap();

        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet2 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let ts2 = packet2.header.timestamp;

        assert_eq!(ts2.wrapping_sub(ts1), 3000);

        // Sample 3: TS 1,000,000 (Large Jump - e.g. source switch)
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                rtp_timestamp: 1_000_000,
                data: Bytes::from_static(&[3]),
                ..rustrtc::media::frame::VideoFrame::default()
            })
            .await
            .unwrap();

        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet3 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let ts3 = packet3.header.timestamp;

        // Expectation: The output timestamp should NOT jump by ~1,000,000.
        // It should continue from ts2 with a small delta (we hardcoded 3000 for jumps).
        // So ts3 should be approx ts2 + 3000.
        assert_eq!(ts3.wrapping_sub(ts2), 3000);
    }
}
