#![cfg(feature = "std")]

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

        let ice_conn = IceConn::new(rx, receiver_addr, None);
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn, false));

        // 2. Create a track and source
        let (source, track, _) = sample_track(MediaKind::Audio, 10);

        // 3. Create RtpSender
        let params = RtpCodecParameters {
            payload_type: 111,
            name: "opus".to_string(),
            clock_rate: 48000,
            channels: 2,
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

        let ice_conn = IceConn::new(rx, receiver_addr, None);
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn, false));

        // 2. Create a track and source
        let (source, track, _) = sample_track(MediaKind::Video, 90000);

        // 3. Create RtpSender
        let params = RtpCodecParameters {
            payload_type: 96,
            name: "VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("stream".to_string())
            .params(params)
            .build();
        sender.set_transport(rtp_transport.clone());

        let mut buf = [0u8; 1500];

        // Sample 1: TS 1000
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                sequence_number: Some(0),
                rtp_timestamp: 1000,
                is_last_packet: false,
                data: Bytes::from_static(&[1]),
                ..rustrtc::media::frame::VideoFrame::default()
            })
            .unwrap();

        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet1 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let ts1 = packet1.header.timestamp;

        // Restart the sender loop between fragments, as after transport setup
        // changes. Video timing/numbering remains on the sender's timeline.
        sender.set_transport(rtp_transport);
        // Another locally packetized fragment: new sequence, same timestamp.
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                sequence_number: Some(1),
                rtp_timestamp: 1000,
                is_last_packet: true,
                data: Bytes::from_static(&[9]),
                ..Default::default()
            })
            .unwrap();
        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let fragment = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        assert_eq!(fragment.header.timestamp, ts1);
        assert_eq!(
            fragment.header.sequence_number,
            packet1.header.sequence_number.wrapping_add(1)
        );

        // Sample 2: TS 4000 (Delta 3000 - normal)
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                sequence_number: Some(2),
                rtp_timestamp: 4000,
                is_last_packet: true,
                data: Bytes::from_static(&[2]),
                ..rustrtc::media::frame::VideoFrame::default()
            })
            .unwrap();

        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet2 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let ts2 = packet2.header.timestamp;

        assert_eq!(ts2.wrapping_sub(ts1), 3000);

        // Sample 3: TS 1,000,000 (Large Jump - e.g. source switch)
        source
            .send_video(rustrtc::media::frame::VideoFrame {
                sequence_number: Some(3),
                rtp_timestamp: 1_000_000,
                is_last_packet: true,
                data: Bytes::from_static(&[3]),
                ..rustrtc::media::frame::VideoFrame::default()
            })
            .unwrap();

        let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let packet3 = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
        let ts3 = packet3.header.timestamp;

        // Expectation: the output timestamp does NOT jump by ~1,000,000; a
        // large packet timestamp gap reanchors after the shared cursor.
        assert!(ts3.wrapping_sub(ts2) >= 1800);
        assert!(ts3.wrapping_sub(ts2) < 90_000);

        let mut packetizer = rustrtc::media::H264Packetizer::new();
        let mut previous_seq = packet3.header.sequence_number;
        let mut first_ts = None;
        let mut nal = vec![0xab; 1800];
        nal[0] = 0x65;
        for _ in 0..2 {
            let timestamp = packetizer.timestamp();
            let fragments = packetizer.packetize_access_unit([nal.as_slice()], timestamp);
            assert_eq!(fragments.len(), 2);
            for (index, frame) in fragments.into_frames(640, 360).into_iter().enumerate() {
                source.send_video(frame).unwrap();
                let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
                let packet = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
                let header = packet.header;
                assert_eq!(header.sequence_number, previous_seq.wrapping_add(1));
                let base = *first_ts.get_or_insert(header.timestamp);
                assert_eq!(header.timestamp.wrapping_sub(base), timestamp);
                assert_eq!(header.marker, index == 1);
                previous_seq = header.sequence_number;
            }
            packetizer.advance();
        }
    }

    /// Samples continue right after relayed packets on the
    /// shared timeline, follow their producer-supplied duration, and a relayed packet
    /// after them continues the same space.
    #[tokio::test]
    async fn rtp_sender_timeline_mode_continues_relay_packets() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ice_conn = IceConn::new(rx, receiver_socket.local_addr().unwrap(), None);
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn, false));

        let (source, track, _) = sample_track(MediaKind::Audio, 10);
        let sender = RtpSender::builder(track, 777)
            .stream_id("stream".to_string())
            .params(RtpCodecParameters {
                payload_type: 0,
                name: "PCMU".to_string(),
                clock_rate: 8000,
                channels: 1,
            })
            .build();
        sender.set_transport(rtp_transport);

        // A relayed peer packet goes out first.
        let timeline = sender.timeline();
        let mut first = rustrtc::rtp::RtpPacket::new(
            rustrtc::rtp::RtpHeader::new(0, 10, 0, 0xB),
            Vec::new(),
        );
        timeline.write_peer(&mut first, 8000);

        let mut buf = [0u8; 1500];
        let mut recv = async |frame: AudioFrame| {
            source.send_audio(frame).unwrap();
            let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
            rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap()
        };
        let p1 = recv(AudioFrame {
            sequence_number: Some(40),
            rtp_timestamp: 9_000,
            data: Bytes::from_static(&[1; 160]),
            ..AudioFrame::default()
        })
        .await;
        assert_eq!(p1.header.ssrc, 777);
        assert_eq!(
            p1.header.sequence_number,
            first.header.sequence_number.wrapping_add(1)
        );
        assert!(p1.header.timestamp.wrapping_sub(first.header.timestamp) >= 160);
        let p2 = recv(AudioFrame {
            sequence_number: Some(41),
            rtp_timestamp: 999_999,
            data: Bytes::from_static(&[2; 160]),
            ..AudioFrame::default()
        })
        .await;
        assert_eq!(
            p2.header.sequence_number,
            p1.header.sequence_number.wrapping_add(1)
        );
        assert_eq!(p2.header.timestamp, p1.header.timestamp.wrapping_add(160));
        assert!(!p2.header.marker);
        assert_eq!(
            sender.next_sequence_number(),
            p2.header.sequence_number.wrapping_add(1)
        );

        // The relay resumes: it anchors right after the frames.
        let mut next = rustrtc::rtp::RtpPacket::new(
            rustrtc::rtp::RtpHeader::new(0, 5, 77, 0xC),
            Vec::new(),
        );
        timeline.write_peer(&mut next, 8000);
        assert_eq!(
            next.header.sequence_number,
            p2.header.sequence_number.wrapping_add(1)
        );
    }

    /// A transcoding leg: generated audio with the peer's DTMF event relayed
    /// in between (samples carrying their original RTP packet). Every packet
    /// of the event keeps one output timestamp; sequence numbers stay
    /// continuous across both kinds.
    #[tokio::test]
    async fn rtp_sender_keeps_one_timestamp_for_a_relayed_event_between_frames() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ice_conn = IceConn::new(rx, receiver_socket.local_addr().unwrap(), None);
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn, false));

        let (source, track, _) = sample_track(MediaKind::Audio, 10);
        let sender = RtpSender::builder(track, 777)
            .stream_id("stream".to_string())
            .params(RtpCodecParameters {
                payload_type: 0,
                name: "PCMU".to_string(),
                clock_rate: 8000,
                channels: 1,
            })
            .build();
        sender.set_transport(rtp_transport);

        let mut buf = [0u8; 1500];
        let mut recv = async |frame: AudioFrame| {
            source.send_audio(frame).unwrap();
            let (len, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
            rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap()
        };
        let audio = |ts: u32| AudioFrame {
            rtp_timestamp: ts,
            clock_rate: 8000,
            data: Bytes::from_static(&[0xFF; 160]),
            ..AudioFrame::default()
        };
        let event = |seq: u16| AudioFrame {
            rtp_timestamp: 96_000,
            clock_rate: 48_000,
            data: Bytes::from_static(&[5, 7, 0, 160]),
            sequence_number: Some(seq),
            payload_type: Some(101),
            // RFC 4733: the source marks the first packet of the event.
            marker: seq == 300,
            raw_packet: Some(rustrtc::rtp::RtpPacket::new(
                rustrtc::rtp::RtpHeader::new(101, seq, 96_000, 0xB),
                vec![5, 7, 0, 160],
            )),
            ..AudioFrame::default()
        };

        let a1 = recv(audio(0)).await;
        let e1 = recv(event(300)).await;
        let e2 = recv(event(302)).await;
        let e3 = recv(event(304)).await;
        let a2 = recv(audio(160)).await;
        let a3 = recv(audio(320)).await;

        let seqs: Vec<u16> = [&a1, &e1, &a2, &a3]
            .iter()
            .map(|p| p.header.sequence_number)
            .collect();
        assert_eq!(e1.header.sequence_number, a1.header.sequence_number.wrapping_add(1));
        assert_eq!(e2.header.sequence_number, e1.header.sequence_number.wrapping_add(2));
        assert_eq!(e3.header.sequence_number, e1.header.sequence_number.wrapping_add(4));
        assert_eq!(a2.header.sequence_number, e3.header.sequence_number.wrapping_add(1));
        assert_eq!(a3.header.sequence_number, a2.header.sequence_number.wrapping_add(1), "{seqs:?}");
        assert_eq!(e2.header.timestamp, e1.header.timestamp);
        assert_eq!(e3.header.timestamp, e1.header.timestamp);
        assert!(e1.header.marker, "the source's event-start marker is kept");
        assert!(!e2.header.marker && !e3.header.marker);
        assert_eq!(e1.header.payload_type, 101);
        assert!(a3.header.timestamp.wrapping_sub(a1.header.timestamp) < 0x8000_0000);
    }
    #[tokio::test]
    async fn forwarded_audio_and_video_preserve_packet_loss_and_reordering() {
        use rustrtc::media::MediaSample;
        use rustrtc::rtp::{RtpHeader, RtpPacket};
        for kind in [MediaKind::Audio, MediaKind::Video] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let transport = Arc::new(RtpTransport::new(
                IceConn::new(rx, receiver.local_addr().unwrap(), None), false,
            ));
            let (source, track, _) = sample_track(kind, 10);
            let clock = if kind == MediaKind::Audio { 8000 } else { 90000 };
            let sender = RtpSender::builder(track, 777)
                .params(RtpCodecParameters {
                    payload_type: 96, name: "test".into(), clock_rate: clock, channels: 1,
                })
                .build();
            sender.set_transport(transport);
            let mut packets = Vec::new();
            let mut buf = [0; 1500];
            for (seq, ts) in [(300, 9000), (303, 9480), (302, 9320), (304, 9480)] {
                let packet = RtpPacket::new(RtpHeader::new(96, seq, ts, 0xB), vec![1, 2, 3]);
                source.send(MediaSample::from_rtp_packet(
                    packet, kind, clock, "127.0.0.1:9000".parse().unwrap(),
                )).unwrap();
                let (len, _) = tokio::time::timeout(
                    std::time::Duration::from_secs(2), receiver.recv_from(&mut buf),
                ).await.unwrap().unwrap();
                packets.push(RtpPacket::parse(&buf[..len]).unwrap());
            }
            let first = &packets[0].header;
            for (packet, (seq_delta, ts_delta)) in packets.iter().zip([(0, 0), (3, 480), (2, 320), (4, 480)]) {
                assert_eq!(packet.header.sequence_number, first.sequence_number.wrapping_add(seq_delta));
                assert_eq!(packet.header.timestamp, first.timestamp.wrapping_add(ts_delta));
                assert_eq!(packet.header.ssrc, 777);
            }
        }
    }

    #[tokio::test]
    async fn repacketized_video_drops_stale_input_numbering() {
        use rustrtc::media::{MediaSample, MediaSource, TrackMediaSource};
        use rustrtc::media::packetizer::{Packetizer, Vp8Payloader};
        use rustrtc::rtp::{RtpHeader, RtpPacket};
        let (source, track, _) = sample_track(MediaKind::Video, 10);
        source.send(MediaSample::from_rtp_packet(
            RtpPacket::new(RtpHeader::new(96, 300, 9000, 0xB), vec![1; 100]),
            MediaKind::Video, 90000, "127.0.0.1:9000".parse().unwrap(),
        )).unwrap();
        let mut packetizer = Packetizer::new(
            Box::new(TrackMediaSource::new(track)), 51, Box::new(Vp8Payloader),
        );
        for (expected_seq, last) in [(0, false), (1, true)] {
            let MediaSample::Video(frame) = packetizer.next_sample().await.unwrap() else { panic!("video expected") };
            assert!(frame.raw_packet.is_none(), "new packets must not reuse old packet identity");
            assert_eq!(frame.sequence_number, Some(expected_seq));
            assert_eq!(frame.rtp_timestamp, 9000);
            assert_eq!(frame.is_last_packet, last);
        }
    }

    /// Generated audio steps by the sender timeline's configured `ptime` and
    /// negotiated clock rate, even for a codec unknown to rustrtc. Payload
    /// length and producer timestamp resets do not affect the step.
    #[tokio::test]
    async fn generated_audio_uses_configured_ptime_on_shared_timeline() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = Arc::new(RtpTransport::new(IceConn::new(rx, remote.local_addr().unwrap(), None), false));
        let (source, track, _) = sample_track(MediaKind::Audio, 10);
        let sender = RtpSender::builder(track, 777).params(RtpCodecParameters {
            payload_type: 110, name: "external-codec".into(), clock_rate: 8000, channels: 1,
        }).build();
        sender.set_transport(transport);
        let timeline = sender.timeline();
        let mut first = rustrtc::rtp::RtpPacket::new(
            rustrtc::rtp::RtpHeader::new(110, 30, 9000, 0xB),
            Vec::new(),
        );
        timeline.write_peer(&mut first, 8000);
        let mut previous = (first.header.sequence_number, first.header.timestamp);
        let mut buf = [0u8; 1500];
        for (ptime_ms, expected_ticks, clock, payload_len) in [
            (10, 80, 8000, 3),
            (30, 240, 48000, 1),
            (20, 160, 0, 300),
        ] {
            timeline.set_ptime(std::time::Duration::from_millis(ptime_ms));
            source.send_audio(AudioFrame {
                clock_rate: clock,
                rtp_timestamp: 0, sequence_number: Some(0),
                data: Bytes::from(vec![42; payload_len]), ..Default::default()
            }).unwrap();
            let (len, _) = tokio::time::timeout(std::time::Duration::from_secs(1), remote.recv_from(&mut buf)).await.unwrap().unwrap();
            let packet = rustrtc::rtp::RtpPacket::parse(&buf[..len]).unwrap();
            assert_eq!(packet.header.sequence_number, previous.0.wrapping_add(1));
            assert_eq!(packet.header.timestamp, previous.1.wrapping_add(expected_ticks));
            assert_eq!(packet.payload.len(), payload_len);
            previous = (packet.header.sequence_number, packet.header.timestamp);
        }
        let mut resumed = rustrtc::rtp::RtpPacket::new(
            rustrtc::rtp::RtpHeader::new(110, 1, 0, 0xC),
            Vec::new(),
        );
        timeline.write_peer(&mut resumed, 8000);
        assert_eq!(resumed.header.sequence_number, previous.0.wrapping_add(1));
        assert!((resumed.header.timestamp.wrapping_sub(previous.1) as i32) > 0);
        assert_eq!(sender.packets_sent(), 3);
        assert_eq!(sender.octets_sent(), 304);
    }

    #[tokio::test]
    async fn idle_sender_reports_external_sends_without_a_paced_frame() {
        use rustrtc::rtp::{RtcpPacket, parse_rtcp_packets};
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(Arc::new(socket))));
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = Arc::new(RtpTransport::new(IceConn::new(rx, remote.local_addr().unwrap(), None), false));
        let (_source, track, _) = sample_track(MediaKind::Audio, 10);
        let sender = RtpSender::builder(track, 777).params(RtpCodecParameters {
            payload_type: 0, name: "PCMU".into(), clock_rate: 8000, channels: 1,
        }).build();
        sender.set_transport(transport.clone());
        // Let the sender park with no samples and no traffic counted yet.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let mut pkt = rustrtc::rtp::RtpPacket::new(
            rustrtc::rtp::RtpHeader::new(0, 0, 0, 0),
            vec![0xFF; 160],
        );
        sender.timeline().write_frame(&mut pkt);
        let mapped_timestamp = pkt.header.timestamp;
        transport.send_rtp(pkt).await.unwrap();
        let report = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut buf = [0u8; 1500];
            loop {
                let (len, _) = remote.recv_from(&mut buf).await.unwrap();
                if buf[1] != 200 { continue; }
                for packet in parse_rtcp_packets(&buf[..len], None).unwrap() {
                    if let RtcpPacket::SenderReport(report) = packet { return report; }
                }
            }
        }).await.expect("external traffic must wake RTCP reporting without a sample");
        assert_eq!((report.sender_ssrc, report.packet_count, report.octet_count), (777, 1, 160));
        assert_eq!((sender.packets_sent(), sender.octets_sent()), (1, 160));
        assert!((report.rtp_timestamp.wrapping_sub(mapped_timestamp) as i32) >= 0);
    }

}
