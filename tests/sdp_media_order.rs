#![cfg(feature = "std")]

use rustrtc::{
    MediaKind, PeerConnection, RtcConfiguration, SdpType, SessionDescription, SignalingState,
    TransceiverDirection,
};

#[tokio::test]
async fn sip_answers_keep_every_offered_m_line() {
    let offerer = PeerConnection::new(RtcConfiguration::sip());
    let answerer = PeerConnection::new(RtcConfiguration::sip());
    offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    offerer.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

    let offer = offerer.create_offer().await.unwrap();
    offerer.set_local_description(offer.clone()).unwrap();
    answerer.set_remote_description(offer).await.unwrap();
    let answer = answerer.create_answer().await.unwrap();

    let mut missing_audio = answer.clone();
    missing_audio.media_sections.remove(0);
    missing_audio.session.attributes.retain(|attr| attr.key != "group");
    let mut extra_video = answer.clone();
    extra_video.media_sections.push(answer.media_sections[1].clone());

    for invalid in [missing_audio, extra_video] {
        assert!(answerer.set_local_description(invalid.clone()).is_err());
        assert_eq!(answerer.signaling_state(), SignalingState::HaveRemoteOffer);
        assert!(offerer.set_remote_description(invalid).await.is_err());
        assert_eq!(offerer.signaling_state(), SignalingState::HaveLocalOffer);
    }

    answerer.set_local_description(answer.clone()).unwrap();
    offerer.set_remote_description(answer).await.unwrap();
    offerer.close();
    answerer.close();
}

#[tokio::test]
async fn sip_treats_omitted_video_as_a_rejected_slot() {
    for (kinds, omitted) in [
        ([MediaKind::Audio, MediaKind::Video], true),
        ([MediaKind::Video, MediaKind::Audio], true),
        ([MediaKind::Audio, MediaKind::Video], false),
    ] {
        let offerer = PeerConnection::new(RtcConfiguration::sip());
        let answerer = PeerConnection::new(RtcConfiguration::sip());
        for kind in kinds {
            offerer.add_transceiver(kind, TransceiverDirection::SendRecv);
        }
        let offer = offerer.create_offer().await.unwrap();
        offerer.set_local_description(offer.clone()).unwrap();
        answerer.set_remote_description(offer).await.unwrap();
        let mut answer = answerer.create_answer().await.unwrap();
        let video_index = kinds.iter().position(|kind| *kind == MediaKind::Video).unwrap();
        if omitted {
            answer.media_sections.remove(video_index);
            assert!(answerer.set_local_description(answer.clone()).is_err());
        } else {
            answer.session.attributes.retain(|attr| attr.key != "group");
            answer.media_sections[video_index].port = 0;
            answer.media_sections[video_index].formats.clear();
        }
        let answer = SessionDescription::parse(SdpType::Answer, &answer.to_sdp_string()).unwrap();
        offerer.set_remote_description(answer).await.unwrap();

        let remote = offerer.remote_description().unwrap();
        assert_eq!(remote.media_sections.len(), kinds.len());
        assert_eq!(remote.media_sections[video_index].kind, MediaKind::Video);
        assert!(remote.is_media_rejected(&remote.media_sections[video_index]));
        assert_ne!(remote.media_sections[1 - video_index].port, 0);
        if omitted {
            let audio_mid = &remote.media_sections[1 - video_index].mid;
            assert!(remote.session.attributes.iter().any(|attr| {
                attr.key == "group" && attr.value.as_deref() == Some(&format!("BUNDLE {audio_mid}"))
            }));
        }
        assert_eq!(offerer.signaling_state(), SignalingState::Stable);
        let reoffer = offerer.create_offer().await.unwrap();
        let reoffered_video = &reoffer.media_sections[video_index];
        assert_eq!(reoffered_video.kind, MediaKind::Video);
        assert_eq!(reoffered_video.mid, remote.media_sections[video_index].mid);
        assert!(!reoffer.is_media_rejected(reoffered_video));
        offerer.close();
        answerer.close();
    }
}

#[tokio::test]
async fn webrtc_answers_preserve_same_kind_mids_in_offered_order() {
    let offerer = PeerConnection::new(RtcConfiguration::webrtc());
    let answerer = PeerConnection::new(RtcConfiguration::webrtc());
    for _ in 0..2 {
        offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    }

    let offer = offerer.create_offer().await.unwrap();
    offerer.set_local_description(offer.clone()).unwrap();
    answerer.set_remote_description(offer).await.unwrap();
    let answer = answerer.create_answer().await.unwrap();
    let mut reordered = answer.clone();
    reordered.media_sections.swap(0, 1);

    assert!(answerer.set_local_description(reordered.clone()).is_err());
    assert!(offerer.set_remote_description(reordered).await.is_err());
    answerer.set_local_description(answer.clone()).unwrap();
    offerer.set_remote_description(answer).await.unwrap();
    offerer.close();
    answerer.close();
}

#[tokio::test]
async fn sip_answer_keeps_bundle_tag_separate_from_m_line_order() {
    let answerer = PeerConnection::new(RtcConfiguration::sip());
    let offer = SessionDescription::parse(
        SdpType::Offer,
        "v=0\r\n\
         o=- 1 1 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         c=IN IP4 127.0.0.1\r\n\
         a=group:BUNDLE video audio\r\n\
         m=audio 0 RTP/AVP 111\r\n\
         a=mid:audio\r\n\
         a=bundle-only\r\n\
         a=rtpmap:111 opus/48000/2\r\n\
         m=video 5002 RTP/AVP 96\r\n\
         a=mid:video\r\n\
         a=rtcp-mux\r\n\
         a=rtpmap:96 VP8/90000\r\n",
    )
    .unwrap();
    answerer.set_remote_description(offer).await.unwrap();
    let answer = answerer.create_answer().await.unwrap();

    let [audio, video] = answer.media_sections.as_slice() else {
        panic!("expected audio and video m-lines");
    };
    assert_eq!((audio.mid.as_str(), video.mid.as_str()), ("audio", "video"));
    assert_ne!(audio.port, 0);
    assert_eq!(audio.port, video.port);
    assert!(answer.session.attributes.iter().any(|attr| {
        attr.key == "group" && attr.value.as_deref() == Some("BUNDLE video audio")
    }));
    answerer.set_local_description(answer).unwrap();
    let pair = answerer.ice_transport().get_selected_pair().unwrap();
    assert_eq!(pair.remote.address.port(), 5002);
    answerer.close();
}

#[tokio::test]
async fn sdes_bundle_uses_the_video_tag_for_startup_and_rekey() {
    use base64::prelude::*;
    use bytes::BytesMut;
    use rustrtc::rtp::{RtpHeader, RtpPacket};
    use rustrtc::srtp::SrtpPacket;
    use rustrtc::{Keying, SrtpKeyingMaterial, SrtpProfile, SrtpSession};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, timeout};

    let mut config = RtcConfiguration::sip();
    config.keying = Keying::Sdes;
    config.bind_ips = vec!["127.0.0.1".parse().unwrap()];
    let answerer = PeerConnection::new(config);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let video_port = peer.local_addr().unwrap().port();
    let audio_key = BASE64_STANDARD.encode([0x11; 30]);
    let video_key = BASE64_STANDARD.encode([0x22; 30]);
    let offer = format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         c=IN IP4 127.0.0.1\r\n\
         a=group:BUNDLE video audio\r\n\
         m=audio 5000 RTP/SAVP 111\r\n\
         a=mid:audio\r\n\
         a=rtpmap:111 opus/48000/2\r\n\
         a=rtcp-mux\r\n\
         a=crypto:3 AES_CM_128_HMAC_SHA1_32 inline:{audio_key}\r\n\
         m=video {video_port} RTP/SAVP 96\r\n\
         a=mid:video\r\n\
         a=rtpmap:96 VP8/90000\r\n\
         a=rtcp-mux\r\n\
         a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:{video_key}\r\n",
    );
    answerer
        .set_remote_description(SessionDescription::parse(SdpType::Offer, &offer).unwrap())
        .await
        .unwrap();
    let answer = answerer.create_answer().await.unwrap();
    assert!(answer.media_sections[0].get_crypto_attributes().is_empty());
    let crypto = answer.media_sections[1].get_crypto_attributes().pop().unwrap();
    assert_eq!(crypto.tag, 7);
    assert_eq!(crypto.crypto_suite, "AES_CM_128_HMAC_SHA1_80");
    let key_bytes = BASE64_STANDARD
        .decode(crypto.key_params.strip_prefix("inline:").unwrap())
        .unwrap();
    let answer_key = SrtpKeyingMaterial::new(key_bytes[..16].to_vec(), key_bytes[16..].to_vec());
    answerer.set_local_description(answer).unwrap();
    timeout(Duration::from_secs(2), answerer.wait_for_connected())
        .await
        .unwrap()
        .unwrap();

    let packet = RtpPacket::new(RtpHeader::new(96, 1, 9000, 321), vec![1, 2, 3]);
    answerer.send_raw_rtp(packet.clone()).await.unwrap();
    let mut received = [0; 1500];
    let size = timeout(Duration::from_secs(2), peer.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    let mut remote = SrtpSession::new(
        SrtpProfile::Aes128Sha1_80,
        answer_key.clone(),
        answer_key.clone(),
    )
    .unwrap();
    let protected = SrtpPacket::parse(BytesMut::from(&received[..size])).unwrap();
    assert_eq!(remote.unprotect_rtp(protected).unwrap().payload, packet.payload);

    let reoffer = offer
        .replace("o=- 1 1", "o=- 1 2")
        .replace(&video_key, &BASE64_STANDARD.encode([0x33; 30]));
    answerer
        .set_remote_description(SessionDescription::parse(SdpType::Offer, &reoffer).unwrap())
        .await
        .unwrap();
    let answer = answerer.create_answer().await.unwrap();
    let local_port = answer.media_sections[1].port;
    assert_eq!(answer.media_sections[1].get_crypto_attributes(), [crypto]);
    answerer.set_local_description(answer).unwrap();

    let rotated_key = SrtpKeyingMaterial::new(vec![0x33; 16], vec![0x33; 14]);
    let mut remote = SrtpSession::new(SrtpProfile::Aes128Sha1_80, rotated_key, answer_key).unwrap();
    let mut protected = vec![0; remote.protected_rtp_len(&packet)];
    remote.protect_rtp(&packet, &mut protected).unwrap();
    peer.send_to(&protected, ("127.0.0.1", local_port)).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while answerer.received_rtp_packets() == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the rotated key on the video tag must authenticate inbound media");
    answerer.close();
}
