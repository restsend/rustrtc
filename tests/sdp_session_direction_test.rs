//! RFC 8866 §6.7 (RFC 4566 §6): a direction attribute at session level
//! applies to every media section that does not carry its own.
use rustrtc::sdp::{Direction, SdpType, SessionDescription};
use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection, TransportMode};

fn sdp(session_direction: Option<&str>, media_directions: &[Option<&str>]) -> String {
    let mut out = String::from("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
    if let Some(direction) = session_direction {
        out.push_str(&format!("a={direction}\r\n"));
    }
    for (port, direction) in media_directions.iter().enumerate() {
        out.push_str(&format!(
            "m=audio {} RTP/AVP 0\r\nc=IN IP4 127.0.0.1\r\na=rtpmap:0 PCMU/8000\r\n",
            40000 + 2 * port
        ));
        if let Some(direction) = direction {
            out.push_str(&format!("a={direction}\r\n"));
        }
    }
    out
}

fn directions(raw: &str) -> Vec<Direction> {
    SessionDescription::parse(SdpType::Offer, raw)
        .expect("parse")
        .media_sections
        .iter()
        .map(|section| section.direction)
        .collect()
}

#[test]
fn session_level_direction_applies_to_media_without_one() {
    for (attribute, direction) in [
        ("sendonly", Direction::SendOnly),
        ("recvonly", Direction::RecvOnly),
        ("inactive", Direction::Inactive),
        ("sendrecv", Direction::SendRecv),
    ] {
        assert_eq!(
            directions(&sdp(Some(attribute), &[None, None])),
            vec![direction, direction],
            "session-level a={attribute}"
        );
    }
}

#[test]
fn media_level_direction_overrides_session_level() {
    assert_eq!(
        directions(&sdp(Some("sendonly"), &[Some("sendrecv"), None])),
        vec![Direction::SendRecv, Direction::SendOnly]
    );
}

/// T.38 `m=image` sections inherit it like audio; SCTP data channels do not.
#[test]
fn image_sections_inherit_and_data_channels_do_not() {
    let raw = format!(
        "{}m=image 40002 udptl t38\r\na=T38FaxVersion:0\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=sctp-port:5000\r\n",
        sdp(Some("sendonly"), &[None])
    );
    assert_eq!(
        directions(&raw),
        vec![
            Direction::SendOnly,
            Direction::SendOnly,
            Direction::SendRecv
        ]
    );
}

#[test]
fn without_any_direction_media_is_sendrecv() {
    assert_eq!(
        directions(&sdp(None, &[None, Some("recvonly")])),
        vec![Direction::SendRecv, Direction::RecvOnly]
    );
}

#[test]
fn reparsing_our_serialization_keeps_the_direction() {
    let parsed =
        SessionDescription::parse(SdpType::Offer, &sdp(Some("inactive"), &[None])).expect("parse");
    assert_eq!(
        directions(&parsed.to_sdp_string()),
        vec![Direction::Inactive]
    );
}

/// A SIP peer holds the call with a session-level `a=sendonly`, in the
/// initial offer or in a re-INVITE: we answer `recvonly`, as for a
/// media-level hold, and `direction()` reads the remote's `sendonly`.
#[tokio::test]
async fn a_session_level_hold_is_answered_recvonly() {
    for initial in [Some("sendonly"), None] {
        let pc = PeerConnection::new(RtcConfiguration {
            transport_mode: TransportMode::Rtp,
            ..RtcConfiguration::default()
        });
        for session_direction in [initial, Some("sendonly")] {
            let raw = sdp(session_direction, &[None]);
            let offer = SessionDescription::parse(SdpType::Offer, &raw).expect("parse");
            pc.set_remote_description(offer)
                .await
                .expect("remote offer");
            let answer = pc.create_answer().await.expect("answer");
            let expected = match session_direction {
                Some(_) => Direction::RecvOnly,
                None => Direction::SendRecv,
            };
            assert_eq!(answer.media_sections[0].direction, expected);
            pc.set_local_description(answer).expect("local answer");
        }
        assert_eq!(
            pc.get_transceivers()[0].direction(),
            TransceiverDirection::SendOnly
        );
    }
}

/// A session-level direction in the remote answer is the answered direction.
#[tokio::test]
async fn a_session_level_direction_in_the_answer_applies() {
    let pc = PeerConnection::new(RtcConfiguration {
        transport_mode: TransportMode::Rtp,
        ..RtcConfiguration::default()
    });
    let t = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc.create_offer().await.expect("offer");
    pc.set_local_description(offer).expect("local offer");
    let raw = sdp(Some("recvonly"), &[None]).replace("PCMU/8000\r\n", "PCMU/8000\r\na=mid:0\r\n");
    let answer = SessionDescription::parse(SdpType::Answer, &raw).expect("parse");
    pc.set_remote_description(answer)
        .await
        .expect("remote answer");
    assert_eq!(t.direction(), TransceiverDirection::RecvOnly);
}
