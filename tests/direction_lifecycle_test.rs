#![cfg(feature = "std")]

//! Direction-semantics regression tests — locks in the fixes from PRs #41/#44/#45:
//!
//! - answers intersect the offered direction with our own intent
//!   (`set_direction`), they never merely mirror the offer (RFC 3264 §6.1,
//!   RFC 8829 §5.3.1);
//! - session-level direction attributes are inherited by media sections that
//!   do not state their own (RFC 8866 §6.7), and that inheritance composes
//!   with the answer-intersection rule through the real parse path;
//! - a full SIP hold/resume lifecycle keeps every transition on the direction
//!   we asked for (`direction()` reflects the negotiated state after each
//!   answer, `set_direction` re-arms our intent for the next offer);
//! - `restart_ice` does not disturb the negotiated direction intent.
#![allow(clippy::field_reassign_with_default)]
use rustrtc::sdp::{
    Attribute, Direction, MediaSection, SdpType, SessionDescription, SessionSection,
};
use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection, TransportMode};

fn dir_str(direction: Direction) -> &'static str {
    match direction {
        Direction::SendRecv => "sendrecv",
        Direction::SendOnly => "sendonly",
        Direction::RecvOnly => "recvonly",
        Direction::Inactive => "inactive",
    }
}

fn as_trans(direction: Direction) -> TransceiverDirection {
    match direction {
        Direction::SendRecv => TransceiverDirection::SendRecv,
        Direction::SendOnly => TransceiverDirection::SendOnly,
        Direction::RecvOnly => TransceiverDirection::RecvOnly,
        Direction::Inactive => TransceiverDirection::Inactive,
    }
}

/// Minimal single-audio-section SDP (in-memory form, no session attribute).
fn minimal_sdp(sdp_type: SdpType, mid: &str, direction: Direction) -> SessionDescription {
    let mut desc = SessionDescription::new(sdp_type);
    desc.session = SessionSection::default();

    let mut section = MediaSection::new(MediaKind::Audio, mid);
    section.direction = direction;
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some("111 opus/48000/2".to_string()),
    ));
    section
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    desc.media_sections.push(section);
    desc
}

/// Raw SDP text with a session-level direction attribute — mirrors how SIP
/// UAs signal a hold (RFC 8866 §6.7). Built as text so the parse path
/// (attribute inheritance) is exercised for real.
fn session_level_sdp(session_direction: Direction) -> String {
    format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         a={}\r\n\
         m=audio 40000 RTP/AVP 0 111\r\n\
         c=IN IP4 127.0.0.1\r\n\
         a=rtpmap:111 opus/48000/2\r\n",
        dir_str(session_direction)
    )
}

fn rtp_pc_with_audio_sender() -> PeerConnection {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);
    let (_source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::MediaKind::Audio, 10);
    let params = RtpCodecParameters {
        payload_type: 111,
        name: "opus".to_string(),
        clock_rate: 48000,
        channels: 2,
    };
    pc.add_track(track, params).unwrap();
    pc
}

use rustrtc::RtpCodecParameters;

/// The complete SIP hold dance driven by OUR side. `direction()` reflects the
/// negotiated state after each answer, while `set_direction` re-arms our
/// intent for the next offer — both must land exactly where we ask.
#[tokio::test]
async fn hold_resume_lifecycle_we_initiate() {
    let pc = rtp_pc_with_audio_sender();

    // 1. Establish sendrecv.
    let offer = pc.create_offer().await.unwrap();
    assert_eq!(offer.media_sections[0].direction, Direction::SendRecv);
    pc.set_local_description(offer.clone()).unwrap();
    let answer = minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    pc.set_remote_description(answer).await.unwrap();
    assert_eq!(
        pc.get_transceivers()[0].direction(),
        as_trans(Direction::SendRecv)
    );

    // 2. WE hold: set_direction(SendOnly) → our offer must be sendonly.
    pc.get_transceivers()[0].set_direction(TransceiverDirection::SendOnly);
    assert_eq!(
        pc.get_transceivers()[0].direction(),
        as_trans(Direction::SendOnly)
    );
    let hold_offer = pc.create_offer().await.unwrap();
    assert_eq!(
        hold_offer.media_sections[0].direction,
        Direction::SendOnly,
        "our hold offer must be sendonly"
    );
    pc.set_local_description(hold_offer).unwrap();
    // Remote accepts our hold by answering recvonly (it only listens) — the
    // negotiated direction is now recvonly.
    let hold_answer = minimal_sdp(SdpType::Answer, "0", Direction::RecvOnly);
    pc.set_remote_description(hold_answer).await.unwrap();
    assert_eq!(
        pc.get_transceivers()[0].direction(),
        as_trans(Direction::RecvOnly),
        "negotiated direction follows the remote's answer"
    );

    // 3. WE resume: set_direction(SendRecv) → our offer must be sendrecv.
    pc.get_transceivers()[0].set_direction(TransceiverDirection::SendRecv);
    let resume_offer = pc.create_offer().await.unwrap();
    assert_eq!(
        resume_offer.media_sections[0].direction,
        Direction::SendRecv,
        "our resume offer must be sendrecv"
    );
    pc.set_local_description(resume_offer).unwrap();
    let resume_answer = minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    pc.set_remote_description(resume_answer).await.unwrap();
    assert_eq!(
        pc.get_transceivers()[0].direction(),
        as_trans(Direction::SendRecv)
    );
}

/// #45 ∘ #44 composition through the real parse path: a session-level
/// `a=sendonly` hold from the remote is inherited by the media section during
/// parse, and our answer intersects it with our own intent. With no local
/// preference the natural answer to a sendonly offer is recvonly; with
/// `set_direction(Inactive)` it is inactive.
#[tokio::test]
async fn session_level_hold_intersects_with_local_intent() {
    for (desired, expected) in [
        (None, Direction::RecvOnly),
        (Some(TransceiverDirection::RecvOnly), Direction::RecvOnly),
        (Some(TransceiverDirection::Inactive), Direction::Inactive),
        (Some(TransceiverDirection::SendRecv), Direction::RecvOnly),
    ] {
        let pc = rtp_pc_with_audio_sender();
        // Session-level hold from the remote (SIP UA convention) — parse it.
        let offer =
            SessionDescription::parse(SdpType::Offer, &session_level_sdp(Direction::SendOnly))
                .unwrap();
        assert_eq!(
            offer.media_sections[0].direction,
            Direction::SendOnly,
            "session-level a=sendonly must apply to the media section"
        );
        pc.set_remote_description(offer).await.unwrap();
        if let Some(desired) = desired {
            pc.get_transceivers()[0].set_direction(desired);
        }
        let answer = pc.create_answer().await.unwrap();
        assert_eq!(
            answer.media_sections[0].direction, expected,
            "desired={desired:?} must intersect the offered sendonly"
        );
        pc.set_local_description(answer).unwrap();
    }
}

/// After answering a remote session-level hold, our next offer (re-INVITE
/// without SDP) must carry OUR direction and must not re-serialize the
/// remote's session-level sendonly into the media section.
#[tokio::test]
async fn reoffer_after_session_level_hold_carries_local_direction() {
    let pc = rtp_pc_with_audio_sender();
    let offer =
        SessionDescription::parse(SdpType::Offer, &session_level_sdp(Direction::SendOnly)).unwrap();
    pc.set_remote_description(offer).await.unwrap();
    let answer = pc.create_answer().await.unwrap();
    assert_eq!(answer.media_sections[0].direction, Direction::RecvOnly);
    pc.set_local_description(answer).unwrap();

    // Re-INVITE without SDP: we did not initiate the hold, so our offer is
    // sendrecv (an attempt to resume) — it must never echo the remote's
    // sendonly (that would tell the remote that WE hold IT).
    let reoffer = pc.create_offer().await.unwrap();
    assert_eq!(
        reoffer.media_sections[0].direction,
        Direction::SendRecv,
        "re-offer must carry our own sendrecv intent, not the remote's sendonly"
    );
    // And the serialized offer states the direction at media level, so the
    // session-level attribute of the remote's old offer cannot leak back.
    let serialized = reoffer.to_sdp_string();
    let media_section_has_direction =
        serialized
            .lines()
            .skip_while(|l| !l.starts_with("m="))
            .any(|l| {
                l.starts_with("a=sendonly")
                    || l.starts_with("a=recvonly")
                    || l.starts_with("a=sendrecv")
                    || l.starts_with("a=inactive")
            });
    assert!(
        media_section_has_direction,
        "serialized offer must state direction at media level:\n{serialized}"
    );
}

/// `restart_ice` re-rolls credentials but must not disturb the negotiated
/// direction intent: the restart offer keeps sendrecv.
#[tokio::test]
async fn restart_ice_preserves_direction_intent() {
    let pc = PeerConnection::new(RtcConfiguration::default());
    pc.create_data_channel("dir", None).unwrap();

    // Establish a stable session first (Stable state is required for
    // restart_ice). The hand-written answer needs the WebRTC-mode mandatory
    // attributes: DTLS fingerprint + setup + ICE credentials.
    let offer = pc.create_offer().await.unwrap();
    assert_eq!(offer.media_sections[0].direction, Direction::SendRecv);
    pc.set_local_description(offer.clone()).unwrap();

    let mut answer = minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    answer.session.attributes.push(Attribute::new(
        "fingerprint",
        Some("sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF".to_string()),
    ));
    answer
        .session
        .attributes
        .push(Attribute::new("setup", Some("active".to_string())));
    answer
        .session
        .attributes
        .push(Attribute::new("ice-ufrag", Some("answerufrag".to_string())));
    answer.session.attributes.push(Attribute::new(
        "ice-pwd",
        Some("answerpwdanswerpwdanswerpwd".to_string()),
    ));
    answer.media_sections[0]
        .attributes
        .push(Attribute::new("setup", Some("active".to_string())));
    pc.set_remote_description(answer).await.unwrap();
    assert_eq!(pc.signaling_state(), rustrtc::SignalingState::Stable);

    let ufrag_before = offer
        .session
        .attributes
        .iter()
        .find(|a| a.key == "ice-ufrag")
        .and_then(|a| a.value.clone())
        .or_else(|| {
            offer.media_sections[0]
                .attributes
                .iter()
                .find(|a| a.key == "ice-ufrag")
                .and_then(|a| a.value.clone())
        })
        .unwrap();

    pc.restart_ice().await.unwrap();
    let restart_offer = pc.create_offer().await.unwrap();

    let ufrag_after = restart_offer
        .session
        .attributes
        .iter()
        .find(|a| a.key == "ice-ufrag")
        .and_then(|a| a.value.clone())
        .or_else(|| {
            restart_offer.media_sections[0]
                .attributes
                .iter()
                .find(|a| a.key == "ice-ufrag")
                .and_then(|a| a.value.clone())
        })
        .unwrap();
    assert_ne!(ufrag_before, ufrag_after, "restart must rotate ice-ufrag");
    assert_eq!(
        restart_offer.media_sections[0].direction,
        Direction::SendRecv,
        "restart offer must preserve the negotiated direction"
    );
}

/// The direction a fresh senderless transceiver offers: created by a remote
/// offer (and answered) or locally as recvonly, then `set` if given.
async fn senderless_offer(
    mode: TransportMode,
    kind: MediaKind,
    from_remote: bool,
    set: Option<TransceiverDirection>,
) -> Direction {
    let config = || RtcConfiguration {
        transport_mode: mode.clone(),
        ..RtcConfiguration::default()
    };
    let pc = PeerConnection::new(config());
    if from_remote {
        let remote = PeerConnection::new(config());
        remote.add_transceiver(kind, TransceiverDirection::RecvOnly);
        pc.set_remote_description(remote.create_offer().await.unwrap())
            .await
            .unwrap();
        let answer = pc.create_answer().await.unwrap();
        pc.set_local_description(answer).unwrap();
    } else {
        pc.add_transceiver(kind, TransceiverDirection::RecvOnly);
    }
    let t = pc.get_transceivers()[0].clone();
    if let Some(set) = set {
        t.set_direction(set);
        assert_eq!(t.direction(), set);
    }
    pc.create_offer().await.unwrap().media_sections[0].direction
}

/// A direction the application sets is offered as is, with or without a
/// sender (RFC 8829 §4.2.3), whichever side created the transceiver. Only a
/// transceiver created by a remote offer and never configured waits for a
/// sender before it offers to send.
#[tokio::test]
async fn set_direction_is_offered_without_a_sender() {
    use TransceiverDirection as TD;
    for mode in [
        TransportMode::Rtp,
        TransportMode::Srtp,
        TransportMode::WebRtc,
    ] {
        for kind in [MediaKind::Audio, MediaKind::Video] {
            for (from_remote, set, expected) in [
                (false, Some(TD::SendRecv), Direction::SendRecv),
                (false, Some(TD::SendOnly), Direction::SendOnly),
                (true, Some(TD::SendRecv), Direction::SendRecv),
                (true, Some(TD::SendOnly), Direction::SendOnly),
                (true, None, Direction::RecvOnly),
            ] {
                let offered = senderless_offer(mode.clone(), kind, from_remote, set).await;
                assert_eq!(
                    offered, expected,
                    "{mode:?} {kind:?} from_remote={from_remote} set={set:?}"
                );
            }
        }
    }
}

/// A local offer whose direction the application rewrote becomes its
/// preference for a senderless transceiver too, once that direction is its own.
#[tokio::test]
async fn rewritten_offer_direction_is_adopted_without_a_sender() {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);
    let t = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
    t.set_direction(TransceiverDirection::SendRecv);
    let mut offer = pc.create_offer().await.unwrap();
    offer.media_sections[0].direction = Direction::RecvOnly;
    pc.set_local_description(offer).unwrap();
    let answer = minimal_sdp(SdpType::Answer, "0", Direction::SendOnly);
    pc.set_remote_description(answer).await.unwrap();
    let next = pc.create_offer().await.unwrap();
    assert_eq!(next.media_sections[0].direction, Direction::RecvOnly);
}
