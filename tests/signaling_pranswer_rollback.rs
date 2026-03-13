use anyhow::Result;
use rustrtc::sdp::{
    Attribute, Direction, MediaSection, SdpType, SessionDescription, SessionSection,
};
use rustrtc::*;

fn create_minimal_sdp(
    sdp_type: SdpType,
    mid: &str,
    direction: Direction,
    payload_type: u8,
    ssrc: u32,
) -> SessionDescription {
    let mut desc = SessionDescription::new(sdp_type);
    desc.session = SessionSection::default();

    let mut section = MediaSection::new(MediaKind::Audio, mid);
    section.direction = direction;
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some(format!("{payload_type} opus/48000/2")),
    ));
    section
        .attributes
        .push(Attribute::new("ssrc", Some(format!("{ssrc} cname:test"))));

    desc.media_sections.push(section);
    desc
}

#[tokio::test]
async fn local_rollback_restores_stable() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration::default());
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

    let local_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv, 111, 12345);
    pc.set_local_description(local_offer.clone())?;
    let remote_answer = create_minimal_sdp(SdpType::Answer, "0", Direction::SendRecv, 111, 12345);
    pc.set_remote_description(remote_answer.clone()).await?;
    assert_eq!(pc.signaling_state(), SignalingState::Stable);

    let transceiver = pc.get_transceivers()[0].clone();
    assert!(transceiver.get_payload_map().contains_key(&111));

    let reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv, 120, 12345);
    pc.set_local_description(reinvite_offer)?;
    assert_eq!(pc.signaling_state(), SignalingState::HaveLocalOffer);
    assert!(transceiver.get_payload_map().contains_key(&120));

    pc.set_local_description(SessionDescription::new(SdpType::Rollback))?;

    assert_eq!(pc.signaling_state(), SignalingState::Stable);
    assert_eq!(pc.local_description().unwrap().sdp_type, SdpType::Offer);
    assert_eq!(pc.remote_description().unwrap().sdp_type, SdpType::Answer);
    assert!(transceiver.get_payload_map().contains_key(&111));
    assert!(!transceiver.get_payload_map().contains_key(&120));
    Ok(())
}

#[tokio::test]
async fn remote_rollback_restores_stable() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration::default());

    let remote_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv, 111, 12345);
    pc.set_remote_description(remote_offer).await?;

    assert_eq!(pc.signaling_state(), SignalingState::HaveRemoteOffer);
    assert_eq!(pc.get_transceivers().len(), 1);

    pc.set_remote_description(SessionDescription::new(SdpType::Rollback))
        .await?;

    assert_eq!(pc.signaling_state(), SignalingState::Stable);
    assert!(pc.local_description().is_none());
    assert!(pc.remote_description().is_none());
    assert!(pc.get_transceivers().is_empty());
    Ok(())
}

#[tokio::test]
async fn pranswer_then_answer_succeeds() -> Result<()> {
    let offerer = PeerConnection::new(RtcConfiguration::default());
    offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

    let local_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv, 111, 12345);
    offerer.set_local_description(local_offer)?;

    let remote_pranswer =
        create_minimal_sdp(SdpType::Pranswer, "0", Direction::SendRecv, 111, 12345);
    offerer.set_remote_description(remote_pranswer).await?;
    assert_eq!(
        offerer.signaling_state(),
        SignalingState::HaveRemotePranswer
    );

    let remote_answer = create_minimal_sdp(SdpType::Answer, "0", Direction::SendRecv, 111, 12345);
    offerer.set_remote_description(remote_answer).await?;
    assert_eq!(offerer.signaling_state(), SignalingState::Stable);
    assert_eq!(
        offerer.remote_description().unwrap().sdp_type,
        SdpType::Answer
    );

    let answerer = PeerConnection::new(RtcConfiguration::default());
    let remote_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv, 111, 22222);
    answerer.set_remote_description(remote_offer).await?;

    let local_pranswer =
        create_minimal_sdp(SdpType::Pranswer, "0", Direction::SendRecv, 111, 22222);
    answerer.set_local_description(local_pranswer)?;
    assert_eq!(
        answerer.signaling_state(),
        SignalingState::HaveLocalPranswer
    );

    let local_answer = answerer.create_answer().await?;
    answerer.set_local_description(local_answer)?;
    assert_eq!(answerer.signaling_state(), SignalingState::Stable);
    Ok(())
}

#[tokio::test]
async fn invalid_state_rejected() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration::default());

    let local_pranswer = pc.set_local_description(create_minimal_sdp(
        SdpType::Pranswer,
        "0",
        Direction::SendRecv,
        111,
        1,
    ));
    assert!(matches!(local_pranswer, Err(RtcError::InvalidState(_))));

    let remote_pranswer = pc
        .set_remote_description(create_minimal_sdp(
            SdpType::Pranswer,
            "0",
            Direction::SendRecv,
            111,
            1,
        ))
        .await;
    assert!(matches!(remote_pranswer, Err(RtcError::InvalidState(_))));

    let local_rollback = pc.set_local_description(SessionDescription::new(SdpType::Rollback));
    assert!(matches!(local_rollback, Err(RtcError::InvalidState(_))));

    let remote_rollback = pc
        .set_remote_description(SessionDescription::new(SdpType::Rollback))
        .await;
    assert!(matches!(remote_rollback, Err(RtcError::InvalidState(_))));

    Ok(())
}
