use anyhow::Result;
use rustrtc::config::{ApplicationCapability, MediaCapabilities};
use rustrtc::sdp::{
    Attribute, Direction, MediaSection, SdpType, SessionDescription, SessionSection,
};
use rustrtc::*;

fn create_codec_offer(
    kind: MediaKind,
    mid: &str,
    payload_type: u8,
    rtpmap: &str,
    fmtp: Option<&str>,
    rtcp_fbs: &[&str],
) -> SessionDescription {
    let mut desc = SessionDescription::new(SdpType::Offer);
    desc.session = SessionSection::default();

    let mut section = MediaSection::new(kind, mid);
    section.direction = Direction::SendRecv;
    section.formats.push(payload_type.to_string());
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some(format!("{payload_type} {rtpmap}")),
    ));
    if let Some(fmtp) = fmtp {
        section.attributes.push(Attribute::new(
            "fmtp",
            Some(format!("{payload_type} {fmtp}")),
        ));
    }
    for fb in rtcp_fbs {
        section.attributes.push(Attribute::new(
            "rtcp-fb",
            Some(format!("{payload_type} {fb}")),
        ));
    }
    desc.media_sections.push(section);
    desc
}

#[tokio::test]
async fn extract_payload_map_preserves_codec_name() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration::default());
    let offer = create_codec_offer(MediaKind::Audio, "0", 111, "opus/48000/2", None, &[]);

    pc.set_remote_description(offer).await?;

    let payload_map = pc.get_transceivers()[0].get_payload_map();
    assert_eq!(payload_map.get(&111).unwrap().codec_name, "opus");
    Ok(())
}

#[tokio::test]
async fn extract_payload_map_preserves_fmtp() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration::default());
    let offer = create_codec_offer(
        MediaKind::Video,
        "0",
        102,
        "H264/90000",
        Some("profile-level-id=42e01f;packetization-mode=1"),
        &[],
    );

    pc.set_remote_description(offer).await?;

    let payload_map = pc.get_transceivers()[0].get_payload_map();
    let codec = payload_map.get(&102).unwrap();
    assert_eq!(
        codec.fmtp.as_deref(),
        Some("profile-level-id=42e01f;packetization-mode=1")
    );
    assert_eq!(
        codec.codec_specific_parameters().get("profile-level-id"),
        Some(&"42e01f".to_string())
    );
    assert_eq!(
        codec.codec_specific_parameters().get("packetization-mode"),
        Some(&"1".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn extract_payload_map_preserves_rtcp_fb() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration::default());
    let offer = create_codec_offer(
        MediaKind::Video,
        "0",
        96,
        "VP8/90000",
        None,
        &["nack", "nack pli", "transport-cc"],
    );

    pc.set_remote_description(offer).await?;

    let payload_map = pc.get_transceivers()[0].get_payload_map();
    let codec = payload_map.get(&96).unwrap();
    assert_eq!(
        codec.rtcp_fbs,
        vec![
            "nack".to_string(),
            "nack pli".to_string(),
            "transport-cc".to_string()
        ]
    );
    Ok(())
}

#[tokio::test]
async fn answer_rejects_incompatible_codec_pair() -> Result<()> {
    let config = RtcConfigurationBuilder::new()
        .media_capabilities(MediaCapabilities {
            audio: vec![AudioCapability::pcmu()],
            video: vec![VideoCapability::default()],
            application: Some(ApplicationCapability::default()),
        })
        .build();
    let pc = PeerConnection::new(config);
    let offer = create_codec_offer(MediaKind::Audio, "0", 111, "opus/48000/2", None, &[]);

    pc.set_remote_description(offer).await?;
    let answer = pc.create_answer().await?;
    assert_eq!(answer.media_sections[0].port, 0);

    pc.set_local_description(answer)?;
    assert!(pc.get_transceivers()[0].get_payload_map().is_empty());
    Ok(())
}
