use anyhow::Result;
use rustrtc::config::{ApplicationCapability, MediaCapabilities};
use rustrtc::sdp::{
    Attribute, Direction, MediaSection, SdpType, SessionDescription, SessionSection,
};
use rustrtc::*;

fn create_offer_with_codec(
    kind: MediaKind,
    mid: &str,
    payload_type: u8,
    rtpmap: &str,
    fmtp: Option<&str>,
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
    desc.media_sections.push(section);
    desc
}

fn find_attr<'a>(section: &'a MediaSection, key: &str) -> Vec<&'a str> {
    section
        .attributes
        .iter()
        .filter(|attr| attr.key == key)
        .filter_map(|attr| attr.value.as_deref())
        .collect()
}

#[tokio::test]
async fn opus_fmtp_roundtrip() -> Result<()> {
    let config = RtcConfigurationBuilder::new()
        .media_capabilities(MediaCapabilities {
            audio: vec![AudioCapability::opus()],
            video: vec![VideoCapability::default()],
            application: Some(ApplicationCapability::default()),
        })
        .build();
    let pc = PeerConnection::new(config);
    let offer = create_offer_with_codec(
        MediaKind::Audio,
        "0",
        111,
        "opus/48000/2",
        Some("minptime=10;useinbandfec=1"),
    );

    pc.set_remote_description(offer).await?;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;

    let fmtp_values = find_attr(&answer.media_sections[0], "fmtp");
    assert!(
        fmtp_values
            .iter()
            .any(|value| *value == "111 minptime=10;useinbandfec=1")
    );
    assert_eq!(
        pc.get_transceivers()[0].get_payload_map()[&111]
            .fmtp
            .as_deref(),
        Some("minptime=10;useinbandfec=1")
    );
    Ok(())
}

#[tokio::test]
async fn h264_profile_level_id_roundtrip() -> Result<()> {
    let config = RtcConfigurationBuilder::new()
        .media_capabilities(MediaCapabilities {
            audio: vec![AudioCapability::opus()],
            video: vec![VideoCapability {
                payload_type: 96,
                codec_name: "H264".to_string(),
                clock_rate: 90000,
                fmtp: Some("profile-level-id=42e01f;packetization-mode=1".to_string()),
                rtcp_fbs: vec![],
            }],
            application: Some(ApplicationCapability::default()),
        })
        .build();
    let pc = PeerConnection::new(config);
    let offer = create_offer_with_codec(
        MediaKind::Video,
        "1",
        102,
        "H264/90000",
        Some("profile-level-id=42e01f;packetization-mode=1"),
    );

    pc.set_remote_description(offer).await?;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;

    let fmtp_values = find_attr(&answer.media_sections[0], "fmtp");
    assert!(
        fmtp_values.iter().any(|value| {
            value.contains("profile-level-id=42e01f") && value.starts_with("102 ")
        })
    );
    assert_eq!(
        pc.get_transceivers()[0].get_payload_map()[&102]
            .codec_specific_parameters()
            .get("profile-level-id"),
        Some(&"42e01f".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn h264_packetization_mode_roundtrip() -> Result<()> {
    let config = RtcConfigurationBuilder::new()
        .media_capabilities(MediaCapabilities {
            audio: vec![AudioCapability::opus()],
            video: vec![VideoCapability {
                payload_type: 96,
                codec_name: "H264".to_string(),
                clock_rate: 90000,
                fmtp: Some("packetization-mode=1;profile-level-id=42e01f".to_string()),
                rtcp_fbs: vec![],
            }],
            application: Some(ApplicationCapability::default()),
        })
        .build();
    let pc = PeerConnection::new(config);
    let offer = create_offer_with_codec(
        MediaKind::Video,
        "2",
        104,
        "H264/90000",
        Some("packetization-mode=1;profile-level-id=42e01f"),
    );

    pc.set_remote_description(offer).await?;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;

    let fmtp_values = find_attr(&answer.media_sections[0], "fmtp");
    assert!(
        fmtp_values
            .iter()
            .any(|value| { value.contains("packetization-mode=1") && value.starts_with("104 ") })
    );
    assert_eq!(
        pc.get_transceivers()[0].get_payload_map()[&104]
            .codec_specific_parameters()
            .get("packetization-mode"),
        Some(&"1".to_string())
    );
    Ok(())
}
