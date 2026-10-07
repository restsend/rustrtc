#![cfg(feature = "std")]

//! RFC 3264 §6 / §8.2: a media section with port 0 is rejected and carries
//! no media, except a `bundle-only` section inside a BUNDLE group, which
//! uses port 0 while sharing the group's transport (RFC 9143 §7).
use anyhow::Result;
use bytes::Bytes;
use rustrtc::media::frame::{AudioFrame, MediaSample};
use rustrtc::media::track::{SampleStreamSource, sample_track};
use rustrtc::peer_connection::RtpSender;
use rustrtc::sdp::{Attribute, SessionDescription};
use rustrtc::{PeerConnection, RtcConfiguration, RtpCodecParameters, TransportMode};
use std::time::Duration;

const MODES: [TransportMode; 3] = [
    TransportMode::WebRtc,
    TransportMode::Rtp,
    TransportMode::Srtp,
];

fn opus() -> RtpCodecParameters {
    RtpCodecParameters {
        payload_type: 111,
        name: "opus".to_string(),
        clock_rate: 48000,
        channels: 2,
    }
}

fn pc(mode: TransportMode) -> PeerConnection {
    PeerConnection::new(RtcConfiguration {
        transport_mode: mode,
        ..RtcConfiguration::default()
    })
}

fn reject(desc: &mut SessionDescription) {
    desc.media_sections[0].port = 0;
}

/// Section `index` becomes port 0 + `bundle-only`, and the BUNDLE group
/// lists every section (the first one is the tag).
fn make_bundle_only(desc: &mut SessionDescription, index: usize) {
    desc.media_sections[index].port = 0;
    desc.media_sections[index]
        .attributes
        .push(Attribute::new("bundle-only", None));
    let mids: Vec<String> = desc.media_sections.iter().map(|m| m.mid.clone()).collect();
    desc.session.attributes.retain(|a| a.key != "group");
    desc.session.attributes.push(Attribute::new(
        "group",
        Some(format!("BUNDLE {}", mids.join(" "))),
    ));
}

fn pump(source: SampleStreamSource) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let frame = AudioFrame {
                data: Bytes::from_static(&[0xAA; 20]),
                ..AudioFrame::default()
            };
            if source.send(MediaSample::Audio(frame)).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
}

/// Per m= line, whether `pc` sends RTP on it within one second.
async fn sends(pc: &PeerConnection) -> Vec<bool> {
    let senders: Vec<_> = pc.get_transceivers().iter().map(|t| t.sender()).collect();
    let count = |s: &Option<std::sync::Arc<RtpSender>>| s.as_ref().map(|s| s.packets_sent());
    let before: Vec<_> = senders.iter().map(count).collect();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    senders
        .iter()
        .zip(before)
        .map(|(s, b)| count(s) > b)
        .collect()
}

/// One offer/answer exchange; `edit_offer` / `edit_answer` modify the
/// descriptions on the wire.
async fn exchange(
    offerer: &PeerConnection,
    answerer: &PeerConnection,
    edit_offer: fn(&mut SessionDescription),
    edit_answer: fn(&mut SessionDescription),
) -> Result<()> {
    let _ = offerer.create_offer().await?;
    offerer.wait_for_gathering_complete().await;
    let mut offer = offerer.create_offer().await?;
    edit_offer(&mut offer);
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer).await?;
    let _ = answerer.create_answer().await?;
    answerer.wait_for_gathering_complete().await;
    let mut answer = answerer.create_answer().await?;
    edit_answer(&mut answer);
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer).await?;
    Ok(())
}

/// The peers, and the pumps feeding their tracks.
type Call = (
    PeerConnection,
    PeerConnection,
    Vec<tokio::task::JoinHandle<()>>,
);

/// Both peers send `tracks` audio m= lines; pc1 offers.
async fn call(
    mode: TransportMode,
    tracks: usize,
    edit_offer: fn(&mut SessionDescription),
    edit_answer: fn(&mut SessionDescription),
) -> Result<Call> {
    let (pc1, pc2) = (pc(mode.clone()), pc(mode));
    let mut pumps = Vec::new();
    for peer in [&pc1, &pc2] {
        for _ in 0..tracks {
            let (source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
            peer.add_track(track, opus())?;
            pumps.push(pump(source));
        }
    }
    exchange(&pc1, &pc2, edit_offer, edit_answer).await?;
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    Ok((pc1, pc2, pumps))
}

async fn offerer_sends_on(
    tracks: usize,
    edit_offer: fn(&mut SessionDescription),
    edit_answer: fn(&mut SessionDescription),
) -> Result<Vec<bool>> {
    let (pc1, _pc2, _pumps) = call(TransportMode::WebRtc, tracks, edit_offer, edit_answer).await?;
    Ok(sends(&pc1).await)
}

/// JSEP (RFC 8829 §5.2.1): a WebRTC offer always carries a BUNDLE group;
/// a plain RTP offer with one section still does not.
#[tokio::test]
async fn a_webrtc_offer_with_one_section_carries_a_bundle_group() -> Result<()> {
    for (mode, grouped) in [(TransportMode::WebRtc, true), (TransportMode::Rtp, false)] {
        let pc = pc(mode.clone());
        let (_source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
        pc.add_track(track, opus())?;
        let offer = pc.create_offer().await?;
        let group = format!("BUNDLE {}", offer.media_sections[0].mid);
        let has_group = (offer.session.attributes.iter())
            .any(|a| a.key == "group" && a.value.as_deref() == Some(group.as_str()));
        assert_eq!(has_group, grouped, "{mode:?}: {}", offer.to_sdp_string());
    }
    Ok(())
}

#[tokio::test]
async fn media_flows_on_an_accepted_section() -> Result<()> {
    for mode in MODES {
        let (pc1, pc2, _pumps) = call(mode.clone(), 1, |_| {}, |_| {}).await?;
        assert_eq!(sends(&pc1).await, vec![true], "{mode:?}: offerer");
        assert_eq!(sends(&pc2).await, vec![true], "{mode:?}: answerer");
    }
    Ok(())
}

#[tokio::test]
async fn no_rtp_after_the_answer_rejects_the_section() -> Result<()> {
    for mode in [
        TransportMode::WebRtc,
        TransportMode::Rtp,
        TransportMode::Srtp,
    ] {
        let (pc1, pc2, _pumps) = call(mode.clone(), 1, |_| {}, reject).await?;
        assert_eq!(sends(&pc1).await, vec![false], "{mode:?}: offerer sent RTP");
        assert_eq!(
            sends(&pc2).await,
            vec![false],
            "{mode:?}: answerer sent RTP"
        );
    }
    Ok(())
}

/// Both sides: our offer disabled the stream, and the answer (port 0 as
/// well) rejects it.
#[tokio::test]
async fn no_rtp_on_a_section_we_offered_with_port_zero() -> Result<()> {
    let (pc1, pc2, _pumps) = call(TransportMode::WebRtc, 1, reject, |_| {}).await?;
    assert_eq!(sends(&pc1).await, vec![false], "offerer sent RTP");
    assert_eq!(sends(&pc2).await, vec![false], "answerer sent RTP");
    Ok(())
}

/// RFC 3264 §8: a re-offer with a live port brings a rejected stream back.
#[tokio::test]
async fn media_resumes_when_a_reoffer_accepts_the_rejected_section() -> Result<()> {
    let (pc1, pc2, _pumps) = call(TransportMode::WebRtc, 1, |_| {}, reject).await?;
    assert_eq!(sends(&pc1).await, vec![false]);
    exchange(&pc1, &pc2, |_| {}, |_| {}).await?;
    assert_eq!(sends(&pc1).await, vec![true], "offerer did not resume");
    assert_eq!(sends(&pc2).await, vec![true], "answerer did not resume");
    Ok(())
}

#[tokio::test]
async fn a_bundle_only_section_with_port_zero_is_not_rejected() -> Result<()> {
    assert_eq!(
        offerer_sends_on(2, |_| {}, |d| make_bundle_only(d, 1)).await?,
        vec![true, true],
        "a non-tag bundle-only section in a BUNDLE group keeps its media"
    );
    Ok(())
}

#[tokio::test]
async fn the_bundle_tag_with_port_zero_is_rejected() -> Result<()> {
    assert_eq!(
        offerer_sends_on(2, |_| {}, |d| make_bundle_only(d, 0)).await?,
        vec![false, true]
    );
    Ok(())
}

#[tokio::test]
async fn bundle_only_outside_a_bundle_group_is_rejected() -> Result<()> {
    fn bundle_only_without_group(desc: &mut SessionDescription) {
        make_bundle_only(desc, 1);
        desc.session.attributes.retain(|a| a.key != "group");
    }
    assert_eq!(
        offerer_sends_on(2, |_| {}, bundle_only_without_group).await?,
        vec![true, false]
    );
    Ok(())
}

/// RFC 3264 §6: a stream offered with port 0 is answered with port 0, also
/// once candidates have been gathered.
#[tokio::test]
async fn a_disabled_offered_stream_is_answered_with_port_zero() -> Result<()> {
    let pc = pc(TransportMode::Rtp);
    let raw = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nc=IN IP4 127.0.0.1\r\n\
               m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
               m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
    let offer = SessionDescription::parse(rustrtc::sdp::SdpType::Offer, raw)?;
    pc.set_remote_description(offer).await?;
    let answer = pc.create_answer().await?;
    assert_ne!(answer.media_sections[0].port, 0);
    assert_eq!(answer.media_sections[1].port, 0);
    pc.set_local_description(answer)?;
    pc.wait_for_gathering_complete().await;
    let applied = pc.local_description().expect("local description");
    assert_eq!(
        applied.media_sections[1].port,
        0,
        "{}",
        applied.to_sdp_string()
    );
    Ok(())
}

/// A rejected section is left out of the answer's BUNDLE group, so it can
/// never become the group's tag (RFC 9143 §7.3.2).
#[tokio::test]
async fn a_rejected_section_is_not_bundled_in_the_answer() -> Result<()> {
    let pc1 = pc(TransportMode::WebRtc);
    let pc2 = pc(TransportMode::WebRtc);
    for _ in 0..2 {
        let (_source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
        pc1.add_track(track, opus())?;
    }
    let mut offer = pc1.create_offer().await?;
    reject(&mut offer);
    pc2.set_remote_description(offer).await?;
    let answer = pc2.create_answer().await?;
    assert_eq!(answer.media_sections[0].port, 0);
    let second = &answer.media_sections[1].mid;
    let group: Vec<_> = (answer.session.attributes.iter())
        .filter(|a| a.key == "group")
        .filter_map(|a| a.value.clone())
        .collect();
    assert_eq!(group, vec![format!("BUNDLE {second}")]);
    Ok(())
}
