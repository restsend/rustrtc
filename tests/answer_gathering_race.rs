#![cfg(feature = "std")]

//! The answerer starts ICE gathering in `set_remote_description`. When that
//! gathering completes between `create_answer` and `set_local_description`,
//! the gathered candidates must still reach the answer that
//! `wait_for_gathering_complete` lets out - JSEP (RFC 9429) and W3C
//! webrtc-pc have the local description carry the candidates gathered so far.
//!
//! The offer here carries no candidates (a trickle-ICE browser offer, its
//! candidates going out separately), so the answer is the only way the
//! offerer learns where to send its checks. An answer without candidates
//! and no trickle to follow (RFC 8838/8840) leaves both sides with nothing
//! to check, and the connection never comes up.

use anyhow::Result;
use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, SdpType, TransceiverDirection};
use std::time::Duration;

fn strip_candidates(desc: &mut rustrtc::SessionDescription) {
    for section in desc.media_sections.iter_mut() {
        section
            .attributes
            .retain(|a| a.key != "candidate" && a.key != "end-of-candidates");
    }
}

fn candidate_count(desc: &rustrtc::SessionDescription) -> usize {
    desc.media_sections
        .iter()
        .flat_map(|s| s.attributes.iter())
        .filter(|a| a.key == "candidate")
        .count()
}

#[tokio::test]
async fn answer_gathered_before_local_description_still_connects() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let offerer = PeerConnection::new(RtcConfiguration::webrtc());
    offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let answerer = PeerConnection::new(RtcConfiguration::webrtc());
    answerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

    // trickle-style offer: no candidates in the SDP
    let mut offer = offerer.create_offer().await?;
    strip_candidates(&mut offer);
    offerer.set_local_description(offer.clone())?;

    answerer.set_remote_description(offer).await?;
    // an answer created before the answerer's gathering got anywhere
    let mut answer = answerer.create_answer().await?;
    strip_candidates(&mut answer);
    // host gathering finishes well within this, with no local description set
    tokio::time::sleep(Duration::from_millis(200)).await;

    answerer.set_local_description(answer)?;
    tokio::time::timeout(
        Duration::from_secs(5),
        answerer.wait_for_gathering_complete(),
    )
    .await
    .expect("answerer gathering never reported complete");
    let answer = answerer
        .local_description()
        .expect("answerer has a local description");
    assert!(
        candidate_count(&answer) >= 1,
        "answer went out without candidates"
    );
    assert_eq!(answer.sdp_type, SdpType::Answer);

    offerer.set_remote_description(answer).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(offerer.wait_for_connected(), answerer.wait_for_connected())
    })
    .await
    .expect("peers never connected")?;
    Ok(())
}
