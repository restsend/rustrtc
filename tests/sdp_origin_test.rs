//! RFC 3264 §8 and RFC 8829 §5.2.2 / §5.3.2: once a session description has
//! been sent, every later offer or answer keeps the `o=` line of the previous
//! local description and increments `<sess-version>` by one.
use anyhow::Result;
use rustrtc::media::track::sample_track;
use rustrtc::sdp::{Origin, SessionDescription};
use rustrtc::{
    MediaKind, PeerConnection, RtcConfiguration, RtpCodecParameters, TransceiverDirection,
    TransportMode,
};

fn opus() -> RtpCodecParameters {
    RtpCodecParameters {
        payload_type: 111,
        name: "opus".to_string(),
        clock_rate: 48000,
        channels: 2,
    }
}

fn rtp_pc() -> PeerConnection {
    PeerConnection::new(RtcConfiguration {
        transport_mode: TransportMode::Rtp,
        ..RtcConfiguration::default()
    })
}

async fn negotiate(offerer: &PeerConnection, answerer: &PeerConnection) -> Result<()> {
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer).await?;
    let answer = answerer.create_answer().await?;
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer).await?;
    Ok(())
}

fn origin(desc: &SessionDescription) -> Origin {
    desc.session.origin.clone()
}

/// `next` is the description sent after `previous`: same origin, version + 1.
fn assert_follows(previous: &Origin, next: &Origin, what: &str) {
    assert_eq!(
        next.session_id, previous.session_id,
        "{what}: <sess-id> must not change"
    );
    assert_eq!(
        next.session_version,
        previous.session_version + 1,
        "{what}: <sess-version> must increment by one"
    );
    assert_eq!(
        (&next.username, &next.unicast_address),
        (&previous.username, &previous.unicast_address),
        "{what}: the rest of o= must not change"
    );
}

async fn connected_pair() -> Result<(PeerConnection, PeerConnection)> {
    let pc1 = rtp_pc();
    let pc2 = rtp_pc();
    let (_source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    negotiate(&pc1, &pc2).await?;
    Ok((pc1, pc2))
}

#[tokio::test]
async fn reoffers_keep_the_origin_and_increment_the_version() -> Result<()> {
    let (pc1, pc2) = connected_pair().await?;

    // Several renegotiations within the same second: each one changes the
    // SDP, so each needs its own, strictly consecutive version.
    for (round, direction) in [
        TransceiverDirection::SendOnly,
        TransceiverDirection::SendRecv,
        TransceiverDirection::Inactive,
        TransceiverDirection::SendRecv,
    ]
    .into_iter()
    .enumerate()
    {
        let previous_offerer = origin(&pc1.local_description().unwrap());
        let previous_answerer = origin(&pc2.local_description().unwrap());
        pc1.get_transceivers()[0].set_direction(direction);

        let offer = pc1.create_offer().await?;
        assert_follows(
            &previous_offerer,
            &origin(&offer),
            &format!("re-offer {round}"),
        );
        pc1.set_local_description(offer.clone())?;
        pc2.set_remote_description(offer).await?;

        let answer = pc2.create_answer().await?;
        assert_follows(
            &previous_answerer,
            &origin(&answer),
            &format!("answer {round}"),
        );
        pc2.set_local_description(answer.clone())?;
        pc1.set_remote_description(answer).await?;
    }
    Ok(())
}

#[tokio::test]
async fn the_answerer_can_reoffer_with_its_own_origin() -> Result<()> {
    let (pc1, pc2) = connected_pair().await?;

    // Roles swap: the side that answered now offers (e.g. a re-INVITE from
    // the callee). Its offer continues its own previous answer's o= line.
    let previous = origin(&pc2.local_description().unwrap());
    let offer = pc2.create_offer().await?;
    assert_follows(&previous, &origin(&offer), "answerer re-offer");
    pc2.set_local_description(offer.clone())?;
    pc1.set_remote_description(offer).await?;
    let previous = origin(&pc1.local_description().unwrap());
    let answer = pc1.create_answer().await?;
    assert_follows(&previous, &origin(&answer), "offerer answers");
    Ok(())
}

#[tokio::test]
async fn an_offer_that_is_not_applied_does_not_advance_the_version() -> Result<()> {
    let (pc1, _pc2) = connected_pair().await?;
    let previous = origin(&pc1.local_description().unwrap());
    let first = pc1.create_offer().await?;
    let second = pc1.create_offer().await?;
    assert_follows(&previous, &origin(&first), "first re-offer");
    assert_eq!(origin(&second), origin(&first));
    Ok(())
}

#[tokio::test]
async fn the_first_description_gets_a_fresh_origin() -> Result<()> {
    let pc1 = rtp_pc();
    let pc2 = rtp_pc();
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc1.create_offer().await?;
    assert_ne!(offer.session.origin.session_id, 0);
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;
    let answer = pc2.create_answer().await?;
    assert_ne!(answer.session.origin.session_id, 0);
    Ok(())
}
