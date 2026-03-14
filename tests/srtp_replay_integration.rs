use anyhow::Result;
use rustrtc::errors::SrtpError;
use rustrtc::rtp::{PictureLossIndication, RtcpPacket, RtpHeader, RtpPacket, marshal_rtcp_packets};
use rustrtc::stats::{DynProvider, StatsKind, gather_once};
use rustrtc::stats_collector::StatsCollector;
use rustrtc::{SrtpKeyingMaterial, SrtpProfile, SrtpSession};
use std::sync::Arc;

fn material() -> SrtpKeyingMaterial {
    SrtpKeyingMaterial::new(vec![0; 16], vec![0; 14])
}

fn sample_rtp(seq: u16) -> RtpPacket {
    let header = RtpHeader::new(96, seq, 1234, 0xdead_beef);
    RtpPacket::new(header, vec![1, 2, 3, 4])
}

fn sample_rtcp() -> Vec<u8> {
    marshal_rtcp_packets(&[RtcpPacket::PictureLossIndication(PictureLossIndication {
        sender_ssrc: 1234,
        media_ssrc: 5678,
    })])
    .expect("marshal rtcp packet")
}

fn sessions() -> Result<(SrtpSession, SrtpSession)> {
    let keying = material();
    Ok((
        SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone())?,
        SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone())?,
    ))
}

#[test]
fn local_srtp_sessions_accept_reordered_packets_and_reject_duplicates() -> Result<()> {
    let (mut sender, mut receiver) = sessions()?;

    let mut packet_100 = sample_rtp(100);
    let mut packet_101 = sample_rtp(101);
    let mut packet_102 = sample_rtp(102);
    sender.protect_rtp(&mut packet_100)?;
    sender.protect_rtp(&mut packet_101)?;
    sender.protect_rtp(&mut packet_102)?;

    let mut duplicate = packet_100.clone();
    receiver.unprotect_rtp(&mut packet_100)?;
    receiver.unprotect_rtp(&mut packet_102)?;
    receiver.unprotect_rtp(&mut packet_101)?;

    let duplicate_err = receiver.unprotect_rtp(&mut duplicate).unwrap_err();
    assert_eq!(duplicate_err, SrtpError::ReplayDetected);
    Ok(())
}

#[tokio::test]
async fn stats_report_includes_replay_reject_counters() -> Result<()> {
    let (mut sender, mut receiver) = sessions()?;
    let collector = StatsCollector::new();

    let mut late_packet = sample_rtp(1);
    sender.protect_rtp(&mut late_packet)?;
    for seq in 2..=65 {
        let mut packet = sample_rtp(seq);
        sender.protect_rtp(&mut packet)?;
        receiver.unprotect_rtp(&mut packet)?;
    }

    let late_err = receiver.unprotect_rtp(&mut late_packet).unwrap_err();
    collector.record_srtp_replay_reject(false, &late_err);
    assert_eq!(late_err, SrtpError::PacketTooOld);

    let mut rtcp = sample_rtcp();
    sender.protect_rtcp(&mut rtcp)?;
    let mut rtcp_duplicate = rtcp.clone();
    receiver.unprotect_rtcp(&mut rtcp)?;

    let rtcp_err = receiver.unprotect_rtcp(&mut rtcp_duplicate).unwrap_err();
    collector.record_srtp_replay_reject(true, &rtcp_err);
    assert_eq!(rtcp_err, SrtpError::ReplayDetected);

    let provider: Arc<DynProvider> = Arc::new(collector);
    let report = gather_once(&[provider]).await?;
    let transport = report
        .entries
        .iter()
        .find(|entry| entry.kind == StatsKind::Transport)
        .expect("transport stats entry with replay counters");

    assert_eq!(transport.values["srtpReplayRejectDuplicates"], 0);
    assert_eq!(transport.values["srtpReplayRejectTooOld"], 1);
    assert_eq!(transport.values["srtcpReplayRejectDuplicates"], 1);
    assert_eq!(transport.values["srtcpReplayRejectTooOld"], 0);
    Ok(())
}
