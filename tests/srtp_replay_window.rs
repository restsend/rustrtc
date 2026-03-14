use anyhow::Result;
use rustrtc::errors::SrtpError;
use rustrtc::rtp::{PictureLossIndication, RtcpPacket, RtpHeader, RtpPacket, marshal_rtcp_packets};
use rustrtc::{SrtpKeyingMaterial, SrtpProfile, SrtpSession};

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
fn duplicate_rtp_packet_rejected() -> Result<()> {
    let (mut sender, mut receiver) = sessions()?;
    let mut packet = sample_rtp(100);
    sender.protect_rtp(&mut packet)?;

    let mut duplicate = packet.clone();
    receiver.unprotect_rtp(&mut packet)?;

    let err = receiver.unprotect_rtp(&mut duplicate).unwrap_err();
    assert_eq!(err, SrtpError::ReplayDetected);
    Ok(())
}

#[test]
fn out_of_order_rtp_packet_within_window_accepted() -> Result<()> {
    let (mut sender, mut receiver) = sessions()?;

    let mut first = sample_rtp(10);
    let mut second = sample_rtp(11);
    let mut third = sample_rtp(12);

    sender.protect_rtp(&mut first)?;
    sender.protect_rtp(&mut second)?;
    sender.protect_rtp(&mut third)?;

    receiver.unprotect_rtp(&mut first)?;
    receiver.unprotect_rtp(&mut third)?;
    receiver.unprotect_rtp(&mut second)?;

    assert_eq!(first.payload, vec![1, 2, 3, 4]);
    assert_eq!(second.payload, vec![1, 2, 3, 4]);
    assert_eq!(third.payload, vec![1, 2, 3, 4]);
    Ok(())
}

#[test]
fn too_old_rtp_packet_rejected() -> Result<()> {
    let (mut sender, mut receiver) = sessions()?;
    let mut late_packet = sample_rtp(1);
    sender.protect_rtp(&mut late_packet)?;

    let mut newer_packets = Vec::new();
    for seq in 2..=65 {
        let mut packet = sample_rtp(seq);
        sender.protect_rtp(&mut packet)?;
        newer_packets.push(packet);
    }

    for packet in &mut newer_packets {
        receiver.unprotect_rtp(packet)?;
    }

    let err = receiver.unprotect_rtp(&mut late_packet).unwrap_err();
    assert_eq!(err, SrtpError::PacketTooOld);
    Ok(())
}

#[test]
fn duplicate_srtcp_packet_rejected() -> Result<()> {
    let (mut sender, mut receiver) = sessions()?;
    let mut packet = sample_rtcp();
    sender.protect_rtcp(&mut packet)?;

    let mut duplicate = packet.clone();
    receiver.unprotect_rtcp(&mut packet)?;

    let err = receiver.unprotect_rtcp(&mut duplicate).unwrap_err();
    assert_eq!(err, SrtpError::ReplayDetected);
    Ok(())
}
