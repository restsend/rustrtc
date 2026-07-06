// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
use anyhow::Result;
use rustrtc::rtp::{PictureLossIndication, RtcpPacket, marshal_rtcp_packets};
use rustrtc::srtp::{SrtpKeyingMaterial, SrtpProfile, SrtpSession};

#[test]
fn test_srtcp_roundtrip() -> Result<()> {
    let keying = SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]);
    let mut sender = SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone())?;
    let mut receiver =
        SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone())?;

    let pli = RtcpPacket::PictureLossIndication(PictureLossIndication {
        sender_ssrc: 1234,
        media_ssrc: 5678,
    });
    let mut packet = marshal_rtcp_packets(&[pli])?;

    println!("Original packet len: {}", packet.len());

    // Protect
    sender.protect_rtcp(&mut packet)?;
    println!("Protected packet len: {}", packet.len());

    // Unprotect
    receiver.unprotect_rtcp(&mut packet)?;
    println!("Unprotected packet len: {}", packet.len());

    Ok(())
}

#[test]
fn test_srtcp_index_handling() -> Result<()> {
    let keying = SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]);
    let mut sender = SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone())?;
    let mut receiver =
        SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone())?;

    let pli = RtcpPacket::PictureLossIndication(PictureLossIndication {
        sender_ssrc: 1234,
        media_ssrc: 5678,
    });

    for i in 0..5 {
        let mut packet = marshal_rtcp_packets(&[pli.clone()])?;
        sender.protect_rtcp(&mut packet)?;

        // Verify index is appended correctly
        // Last 4 bytes are index + E-bit
        let len = packet.len();
        let index_bytes = &packet[len - 14..len - 10]; // Tag is 10 bytes
        let index_val = u32::from_be_bytes([
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ]);
        println!("Packet {} index field: {:08x}", i, index_val);

        // E-bit should be set (0x80000000) + index (1, 2, 3...)
        assert_eq!(index_val, 0x80000000 | (i + 1));

        receiver.unprotect_rtcp(&mut packet)?;
    }

    Ok(())
}
