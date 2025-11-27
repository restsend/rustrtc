use anyhow::Result;
use rustrtc::rtp::{RtpHeader, RtpPacket};
use rustrtc::srtp::{SrtpKeyingMaterial, SrtpProfile, SrtpSession};
use rustrtc::transports::rtp::UdpRtpEndpoint;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_srtp_interop_loopback() -> Result<()> {
    // 1. Setup keys (normally exchanged via DTLS or SDES)
    let key_len = 16;
    let salt_len = 14;
    let master_key_a = vec![0x01u8; key_len];
    let master_salt_a = vec![0x02u8; salt_len];
    let master_key_b = vec![0x01u8; key_len]; // Symmetric for this test
    let master_salt_b = vec![0x02u8; salt_len];

    let km_a = SrtpKeyingMaterial::new(master_key_a, master_salt_a);
    let km_b = SrtpKeyingMaterial::new(master_key_b, master_salt_b);

    // 2. Create SRTP Sessions
    // Note: In a real scenario, one is sender, one is receiver, or both.
    // SrtpSession handles both protect (send) and unprotect (recv).
    let mut tx_session = SrtpSession::new(
        SrtpProfile::Aes128Sha1_80,
        km_a.clone(),
        km_a,
    )?;
    let mut rx_session = SrtpSession::new(
        SrtpProfile::Aes128Sha1_80,
        km_b.clone(),
        km_b,
    )?;

    // 3. Setup UDP Transport
    let socket_a = UdpSocket::bind("127.0.0.1:0").await?;
    let socket_b = UdpSocket::bind("127.0.0.1:0").await?;
    let addr_a = socket_a.local_addr()?;
    let addr_b = socket_b.local_addr()?;

    let endpoint_a = UdpRtpEndpoint::connect(socket_a, None, addr_b, None).await?;
    let endpoint_b = UdpRtpEndpoint::connect(socket_b, None, addr_a, None).await?;

    // 4. Create and Protect RTP Packet
    let header = RtpHeader::new(96, 5000, 987654, 0x11223344);
    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let mut packet = RtpPacket::new(header, payload.clone());

    println!("Original payload: {:02X?}", packet.payload);

    // Protect (Encrypt)
    tx_session.protect_rtp(&mut packet)?;
    println!("Protected payload (encrypted): {:02X?}", packet.payload);
    assert_ne!(packet.payload, payload, "Payload should be encrypted");

    // 5. Send
    endpoint_a.send_rtp(&packet).await?;

    // 6. Receive
    let mut received = match endpoint_b.recv().await? {
        rustrtc::transports::rtp::ReceivedPacket::Rtp(p) => p,
        _ => panic!("expected RTP"),
    };

    // 7. Unprotect (Decrypt)
    rx_session.unprotect_rtp(&mut received)?;
    println!("Decrypted payload: {:02X?}", received.payload);

    // 8. Verify
    assert_eq!(received.payload, payload);
    assert_eq!(received.header.sequence_number, 5000);

    println!("SRTP Interop Test Passed: A -> B");
    Ok(())
}
