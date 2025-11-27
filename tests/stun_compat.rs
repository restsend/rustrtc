use rustrtc::transports::ice::stun::{StunAttribute, StunMessage};
use std::net::SocketAddr;
use webrtc::stun::integrity::MessageIntegrity;
use webrtc::stun::message::Getter;
use webrtc::stun::message::{BINDING_REQUEST, Message};
use webrtc::stun::xoraddr::XorMappedAddress;

#[test]
fn test_stun_encoding_compatibility() {
    let tx_id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));

    // Match interop_webrtc.rs attributes
    msg.attributes
        .push(StunAttribute::Username("8u0s:h654".to_string()));
    msg.attributes.push(StunAttribute::Priority(1869119103));
    msg.attributes
        .push(StunAttribute::IceControlled(12977805629827341886));

    // Add XorMappedAddress
    let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
    msg.attributes.push(StunAttribute::XorMappedAddress(addr));

    let password = "password";
    let encoded = msg
        .encode(Some(password.as_bytes()), true)
        .expect("failed to encode");

    // Now try to decode with webrtc crate
    let mut other_msg = Message::new();
    let mut buf = encoded.clone();
    other_msg
        .unmarshal_binary(&mut buf)
        .expect("failed to unmarshal with webrtc");

    assert_eq!(other_msg.typ, BINDING_REQUEST);
    assert_eq!(other_msg.transaction_id.0, tx_id);

    // Verify Integrity
    let integrity = MessageIntegrity::new_short_term_integrity(password.to_string());

    match integrity.check(&mut other_msg) {
        Ok(_) => println!("Integrity check passed"),
        Err(e) => {
            println!("Integrity check failed: {:?}", e);
            println!("Encoded buffer: {:?}", encoded);
            panic!("Integrity mismatch");
        }
    }

    // Verify XorMappedAddress
    let mut xor_addr = XorMappedAddress::default();
    match xor_addr.get_from(&other_msg) {
        Ok(_) => {
            println!("Got address: IP={}, Port={}", xor_addr.ip, xor_addr.port);
            assert_eq!(xor_addr.ip.to_string(), "192.168.1.1");
            assert_eq!(xor_addr.port, 1234);
        }
        Err(e) => panic!("Failed to get XorMappedAddress: {}", e),
    }
}
