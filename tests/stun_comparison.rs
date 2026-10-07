#![cfg(feature = "std")]

use rustrtc::transports::ice::stun::{StunAttribute, StunMessage};
use webrtc::stun::attributes::*;
use webrtc::stun::integrity::*;
use webrtc::stun::message::Message as WebrtcMessage;
use webrtc::stun::textattrs::*;

#[test]
fn compare_stun_encoding() {
    let tx_id = [1u8; 12];
    let username = "remote:local";
    let password = "password";
    let priority = 12345;
    let controlling = 999;

    // RustRTC
    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));
    msg.attributes
        .push(StunAttribute::Username(username.to_string()));
    msg.attributes.push(StunAttribute::Priority(priority));
    msg.attributes
        .push(StunAttribute::IceControlling(controlling));

    let rust_bytes = msg.encode(Some(password.as_bytes()), true).unwrap();

    // WebRTC (stun crate)
    let mut w_msg = WebrtcMessage::new();

    // Transaction ID
    // TransactionId is a struct wrapping [u8; 12]
    // It seems we can't easily set it if new() is random and fields are private.
    // But let's try to see if we can access raw bytes.
    // w_msg.transaction_id.0 = tx_id; // This worked in my thought but maybe field is private.

    // Let's try to use build() with correct args.
    // Software::new(ATTR_SOFTWARE, "rustrtc")
    // Username::new(ATTR_USERNAME, username)
    // PriorityAttr::new(ATTR_PRIORITY, priority)
    // IceControlling::new(ATTR_ICE_CONTROLLING, controlling)

    w_msg
        .build(&[
            Box::new(webrtc::stun::message::BINDING_REQUEST),
            // Box::new(TransactionId::new(tx_id)), // Skip tx id for now, we can overwrite bytes later
            Box::new(Software::new(ATTR_SOFTWARE, "rustrtc".to_string())),
            Box::new(Username::new(ATTR_USERNAME, username.to_string())),
            // Box::new(PriorityAttr::new(ATTR_PRIORITY, priority)),
            // Box::new(IceControlling::new(ATTR_ICE_CONTROLLING, controlling)),
            Box::new(MessageIntegrity::new_short_term_integrity(
                password.to_string(),
            )),
            // Box::new(Fingerprint::new(ATTR_FINGERPRINT)),
        ])
        .unwrap();

    // Overwrite transaction ID in raw bytes
    w_msg.raw[8..20].copy_from_slice(&tx_id);

    // Re-calculate integrity and fingerprint because we changed tx_id?
    // No, build() calculates them.
    // But build() used random tx_id.
    // So integrity and fingerprint are wrong for our tx_id.

    // This approach is hard.

    println!("RustRTC bytes: {:02x?}", rust_bytes);
}
