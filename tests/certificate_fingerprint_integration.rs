use anyhow::Result;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rustrtc::transports::dtls;
use rustrtc::{
    CertificateConfig, MediaKind, PeerConnection, RtcConfigurationBuilder, TransceiverDirection,
};

fn certificate_config_from_chain(chain: &[Vec<u8>], private_key_pem: &str) -> CertificateConfig {
    CertificateConfig {
        pem_chain: chain
            .iter()
            .map(|der| der_to_pem("CERTIFICATE", der))
            .collect(),
        private_key_pem: Some(private_key_pem.to_string()),
    }
}

fn der_to_pem(label: &str, der: &[u8]) -> String {
    let base64 = BASE64_STANDARD.encode(der);
    let body = base64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn init_test_runtime() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();
}

#[tokio::test]
async fn configured_certificate_fingerprint_matches_generated_sdp() -> Result<()> {
    init_test_runtime();

    let leaf = dtls::generate_certificate()?;
    let extra_chain_cert = dtls::generate_certificate()?;
    let expected_fingerprint = dtls::fingerprint(&leaf);

    let mut chain = leaf.certificate.clone();
    chain.extend(extra_chain_cert.certificate.clone());
    let config = RtcConfigurationBuilder::new()
        .certificate(certificate_config_from_chain(&chain, &leaf.private_key))
        .build();

    let pc = PeerConnection::try_new(config)?;
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc.create_offer().await?;
    pc.set_local_description(offer)?;
    pc.wait_for_gathering_complete().await;

    let local_description = pc
        .local_description()
        .expect("local description should be stored after offer");
    let fingerprint = local_description
        .dtls_fingerprint()?
        .expect("generated SDP should contain DTLS fingerprint");

    assert_eq!(fingerprint.algorithm, "sha-256");
    assert_eq!(fingerprint.value, expected_fingerprint);
    assert!(
        local_description
            .to_sdp_string()
            .contains(&format!("a=fingerprint:sha-256 {}", expected_fingerprint))
    );
    Ok(())
}
