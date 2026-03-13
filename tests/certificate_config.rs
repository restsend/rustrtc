use anyhow::Result;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rustrtc::transports::dtls;
use rustrtc::{
    CertificateConfig, MediaKind, PeerConnection, RtcConfiguration, RtcConfigurationBuilder,
    RtcError, TransceiverDirection,
};

fn certificate_config_from_dtls(cert: &dtls::Certificate) -> CertificateConfig {
    CertificateConfig {
        pem_chain: cert
            .certificate
            .iter()
            .map(|der| der_to_pem("CERTIFICATE", der))
            .collect(),
        private_key_pem: Some(cert.private_key.clone()),
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
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
}

#[tokio::test]
async fn pem_certificate_load_success() -> Result<()> {
    init_test_runtime();

    let certificate = dtls::generate_certificate()?;
    let expected_fingerprint = dtls::fingerprint(&certificate);
    let config = RtcConfigurationBuilder::new()
        .certificate(certificate_config_from_dtls(&certificate))
        .build();

    let pc = PeerConnection::try_new(config)?;
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc.create_offer().await?;
    let fingerprint = offer
        .dtls_fingerprint()?
        .expect("offer should contain DTLS fingerprint");

    assert_eq!(fingerprint.algorithm, "sha-256");
    assert_eq!(fingerprint.value, expected_fingerprint);
    Ok(())
}

#[tokio::test]
async fn pem_key_mismatch_fails() -> Result<()> {
    init_test_runtime();

    let certificate = dtls::generate_certificate()?;
    let wrong_key = dtls::generate_certificate()?;
    let mut config = certificate_config_from_dtls(&certificate);
    config.private_key_pem = Some(wrong_key.private_key.clone());

    let err =
        match PeerConnection::try_new(RtcConfigurationBuilder::new().certificate(config).build()) {
            Ok(_) => panic!("mismatched certificate and key should be rejected"),
            Err(err) => err,
        };
    assert!(
        matches!(err, RtcError::InvalidConfiguration(ref message) if message.contains("does not match")),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn default_self_signed_fallback_works() -> Result<()> {
    init_test_runtime();

    let pc = PeerConnection::try_new(RtcConfiguration::default())?;
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc.create_offer().await?;
    let fingerprint = offer
        .dtls_fingerprint()?
        .expect("default offer should contain DTLS fingerprint");

    assert_eq!(fingerprint.algorithm, "sha-256");
    assert!(!fingerprint.value.is_empty());
    Ok(())
}
