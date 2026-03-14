use anyhow::Result;
use rustrtc::{
    BundlePolicy, IceCredentialType, IceServer, IceTransport, PeerConnection, RtcConfiguration,
    RtcError,
};

#[test]
fn oauth_credential_fails_early_with_clear_error() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.ice_servers.push(
        IceServer::new(vec!["turn:127.0.0.1:3478?transport=udp".to_string()])
            .with_credential("user", "token")
            .credential_type(IceCredentialType::Oauth),
    );

    let err = match PeerConnection::try_new(config) {
        Ok(_) => panic!("OAuth TURN config should fail early"),
        Err(err) => err,
    };
    assert!(
        matches!(err, RtcError::InvalidConfiguration(ref message) if message.contains("Oauth") && message.contains("TURN")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn bundle_policy_behavior_is_explicit() -> Result<()> {
    let config = RtcConfiguration::default();
    assert_eq!(config.bundle_policy, BundlePolicy::MaxBundle);
    config.validate_runtime_support()?;

    let mut unsupported = RtcConfiguration::default();
    unsupported.bundle_policy = BundlePolicy::Balanced;
    let err = match unsupported.validate_runtime_support() {
        Ok(_) => panic!("unsupported bundle policy should fail before runtime"),
        Err(err) => err,
    };
    assert!(
        matches!(err, RtcError::InvalidConfiguration(ref message) if message.contains("bundle_policy") && message.contains("MaxBundle")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn unsupported_config_is_not_silently_ignored() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.rtp_start_port = Some(40000);

    let err = match IceTransport::try_new(config) {
        Ok(_) => panic!("partial RTP port range should fail instead of being ignored"),
        Err(err) => err,
    };
    assert!(
        matches!(err, RtcError::InvalidConfiguration(ref message) if message.contains("rtp_start_port") && message.contains("rtp_end_port")),
        "unexpected error: {err:?}"
    );
    Ok(())
}
