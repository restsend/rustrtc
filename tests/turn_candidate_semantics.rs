use anyhow::{Result, anyhow};
use rustrtc::{
    IceCandidateType, IceGathererState, IceServer, IceTransportPolicy, RtcConfiguration,
};
use std::time::{Duration, Instant};

#[path = "clients/local_turn_server/mod.rs"]
mod local_turn_server;

use local_turn_server::LocalTurnServer;

const TEST_USERNAME: &str = "turn-user";
const TEST_PASSWORD: &str = "turn-password";

#[tokio::test]
async fn relay_candidate_from_turn_tcp_still_advertises_udp() -> Result<()> {
    let server = LocalTurnServer::start().await?;
    let result = assert_relay_candidate_transport(server.turn_tcp_url(), false).await;
    server.stop().await;
    result
}

#[tokio::test]
async fn relay_candidate_from_turns_still_advertises_udp() -> Result<()> {
    let server = LocalTurnServer::start().await?;
    let result = assert_relay_candidate_transport(server.turns_url(), true).await;
    server.stop().await;
    result
}

async fn assert_relay_candidate_transport(
    url: String,
    allow_insecure_turn_tls: bool,
) -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.allow_insecure_turn_tls = allow_insecure_turn_tls;
    config
        .ice_servers
        .push(IceServer::new(vec![url]).with_credential(TEST_USERNAME, TEST_PASSWORD));

    let (transport, runner) = rustrtc::transports::ice::IceTransportBuilder::new(config).build();
    let task = tokio::spawn(runner);
    wait_for_gather_complete(&transport).await?;

    let relay = transport
        .local_candidates()
        .into_iter()
        .find(|candidate| candidate.typ == IceCandidateType::Relay)
        .ok_or_else(|| anyhow!("relay candidate missing"))?;

    assert_eq!(relay.transport, "udp");

    task.abort();
    Ok(())
}

async fn wait_for_gather_complete(transport: &rustrtc::IceTransport) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if transport.gather_state() == IceGathererState::Complete {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("timed out waiting for ICE gathering to complete"))
}
