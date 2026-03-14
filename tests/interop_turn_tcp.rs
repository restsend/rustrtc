use anyhow::Result;

#[path = "clients/local_turn_server/mod.rs"]
mod local_turn_server;
#[path = "clients/turn_interop_case.rs"]
mod turn_interop_case;

use local_turn_server::LocalTurnServer;

#[tokio::test]
async fn interop_turn_tcp_datachannel_test() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let server = LocalTurnServer::start().await?;
    let result =
        turn_interop_case::run_turn_datachannel_roundtrip(server.turn_tcp_url(), false).await;
    server.stop().await;
    result
}
