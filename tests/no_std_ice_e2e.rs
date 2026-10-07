#![cfg(not(feature = "std"))]

//! G1 capstone: full ICE connectivity over an in-process loopback network,
//! driving two `IceTransport`s to `Connected` with the mock runtime that an
//! embedded integration (rtcembed) would provide. The runtime itself lives
//! in `tests/common/` — this file only wires the scenario.

mod common;

use common::{drive_until, install_mock_platform};
use rustrtc::transports::ice::{IceCandidate, IceCandidateType, IceRole, IceTransport, IceTransportState};

#[test]
fn two_ice_agents_connect_over_the_loopback_seams() {
    install_mock_platform();

    // Two agents, distinct even-port ranges so LoopNet hands them
    // different ports (AddrInUse retry exercised if a port collides).
    fn agent(start: u16, end: u16) -> IceTransport {
        let mut cfg = rustrtc::config::RtcConfiguration::default();
        cfg.bind_ip = Some("127.0.0.1".to_string());
        cfg.rtp_start_port = Some(start);
        cfg.rtp_end_port = Some(end);
        let (transport, runner) = IceTransport::new(cfg);
        common::keep_task(Box::new(runner));
        transport
    }

    let a = agent(30_000, 30_020);
    let b = agent(31_000, 31_020);
    a.set_role(IceRole::Controlling);
    b.set_role(IceRole::Controlled);

    // 1. Gather host candidates through the factory.
    a.start_gathering().unwrap();
    b.start_gathering().unwrap();
    let gathered = drive_until(
        || {
            a.gather_state() == rustrtc::transports::ice::IceGathererState::Complete
                && b.gather_state() == rustrtc::transports::ice::IceGathererState::Complete
        },
        2_000,
    );
    assert!(gathered, "gathering must complete on the loopback seams");
    let a_cands = a.local_candidates();
    let b_cands = b.local_candidates();
    assert!(
        a_cands
            .iter()
            .any(|c: &IceCandidate| c.typ == IceCandidateType::Host),
        "agent A must have a host candidate from the factory socket, got {a_cands:?}"
    );

    // 2. Exchange credentials + candidates (the signaling hop).
    a.set_remote_parameters(b.local_parameters());
    b.set_remote_parameters(a.local_parameters());
    for c in &b_cands {
        a.add_remote_candidate(c.clone());
    }
    for c in &a_cands {
        b.add_remote_candidate(c.clone());
    }

    // 3. Start connectivity checks; STUN bindings flow over LoopNet.
    // `start` is async but resolves in a few polls (command sends only).
    common::block_on(a.start(b.local_parameters())).unwrap();
    common::block_on(b.start(a.local_parameters())).unwrap();

    let connected = drive_until(
        || {
            a.state() == IceTransportState::Connected
                && b.state() == IceTransportState::Connected
                && a.get_selected_pair().is_some()
                && b.get_selected_pair().is_some()
        },
        30_000,
    );
    eprintln!(
        "connect done={connected} a={:?} b={:?} a_pair={:?} sim_clock={}ms",
        a.state(),
        b.state(),
        a.get_selected_pair(),
        common::clock(),
    );
    assert!(
        connected,
        "both agents must reach Connected with a nominated pair"
    );

    // 4. Stop both agents cleanly (runner teardown over the seams).
    a.stop();
    b.stop();
    let _ = drive_until(
        || a.state() == IceTransportState::Closed && b.state() == IceTransportState::Closed,
        2_000,
    );
}
