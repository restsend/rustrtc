#![cfg(not(feature = "std"))]

//! G1: platform seams under the no_std build — backends that work without
//! any injection, plus an embedder-style `UdpSocket` implementation
//! round-tripping through the trait + bind factory.
//!
//! Injection contracts (`rng::fill` / `task::sleep` panic when unset) are
//! covered in `platform_seams_injected.rs`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use rustrtc::platform::net::{NetError, UdpSocket, set_udp_bind_fn};
use rustrtc::platform::time::{Instant, advance_ms, set_now_ms};

// ── logical clock ────────────────────────────────────────────────────────

#[test]
fn logical_clock_contract() {
    // One test: the logical clock is process-global and sibling tests run
    // in parallel, so absolute-clock assertions must stay in one place.
    set_now_ms(1_000);
    let t0 = Instant::now();
    advance_ms(150);
    assert_eq!(t0.elapsed().as_millis(), 150);
    assert_eq!(t0.duration_since(Instant::now()).as_millis(), 0);
    set_now_ms(1_150);
    assert_eq!(t0.elapsed().as_millis(), 150);

    // advance_ms always moves the clock by at least one tick.
    let before = Instant::now();
    advance_ms(0);
    let after = Instant::now();
    assert!(after.duration_since(before).as_millis() >= 1);
}

// ── embedder-style UdpSocket + bind factory ──────────────────────────────

/// Minimal rtcembed-shaped backend: an inbox per port, single reader.
struct LoopSock {
    local: SocketAddr,
}

fn inboxes() -> &'static Mutex<HashMap<u16, VecDeque<(SocketAddr, Vec<u8>)>>> {
    static INBOXES: OnceLock<Mutex<HashMap<u16, VecDeque<(SocketAddr, Vec<u8>)>>>> =
        OnceLock::new();
    INBOXES.get_or_init(|| Mutex::new(HashMap::new()))
}

impl LoopSock {
    fn bind(addr: SocketAddr) -> Result<Arc<Self>, NetError> {
        inboxes().lock().unwrap().entry(addr.port()).or_default();
        Ok(Arc::new(Self { local: addr }))
    }
}

#[async_trait::async_trait]
impl UdpSocket for LoopSock {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        let packet = inboxes()
            .lock()
            .unwrap()
            .get_mut(&self.local.port())
            .and_then(|q| q.pop_front());
        match packet {
            Some((from, data)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok((len, from))
            }
            None => Err(NetError::Closed),
        }
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
        if let Some(q) = inboxes().lock().unwrap().get_mut(&addr.port()) {
            q.push_back((self.local, buf.to_vec()));
            Ok(buf.len())
        } else {
            // UDP semantics: no listener → datagram dropped.
            Ok(buf.len())
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.local)
    }
}

#[test]
fn udp_bind_factory_installs_and_the_trait_round_trips() {
    fn factory(addr: SocketAddr) -> Result<Arc<dyn UdpSocket>, rustrtc::errors::RtcError> {
        use rustrtc::errors::RtcError;
        LoopSock::bind(addr)
            .map_err(RtcError::from)
            .map(|s| s as Arc<dyn UdpSocket>)
    }
    set_udp_bind_fn(factory);

    let a = LoopSock::bind("127.0.0.1:41000".parse().unwrap()).unwrap();
    let b = LoopSock::bind("127.0.0.1:41001".parse().unwrap()).unwrap();
    assert_eq!(b.local_addr().unwrap().port(), 41001);

    // a → b, then b echoes back — the exact shape rtcembed's demux serves.
    block_on(async {
        a.send_to(b"hello-embed", b.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (len, from) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello-embed");
        assert_eq!(from, a.local_addr().unwrap());

        b.send_to(b"pong", from).await.unwrap();
        let (len, _) = a.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"pong");
    });
}

// ── sync_embedded contract guards ────────────────────────────────────────

#[test]
fn broadcast_channel_stays_open_while_sender_is_alive() {
    let (tx, mut rx) = rustrtc::platform::sync::broadcast::channel::<u32>(16);
    let mut rx2 = tx.subscribe();
    let _keep = tx.clone();
    drop(rx);
    use rustrtc::platform::sync::broadcast::TryRecvError;
    assert!(
        matches!(rx2.try_recv(), Err(TryRecvError::Empty)),
        "an alive sender must keep the channel open"
    );
    tx.send(1).unwrap();
    assert_eq!(rx2.try_recv().ok(), Some(1));
}

// ── helpers ──────────────────────────────────────────────────────────────

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn clone_raw(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop_raw(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_raw, noop_raw, noop_raw, noop_raw);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

// ── watch: per-receiver cursor ───────────────────────────────────────────

/// Regression: `seen` used to live on the *shared* inner, so with two
/// receivers whichever polled `changed()` first consumed the version bump and
/// the second silently missed the update. In the PeerConnection that meant the
/// DTLS loop could miss ICE `Connected` (the ICE-state monitor consumed it
/// first) and therefore never call `start_dtls` — the intermittent
/// "ICE connects but no media" failure. Every receiver must observe every
/// update on its own cursor.
#[test]
fn watch_every_receiver_observes_each_update() {
    use rustrtc::platform::sync::watch;

    let (tx, _rx0) = watch::channel(0u8);
    let r1 = tx.subscribe();
    let r2 = tx.subscribe();
    tx.send(1).unwrap();

    assert!(
        poll_once(r1.changed()).is_ready(),
        "receiver 1 must observe the update"
    );
    assert!(
        poll_once(r2.changed()).is_ready(),
        "receiver 2 must also observe it (shared-`seen` regression)"
    );

    // A freshly subscribed receiver starts caught up and only sees later writes.
    let r3 = tx.subscribe();
    assert!(
        poll_once(r3.changed()).is_pending(),
        "a fresh receiver must not replay the current value"
    );
    tx.send(2).unwrap();
    assert!(
        poll_once(r3.changed()).is_ready(),
        "a fresh receiver must observe subsequent updates"
    );
}

fn poll_once<F: core::future::Future>(fut: F) -> core::task::Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    fut.as_mut().poll(&mut cx)
}
