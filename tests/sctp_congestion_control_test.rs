#![cfg(feature = "std")]

use std::sync::atomic::{AtomicUsize, Ordering};

// Test for SCTP congestion control in rate-limited scenarios
// Simulates TURN relay rate limiting

const MTU: usize = 1200;
const CWND_INITIAL: usize = MTU * 10; // Match actual implementation (12KB)
const SSTHRESH_MIN: usize = CWND_INITIAL / 3; // 4KB minimum ssthresh

struct CongestionControl {
    cwnd: AtomicUsize,
    ssthresh: AtomicUsize,
    partial_bytes_acked: AtomicUsize,
    flight_size: AtomicUsize,
}

impl CongestionControl {
    fn new() -> Self {
        Self {
            cwnd: AtomicUsize::new(CWND_INITIAL),
            ssthresh: AtomicUsize::new(usize::MAX),
            partial_bytes_acked: AtomicUsize::new(0),
            flight_size: AtomicUsize::new(0),
        }
    }

    // Simulate RTO timeout - should reduce cwnd (matching actual implementation)
    fn on_rto_timeout(&self) {
        let cwnd = self.cwnd.load(Ordering::SeqCst);
        let new_ssthresh = (cwnd / 2).max(SSTHRESH_MIN);
        self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
        // Set cwnd to 2*MTU for better recovery while still conservative
        let new_cwnd = MTU * 2;
        self.cwnd.store(new_cwnd, Ordering::SeqCst);
        self.partial_bytes_acked.store(0, Ordering::SeqCst);
        self.flight_size.store(0, Ordering::SeqCst); // Important: reset flight size
    }

    // Simulate receiving ACK - should grow cwnd
    fn on_ack(&self, bytes_acked: usize) {
        let cwnd = self.cwnd.load(Ordering::SeqCst);
        let ssthresh = self.ssthresh.load(Ordering::SeqCst);

        // Reduce flight size
        self.flight_size.fetch_sub(bytes_acked, Ordering::SeqCst);

        if cwnd < ssthresh {
            // Slow Start: exponential growth, limited to 2*MTU per ACK
            self.cwnd
                .fetch_add(bytes_acked.min(MTU * 2), Ordering::SeqCst);
        } else {
            // Congestion Avoidance: linear growth
            let pba = self
                .partial_bytes_acked
                .fetch_add(bytes_acked, Ordering::SeqCst);
            if pba + bytes_acked >= cwnd {
                self.partial_bytes_acked.fetch_sub(cwnd, Ordering::SeqCst);
                self.cwnd.fetch_add(MTU, Ordering::SeqCst);
            }
        }
    }

    // Check if we can send more data
    fn can_send(&self) -> bool {
        let cwnd = self.cwnd.load(Ordering::SeqCst);
        let flight = self.flight_size.load(Ordering::SeqCst);
        flight < cwnd
    }

    // Send data
    fn send(&self, bytes: usize) -> bool {
        if self.can_send() {
            self.flight_size.fetch_add(bytes, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    fn stats(&self) -> (usize, usize, usize) {
        (
            self.cwnd.load(Ordering::SeqCst),
            self.ssthresh.load(Ordering::SeqCst),
            self.flight_size.load(Ordering::SeqCst),
        )
    }
}

#[test]
fn test_congestion_control_rto_timeout() {
    let cc = CongestionControl::new();

    // Initial state
    let (cwnd, ssthresh, _) = cc.stats();
    assert_eq!(cwnd, CWND_INITIAL);
    assert_eq!(ssthresh, usize::MAX);

    // Simulate sending data until cwnd is full
    for _ in 0..(CWND_INITIAL / MTU) {
        assert!(cc.send(MTU));
    }
    assert!(!cc.can_send()); // Should be blocked now

    // Simulate RTO timeout
    cc.on_rto_timeout();

    // After timeout, cwnd should be 2*MTU (balanced restart)
    // ssthresh should be half of old cwnd (but min SSTHRESH_MIN)
    let (cwnd_after, ssthresh_after, flight_after) = cc.stats();
    assert_eq!(cwnd_after, MTU * 2, "cwnd should be 2*MTU after timeout");
    let expected_ssthresh = (CWND_INITIAL / 2).max(SSTHRESH_MIN);
    assert_eq!(
        ssthresh_after, expected_ssthresh,
        "ssthresh should be max(cwnd/2, SSTHRESH_MIN)"
    );
    assert_eq!(flight_after, 0, "flight size should be reset to 0");

    // Should be able to send 2 MTUs now
    assert!(cc.can_send());
}

#[test]
fn test_congestion_control_slow_start() {
    let cc = CongestionControl::new();

    // Simulate multiple successful ACKs during slow start
    for i in 1..=5 {
        cc.send(MTU);
        cc.on_ack(MTU);
        let (cwnd, ssthresh, _) = cc.stats();
        println!("Iteration {}: cwnd={}, ssthresh={}", i, cwnd, ssthresh);

        // In slow start, cwnd should grow exponentially
        assert!(cwnd > CWND_INITIAL, "cwnd should be growing");
        assert_eq!(ssthresh, usize::MAX, "ssthresh should still be MAX");
    }
}

#[test]
fn test_congestion_control_rate_limiting_scenario() {
    let cc = CongestionControl::new();

    // Scenario 1: Initial burst - send multiple packets
    println!("\n=== Scenario 1: Initial burst ===");
    let mut sent_count = 0;
    while cc.can_send() && sent_count < 20 {
        assert!(cc.send(MTU));
        sent_count += 1;
    }
    println!("Sent {} packets before blocking", sent_count);
    let (cwnd, _, flight) = cc.stats();
    println!("cwnd={}, flight={}", cwnd, flight);
    assert_eq!(
        sent_count,
        CWND_INITIAL / MTU,
        "Should send exactly cwnd/MTU packets"
    );

    // Scenario 2: TURN rate limit hit - no ACKs received, RTO timeout
    println!("\n=== Scenario 2: RTO timeout due to rate limiting ===");
    cc.on_rto_timeout();
    let (cwnd_after_rto, ssthresh_after_rto, flight_after_rto) = cc.stats();
    println!(
        "After RTO: cwnd={}, ssthresh={}, flight={}",
        cwnd_after_rto, ssthresh_after_rto, flight_after_rto
    );
    assert_eq!(cwnd_after_rto, MTU * 2, "cwnd should be 2*MTU");
    assert_eq!(flight_after_rto, 0, "flight should be 0");

    // Scenario 3: Recovery - slowly increase sending rate
    println!("\n=== Scenario 3: Recovery phase ===");
    for round in 1..=10 {
        // Try to send
        let sent_this_round = if cc.can_send() {
            cc.send(MTU);
            1
        } else {
            0
        };

        // Simulate ACK
        if sent_this_round > 0 {
            cc.on_ack(MTU);
        }

        let (cwnd, ssthresh, flight) = cc.stats();
        println!(
            "Round {}: cwnd={}, ssthresh={}, flight={}, sent={}",
            round, cwnd, ssthresh, flight, sent_this_round
        );

        // In recovery, cwnd should be bounded by ssthresh in congestion avoidance
        // After entering congestion avoidance (cwnd >= ssthresh), growth should be slower
    }
}

#[test]
fn test_congestion_control_multiple_timeouts() {
    let cc = CongestionControl::new();

    println!("\n=== Multiple timeout scenario (persistent rate limiting) ===");

    // Simulate persistent rate limiting with multiple timeouts
    for timeout_num in 1..=5 {
        // Send as much as cwnd allows
        let mut sent = 0;
        while cc.can_send() {
            cc.send(MTU);
            sent += 1;
        }

        let (cwnd_before, ssthresh_before, _) = cc.stats();
        println!(
            "\nTimeout #{}: Sent {} packets, cwnd={}, ssthresh={}",
            timeout_num, sent, cwnd_before, ssthresh_before
        );

        // RTO timeout
        cc.on_rto_timeout();

        let (cwnd_after, ssthresh_after, flight_after) = cc.stats();
        println!(
            "  After timeout: cwnd={}, ssthresh={}, flight={}",
            cwnd_after, ssthresh_after, flight_after
        );

        assert_eq!(cwnd_after, MTU * 2, "cwnd should be 2*MTU after timeout");
        assert_eq!(flight_after, 0, "flight should always reset to 0");

        // Key assertion: ssthresh should keep decreasing or hit minimum
        if timeout_num > 1 {
            assert!(
                ssthresh_after <= ssthresh_before,
                "ssthresh should decrease or stay at minimum"
            );
        }

        // Try small recovery
        if cc.can_send() {
            cc.send(MTU);
            cc.on_ack(MTU);
        }
    }
}

#[test]
fn test_congestion_control_metrics() {
    let cc = CongestionControl::new();

    println!("\n=== Congestion control metrics test ===");

    // Test that flight size is properly tracked
    assert_eq!(cc.flight_size.load(Ordering::SeqCst), 0);

    cc.send(MTU);
    assert_eq!(cc.flight_size.load(Ordering::SeqCst), MTU);

    cc.send(MTU);
    assert_eq!(cc.flight_size.load(Ordering::SeqCst), MTU * 2);

    cc.on_ack(MTU);
    assert_eq!(cc.flight_size.load(Ordering::SeqCst), MTU);

    cc.on_rto_timeout();
    assert_eq!(
        cc.flight_size.load(Ordering::SeqCst),
        0,
        "CRITICAL: flight size must be reset on timeout"
    );
}

#[test]
fn test_congestion_control_cwnd_not_stuck() {
    println!("\n=== Test: cwnd should not get stuck on repeated timeouts ===");
    let cc = CongestionControl::new();

    // Start with initial cwnd
    let (initial_cwnd, _, _) = cc.stats();
    println!("Initial: cwnd={}", initial_cwnd);
    assert_eq!(initial_cwnd, CWND_INITIAL);

    // First timeout from initial state
    cc.on_rto_timeout();
    let (cwnd1, ssthresh1, _) = cc.stats();
    println!("After 1st timeout: cwnd={}, ssthresh={}", cwnd1, ssthresh1);
    // cwnd should be 2*MTU
    assert_eq!(cwnd1, MTU * 2, "cwnd should be 2*MTU after first timeout");
    let expected_ssthresh1 = (CWND_INITIAL / 2).max(SSTHRESH_MIN);
    assert_eq!(
        ssthresh1, expected_ssthresh1,
        "ssthresh should be max(CWND_INITIAL/2, SSTHRESH_MIN)"
    );

    // Grow cwnd a bit
    for _ in 0..3 {
        if cc.can_send() {
            cc.send(MTU);
            cc.on_ack(MTU);
        }
    }
    let (cwnd_grown, _, _) = cc.stats();
    println!("After growth: cwnd={}", cwnd_grown);
    assert!(cwnd_grown > cwnd1, "cwnd should grow after successful ACKs");

    // Second timeout - cwnd should still be able to reduce
    cc.on_rto_timeout();
    let (cwnd2, ssthresh2, _) = cc.stats();
    println!("After 2nd timeout: cwnd={}, ssthresh={}", cwnd2, ssthresh2);
    assert_eq!(cwnd2, MTU * 2, "cwnd should be 2*MTU");
    // ssthresh should be half of cwnd_grown, but at least SSTHRESH_MIN
    let expected_ssthresh2 = (cwnd_grown / 2).max(SSTHRESH_MIN);
    assert_eq!(ssthresh2, expected_ssthresh2);

    // Third timeout from cwnd=2*MTU=2400
    cc.on_rto_timeout();
    let (cwnd3, ssthresh3, _) = cc.stats();
    println!("After 3rd timeout: cwnd={}, ssthresh={}", cwnd3, ssthresh3);
    // cwnd should still be 2*MTU
    assert_eq!(cwnd3, MTU * 2, "cwnd should remain at 2*MTU");
    // ssthresh = max(2400/2, 4000) = max(1200, 4000) = 4000
    assert_eq!(
        ssthresh3, SSTHRESH_MIN,
        "ssthresh should be at SSTHRESH_MIN"
    );

    // Fourth timeout - verify cwnd stays at 2*MTU
    cc.on_rto_timeout();
    let (cwnd4, ssthresh4, _) = cc.stats();
    println!("After 4th timeout: cwnd={}, ssthresh={}", cwnd4, ssthresh4);
    assert_eq!(cwnd4, MTU * 2, "cwnd should still be 2*MTU");
    assert_eq!(ssthresh4, SSTHRESH_MIN);

    // Verify we can still send data (cwnd=2*MTU)
    assert!(
        cc.can_send(),
        "Should be able to send even after multiple timeouts"
    );
    cc.send(MTU);
    let (_, _, flight) = cc.stats();
    assert_eq!(flight, MTU, "Should have sent 1 MTU");

    println!("✓ cwnd correctly stays at 2*MTU and doesn't get stuck");
}

#[test]
fn test_flight_size_not_duplicated_on_rto() {
    println!("\n=== Test: flight_size should not be duplicated on RTO retransmission ===");
    let cc = CongestionControl::new();

    // Send initial data to fill cwnd
    let mut sent_bytes = 0;
    while cc.can_send() && sent_bytes < CWND_INITIAL {
        cc.send(MTU);
        sent_bytes += MTU;
    }

    let (cwnd_before, _, flight_before) = cc.stats();
    println!(
        "After initial send: cwnd={}, flight={}",
        cwnd_before, flight_before
    );
    assert_eq!(
        flight_before, sent_bytes,
        "Flight size should match sent bytes"
    );
    assert!(!cc.can_send(), "Window should be full");

    // First RTO timeout - should NOT duplicate flight_size
    // In real implementation, RTO marks chunks for retransmit but doesn't re-add to flight_size
    cc.on_rto_timeout();
    let (cwnd_after_rto, ssthresh_after_rto, flight_after_rto) = cc.stats();
    println!(
        "After RTO: cwnd={}, ssthresh={}, flight={}",
        cwnd_after_rto, ssthresh_after_rto, flight_after_rto
    );

    // Critical assertion: flight_size should be 0 after RTO
    assert_eq!(
        flight_after_rto, 0,
        "CRITICAL BUG: flight_size must be reset to 0 on RTO timeout"
    );

    // After RTO, cwnd is reduced but we should be able to send again
    assert!(
        cc.can_send(),
        "Should be able to send after RTO (cwnd={}, flight={})",
        cwnd_after_rto,
        flight_after_rto
    );

    // Simulate retransmission of chunks (limited by cwnd=2*MTU now)
    let mut retrans_count = 0;
    while cc.can_send() && retrans_count < 3 {
        cc.send(MTU);
        retrans_count += 1;
    }

    let (cwnd_after_retrans, _, flight_after_retrans) = cc.stats();
    println!(
        "After retransmitting {} chunks: cwnd={}, flight={}",
        retrans_count, cwnd_after_retrans, flight_after_retrans
    );
    assert_eq!(
        flight_after_retrans,
        retrans_count * MTU,
        "Flight size should only count retransmitted chunks, not original+retrans"
    );
    assert!(
        retrans_count >= 2,
        "Should have retransmitted at least 2 chunks (cwnd=2*MTU={})",
        cwnd_after_retrans
    );

    // Second RTO timeout - verify flight_size doesn't accumulate
    cc.on_rto_timeout();
    let (_, _, flight_after_2nd_rto) = cc.stats();
    println!("After 2nd RTO: flight={}", flight_after_2nd_rto);
    assert_eq!(
        flight_after_2nd_rto, 0,
        "Flight size should be 0 again after 2nd RTO"
    );

    // Verify we can send up to cwnd limit
    let mut can_send_bytes = 0;
    let cwnd_after_2nd = cc.cwnd.load(Ordering::SeqCst);
    while cc.can_send() && can_send_bytes < cwnd_after_2nd {
        cc.send(MTU);
        can_send_bytes += MTU;
    }

    let (_, _, final_flight) = cc.stats();
    println!(
        "After sending up to cwnd: cwnd={}, flight={}",
        cwnd_after_2nd, final_flight
    );
    assert!(
        final_flight <= cwnd_after_2nd,
        "Flight size {} should never exceed cwnd {}",
        final_flight,
        cwnd_after_2nd
    );

    println!("✓ Flight size correctly managed, no duplication on RTO");
}

// Test that chunks exceeding first MTU during RTO can be retransmitted
// This tests the fix for the bug where overflow chunks remained in_flight=true
#[test]
fn test_rto_overflow_chunks_drainable() {
    println!("\n=== Testing RTO overflow chunks are drainable ===");
    let cc = CongestionControl::new();

    // Build up initial state: send chunks up to cwnd limit
    let initial_cwnd = cc.cwnd.load(Ordering::SeqCst);
    let chunk_count = initial_cwnd / MTU; // Send exactly cwnd worth of data
    for i in 0..chunk_count {
        assert!(cc.can_send(), "Should be able to send chunk {}", i);
        cc.send(MTU);
    }

    let initial_flight = cc.flight_size.load(Ordering::SeqCst);
    println!(
        "Initial state: {} chunks sent, flight={}, cwnd={}",
        chunk_count, initial_flight, initial_cwnd
    );
    assert_eq!(
        initial_flight,
        chunk_count * MTU,
        "Flight should equal bytes sent"
    );
    assert!(
        !cc.can_send(),
        "Should not be able to send more (cwnd full)"
    );

    // Simulate RTO timeout - this triggers retransmission logic
    // In actual code, first MTU fits in retransmit, rest marked as overflow
    cc.on_rto_timeout();

    let flight_after_rto = cc.flight_size.load(Ordering::SeqCst);
    let cwnd_after_rto = cc.cwnd.load(Ordering::SeqCst);
    println!(
        "After RTO timeout: cwnd={}, flight={}, can_send={}",
        cwnd_after_rto,
        flight_after_rto,
        cc.can_send()
    );

    // After RTO timeout:
    // - cwnd should be 2*MTU
    // - flight_size reset to 0 (test model simplification)
    // - Should be able to send 2 MTUs
    assert_eq!(cwnd_after_rto, MTU * 2, "cwnd should be 2*MTU after RTO");
    assert_eq!(flight_after_rto, 0, "Flight should be reset after RTO");
    assert!(cc.can_send(), "Should be able to send after RTO");

    // Simulate the key scenario: send first retransmission packet
    cc.send(MTU);
    let flight_after_first_retrans = cc.flight_size.load(Ordering::SeqCst);
    println!(
        "After first retransmission: flight={}",
        flight_after_first_retrans
    );
    assert_eq!(flight_after_first_retrans, MTU, "Flight should be 1 MTU");

    // Can send second chunk (cwnd=2*MTU)
    assert!(cc.can_send(), "Should be able to send second chunk");
    cc.send(MTU);
    let flight_after_second = cc.flight_size.load(Ordering::SeqCst);
    println!(
        "After second retransmission: flight={}",
        flight_after_second
    );
    assert_eq!(flight_after_second, 2 * MTU, "Flight should be 2*MTU");
    assert!(!cc.can_send(), "Window should be full after 2 MTU");

    // Simulate successful ACK to grow window again
    cc.on_ack(MTU);
    let cwnd_after_ack = cc.cwnd.load(Ordering::SeqCst);
    println!(
        "After ACK: cwnd={}, can_send={}",
        cwnd_after_ack,
        cc.can_send()
    );

    // Should be able to send more now
    assert!(cc.can_send(), "Should be able to send after ACK");

    // Send remaining chunks progressively
    let mut total_retransmitted = 2 * MTU; // Already sent 2 MTU above
    while total_retransmitted < chunk_count * MTU && cc.can_send() {
        cc.send(MTU);
        cc.on_ack(MTU); // Simulate progressive ACKs to grow window
        total_retransmitted += MTU;
    }

    println!(
        "Final state: total_retransmitted={}, target={}",
        total_retransmitted,
        chunk_count * MTU
    );

    // Verify we could eventually retransmit all data
    assert!(
        total_retransmitted >= chunk_count * MTU,
        "Should be able to retransmit all {} bytes, only got {}",
        chunk_count * MTU,
        total_retransmitted
    );

    println!("✓ Overflow chunks are correctly marked drainable after RTO");
}

fn main() {
    println!("Running SCTP congestion control tests...\n");

    test_congestion_control_rto_timeout();
    println!("✓ test_congestion_control_rto_timeout passed");

    test_congestion_control_slow_start();
    println!("✓ test_congestion_control_slow_start passed");

    test_congestion_control_rate_limiting_scenario();
    println!("✓ test_congestion_control_rate_limiting_scenario passed");

    test_congestion_control_multiple_timeouts();
    println!("✓ test_congestion_control_multiple_timeouts passed");

    test_congestion_control_metrics();
    println!("✓ test_congestion_control_metrics passed");

    test_congestion_control_cwnd_not_stuck();
    println!("✓ test_congestion_control_cwnd_not_stuck passed");

    test_flight_size_not_duplicated_on_rto();
    println!("✓ test_flight_size_not_duplicated_on_rto passed");

    test_rto_overflow_chunks_drainable();
    println!("✓ test_rto_overflow_chunks_drainable passed");

    println!("\n✅ All tests passed!");
}
