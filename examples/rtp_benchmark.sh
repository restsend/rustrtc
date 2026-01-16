#!/bin/bash
CONCURRENCY=${1:-4}
echo "Running RTP benchmark with concurrency: $CONCURRENCY"

# Use release mode for benchmarks
cargo build --release --examples

pkill -f rtp_bench_sut
pkill -f rtp_bench_generator
pkill -f rtp_bench_echo

echo "Starting Echo Server..."
../target/release/examples/rtp_bench_echo &
ECHO_PID=$!
sleep 1

echo "Starting SUT..."
# Use release binary
RUST_LOG=rustrtc=info,rtp_bench_sut=info ../target/release/examples/rtp_bench_sut > sut.log 2>&1 &
SUT_PID=$!
sleep 2

echo "Starting Generator..."
../target/release/examples/rtp_bench_generator $CONCURRENCY

echo "Cleaning up..."
kill $SUT_PID
kill $ECHO_PID
