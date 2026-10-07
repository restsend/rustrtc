#!/bin/sh
# G1/G2 no_std gates (run from the repo root):
#   1. no_std lib check (host)
#   2. no_std cross check — riscv32imac-unknown-none-elf (ESP32-C3 core;
#      no 64-bit atomics → exercises platform::atomic64's shim)
#   3. no_std platform-seam tests (logical clock + injected backends)
#   4. std build stays green (feature matrix guard)
set -e
cd "$(dirname "$0")/.."

echo "== [1/5] cargo check --lib --no-default-features"
cargo check --lib --no-default-features

echo "== [2/5] cargo check --lib --no-default-features --target riscv32imac-unknown-none-elf"
if rustup target list --installed | grep -q riscv32imac-unknown-none-elf; then
    cargo check --lib --no-default-features --target riscv32imac-unknown-none-elf
else
    echo "   SKIP: target not installed (rustup target add riscv32imac-unknown-none-elf)"
fi

echo "== [3/5] cargo test --test platform_seams_* + no_std e2e --no-default-features"
cargo test --test platform_seams_logical --no-default-features
cargo test --test platform_seams_injected --no-default-features
cargo test --test platform_seams_strict --no-default-features
cargo test --test no_std_ice_e2e --no-default-features
cargo test --test no_std_pc_srtp_e2e --no-default-features

echo "== [4/5] no_std DTLS e2e (crypto-p256 backend)"
cargo test --test no_std_dtls_e2e --no-default-features --features crypto-p256

echo "== [5/5] cargo check --lib (std matrix guard)"

cargo check --lib

echo "all no_std gates passed"
