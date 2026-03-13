#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GROUP="${1:-all}"

run_cmd() {
  echo "+ $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  )
}

# Keep these groups aligned with docs/rustrtc-issue-task-checklist.md so the
# script doubles as the local execution map for ISSUE-01 and later protocol work.
run_group() {
  case "$1" in
    security)
      run_cmd cargo test --test regression_baseline regression_security_entrypoints_exist
      run_cmd cargo test --lib test_dtls_handshake_full_flow
      run_cmd cargo test --lib test_dtls_handshake_fails_on_fingerprint_mismatch
      ;;
    signaling)
      run_cmd cargo test --test regression_baseline regression_signaling_entrypoints_exist
      run_cmd cargo test --test rtp_reinvite_comprehensive_test
      ;;
    datachannel)
      run_cmd cargo test --test regression_baseline regression_datachannel_entrypoints_exist
      run_cmd cargo test --test ordered_channel_test
      run_cmd cargo test --test interop_datachannel
      ;;
    network)
      run_cmd cargo test --test regression_baseline regression_network_entrypoints_exist
      run_cmd cargo test --test interop_turn
      ;;
    media)
      run_cmd cargo test --test regression_baseline regression_media_entrypoints_exist
      run_cmd cargo test --test media_flow
      run_cmd cargo test --test interop_simulcast
      ;;
    stats)
      run_cmd cargo test --test regression_baseline regression_stats_entrypoints_exist
      ;;
    *)
      echo "unknown group: $1" >&2
      exit 1
      ;;
  esac
}

case "${GROUP}" in
  list)
    printf '%s\n' security signaling datachannel network media stats all
    ;;
  all)
    run_cmd cargo check
    run_cmd cargo check --tests --examples
    for group in security signaling datachannel network media stats; do
      run_group "${group}"
    done
    ;;
  security|signaling|datachannel|network|media|stats)
    run_group "${GROUP}"
    ;;
  *)
    echo "usage: $(basename "$0") [security|signaling|datachannel|network|media|stats|all|list]" >&2
    exit 1
    ;;
esac
