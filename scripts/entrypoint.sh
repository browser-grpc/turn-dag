#!/bin/sh
# In-container arg dispatch only; build/test logic itself is in the Dockerfile stages.
set -eu
cmd="${1:-run}"
case "$cmd" in
  test) cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace ;;
  build) cargo build --workspace && cargo build --workspace --release -p turn-dag-node ;;
  ci) cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace ;;
  tool) exec /bin/bash ;;
  run) exec turn-dag-node demo ;;
  *) exec turn-dag-node "$@" ;;
esac
