#!/bin/sh
# In-container only: Playwright WebRTC suite against the live TURN server.
# Host networking gives the browsers a real LAN path to the relay, so
# gather/relay/issuer failures are hard failures here (REQUIRE_RELAY=1)
# and at least MIN_PASS sub-tests must pass.
set -eu
cd "$(dirname "$0")/.."
HOST="$(hostname -I | awk '{print $1}')"
if [ -z "$HOST" ]; then
  echo "no host IP found; running with TURN_HOST=127.0.0.1 (relay sub-tests will SKIP)"
  HOST=127.0.0.1
  exec env TURN_HOST="$HOST" BROWSERS="${BROWSERS:-firefox,chromium,webkit}" node tests/browser/run.mjs
fi
exec env TURN_HOST="$HOST" REQUIRE_RELAY=1 MIN_PASS="${MIN_PASS:-10}" BROWSERS="${BROWSERS:-firefox,chromium,webkit}" node tests/browser/run.mjs
