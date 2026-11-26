#!/bin/sh
# In-container only: Playwright WebRTC suite against the live TURN server.
# Host networking gives the browsers a real LAN path to the relay, so
# gather/relay/issuer failures are hard failures here (REQUIRE_RELAY=1)
# and at least MIN_PASS sub-tests must pass.
# With /dev/net/tun + NET_ADMIN (docker run --device /dev/net/tun
# --cap-add NET_ADMIN) it also starts the TUN-backed serve-tls and
# exports TURNS_URL so the turns: (5349) sub-tests run for real.
set -eu
cd "$(dirname "$0")/.."
HOST="$(hostname -I | awk '{print $1}')"
if [ -z "$HOST" ]; then
  echo "no host IP found; running with TURN_HOST=127.0.0.1 (relay sub-tests will SKIP)"
  HOST=127.0.0.1
  exec env TURN_HOST="$HOST" BROWSERS="${BROWSERS:-firefox,chromium,webkit}" node tests/browser/run.mjs
fi
TLS_PID=""
if [ -c /dev/net/tun ] && command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/turns-key.pem -out /tmp/turns-cert.pem \
    -days 2 -subj "/CN=10.99.0.1" -addext "subjectAltName=IP:10.99.0.1" >/dev/null 2>&1 || true
  if [ -f /tmp/turns-cert.pem ]; then
    ./target/debug/turn-dag-node serve-tls --cert /tmp/turns-cert.pem --key /tmp/turns-key.pem \
      --user browser-test-user --pass browser-test-secret >/tmp/turns-server.log 2>&1 &
    TLS_PID=$!
    sleep 2
    if ip addr add 10.99.0.2/24 dev turndag0 2>/dev/null && ip link set turndag0 up 2>/dev/null; then
      export TURNS_URL="turns:10.99.0.1:5349?transport=tcp"
      echo "turns: serve-tls up on 10.99.0.1:5349 (tun turndag0)"
    else
      echo "turns: TUN present but cannot configure interface (needs NET_ADMIN); turns sub-tests will SKIP"
      kill "$TLS_PID" 2>/dev/null || true
      TLS_PID=""
    fi
  fi
fi
set +e
env TURN_HOST="$HOST" REQUIRE_RELAY=1 MIN_PASS="${MIN_PASS:-10}" BROWSERS="${BROWSERS:-firefox,chromium,webkit}" node tests/browser/run.mjs
RC=$?
set -e
if [ -n "$TLS_PID" ]; then kill "$TLS_PID" 2>/dev/null || true; fi
exit "$RC"
