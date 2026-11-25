#!/bin/sh
# Thin host wrapper only — all logic is in the Dockerfile (ci stage).
set -eu
cd "$(dirname "$0")/.."
docker build --target ci -t turn-dag:ci .
echo "ci: PASS (via Dockerfile ci stage)"
