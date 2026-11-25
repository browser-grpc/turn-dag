#!/bin/sh
# Thin host wrapper only — all logic is in the Dockerfile (test stage runs at image build).
set -eu
cd "$(dirname "$0")/.."
docker build --target test -t turn-dag:test .
echo "test: PASS (via Dockerfile test stage)"
