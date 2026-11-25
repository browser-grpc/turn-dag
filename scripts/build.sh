#!/bin/sh
# Thin host wrapper only — all logic is in the Dockerfile (build stage runs at image build).
set -eu
cd "$(dirname "$0")/.."
docker build --target build -t turn-dag:build .
echo "build: PASS (via Dockerfile build stage)"
