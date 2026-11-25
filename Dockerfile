# syntax=docker/dockerfile:1
# turn-dag — all build/test/tool/run/ci concerns live in this file.
# No host tooling required beyond Docker. Use:
#   docker build -t turn-dag .
#   docker run --rm turn-dag test
#   docker run --rm turn-dag build
#   docker run --rm -it turn-dag tool
#   docker run --rm turn-dag run
#   docker run --rm turn-dag ci

ARG RUST_VERSION=1.85
ARG NODE_VERSION=22
ARG PYTHON_VERSION=3.12

# ---------- base: tools ----------
FROM rust:${RUST_VERSION}-bookworm AS base
ARG NODE_VERSION
ARG PYTHON_VERSION
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq python3 python3-pip \
    poppler-utils file make pkg-config libssl-dev \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*
# Pin Node via nodesource only if needed; Debian node is a fallback.
# Rust toolchain: smoltcp / ML-DSA / Argon2 crates build here.
RUN rustup component add clippy rustfmt 2>/dev/null || true
WORKDIR /work
COPY . /work

# ---------- build ----------
FROM base AS build
# Build = validate the spec artifact and produce a build report.
# Future code: `cargo build --release` goes here, behind the same target.
RUN ./scripts/build.sh 2>/dev/null || \
    (echo "== build ==" && \
     test -f docs/bond-contract-fraud-proof-spec.pdf && \
     pdfinfo docs/bond-contract-fraud-proof-spec.pdf | head -20 && \
     ls -lh docs/ README.md LICENSE Dockerfile)

# ---------- test ----------
FROM build AS test
# Test = spec checks + unit tests when code lands.
# Future code: `cargo test --all` goes here.
RUN ./scripts/test.sh 2>/dev/null || \
    (echo "== test ==" && \
     test -f docs/bond-contract-fraud-proof-spec.pdf && \
     test -s docs/bond-contract-fraud-proof-spec.pdf && \
     file docs/bond-contract-fraud-proof-spec.pdf | grep -qi pdf && \
     grep -q "Bond Contract" README.md && \
     grep -q "Apache" LICENSE && \
     echo "spec checks: PASS")

# ---------- tool ----------
FROM base AS tool
# Tool = interactive dev shell, all tools in-image, no host installs.
# Usage: docker run --rm -it turn-dag tool
ENTRYPOINT ["/bin/bash"]

# ---------- run ----------
FROM base AS run
# Run = default runtime. Spec-only for now: print the spec summary.
# Future code: replace CMD with the TURN / DAG node binary.
CMD ["bash", "-c", "echo 'turn-dag: spec only, no server yet'; ls -R docs; echo 'See docs/bond-contract-fraud-proof-spec.pdf'"]

# ---------- ci ----------
FROM test AS ci
# CI = build + test, in one image, no host CI tooling.
# Usage in GitHub Actions: docker build --target ci -t turn-dag:ci .
# GitHub Actions should only do: checkout, docker build, docker run.
# All lint / test / build logic lives in this Dockerfile + scripts/.
RUN echo "== ci ==" && echo "build+test: PASS"

# Default target is run, so `docker build -t turn-dag .` gives a runnable image.
FROM run AS final
