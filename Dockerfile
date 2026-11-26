# syntax=docker/dockerfile:1
# turn-dag — ALL build/test/tool/run/ci logic lives in this file.
# No host tooling beyond Docker. No build/test logic in scripts/ or CI YAML:
# scripts/*.sh are thin `docker build`/`docker run` wrappers only.
#   docker build -t turn-dag .
#   docker run --rm turn-dag test|build|ci|run
#   docker run --rm -it turn-dag tool
#   docker build --target ci -t turn-dag:ci .
#   docker build --target browser -t turn-dag:browser .
#   docker run --rm --network host turn-dag:browser
#     (host network so the container's LAN IP is reachable by the
#     in-container browsers; sub-tests that need a real TURN path
#     SKIP elsewhere instead of failing)
ARG RUST_VERSION=1.87

# ---------- base: Rust toolchain only (no Node/Python runtimes) ----------
FROM rust:${RUST_VERSION}-bookworm AS base
ENV DEBIAN_FRONTEND=noninteractive CARGO_TERM_COLOR=never
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git file \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt
WORKDIR /work
COPY . /work
RUN chmod +x scripts/*.sh

# ---------- build ----------
FROM base AS build
RUN test -f docs/bond-contract-fraud-proof-spec.pdf \
    && cargo build --workspace \
    && cargo build --workspace --release -p turn-dag-node \
    && echo "build: PASS"

# ---------- test (fmt + clippy + full test suite) ----------
FROM build AS test
RUN test -s docs/bond-contract-fraud-proof-spec.pdf \
    && grep -q "Apache" LICENSE \
    && cargo fmt --all -- --check \
    && cargo clippy --workspace --all-targets -- -D warnings \
    && cargo test --workspace \
    && echo "test: PASS"

# ---------- tool (interactive dev shell) ----------
FROM base AS tool
ENTRYPOINT ["/bin/bash"]

# ---------- run (node binary; arg dispatch in scripts/entrypoint.sh) ----------
FROM base AS run
RUN cargo build --release -p turn-dag-node \
    && cp target/release/turn-dag-node /usr/local/bin/turn-dag-node
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["run"]

# ---------- ci = build + test, nothing else ----------
FROM test AS ci
RUN echo "== ci == build+test: PASS"
# `docker run turn-dag:ci ci` must dispatch through entrypoint.sh
# (the test stage otherwise has no entrypoint and run fails 127).
ENTRYPOINT ["./scripts/entrypoint.sh"]

# ---------- browser (Playwright WebRTC relay tests, in-container) ----------
FROM rust:${RUST_VERSION}-bookworm AS browser
ENV DEBIAN_FRONTEND=noninteractive CARGO_TERM_COLOR=never
ARG NODE_VERSION=22.14.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git file iproute2 curl xz-utils openssl libnss3-tools \
    && rm -rf /var/lib/apt/lists/* \
    && case "$(dpkg --print-architecture)" in arm64) NODE_ARCH=arm64 ;; amd64) NODE_ARCH=x64 ;; *) echo "unsupported arch" && exit 1 ;; esac \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" \
       | tar -xJ -C /usr/local --strip-components=1 \
    && node --version && npm --version
RUN rustup component add clippy rustfmt
WORKDIR /work
COPY . /work
RUN chmod +x scripts/*.sh \
    && cargo build -p turn-dag-node \
    && cd /work/tests/browser && npm ci --no-audit --no-fund \
    && npx playwright install --with-deps firefox chromium webkit
# The in-container TURN server binds 0.0.0.0; browsers must reach it
# via the container's primary LAN/bridge IP (loopback TURN is
# policy-blocked by headless Firefox).
CMD ["bash", "scripts/browser-test.sh"]

# Default target: runnable node image.
FROM run AS final
