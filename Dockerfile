# syntax=docker/dockerfile:1
# turn-dag — ALL build/test/tool/run/ci logic lives in this file.
# No host tooling beyond Docker. No build/test logic in scripts/ or CI YAML:
# scripts/*.sh are thin `docker build`/`docker run` wrappers only.
#   docker build -t turn-dag .
#   docker run --rm turn-dag test|build|ci|run
#   docker run --rm -it turn-dag tool
#   docker build --target ci -t turn-dag:ci .
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

# Default target: runnable node image.
FROM run AS final
