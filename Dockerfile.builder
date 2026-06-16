# Hermetic builder image for citrate-comms reproducible releases (COMMS-S4 WP-4.7).
#
# Pinned via rust-toolchain.toml (consumed by rustup inside the image) + this
# Dockerfile's base-image digest. The two-machine bit-for-bit comparison lives in
# .github/workflows/release.yml; this image closes the deterministic-build-environment
# half (PLANSET/07 §1.1).
#
# Build:
#   docker build -f Dockerfile.builder -t citrate-comms-builder .
# Use:
#   docker run --rm -v "$PWD":/work -w /work citrate-comms-builder \
#     cargo build --release --locked -p comms-relay --bin comms-relay
#
# citrate-comms is a self-contained, path-only workspace — NO git/SSH deps — so unlike
# nist-agent the builder needs no deploy keys.

# Pin by digest (multi-platform index) so re-builds against the same base are
# deterministic. Update in tandem with rust-toolchain.toml bumps. Resolve a current
# digest with:  docker buildx imagetools inspect debian:bookworm-slim
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

ARG RUST_VERSION=1.96.0

# Native deps:
# - clang / libclang-dev → rocksdb's bindgen (comms-core::store at-rest CFs).
# - build-essential / pkg-config / libssl-dev → C build + rustls native paths.
# - libfontconfig1-dev → the Slint desktop client (comms-client) build.
# - curl → rustup-init; git + ca-certificates → cargo fetch (build-time only).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        libclang-dev \
        cmake \
        curl \
        git \
        libssl-dev \
        libfontconfig1-dev \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install rustup + the toolchain pinned in rust-toolchain.toml.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal \
        --component rustfmt --component clippy
ENV PATH=/root/.cargo/bin:$PATH

# Pre-cache cargo-audit + cargo-deny + cargo-cyclonedx so the release pipeline performs
# NO network tool install — the audit/SBOM steps run entirely from this image.
RUN cargo install cargo-audit --locked --version 0.22.1 \
 && cargo install cargo-deny  --locked --version 0.19.6 \
 && cargo install cargo-cyclonedx --locked --version 0.5.7

WORKDIR /work
CMD ["bash"]
