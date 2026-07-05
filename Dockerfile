# Integration-test image: a container with capture privileges baked in
# (root + the default CAP_NET_RAW every Docker container gets), so the
# `#[ignore = "needs capture privileges..."]` tests in
# crates/pktflow-capture/tests/live.rs run for real instead of being
# skipped — GitHub Actions' bare runners execute test steps as an
# unprivileged user, which is why those tests are ignored there today.
#
# Build: docker build -t pktflow-test .
# Run:   docker run --rm pktflow-test
#
# `rust:1-slim-bookworm` tracks the latest 1.x stable, mirroring
# `dtolnay/rust-toolchain@stable` in .github/workflows/ci.yml — pin an
# exact version here only if reproducibility ever matters more than
# staying current.
FROM rust:1-slim-bookworm

# Non-interactive: tshark's postinst otherwise prompts via debconf
# ("allow non-superusers to capture packets?"), which hangs a build
# with no TTY attached.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libpcap-dev \
    tshark \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --workspace --all-features --tests

# --include-ignored: this is the whole point of running in a
# container — the privileged live-capture tests are no longer skipped.
CMD ["cargo", "test", "--workspace", "--all-features", "--", "--include-ignored"]
