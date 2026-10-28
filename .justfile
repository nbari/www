default: build

# Build the standalone release binary.
build:
    cargo build --release --locked

# Run ordinary unit, integration, and benchmark safeguard tests.
test:
    cargo test --locked
    cargo test --locked --example bench

fmt:
    cargo fmt --all
    just --fmt

fmt-check:
    cargo fmt --all -- --check
    just --fmt --check

lint:
    cargo clippy --all-targets --all-features --locked -- -D warnings

check: fmt-check lint tls-check test

# Install the coverage collector and matching Rust LLVM tools.
coverage-tools:
    rustup component add llvm-tools-preview
    cargo install grcov --locked --version 0.10.7

# Run all local test targets and generate HTML and LCOV source coverage.
coverage:
    sh scripts/coverage.sh

alias coverate := coverage

# Fail if a dependency introduces native TLS or OpenSSL into any feature set.
tls-check:
    #!/usr/bin/env sh
    set -eu
    dependencies="$(cargo tree --all-features --target all --locked --prefix none --format '{p}')"
    if printf '%s\n' "$dependencies" | grep -E '^(openssl|openssl-sys|native-tls|tokio-native-tls|hyper-tls) v'; then
        echo 'TLS dependencies must use Rustls' >&2
        exit 1
    fi

# Install the Cargo packagers at pinned versions.
package-tools:
    cargo install --locked --version 3.8.0 cargo-deb
    cargo install --locked --version 0.21.1 cargo-generate-rpm

# Package a prebuilt static musl binary. Build the target before running this recipe.
packages target="x86_64-unknown-linux-musl":
    python3 scripts/package-linux.py {{ quote(target) }}

# Verify the declared minimum Rust version (install it through rustup first).
msrv:
    cargo +1.88.0 check --all-targets --locked

# Run the in-process Rust ACME CA integration and validator tests.
acme:
    cargo test --locked --test acme -- --nocapture

# Opt-in live Let's Encrypt staging verification (requires ACME_DOMAIN and ACME_INGRESS_PROBE_CMD).
acme-live:
    cargo test --locked --test acme live_staging_issuance_and_certificate_reuse -- --ignored --exact --nocapture

# Install the pinned Rustls load generator for local benchmarks.
bench-tools:
    cargo install --locked --version 1.16.0 --no-default-features --features rustls oha

# Run local HTTP and HTTPS benchmarks (compares TCP_NODELAY enabled vs disabled by default).
[positional-arguments]
bench *args:
    cargo run --locked --example bench -- "$@"

# Run local HTTP benchmarks only.
[positional-arguments]
bench-http *args:
    cargo run --locked --example bench -- --mode http "$@"

# Run local localhost HTTPS benchmarks only.
[positional-arguments]
bench-https *args:
    cargo run --locked --example bench -- --mode https "$@"

# Validate benchmark error handling, fixture generation, and result aggregation without running oha.
bench-check:
    cargo test --locked --example bench

# Install under a chosen prefix, optionally staging files under destdir.
install prefix="/usr/local" destdir="": build
    install -d {{ quote(destdir + prefix + "/bin") }} {{ quote(destdir + prefix + "/share/man/man1") }}
    install -m 755 target/release/www {{ quote(destdir + prefix + "/bin/www") }}
    install -m 644 man/www.1 {{ quote(destdir + prefix + "/share/man/man1/www.1") }}

clean:
    cargo clean
