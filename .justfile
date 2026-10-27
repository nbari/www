default: build

# Build the standalone release binary.
build:
    cargo build --release --locked

# Run the ordinary tests; the Pebble integration test is run by acme.
test:
    cargo test --locked

fmt:
    cargo fmt --all
    just --fmt

fmt-check:
    cargo fmt --all -- --check
    just --fmt --check

lint:
    cargo clippy --all-targets --all-features --locked -- -D warnings

check: fmt-check lint tls-check test

# Fail if a dependency introduces native TLS or OpenSSL into any feature set.
tls-check:
    #!/usr/bin/env sh
    set -eu
    dependencies="$(cargo tree --all-features --target all --locked --prefix none --format '{p}')"
    if printf '%s\n' "$dependencies" | grep -E '^(openssl|openssl-sys|native-tls|tokio-native-tls|hyper-tls) v'; then
        echo 'TLS dependencies must use Rustls' >&2
        exit 1
    fi

# Install the same Cargo packagers used by s3m, at pinned versions.
package-tools:
    cargo install --locked --version 3.8.0 cargo-deb
    cargo install --locked --version 0.21.1 cargo-generate-rpm

# Package a prebuilt static musl binary. Build the target before running this recipe.
packages target="x86_64-unknown-linux-musl":
    python3 scripts/package-linux.py {{ quote(target) }}

# Verify the declared minimum Rust version (install it through rustup first).
msrv:
    cargo +1.88.0 check --all-targets --locked

# Requires Pebble v2.8.0 on PATH, or an absolute PEBBLE_BIN environment variable.
acme:
    cargo test --locked --test acme -- --ignored --nocapture

# Install under a chosen prefix, optionally staging files under destdir.
install prefix="/usr/local" destdir="": build
    install -d {{ quote(destdir + prefix + "/bin") }} {{ quote(destdir + prefix + "/share/man/man1") }}
    install -m 755 target/release/www {{ quote(destdir + prefix + "/bin/www") }}
    install -m 644 man/www.1 {{ quote(destdir + prefix + "/share/man/man1/www.1") }}

clean:
    cargo clean
