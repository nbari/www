## 3.0.0
* Replace the Go server with a Rust implementation using the modular CLI architecture.
* Preserve the existing flags, directory browsing, file streaming, and HTTPS modes.
* Add persistent private ACME storage, atomic cache writes, and --cert-cache.
* Add --acme-staging and automated TLS-ALPN issuance, idle renewal, restart, and CA outage tests.
* Generate localhost certificates with correct DNS and IP subject alternative names.
* Add graceful signal shutdown and Cargo-based builds for the existing release architectures.
* Add just recipes, strict lint checks, Rustls dependency checks, and static x86_64/ARM64 RPM/DEB packages.

## 2.0.5
* Update Go version and GitHub workflows

## 2.0.4
* Update dependencies

## 2.0.0
* Issue ECC (Elliptic-curve cryptography) for self-signed certificate `www -s localhost -p 8080`
