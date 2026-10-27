[![Test & Build](https://github.com/nbari/www/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nbari/www/actions/workflows/build.yml?query=branch%3Amain)
[![Security audit](https://github.com/nbari/www/actions/workflows/security-audit.yml/badge.svg?branch=main)](https://github.com/nbari/www/actions/workflows/security-audit.yml?query=branch%3Amain)
[![Release](https://img.shields.io/github/v/release/nbari/www.svg)](https://github.com/nbari/www/releases/latest)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

# www

A simple static web server. Run `www` to share the current directory over HTTP on port 8000.

```sh
www
www -r /tmp -p 8080
www -q -r ./public
```

The server supports directory listings, `index.html`, streamed downloads, HEAD, byte ranges,
and conditional requests.

## Install

Build from this repository with Rust 1.88 or newer and a C compiler:

```sh
cargo install --path . --locked
```

Or build and install the binary and man page:

```sh
just build
just install "$HOME/.local"
```

Release builds cover Linux and FreeBSD on x86, x86_64, and ARM64, and macOS on x86_64 and ARM64.
Linux additionally provides static musl archives and RPM/DEB packages on x86_64 and ARM64,
using the same Cargo packagers as s3m. Packages install the binary under `/usr/bin`, together
with the man page and license documentation. Release tags must match the Cargo package version.
FreeBSD release binaries use the FreeBSD 14.3 ABI sysroot; CI runs tests in FreeBSD 14.4 VMs.

## Options

| Option | Behavior |
| --- | --- |
| `-p PORT` | Listen on this port; default 8000 |
| `-r PATH` | Serve this directory; default current directory |
| `-q` | Suppress startup and request logs; errors remain visible |
| `-s localhost` | Generate a temporary self-signed certificate and use the selected port |
| `-s DOMAIN` | Obtain and renew a Let's Encrypt certificate; always listen on port 443 |
| `--cert-cache PATH` | Override persistent ACME account and certificate storage |
| `--acme-staging` | Test domain HTTPS against Let's Encrypt staging |
| `-h`, `--help` | Show help |
| `-V` | Show the package version |
| `--version` | Show the package version and full source commit hash |

The server listens on all IPv4 and IPv6 interfaces when IPv6 is available. Hidden files are served,
and ordinary symlinks are followed, including links outside the document root.
Choose the directory you share accordingly. The active certificate cache and its symlink aliases
are excluded from listings and downloads.

Help uses the same terminal colors as cron-when. Colors are automatic and disabled for redirected
output. Version metadata is generated with `built`; registry packages retain the source commit
through Cargo's `.cargo_vcs_info.json`. Builds without Git or Cargo source metadata show `unknown`.

## HTTPS on localhost

```sh
www -s localhost -r ./public -p 8080
curl --insecure https://localhost:8080/
```

A fresh ECDSA certificate is generated in memory each time. It covers `localhost`, `127.0.0.1`,
and `::1` and is self-signed, so browsers and clients require an explicit trust decision.

## HTTPS with Let's Encrypt

Create an **A record** at your DNS provider pointing your chosen name, such as
`share.example.com`, to the public IPv4 address of the server running `www`.
Add an **AAAA record** only when the server also has working public IPv6.

Allow incoming **TCP port 443** in the server and hosting provider firewalls. When using a router,
forward public TCP port 443 to this machine. DNS proxies such as Cloudflare must use DNS-only
mode, or otherwise pass TLS through unchanged. The process needs permission to bind port 443.

```sh
www -s share.example.com -r ./public
```

`www` uses the TLS-ALPN-01 challenge on the HTTPS listener. It manages registration, certificate
issuance, caching, and renewal while running. Port 80 and a separate renewal job are unnecessary.
Domain mode always uses port 443, including when `-p` is supplied. Individual DNS names are
supported; wildcard names require a different validation method.

Certificates identify the hostname and can also be used on public port 8443. With the current
443 listener, forward public 8443 to the server's 443 port and keep public 443 reaching the same
listener for certificate validation. Exposing only 8443 cannot satisfy TLS-ALPN-01 validation.

Certificate storage defaults to:

- Linux and FreeBSD: `$XDG_DATA_HOME/www/acme`, or `$HOME/.local/share/www/acme`.
- macOS: `$HOME/Library/Application Support/io.nbari.www/acme`.

Use `--cert-cache /path/to/private/acme` for a service account or persistent container volume.
New directories use mode 0700 and cache files use 0600 on Unix. An existing directory must
already have owner-only permissions. Cache writes are atomic. Keep this storage across restarts
to reuse ACME accounts and certificates.

For a public test, start with staging:

```sh
www -s share.example.com -r ./public --acme-staging
```

Staging certificates are intentionally untrusted. Staging and production use separate cache keys.
After testing, restart without `--acme-staging` to request a publicly trusted certificate.
The startup log confirms the listener; subsequent ACME events report certificate deployment.
Transient renewal errors are retried while the current certificate continues to be used.

See [Let's Encrypt challenge requirements](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01)
and [staging documentation](https://letsencrypt.org/docs/staging-environment/).

## Development and validation

```sh
just check
just build
```

The CLI separates argument definitions, dispatch, and serving actions. Local logging uses `tracing`;
distributed telemetry is not part of the default application.
Development recipes live in `.justfile` and require [just](https://github.com/casey/just).
Use `just msrv` to check with Rust 1.88.0 after installing that toolchain.
The manifest's `rust-version` declares the minimum supported compiler, with no upper limit.
Rust 1.88 is currently required for let chains; the minimum may be raised when future code or
dependencies need a newer compiler, together with the compatibility check.
`just check` also rejects OpenSSL and native-TLS dependencies; the server, ACME client, test
clients, and build-time HTTPS downloader all use Rustls.

To produce Linux packages from a prebuilt static musl binary:

```sh
just package-tools
cargo build --release --locked --target x86_64-unknown-linux-musl
just packages x86_64-unknown-linux-musl
```

Use `aarch64-unknown-linux-musl` on an ARM64 Linux builder. The packager checks the executable's
architecture and static linkage before generating RPM and DEB files in `dist/`. CI builds all
release architectures after the test workflow passes, and matching version tags publish archives,
packages, and SHA-256 checksums as GitHub release assets. The separate `release.yml` workflow
also publishes to crates.io through Trusted Publishing. Every tag triggers the workflow; tags
must equal the Cargo version, optionally prefixed with `v`. A manual run on `main` validates
all builds and the crate without publishing. See [release setup](CONTRIBUTING.md#releases)
for the required crates.io configuration.

The ACME integration test starts Pebble on temporary loopback ports with generated test keys.
It performs real TLS-ALPN-01 validation, renews a short-lived certificate without HTTP traffic,
restarts with the CA offline, and checks that failed renewal leaves HTTPS running.

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.8.0
PEBBLE_BIN="$(go env GOPATH)/bin/pebble" just acme
```

Pebble is needed only for this integration test, which CI runs explicitly. Ordinary `just test`
reports it as ignored. No public domain or production CA is used by the automated tests.
The Go toolchain is used only to build the external Pebble test server.

To cross-build a FreeBSD release on Linux, install Python 3.11+, clang, tar, and Rust through
rustup, then run, for example:

```sh
python3 scripts/build-freebsd.py aarch64-unknown-freebsd
```

The script downloads and verifies the official FreeBSD sysroot and installs the selected Rust
target. It also supports `x86_64-unknown-freebsd` and `i686-unknown-freebsd`.
With `--tests`, it lints and cross-compiles the full test suite and writes a shell runner under
`target/freebsd-tests/`. CI runs the ARM64 executables inside FreeBSD with the workspace shared
at the same path over NFS, avoiding compiler work under CPU emulation. The x86_64 VM also
builds and runs `just check` inside FreeBSD.

## Container

```sh
docker build -t www .
docker run --rm -p 8000:8000 -v "$PWD:/srv:ro" www
```

The image runs as an unprivileged user. HTTPS deployments must additionally permit binding
port 443, publish that port, and mount writable persistent certificate storage.

## Security

Security support starts with version 3. Report vulnerabilities privately as described in
[the security policy](.github/SECURITY.md).
