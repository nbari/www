[![Test & Build](https://github.com/nbari/www/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nbari/www/actions/workflows/build.yml?query=branch%3Amain)
[![Security audit](https://github.com/nbari/www/actions/workflows/security-audit.yml/badge.svg?branch=main)](https://github.com/nbari/www/actions/workflows/security-audit.yml?query=branch%3Amain)
[![Release](https://img.shields.io/github/v/release/nbari/www.svg)](https://github.com/nbari/www/releases/latest)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

# www

A static HTTP and HTTPS web server written in Rust. Run `www` to share the current directory over HTTP on port 8000.

## Features

- Static file streaming with `HEAD`, byte-range (`206 Partial Content`), and conditional (`If-Modified-Since`) support.
- Automatic `index.html` serving and HTML-escaped, sorted directory listings.
- Instant self-signed ECDSA HTTPS for `localhost` (`127.0.0.1` and `::1`).
- Automatic Let's Encrypt HTTPS via TLS-ALPN-01 on port 443 with background renewal and private atomic certificate caching.
- Dual-stack IPv4/IPv6 listener with `TCP_NODELAY` enabled across HTTP, localhost HTTPS, and ACME HTTPS.
- Pure Rustls TLS stack with zero OpenSSL or native-TLS dependencies.

## Install

Install from crates.io:

```sh
cargo install www --locked
```

Or build and install from a checkout (requires Rust 1.88+):

```sh
just build
just install "$HOME/.local"
```

Prebuilt release archives and packages are published on [GitHub Releases](https://github.com/nbari/www/releases) for Linux (`x86_64`, `i686`, and `aarch64` GNU archives; static `musl` archives and DEB/RPM packages on `x86_64` and `aarch64`), FreeBSD (`x86_64`, `i686`, `aarch64`), and macOS (`x86_64`, `aarch64`).

## Quick start

```sh
www
www -r /tmp -p 8080
www --bind 127.0.0.1 -r ./public -p 8080
www -q -r ./public
```

## Options

| Option | Behavior |
| --- | --- |
| `-p PORT` | Listen on this port; default `8000` |
| `--bind IP` | Bind a numeric IPv4 or IPv6 address; default all interfaces |
| `-r PATH` | Serve this directory; default current directory (`.`) |
| `-q` | Suppress startup and request logs; errors remain visible |
| `-s localhost` | Generate an in-memory self-signed ECDSA certificate and use the selected port |
| `-s DOMAIN` | Obtain and renew a Let's Encrypt certificate; always listens on port `443` |
| `--cert-cache PATH` | Override persistent ACME account and certificate storage |
| `--acme-staging` | Use Let's Encrypt staging for domain testing |
| `-h`, `--help` | Show help |
| `-V` | Show the package version |
| `--version` | Show the package version and source commit hash |

## HTTPS on localhost

```sh
www -s localhost -r ./public -p 8080
curl --insecure https://localhost:8080/
```

A fresh ECDSA P-256 certificate covering `localhost`, `127.0.0.1`, and `::1` is generated in memory on each start. Because it is self-signed, clients require an explicit trust decision.

## HTTPS with Let's Encrypt

1. Point your domain's **A record** (for example `share.example.com`) to the server's public IPv4 address. Add an **AAAA record** only when public IPv6 reaches the same server.
2. Allow incoming **TCP port 443** directly to `www` (no TLS-terminating reverse proxy or CDN proxy mode).
3. Ensure the process has permission to bind port `443` (for example `CAP_NET_BIND_SERVICE` on Linux).

Run with your domain to obtain a publicly trusted certificate. Let's Encrypt production is the default; no staging flag is needed:

```sh
www -s share.example.com -r ./public
```

`www` answers TLS-ALPN-01 challenges directly on port 443 and renews certificates automatically while running; port 80 and external cron jobs are unnecessary.

### Certificate cache

`--cert-cache PATH` selects persistent storage for ACME account keys, certificate private keys, and issued certificates. It requires `-s DOMAIN`; `-s localhost` generates its certificate in memory.

For a manual run from a checkout with an explicit cache, build as your normal user, then use `sudo` to bind port 443:

```sh
just build
sudo ./target/release/www -s share.example.com \
  -r ./public --cert-cache /var/lib/www/acme
```

Replace `share.example.com` with your domain and `./public` with the directory you intend to share. Press **Ctrl+C** to stop. Restart with the same cache path and service account to reuse the account and certificate. For deployments, keep the cache in persistent storage, including across container replacements.

The running user must be able to create and write the cache. New cache directories use `0700` and atomically written files use `0600` on Unix; existing directories must already have owner-only permissions. A cache created by `sudo` contains root-owned files. Treat the cache as private key material and keep it outside your public document root.

Without `--cert-cache`, storage defaults to the running user's data directory:

- Linux and FreeBSD: `$XDG_DATA_HOME/www/acme` or `$HOME/.local/share/www/acme`
- macOS: `$HOME/Library/Application Support/io.nbari.www/acme`

Preserve the cache across restarts to avoid unnecessary issuance.

### What `--acme-staging` does

Use `--acme-staging` when testing or debugging certificate issuance:

```sh
www -s share.example.com -r ./public --acme-staging
```

This selects Let's Encrypt's test CA. It exercises real certificate issuance and TLS-ALPN-01 validation, with the same DNS and public TCP/443 requirements, but its certificates are not trusted by browsers or ordinary HTTPS clients.

Omit `--acme-staging` for normal HTTPS with a publicly trusted certificate. Staging and production can use the same cache directory because their cache keys are isolated; switching to production uses a cached production certificate or obtains one if needed.

### Testing from another machine

On first start, HTTPS handshakes can fail until issuance finishes. Wait for `DeployedNewCert` or `DeployedCachedCert` in the server log, then run from a remote machine:

```sh
curl -v https://share.example.com/
curl -I https://share.example.com/
```

For a staging test, add `-k` to skip verification of its untrusted certificate, for example `curl -vk https://share.example.com/`. Production certificates should work without `-k`.

To select a protocol explicitly, add `--http1.1` or `--http2` (if your curl build supports HTTP/2). Keep the domain in the URL so the client sends the expected TLS server name.

## Development and testing

```sh
just check
just acme
```

- `just check` runs formatting, strict Clippy lints, the Rustls-only dependency gate, unit/integration tests, and benchmark safeguard unit tests.
- `just acme` runs TLS-ALPN-01 issuance, idle renewal, cached restart, and CA outage recovery against an in-process Rust test CA. No external service or container runtime is required.
- `just coverage` generates HTML and LCOV reports using `grcov`; install its prerequisites with `just coverage-tools`. See [code coverage](CONTRIBUTING.md#code-coverage).
- `ACME_DOMAIN=example.com ACME_INGRESS_PROBE_CMD='...' just acme-live` runs opt-in live Let's Encrypt staging verification after fail-closed public DNS, egress, port-443 bind, and external ingress nonce checks (see [Live staging verification](CONTRIBUTING.md#live-staging-verification)).

See [CONTRIBUTING.md](CONTRIBUTING.md) for MSRV verification, live ACME probe protocol, Linux static `musl` packaging, FreeBSD cross-compilation, and release workflows.

## Local benchmarks

Measure local HTTP and localhost HTTPS throughput and latency on Linux using [oha](https://github.com/hatoo/oha) (built with Rustls):

```sh
just bench-tools
just bench
just bench-http
just bench-https
```

The benchmark runner (`examples/bench.rs`) builds the release binary, generates temporary `1 KiB`, `100 KiB`, `4 MiB`, and 200-entry directory fixtures, pins server and client CPU sets with `taskset`, and compares `TCP_NODELAY` enabled vs. disabled across concurrencies `1`, `16`, `64`, and `128`. Raw `oha` JSON, `results.json`, `samples.csv`, and `summary.txt` are written under `target/benchmarks/`.

## Container

```sh
docker build -t www .
docker run --rm -p 8000:8000 -v "$PWD:/srv:ro" www
```

## Security

`www` binds all IPv4 and IPv6 interfaces (`[::]:port` with dual-stack fallback to `0.0.0.0:port`) by default. Use `--bind 127.0.0.1` or `--bind ::1` for loopback access. Explicit addresses bind only their selected family; IPv6 addresses do not accept IPv4 connections. Hostnames and address:port forms are not accepted; select the port with `-p`. Domain HTTPS still uses port `443`, and the selected interface must receive public ACME validation traffic. Hidden files (dotfiles) are served and ordinary symbolic links are followed, including links pointing outside the document root; share only directories intended for public access. Path traversal (`..`), NUL bytes, backslashes, and the active ACME certificate cache directory (including symlink aliases to it) are rejected.

Security support starts with version 3. Report vulnerabilities privately as described in [the security policy](.github/SECURITY.md).
