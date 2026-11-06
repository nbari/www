[![Test & Build](https://github.com/nbari/www/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nbari/www/actions/workflows/build.yml?query=branch%3Amain)
[![Security audit](https://github.com/nbari/www/actions/workflows/security-audit.yml/badge.svg?branch=main)](https://github.com/nbari/www/actions/workflows/security-audit.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/nbari/www/graph/badge.svg?token=AFKgrEetRh)](https://codecov.io/gh/nbari/www)
[![Release](https://img.shields.io/github/v/release/nbari/www.svg)](https://github.com/nbari/www/releases/latest)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

# www

A simple static web server written in Rust. Run `www` to serve the current directory over HTTP on port 8000, with HTTPS available when you need it.

## Why?

To make starting a web server as simple as running one command. The project began with the need to share files and test the contents of a directory over HTTP, without setting up a web framework or writing a configuration file.

If you usually reach for:

```sh
python3 -m http.server 8000
```

Use `www` as a standalone alternative:

```sh
www
```

Open <http://localhost:8000/> to browse the current directory. Serve a different directory with `-r`, choose a port with `-p`, or add HTTPS with `-s localhost` for local testing and `-s DOMAIN` for automatic Let's Encrypt certificates.

## Install

### With Cargo

If you have Rust 1.88+ and Cargo (Rust's package manager) installed:

```sh
cargo install www --locked
```

Cargo installs the executable into `~/.cargo/bin` by default. Make sure that directory is in your `PATH` so your shell can find `www`.

### Without Rust

Download an archive or package for your operating system and CPU architecture from [GitHub Releases](https://github.com/nbari/www/releases). Prebuilt binaries do not require Rust or Python to run.

For a `.tar.gz` archive, extract it and run `./www` from the extracted directory, or place the `www` executable in a directory on your `PATH` to run it from anywhere. DEB and RPM packages install the command through your system's package manager.

Available builds cover Linux (`x86_64`, `i686`, and `aarch64` GNU archives; static `musl` archives and DEB/RPM packages on `x86_64` and `aarch64`), FreeBSD (`x86_64`, `i686`, `aarch64`), and macOS (`x86_64`, `aarch64`).

### From a source checkout

Requires Git, Rust 1.88+, and the `just` command runner:

```sh
git clone https://github.com/nbari/www.git
cd www
just build
just install "$HOME/.local"
```

Make sure `~/.local/bin` is in your `PATH`.

## Quick start

In a terminal, change to the directory you want to serve and run:

```sh
www
```

Open <http://localhost:8000/> in your browser. If the directory contains `index.html`, you will see that page; otherwise, you will see a list of files. Keep the terminal running while you browse, and press **Ctrl+C** to stop the server.

`www` serves static files, such as HTML, CSS, JavaScript, images, and downloads. It does not execute server-side code such as PHP or Python.

By default, the server also accepts connections from other machines. On the same network, open `http://<server-ip>:8000/`, replacing `<server-ip>` with the serving machine's network IP address; your firewall must allow the connection. Share only directories intended for others to access, including their hidden files and linked files; see [Security](#security).

### Common examples

Run each example separately, stopping a running server with **Ctrl+C** before starting another.

Serve a different directory on port 8080 (also useful when port 8000 is already in use):

```sh
www -r /path/to/files -p 8080
```

Open <http://localhost:8080/>. Replace `/path/to/files` with an existing directory.

For a local preview accessible only from your own machine:

```sh
www --bind 127.0.0.1 -r ./public -p 8080
```

Open <http://127.0.0.1:8080/>. Here and in later examples, replace `./public` with your site's existing directory.

To suppress startup and request logs:

```sh
www -q -r ./public
```

## Features

- Static file streaming with `HEAD`, byte-range (`206 Partial Content`), and conditional (`If-Modified-Since`) support.
- Automatic `index.html` serving and HTML-escaped, sorted directory listings.
- Instant self-signed ECDSA HTTPS for `localhost` (`127.0.0.1` and `::1`).
- Automatic Let's Encrypt HTTPS via TLS-ALPN-01 on port 443 with background renewal and private atomic certificate caching.
- Dual-stack IPv4/IPv6 listener with `TCP_NODELAY` enabled across HTTP, localhost HTTPS, and ACME HTTPS.
- Pure Rustls TLS stack with zero OpenSSL or native-TLS dependencies.

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
```

Open <https://localhost:8080/> in your browser. A certificate warning is expected because the certificate is self-signed; proceed only if you trust this local server. To test from a second terminal:

```sh
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

## How files are read

Serving a file is one filesystem step: the path is resolved, the handle is
opened, and a body up to 256 KiB is read, all in a single operation. Bodies
larger than that stream in 128 KiB chunks.

That step normally runs directly on a runtime worker, because on a warm page
cache the thread handoff costs more than the syscalls do. Two limits keep a
slow filesystem from turning that into a stall:

- At most half the runtime workers may be inside a filesystem operation at
  once, so accepting connections, timers, ACME renewal and shutdown keep
  running even against a mount that never answers. A single-worker runtime
  therefore never reads inline, and always uses the blocking pool.
- If any resolution takes longer than 1 ms, every resolution moves to the
  blocking pool for the next second, then the fast path is retried with a
  single probe.

The effect scales with the number of workers. Serving a 1 KiB file, measured
against 3.0.1 on the same host:

| Server CPUs / workers | 3.0.1 | 3.1.0 | |
|---|---|---|---|
| 1 | 27,853 req/s | 43,379 req/s | 1.56x |
| 2 | 49,205 req/s | 111,737 req/s | 2.27x |
| 4 | 81,974 req/s | 230,465 req/s | 2.81x |

Streaming bodies share a 64 MiB memory ceiling. Past it, further responses
stream in 16 KiB chunks rather than waiting or failing, so the memory a set
of slow readers can pin grows more slowly than the number of connections.

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

The benchmark runner (`examples/bench.rs`) builds the release binary, generates temporary `1 KiB`, `100 KiB`, `4 MiB`, and 200-entry directory fixtures, pins server and client CPU sets with `taskset`, and measures GET, HEAD, conditional (`304`), and byte-range (`206`) workloads over HTTP and localhost HTTPS with keep-alive enabled and disabled, comparing `TCP_NODELAY` enabled vs. disabled across concurrencies `1`, `16`, `64`, and `128`. Besides requests/sec, throughput, latency percentiles, CPU, and RSS it records per-request read/write syscalls and context switches from `/proc`, summed across every server thread.

The load generator never runs on an SMT sibling of a server CPU, so the two processes cannot compete for the same physical cores. Samples that saw an unexpected status or a transport error stay in the raw output but are excluded from published medians and ratios. The `nagle` variant applies only to the `rust` implementation, the one that reads `WWW_BENCH_DISABLE_TCP_NODELAY`; external binaries are measured under their own default socket configuration.

Any other prebuilt server that accepts `-p <port> -r <root> -q [-s localhost]` can be benchmarked side by side with `--server LABEL=PATH` (repeatable); `--servers LIST` selects and orders the labels to run. The implicit `rust` label is always the working-tree release build:

```sh
just bench --server go=/tmp/www-go --servers rust,go
```

Results are grouped per case and implementation (medians across rounds, never averaged across cases or implementations) and include a `rust/go` req/s ratio when both labels run. Raw `oha` JSON, `results.json`, `samples.csv`, and `summary.txt` are written under `target/benchmarks/`.

## Container

```sh
docker build -t www .
docker run --rm -p 8000:8000 -v "$PWD:/srv:ro" www
```

## Security

`www` binds all IPv4 and IPv6 interfaces (`[::]:port` with dual-stack fallback to `0.0.0.0:port`) by default. Use `--bind 127.0.0.1` or `--bind ::1` for loopback access. Explicit addresses bind only their selected family; IPv6 addresses do not accept IPv4 connections. Hostnames and address:port forms are not accepted; select the port with `-p`. Domain HTTPS still uses port `443`, and the selected interface must receive public ACME validation traffic. Hidden files (dotfiles) are served and ordinary symbolic links are followed, including links pointing outside the document root; share only directories intended for public access. Path traversal (`..`), NUL bytes, backslashes, and the active ACME certificate cache directory (including symlink aliases to it) are rejected.

Security support starts with version 3. Report vulnerabilities privately as described in [the security policy](.github/SECURITY.md).
