# Contributing to  www

First and foremost, thank you! We appreciate that you want to contribute to
**www**, your time is valuable, and your contributions mean a lot to us.

## Important!

By contributing to this project, you:

* Agree that you have authored 100% of the content
* Agree that you have the necessary rights to the content
* Agree that you have received the necessary permissions from your employer to make the contributions (if applicable)
* Agree that the content you contribute may be provided under the Project license(s)

## Getting started

**What does "contributing" mean?**

Creating an issue is the simplest form of contributing to a project. But there
are many ways to contribute, including the following:

- Updating or correcting documentation
- Feature requests
- Bug reports

**Showing support for www**

Please keep in mind that open source software is built by people like you, who
spend their free time creating things the rest the community can use.

Don't have time to contribute? No worries, here are some other ways to show your
support for **www**:

- star :star: the [project](https://github.com/nbari/www)
- tweet your support for **www**

## Issues

### Before creating an issue

Please try to determine if the issue is caused by an underlying library, and if
so, create the issue there. Sometimes this is difficult to know. We only ask
that you attempt to give a reasonable attempt to find out. Oftentimes the readme
will have advice about where to go to create issues.

Try to follow these guidelines

- **Investigate the issue**
- **Check the readme** - oftentimes you will find notes about creating issues, and where to go depending on the type of issue.
- Create the issue in the appropriate repository.

### Creating an issue

Please be as descriptive as possible when creating an issue. Give us the information we need to successfully answer your question or address your issue by answering the following in your issue:

- **version**: please note the version of **www** are you using
- **extensions, plugins, helpers, etc** (if applicable): please list any extensions you're using
- **error messages**: please paste any error messages into the issue, or a [gist](https://gist.github.com/)

### Closing issues

The original poster or the maintainer's of **www** may close an issue at
any time. Typically, but not exclusively, issues are closed when:

- The issue is resolved
- The project's maintainers have determined the issue is out of scope
- An issue is clearly a duplicate of another issue, in which case the duplicate issue will be linked.
- A discussion has clearly run its course


## Development and Verification

Development recipes live in `.justfile` and require [just](https://github.com/casey/just):

```sh
just check
just msrv
just acme
just bench-check
```

- `just check` enforces `cargo fmt --all -- --check`, `just --fmt --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, the Rustls-only dependency check (`tls-check`), and the unit/integration/benchmark-safeguard test suites.
- `just msrv` verifies compatibility with the minimum supported Rust version (`1.88.0`, declared in `Cargo.toml`).
- `just acme` runs TLS-ALPN-01 issuance, idle renewal, cached restart, and CA outage recovery against an in-process Rust test CA. No external service or container runtime is required.
- `ACME_DOMAIN=example.com ACME_INGRESS_PROBE_CMD='...' just acme-live` runs opt-in live Let's Encrypt staging verification after fail-closed public DNS (Cloudflare DoH), public IPv4/IPv6 egress matching, port 443 bindability, and external ingress nonce verification.

### Local ACME coverage

`tests/acme.rs` hosts a temporary Rustls HTTPS ACME API and signing CA in the test process. It verifies ES256 JWS signatures, account ownership, request URLs and single-use nonces. Before accepting an authorization, it connects to the running `www` listener with SNI and `acme-tls/1`, verifies the TLS handshake signature, and checks the self-signed challenge certificate's single DNS SAN and critical SHA-256 `acmeIdentifier` extension. Finalization checks the CSR signature and ordered identifiers before signing the requested key.

The end-to-end test exercises issuance, GET/HEAD, idle renewal, certificate/account persistence, restart during a CA outage, continued HTTPS during a failed renewal, automatic recovery, and graceful shutdown. Rotation assertions use fresh TLS handshakes with pooling and session resumption disabled. Negative tests exercise malformed certificates/CSRs, missing ALPN, invalid/replayed signed requests, and finalization before or after failed validation. Separate cache and filesystem tests check permissions, isolation, atomic persistence, and symlink aliases.

This is a deliberately limited test CA: it supports P-256/ES256 and `localhost` only, binds its API to loopback, and maps validation to an ephemeral loopback port instead of public TCP/443. It does not implement public DNS validation, alternate challenge types, revocation, rate limits, or the full behavior of a public CA. Public reachability and Let's Encrypt interoperability require the separate opt-in staging test below; local success does not establish those prerequisites.

### Live staging verification

`just acme-live` never contacts Let's Encrypt unless public ingress to port 443 on this host is proven from an independent external vantage point. Same-host or hairpin NAT probes cannot detect upstream firewall blocks or misrouted public IPs, so the test fails closed when `ACME_INGRESS_PROBE_CMD` is unset.

For each public A and AAAA address resolved via Cloudflare DoH, the preflight listener binds TCP port 443 and executes `sh -c "$ACME_INGRESS_PROBE_CMD"` in a dedicated process group with a 10-second deadline and these environment variables:

- `ACME_PROBE_DOMAIN`: normalized DNS name under test.
- `ACME_PROBE_IP`: target public IPv4 or IPv6 address.
- `ACME_PROBE_PORT`: target TCP port (`443`).
- `ACME_PROBE_NONCE`: single-line random token (`www-acme-probe-<32-hex>`).

The probe command must connect from an external host to `$ACME_PROBE_IP:$ACME_PROBE_PORT`, send `$ACME_PROBE_NONCE` followed by `\n`, verify that the exact line is echoed back unmodified (proving no TLS-terminating proxy intercepted the connection), and exit `0`:

```sh
ACME_DOMAIN=share.example.com \
ACME_INGRESS_PROBE_CMD='ssh probe-host "printf \"%s\n\" \"$ACME_PROBE_NONCE\" | nc -w 5 \"$ACME_PROBE_IP\" \"$ACME_PROBE_PORT\" | grep -Fxq \"$ACME_PROBE_NONCE\""' \
just acme-live
```

### Listener binding and serving policy evaluation

- **Listener addresses**: Omitting `--bind` retains `server::bind(port)` and its all-interface dual-stack default (`[::]:port`, `IPV6_V6ONLY=false`, with IPv4 fallback when IPv6 socket setup is unavailable). `--bind IP` accepts a numeric IPv4 or IPv6 address, binds that exact family/address, and never falls back after an explicit bind failure. Explicit IPv6 uses `IPV6_V6ONLY=true`. `-p` still selects the port except domain HTTPS, which always uses 443. ACME TLS-ALPN-01 validation must reach the selected listener through public DNS and ingress.
- **Dotfiles, symlinks, and directory listings**: Serving hidden files, following ordinary symlinks outside the document root, and generating directory listings when `index.html` is absent remain intentional defaults for compatibility. Path traversal (`..`), NUL/backslash bytes, and the active ACME certificate cache (including symlink aliases to it) are always blocked. Future strict-mode toggles (such as disabling external symlinks, dotfiles, or listings) should be introduced only if requested as a single cohesive policy rather than multiple overlapping flags.

### Linux static musl packages (DEB and RPM)

```sh
just package-tools
cargo build --release --locked --target x86_64-unknown-linux-musl
just packages x86_64-unknown-linux-musl
```

Use `aarch64-unknown-linux-musl` on ARM64 builders. `scripts/package-linux.py` verifies ELF architecture and static linkage before generating `.deb` and `.rpm` packages in `dist/`.

### FreeBSD cross-compilation

To cross-build FreeBSD release binaries or test suites on Linux (requires Python 3.11+, `clang`, `tar`, and `rustup`):

```sh
python3 scripts/build-freebsd.py aarch64-unknown-freebsd
python3 scripts/build-freebsd.py aarch64-unknown-freebsd --tests
```

Supported targets are `x86_64-unknown-freebsd`, `aarch64-unknown-freebsd`, and `i686-unknown-freebsd`. The script downloads and verifies the official FreeBSD 14.3 ABI sysroot using the Rustls-based `examples/fetch.rs` helper.

## Pull Request Process

- Target **main** when opening a pull request.
- Run `just check` and the relevant integration checks before submitting changes.

## Releases

`release.yml` runs on every pushed tag and through **Run workflow**. A branch run is a dry run:
it tests, builds all release architectures and packages, and checks `cargo publish --dry-run`.
A tag run publishes only when the tag matches `Cargo.toml`, for example `3.0.0` or `v3.0.0`.
All tests, builds, and crate validation must pass before either publication job runs.

Configure [crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing) before
using tag releases:

1. Make the initial crate publication locally using an API token. crates.io requires an existing
   crate before Trusted Publishing can be configured. Publish from a clean checkout of the
   commit you intend to release, using `cargo publish --locked`.
2. In the crate's **Settings → Trusted Publishing**, add GitHub with repository owner `nbari`,
   repository name `www`, workflow filename `release.yml`, and environment `crates-io`.
3. In GitHub repository settings, create the matching `crates-io` environment. Any deployment
   restrictions must permit your release tags. Required reviewers are optional.

The workflow obtains a short-lived OIDC token only for the final upload; no crates.io token
secret is needed in GitHub. An identical, non-yanked crate version already on crates.io is
accepted after checking its SHA-256 checksum. Different contents under the same version fail;
bump the version rather than reusing it. GitHub release creation precedes the crates.io upload,
so an upload failure leaves the GitHub assets available and the failed job can be rerun.

For subsequent releases, update the Cargo version and lockfile, commit the changes, wait for
CI, then push a matching tag. Manually dispatching on a matching tag also publishes; select
`main` for validation without publication.

### Homebrew tap (`nbari/homebrew-www`)

The existing `nbari/homebrew-www` tap (`master:www.rb`, blob `2cd622cf086eeffe6a995dd7be15cf9cdb553e60`) still targets tag `2.0.0` (`057958f4d73629d886801dc2c24c6c0f268861ac`) with `depends_on "go" => :build` and `depends_on "dep" => :build`. Replace `www.rb` in that repository with the prebuilt Rust release archives and man page below (verified against the published `3.0.0` GitHub release `SHA256SUMS`; neither `ruby` nor `brew` is installed on this Linux builder, so validate with `brew audit --strict` / `brew test` on the tap host):

```ruby
class Www < Formula
  desc "Simple static web server with automatic HTTPS"
  homepage "https://github.com/nbari/www"
  version "3.0.0"
  license "BSD-3-Clause"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/nbari/www/releases/download/3.0.0/www-3.0.0-aarch64-apple-darwin.tar.gz"
      sha256 "5758fe8a6e8b060fe874ac2aa1819dc2cf721683eb0569649c09108f404180e7"
    else
      url "https://github.com/nbari/www/releases/download/3.0.0/www-3.0.0-x86_64-apple-darwin.tar.gz"
      sha256 "3ecfb6cc9e79a68642a08fd2dd5701720a88552fd1f84aec262eb1b0110313e1"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/nbari/www/releases/download/3.0.0/www-3.0.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "6430771b3eecc9234af9d8bf3d84661619c652775f175d2881e17ace8a18a5ba"
    else
      url "https://github.com/nbari/www/releases/download/3.0.0/www-3.0.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "ab2348c8220b7671cfc083150f0e5b9df1d34706d73362e55edb38c6cdd67d05"
    end
  end

  def install
    bin.install "www"
    man1.install "man/www.1"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/www -V")
  end
end
```

[so]: http://stackoverflow.com/questions/tagged/www
