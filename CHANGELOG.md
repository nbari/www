## 3.1.0
* Serve file responses directly instead of through `tower-http`'s `ServeDir`, keeping validators, RFC 9110 preconditions, byte ranges and header order byte-identical.
* Collapse every per-request filesystem operation into a single resolution step and read bodies up to 256 KiB during it, removing one blocking-pool handoff per 64 KiB of body.
* Resolve on the runtime thread while the filesystem is fast, falling back to the blocking pool for one second whenever a resolution exceeds 1 ms.
* Stream larger bodies in 128 KiB chunks, chosen by measurement to keep the memory a slow client can pin close to the smallest chunk size, and report a truncated file as an error instead of a short but successful response.
* Drop validators instead of panicking when a file's modification time cannot be represented as an HTTP date.
* Ignore an unsatisfiable or malformed `Range` when `If-Range` does not match, instead of answering `416`.
* Cancel a queued chunk read when the client disconnects mid-response.
* Benchmark side by side against any prebuilt server with `--server LABEL=PATH`, isolate the load generator from the server's SMT siblings, and exclude samples with errors from published medians.

## 3.0.1
* Add grcov source coverage, local just recipes, and CI coverage reports.
* Add configurable `--bind` address selection with dual-stack default behavior.
* Enable TCP_NODELAY on accepted HTTP and HTTPS connections and add Rust-only local benchmarks.
* Replace external ACME test tooling with a Rust-native CA covering TLS-ALPN-01, renewal, persistence, and failure recovery.
* Remove remaining Go development tooling and migration notes.
* Harden ACME cache and file serving against cache-path races using pinned directory descriptors.
* Reuse authorized file handles and cached metadata for streaming and conditional responses.
* Correct If-Range fallback, ignore Range on HEAD, and serve full responses for unsupported multiple ranges.
* Preserve symlink MIME types, unreadable-file listings, and 404 responses for unsupported file types.

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
