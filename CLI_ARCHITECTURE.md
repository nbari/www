# CLI architecture

This project follows the modular architecture from
[cron-when](https://github.com/nbari/cron-when/blob/main/CLI_ARCHITECTURE.md), adapted to a
long-running static server with local tracing.

## Structure

```text
src/
├── bin/www.rs
├── lib.rs
├── cli/
│   ├── commands/mod.rs
│   ├── dispatch/mod.rs
│   ├── actions/{mod.rs,serve.rs}
│   ├── mod.rs
│   ├── start.rs
│   └── telemetry.rs
├── server/{mod.rs,directory.rs}
└── tls/{mod.rs,acme.rs,cache.rs,localhost.rs}
```

## Responsibilities and contracts

- `commands::new() -> clap::Command` defines arguments, defaults, help, and syntactic validation.
  It performs no filesystem, network, or logging initialization.
- `dispatch::handler(&ArgMatches) -> Result<Action>` interprets arguments, validates domain and
  option combinations, computes the effective port, and chooses certificate storage.
- `Action::Serve(ServerConfig)` is the typed contract. The configuration carries the root,
  effective port, and `TlsMode::{Http, Localhost, Acme(AcmeOptions)}`.
- `cli::start() -> Result<Action>` orchestrates parsing, logging initialization, and dispatch.
- The binary matches the action and awaits `actions::serve::execute(config)`. The action delegates
  to domain services and contains no argument parsing.
- `telemetry::init(quiet)` installs local stderr tracing once per invocation. Informational logs
  are suppressed by quiet mode; fatal errors still reach stderr. No OTLP exporter is included.
- `server` validates the root, builds the shared HTTP router, binds a dual-stack listener, and
  handles lifecycle and signals. Its directory handler delegates streaming files, ranges, and
  conditionals to `tower-http`; directory HTML escapes names and encodes links.
- `tls` owns localhost certificates, ACME configuration, and private atomic persistence.

## Execution and lifecycle

```text
bin/www -> cli::start -> commands -> telemetry -> dispatch -> Action::Serve
bin/www -> actions::serve::execute -> server::run -> HTTP / localhost TLS / ACME TLS
```

HTTP routing is shared across transports. TLS-specific code does not implement file serving.
ACME challenge connections are handled by the TLS acceptor before they reach the HTTP router.
The independent ACME task continuously polls acquisition, retries, and renewal even when the
HTTP server is idle. A terminated ACME task stops the server with an error. SIGINT and SIGTERM
start a bounded graceful drain, after which certificate processing is cancelled and joined.

## Storage and tests

Certificates and account keys use persistent per-user storage, with an optional CLI override.
The cache directory is private and canonicalized; atomic replacement prevents partial entries.
Cache keys distinguish accounts, domains, and CA directory URLs. HTTP handling excludes the
active cache, including index-file and symlink aliases.

Tests separately cover argument dispatch, HTTP service behavior, persistence, the actual binary,
and ACME issuance/idle renewal/restart/outage through Pebble. The ACME CA configuration and
shutdown future can be injected without adding a custom-CA production CLI option.
