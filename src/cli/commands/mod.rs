use clap::{Arg, ArgAction, Command, value_parser};
use std::path::PathBuf;

/// Define arguments without opening files, sockets, or certificate storage.
#[must_use]
pub fn new() -> Command {
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("port")
                .short('p')
                .value_name("PORT")
                .value_parser(value_parser!(u16))
                .default_value("8000")
                .help("Listen on this port (domain HTTPS always uses 443)"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .action(ArgAction::SetTrue)
                .help("Suppress startup and request logs"),
        )
        .arg(
            Arg::new("root")
                .short('r')
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .default_value(".")
                .help("Serve this directory"),
        )
        .arg(
            Arg::new("tls")
                .short('s')
                .value_name("DOMAIN")
                .help("Enable HTTPS; localhost generates a self-signed certificate"),
        )
        .arg(
            Arg::new("cert-cache")
                .long("cert-cache")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .requires("tls")
                .help("Use this private directory for ACME accounts and certificates"),
        )
        .arg(
            Arg::new("acme-staging")
                .long("acme-staging")
                .action(ArgAction::SetTrue)
                .requires("tls")
                .help("Use Let's Encrypt staging (certificates are not publicly trusted)"),
        )
}
