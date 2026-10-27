use clap::{
    Arg, ArgAction, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
    value_parser,
};
use std::{path::PathBuf, sync::LazyLock};

#[allow(clippy::doc_markdown)]
pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    let git_hash = built_info::PACKAGE_COMMIT_HASH
        .or(built_info::GIT_COMMIT_HASH)
        .unwrap_or("unknown");
    format!("{} - {git_hash}", env!("CARGO_PKG_VERSION"))
});

/// Define arguments without opening files, sockets, or certificate storage.
#[must_use]
pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .long_version(LONG_VERSION.as_str())
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .color(ColorChoice::Auto)
        .styles(styles)
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
