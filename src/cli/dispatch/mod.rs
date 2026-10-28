use crate::{
    cli::actions::Action,
    server::ServerConfig,
    tls::{AcmeOptions, TlsMode},
};
use anyhow::{Context, Result, bail};
use clap::ArgMatches;
use directories::ProjectDirs;
use std::path::PathBuf;

/// Turn parsed arguments into an action. Resource initialization belongs to execution.
///
/// # Errors
/// Returns an error for missing values, invalid domains or option combinations,
/// or unavailable default certificate storage.
pub fn handler(matches: &ArgMatches) -> Result<Action> {
    let root = matches
        .get_one::<PathBuf>("root")
        .context("missing document root")?
        .clone();
    let mut port = *matches.get_one::<u16>("port").context("missing port")?;
    let domain = matches.get_one::<String>("tls").map(String::as_str);
    let staging = matches.get_flag("acme-staging");
    let cache_override = matches.get_one::<PathBuf>("cert-cache");

    let tls = match domain {
        None | Some("") => TlsMode::Http,
        Some("localhost") => TlsMode::Localhost,
        Some(domain) => {
            let domain = crate::tls::normalize_domain(domain)?;
            let cache_dir = match cache_override {
                Some(path) => path.clone(),
                None => default_cache_dir()?,
            };
            port = 443;
            TlsMode::Acme(AcmeOptions {
                domain,
                cache_dir,
                staging,
            })
        }
    };
    if !matches!(tls, TlsMode::Acme(_)) && (staging || cache_override.is_some()) {
        bail!("--cert-cache and --acme-staging require -s with a domain other than localhost");
    }
    let config = ServerConfig { root, port, tls };
    Ok(match matches.get_one::<std::net::IpAddr>("bind") {
        Some(address) => Action::ServeBound(config, *address),
        None => Action::Serve(config),
    })
}

fn default_cache_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("io", "nbari", "www")
        .context("cannot determine certificate storage; specify --cert-cache PATH")?;
    Ok(dirs.data_local_dir().join("acme"))
}
