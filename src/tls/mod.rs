use anyhow::{Result, bail};
use std::{net::IpAddr, path::PathBuf};

pub mod acme;
pub mod cache;
pub mod localhost;

#[derive(Debug, Clone)]
pub enum TlsMode {
    Http,
    Localhost,
    Acme(AcmeOptions),
}

#[derive(Debug, Clone)]
pub struct AcmeOptions {
    pub domain: String,
    pub cache_dir: PathBuf,
    pub staging: bool,
}

/// Canonical DNS identifiers shared by CLI and direct server callers.
///
/// # Errors
/// Returns an error for non-DNS identifiers, wildcard or single-label names,
/// trailing dots, or underscores.
pub fn normalize_domain(domain: &str) -> Result<String> {
    let normalized = domain.to_ascii_lowercase();
    if domain.parse::<IpAddr>().is_ok()
        || domain.contains('*')
        || domain.contains('_')
        || domain.ends_with('.')
        || !domain.contains('.')
        || rustls_acme::rustls::pki_types::DnsName::try_from(domain).is_err()
    {
        bail!("invalid ACME domain {domain:?}; use a DNS name such as example.com");
    }
    Ok(normalized)
}
