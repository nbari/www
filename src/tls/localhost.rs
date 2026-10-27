use anyhow::Result;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use time::{Duration, OffsetDateTime};

/// A fresh ECDSA certificate for each invocation; trust remains a client decision.
///
/// # Errors
/// Returns key generation, certificate signing, or TLS configuration errors.
pub async fn config() -> Result<RustlsConfig> {
    let mut params = CertificateParams::new(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])?;
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key)?;
    Ok(RustlsConfig::from_der(vec![cert.der().to_vec()], key.serialize_der()).await?)
}
