//! In-process Rust RFC 8555 / RFC 8737 TLS-ALPN-01 ACME test CA, plus opt-in live Let's Encrypt staging.
//! Run local ACME suite with: `just acme`
//! Run live staging with: `ACME_DOMAIN=example.com ACME_INGRESS_PROBE_CMD='...' just acme-live`

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, head, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData,
    SerialNumber, SignatureAlgorithm,
};
use ring::{
    digest::{SHA256, digest},
    signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey},
};
use rustls_acme::{
    AccountCache, AcmeConfig, CertCache,
    rustls::{
        ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::oneshot;
use www::{
    server,
    tls::{self, acme, cache::PrivateCache},
};
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
    prelude::FromDer,
};

#[path = "acme/validation.rs"]
mod validation;

const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";
const OID_PE_ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

const LETSENCRYPT_STAGING_ROOT_X1_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBm\n\
MQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\n\
aXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\n\
ZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQzOFowZjELMAkGA1UE\n\
BhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\n\
YXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQgUGVhciBYMTCC\n\
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhsc\n\
ZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPWnL++fgehT0FbRHZg\n\
jOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4\n\
wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmD\n\
oaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPt\n\
TdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstO\n\
fRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6\n\
rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQ\n\
FjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8\n\
mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/\n\
GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26bW5LKeru\n\
mJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\n\
Af8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCsYyXDFDANBgkqhkiG\n\
9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8Y\n\
nLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrNKHkn5kn+9E9LCjCaEsyIIn2j\n\
qdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1x\n\
qAeaAhQ2rgo1F58hcflgqKTXnpPM02intVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/\n\
sTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5Q\n\
CJL6TERVDbM/aAPly8kJ1sWGLuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/\n\
5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmR\n\
xUuXY4xRdh45tMJnLTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/\n\
fxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWof\n\
gN9WUwCbEMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M\n\
7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc=\n\
-----END CERTIFICATE-----\n";

const LETSENCRYPT_STAGING_ROOT_X2_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL\n\
MAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\n\
eSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\n\
b2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE\n\
BhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\n\
YXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy\n\
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo\n\
FQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT\n\
VqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\n\
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI\n\
KoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo\n\
uc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9\n\
vbtH7QiVzeKCOTQPINyRql6P\n\
-----END CERTIFICATE-----\n";

const LETSENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Clone, Debug)]
struct RawPublicKey {
    raw: Vec<u8>,
}

impl PublicKeyData for RawPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

#[derive(Debug)]
struct SelfSignedAlpnVerifier;

impl ServerCertVerifier for SelfSignedAlpnVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let (_, cert) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| RustlsError::General("invalid X.509 DER in TLS-ALPN-01 cert".into()))?;
        cert.verify_signature(None).map_err(|_| {
            RustlsError::General("TLS-ALPN-01 validation certificate is not self-signed".into())
        })?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_challenge_handshake_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_challenge_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

// Test-only P-256 verifier: WebPKI's general certificate parser rejects the
// mandatory critical acmeIdentifier extension. Still verify CertificateVerify
// cryptographically, including the advertised signature scheme.
fn verify_challenge_handshake_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
    if dss.scheme != SignatureScheme::ECDSA_NISTP256_SHA256 {
        return Err(RustlsError::General(
            "unsupported challenge signature scheme".into(),
        ));
    }
    let (_, parsed) = parse_x509_certificate(cert.as_ref())
        .map_err(|_| RustlsError::General("invalid challenge certificate".into()))?;
    UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        parsed.public_key().subject_public_key.data.as_ref(),
    )
    .verify(message, dss.signature())
    .map_err(|_| RustlsError::General("invalid challenge handshake signature".into()))?;
    Ok(HandshakeSignatureValid::assertion())
}

fn validate_tls_alpn_01_certificate(
    cert_der: &[u8],
    expected_domain: &str,
    token: &str,
    account_thumbprint: &str,
) -> Result<()> {
    let (rem, cert) =
        parse_x509_certificate(cert_der).context("failed to parse TLS-ALPN-01 certificate DER")?;
    if !rem.is_empty() {
        bail!("trailing bytes in TLS-ALPN-01 certificate DER");
    }
    cert.verify_signature(None)
        .context("TLS-ALPN-01 certificate signature verification failed")?;

    let san_ext = cert
        .subject_alternative_name()
        .context("invalid SubjectAlternativeName extension")?
        .context("missing SubjectAlternativeName extension")?;
    if san_ext.value.general_names.len() != 1 {
        bail!(
            "expected exactly 1 SubjectAlternativeName entry, got {}",
            san_ext.value.general_names.len()
        );
    }
    match san_ext.value.general_names.first() {
        Some(GeneralName::DNSName(dns)) if dns.eq_ignore_ascii_case(expected_domain) => {}
        other => {
            bail!("TLS-ALPN-01 SAN {other:?} does not match expected domain {expected_domain:?}")
        }
    }

    let key_auth = format!("{token}.{account_thumbprint}");
    let expected_digest = digest(&SHA256, key_auth.as_bytes());
    let mut expected_ext_der = Vec::with_capacity(34);
    expected_ext_der.push(0x04);
    expected_ext_der.push(0x20);
    expected_ext_der.extend_from_slice(expected_digest.as_ref());

    let mut acme_exts = cert
        .extensions()
        .iter()
        .filter(|ext| ext.oid.to_id_string() == OID_PE_ACME_IDENTIFIER);
    let acme_ext = acme_exts
        .next()
        .context("missing id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31) extension")?;
    if acme_exts.next().is_some() {
        bail!("duplicate id-pe-acmeIdentifier extension");
    }
    if !acme_ext.critical {
        bail!("id-pe-acmeIdentifier extension must be marked critical");
    }
    if acme_ext.value != expected_ext_der.as_slice() {
        bail!("id-pe-acmeIdentifier SHA-256 digest mismatch");
    }
    Ok(())
}

async fn probe_tls_alpn_01_challenge(
    target_port: u16,
    domain: &str,
    token: &str,
    account_thumbprint: &str,
) -> Result<()> {
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(
        rustls_acme::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(SelfSignedAlpnVerifier))
    .with_no_client_auth();
    client_config.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, target_port)),
    )
    .await
    .context("TLS-ALPN-01 TCP connect timed out")??;
    let server_name = ServerName::try_from(domain.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid DNS name {domain:?}"))?;
    let tls_stream =
        tokio::time::timeout(Duration::from_secs(3), connector.connect(server_name, tcp))
            .await
            .context("TLS-ALPN-01 handshake timed out")??;

    let (_, session) = tls_stream.get_ref();
    if session.alpn_protocol() != Some(ACME_TLS_ALPN_PROTOCOL) {
        bail!(
            "server did not negotiate acme-tls/1 ALPN (got {:?})",
            session.alpn_protocol()
        );
    }
    let certs = session
        .peer_certificates()
        .context("server presented no peer certificates during TLS-ALPN-01 handshake")?;
    let leaf = certs
        .first()
        .context("empty peer certificate chain in TLS-ALPN-01 handshake")?;
    validate_tls_alpn_01_certificate(leaf.as_ref(), domain, token, account_thumbprint)
}

fn validate_and_extract_csr(csr_der: &[u8], expected_domains: &[String]) -> Result<RawPublicKey> {
    let (rem, csr) =
        X509CertificationRequest::from_der(csr_der).context("failed to parse CSR DER")?;
    if !rem.is_empty() {
        bail!("trailing bytes in CSR DER");
    }
    csr.verify_signature()
        .context("CSR cryptographic signature verification failed")?;

    let mut csr_domains = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => csr_domains.push((*dns).to_ascii_lowercase()),
                        other => bail!("unsupported CSR SAN entry: {other:?}"),
                    }
                }
            }
        }
    }
    let expected_normalized: Vec<String> = expected_domains
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    if csr_domains != expected_normalized {
        bail!("CSR SAN domains {csr_domains:?} do not match order domains {expected_normalized:?}");
    }
    let raw_key = csr
        .certification_request_info
        .subject_pki
        .subject_public_key
        .data
        .to_vec();
    if raw_key.len() != 65 || raw_key.first().copied() != Some(0x04) {
        bail!(
            "expected uncompressed P-256 subjectPublicKeyInfo (65 bytes), got {} bytes",
            raw_key.len()
        );
    }
    Ok(RawPublicKey { raw: raw_key })
}

#[derive(Clone, Debug)]
struct AccountRecord {
    public_key_uncompressed: Vec<u8>,
    thumbprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthState {
    Pending,
    Valid,
    Invalid,
}

#[derive(Clone, Debug)]
struct AuthorizationRecord {
    account_id: u64,
    domain: String,
    token: String,
    state: AuthState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OrderState {
    Pending,
    Ready,
    Valid { cert_id: u64 },
    Invalid,
}

#[derive(Clone, Debug)]
struct OrderRecord {
    account_id: u64,
    domains: Vec<String>,
    auth_ids: Vec<u64>,
    state: OrderState,
}

struct CaInner {
    accounts: BTreeMap<u64, AccountRecord>,
    authorizations: BTreeMap<u64, AuthorizationRecord>,
    orders: BTreeMap<u64, OrderRecord>,
    certificates: BTreeMap<u64, String>,
    next_id: u64,
}

struct CaState {
    base_url: String,
    target_port: u16,
    validity_secs: i64,
    ca_cert: rcgen::Certificate,
    ca_cert_pem: String,
    ca_key: KeyPair,
    failing: Arc<AtomicBool>,
    failed_requests: Arc<AtomicU64>,
    serial_counter: AtomicU64,
    nonces: Mutex<BTreeSet<String>>,
    inner: Mutex<CaInner>,
}

impl CaState {
    fn issue_nonce(&self) -> Result<String> {
        let nonce = random_nonce_hex()?;
        self.nonces
            .lock()
            .map_err(|_| anyhow::anyhow!("CA mutex poisoned"))?
            .insert(nonce.clone());
        Ok(nonce)
    }

    fn check_online(&self) -> Option<Response> {
        if self.failing.load(Ordering::SeqCst) {
            self.failed_requests.fetch_add(1, Ordering::SeqCst);
            let body = json!({
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": "simulated CA outage"
            });
            return Some((StatusCode::SERVICE_UNAVAILABLE, body.to_string()).into_response());
        }
        None
    }

    fn verify_jws(
        &self,
        expected_url: &str,
        body: &[u8],
        require_kid: bool,
    ) -> Result<(u64, Vec<u8>)> {
        let envelope: Value = serde_json::from_slice(body).context("invalid JWS JSON")?;
        let protected_b64 = envelope
            .get("protected")
            .and_then(Value::as_str)
            .context("missing JWS protected header")?;
        let payload_b64 = envelope
            .get("payload")
            .and_then(Value::as_str)
            .context("missing JWS payload")?;
        let signature_b64 = envelope
            .get("signature")
            .and_then(Value::as_str)
            .context("missing JWS signature")?;

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(protected_b64)
            .context("invalid base64url in JWS protected")?;
        let protected: Value =
            serde_json::from_slice(&protected_bytes).context("invalid protected header JSON")?;
        if protected.get("alg").and_then(Value::as_str) != Some("ES256") {
            bail!("unsupported JWS alg (expected ES256)");
        }
        if protected.get("url").and_then(Value::as_str) != Some(expected_url) {
            bail!(
                "JWS url {:?} does not match request URL {expected_url:?}",
                protected.get("url")
            );
        }
        let nonce = protected
            .get("nonce")
            .and_then(Value::as_str)
            .context("missing JWS replay nonce")?;

        if !self
            .nonces
            .lock()
            .map_err(|_| anyhow::anyhow!("CA nonce mutex poisoned"))?
            .remove(nonce)
        {
            bail!("invalid or replayed ACME nonce {nonce:?}");
        }

        let (account_id, pub_key, registration) = if require_kid {
            if protected.get("jwk").is_some() {
                bail!("kid-authenticated request must not include jwk");
            }
            let kid = protected
                .get("kid")
                .and_then(Value::as_str)
                .context("missing JWS kid")?;
            let id_str = kid
                .strip_prefix(&format!("{}/acct/", self.base_url))
                .context("unrecognized JWS kid prefix")?;
            let id: u64 = id_str.parse().context("invalid account id in kid")?;
            let acct = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("CA mutex poisoned"))?
                .accounts
                .get(&id)
                .cloned()
                .with_context(|| format!("unknown account id {id}"))?;
            (id, acct.public_key_uncompressed, None)
        } else {
            if protected.get("kid").is_some() {
                bail!("newAccount request must use jwk without kid");
            }
            let record = registration_key(&protected)?;
            let uncompressed = record.public_key_uncompressed.clone();
            (0, uncompressed, Some(record))
        };

        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .context("invalid JWS signature base64url")?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pub_key)
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("JWS ECDSA P-256 signature verification failed"))?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .context("invalid JWS payload base64url")?;
        let account_id = match registration {
            Some(record) => self.register_account(record, &payload)?,
            None => account_id,
        };
        Ok((account_id, payload))
    }

    fn register_account(&self, record: AccountRecord, payload: &[u8]) -> Result<u64> {
        let request: Value = serde_json::from_slice(payload)?;
        if !request.is_object() {
            bail!("newAccount payload must be a JSON object");
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("CA mutex poisoned"))?;
        if let Some((&id, _)) = guard
            .accounts
            .iter()
            .find(|(_, account)| account.thumbprint == record.thumbprint)
        {
            Ok(id)
        } else {
            if request.get("onlyReturnExisting") == Some(&Value::Bool(true)) {
                bail!("account does not exist");
            }
            guard.next_id += 1;
            let id = guard.next_id;
            guard.accounts.insert(id, record);
            Ok(id)
        }
    }

    fn sign_leaf_certificate(
        &self,
        domains: &[String],
        public_key: &RawPublicKey,
    ) -> Result<String> {
        let mut leaf_params = CertificateParams::new(domains.to_vec())?;
        leaf_params.distinguished_name = DistinguishedName::new();
        if let Some(first) = domains.first() {
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, first.clone());
        }
        let now = OffsetDateTime::now_utc();
        leaf_params.not_before = now - TimeDuration::seconds(1);
        leaf_params.not_after = now + TimeDuration::seconds(self.validity_secs);
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        leaf_params.serial_number = Some(SerialNumber::from(serial));

        let leaf_cert = leaf_params.signed_by(public_key, &self.ca_cert, &self.ca_key)?;
        Ok(format!("{}\n{}", leaf_cert.pem(), self.ca_cert_pem))
    }
}

fn registration_key(protected: &Value) -> Result<AccountRecord> {
    let jwk = protected.get("jwk").context("newAccount JWS missing jwk")?;
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        bail!("unsupported JWK curve or key type");
    }
    let x_b64 = jwk
        .get("x")
        .and_then(Value::as_str)
        .context("missing JWK x")?;
    let y_b64 = jwk
        .get("y")
        .and_then(Value::as_str)
        .context("missing JWK y")?;
    let x = URL_SAFE_NO_PAD.decode(x_b64).context("invalid JWK x")?;
    let y = URL_SAFE_NO_PAD.decode(y_b64).context("invalid JWK y")?;
    if x.len() != 32 || y.len() != 32 {
        bail!("invalid P-256 coordinate length");
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    let thumb_json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
    let thumb = URL_SAFE_NO_PAD.encode(digest(&SHA256, thumb_json.as_bytes()));

    Ok(AccountRecord {
        public_key_uncompressed: uncompressed,
        thumbprint: thumb,
    })
}

fn acme_response(
    state: &CaState,
    status: StatusCode,
    location: Option<String>,
    content_type: &'static str,
    body: String,
) -> Response {
    let nonce = state.issue_nonce().unwrap_or_default();
    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&nonce) {
        headers.insert("replay-nonce", val);
    }
    headers.insert("content-type", HeaderValue::from_static(content_type));
    if let Ok(len) = HeaderValue::from_str(&body.len().to_string()) {
        headers.insert("content-length", len);
    }
    if let Some(loc) = location
        && let Ok(val) = HeaderValue::from_str(&loc)
    {
        headers.insert("location", val);
    }
    (status, headers, body).into_response()
}

fn acme_error(state: &CaState, status: StatusCode, detail: impl Into<String>) -> Response {
    let body = json!({
        "type": "urn:ietf:params:acme:error:malformed",
        "detail": detail.into(),
    });
    acme_response(
        state,
        status,
        None,
        "application/problem+json",
        body.to_string(),
    )
}

async fn handle_dir(State(state): State<Arc<CaState>>) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let body = json!({
        "newNonce": format!("{}/new-nonce", state.base_url),
        "newAccount": format!("{}/new-acct", state.base_url),
        "newOrder": format!("{}/new-order", state.base_url),
    });
    acme_response(
        &state,
        StatusCode::OK,
        None,
        "application/json",
        body.to_string(),
    )
}

async fn handle_new_nonce(State(state): State<Arc<CaState>>) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    acme_response(
        &state,
        StatusCode::OK,
        None,
        "application/json",
        String::new(),
    )
}

async fn handle_new_account(State(state): State<Arc<CaState>>, body: Bytes) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/new-acct", state.base_url);
    let (account_id, _payload) = match state.verify_jws(&url, &body, false) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    let location = format!("{}/acct/{account_id}", state.base_url);
    let resp_body = json!({ "status": "valid" }).to_string();
    acme_response(
        &state,
        StatusCode::CREATED,
        Some(location),
        "application/json",
        resp_body,
    )
}

async fn handle_new_order(State(state): State<Arc<CaState>>, body: Bytes) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/new-order", state.base_url);
    let (account_id, payload) = match state.verify_jws(&url, &body, true) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    let req: Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    let Some(identifiers) = req.get("identifiers").and_then(Value::as_array) else {
        return acme_error(&state, StatusCode::BAD_REQUEST, "missing identifiers array");
    };
    if identifiers.is_empty() {
        return acme_error(&state, StatusCode::BAD_REQUEST, "empty identifiers");
    }
    let mut domains = Vec::with_capacity(identifiers.len());
    for ident in identifiers {
        if ident.get("type").and_then(Value::as_str) != Some("dns") {
            return acme_error(
                &state,
                StatusCode::BAD_REQUEST,
                "unsupported identifier type",
            );
        }
        let Some(val) = ident.get("value").and_then(Value::as_str) else {
            return acme_error(&state, StatusCode::BAD_REQUEST, "missing identifier value");
        };
        if !val.eq_ignore_ascii_case("localhost") {
            return acme_error(
                &state,
                StatusCode::BAD_REQUEST,
                "test CA only validates localhost",
            );
        }
        domains.push(val.to_ascii_lowercase());
    }

    let mut auth_ids = Vec::with_capacity(domains.len());
    let mut auth_urls = Vec::with_capacity(domains.len());
    let order_id = {
        let Ok(mut guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        for domain in &domains {
            guard.next_id += 1;
            let auth_id = guard.next_id;
            let token = match random_nonce_hex() {
                Ok(token) => token,
                Err(err) => {
                    return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
                }
            };
            guard.authorizations.insert(
                auth_id,
                AuthorizationRecord {
                    account_id,
                    domain: domain.clone(),
                    token,
                    state: AuthState::Pending,
                },
            );
            auth_ids.push(auth_id);
            auth_urls.push(format!("{}/authz/{auth_id}", state.base_url));
        }
        guard.next_id += 1;
        let order_id = guard.next_id;
        guard.orders.insert(
            order_id,
            OrderRecord {
                account_id,
                domains,
                auth_ids,
                state: OrderState::Pending,
            },
        );
        order_id
    };

    let location = format!("{}/order/{order_id}", state.base_url);
    let finalize = format!("{}/finalize/{order_id}", state.base_url);
    let resp_body = json!({
        "status": "pending",
        "authorizations": auth_urls,
        "finalize": finalize,
    })
    .to_string();
    acme_response(
        &state,
        StatusCode::CREATED,
        Some(location),
        "application/json",
        resp_body,
    )
}

async fn handle_authz(
    State(state): State<Arc<CaState>>,
    AxumPath(auth_id): AxumPath<u64>,
    body: Bytes,
) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/authz/{auth_id}", state.base_url);
    let (account_id, payload) = match state.verify_jws(&url, &body, true) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    if !payload.is_empty() {
        return acme_error(
            &state,
            StatusCode::BAD_REQUEST,
            "POST-as-GET payload must be empty",
        );
    }
    let auth = {
        let Ok(guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        match guard.authorizations.get(&auth_id) {
            Some(a) if a.account_id == account_id => a.clone(),
            _ => return acme_error(&state, StatusCode::NOT_FOUND, "unknown authorization"),
        }
    };
    let status_str = match auth.state {
        AuthState::Pending => "pending",
        AuthState::Valid => "valid",
        AuthState::Invalid => "invalid",
    };
    let resp_body = json!({
        "status": status_str,
        "identifier": { "type": "dns", "value": auth.domain },
        "challenges": [{
            "type": "tls-alpn-01",
            "url": format!("{}/chall/{auth_id}", state.base_url),
            "token": auth.token,
        }]
    })
    .to_string();
    acme_response(&state, StatusCode::OK, None, "application/json", resp_body)
}

async fn handle_challenge(
    State(state): State<Arc<CaState>>,
    AxumPath(auth_id): AxumPath<u64>,
    body: Bytes,
) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/chall/{auth_id}", state.base_url);
    let (account_id, payload) = match state.verify_jws(&url, &body, true) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    if !serde_json::from_slice::<Value>(&payload)
        .ok()
        .and_then(|value| value.as_object().map(serde_json::Map::is_empty))
        .unwrap_or(false)
    {
        return acme_error(
            &state,
            StatusCode::BAD_REQUEST,
            "challenge payload must be {}",
        );
    }
    let (auth, thumbprint) = {
        let Ok(guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        let Some(auth) = guard.authorizations.get(&auth_id).cloned() else {
            return acme_error(&state, StatusCode::NOT_FOUND, "unknown challenge");
        };
        if auth.account_id != account_id {
            return acme_error(&state, StatusCode::FORBIDDEN, "account mismatch");
        }
        let Some(acct) = guard.accounts.get(&account_id) else {
            return acme_error(&state, StatusCode::FORBIDDEN, "missing account");
        };
        (auth, acct.thumbprint.clone())
    };

    let probe_res =
        probe_tls_alpn_01_challenge(state.target_port, &auth.domain, &auth.token, &thumbprint)
            .await;
    {
        let Ok(mut guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        if let Some(record) = guard.authorizations.get_mut(&auth_id) {
            record.state = if probe_res.is_ok() {
                AuthState::Valid
            } else {
                AuthState::Invalid
            };
        }
        let CaInner {
            orders,
            authorizations,
            ..
        } = &mut *guard;
        for order in orders.values_mut() {
            if order.auth_ids.contains(&auth_id) && order.state == OrderState::Pending {
                let all_valid = order.auth_ids.iter().all(|id| {
                    authorizations
                        .get(id)
                        .is_some_and(|a| a.state == AuthState::Valid)
                });
                let any_invalid = order.auth_ids.iter().any(|id| {
                    authorizations
                        .get(id)
                        .is_some_and(|a| a.state == AuthState::Invalid)
                });
                if all_valid {
                    order.state = OrderState::Ready;
                } else if any_invalid {
                    order.state = OrderState::Invalid;
                }
            }
        }
    }
    if let Err(err) = probe_res {
        return acme_error(
            &state,
            StatusCode::BAD_REQUEST,
            format!("TLS-ALPN-01 validation failed: {err}"),
        );
    }
    let resp_body = json!({
        "type": "tls-alpn-01",
        "url": url,
        "token": auth.token,
        "status": "valid"
    })
    .to_string();
    acme_response(&state, StatusCode::OK, None, "application/json", resp_body)
}

fn serialize_order_json(state: &CaState, order_id: u64, order: &OrderRecord) -> String {
    let auth_urls: Vec<String> = order
        .auth_ids
        .iter()
        .map(|id| format!("{}/authz/{id}", state.base_url))
        .collect();
    let finalize = format!("{}/finalize/{order_id}", state.base_url);
    match order.state {
        OrderState::Pending => json!({
            "status": "pending",
            "authorizations": auth_urls,
            "finalize": finalize,
        })
        .to_string(),
        OrderState::Ready => json!({
            "status": "ready",
            "authorizations": auth_urls,
            "finalize": finalize,
        })
        .to_string(),
        OrderState::Invalid => json!({
            "status": "invalid",
            "authorizations": auth_urls,
            "finalize": finalize,
        })
        .to_string(),
        OrderState::Valid { cert_id } => json!({
            "status": "valid",
            "authorizations": auth_urls,
            "finalize": finalize,
            "certificate": format!("{}/cert/{cert_id}", state.base_url),
        })
        .to_string(),
    }
}

async fn handle_order(
    State(state): State<Arc<CaState>>,
    AxumPath(order_id): AxumPath<u64>,
    body: Bytes,
) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/order/{order_id}", state.base_url);
    let (account_id, payload) = match state.verify_jws(&url, &body, true) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    if !payload.is_empty() {
        return acme_error(
            &state,
            StatusCode::BAD_REQUEST,
            "POST-as-GET payload must be empty",
        );
    }
    let order = {
        let Ok(guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        match guard.orders.get(&order_id) {
            Some(o) if o.account_id == account_id => o.clone(),
            _ => return acme_error(&state, StatusCode::NOT_FOUND, "unknown order"),
        }
    };
    acme_response(
        &state,
        StatusCode::OK,
        Some(url),
        "application/json",
        serialize_order_json(&state, order_id, &order),
    )
}

async fn handle_finalize(
    State(state): State<Arc<CaState>>,
    AxumPath(order_id): AxumPath<u64>,
    body: Bytes,
) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/finalize/{order_id}", state.base_url);
    let (account_id, payload) = match state.verify_jws(&url, &body, true) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    let req: Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    let Some(csr_b64) = req.get("csr").and_then(Value::as_str) else {
        return acme_error(&state, StatusCode::BAD_REQUEST, "missing csr field");
    };
    let Ok(csr_der) = URL_SAFE_NO_PAD.decode(csr_b64) else {
        return acme_error(&state, StatusCode::BAD_REQUEST, "invalid csr base64url");
    };

    let order = {
        let Ok(guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        match guard.orders.get(&order_id) {
            Some(o) if o.account_id == account_id => o.clone(),
            _ => return acme_error(&state, StatusCode::NOT_FOUND, "unknown order"),
        }
    };
    if order.state != OrderState::Ready {
        return acme_error(
            &state,
            StatusCode::FORBIDDEN,
            format!(
                "order {order_id} is not ready for finalization (state={:?})",
                order.state
            ),
        );
    }

    let pub_key = match validate_and_extract_csr(&csr_der, &order.domains) {
        Ok(pk) => pk,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    let cert_pem = match state.sign_leaf_certificate(&order.domains, &pub_key) {
        Ok(pem) => pem,
        Err(err) => return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    let updated_order = {
        let Ok(mut guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        let all_valid = order.auth_ids.iter().all(|id| {
            guard
                .authorizations
                .get(id)
                .is_some_and(|a| a.state == AuthState::Valid)
        });
        if !all_valid {
            return acme_error(
                &state,
                StatusCode::FORBIDDEN,
                "order authorizations are not all valid",
            );
        }
        guard.next_id += 1;
        let cert_id = guard.next_id;
        guard.certificates.insert(cert_id, cert_pem);
        let Some(order_mut) = guard.orders.get_mut(&order_id) else {
            return acme_error(&state, StatusCode::NOT_FOUND, "order disappeared");
        };
        order_mut.state = OrderState::Valid { cert_id };
        order_mut.clone()
    };

    acme_response(
        &state,
        StatusCode::OK,
        Some(format!("{}/order/{order_id}", state.base_url)),
        "application/json",
        serialize_order_json(&state, order_id, &updated_order),
    )
}

async fn handle_cert(
    State(state): State<Arc<CaState>>,
    AxumPath(cert_id): AxumPath<u64>,
    body: Bytes,
) -> Response {
    if let Some(resp) = state.check_online() {
        return resp;
    }
    let url = format!("{}/cert/{cert_id}", state.base_url);
    let (_account_id, payload) = match state.verify_jws(&url, &body, true) {
        Ok(res) => res,
        Err(err) => return acme_error(&state, StatusCode::BAD_REQUEST, err.to_string()),
    };
    if !payload.is_empty() {
        return acme_error(
            &state,
            StatusCode::BAD_REQUEST,
            "POST-as-GET payload must be empty",
        );
    }
    let pem = {
        let Ok(guard) = state.inner.lock() else {
            return acme_error(&state, StatusCode::INTERNAL_SERVER_ERROR, "poisoned");
        };
        let Some(pem) = guard.certificates.get(&cert_id).cloned() else {
            return acme_error(&state, StatusCode::NOT_FOUND, "unknown certificate");
        };
        pem
    };
    acme_response(
        &state,
        StatusCode::OK,
        None,
        "application/pem-certificate-chain",
        pem,
    )
}

fn test_ca_params() -> Result<CertificateParams> {
    let mut ca_params = CertificateParams::new(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "www Rust Test CA");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let now = OffsetDateTime::now_utc();
    ca_params.not_before = now - TimeDuration::days(1);
    ca_params.not_after = now + TimeDuration::days(7);

    Ok(ca_params)
}

struct Authority {
    handle: axum_server::Handle<SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    directory: String,
    trust: Arc<ClientConfig>,
    client: reqwest::Client,
    failing: Arc<AtomicBool>,
    failed_requests: Arc<AtomicU64>,
    state: Arc<CaState>,
}

impl Authority {
    async fn start(target_port: u16, validity_secs: i64) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let ca_port = listener.local_addr()?.port();
        let base_url = format!("https://localhost:{ca_port}");

        let ca_params = test_ca_params()?;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca_cert_der = ca_cert.der().to_vec();
        let ca_cert_pem = ca_cert.pem();

        let api_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let api_params = CertificateParams::new(vec!["localhost".to_owned()])?;
        let api_cert = api_params.signed_by(&api_key, &ca_cert, &ca_key)?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_der(
            vec![api_cert.der().to_vec(), ca_cert_der.clone()],
            api_key.serialize_der(),
        )
        .await?;

        let failing = Arc::new(AtomicBool::new(false));
        let failed_requests = Arc::new(AtomicU64::new(0));
        let state = Arc::new(CaState {
            base_url: base_url.clone(),
            target_port,
            validity_secs,
            ca_cert,
            ca_cert_pem: ca_cert_pem.clone(),
            ca_key,
            failing: Arc::clone(&failing),
            failed_requests: Arc::clone(&failed_requests),
            serial_counter: AtomicU64::new(1),
            nonces: Mutex::new(BTreeSet::new()),
            inner: Mutex::new(CaInner {
                accounts: BTreeMap::new(),
                authorizations: BTreeMap::new(),
                orders: BTreeMap::new(),
                certificates: BTreeMap::new(),
                next_id: 0,
            }),
        });

        let router = Router::new()
            .route("/dir", get(handle_dir))
            .route("/new-nonce", head(handle_new_nonce).get(handle_new_nonce))
            .route("/new-acct", post(handle_new_account))
            .route("/new-order", post(handle_new_order))
            .route("/authz/{id}", post(handle_authz))
            .route("/chall/{id}", post(handle_challenge))
            .route("/order/{id}", post(handle_order))
            .route("/finalize/{id}", post(handle_finalize))
            .route("/cert/{id}", post(handle_cert))
            .with_state(Arc::clone(&state));

        let handle = axum_server::Handle::new();
        let srv = axum_server::from_tcp_rustls(listener, tls)?
            .map(|acceptor| acceptor.acceptor(axum_server::accept::NoDelayAcceptor::new()))
            .handle(handle.clone())
            .serve(router.into_make_service());
        let task = tokio::spawn(srv);

        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca_cert_der))?;
        let mut trust = ClientConfig::builder_with_provider(Arc::new(
            rustls_acme::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        // Resumed handshakes retain the old peer certificate. Disable tickets
        // as well as HTTP pooling so deployment checks observe the live leaf.
        trust.resumption = rustls_acme::rustls::client::Resumption::disabled();
        let trust = Arc::new(trust);
        let client = reqwest::Client::builder()
            .no_proxy()
            .use_preconfigured_tls((*trust).clone())
            .tls_info(true)
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(2))
            .build()?;

        let directory = format!("{base_url}/dir");
        Ok(Self {
            handle,
            task,
            directory,
            trust,
            client,
            failing,
            failed_requests,
            state,
        })
    }

    fn set_failing(&self, fail: bool) {
        self.failing.store(fail, Ordering::SeqCst);
    }

    fn failed_request_count(&self) -> u64 {
        self.failed_requests.load(Ordering::SeqCst)
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}

async fn launch_server(
    cache: PrivateCache,
    root: &Path,
    listener: TcpListener,
    directory: &str,
    trust: Arc<ClientConfig>,
) -> Result<(oneshot::Sender<()>, tokio::task::JoinHandle<Result<()>>)> {
    let app = server::router(root.to_owned(), Some(cache.directory().to_owned())).await?;
    let config = AcmeConfig::new_with_client_config(["localhost"], trust)
        .cache(cache)
        .directory(directory);
    let (stop, shutdown) = oneshot::channel();
    let task = tokio::spawn(acme::serve(listener, app, config, async {
        let _ = shutdown.await;
    }));
    Ok((stop, task))
}

async fn stop_server(
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(12), task).await???;
    Ok(())
}

async fn cached(cache: &PrivateCache, directory: &str) -> Result<Vec<u8>> {
    cache
        .load_cert(&["localhost".to_owned()], directory)
        .await?
        .context("certificate was not cached")
}

fn cached_leaf(pem: &[u8]) -> Result<CertificateDer<'static>> {
    use rustls_acme::rustls::pki_types::pem::PemObject as _;
    CertificateDer::from_pem_slice(pem).context("cached certificate has no PEM leaf")
}

fn peer_certificate(response: &reqwest::Response) -> Result<Vec<u8>> {
    response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .map(<[u8]>::to_vec)
        .context("HTTPS response did not expose peer certificate")
}

async fn verify_deployed_certificate(
    client: &reqwest::Client,
    url: &str,
    pem: &[u8],
) -> Result<()> {
    let expected = cached_leaf(pem)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // The client disables pooling; every observation performs a fresh TLS
        // handshake, so an old keep-alive connection cannot hide failed rotation.
        if let Ok(response) = client.get(url).send().await {
            let actual = peer_certificate(&response)?;
            assert_eq!(response.error_for_status()?.text().await?, "ACME works");
            if actual == expected.as_ref() {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!("fresh HTTPS connection did not serve the cached certificate");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn validator_rejects_bad_san_alpn_digest_criticality_and_csr() -> Result<()> {
    let domain = "localhost";
    let token = "test-token-12345";
    let thumb = "test-thumbprint-67890";
    let key_auth = format!("{token}.{thumb}");
    let valid_digest = digest(&SHA256, key_auth.as_bytes());

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut valid_params = CertificateParams::new(vec![domain.to_owned()])?;
    valid_params.custom_extensions =
        vec![CustomExtension::new_acme_identifier(valid_digest.as_ref())];
    let valid_cert = valid_params.self_signed(&key)?;
    validate_tls_alpn_01_certificate(valid_cert.der(), domain, token, thumb)?;

    // Wrong domain SAN must fail.
    assert!(
        validate_tls_alpn_01_certificate(valid_cert.der(), "other.example", token, thumb).is_err()
    );

    // Wrong token / keyAuthorization digest must fail.
    assert!(
        validate_tls_alpn_01_certificate(valid_cert.der(), domain, "wrong-token", thumb).is_err()
    );

    // Non-critical acmeIdentifier extension must fail.
    let mut non_crit_ext = CustomExtension::new_acme_identifier(valid_digest.as_ref());
    non_crit_ext.set_criticality(false);
    let mut non_crit_params = CertificateParams::new(vec![domain.to_owned()])?;
    non_crit_params.custom_extensions = vec![non_crit_ext];
    let non_crit_cert = non_crit_params.self_signed(&key)?;
    assert!(validate_tls_alpn_01_certificate(non_crit_cert.der(), domain, token, thumb).is_err());

    // Missing acmeIdentifier extension must fail.
    let no_ext_cert = CertificateParams::new(vec![domain.to_owned()])?.self_signed(&key)?;
    assert!(validate_tls_alpn_01_certificate(no_ext_cert.der(), domain, token, thumb).is_err());

    // CSR validation: matching domain succeeds; mismatched domain or corrupted signature fails.
    let csr_params = CertificateParams::new(vec![domain.to_owned()])?;
    let csr = csr_params.serialize_request(&key)?;
    let extracted = validate_and_extract_csr(csr.der(), &[domain.to_owned()])?;
    assert_eq!(extracted.der_bytes(), key.der_bytes());
    assert!(validate_and_extract_csr(csr.der(), &["wrong.example".to_owned()]).is_err());

    let mut corrupted_csr = csr.der().as_ref().to_vec();
    if let Some(last) = corrupted_csr.last_mut() {
        *last ^= 0xff;
    }
    assert!(validate_and_extract_csr(&corrupted_csr, &[domain.to_owned()]).is_err());
    Ok(())
}

#[tokio::test]
async fn issue_renew_restart_and_recover_from_ca_outage() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _ = rustls_acme::rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("hello.txt"), "ACME works")?;
    let cache = PrivateCache::open(root.path().join("acme")).await?;
    let listener = server::bind(0)?;
    let port = listener.local_addr()?.port();

    // Short-lived certificates exercise real idle renewal before expiration.
    let authority = Authority::start(port, 30).await?;
    let directory = authority.directory.clone();
    let trust = authority.trust.clone();
    let client = authority.client.clone();

    let (stop, task) = launch_server(
        cache.clone(),
        root.path(),
        listener,
        &directory,
        trust.clone(),
    )
    .await?;
    let url = format!("https://localhost:{port}/hello.txt");
    let deadline = Instant::now() + Duration::from_secs(10);
    let original_der = loop {
        if let Ok(response) = client.get(&url).send().await {
            let der = peer_certificate(&response)?;
            let (_, x509) = parse_x509_certificate(&der)?;
            let san = x509
                .subject_alternative_name()?
                .context("issued leaf missing SAN")?;
            assert!(
                san.value
                    .general_names
                    .contains(&GeneralName::DNSName("localhost")),
                "issued leaf SAN does not contain localhost"
            );
            assert_eq!(response.error_for_status()?.text().await?, "ACME works");
            break der;
        }
        if task.is_finished() || Instant::now() > deadline {
            bail!("initial ACME issuance failed or timed out");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let head = client.head(&url).send().await?.error_for_status()?;
    assert_eq!(
        head.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("10")
    );
    assert!(head.bytes().await?.is_empty());

    let original = cached(&cache, &directory).await?;
    assert_eq!(original_der, cached_leaf(&original)?.as_ref());
    let account_before = cache
        .load_account(&[], &directory)
        .await?
        .context("ACME account key was not cached")?;

    // No HTTP requests while waiting: background renewal must occur automatically while idle.
    let deadline = Instant::now() + Duration::from_secs(30);
    while cached(&cache, &directory).await? == original {
        if Instant::now() > deadline {
            bail!("certificate was not renewed while idle");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let renewed = cached(&cache, &directory).await?;
    assert_ne!(renewed, original);
    assert_ne!(cached_leaf(&renewed)?, cached_leaf(&original)?);
    verify_deployed_certificate(&client, &url, &renewed).await?;
    stop_server(stop, task).await?;

    verify_outage_and_recovery(
        &authority,
        &cache,
        root.path(),
        port,
        &directory,
        trust,
        &client,
        &url,
        &renewed,
        &account_before,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn verify_outage_and_recovery(
    authority: &Authority,
    cache: &PrivateCache,
    root: &Path,
    port: u16,
    directory: &str,
    trust: Arc<ClientConfig>,
    client: &reqwest::Client,
    url: &str,
    renewed: &[u8],
    account_before: &[u8],
) -> Result<()> {
    // Simulate CA outage and restart www on the same cache.
    authority.set_failing(true);
    let listener = server::bind(port)?;
    let (stop, task) = launch_server(cache.clone(), root, listener, directory, trust).await?;
    verify_deployed_certificate(client, url, renewed).await?;

    // Wait until the background renewal task actually hits the failing CA at least once.
    let deadline = Instant::now() + Duration::from_secs(25);
    while authority.failed_request_count() == 0 {
        if Instant::now() > deadline {
            bail!("background renewal did not contact the failing CA during outage window");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    verify_deployed_certificate(client, url, renewed).await?;
    assert_eq!(
        cached(cache, directory).await?,
        renewed,
        "cached certificate changed while CA was failing"
    );
    assert!(
        !task.is_finished(),
        "CA renewal failure stopped HTTPS serving"
    );

    // Restore the CA and verify automatic recovery issues a fresh certificate without restarting www.
    authority.set_failing(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    while cached(cache, directory).await? == renewed {
        if Instant::now() > deadline {
            bail!("server did not recover and renew certificate after CA was restored");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let recovered = cached(cache, directory).await?;
    assert_ne!(recovered, renewed);
    assert_ne!(cached_leaf(&recovered)?, cached_leaf(renewed)?);
    assert_eq!(
        cache.load_account(&[], directory).await?.as_deref(),
        Some(account_before),
        "cached ACME account key was not preserved across restart and recovery"
    );
    verify_deployed_certificate(client, url, &recovered).await?;
    {
        let state = authority
            .state
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?;
        assert_eq!(state.accounts.len(), 1);
        assert!(state.certificates.len() >= 3);
        assert!(
            state
                .authorizations
                .values()
                .filter(|a| a.state == AuthState::Valid)
                .count()
                >= 3
        );
    }
    stop_server(stop, task).await
}
#[derive(Debug, PartialEq, Eq)]
struct LivePrerequisites {
    domain: String,
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

fn validate_live_domain_and_ips(
    raw_domain: Option<&str>,
    resolved: &[IpAddr],
) -> Result<LivePrerequisites> {
    let raw = raw_domain
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("ACME_DOMAIN is required for live staging verification (for example: ACME_DOMAIN=example.com just acme-live)")?;
    if raw.eq_ignore_ascii_case("localhost") {
        bail!("ACME_DOMAIN cannot be localhost for live Let's Encrypt staging");
    }
    let domain = tls::normalize_domain(raw)?;
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for ip in resolved {
        match ip {
            IpAddr::V4(addr) => {
                if addr.is_loopback()
                    || addr.is_private()
                    || addr.is_link_local()
                    || addr.is_unspecified()
                    || addr.is_documentation()
                {
                    bail!(
                        "ACME_DOMAIN {domain} resolved to non-public IPv4 address {addr}; Let's Encrypt requires a public A record"
                    );
                }
                if !ipv4.contains(addr) {
                    ipv4.push(*addr);
                }
            }
            IpAddr::V6(addr) => {
                if addr.is_loopback()
                    || addr.is_unspecified()
                    || addr.is_unique_local()
                    || addr.is_unicast_link_local()
                {
                    bail!(
                        "ACME_DOMAIN {domain} resolved to non-public IPv6 address {addr}; remove non-public AAAA records"
                    );
                }
                if !ipv6.contains(addr) {
                    ipv6.push(*addr);
                }
            }
        }
    }
    if ipv4.is_empty() {
        bail!("ACME_DOMAIN {domain} has no public A record");
    }
    Ok(LivePrerequisites { domain, ipv4, ipv6 })
}

fn validate_egress_matches_dns(
    prereqs: &LivePrerequisites,
    egress_v4: Result<Ipv4Addr>,
    egress_v6: Option<Result<Ipv6Addr>>,
) -> Result<()> {
    let v4 = egress_v4.context(
        "failed to determine this host's public IPv4 egress address; refusing to run live ACME without verified IPv4 identity",
    )?;
    if !prereqs.ipv4.contains(&v4) {
        bail!(
            "ACME_DOMAIN {} public A records {:?} do not match this host's public IPv4 address {v4}",
            prereqs.domain,
            prereqs.ipv4
        );
    }
    if !prereqs.ipv6.is_empty() {
        let v6_result = egress_v6.context(
            "ACME_DOMAIN publishes AAAA records, so public IPv6 egress verification is required",
        )?;
        let v6 = v6_result.with_context(|| {
            format!(
                "ACME_DOMAIN {} publishes AAAA records {:?}, but public IPv6 egress verification failed",
                prereqs.domain, prereqs.ipv6
            )
        })?;
        if !prereqs.ipv6.contains(&v6) {
            bail!(
                "ACME_DOMAIN {} public AAAA records {:?} do not match this host's public IPv6 address {v6}",
                prereqs.domain,
                prereqs.ipv6
            );
        }
    }
    Ok(())
}

async fn resolve_public_dns(domain: &str) -> Result<Vec<IpAddr>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut addresses = Vec::new();
    for (rr_name, rr_code) in [("A", 1_u64), ("AAAA", 28_u64)] {
        let url = format!("https://cloudflare-dns.com/dns-query?name={domain}&type={rr_name}");
        let response: serde_json::Value = client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .with_context(|| format!("public DoH query failed for {domain} ({rr_name})"))?
            .error_for_status()
            .with_context(|| format!("public DoH HTTP error for {domain} ({rr_name})"))?
            .json()
            .await
            .with_context(|| format!("invalid DoH JSON for {domain} ({rr_name})"))?;
        let status = response
            .get("Status")
            .and_then(serde_json::Value::as_u64)
            .context("DoH response missing numeric Status")?;
        if status != 0 {
            bail!("public DNS query for {domain} ({rr_name}) returned DNS RCODE {status}");
        }
        if let Some(answers) = response.get("Answer").and_then(serde_json::Value::as_array) {
            for ans in answers {
                if ans.get("type").and_then(serde_json::Value::as_u64) == Some(rr_code)
                    && let Some(data) = ans.get("data").and_then(serde_json::Value::as_str)
                {
                    let ip: IpAddr = data.trim().parse().with_context(|| {
                        format!("public DNS returned invalid IP {data:?} for {domain} ({rr_name})")
                    })?;
                    if !addresses.contains(&ip) {
                        addresses.push(ip);
                    }
                }
            }
        }
    }
    Ok(addresses)
}

async fn detect_public_ipv4() -> Result<Ipv4Addr> {
    let text = reqwest::Client::builder()
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .timeout(Duration::from_secs(5))
        .build()?
        .get("https://api.ipify.org")
        .send()
        .await
        .context("IPv4 egress probe to api.ipify.org failed")?
        .error_for_status()?
        .text()
        .await?;
    text.trim()
        .parse::<Ipv4Addr>()
        .with_context(|| format!("expected public IPv4 from api.ipify.org, got {text:?}"))
}

async fn detect_public_ipv6() -> Result<Ipv6Addr> {
    let text = reqwest::Client::builder()
        .local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .timeout(Duration::from_secs(5))
        .build()?
        .get("https://api64.ipify.org")
        .send()
        .await
        .context("IPv6 egress probe to api64.ipify.org failed")?
        .error_for_status()?
        .text()
        .await?;
    text.trim().parse::<Ipv6Addr>().with_context(|| {
        format!("expected public IPv6 from api64.ipify.org over IPv6 socket, got {text:?}")
    })
}

fn verify_listener_bindable(port: u16) -> Result<TcpListener> {
    server::bind(port).with_context(|| {
        format!(
            "cannot bind TCP port {port} for ACME TLS-ALPN-01 validation (check permissions/CAP_NET_BIND_SERVICE and whether another process occupies port {port})"
        )
    })
}

fn random_nonce_hex() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate preflight nonce"))?;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct ScopedChild {
    child: Child,
    log: tempfile::NamedTempFile,
}

impl ScopedChild {
    fn spawn(cmd: &str, domain: &str, target: SocketAddr, port: u16, nonce: &str) -> Result<Self> {
        let log = tempfile::NamedTempFile::new()?;
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(cmd)
            .env("ACME_PROBE_DOMAIN", domain)
            .env("ACME_PROBE_IP", target.ip().to_string())
            .env("ACME_PROBE_PORT", port.to_string())
            .env("ACME_PROBE_NONCE", nonce)
            .stdout(log.reopen()?)
            .stderr(log.reopen()?);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let child = command
            .spawn()
            .context("cannot spawn ACME_INGRESS_PROBE_CMD")?;
        Ok(Self { child, log })
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(self.log.path())
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    fn terminate_group(&mut self) {
        #[cfg(unix)]
        {
            let pgid = format!("-{}", self.child.id());
            let _ = Command::new("kill")
                .args(["-KILL", &pgid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn wait_until(&mut self, deadline: Instant, target: SocketAddr) -> Result<()> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                bail!(
                    "external ingress probe command failed for {target} ({status}): {}",
                    self.logs()
                );
            }
            if Instant::now() > deadline {
                self.terminate_group();
                bail!(
                    "external ingress probe command timed out after nonce exchange for {target}: {}",
                    self.logs()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ScopedChild {
    fn drop(&mut self) {
        self.terminate_group();
    }
}

fn verify_external_ingress_probe_with_timeout(
    listener: &TcpListener,
    domain: &str,
    targets: &[SocketAddr],
    probe_cmd: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    let cmd = probe_cmd.map(str::trim).filter(|s| !s.is_empty()).context(
        "refusing to contact Let's Encrypt staging without verified external TCP/443 ingress: \
         same-host hairpin connections cannot prove external firewall/NAT forwarding. \
         Provide ACME_INGRESS_PROBE_CMD (for example an external ssh/curl command connecting to \
         $ACME_PROBE_IP:$ACME_PROBE_PORT and sending/receiving $ACME_PROBE_NONCE)",
    )?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    for &target in targets {
        let nonce = format!("www-acme-probe-{}\n", random_nonce_hex()?);
        let deadline = Instant::now() + timeout;
        let mut probe = ScopedChild::spawn(cmd, domain, target, port, nonce.trim_end())?;

        let mut server_stream = None;
        let mut peer_addr = None;
        while Instant::now() <= deadline {
            match listener.accept() {
                Ok((stream, peer)) => {
                    server_stream = Some(stream);
                    peer_addr = Some(peer);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(err.into()),
            }
        }
        let Some(mut server_stream) = server_stream else {
            bail!(
                "external ingress probe to {target} did not reach local listener on port {port}: {}",
                probe.logs()
            );
        };
        let peer = peer_addr.context("missing peer address")?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_millis(1));
        server_stream.set_nonblocking(false)?;
        server_stream.set_read_timeout(Some(remaining))?;
        server_stream.set_write_timeout(Some(remaining))?;
        let mut received = vec![0_u8; nonce.len()];
        server_stream.read_exact(&mut received).with_context(|| {
            format!("failed to read external probe nonce on {target} from {peer}")
        })?;
        if received != nonce.as_bytes() {
            bail!(
                "external probe bytes on {target} from {peer} did not match nonce (possible TLS-terminating proxy or wrong host)"
            );
        }
        server_stream.write_all(&received)?;
        drop(server_stream);
        probe.wait_until(deadline, target)?;
    }
    Ok(())
}

fn verify_external_ingress_probe(
    listener: &TcpListener,
    domain: &str,
    targets: &[SocketAddr],
    probe_cmd: Option<&str>,
) -> Result<()> {
    verify_external_ingress_probe_with_timeout(
        listener,
        domain,
        targets,
        probe_cmd,
        Duration::from_secs(10),
    )
}

fn build_staging_trusted_client(
    domain: &str,
    port: u16,
    http2_only: bool,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(
            LETSENCRYPT_STAGING_ROOT_X1_PEM,
        )?)
        .add_root_certificate(reqwest::Certificate::from_pem(
            LETSENCRYPT_STAGING_ROOT_X2_PEM,
        )?)
        .tls_info(true)
        .resolve(domain, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .timeout(Duration::from_secs(5));
    if http2_only {
        builder = builder.http2_prior_knowledge();
    } else {
        builder = builder.http1_only();
    }
    Ok(builder.build()?)
}

struct RunningServer {
    child: Child,
    log: tempfile::NamedTempFile,
}

impl RunningServer {
    fn start(domain: &str, root: &Path, cache_path: &Path) -> Result<Self> {
        let log = tempfile::NamedTempFile::new()?;
        let child = Command::new(env!("CARGO_BIN_EXE_www"))
            .args(["-s", domain, "--acme-staging", "--cert-cache"])
            .arg(cache_path)
            .arg("-r")
            .arg(root)
            .stdout(log.reopen()?)
            .stderr(log.reopen()?)
            .spawn()
            .context("cannot spawn www for live staging test")?;
        Ok(Self { child, log })
    }

    fn logs(&self) -> Result<String> {
        Ok(std::fs::read_to_string(self.log.path())?)
    }

    async fn stop_gracefully(&mut self) -> Result<()> {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .context("failed to send SIGTERM to www")?;
        if !status.success() {
            bail!("kill -TERM failed with status {status}");
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(exit) = self.child.try_wait()? {
                if !exit.success() {
                    bail!("www exited with non-zero status {exit}: {}", self.logs()?);
                }
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!(
                    "www did not exit within 12s after SIGTERM: {}",
                    self.logs()?
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn run_live_staging_attempt(
    domain: &str,
    root: &Path,
    cache_path: &Path,
    attempt: usize,
) -> Result<Vec<u8>> {
    let mut server = RunningServer::start(domain, root, cache_path)?;
    let h1_client = build_staging_trusted_client(domain, 443, false)?;
    // Standard ALPN client that negotiates HTTP/2 over TLS with Let's Encrypt staging roots.
    let h2_client = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(
            LETSENCRYPT_STAGING_ROOT_X1_PEM,
        )?)
        .add_root_certificate(reqwest::Certificate::from_pem(
            LETSENCRYPT_STAGING_ROOT_X2_PEM,
        )?)
        .tls_info(true)
        .resolve(domain, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("https://{domain}/hello.txt");
    let deadline = Instant::now() + Duration::from_secs(60);
    let der = loop {
        if let Some(status) = server.child.try_wait()? {
            bail!(
                "www exited ({status}) during staging attempt {attempt}: {}",
                server.logs()?
            );
        }
        if let Ok(response) = h2_client.get(&url).send().await
            && response.status().is_success()
        {
            assert_eq!(
                response.version(),
                reqwest::Version::HTTP_2,
                "expected ALPN HTTP/2 negotiation"
            );
            let cert = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(reqwest::tls::TlsInfo::peer_certificate)
                .context("missing peer certificate on staging HTTPS connection")?
                .to_vec();
            assert_eq!(response.text().await?, "live staging works");
            break cert;
        }
        if Instant::now() > deadline {
            bail!(
                "timed out waiting for staging HTTPS on attempt {attempt}: {}",
                server.logs()?
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };

    let h1_get = h1_client.get(&url).send().await?.error_for_status()?;
    assert_eq!(
        h1_get.version(),
        reqwest::Version::HTTP_11,
        "expected HTTP/1.1 response when client requests HTTP/1.1"
    );
    assert_eq!(h1_get.text().await?, "live staging works");

    let head_resp = h2_client.head(&url).send().await?.error_for_status()?;
    assert_eq!(
        head_resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("18")
    );
    assert!(head_resp.bytes().await?.is_empty());

    server.stop_gracefully().await?;
    Ok(der)
}

fn run_test_probe_client_helper(mode: &str) -> Result<()> {
    let ip: IpAddr = std::env::var("ACME_PROBE_IP")?.parse()?;
    let port: u16 = std::env::var("ACME_PROBE_PORT")?.parse()?;
    let nonce = std::env::var("ACME_PROBE_NONCE")?;
    let target = SocketAddr::from((ip, port));
    let mut stream = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let payload = if mode == "corrupt" {
        format!("{}\n", "x".repeat(nonce.len()))
    } else {
        format!("{nonce}\n")
    };
    stream.write_all(payload.as_bytes())?;
    let mut reply = vec![0_u8; payload.len()];
    stream.read_exact(&mut reply)?;
    if reply != payload.as_bytes() {
        bail!("probe reply mismatch");
    }
    drop(stream);
    if mode == "hang" {
        std::thread::sleep(Duration::from_secs(60));
    }
    Ok(())
}

#[test]
fn live_prerequisite_validation_rejects_missing_or_non_public_targets_without_network() -> Result<()>
{
    if let Ok(mode) = std::env::var("WWW_TEST_PROBE_CLIENT_MODE") {
        return run_test_probe_client_helper(&mode);
    }
    assert!(validate_live_domain_and_ips(None, &[]).is_err());
    assert!(validate_live_domain_and_ips(Some(""), &[]).is_err());
    assert!(
        validate_live_domain_and_ips(Some("localhost"), &[IpAddr::V4(Ipv4Addr::LOCALHOST)])
            .is_err()
    );
    assert!(
        validate_live_domain_and_ips(Some("example.com"), &[IpAddr::V4(Ipv4Addr::LOCALHOST)])
            .is_err()
    );
    assert!(
        validate_live_domain_and_ips(
            Some("example.com"),
            &[IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]
        )
        .is_err()
    );
    assert!(
        validate_live_domain_and_ips(Some("example.com"), &[IpAddr::V6(Ipv6Addr::LOCALHOST)])
            .is_err()
    );
    let valid = validate_live_domain_and_ips(
        Some("EXAMPLE.COM"),
        &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    )?;
    assert_eq!(valid.domain, "example.com");
    assert_eq!(valid.ipv4, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    assert_eq!(valid.ipv6, [] as [Ipv6Addr; 0]);

    // Fail-closed egress checks: errors or mismatches on IPv4 or IPv6 must fail.
    assert!(
        validate_egress_matches_dns(&valid, Err(anyhow::anyhow!("offline")), None).is_err(),
        "IPv4 egress lookup failure must fail closed"
    );
    assert!(
        validate_egress_matches_dns(&valid, Ok(Ipv4Addr::new(198, 51, 100, 1)), None).is_err(),
        "IPv4 egress mismatch must fail"
    );
    assert!(validate_egress_matches_dns(&valid, Ok(Ipv4Addr::new(93, 184, 216, 34)), None).is_ok());

    let dual = validate_live_domain_and_ips(
        Some("example.com"),
        &[
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse()?),
        ],
    )?;
    assert!(
        validate_egress_matches_dns(
            &dual,
            Ok(Ipv4Addr::new(93, 184, 216, 34)),
            Some(Err(anyhow::anyhow!("no ipv6 route")))
        )
        .is_err(),
        "IPv6 egress lookup failure when AAAA exists must fail closed"
    );

    let occupied = server::bind(0)?;
    let occupied_port = occupied.local_addr()?.port();
    assert!(
        verify_listener_bindable(occupied_port).is_err(),
        "occupied port must fail preflight before ACME issuance"
    );
    drop(occupied);
    verify_probe_runner_behaviors()
}

fn verify_probe_runner_behaviors() -> Result<()> {
    assert_eq!(
        shell_single_quote("/tmp/bad$(touch /tmp/pwn)'path/www"),
        "'/tmp/bad$(touch /tmp/pwn)'\\''path/www'"
    );
    let probe_listener = server::bind(0)?;
    let probe_port = probe_listener.local_addr()?.port();
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, probe_port));
    assert!(
        verify_external_ingress_probe(&probe_listener, "example.com", &[target], None).is_err(),
        "missing external ingress probe command must fail closed"
    );

    let exe = std::env::current_exe()?;
    let quoted_exe = shell_single_quote(&exe.display().to_string());
    let test_name =
        "live_prerequisite_validation_rejects_missing_or_non_public_targets_without_network";
    let ok_cmd =
        format!("WWW_TEST_PROBE_CLIENT_MODE=ok {quoted_exe} --exact {test_name} --nocapture");
    verify_external_ingress_probe(&probe_listener, "example.com", &[target], Some(&ok_cmd))?;

    let corrupt_cmd =
        format!("WWW_TEST_PROBE_CLIENT_MODE=corrupt {quoted_exe} --exact {test_name} --nocapture");
    assert!(
        verify_external_ingress_probe(
            &probe_listener,
            "example.com",
            &[target],
            Some(&corrupt_cmd)
        )
        .is_err(),
        "corrupted probe nonce must be rejected"
    );

    // Spawn a subshell that forks a background grandchild (`hang` helper) and waits on it.
    // Process-group termination must kill both `sh` and the hanging grandchild.
    let hang_cmd = format!(
        "WWW_TEST_PROBE_CLIENT_MODE=hang {quoted_exe} --exact {test_name} --nocapture & wait"
    );
    let started = Instant::now();
    let hang_res = verify_external_ingress_probe_with_timeout(
        &probe_listener,
        "example.com",
        &[target],
        Some(&hang_cmd),
        Duration::from_millis(250),
    );
    assert!(
        hang_res.is_err(),
        "probe that hangs after nonce exchange must be rejected within timeout"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "hung probe and its descendants were not terminated within bounded timeout"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "opt-in live Let's Encrypt staging test; run with ACME_DOMAIN=example.com just acme-live"]
async fn live_staging_issuance_and_certificate_reuse() -> Result<()> {
    let raw_domain = std::env::var("ACME_DOMAIN").ok();
    let domain_for_lookup = raw_domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("ACME_DOMAIN is required (run: ACME_DOMAIN=example.com just acme-live)")?;
    let normalized = tls::normalize_domain(domain_for_lookup)?;
    let resolved = resolve_public_dns(&normalized).await?;
    let prereqs = validate_live_domain_and_ips(raw_domain.as_deref(), &resolved)?;

    let egress_v4 = detect_public_ipv4().await;
    let egress_v6 = if prereqs.ipv6.is_empty() {
        None
    } else {
        Some(detect_public_ipv6().await)
    };
    validate_egress_matches_dns(&prereqs, egress_v4, egress_v6)?;

    let root = tempfile::tempdir()?;
    let cache_path = root.path().join("acme");
    let cache = PrivateCache::open(cache_path.clone()).await?;
    std::fs::write(root.path().join("hello.txt"), "live staging works")?;

    let preflight_listener = verify_listener_bindable(443)?;
    let mut targets: Vec<SocketAddr> = prereqs
        .ipv4
        .iter()
        .copied()
        .map(|ip| SocketAddr::from((ip, 443)))
        .collect();
    targets.extend(
        prereqs
            .ipv6
            .iter()
            .copied()
            .map(|ip| SocketAddr::from((ip, 443))),
    );
    let probe_cmd = std::env::var("ACME_INGRESS_PROBE_CMD").ok();
    verify_external_ingress_probe(
        &preflight_listener,
        &prereqs.domain,
        &targets,
        probe_cmd.as_deref(),
    )
    .context("public TCP/443 reachability check failed before contacting Let's Encrypt staging")?;
    drop(preflight_listener);

    let first_leaf = run_live_staging_attempt(&prereqs.domain, root.path(), &cache_path, 1).await?;
    let cached_account_first = cache
        .load_account(&[], LETSENCRYPT_STAGING_DIRECTORY)
        .await?
        .context("staging ACME account was not persisted in cache")?;
    let cached_cert_first = cache
        .load_cert(
            std::slice::from_ref(&prereqs.domain),
            LETSENCRYPT_STAGING_DIRECTORY,
        )
        .await?
        .context("staging ACME certificate was not persisted in cache")?;

    let second_leaf =
        run_live_staging_attempt(&prereqs.domain, root.path(), &cache_path, 2).await?;
    let cached_account_second = cache
        .load_account(&[], LETSENCRYPT_STAGING_DIRECTORY)
        .await?
        .context("staging ACME account missing after restart")?;
    let cached_cert_second = cache
        .load_cert(
            std::slice::from_ref(&prereqs.domain),
            LETSENCRYPT_STAGING_DIRECTORY,
        )
        .await?
        .context("staging ACME certificate missing after restart")?;

    assert_eq!(
        first_leaf, second_leaf,
        "restarted server did not reuse the issued staging leaf certificate"
    );
    assert_eq!(
        cached_account_first, cached_account_second,
        "restarted server modified the cached ACME account"
    );
    assert_eq!(
        cached_cert_first, cached_cert_second,
        "restarted server modified the cached ACME certificate"
    );
    Ok(())
}
