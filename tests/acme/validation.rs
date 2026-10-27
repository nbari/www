use super::*;

struct Account {
    key: ring::signature::EcdsaKeyPair,
    jwk: Value,
    kid: Option<String>,
}

impl Account {
    fn new() -> Result<Self> {
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair as _};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            ring::signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| anyhow::anyhow!("cannot generate account key"))?;
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .map_err(|_| anyhow::anyhow!("cannot load account key"))?;
        let public = key.public_key().as_ref();
        let jwk = json!({"kty":"EC", "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(public.get(1..33).context("missing x")?),
            "y":URL_SAFE_NO_PAD.encode(public.get(33..65).context("missing y")?)});
        Ok(Self {
            key,
            jwk,
            kid: None,
        })
    }

    fn body(&self, url: &str, nonce: &str, payload: &[u8]) -> Result<Value> {
        let mut protected = json!({"alg":"ES256", "url":url, "nonce":nonce});
        let headers = protected.as_object_mut().context("invalid headers")?;
        if let Some(kid) = &self.kid {
            headers.insert("kid".to_owned(), json!(kid));
        } else {
            headers.insert("jwk".to_owned(), self.jwk.clone());
        }
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signature = self
            .key
            .sign(
                &ring::rand::SystemRandom::new(),
                format!("{protected}.{payload}").as_bytes(),
            )
            .map_err(|_| anyhow::anyhow!("cannot sign JWS"))?;
        Ok(json!({"protected":protected, "payload":payload,
            "signature":URL_SAFE_NO_PAD.encode(signature.as_ref())}))
    }

    async fn request(
        &self,
        ca: &Authority,
        path: &str,
        payload: &[u8],
    ) -> Result<reqwest::Response> {
        let body = self.body(
            &format!("{}{path}", ca.state.base_url),
            &nonce(ca).await?,
            payload,
        )?;
        post(ca, path, &body).await
    }

    async fn register(&mut self, ca: &Authority) -> Result<()> {
        let response = self
            .request(ca, "/new-acct", b"{\"termsOfServiceAgreed\":true}")
            .await?
            .error_for_status()?;
        self.kid = Some(
            response
                .headers()
                .get("location")
                .context("missing account URL")?
                .to_str()?
                .to_owned(),
        );
        Ok(())
    }
}

async fn nonce(ca: &Authority) -> Result<String> {
    Ok(ca
        .client
        .head(format!("{}/new-nonce", ca.state.base_url))
        .send()
        .await?
        .error_for_status()?
        .headers()
        .get("replay-nonce")
        .context("missing nonce")?
        .to_str()?
        .to_owned())
}

async fn post(ca: &Authority, path: &str, body: &Value) -> Result<reqwest::Response> {
    Ok(ca
        .client
        .post(format!("{}{path}", ca.state.base_url))
        .json(body)
        .header("content-type", "application/jose+json")
        .send()
        .await?)
}

#[tokio::test]
async fn invalid_signed_requests_do_not_create_accounts_or_orders() -> Result<()> {
    let ca = Authority::start(1, 30).await?;
    let mut account = Account::new()?;
    let url = format!("{}/new-acct", ca.state.base_url);
    let mut body = account.body(&url, &nonce(&ca).await?, b"{}")?;
    let mut signature = URL_SAFE_NO_PAD.decode(
        body.get("signature")
            .and_then(Value::as_str)
            .context("missing signature")?,
    )?;
    *signature.first_mut().context("empty signature")? ^= 1;
    body.as_object_mut().context("invalid envelope")?.insert(
        "signature".to_owned(),
        json!(URL_SAFE_NO_PAD.encode(signature)),
    );
    assert_eq!(
        post(&ca, "/new-acct", &body).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ca.state
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?
            .accounts
            .len(),
        0
    );

    let malformed = account.body(&url, &nonce(&ca).await?, b"[")?;
    assert_eq!(
        post(&ca, "/new-acct", &malformed).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ca.state
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?
            .accounts
            .len(),
        0
    );
    account.register(&ca).await?;
    let payload = br#"{"identifiers":[{"type":"dns","value":"localhost"}]}"#;
    let url = format!("{}/new-order", ca.state.base_url);
    let body = account.body(&url, &nonce(&ca).await?, payload)?;
    assert_eq!(
        post(&ca, "/new-order", &body).await?.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        post(&ca, "/new-order", &body).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let wrong_url = account.body("https://localhost/wrong", &nonce(&ca).await?, payload)?;
    assert_eq!(
        post(&ca, "/new-order", &wrong_url).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let mut other = Account::new()?;
    other.kid.clone_from(&account.kid);
    assert_eq!(
        other.request(&ca, "/new-order", payload).await?.status(),
        StatusCode::BAD_REQUEST
    );
    other.kid = Some(format!("{}/acct/99999", ca.state.base_url));
    assert_eq!(
        other.request(&ca, "/new-order", payload).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let state = ca
        .state
        .inner
        .lock()
        .map_err(|_| anyhow::anyhow!("poisoned"))?;
    assert_eq!(state.accounts.len(), 1);
    assert_eq!(state.orders.len(), 1);
    assert!(state.certificates.is_empty());
    Ok(())
}

#[tokio::test]
async fn pending_or_failed_challenges_cannot_issue_certificates() -> Result<()> {
    let unavailable = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let ca = Authority::start(unavailable.local_addr()?.port(), 30).await?;
    let mut account = Account::new()?;
    account.register(&ca).await?;
    let order = account
        .request(
            &ca,
            "/new-order",
            br#"{"identifiers":[{"type":"dns","value":"localhost"}]}"#,
        )
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let finalize = order
        .get("finalize")
        .and_then(Value::as_str)
        .context("missing finalize")?
        .strip_prefix(&ca.state.base_url)
        .context("wrong origin")?;
    let key = KeyPair::generate()?;
    let csr = CertificateParams::new(vec!["localhost".to_owned()])?.serialize_request(&key)?;
    let payload = serde_json::to_vec(&json!({"csr":URL_SAFE_NO_PAD.encode(csr.der())}))?;
    assert_eq!(
        account.request(&ca, finalize, &payload).await?.status(),
        StatusCode::FORBIDDEN
    );
    let auth = order
        .get("authorizations")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .context("missing authorization")?;
    let challenge = auth.replace("/authz/", "/chall/");
    let path = challenge
        .strip_prefix(&ca.state.base_url)
        .context("wrong origin")?;
    drop(unavailable);
    assert_eq!(
        account.request(&ca, path, b"{}").await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        account.request(&ca, finalize, &payload).await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        account.request(&ca, "/order/99999", b"").await?.status(),
        StatusCode::NOT_FOUND
    );
    let mut other = Account::new()?;
    other.register(&ca).await?;
    assert_eq!(
        other.request(&ca, path, b"{}").await?.status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        !nonce(&ca).await?.is_empty(),
        "CA must remain responsive after rejected requests"
    );
    assert!(
        ca.state
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?
            .certificates
            .is_empty()
    );
    Ok(())
}

struct ProbeServer {
    handle: axum_server::Handle<SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    port: u16,
}

impl ProbeServer {
    fn start(cert: &rcgen::Certificate, key: &KeyPair, alpn: Vec<Vec<u8>>) -> Result<Self> {
        use rustls_acme::rustls::{
            ServerConfig,
            server::{ClientHello, ResolvesServerCert},
            sign::CertifiedKey,
        };
        #[derive(Debug)]
        struct Resolver(Arc<CertifiedKey>);
        impl ResolvesServerCert for Resolver {
            fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                Some(Arc::clone(&self.0))
            }
        }
        // As in rustls-acme, resolve challenge certificates directly: the
        // general-purpose certificate loader rejects their critical extension.
        let signing_key = rustls_acme::rustls::crypto::ring::sign::any_supported_type(
            &rustls_acme::rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        let certified = CertifiedKey::new(vec![cert.der().clone()], signing_key);
        let mut raw = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(Arc::new(certified))));
        raw.alpn_protocols = alpn;
        let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(raw));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(listener, config)?
            .handle(handle.clone())
            .serve(Router::new().into_make_service());
        Ok(Self {
            handle,
            task: tokio::spawn(server),
            port,
        })
    }
}

impl Drop for ProbeServer {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}

#[tokio::test]
async fn successful_tls_handshake_still_requires_acme_alpn() -> Result<()> {
    let _ = rustls_acme::rustls::crypto::ring::default_provider().install_default();
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["localhost".to_owned()])?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(
        digest(&SHA256, b"token.thumb").as_ref(),
    )];
    let cert = params.self_signed(&key)?;
    let good = ProbeServer::start(&cert, &key, vec![ACME_TLS_ALPN_PROTOCOL.to_vec()])?;
    probe_tls_alpn_01_challenge(good.port, "localhost", "token", "thumb").await?;
    let missing = ProbeServer::start(&cert, &key, vec![])?;
    let error = probe_tls_alpn_01_challenge(missing.port, "localhost", "token", "thumb")
        .await
        .err()
        .context("missing ALPN was accepted")?;
    assert!(error.to_string().contains("did not negotiate"));
    let wrong = ProbeServer::start(&cert, &key, vec![b"h2".to_vec()])?;
    assert!(
        probe_tls_alpn_01_challenge(wrong.port, "localhost", "token", "thumb")
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_challenge_certificates_and_csrs_are_rejected() -> Result<()> {
    let key = KeyPair::generate()?;
    let expected = digest(&SHA256, b"token.thumb");
    let valid = || CustomExtension::new_acme_identifier(expected.as_ref());
    for names in [
        vec!["localhost", "extra.example"],
        vec!["localhost", "127.0.0.1"],
    ] {
        let mut params =
            CertificateParams::new(names.into_iter().map(str::to_owned).collect::<Vec<_>>())?;
        params.custom_extensions = vec![valid()];
        assert!(
            validate_tls_alpn_01_certificate(
                params.self_signed(&key)?.der(),
                "localhost",
                "token",
                "thumb"
            )
            .is_err()
        );
    }
    for extensions in [
        vec![valid(), valid()],
        vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 1, 31],
            expected.as_ref().to_vec(),
        )],
    ] {
        let mut params = CertificateParams::new(vec!["localhost".to_owned()])?;
        params.custom_extensions = extensions;
        assert!(
            validate_tls_alpn_01_certificate(
                params.self_signed(&key)?.der(),
                "localhost",
                "token",
                "thumb"
            )
            .is_err()
        );
    }
    for names in [
        vec![],
        vec!["localhost", "extra.example"],
        vec!["127.0.0.1"],
    ] {
        let params =
            CertificateParams::new(names.into_iter().map(str::to_owned).collect::<Vec<_>>())?;
        let csr = params.serialize_request(&key)?;
        assert!(validate_and_extract_csr(csr.der(), &["localhost".to_owned()]).is_err());
    }
    let csr = CertificateParams::new(vec!["localhost".to_owned()])?.serialize_request(&key)?;
    let mut corrupted = csr.der().to_vec();
    *corrupted.last_mut().context("empty CSR")? ^= 1;
    X509CertificationRequest::from_der(&corrupted).context("tampered CSR must still parse")?;
    assert!(validate_and_extract_csr(&corrupted, &["localhost".to_owned()]).is_err());
    Ok(())
}
