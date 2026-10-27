use anyhow::Result;
use rustls_acme::{AccountCache, CertCache};
use www::tls::cache::PrivateCache;

#[tokio::test]
async fn persist_and_isolate_accounts_certificates_and_environments() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("acme");
    let cache = PrivateCache::open(path.clone()).await?;
    let domains = vec!["example.com".to_owned()];
    let contact = vec![];
    cache
        .store_account(&contact, "production", b"account")
        .await?;
    cache.store_cert(&domains, "production", b"old").await?;
    cache.store_cert(&domains, "production", b"new").await?;
    drop(cache);
    let cache = PrivateCache::open(path.clone()).await?;
    assert_eq!(
        cache.load_account(&contact, "production").await?.as_deref(),
        Some(b"account".as_slice())
    );
    assert_eq!(
        cache.load_cert(&domains, "production").await?.as_deref(),
        Some(b"new".as_slice())
    );
    assert!(cache.load_cert(&domains, "staging").await?.is_none());
    assert!(
        cache
            .load_cert(&["other.com".to_owned()], "production")
            .await?
            .is_none()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(path.metadata()?.permissions().mode() & 0o777, 0o700);
        for entry in std::fs::read_dir(path)? {
            assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
        }
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn reject_shared_cache_without_changing_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))?;
    assert!(PrivateCache::open(root.path().to_owned()).await.is_err());
    assert_eq!(root.path().metadata()?.permissions().mode() & 0o777, 0o755);
    Ok(())
}
