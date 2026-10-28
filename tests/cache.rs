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

/// Observe the cache key filename a prior `store_cert` created by listing the
/// directory (no new public testing APIs).
fn cert_key_name(cache_dir: &std::path::Path) -> Result<String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(cache_dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with("cert-") {
            names.push(name);
        }
    }
    assert_eq!(names.len(), 1);
    Ok(names.remove(0))
}

/// Original cache dir renamed aside and the same path replaced by a directory
/// with a decoy key: loads still return the held original bytes, and stores
/// affect the original only.
#[tokio::test]
async fn renamed_cache_directory_keeps_original_bytes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("acme");
    let cache = PrivateCache::open(path.clone()).await?;
    let domains = vec!["example.com".to_owned()];
    cache
        .store_cert(&domains, "production", b"original")
        .await?;
    let key = cert_key_name(&path)?;

    // Rename the original aside and replace the same path with a decoy dir.
    let aside = root.path().join("acme-aside");
    std::fs::rename(&path, &aside)?;
    std::fs::create_dir_all(&path)?;
    std::fs::write(path.join(&key), b"decoy")?;

    // Loads still return the held original bytes.
    assert_eq!(
        cache.load_cert(&domains, "production").await?.as_deref(),
        Some(b"original".as_slice())
    );
    // Stores affect the original only.
    cache.store_cert(&domains, "production", b"updated").await?;
    assert_eq!(std::fs::read(aside.join(&key))?, b"updated");
    assert_eq!(std::fs::read(path.join(&key))?, b"decoy");
    Ok(())
}

/// Original path replaced by a symlink to a public directory: account/cert
/// writes never appear publicly and loads still work.
#[cfg(unix)]
#[tokio::test]
async fn replaced_cache_path_symlink_keeps_writes_private() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("acme");
    let cache = PrivateCache::open(path.clone()).await?;
    let domains = vec!["example.com".to_owned()];
    let contact = vec!["mailto:a@example.com".to_owned()];
    cache
        .store_cert(&domains, "production", b"cert-bytes")
        .await?;
    let key = cert_key_name(&path)?;

    // Replace the cache path with a symlink to a public directory.
    let public = root.path().join("public");
    std::fs::create_dir_all(&public)?;
    let aside = root.path().join("acme-aside");
    std::fs::rename(&path, &aside)?;
    std::os::unix::fs::symlink(&public, &path)?;

    // Writes never appear publicly.
    cache
        .store_account(&contact, "production", b"account-bytes")
        .await?;
    cache.store_cert(&domains, "production", b"cert-2").await?;
    let mut public_entries = 0usize;
    for entry in std::fs::read_dir(&public)? {
        entry?;
        public_entries += 1;
    }
    assert_eq!(public_entries, 0, "cache writes leaked into public dir");
    // Loads still work through the held handle.
    assert_eq!(
        cache.load_cert(&domains, "production").await?.as_deref(),
        Some(b"cert-2".as_slice())
    );
    assert_eq!(
        cache.load_account(&contact, "production").await?.as_deref(),
        Some(b"account-bytes".as_slice())
    );
    assert_eq!(std::fs::read(aside.join(&key))?, b"cert-2");
    Ok(())
}

/// Symlink and FIFO cache entries reject promptly (NONBLOCK + regular check).
///
/// This is a synchronous test with its OWN current-thread runtime so a
/// potentially blocked `spawn_blocking` load job cannot hang runtime teardown:
/// the load is bounded by `timeout(1s)`, the outcome is captured, and the
/// runtime is ALWAYS shut down with `shutdown_timeout(100ms)` before any
/// assertion or error propagation. `#[tokio::test]` + `timeout` alone is
/// insufficient because `Runtime::drop` waits on blocking jobs.
#[cfg(unix)]
#[test]
fn symlink_and_fifo_cache_entries_reject() -> Result<()> {
    use rustix::fs::{CWD, Mode, mkfifoat};
    use std::time::Duration;
    use tokio::time::timeout;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let root = tempfile::tempdir()?;
    let path = root.path().join("acme");
    let cache = runtime.block_on(PrivateCache::open(path.clone()))?;
    let domains = vec!["example.com".to_owned()];
    runtime.block_on(cache.store_cert(&domains, "production", b"cert"))?;
    let key = cert_key_name(&path)?;

    // Replace the regular entry with a symlink to a readable file.
    let target = root.path().join("target.txt");
    std::fs::write(&target, b"target")?;
    std::fs::remove_file(path.join(&key))?;
    std::os::unix::fs::symlink(&target, path.join(&key))?;
    let symlink_outcome = runtime.block_on(async {
        timeout(
            Duration::from_secs(1),
            cache.load_cert(&domains, "production"),
        )
        .await
    });

    // Replace with a FIFO: NONBLOCK + regular check must reject promptly.
    std::fs::remove_file(path.join(&key))?;
    let fifo = path.join(&key);
    mkfifoat(CWD, &fifo, Mode::from_bits_truncate(0o600))?;
    let fifo_outcome = runtime.block_on(async {
        timeout(
            Duration::from_secs(1),
            cache.load_cert(&domains, "production"),
        )
        .await
    });

    // ALWAYS tear down the runtime before asserting, so a stuck blocking job
    // cannot hang this test's teardown.
    runtime.shutdown_timeout(Duration::from_millis(100));

    let Ok(symlink_result) = symlink_outcome else {
        return Err(anyhow::anyhow!("symlink load did not finish within 1s"));
    };
    assert!(symlink_result.is_err());
    let Ok(fifo_result) = fifo_outcome else {
        return Err(anyhow::anyhow!("FIFO load did not finish within 1s"));
    };
    assert!(fifo_result.is_err());
    Ok(())
}

/// Rename failure with the final key precreated as a directory cleans
/// temporary files.
#[tokio::test]
async fn rename_failure_cleans_temporary_files() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("acme");
    let cache = PrivateCache::open(path.clone()).await?;
    let domains = vec!["example.com".to_owned()];
    cache.store_cert(&domains, "production", b"first").await?;
    let key = cert_key_name(&path)?;

    // Precreate the final key as a directory so renameat fails.
    std::fs::remove_file(path.join(&key))?;
    std::fs::create_dir_all(path.join(&key))?;
    let result = cache.store_cert(&domains, "production", b"second").await;
    assert!(result.is_err());
    // No temporary files remain (propagate IO errors so a failed read cannot
    // falsely prove the directory is clean).
    let mut temps = Vec::new();
    for entry in std::fs::read_dir(&path)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with(".tmp-") {
            temps.push(name);
        }
    }
    assert!(temps.is_empty(), "temporary files leaked: {temps:?}");
    Ok(())
}
