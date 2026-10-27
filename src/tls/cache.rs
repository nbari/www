//! Private, atomically replaced ACME account and certificate storage.

use async_trait::async_trait;
use ring::digest::{Context, SHA256};
use rustls_acme::{AccountCache, CertCache};
use std::{
    fmt::Write as _,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct PrivateCache {
    directory: PathBuf,
}

impl PrivateCache {
    /// Existing directories must already be private; never chmod an arbitrary user path.
    ///
    /// # Errors
    /// Returns filesystem errors, non-private directory permissions, or worker failures.
    pub async fn open(directory: PathBuf) -> io::Result<Self> {
        tokio::task::spawn_blocking(move || {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&directory)?;
            let directory = directory.canonicalize()?;
            let metadata = directory.metadata()?;
            if !metadata.is_dir() {
                return Err(io::Error::other("certificate cache is not a directory"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "certificate cache must have owner-only permissions (0700); choose a dedicated --cert-cache directory",
                    ));
                }
            }
            Ok(Self { directory })
        })
        .await
        .map_err(io::Error::other)?
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn path(&self, kind: &str, identifiers: &[String], directory_url: &str) -> PathBuf {
        let mut digest = Context::new(&SHA256);
        for value in identifiers
            .iter()
            .map(String::as_str)
            .chain([directory_url])
        {
            digest.update(&(value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        let mut hash = String::with_capacity(64);
        for byte in digest.finish().as_ref() {
            // Formatting into a String cannot fail.
            let _ = write!(hash, "{byte:02x}");
        }
        self.directory.join(format!("{kind}-{hash}"))
    }

    async fn load(&self, path: PathBuf) -> io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn store(&self, path: PathBuf, bytes: &[u8]) -> io::Result<()> {
        let directory = self.directory.clone();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || {
            // NamedTempFile uses mode 0600 on Unix. Rename prevents truncated cache entries.
            let mut file = tempfile::NamedTempFile::new_in(directory)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist(path).map_err(|error| error.error)?;
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }
}

#[async_trait]
impl AccountCache for PrivateCache {
    type EA = io::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> io::Result<Option<Vec<u8>>> {
        self.load(self.path("account", contact, directory_url))
            .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.store(self.path("account", contact, directory_url), bytes)
            .await
    }
}

#[async_trait]
impl CertCache for PrivateCache {
    type EC = io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> io::Result<Option<Vec<u8>>> {
        self.load(self.path("cert", domains, directory_url)).await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.store(self.path("cert", domains, directory_url), bytes)
            .await
    }
}
