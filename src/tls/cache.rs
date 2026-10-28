//! Private, atomically replaced ACME account and certificate storage.
//!
//! All I/O is descriptor-relative to a single pinned directory handle, so
//! replacing the cache pathname after [`PrivateCache::open`] can never redirect
//! renewal reads or writes outside the opened directory.

use async_trait::async_trait;
use ring::{
    digest::{Context, SHA256},
    rand::{SecureRandom, SystemRandom},
};
use rustix::fs::{self as rfs, Mode, OFlags};
use rustls_acme::{AccountCache, CertCache};
use std::{
    fmt::Write as _,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsFd,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct PrivateCache {
    directory: PathBuf,
    handle: Arc<File>,
}

/// RAII cleanup guard for a temporary file created in the cache directory.
///
/// Holds the pinned directory handle and the temporary basename; unlinks the
/// temporary on drop unless disarmed after a successful rename.
struct TempGuard {
    dir: Arc<File>,
    name: String,
    armed: bool,
}

impl TempGuard {
    fn new(dir: Arc<File>, name: String) -> Self {
        Self {
            dir,
            name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = rfs::unlinkat(self.dir.as_fd(), self.name.as_str(), rfs::AtFlags::empty());
        }
    }
}

impl PrivateCache {
    /// Existing directories must already be private; never chmod an arbitrary user path.
    ///
    /// The directory is created/canonicalized once, opened as a pinned handle
    /// (`RDONLY|DIRECTORY|NOFOLLOW|CLOEXEC`), and validated with `fstat` of
    /// that handle. Later `load`/`store` I/O is descriptor-relative to it.
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
            let handle = rfs::openat(
                rfs::CWD,
                &directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?;
            let handle = Arc::new(File::from(handle));
            let metadata = handle.metadata()?;
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
            Ok(Self { directory, handle })
        })
        .await
        .map_err(io::Error::other)?
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Pinned handle for the cache directory, for shared-pin integration.
    #[must_use]
    pub(crate) fn directory_handle(&self) -> Arc<File> {
        Arc::clone(&self.handle)
    }

    fn key(kind: &str, identifiers: &[String], directory_url: &str) -> String {
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
        format!("{kind}-{hash}")
    }

    async fn load(&self, key: String) -> io::Result<Option<Vec<u8>>> {
        let handle = Arc::clone(&self.handle);
        tokio::task::spawn_blocking(move || {
            let fd = match rfs::openat(
                handle.as_fd(),
                key.as_str(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
                Err(e) => return Err(io::Error::from(e)),
            };
            let file = File::from(fd);
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cache entry is not a regular file",
                ));
            }
            let mut bytes = Vec::new();
            let mut file = file;
            file.read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        })
        .await
        .map_err(io::Error::other)?
    }

    async fn store(&self, key: String, bytes: &[u8]) -> io::Result<()> {
        let handle = Arc::clone(&self.handle);
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || {
            let random = SystemRandom::new();
            // Bounded collision retries for the exclusive temporary name.
            for _ in 0..16u32 {
                let mut salt = [0u8; 16];
                random
                    .fill(&mut salt)
                    .map_err(|_| io::Error::other("secure random source unavailable"))?;
                let mut tmp = String::with_capacity(5 + 32);
                tmp.push_str(".tmp-");
                for byte in salt {
                    // Formatting into a String cannot fail.
                    let _ = write!(tmp, "{byte:02x}");
                }
                let fd = match rfs::openat(
                    handle.as_fd(),
                    tmp.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::CLOEXEC
                        | OFlags::NOFOLLOW,
                    Mode::from_bits_truncate(0o600),
                ) {
                    Ok(fd) => fd,
                    Err(e) if e == rustix::io::Errno::EXIST => continue,
                    Err(e) => return Err(io::Error::from(e)),
                };
                let mut guard = TempGuard::new(Arc::clone(&handle), tmp);
                {
                    let mut file = File::from(fd);
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                }
                rfs::renameat(
                    handle.as_fd(),
                    guard.name.as_str(),
                    handle.as_fd(),
                    key.as_str(),
                )
                .map_err(io::Error::from)?;
                guard.disarm();
                return Ok(());
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique cache temporary file",
            ))
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
        self.load(Self::key("account", contact, directory_url))
            .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.store(Self::key("account", contact, directory_url), bytes)
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
        self.load(Self::key("cert", domains, directory_url)).await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.store(Self::key("cert", domains, directory_url), bytes)
            .await
    }
}
