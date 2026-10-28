//! Race-safe filesystem access helpers for the file server.
//!
//! [`Protected::open`] walks a resolved absolute pathname from the root
//! directory using held directory descriptors opened with `O_NOFOLLOW`, so a
//! concurrently retargeted symlink can never redirect the walk into the
//! protected certificate cache. Identity (device/inode) checks reject the cache
//! directory even after it has been renamed.

use rustix::fs::{self, AtFlags, CWD, Dir, FileType, Mode, OFlags};
use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
};

/// Directory search flags for `openat` walks.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const DIR_SEARCH: OFlags = OFlags::PATH;

#[cfg(target_os = "macos")]
const DIR_SEARCH: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as u32);

/// The protected certificate cache directory.
#[derive(Debug)]
pub struct Protected {
    /// Canonical absolute pathname of the cache directory.
    canonical: PathBuf,
    /// Held search descriptor pinning the cache directory's lifetime.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "descriptor ownership pins the cache inode")
    )]
    cache: Arc<File>,
    /// Device and inode identity of the cache directory.
    dev: u64,
    ino: u64,
}

/// A single directory entry: raw filename plus file type.
#[derive(Debug)]
pub struct Entry {
    /// Raw filename (may be non-UTF-8).
    pub name: OsString,
    /// File type of the entry (symlink/unknown preserved for the handler).
    pub file_type: rustix::fs::FileType,
}

impl Entry {
    /// Whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }

    /// Whether the entry is a regular file.
    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }
}

/// A file opened by [`open`] or [`Protected::open`].
#[derive(Debug)]
pub struct Opened {
    /// The open file handle.
    pub file: File,
    /// `fstat` metadata of the open handle.
    pub metadata: Metadata,
}

/// Policy/race denial marker distinguishing a protected-cache rejection from a
/// genuine missing file. Mapped to HTTP 404 but never treated as "no index".
#[derive(Debug)]
pub struct Denied;

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("path is protected and cannot be served")
    }
}

impl std::error::Error for Denied {}

impl From<Denied> for io::Error {
    fn from(denied: Denied) -> Self {
        io::Error::new(io::ErrorKind::PermissionDenied, denied)
    }
}

/// Returns `true` when `error` is a policy/race denial from the protected
/// resolver (as opposed to an ordinary filesystem permission error).
pub fn is_denied(error: &io::Error) -> bool {
    match error.get_ref() {
        Some(inner) => inner.is::<Denied>(),
        None => false,
    }
}

/// Returns a policy denial (distinct from [`not_found`]).
fn denied<T>() -> io::Result<T> {
    Err(Denied.into())
}

fn not_found<T>() -> io::Result<T> {
    Err(io::Error::from(io::ErrorKind::NotFound))
}

/// Open the final path component read-only, falling back to a search
/// descriptor only for directories (execute-only traversal). A non-directory
/// that is not readable keeps its original `PermissionDenied`.
fn open_final(
    parent: impl AsFd,
    leaf: &std::ffi::OsStr,
    nofollow: OFlags,
) -> io::Result<(File, Metadata)> {
    match fs::openat(
        parent.as_fd(),
        leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | nofollow,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file = file_from_fd(fd);
            let metadata = file.metadata()?;
            Ok((file, metadata))
        }
        Err(e) => {
            let original: io::Error = e.into();
            if original.kind() != io::ErrorKind::PermissionDenied {
                return Err(not_found_or(original));
            }
            // Execute-only directory fallback: search descriptor, directories only.
            let fd = fs::openat(
                parent.as_fd(),
                leaf,
                DIR_SEARCH | OFlags::DIRECTORY | OFlags::CLOEXEC | nofollow,
                Mode::empty(),
            )
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?; // preserve original
            let file = file_from_fd(fd);
            let metadata = file.metadata()?;
            if !metadata.is_dir() {
                return Err(original);
            }
            Ok((file, metadata))
        }
    }
}

fn not_found_or(e: io::Error) -> io::Error {
    let raw = e.raw_os_error();
    let race_like = matches!(
        e.kind(),
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::IsADirectory
            | io::ErrorKind::InvalidInput
    ) || raw == Some(rustix::io::Errno::LOOP.raw_os_error())
        // ENXIO: opening a Unix-domain socket path with O_RDONLY fails; the
        // old metadata preflight classified it as a non-file (404).
        || raw == Some(rustix::io::Errno::NXIO.raw_os_error());
    if race_like {
        io::Error::from(io::ErrorKind::NotFound)
    } else {
        e
    }
}

fn file_from_fd(fd: OwnedFd) -> File {
    File::from(fd)
}

/// Whether `path` equals or lies below `root`.
fn under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

/// Enumerate directory entries of an opened directory handle without touching
/// any path. Reading uses a separate `"."` read descriptor so search-only
/// handles stay search-only. Filenames are kept raw (`OsString`) so non-UTF-8
/// names survive. Ordinary read `PermissionDenied` (403) is preserved.
pub fn list_entries(dir_handle: &File) -> io::Result<Vec<Entry>> {
    let fd = fs::openat(
        dir_handle.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = file_from_fd(fd);
    let mut dir = Dir::read_from(file.as_fd())?;
    let mut entries = Vec::new();
    while let Some(entry) = dir.read() {
        let entry = entry?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let name = OsString::from_vec(raw.to_vec());
        let file_type = entry.file_type();
        entries.push(Entry { name, file_type });
    }
    Ok(entries)
}

use std::os::unix::ffi::OsStringExt as _;

impl Protected {
    /// Pin the cache directory at `path` by canonical path and held descriptor.
    pub fn new(path: &Path) -> io::Result<Self> {
        let canonical = std::fs::canonicalize(path)?;
        if !std::fs::metadata(&canonical)?.is_dir() {
            return not_found();
        }
        let fd = fs::openat(
            CWD,
            &canonical,
            DIR_SEARCH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| not_found_or(e.into()))?;
        Self::from_handle(canonical, Arc::new(file_from_fd(fd)))
    }

    /// Pin the cache directory from an already-open directory handle, deriving
    /// the dev/ino identity via `fstat` of that exact handle (no pathname
    /// re-open). `canonical` is the resolved pathname used for the prefix
    /// rejection only; identity checks use the pinned handle.
    pub fn from_handle(canonical: PathBuf, cache: Arc<File>) -> io::Result<Self> {
        let metadata = cache.metadata()?;
        if !metadata.is_dir() {
            return not_found();
        }
        Ok(Self {
            canonical,
            cache,
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    /// Read-capable duplicate of the held cache directory descriptor, usable
    /// with `Dir::read_from` (which reopens the descriptor for reading).
    #[cfg(test)]
    pub fn cache(&self) -> io::Result<File> {
        let fd = fs::openat(
            self.cache.as_fd(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| not_found_or(e.into()))?;
        Ok(file_from_fd(fd))
    }

    /// Open `path` for reading without racing the cache.
    ///
    /// The path is canonicalized first (so ordinary outside-root symlinks keep
    /// working), checked against the cache pathname, then walked component by
    /// component from `/` with `openat(.., NOFOLLOW)` through held directory
    /// descriptors. Every directory encountered, including a renamed cache, is
    /// rejected by device/inode identity. The original pathname is never
    /// reopened. Denied or racy outcomes map to [`io::ErrorKind::NotFound`].
    pub fn open(&self, path: &Path) -> io::Result<Opened> {
        self.open_with(path, || Ok(()))
    }

    fn open_with(
        &self,
        path: &Path,
        after_canonicalize: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Opened> {
        let resolved = std::fs::canonicalize(path).map_err(not_found_or)?;
        if under(&resolved, &self.canonical) {
            return denied();
        }
        if !resolved.is_absolute() {
            return denied();
        }
        after_canonicalize()?;
        // Walk the resolved absolute path from "/" through held directory FDs.
        let (dir, leaf) = walk_to_parent(self, &resolved)?;
        // The resolved root "/" itself is an authorized object: return its
        // handle rather than failing the empty walk.
        let Some(leaf) = leaf else {
            let metadata = dir.metadata()?;
            return Ok(Opened {
                file: dir,
                metadata,
            });
        };
        let (file, metadata) = open_final(&dir, leaf, OFlags::NOFOLLOW)?;
        if !(metadata.is_file() || metadata.is_dir()) {
            return not_found();
        }
        // Final-directory identity guard: a renamed cache opened as the leaf
        // must be rejected even though the pathname check passed.
        if metadata.is_dir() && (metadata.dev(), metadata.ino()) == (self.dev, self.ino) {
            return denied();
        }
        // Directory handles are kept as opened (search or read descriptors);
        // `entries()` reads through a separate "." descriptor when listing is
        // requested, so execute-only traversal is never undone here.
        Ok(Opened { file, metadata })
    }

    /// Metadata-only classification of `path` for directory listings: returns
    /// whether the target is a directory, without requiring read permission.
    ///
    /// Reuses the same canonicalize + NOFOLLOW descriptor walk and cache
    /// identity checks as [`Protected::open`], but resolves the final component
    /// with `statat(.., SYMLINK_NOFOLLOW)` (portable; no `O_PATH`/`O_SEARCH` on
    /// regular files). A symlink leaf is denied after canonicalization; only
    /// regular files and directories are accepted, and a final directory is
    /// rejected by cache dev/ino identity.
    pub fn classify(&self, path: &Path) -> io::Result<bool> {
        let resolved = std::fs::canonicalize(path).map_err(not_found_or)?;
        if under(&resolved, &self.canonical) {
            return denied();
        }
        if !resolved.is_absolute() {
            return denied();
        }
        let (dir, leaf) = walk_to_parent(self, &resolved)?;
        let Some(leaf) = leaf else {
            // Resolved root is a directory.
            return Ok(true);
        };
        // Final component via statat NOFOLLOW: no read permission required.
        let stat = fs::statat(dir.as_fd(), leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| not_found_or(e.into()))?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        // A symlink leaf (NOFOLLOW) is denied after canonicalization.
        if file_type.is_symlink() {
            return denied();
        }
        if file_type.is_dir() {
            // Final-directory identity guard. The device id must match std's
            // `MetadataExt::dev()` representation exactly: on macOS `dev_t` is
            // signed and std sign-extends it to u64, so a negative device id
            // must not bypass the identity check.
            #[cfg(target_os = "macos")]
            let dev = u64::from_ne_bytes(i64::from(stat.st_dev).to_ne_bytes());
            #[cfg(not(target_os = "macos"))]
            let dev = stat.st_dev;
            let ino = stat.st_ino;
            if (dev, ino) == (self.dev, self.ino) {
                return denied();
            }
            return Ok(true);
        }
        if file_type.is_file() {
            return Ok(false);
        }
        not_found()
    }
}

/// Open `path` for reading without cache protection.
///
/// The file is read-opened with `O_NONBLOCK` (so opening a FIFO cannot block
/// the server) and symlinks are preserved (resolved by the kernel). Ordinary
/// `PermissionDenied` is preserved for the caller.
pub fn open(path: &Path) -> io::Result<Opened> {
    // Reuse the read-or-search-directory logic so execute-only directories can
    // still serve their readable index.html without read permission on the
    // directory itself. Symlinks are preserved (kernel resolves them); the
    // NOFOLLOW flag is intentionally not applied here.
    let (file, metadata) = open_final(CWD, path.as_os_str(), OFlags::empty())?;
    if !(metadata.is_file() || metadata.is_dir()) {
        return not_found();
    }
    Ok(Opened { file, metadata })
}

/// Walk the resolved absolute path from "/" through held directory descriptors
/// up to (but excluding) the final component, applying `O_NOFOLLOW` and cache
/// dev/ino identity checks at every intermediate directory. Returns the parent
/// directory handle and the final component name. Reused by `open`/`classify`.
fn walk_to_parent<'p>(
    cache: &Protected,
    resolved: &'p Path,
) -> io::Result<(File, Option<&'p std::ffi::OsStr>)> {
    let root_fd = fs::openat(
        CWD,
        "/",
        DIR_SEARCH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| not_found_or(e.into()))?;
    let mut dir = file_from_fd(root_fd);
    let mut components: Vec<&std::ffi::OsStr> = Vec::new();
    for component in resolved.components() {
        if let Component::Normal(name) = component {
            components.push(name);
        }
    }
    let Some((&leaf, parents)) = components.split_last() else {
        return Ok((dir, None));
    };
    for name in parents {
        let (next_dir, dir_meta) = open_dir_at(&dir, name)?;
        dir = next_dir;
        if (dir_meta.dev(), dir_meta.ino()) == (cache.dev, cache.ino) {
            return denied();
        }
    }
    Ok((dir, Some(leaf)))
}

/// Open `name` as a directory below `dir` without following symlinks, keeping
/// execute-only traversal working via search descriptors. `O_DIRECTORY`
/// already enforces the directory type, so the returned metadata is the single
/// `fstat` reused by the caller for the identity check.
fn open_dir_at(dir: &File, name: &std::ffi::OsStr) -> io::Result<(File, Metadata)> {
    let fd = fs::openat(
        dir.as_fd(),
        name,
        DIR_SEARCH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| not_found_or(e.into()))?;
    let file = file_from_fd(fd);
    let metadata = file.metadata()?;
    Ok((file, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Scenario fixture. All setup returns `io::Result` so tests obey the
    /// strict `expect_used`/`unwrap_used`/`panic` lint policy by carrying
    /// errors out of the test body instead of panicking mid-fixture.
    struct Scenario {
        _tmp: TempDir,
        root: PathBuf,
        cache: PathBuf,
        protected: Protected,
        /// Separate benign alias symlink pointing at the canonical leaf.
        alias: PathBuf,
        /// Canonical leaf file with benign content.
        leaf: PathBuf,
    }

    impl Scenario {
        fn new() -> io::Result<Self> {
            let tmp = TempDir::new()?;
            let root = tmp.path().join("root");
            let cache = tmp.path().join("cache");
            fs::create_dir_all(root.join("sub"))?;
            fs::create_dir_all(&cache)?;
            let leaf = root.join("sub").join("leaf.txt");
            fs::write(&leaf, b"legit")?;
            // Same basename as the requested leaf so a broken parent/identity
            // guard cannot pass by hitting a missing cache/leaf.txt.
            fs::write(cache.join("leaf.txt"), b"private-leaf")?;
            fs::write(cache.join("secret.txt"), b"top secret")?;
            let protected = Protected::new(&cache)?;
            let alias = root.join("alias.txt");
            std::os::unix::fs::symlink(&leaf, &alias)?;
            Ok(Self {
                _tmp: tmp,
                root,
                cache,
                protected,
                alias,
                leaf,
            })
        }

        /// Open `alias`, racing the filesystem after canonicalization. The
        /// seam closure returns `io::Result` so fixture mutation can use `?`.
        fn race_open(&self, race: impl FnOnce() -> io::Result<()>) -> io::Result<Opened> {
            self.protected.open_with(&self.alias, race)
        }
    }

    fn read_to_string(mut file: File) -> io::Result<String> {
        use std::io::Read;
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn entry_names(opened: &Opened) -> io::Result<Vec<String>> {
        let mut names: Vec<String> = list_entries(&opened.file)?
            .into_iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        Ok(names)
    }

    /// Original alias retargeted to cache content while the canonical leaf is
    /// left untouched: the walk uses the canonical path, so benign bytes are
    /// still served (benign authorized object).
    #[test]
    fn alias_retargeted_to_cache_is_ignored() -> io::Result<()> {
        let s = Scenario::new()?;
        let opened = s.race_open(|| {
            fs::remove_file(&s.alias)?;
            std::os::unix::fs::symlink(s.cache.join("secret.txt"), &s.alias)?;
            Ok(())
        })?;
        assert_eq!(read_to_string(opened.file)?, "legit");
        Ok(())
    }

    /// Canonical leaf itself replaced with a symlink into the cache: NOFOLLOW
    /// at the leaf rejects it.
    #[test]
    fn canonical_leaf_replaced_with_cache_symlink_is_rejected() -> io::Result<()> {
        let s = Scenario::new()?;
        let result = s.race_open(|| {
            fs::remove_file(&s.leaf)?;
            std::os::unix::fs::symlink(s.cache.join("secret.txt"), &s.leaf)?;
            Ok(())
        });
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        Ok(())
    }

    /// Parent directory replaced with a symlink to the cache: NOFOLLOW at the
    /// parent component rejects it.
    #[test]
    fn parent_replaced_with_cache_symlink_is_rejected() -> io::Result<()> {
        let s = Scenario::new()?;
        let sub = s.root.join("sub");
        let result = s.race_open(|| {
            fs::remove_dir_all(&sub)?;
            std::os::unix::fs::symlink(s.cache.clone(), &sub)?;
            Ok(())
        });
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        Ok(())
    }

    /// Index leaf replacement: `index.html` is swapped for a cache-file
    /// symlink at the controlled seam and must be rejected.
    #[test]
    fn index_leaf_replaced_with_cache_symlink_is_rejected() -> io::Result<()> {
        let s = Scenario::new()?;
        let index = s.root.join("index.html");
        fs::write(&index, b"benign index")?;
        let result = s.protected.open_with(&index, || {
            fs::remove_file(&index)?;
            std::os::unix::fs::symlink(s.cache.join("secret.txt"), &index)?;
            Ok(())
        });
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        Ok(())
    }

    /// Public directory renamed aside and its original pathname replaced by
    /// the cache directory: the final-directory identity guard must reject it.
    #[test]
    fn renamed_cache_into_public_dir_name_is_rejected_by_identity() -> io::Result<()> {
        let s = Scenario::new()?;
        let public_dir = s.root.join("public");
        fs::create_dir_all(&public_dir)?;
        fs::write(public_dir.join("page.txt"), b"benign page")?;
        let result = s.protected.open_with(&public_dir, || {
            let aside = s.root.join("public-aside");
            fs::rename(&public_dir, &aside)?;
            fs::rename(&s.cache, &public_dir)?;
            Ok(())
        });
        let err = result
            .err()
            .unwrap_or_else(|| io::Error::other("expected denial"));
        assert!(is_denied(&err), "expected policy denial, got {err:?}");
        Ok(())
    }

    /// Held directory listing survives pathname replacement: an authorized
    /// public directory is opened, renamed aside intact, and its original
    /// pathname is replaced with a cache symlink; the held handle must still
    /// enumerate the benign entries with no private names.
    #[test]
    fn held_directory_listing_survives_pathname_replacement() -> io::Result<()> {
        let s = Scenario::new()?;
        let public_dir = s.root.join("listing");
        fs::create_dir_all(&public_dir)?;
        fs::write(public_dir.join("benign.txt"), b"benign")?;
        let opened = s.protected.open(&public_dir)?;
        let aside = s.root.join("listing-aside");
        fs::rename(&public_dir, &aside)?;
        std::os::unix::fs::symlink(&s.cache, &public_dir)?;
        let names = entry_names(&opened)?;
        assert!(names.contains(&"benign.txt".to_string()));
        assert!(!names.iter().any(|n| n == "secret.txt" || n == "leaf.txt"));
        Ok(())
    }

    /// Held cache descriptor lists the ORIGINAL private entries even after the
    /// cache pathname is renamed/replaced.
    #[test]
    fn held_cache_descriptor_survives_pathname_replacement() -> io::Result<()> {
        let s = Scenario::new()?;
        // Capture the held cache handle, then rename its pathname away and
        // replace it with a decoy directory.
        let cache = s.protected.cache()?;
        let meta = cache.metadata()?;
        let opened = Opened {
            file: cache,
            metadata: meta,
        };
        let aside = s.root.join("cache-aside");
        fs::rename(&s.cache, &aside)?;
        fs::create_dir_all(&s.cache)?;
        fs::write(s.cache.join("decoy.txt"), b"decoy")?;
        // The held handle still lists the original private entries.
        let names = entry_names(&opened)?;
        assert!(names.contains(&"secret.txt".to_string()));
        assert!(names.contains(&"leaf.txt".to_string()));
        assert!(!names.contains(&"decoy.txt".to_string()));
        Ok(())
    }

    /// Unprotected open preserves symlinks and reads the benign content.
    #[test]
    fn unprotected_open_preserves_symlinks_and_reads_content() -> io::Result<()> {
        let s = Scenario::new()?;
        let opened = open(&s.alias)?;
        assert_eq!(read_to_string(opened.file)?, "legit");
        assert!(opened.metadata.is_file());
        Ok(())
    }

    /// Protected open accepts regular files and ordinary directories.
    #[test]
    fn protected_open_accepts_regular_files_and_dirs() -> io::Result<()> {
        let s = Scenario::new()?;
        let opened = s.protected.open(&s.leaf)?;
        assert!(opened.metadata.is_file());
        let dir_opened = s.protected.open(&s.root)?;
        assert!(dir_opened.metadata.is_dir());
        Ok(())
    }

    /// Resolved "/" is returned as the authorized root directory handle.
    #[test]
    fn protected_open_of_root_returns_root_handle() -> io::Result<()> {
        let s = Scenario::new()?;
        let opened = s.protected.open(Path::new("/"))?;
        assert!(opened.metadata.is_dir());
        Ok(())
    }

    /// Cache renamed into an INTERMEDIATE public directory: requesting
    /// `leaf.txt` (which also exists privately with the same basename) must be
    /// rejected by the intermediate-directory identity check. Removing that
    /// check would leak private bytes via the leaf open.
    #[test]
    fn cache_renamed_into_intermediate_dir_is_rejected_by_identity() -> io::Result<()> {
        let s = Scenario::new()?;
        // Setup (outside expected-error matching): verify private bytes exist.
        let private = fs::read(s.cache.join("leaf.txt"))?;
        assert_eq!(private, b"private-leaf");
        // Build root/pub/leaf.txt and request it; move cache to root/pub.
        let pub_dir = s.root.join("pub");
        fs::create_dir_all(&pub_dir)?;
        let target = pub_dir.join("leaf.txt");
        fs::write(&target, b"benign pub leaf")?;
        let result = s.protected.open_with(&target, || {
            let aside = s.root.join("pub-aside");
            fs::rename(&pub_dir, &aside)?;
            fs::rename(&s.cache, &pub_dir)?;
            Ok(())
        });
        let err = result
            .err()
            .unwrap_or_else(|| io::Error::other("expected denial"));
        assert!(is_denied(&err), "expected policy denial, got {err:?}");
        Ok(())
    }

    /// Parent replaced with a symlink to a NESTED cache subdirectory that
    /// contains `leaf.txt`: the intermediate NOFOLLOW check must reject it.
    /// The cache-root identity check alone cannot mask a missing NOFOLLOW
    /// because the nested subdirectory has a different dev/ino than the cache
    /// root.
    #[test]
    fn parent_replaced_with_nested_cache_symlink_is_rejected() -> io::Result<()> {
        let s = Scenario::new()?;
        // Setup (outside expected-error matching): verify private bytes exist.
        let nested = s.cache.join("nested");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("leaf.txt"), b"private nested leaf")?;
        let sub = s.root.join("sub");
        let result = s.protected.open_with(&s.leaf, || {
            fs::remove_dir_all(&sub)?;
            std::os::unix::fs::symlink(&nested, &sub)?;
            Ok(())
        });
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        Ok(())
    }

    /// Independent check that this process actually enforces DAC (not e.g.
    /// running as root). Reads a mode-0000 file with `std::fs`; if that read
    /// succeeds, the process bypasses DAC and the permission tests are skipped.
    fn bypasses_dac(probe: &Path) -> bool {
        std::fs::read(probe).is_ok()
    }

    /// Unreadable regular file under protection must return `PermissionDenied`,
    /// not `NotFound` and not an `O_PATH` handle (which would stream `EBADF` later).
    #[test]
    fn unreadable_regular_file_returns_permission_denied() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let s = Scenario::new()?;
        let secret = s.root.join("unreadable.txt");
        fs::write(&secret, b"private bytes")?;
        let mut perms = fs::metadata(&secret)?.permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&secret, perms)?;
        // Independent DAC probe: if std::fs can read the mode-0000 file, this
        // process bypasses DAC (root) and the test is not meaningful.
        if bypasses_dac(&secret) {
            let mut perms = fs::metadata(&secret)?.permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&secret, perms)?;
            return Ok(());
        }
        // Capture the outcome WHILE the file is still unreadable.
        let result = s.protected.open(&secret);
        // Restore mode before assertion/cleanup.
        let mut perms = fs::metadata(&secret)?.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&secret, perms)?;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        Ok(())
    }

    /// Execute-only directory yields a search handle but enumeration fails
    /// with `PermissionDenied` (403 preserved, not mapped to `NotFound`).
    #[test]
    fn execute_only_directory_enumeration_fails_permission_denied() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let s = Scenario::new()?;
        let ex_dir = s.root.join("exonly");
        fs::create_dir_all(&ex_dir)?;
        fs::write(ex_dir.join("index.html"), b"benign index")?;
        let mut perms = fs::metadata(&ex_dir)?.permissions();
        perms.set_mode(0o111); // execute-only
        fs::set_permissions(&ex_dir, perms)?;
        // Independent DAC probe: if std::fs can enumerate the execute-only
        // directory, this process bypasses DAC and the test is not meaningful.
        let dac_ok = fs::read_dir(&ex_dir).is_ok();
        if dac_ok {
            let mut perms = fs::metadata(&ex_dir)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&ex_dir, perms)?;
            return Ok(());
        }
        // Open the search handle and capture the enumeration outcome WHILE
        // the directory is still execute-only (mode 0111).
        let opened = s.protected.open(&ex_dir)?;
        assert!(opened.metadata.is_dir());
        let result = list_entries(&opened.file);
        // Restore mode before assertion/cleanup.
        let mut perms = fs::metadata(&ex_dir)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&ex_dir, perms)?;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        Ok(())
    }
}
