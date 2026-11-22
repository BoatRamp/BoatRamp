//! OCI image → `ext4` rootfs build, behind the `build`
//! feature. No container runtime: pull the image over the registry HTTP API,
//! **overlay** its layers onto a tree (honoring OCI whiteouts), and `mke2fs -d`
//! the result into an ext4 image.
//!
//! The **layer overlay** ([`apply_layer_gz`]) is pure and unit-tested. The
//! registry pull + overlay ([`build_rootfs_dir`], network) and the ext4 build
//! ([`build_ext4`], the `e2fsprogs` `mke2fs` tool) are host seams. Each layer is
//! **streamed to disk** as it downloads (bounded memory + a size cap enforced
//! mid-stream), and the whole pull is bounded by an overall wall-clock deadline.
//! The *compressed* size cap does not bound how large a layer **inflates** to, so
//! the overlay bounds the **decompressed** byte count too — a gzip zip-bomb (small
//! compressed, huge decompressed) is aborted DURING inflation, per layer and across
//! the whole rootfs, before it can fill the node disk. The same decompressed budget
//! also charges the hard-link `fs::copy` fallback (which reads the target **from
//! disk**, invisible to the gunzip stream, so a copy-amplification bomb would
//! otherwise be uncounted), and a per-image **tar-entry count** cap bounds an
//! inode-exhaustion bomb (millions of tiny entries).

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use ipnet::IpNet;

/// An OCI build error.
#[derive(Debug)]
pub enum OciError {
    /// A filesystem / extraction error.
    Io(std::io::Error),
    /// A tar entry escaped the root (path traversal) — refused.
    UnsafePath(String),
    /// A registry / HTTP error.
    Registry(String),
    /// `mke2fs` failed or is missing.
    Mkfs(String),
    /// The image reference could not be parsed.
    BadReference(String),
}

impl std::fmt::Display for OciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::UnsafePath(p) => write!(f, "unsafe path in layer: {p}"),
            Self::Registry(m) => write!(f, "registry error: {m}"),
            Self::Mkfs(m) => write!(f, "mke2fs error: {m}"),
            Self::BadReference(m) => write!(f, "bad image reference: {m}"),
        }
    }
}

impl std::error::Error for OciError {}

impl From<std::io::Error> for OciError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Normalize a tar entry path to a safe relative path under the root, rejecting
/// absolute paths and any `..` that would escape (path-traversal guard).
fn safe_relative(path: &Path) -> Result<PathBuf, OciError> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            // Anything that could escape the root is refused.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(OciError::UnsafePath(path.display().to_string()));
            }
        }
    }
    Ok(out)
}

/// Bound on symlink expansions while resolving one path — a loop / long-chain
/// guard (mirrors `openat2`'s `SYMLOOP_MAX`-style cap).
const MAX_SYMLINK_HOPS: usize = 40;

/// One owned element of a path being resolved. Owned (not a borrowing
/// [`Component`]) so a followed symlink's target elements can be spliced in.
enum PathTok {
    Name(std::ffi::OsString),
    Parent,
    Root,
}

fn path_toks(p: &Path) -> Vec<PathTok> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(PathTok::Name(n.to_os_string())),
            Component::ParentDir => Some(PathTok::Parent),
            Component::RootDir | Component::Prefix(_) => Some(PathTok::Root),
            Component::CurDir => None,
        })
        .collect()
}

/// Resolve `rel` under `root` with **`RESOLVE_IN_ROOT` (chroot-style) semantics**,
/// cross-platform and without `openat2` (the macOS VZ path needs it too):
/// symlink components ARE followed, but `root` is treated as the filesystem root,
/// so the result is ALWAYS inside `root`. An **absolute** symlink target is
/// reinterpreted root-relative (`sbin -> /etc/cron.d` resolves to `<root>/etc/cron.d`,
/// never the host's `/etc`); a **relative** target resolves from the symlink's own
/// directory; `..` is clamped at `root` (it never escapes); and symlink chains are
/// bounded by [`MAX_SYMLINK_HOPS`]. This both CONTAINS a hostile layer's planted
/// symlink (the escape is neutralized) AND stays compatible with legitimate
/// in-root symlinks that real images ship (usrmerge `/lib -> usr/lib`,
/// `/sbin -> usr/sbin`, …) — which a strict refuse-all-symlinks guard would wrongly
/// reject.
///
/// `follow_leaf` controls the final component: `true` follows it (used where the
/// resolved path is itself read/traversed — a hard-link target, an opaque-whiteout
/// dir, an existence check); `false` leaves the leaf un-dereferenced so the caller
/// can unlink-then-create it (never following a planted leaf symlink). The parents
/// of the returned path are always real, symlink-free directories (or
/// not-yet-existing) inside `root`.
fn resolve_in_root_impl(root: &Path, rel: &Path, follow_leaf: bool) -> Result<PathBuf, OciError> {
    // `stack`: resolved, symlink-free components relative to `root`.
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    // `queue`: tokens still to process, popped from the END (= front of the path).
    // A followed symlink splices its target's tokens onto the end so they resolve
    // next, from the directory that contained the link.
    let mut queue: Vec<PathTok> = path_toks(rel);
    queue.reverse();
    let mut hops = 0usize;

    while let Some(tok) = queue.pop() {
        match tok {
            PathTok::Root => stack.clear(), // absolute symlink target → back to root
            PathTok::Parent => {
                stack.pop(); // clamp at root (no-op when already at root)
            }
            PathTok::Name(name) => {
                let is_last = queue.is_empty();
                let mut candidate = root.to_path_buf();
                for s in &stack {
                    candidate.push(s);
                }
                candidate.push(&name);
                let followable = follow_leaf || !is_last;
                if followable && fs::symlink_metadata(&candidate).is_ok_and(|m| m.is_symlink()) {
                    hops += 1;
                    if hops > MAX_SYMLINK_HOPS {
                        return Err(OciError::UnsafePath(format!(
                            "too many symlink hops resolving {} under root",
                            rel.display()
                        )));
                    }
                    let target = fs::read_link(&candidate)?;
                    let mut toks = path_toks(&target);
                    toks.reverse();
                    queue.extend(toks);
                } else {
                    stack.push(name);
                }
            }
        }
    }
    let mut out = root.to_path_buf();
    for s in &stack {
        out.push(s);
    }
    Ok(out)
}

/// [`resolve_in_root_impl`] following the final component (for a path that is
/// itself read/traversed).
fn resolve_in_root(root: &Path, rel: &Path) -> Result<PathBuf, OciError> {
    resolve_in_root_impl(root, rel, true)
}

/// [`resolve_in_root_impl`] stopping before the final component: the parent chain
/// is resolved in-root and the leaf is returned un-dereferenced (the caller
/// unlinks a planted leaf symlink before writing, never following it).
fn resolve_parent_in_root(root: &Path, rel: &Path) -> Result<PathBuf, OciError> {
    resolve_in_root_impl(root, rel, false)
}

/// Create (and parents) a real directory for the in-`root` path `rel`, resolving
/// symlink components `RESOLVE_IN_ROOT` so a planted symlink can never redirect
/// the `mkdir` onto the host. A planted leaf symlink is not followed. Returns the
/// resolved real path. The crate's post-unpack writers (`write_init`) and the
/// container backend's resolv.conf writer go through this so EVERY write into the
/// tenant-controlled tree is contained, not just the layer unpack.
pub fn contained_create_dir_all(root: &Path, rel: &Path) -> Result<PathBuf, OciError> {
    let sane = safe_relative(rel)?;
    let dest = resolve_in_root(root, &sane)?;
    fs::create_dir_all(&dest)?;
    Ok(dest)
}

/// Write `data` to the in-`root` path `rel`, resolving the parent chain
/// `RESOLVE_IN_ROOT`, creating it, and — critically — **unlinking any existing
/// leaf symlink before writing** (never following it), so a hostile layer that
/// planted the destination as a symlink cannot redirect the write onto the host.
/// Returns the resolved real path (its parents are real in-root dirs), so a
/// caller can safely `chmod` it. The companion to [`contained_create_dir_all`].
pub fn contained_write(root: &Path, rel: &Path, data: &[u8]) -> Result<PathBuf, OciError> {
    let sane = safe_relative(rel)?;
    let dest = resolve_parent_in_root(root, &sane)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    // Never write THROUGH a planted leaf symlink: unlink it first.
    if fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::remove_file(&dest)?;
    }
    fs::write(&dest, data)?;
    Ok(dest)
}

/// Resolve a tar **hard-link** target into a host path under `root`. A hard link's
/// `linkname` references another member of the *same archive* (the same namespace
/// as member names), so it is always relative to the extraction root — never the
/// process CWD. An absolute target is normalized to root-relative (its leading `/`
/// is stripped, as `tar` does without `--absolute-names`); a `..` in the linkname
/// itself is refused. The result is then resolved [`RESOLVE_IN_ROOT`](resolve_in_root)
/// (following the leaf): a hard link is `hard_link`'d/`copy`'d (and `copy` FOLLOWS
/// symlinks), so a planted symlink target (`-> /etc/shadow`) is reinterpreted
/// root-relative and can only ever reach the image's OWN files, never a host file
/// (read/exfil closed). (A *symlink* entry is different: its target is stored +
/// created verbatim and resolved inside the guest, so it goes through `unpack`.)
fn link_target_under_root(root: &Path, link: &Path) -> Result<PathBuf, OciError> {
    let mut rel = PathBuf::new();
    for comp in link.components() {
        match comp {
            Component::Normal(c) => rel.push(c),
            // A leading `/` (or `./`) just means "from the archive root".
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => return Err(OciError::UnsafePath(link.display().to_string())),
        }
    }
    resolve_in_root(root, &rel)
}

/// Recursively remove a path (file, dir, or symlink) if it exists.
fn remove_path(path: &Path) -> Result<(), OciError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Empty a directory's contents (for an opaque whiteout), leaving the dir.
fn clear_dir(dir: &Path) -> Result<(), OciError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        remove_path(&entry?.path())?;
    }
    Ok(())
}

/// Apply one **gzip-compressed** OCI layer tarball onto `root`, in place,
/// honoring whiteouts:
/// - `.wh.<name>` deletes `<name>` from the same directory (the marker itself is
///   not materialized);
/// - `.wh..wh..opq` makes its directory opaque (clears lower-layer contents);
/// - every other entry is unpacked normally.
///
/// Layers must be applied in image order (lowest first).
///
/// The layer's **decompressed** size is bounded during inflation by the installed
/// [`RegistryPullLimits`] (`max_decompressed_layer_bytes`): a gzip zip-bomb (small compressed,
/// huge decompressed) is aborted the instant it exceeds the cap, so it is never fully inflated.
/// The same budget also charges the hard-link `fs::copy` fallback (invisible to the gunzip
/// stream), and the per-image `max_tar_entries` cap bounds an inode-exhaustion bomb. (The
/// whole-rootfs / whole-image running totals are threaded by [`apply_image_layers_in`] via
/// [`apply_layer_gz_bounded`]; a standalone call here bounds only this one layer.)
pub fn apply_layer_gz(root: &Path, reader: impl Read) -> Result<(), OciError> {
    let lim = registry_pull_limits();
    let rootfs_total = Cell::new(0u64);
    let entries_total = Cell::new(0u64);
    let budget = DecompBudget {
        layer_read: Cell::new(0),
        layer_cap: RegistryPullLimits::cap(lim.max_decompressed_layer_bytes),
        rootfs_total: &rootfs_total,
        rootfs_cap: RegistryPullLimits::cap(lim.max_rootfs_bytes),
        entries_total: &entries_total,
        entries_cap: RegistryPullLimits::cap(lim.max_tar_entries),
    };
    apply_layer_gz_bounded(root, reader, &budget)
}

/// The running decompressed-byte + tar-entry budget for one image's overlay, charged FAIL-CLOSED
/// by BOTH the gunzip [`DecompressionGuard`] (inflated bytes) and the tar extractor's hard-link
/// `fs::copy` fallback (bytes copied FROM DISK, invisible to the gunzip stream — a
/// copy-amplification bomb). `Cell` interior mutability because the guard is moved into the tar
/// archive while the extract loop charges copy-fallback bytes and counts entries against the
/// SAME counters. One budget is built per layer, so `layer_read` starts at 0 each time, while the
/// whole-rootfs / whole-image totals are owned by the caller and borrowed in, so their ceilings
/// span every layer.
struct DecompBudget<'a> {
    /// Decompressed + copy-fallback bytes charged so far in THIS layer (a fresh budget per layer).
    layer_read: Cell<u64>,
    /// Per-layer decompressed ceiling; `None` ⇒ disabled.
    layer_cap: Option<u64>,
    /// Running total of decompressed + copy-fallback bytes across ALL layers of this rootfs;
    /// threaded by the caller so the whole-rootfs ceiling spans the layers, not just one.
    rootfs_total: &'a Cell<u64>,
    /// Whole-rootfs decompressed ceiling; `None` ⇒ disabled.
    rootfs_cap: Option<u64>,
    /// Running count of tar entries unpacked across ALL layers of this image.
    entries_total: &'a Cell<u64>,
    /// Per-image tar-entry ceiling (`max_tar_entries`); `None` ⇒ disabled.
    entries_cap: Option<u64>,
}

impl DecompBudget<'_> {
    /// Charge `n` bytes against the per-layer AND whole-rootfs decompressed counters, erroring
    /// FAIL-CLOSED the instant either ceiling is crossed. Charges the inflated gunzip bytes (via
    /// [`DecompressionGuard`]) AND the hard-link `fs::copy` fallback's copied bytes (read from
    /// disk, never through the gunzip stream, so otherwise uncounted) against the same budget — so
    /// a copy-amplification disk-fill is bounded exactly like a decompressed-byte zip-bomb.
    fn charge(&self, n: u64) -> std::io::Result<()> {
        let layer = self.layer_read.get().saturating_add(n);
        self.layer_read.set(layer);
        let rootfs = self.rootfs_total.get().saturating_add(n);
        self.rootfs_total.set(rootfs);
        if let Some(cap) = self.layer_cap
            && layer > cap
        {
            return Err(std::io::Error::other(format!(
                "decompressed layer exceeded the {cap}-byte per-layer ceiling and was aborted \
                 (possible gzip zip-bomb or hard-link copy-amplification; refusing to fill the \
                 node disk)"
            )));
        }
        if let Some(cap) = self.rootfs_cap
            && rootfs > cap
        {
            return Err(std::io::Error::other(format!(
                "decompressed rootfs exceeded the {cap}-byte whole-rootfs ceiling across layers \
                 and was aborted (possible gzip zip-bomb or hard-link copy-amplification; refusing \
                 to fill the node disk)"
            )));
        }
        Ok(())
    }

    /// Count one tar entry against the per-image entry ceiling (`max_tar_entries`), erroring
    /// FAIL-CLOSED the instant it is crossed. Bounds an inode-exhaustion bomb — millions of tiny
    /// entries that each sit far under every BYTE ceiling yet together exhaust the staging
    /// filesystem's inodes. The running total spans ALL layers (whole image).
    fn count_entry(&self) -> std::io::Result<()> {
        let n = self.entries_total.get().saturating_add(1);
        self.entries_total.set(n);
        if let Some(cap) = self.entries_cap
            && n > cap
        {
            return Err(std::io::Error::other(format!(
                "image exceeded the {cap}-entry tar-entry ceiling and was aborted (possible \
                 inode-exhaustion bomb; refusing to exhaust the staging filesystem inodes)"
            )));
        }
        Ok(())
    }
}

/// A `Read` adapter wrapped around a layer's **decompressed** (gunzip output) stream that charges
/// each inflated chunk against the shared [`DecompBudget`], aborting FAIL-CLOSED the instant a
/// running total exceeds a ceiling. The tar extractor pulls bytes from this reader incrementally
/// as it unpacks each entry, so an over-cap read errors MID-INFLATION — the zip-bomb is never
/// fully expanded and the bytes that would cross the cap are never delivered to (written by) the
/// extractor, so disk usage stays bounded by the cap.
struct DecompressionGuard<'a, R: Read> {
    inner: R,
    /// Shared budget — also charged by the extractor's hard-link `fs::copy` fallback and its
    /// per-entry counter, so all three enforce the same per-layer / whole-rootfs / whole-image
    /// ceilings.
    budget: &'a DecompBudget<'a>,
}

impl<R: Read> Read for DecompressionGuard<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(0);
        }
        // Charge AFTER reading but BEFORE handing the bytes back: an over-cap read returns an
        // error and the just-read buffer is discarded (never written to disk), so the extractor
        // only ever persists bytes up to the cap.
        self.budget.charge(n as u64)?;
        Ok(n)
    }
}

/// As [`apply_layer_gz`] but with the shared [`DecompBudget`] (per-layer + whole-rootfs byte
/// ceilings and the whole-image entry ceiling, each running total threaded by the caller ACROSS
/// layers) passed in. The gunzip output is wrapped in a [`DecompressionGuard`] so the tar
/// extractor inflates through the bound — an over-cap layer aborts DURING decompression, never
/// after the whole bomb is expanded. The caller builds a fresh per-layer [`DecompBudget`] (so
/// `layer_read` starts at 0) whose whole-rootfs / whole-image running totals carry across layers.
fn apply_layer_gz_bounded(
    root: &Path,
    reader: impl Read,
    budget: &DecompBudget,
) -> Result<(), OciError> {
    let gz = flate2::read::GzDecoder::new(reader);
    let guarded = DecompressionGuard { inner: gz, budget };
    apply_layer_tar_bounded(root, guarded, budget)
}

/// As [`apply_layer_gz`] but over an already-decompressed tar stream (the testable core). Every
/// ceiling is disabled and no gunzip guard feeds the decompressed counters, so behavior matches a
/// plain extract; the production overlay instead runs through [`apply_layer_gz_bounded`], which
/// installs the real per-layer / whole-rootfs / whole-image budget.
pub fn apply_layer_tar(root: &Path, reader: impl Read) -> Result<(), OciError> {
    let rootfs_total = Cell::new(0u64);
    let entries_total = Cell::new(0u64);
    let budget = DecompBudget {
        layer_read: Cell::new(0),
        layer_cap: None,
        rootfs_total: &rootfs_total,
        rootfs_cap: None,
        entries_total: &entries_total,
        entries_cap: None,
    };
    apply_layer_tar_bounded(root, reader, &budget)
}

/// Should the hard-link step skip straight to the `fs::copy` fallback? Always `false` in
/// production (link first, copy only when linking can't); a `#[cfg(test)]` seam drives it so a
/// test can exercise the copy-amplification budget charge without fabricating a real
/// cross-`EXT4_LINK_MAX` (65 000 links/inode) ceiling.
#[cfg(not(test))]
#[inline]
fn force_copy_fallback() -> bool {
    false
}

#[cfg(test)]
thread_local! {
    static FORCE_COPY_FALLBACK: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
fn force_copy_fallback() -> bool {
    FORCE_COPY_FALLBACK.with(Cell::get)
}

/// The tar-extract core, bounded by the shared [`DecompBudget`]: counts every entry against the
/// whole-image entry ceiling and charges the hard-link `fs::copy` fallback's copied bytes against
/// the decompressed budget (the gunzip guard, wrapped around `reader` by the caller, charges the
/// inflated bytes). Whiteouts/symlinks/paths are handled exactly as before.
fn apply_layer_tar_bounded(
    root: &Path,
    reader: impl Read,
    budget: &DecompBudget,
) -> Result<(), OciError> {
    fs::create_dir_all(root)?;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);
    for entry in archive.entries()? {
        let mut entry = entry?;
        // Count EVERY entry pulled from the stream (files, dirs, symlinks, whiteouts) against the
        // whole-image ceiling BEFORE touching the filesystem — a flood of tiny entries is aborted
        // before it can exhaust the staging filesystem's inodes.
        budget.count_entry().map_err(OciError::Io)?;
        let raw = entry.path()?.into_owned();
        let rel = safe_relative(&raw)?;
        let Some(file_name) = rel.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue; // root entry (".") — nothing to do
        };
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));

        if file_name == ".wh..wh..opq" {
            // Clear the directory the marker sits in, resolved RESOLVE_IN_ROOT so a
            // planted symlink can only ever redirect the clear onto an in-root
            // directory, never a host one.
            let dir = resolve_in_root(root, parent)?;
            clear_dir(&dir)?;
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(".wh.") {
            // Resolve the parent RESOLVE_IN_ROOT, then remove the named leaf WITHOUT
            // following it (a symlinked whiteout parent is contained in-root; a
            // symlinked victim leaf is unlinked itself, not its target).
            let victim = resolve_parent_in_root(root, &parent.join(target_name))?;
            remove_path(&victim)?;
            continue;
        }

        // Resolve the destination's parent chain RESOLVE_IN_ROOT — a planted
        // symlink parent is followed only within `root`, so the write can never
        // land on the host; the leaf is returned un-dereferenced.
        let dest = resolve_parent_in_root(root, &rel)?;
        // Clear any existing leaf unless BOTH the old and new entries are
        // directories (a dir entry merges onto a lower-layer dir). This lets a
        // later layer replace an entry AND — critically — ensures we never write
        // a file THROUGH a leaf symlink planted by an earlier layer: we unlink the
        // symlink itself (never follow it) before `unpack`.
        if let Ok(meta) = fs::symlink_metadata(&dest) {
            let entry_is_dir = entry.header().entry_type().is_dir();
            let existing_is_dir = meta.file_type().is_dir();
            if !(existing_is_dir && entry_is_dir) {
                remove_path(&dest)?;
            }
        }
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }

        // Hard links (e.g. busybox's applets → `/bin/busybox`) reference another
        // member of this archive, so the target resolves **relative to the rootfs
        // root** ([`link_target_under_root`], which refuses a symlinked target);
        // the tar crate's per-entry `unpack` would resolve it relative to the
        // process CWD and fail. Link here (copy as a fallback if linking can't);
        // everything else (files, dirs, symlinks) goes through `unpack`, which
        // writes a symlink's target verbatim. The leaf was cleared above.
        if entry.header().entry_type() == tar::EntryType::Link {
            let link = entry
                .link_name()?
                .ok_or_else(|| OciError::Io(std::io::Error::other("hard link without target")))?;
            let target = link_target_under_root(root, &link)?;
            // A hard link shares the target's inode → NO new data bytes, so a successful link is
            // free and uncounted. When linking can't — cross-filesystem, or past ext4's
            // EXT4_LINK_MAX (65 000 links/inode) ceiling — we fall back to `fs::copy`, which reads
            // the target FROM DISK, not through the gunzip `DecompressionGuard`, so a Link entry
            // (zero data payload, ~0 decompressed bytes counted) would let N links → one file
            // write N fresh S-byte duplicates INVISIBLE to the decompressed budget. Charge the
            // copy's bytes against the SAME per-layer + whole-rootfs budget and abort fail-closed
            // BEFORE copying, so a copy-amplification disk-fill is bounded exactly like a zip-bomb.
            if force_copy_fallback() || fs::hard_link(&target, &dest).is_err() {
                let copied = fs::metadata(&target)?.len();
                budget.charge(copied).map_err(OciError::Io)?;
                fs::copy(&target, &dest)?;
            }
            continue;
        }
        entry.unpack(&dest)?;
    }
    Ok(())
}

/// Build an `ext4` image at `out` populated from the directory tree at `root`,
/// sized `size_mib` MiB, via `mke2fs -d` (no loopback mount / root needed). Host
/// seam: requires `e2fsprogs`.
pub fn build_ext4(root: &Path, out: &Path, size_mib: u64) -> Result<(), OciError> {
    let root = root
        .to_str()
        .ok_or_else(|| OciError::Mkfs("non-utf8 root".into()))?;
    let out = out
        .to_str()
        .ok_or_else(|| OciError::Mkfs("non-utf8 out".into()))?;
    let status = std::process::Command::new("mke2fs")
        .args(["-t", "ext4", "-F", "-d", root, out, &format!("{size_mib}m")])
        .status()
        .map_err(|e| OciError::Mkfs(format!("spawning mke2fs: {e}")))?;
    if !status.success() {
        return Err(OciError::Mkfs(format!("mke2fs exited with {status}")));
    }
    Ok(())
}

/// A parsed image reference: registry host, repository, and a tag-or-digest.
fn parse_reference(image: &str) -> (String, String, String) {
    // Split the tag/digest off the name.
    let (name, reference) = if let Some((n, d)) = image.split_once('@') {
        // A ref may carry BOTH a tag and a digest (`name:tag@digest`, e.g.
        // `pgvector/pgvector:pg16@sha256:…`). The digest is authoritative, so strip the
        // tag from the name — otherwise the `:tag` stays embedded in the repository path
        // and the manifest GET hits `/v2/<repo:tag>/manifests/<digest>` → 404. The tag is
        // a `:` in the FINAL path component (after the last `/`); a `:` earlier in `n` is a
        // registry `host:port` and must be preserved.
        let name = match n.rsplit_once('/') {
            Some((prefix, last)) => match last.split_once(':') {
                Some((repo_last, _tag)) => format!("{prefix}/{repo_last}"),
                None => n.to_string(),
            },
            None => match n.split_once(':') {
                Some((repo, _tag)) => repo.to_string(),
                None => n.to_string(),
            },
        };
        (name, d.to_string())
    } else if let Some((n, t)) = image.rsplit_once(':') {
        // A ':' after the last '/' is a tag (not a registry port).
        if t.contains('/') {
            (image.to_string(), "latest".to_string())
        } else {
            (n.to_string(), t.to_string())
        }
    } else {
        (image.to_string(), "latest".to_string())
    };
    // Split the registry host off the repository.
    let (registry, repo) = match name.split_once('/') {
        Some((host, rest)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            (host.to_string(), rest.to_string())
        }
        _ => ("registry-1.docker.io".to_string(), name),
    };
    // Docker Hub official single-name images live under `library/`.
    let repo = if registry == "registry-1.docker.io" && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo
    };
    (registry, repo, reference)
}

/// Manifest media types we request (OCI + Docker v2, single + index).
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.docker.distribution.manifest.list.v2+json";

/// Is `v4` a non-globally-routable IPv4 address (loopback, RFC-1918 private,
/// link-local incl. the `169.254.169.254` cloud-metadata endpoint, CGNAT, …)?
/// Such an address is refused as a pull target — the SSRF guard.
fn ipv4_is_disallowed(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast() // 224.0.0.0/4
        || o[0] == 0 // "this network" 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000) // 100.64.0.0/10 CGNAT
        || o[0] >= 240 // 240.0.0.0/4 reserved
}

/// Is `ip` a non-globally-routable address that must never be a pull target?
/// Blocks loopback, private, link-local (v4 `169.254/16`, v6 `fe80::/10`),
/// unique-local (`fc00::/7`), multicast (v4 `224/4` + v6), and — so an IPv4 target
/// can't hide inside an IPv6 transition form — the embedded IPv4 of v4-mapped,
/// v4-compatible, 6to4 and Teredo addresses ([`embedded_ipv4`]).
///
/// Note `to_canonical` collapses ONLY the v4-mapped form (`::ffff:a.b.c.d`) back
/// to IPv4; it does NOT touch v4-compatible (`::a.b.c.d`), 6to4 (`2002::/16`) or
/// Teredo (`2001:0000::/32`), so those are decoded explicitly here (otherwise
/// `::169.254.169.254` / `2002:a9fe:a9fe::` would dodge the screen). Closes SSRF to
/// cloud metadata (`169.254.169.254` and its IPv6-wrapped forms) and internal hosts.
fn ip_is_disallowed(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => ipv4_is_disallowed(v4),
        IpAddr::V6(v6) => {
            if embedded_ipv4(v6).is_some_and(ipv4_is_disallowed) {
                return true;
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Extract the IPv4 address embedded in an IPv6 **transition form** that
/// `Ipv6Addr::to_canonical` does NOT unwrap, so it can be run through the IPv4
/// screen: v4-compatible (`::a.b.c.d`, high 96 bits zero — excluding `::`/`::1`),
/// 6to4 (`2002:ABCD:EFGH::/16`, embedded v4 in bits 16..48), and Teredo
/// (`2001:0000::/32`, client v4 in the last 32 bits, XOR-obfuscated). Returns
/// `None` for an ordinary IPv6 address (incl. v4-mapped, which `to_canonical`
/// already handled before this is reached).
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let o = v6.octets();
    // v4-compatible `::a.b.c.d` (deprecated): first 96 bits zero. Exclude `::`/`::1`.
    if s[..6] == [0, 0, 0, 0, 0, 0] && !(s[6] == 0 && (s[7] == 0 || s[7] == 1)) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 6to4 `2002::/16`: the embedded IPv4 is bits 16..48.
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    // Teredo `2001:0000::/32`: the client IPv4 is the last 32 bits, obfuscated by
    // a bitwise-NOT (XOR `0xff` per octet).
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return Some(Ipv4Addr::new(
            o[12] ^ 0xff,
            o[13] ^ 0xff,
            o[14] ^ 0xff,
            o[15] ^ 0xff,
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// U25: operator allow-list opt-in for private/internal registries
// ---------------------------------------------------------------------------
//
// The SSRF screen above (v0.66.1) blocks EVERY non-globally-routable pull target with no
// override, so an operator's in-house registry on a private network (RFC-1918/ULA/CGNAT)
// cannot be used. This adds a TYPED, EXPLICIT operator opt-in — a host/CIDR allow-list,
// `[compute].allow_private_registries`, installed node-side at serve wiring — that permits
// NAMED private registries while keeping the screen **block-by-default** (unset ⇒ every
// non-global address refused, exactly as before) and keeping cloud-metadata endpoints
// ALWAYS blocked even if a broad CIDR is allowed.
//
// SECURITY (the loosened control — scrutinize here):
//   * This LOOSENS an SSRF control. The allow-list is OPERATOR config (node-side, never
//     guest-influenced — mirrors `[compute].registry_auth`); a tenant's image reference can
//     only ever reach a private address the OPERATOR explicitly allow-listed.
//   * The pull-target host comes from the (tenant-controlled) image reference, so a CIDR
//     allow-list is COARSE: ANY name a tenant puts in an image ref that resolves into the
//     allowed CIDR becomes reachable — SSRF to any host in that range, not just the
//     registry. Prefer an exact `hosts` entry, or the narrowest CIDR. A `hosts` entry is
//     precise (that one name only); it still cannot reach metadata.
//   * Cloud instance-metadata endpoints (169.254.169.254 & the whole IPv4/IPv6 link-local
//     range, Alibaba 100.100.100.200, AWS IMDSv6 fd00:ec2::254) are refused BEFORE the
//     allow-list is consulted — no allow-list entry, however broad, can exempt them.
//   * The DNS-rebinding pin is preserved: the same `ScreeningResolver` lookup that screens
//     an address is the one reqwest connects to; allowing a CIDR only widens which screened
//     addresses pass, it does not reopen the rebinding window.
//   * Fail-closed: a malformed CIDR at install is a hard error; the global then stays at its
//     empty (block-all) default rather than a partial allow-list.

/// Operator opt-in permitting image pulls from registries on otherwise-SSRF-blocked
/// private/non-global networks — the value of `[compute].allow_private_registries`. Node
/// operator config (System·Admin), NEVER guest-influenced; mirrors the shape conventions of
/// `[compute].registry_auth`. Empty (the default) ⇒ the screen stays fully block-by-default.
///
/// This is the raw, serde form (operators write strings); it is compiled + validated into
/// the internal screen form at [`install_private_registry_allowlist`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateRegistryAllowlist {
    /// Exact registry **hostnames** (case-insensitive; host only, no `:port`) that MAY be
    /// pulled from even when they resolve to a non-global address — the PRECISE opt-in (that
    /// one name only; it still cannot reach a cloud-metadata endpoint). e.g.
    /// `"registry.internal"`.
    pub hosts: Vec<String>,
    /// Private/non-global **CIDRs** (`"10.0.0.0/8"`, `"192.168.0.0/16"`, `"fd00::/8"`, …) any
    /// pull-target address inside which MAY be pulled from — the COARSE opt-in (any name
    /// resolving into the range is reachable; cloud-metadata stays blocked). Parsed as
    /// `ipnet::IpNet`; a malformed entry fails config load closed.
    pub cidrs: Vec<String>,
}

/// The compiled, validated allow-list the screen consults (hostnames lowercased, CIDRs
/// parsed). Built from a [`PrivateRegistryAllowlist`] at install; never guest-influenced.
#[derive(Debug, Clone, Default)]
struct CompiledAllowlist {
    hosts: BTreeSet<String>,
    cidrs: Vec<IpNet>,
}

impl CompiledAllowlist {
    /// The empty (block-all) default — a `const fn` so it can seed the process-global static.
    const fn empty() -> Self {
        Self {
            hosts: BTreeSet::new(),
            cidrs: Vec::new(),
        }
    }

    /// Compile + validate a raw [`PrivateRegistryAllowlist`]. A malformed CIDR is an error
    /// (fail closed — the caller keeps the block-all default rather than a partial list).
    fn compile(cfg: &PrivateRegistryAllowlist) -> Result<Self, OciError> {
        let hosts = cfg
            .hosts
            .iter()
            .map(|h| {
                h.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_ascii_lowercase()
            })
            .filter(|h| !h.is_empty())
            .collect();
        let mut cidrs = Vec::with_capacity(cfg.cidrs.len());
        for raw in &cfg.cidrs {
            let net: IpNet = raw.trim().parse().map_err(|_| {
                OciError::Registry(format!(
                    "[compute].allow_private_registries: {raw:?} is not a valid CIDR"
                ))
            })?;
            cidrs.push(net);
        }
        Ok(Self { hosts, cidrs })
    }

    /// Does this allow-list permit a pull to `host` (the pull-target host — `None` for a
    /// literal-IP target) resolving to `ip`? An exact host-name match OR a CIDR containing
    /// `ip` permits. Does NOT consider cloud-metadata — that absolute deny is applied by
    /// [`address_is_refused_with`] BEFORE this is consulted.
    fn permits(&self, host: Option<&str>, ip: IpAddr) -> bool {
        if let Some(h) = host {
            let h = h
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase();
            if self.hosts.contains(&h) {
                return true;
            }
        }
        self.cidrs.iter().any(|c| c.contains(&ip))
    }
}

/// The process-global operator allow-list the OCI pull screen consults. Installed ONCE at
/// node serve wiring from `[compute].allow_private_registries`
/// ([`install_private_registry_allowlist`]); default = empty (block every non-global
/// address — the fail-closed posture, identical to pre-v0.69 behavior). Node operator
/// config, never guest-influenced. Read (not threaded) by the screen so the many pull
/// entry points + callers need no signature change.
static PRIVATE_REGISTRY_ALLOWLIST: RwLock<CompiledAllowlist> =
    RwLock::new(CompiledAllowlist::empty());

/// Install the operator's private-registry allow-list (U25) into the process-global SSRF
/// screen. Called at node serve wiring BEFORE any backend can pull. Returns an error (and
/// leaves the global at its block-all default — fail closed) when a configured CIDR is
/// malformed. Idempotent: a later call replaces the installed list (config reload).
pub fn install_private_registry_allowlist(cfg: &PrivateRegistryAllowlist) -> Result<(), OciError> {
    let compiled = CompiledAllowlist::compile(cfg)?;
    // Poison-tolerant (INFO-2): a panic elsewhere while the lock was held must not wedge the
    // screen — recover the guard and install over it. The data is a plain config snapshot.
    *PRIVATE_REGISTRY_ALLOWLIST
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = compiled;
    Ok(())
}

/// An IPv4 cloud-provider instance-metadata endpoint — refused regardless of the allow-list.
/// The whole link-local `/16` (never a legitimate registry) plus Alibaba Cloud's
/// `100.100.100.200` (which lives inside CGNAT `100.64/10`, so a CGNAT allow-list must not
/// reach it).
fn is_metadata_v4(v4: Ipv4Addr) -> bool {
    v4.is_link_local() || v4 == Ipv4Addr::new(100, 100, 100, 200)
}

/// Is `ip` a cloud instance-metadata endpoint that MUST remain unreachable even when an
/// operator allow-lists a CIDR that would contain it? Decodes IPv6 transition forms (so a
/// wrapped `169.254.169.254` cannot dodge the deny) and blocks the IPv6 link-local range +
/// AWS IMDSv6 (`fd00:ec2::254`). Checked BEFORE the allow-list; no entry can exempt these.
fn is_cloud_metadata(ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip
        && embedded_ipv4(v6).is_some_and(is_metadata_v4)
    {
        return true;
    }
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_metadata_v4(v4),
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254) // AWS IMDSv6
        }
    }
}

/// The pull-screen decision against a given `allow`-list (pure; the global-reading wrapper
/// is [`address_is_refused`]). Block-by-default: refuse `ip` (reached via pull-target `host`,
/// `None` for a literal-IP target) when it is a cloud-metadata endpoint (ALWAYS), else when
/// it is non-global AND the operator allow-list does not permit it.
fn address_is_refused_with(host: Option<&str>, ip: IpAddr, allow: &CompiledAllowlist) -> bool {
    if is_cloud_metadata(ip) {
        return true; // metadata: always refused, no allow-list can exempt it
    }
    if !ip_is_disallowed(ip) {
        return false; // globally routable → fine
    }
    !allow.permits(host, ip) // non-global → only if the operator allow-listed it
}

/// [`address_is_refused_with`] against the installed process-global allow-list (default
/// block-all). The seam every screen site calls, so adding the allow-list needed no change
/// to the pull entry points or their callers.
fn address_is_refused(host: Option<&str>, ip: IpAddr) -> bool {
    // Poison-tolerant (INFO-2): a startup/write panic must never wedge the screen into
    // unavailability — recover the guard and read the last-good snapshot (default = block-all).
    let allow = PRIVATE_REGISTRY_ALLOWLIST
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    address_is_refused_with(host, ip, &allow)
}

/// Split a URL authority (`host`, `host:port`, or `[v6]:port`) into host + port,
/// defaulting to 443. No DNS; purely lexical.
fn split_host_port(authority: &str) -> Result<(String, u16), OciError> {
    if authority.is_empty() {
        return Err(OciError::Registry("empty host in pull target".into()));
    }
    let bad_port = |a: &str| OciError::Registry(format!("bad port in pull target {a}"));
    if let Some(rest) = authority.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port`.
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| OciError::Registry(format!("malformed IPv6 authority {authority}")))?;
        let port = if after.is_empty() {
            443
        } else if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| bad_port(authority))?
        } else {
            return Err(OciError::Registry(format!(
                "malformed IPv6 authority {authority}"
            )));
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((
            h.to_string(),
            p.parse::<u16>().map_err(|_| bad_port(authority))?,
        )),
        None => Ok((authority.to_string(), 443)),
    }
}

/// Validate a `WWW-Authenticate` realm URL as a safe pull target: it MUST be
/// `https://` (no `http://`, no other scheme — a tenant image's 401 realm is
/// attacker-controlled), returning its (host, port). Lexical only; the IP screen of the
/// realm host is [`screen_pull_url`] (normalized literal) + [`ScreeningResolver`] (hostname).
fn parse_realm(realm: &str) -> Result<(String, u16), OciError> {
    let rest = realm
        .strip_prefix("https://")
        .ok_or_else(|| OciError::Registry(format!("auth realm must be https, refusing {realm}")))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip any `userinfo@`.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    split_host_port(authority)
}

/// Screen an already-parsed pull-target URL's host against the SSRF decision, using the
/// **WHATWG-normalized** host (`Url::host_str`) — the form reqwest will actually resolve +
/// connect to. This closes a parser-differential bypass (Security HIGH): Rust's strict
/// `str::parse::<IpAddr>()` REJECTS non-canonical IPv4 literals (`0xa9fea9fe`, decimal
/// `2852039166`, octal `0251.0376.0251.0376`, short/overflow forms), but the WHATWG URL
/// parser DECODES them to a real address and connects straight to it — for an IP-literal
/// host reqwest never calls [`ScreeningResolver`], so a lexical screen of the raw string
/// would miss it entirely and defeat the metadata-block guarantee. `host_str()` has already
/// normalized the literal to canonical dotted-decimal / bracketed v6, so a literal IP is run
/// through [`address_is_refused`] (metadata un-exemptable; the operator allow-list honored via
/// the decoded IP). A domain host is left to [`ScreeningResolver`] at connect, exactly as
/// before. A URL with no host is refused (fail closed).
fn screen_url_host(url: &reqwest::Url) -> Result<(), OciError> {
    let host = url
        .host_str()
        .ok_or_else(|| OciError::Registry(format!("refusing pull URL with no host: {url}")))?;
    // `host_str()` brackets an IPv6 literal (`[::1]`); strip for the IP parse.
    let stripped = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = stripped.parse::<IpAddr>()
        && address_is_refused(Some(stripped), ip)
    {
        return Err(OciError::Registry(format!(
            "refusing to pull from non-global address {ip} (not on the \
             `[compute].allow_private_registries` operator allow-list)"
        )));
    }
    Ok(())
}

/// Parse a pull-target URL the SAME way the connection will (WHATWG via `url`/reqwest) and
/// screen its normalized host ([`screen_url_host`]). The initial-request screen for the
/// registry base + the `WWW-Authenticate` realm — both are IP-literal-bypass surfaces because
/// reqwest connects to a literal-IP host without consulting [`ScreeningResolver`]. Fail-CLOSED
/// on an unparseable URL (an ambiguous/overflowing host literal is refused, never chased).
fn screen_pull_url(url: &str) -> Result<(), OciError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| OciError::Registry(format!("refusing unparseable pull URL {url}: {e}")))?;
    screen_url_host(&parsed)
}

/// A reqwest DNS resolver that screens EVERY resolved address against
/// [`ip_is_disallowed`] — the SSRF block applied at resolution, for the initial
/// request AND for every redirect hop, so the screen and the actual connect share
/// ONE lookup (closing the DNS-rebinding window). getaddrinfo runs on the
/// runtime's blocking pool (`tokio::net::lookup_host`), so it never stalls the
/// async reactor.
#[derive(Debug, Clone, Copy)]
struct ScreeningResolver;

impl reqwest::dns::Resolve for ScreeningResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Port is irrelevant to IP screening; reqwest overrides it on connect.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            if addrs.is_empty() {
                return Err(format!("no address resolved for {host}").into());
            }
            for sa in &addrs {
                // Screen the resolved address against the SSRF block-list, consulting the
                // operator allow-list (U25) by the HOSTNAME being resolved — so an exact
                // `hosts` entry permits this name, a CIDR entry permits the address, and a
                // cloud-metadata endpoint is refused regardless.
                if address_is_refused(Some(&host), sa.ip()) {
                    // Typed (U31) so the actionable message — the refused host + the
                    // `[compute].allow_private_registries` hint — survives reqwest's error
                    // wrapping and reaches the operator, instead of being flattened to a
                    // generic "error sending request for url …". Recovered by `reqwest_err`.
                    //
                    // SECURITY: this message is persisted into a replica's `LaunchFailed`
                    // reason and surfaced to the TENANT (`compute status`). The tenant supplied
                    // the HOST, so naming it discloses nothing new — but the NODE-resolved IP
                    // would, so it is deliberately OMITTED here (unlike the literal-IP screen,
                    // whose address the tenant typed). This denies a tenant an internal
                    // DNS→IP reconnaissance oracle while still pointing the operator at the
                    // allow-list. The connect is refused regardless of what is logged.
                    return Err(Box::new(ScreenRefusal(format!(
                        "refusing to connect to {host}: it resolves to a non-global \
                         (private/internal) address not on the \
                         `[compute].allow_private_registries` operator allow-list"
                    )))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

// ---------------------------------------------------------------------------
// U30: bound the OCI registry pull with timeouts
// ---------------------------------------------------------------------------
//
// The pull client previously had NO connect/read/overall timeout, so a registry that
// accepts the TCP connection and then never answers held the pull FOREVER — and for an
// embedder awaiting several launches together, one such image stalled everything behind it.
// These bounds make a dead/stalling registry fail the pull in bounded time with a clear
// error. Operator-tunable (`[compute].registry_pull_timeouts`), NEVER guest-influenced —
// the values come from node config only, mirroring `[compute].allow_private_registries`.
//
// Design (four time knobs + two byte ceilings, layered so a legitimate large/slow pull always
// completes while a malicious registry cannot stall the node or exhaust its memory):
//   * `connect_secs` bounds the TCP+TLS handshake (a registry that never completes connect).
//   * `read_secs` is the IDLE/read timeout — the max gap with NO bytes flowing on a response
//     before the pull fails. This is what catches "accepts the connection and never answers"
//     (connect succeeds, then silence). Because reqwest's read timeout resets on every chunk,
//     it bounds a STALL without capping a legitimately large-but-progressing blob download.
//   * `response_secs` is an overall per-request cap applied ONLY to the small control-plane
//     requests (token exchange + manifest GET), whose bodies are tiny. It is deliberately NOT
//     applied to a blob GET, so a genuinely large/slow layer stream is bounded by the idle
//     `read_secs` alone and is never severed mid-request-progress.
//   * `overall_pull_secs` (Security HIGH follow-up) is an overall WALL-CLOCK deadline spanning
//     the WHOLE image pull (manifest + config + every layer). The per-chunk idle `read_secs`
//     resets on each byte, so a registry trickling one byte just under that gap forever keeps a
//     blob — and thus the SERIAL reconcile loop that awaits the pull — open indefinitely
//     (a tenant-triggerable cross-tenant DoS: the image ref picks the registry host). This
//     deadline bounds that slow-drip; it is generous (a multi-GB pull over a slow link still
//     finishes) because the idle + byte bounds already catch the common cases.
//
// Byte ceilings ([`RegistryPullLimits`], enforced DURING the read, never after — so an oversize
// body is aborted mid-stream, never buffered whole):
//   * each LAYER blob is capped at `min(its manifest-declared size, max_layer_bytes)` — a layer
//     that streams past its own declared size is malformed and aborted; the operator ceiling
//     backstops a registry that declares (or omits) an implausible size.
//   * `max_image_bytes` caps the running total across all layers (the whole image).
//   * each MANIFEST/CONFIG read ([`manifest_cap`]) is capped by the much tighter `max_manifest_bytes`
//     (default 32 MiB), not the generous layer ceiling: these are KB-scale JSON documents held in
//     MEMORY, and a manifest declares no size of its own, so without this they would be bounded only
//     by `max_layer_bytes` (10 GiB).
// Layers are STREAMED to a temp file as they download (and the tarball dropped right after it is
// overlaid), so node memory stays O(one chunk) instead of buffering every layer in a `Vec<Vec<u8>>`.
//
// DECOMPRESSED ceilings ([`DecompressionGuard`], enforced DURING inflation) — the compressed caps
// above bound the DOWNLOAD, not how large a layer inflates to. gzip is unbounded-ratio, so a layer
// well under `max_layer_bytes` compressed can expand to terabytes (a zip-bomb) and fill the disk.
// The overlay bounds the running DECOMPRESSED byte count as each layer inflates to disk and aborts
// the instant it exceeds a ceiling (the over-cap bytes are never written), per layer
// (`max_decompressed_layer_bytes`) and across the whole rootfs (`max_rootfs_bytes`, running total
// over all layers) — so a bomb is aborted mid-inflation, never fully expanded.
//
// The SAME decompressed budget also charges the hard-link `fs::copy` fallback (a Link entry has no
// data payload, so the gunzip guard counts ~0 bytes for it, but once the ext4 EXT4_LINK_MAX link
// ceiling is hit each further link is copied — reading the target FROM DISK, invisible to the
// gunzip stream): N links → one file would otherwise write unbounded duplicates. ENTRY-COUNT
// ceiling (`max_tar_entries`) — the byte caps bound size but not entry count, so a tar of millions
// of tiny entries exhausts the staging filesystem's inodes; the overlay counts every entry across
// all layers and aborts fail-closed past the cap.

/// Default connect (TCP + TLS handshake) timeout for a registry pull, seconds.
const DEFAULT_PULL_CONNECT_SECS: u64 = 10;
/// Default read/idle timeout, seconds — the max no-bytes-flowing gap on a registry response
/// before the pull fails. Resets per chunk, so it bounds a stall (incl. "accepts then never
/// answers") WITHOUT capping a legitimately large blob stream.
const DEFAULT_PULL_READ_SECS: u64 = 30;
/// Default overall per-request cap, seconds, for the SMALL token + manifest requests only
/// (never the blob stream). Keeps a never-answering control request from stalling the pull
/// even past the idle budget, while leaving large blob downloads to `DEFAULT_PULL_READ_SECS`.
const DEFAULT_PULL_RESPONSE_SECS: u64 = 120;
/// Default overall WALL-CLOCK deadline, seconds, for the WHOLE image pull (manifest + config +
/// every layer). The idle `read_secs` resets per chunk and so does NOT bound a slow-drip
/// (one byte just under the idle gap forever), which would hold a blob — and the serial reconcile
/// loop awaiting it — open indefinitely (tenant-triggerable cross-tenant DoS). `600` (10 min) is
/// generous: a ~2 GiB compressed image over a 30 Mbit/s link is ≈ 9 min of transfer, so a real
/// large/slow pull completes, while an otherwise-unbounded drip is cut off. `0` disables.
const DEFAULT_PULL_OVERALL_SECS: u64 = 600;
/// Default per-blob byte ceiling (operator backstop). A well-formed registry declares each
/// layer's compressed `size` in the manifest, which is the tight per-blob cap; this ceiling
/// backstops a registry that declares an implausible size or omits it. 10 GiB is far above any
/// real single compressed layer. `0` ⇒ no operator per-blob ceiling (the declared size still
/// caps each blob).
const DEFAULT_PULL_MAX_LAYER_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Default whole-image byte ceiling: the running total across ALL layers. Backstops a many-layer
/// image whose individual layers each sit under the per-blob cap. 20 GiB is above any realistic
/// compressed image. `0` ⇒ no whole-image ceiling.
const DEFAULT_PULL_MAX_IMAGE_BYTES: u64 = 20 * 1024 * 1024 * 1024;
/// Default byte ceiling for a MANIFEST or CONFIG read — both small JSON documents buffered in
/// MEMORY (not streamed to disk like a layer). A manifest declares no `size` of its own, so
/// without a dedicated ceiling it is bounded only by the generous per-layer `max_layer_bytes`
/// (10 GiB) — far too loose for a KB-scale document. 32 MiB is generous (no real manifest/config
/// — a fat multi-arch index, an attestation/SBOM manifest, a config with a long `history` — comes
/// anywhere near it) yet ~320× tighter than the layer ceiling. `0` ⇒ no manifest/config ceiling
/// (the config's own declared size still caps it; a size-undeclared manifest is then bounded only
/// by the pull timeouts/deadline).
const DEFAULT_PULL_MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
/// Default per-layer DECOMPRESSED byte ceiling. The compressed per-layer/per-image ceilings bound
/// what a layer *downloads*, NOT what it *inflates* to: gzip is unbounded-ratio, so a layer well
/// under `max_layer_bytes` compressed can expand to terabytes (a zip-bomb) and fill the node disk.
/// This caps the bytes a single layer may inflate to during overlay, enforced DURING decompression.
/// 32 GiB is far above any real single decompressed layer (even a CUDA/ML or full-desktop layer
/// stays in the low tens of GiB) yet aborts a bomb long before it exhausts disk. It is comfortably
/// above the 10 GiB compressed per-layer ceiling, leaving headroom for a maximally-sized real
/// layer's normal ~2–4× (and even ~10×) expansion. `0` ⇒ no per-layer decompressed ceiling.
const DEFAULT_PULL_MAX_DECOMPRESSED_LAYER_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Default whole-rootfs DECOMPRESSED byte ceiling: the running total across ALL layers as they
/// inflate onto the rootfs. Backstops a many-layer image whose layers each sit under the per-layer
/// decompressed cap but together inflate to fill the disk. 64 GiB is above any realistic
/// decompressed rootfs (a real rootfs is typically well under a few GiB; the largest legitimate
/// images stay in the low tens of GiB) and above what even a maximally-sized compressed image at
/// the 20 GiB `max_image_bytes` ceiling could inflate to, while still aborting a bomb that would
/// expand to hundreds of GiB or more. `0` ⇒ no whole-rootfs decompressed ceiling.
const DEFAULT_PULL_MAX_ROOTFS_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Default per-image TAR-ENTRY ceiling: the running count of tar entries (files, dirs, symlinks,
/// hard links, whiteouts) unpacked across ALL layers. The byte ceilings above bound how much a
/// layer downloads/inflates, but NOT how many entries it carries: a tar of millions of tiny
/// (even empty) entries sits far under every byte cap yet creates one inode per entry, exhausting
/// the staging filesystem's inodes — a disk-fill the byte caps miss (an inode-exhaustion bomb; the
/// sibling of the hard-link copy-amplification one). 500 000 is well above any real image (a large
/// image — a full OS with every locale, a TeX distribution, a node_modules-heavy build — runs to
/// tens, at most low hundreds of thousands of entries across all its layers) yet aborts a bomb
/// long before it exhausts a node disk's inodes (a 100 GB ext4 at the default ~16 KiB/inode holds
/// ~6M). `0` ⇒ no per-image entry ceiling.
const DEFAULT_PULL_MAX_TAR_ENTRIES: u64 = 500_000;

/// Operator-tunable timeouts bounding a registry pull (U30) — the value of
/// `[compute].registry_pull_timeouts`. Node operator config (System·Admin), NEVER
/// guest-influenced; mirrors the wiring of `[compute].allow_private_registries`. A
/// dead/stalling registry fails the pull in bounded time instead of hanging forever. Each
/// field is in **seconds**; `0` disables that particular bound (an explicit operator opt-out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryPullTimeouts {
    /// Connect (TCP + TLS handshake) timeout, seconds. `0` ⇒ no connect bound. Default 10.
    pub connect_secs: u64,
    /// Read/idle timeout, seconds — the max no-bytes-flowing gap on a response before the pull
    /// fails. Resets per chunk, so it bounds a stall without capping a legitimately large blob.
    /// `0` ⇒ no idle bound. Default 30.
    pub read_secs: u64,
    /// Overall cap, seconds, for the SMALL token + manifest requests only (NEVER the blob
    /// stream, which is bounded by `read_secs`). `0` ⇒ no overall cap. Default 120.
    pub response_secs: u64,
    /// Overall WALL-CLOCK deadline, seconds, for the WHOLE image pull (manifest + config +
    /// every layer) — distinct from `response_secs` (per small control-plane request) and
    /// `read_secs` (per-chunk idle). Bounds a registry that drip-feeds bytes just under the
    /// idle gap forever, which would otherwise hold the pull — and the serial reconcile loop
    /// awaiting it — open indefinitely. Generous so a legitimately large/slow pull completes.
    /// `0` ⇒ no overall deadline. Default 600 (10 min).
    pub overall_pull_secs: u64,
}

impl RegistryPullTimeouts {
    /// The default bounds, as a `const` so it can seed the process-global static (where
    /// `Default::default()` is not callable).
    const DEFAULT: Self = Self {
        connect_secs: DEFAULT_PULL_CONNECT_SECS,
        read_secs: DEFAULT_PULL_READ_SECS,
        response_secs: DEFAULT_PULL_RESPONSE_SECS,
        overall_pull_secs: DEFAULT_PULL_OVERALL_SECS,
    };

    /// `d` seconds as a `Duration`, or `None` when `d == 0` (bound disabled).
    fn dur(d: u64) -> Option<Duration> {
        (d > 0).then(|| Duration::from_secs(d))
    }
}

impl Default for RegistryPullTimeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The process-global registry-pull timeouts the OCI client builder consults. Installed ONCE
/// at node serve wiring from `[compute].registry_pull_timeouts`
/// ([`install_registry_pull_timeouts`]); default = the built-in bounds above. Node operator
/// config, never guest-influenced. Read (not threaded) by the client builder so the many pull
/// entry points + callers need no signature change (mirrors the allow-list global).
static REGISTRY_PULL_TIMEOUTS: RwLock<RegistryPullTimeouts> =
    RwLock::new(RegistryPullTimeouts::DEFAULT);

/// Install the operator's registry-pull timeouts (U30) into the process-global the OCI pull
/// client reads. Called at node serve wiring; idempotent (a later call replaces the installed
/// values — config reload). Infallible: every field is a plain duration-in-seconds (`0`
/// disables a bound), so there is nothing to reject.
pub fn install_registry_pull_timeouts(cfg: RegistryPullTimeouts) {
    // Poison-tolerant: a panic elsewhere while the lock was held must not wedge the pull —
    // recover the guard and install over it. The data is a plain config snapshot.
    *REGISTRY_PULL_TIMEOUTS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = cfg;
}

/// Snapshot the installed [`RegistryPullTimeouts`] (default when unset).
fn registry_pull_timeouts() -> RegistryPullTimeouts {
    *REGISTRY_PULL_TIMEOUTS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The overall per-request cap for the SMALL control-plane requests (token exchange + manifest
/// GET), from the installed timeouts. `None` ⇒ no cap. Deliberately NOT used for a blob GET,
/// whose legitimately-large body is bounded by the idle read timeout + the byte ceiling
/// ([`blob_cap`]) + the whole-pull deadline ([`overall_pull_timeout`]) instead of a hard
/// per-request cap, so a slow-but-progressing layer is never severed mid-request.
fn small_request_overall_timeout() -> Option<Duration> {
    RegistryPullTimeouts::dur(registry_pull_timeouts().response_secs)
}

/// The overall WALL-CLOCK deadline for the WHOLE image pull (manifest + config + every layer),
/// from the installed timeouts. `None` ⇒ no deadline. Applied by [`with_pull_deadline`] around
/// the whole pull so a registry drip-feeding bytes under the idle timeout cannot hold the pull —
/// and the serial reconcile loop awaiting it — open indefinitely (Security HIGH: cross-tenant
/// DoS). Distinct from the per-request `response_secs` and the per-chunk idle `read_secs`.
fn overall_pull_timeout() -> Option<Duration> {
    RegistryPullTimeouts::dur(registry_pull_timeouts().overall_pull_secs)
}

/// Run a network-bound pull future under the operator's overall per-pull wall-clock deadline
/// ([`overall_pull_timeout`]). On timeout the future is dropped (cancelling the in-flight
/// request) and a typed registry error is returned, so a slow-drip registry cannot hold the
/// serial reconcile loop open past the budget. `None` deadline ⇒ the future runs unbounded
/// (operator opt-out).
async fn with_pull_deadline<F, T>(fut: F) -> Result<T, OciError>
where
    F: std::future::Future<Output = Result<T, OciError>>,
{
    match overall_pull_timeout() {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(result) => result,
            Err(_) => Err(OciError::Registry(format!(
                "image pull exceeded the overall {}s wall-clock deadline and was aborted \
                 (a registry drip-feeding bytes under the idle timeout cannot hold the pull open)",
                d.as_secs()
            ))),
        },
        None => fut.await,
    }
}

/// Operator-tunable BYTE ceilings bounding a registry pull (Security HIGH follow-up to U30) —
/// the value of `[compute].registry_pull_limits`. Node operator config (System·Admin), NEVER
/// guest-influenced; mirrors the wiring of [`RegistryPullTimeouts`]. Each blob is also capped at
/// its manifest-declared size; these are the operator backstops, enforced DURING the download
/// (an oversize body is aborted mid-stream, never buffered whole → no OOM). Two further ceilings
/// bound the OVERLAY (not the download): the decompressed-byte caps (a gzip zip-bomb / hard-link
/// copy-amplification disk-fill) and `max_tar_entries` (an inode-exhaustion bomb). Each field is a
/// **byte** count except `max_tar_entries` (an **entry** count); `0` disables that ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryPullLimits {
    /// Per-blob ceiling, bytes — the max any single layer/config blob may download. A blob that
    /// streams past `min(this, its declared size)` is aborted mid-download. `0` ⇒ no operator
    /// per-blob ceiling (the manifest-declared size still caps each blob). Default 10 GiB.
    pub max_layer_bytes: u64,
    /// Whole-image ceiling, bytes — the max running total across ALL layers. Aborts a
    /// many-layer image that would exceed it even though each layer is individually under the
    /// per-blob cap. `0` ⇒ no whole-image ceiling. Default 20 GiB.
    pub max_image_bytes: u64,
    /// Manifest/config ceiling, bytes — the max a single MANIFEST or CONFIG read may download.
    /// Unlike a layer these are small JSON documents buffered in MEMORY, so this is a far tighter
    /// cap than `max_layer_bytes`: a manifest declares no `size`, so without it the manifest read
    /// is bounded only by the generous 10 GiB layer ceiling. A read past `min(this, the config's
    /// declared size)` is aborted mid-download. `0` ⇒ no manifest/config ceiling (the config's
    /// declared size still caps it; a size-undeclared manifest is then bounded only by the pull
    /// timeouts/deadline). Default 32 MiB.
    pub max_manifest_bytes: u64,
    /// Per-layer DECOMPRESSED ceiling, bytes — the max a single layer may inflate to as it is
    /// overlaid onto the rootfs. The compressed caps above bound the DOWNLOAD; gzip is
    /// unbounded-ratio, so a layer under `max_layer_bytes` compressed can still inflate to
    /// terabytes (a zip-bomb) and fill the node disk. Enforced DURING decompression — the overlay
    /// is aborted the instant a layer's running decompressed byte count exceeds this — so the bomb
    /// is never fully inflated. `0` ⇒ no per-layer decompressed ceiling. Default 32 GiB.
    pub max_decompressed_layer_bytes: u64,
    /// Whole-rootfs DECOMPRESSED ceiling, bytes — the max running total of decompressed bytes
    /// across ALL layers as they inflate onto the rootfs. Backstops a many-layer image whose
    /// layers each sit under `max_decompressed_layer_bytes` but together inflate to fill the disk.
    /// Enforced DURING decompression, same as the per-layer cap. `0` ⇒ no whole-rootfs
    /// decompressed ceiling. Default 64 GiB.
    pub max_rootfs_bytes: u64,
    /// Per-image TAR-ENTRY ceiling — the max number of tar entries (files, dirs, symlinks, hard
    /// links, whiteouts) unpacked across ALL layers. The byte ceilings bound download/inflation
    /// size but NOT entry count: a tar of millions of tiny entries sits under every byte cap yet
    /// creates one inode each, exhausting the staging filesystem's inodes (an inode-exhaustion
    /// bomb). Aborted FAIL-CLOSED the instant the running count exceeds this. `0` ⇒ no entry
    /// ceiling. Default 500 000 (generous — far above any real image).
    pub max_tar_entries: u64,
}

impl RegistryPullLimits {
    /// The default ceilings, as a `const` so it can seed the process-global static.
    const DEFAULT: Self = Self {
        max_layer_bytes: DEFAULT_PULL_MAX_LAYER_BYTES,
        max_image_bytes: DEFAULT_PULL_MAX_IMAGE_BYTES,
        max_manifest_bytes: DEFAULT_PULL_MAX_MANIFEST_BYTES,
        max_decompressed_layer_bytes: DEFAULT_PULL_MAX_DECOMPRESSED_LAYER_BYTES,
        max_rootfs_bytes: DEFAULT_PULL_MAX_ROOTFS_BYTES,
        max_tar_entries: DEFAULT_PULL_MAX_TAR_ENTRIES,
    };

    /// `v` bytes as a ceiling, or `None` when `v == 0` (ceiling disabled).
    fn cap(v: u64) -> Option<u64> {
        (v > 0).then_some(v)
    }
}

impl Default for RegistryPullLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The process-global registry-pull byte ceilings the blob fetchers consult. Installed ONCE at
/// node serve wiring from `[compute].registry_pull_limits` ([`install_registry_pull_limits`]);
/// default = the built-in ceilings above. Node operator config, never guest-influenced (mirrors
/// the timeouts global).
static REGISTRY_PULL_LIMITS: RwLock<RegistryPullLimits> = RwLock::new(RegistryPullLimits::DEFAULT);

/// Install the operator's registry-pull byte ceilings into the process-global the OCI blob
/// fetchers read. Called at node serve wiring; idempotent (a later call replaces the installed
/// values — config reload). Infallible: every field is a plain byte count (`0` disables a
/// ceiling), so there is nothing to reject.
pub fn install_registry_pull_limits(cfg: RegistryPullLimits) {
    *REGISTRY_PULL_LIMITS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = cfg;
}

/// Snapshot the installed [`RegistryPullLimits`] (default when unset).
fn registry_pull_limits() -> RegistryPullLimits {
    *REGISTRY_PULL_LIMITS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The effective per-blob byte ceiling: the tighter of the manifest-declared blob `size` (when
/// present and non-zero) and the operator `max_layer_bytes` ceiling. `None` ⇒ neither bound is
/// set (download uncapped at the per-blob level — the whole-image ceiling + deadline still
/// apply). A blob whose running byte count exceeds this is aborted DURING the read.
fn blob_cap(declared_size: Option<u64>) -> Option<u64> {
    let operator = RegistryPullLimits::cap(registry_pull_limits().max_layer_bytes);
    match (declared_size.filter(|&s| s > 0), operator) {
        (Some(declared), Some(op)) => Some(declared.min(op)),
        (declared, op) => declared.or(op),
    }
}

/// The effective byte cap for a MANIFEST or CONFIG read — both small JSON documents buffered in
/// memory (not streamed to disk like a layer), so bounded by the TIGHT `max_manifest_bytes`
/// ceiling rather than the generous per-layer `max_layer_bytes`, tightened further by the blob's
/// own manifest-declared `size` when it has one (a manifest declares none). `None` ⇒
/// `max_manifest_bytes` is disabled AND the blob declares no size ⇒ the read is uncapped in
/// memory (bounded then only by the pull timeouts/deadline). A read whose running byte count
/// exceeds this is aborted DURING the read, same as [`blob_cap`]. Mirrors [`blob_cap`] but reads
/// the manifest/config ceiling instead of the layer ceiling.
fn manifest_cap(declared_size: Option<u64>) -> Option<u64> {
    let operator = RegistryPullLimits::cap(registry_pull_limits().max_manifest_bytes);
    match (declared_size.filter(|&s| s > 0), operator) {
        (Some(declared), Some(op)) => Some(declared.min(op)),
        (declared, op) => declared.or(op),
    }
}

/// An incremental content-digest hasher, created FAIL-CLOSED: an unknown/unsupported algorithm
/// is rejected BEFORE any bytes are streamed (so a `@sha512:`/future-algo pin is verified, never
/// waved through, and we never download gigabytes only to reject the algo afterwards). A
/// concrete enum (not a `dyn DynDigest`) so the pull future stays `Send`.
enum BlobHasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl BlobHasher {
    /// The hasher for a `<algo>:<hex>` content digest, plus the wanted lowercase hex. Fails
    /// closed on a malformed digest or an unsupported algorithm (matching [`verify_digest`]).
    fn new(digest: &str) -> Result<(Self, String), OciError> {
        use sha2::Digest as _;
        let (algo, hex_want) = digest
            .split_once(':')
            .ok_or_else(|| OciError::Registry(format!("malformed content digest {digest}")))?;
        let hasher = match algo {
            "sha256" => Self::Sha256(sha2::Sha256::new()),
            "sha512" => Self::Sha512(sha2::Sha512::new()),
            other => {
                return Err(OciError::Registry(format!(
                    "unsupported digest algorithm {other:?}: refusing to trust unverifiable content"
                )));
            }
        };
        Ok((hasher, hex_want.to_string()))
    }

    /// Feed a chunk to the running hash.
    fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    /// Finalize to lowercase hex.
    fn finalize_hex(self) -> String {
        use sha2::Digest as _;
        match self {
            Self::Sha256(h) => hex::encode(h.finalize()),
            Self::Sha512(h) => hex::encode(h.finalize()),
        }
    }
}

/// Stream `resp`'s body into `sink` in chunks, aborting DURING the read the moment the running
/// byte count exceeds `cap` — so an oversize body is cut off mid-stream and never buffered whole
/// (closes the unbounded-allocation / OOM vector). Each chunk is fed to `hasher` (when present)
/// so a to-disk blob's digest is verified incrementally without re-reading the file. `what`
/// names the resource for the cap-exceeded error. Returns the total bytes written. `sink` is a
/// concrete `W: Write` (not `&mut dyn Write`) so the future stays `Send` — a `dyn Write` trait
/// object is `!Send`, and this future is held across `.await` on pull paths that must be `Send`.
async fn stream_body<W: std::io::Write>(
    mut resp: reqwest::Response,
    cap: Option<u64>,
    mut hasher: Option<&mut BlobHasher>,
    what: &str,
    sink: &mut W,
) -> Result<u64, OciError> {
    let mut total: u64 = 0;
    while let Some(chunk) = resp.chunk().await.map_err(|e| reqwest_err(&e))? {
        total = total.saturating_add(chunk.len() as u64);
        if let Some(limit) = cap
            && total > limit
        {
            return Err(OciError::Registry(format!(
                "{what} exceeded its {limit}-byte size cap mid-download and was aborted \
                 (refusing to buffer an oversize registry body)"
            )));
        }
        if let Some(h) = hasher.as_deref_mut() {
            h.update(&chunk);
        }
        sink.write_all(&chunk).map_err(OciError::Io)?;
    }
    Ok(total)
}

/// A typed SSRF-screen refusal carried OUT of the custom DNS resolver / redirect screen so its
/// actionable message (the refused host + the `[compute].allow_private_registries` hint)
/// survives reqwest's error wrapping (U31). On the HOSTNAME path the screen fails inside
/// [`ScreeningResolver`] (reqwest never calls it for a literal IP), and reqwest would otherwise
/// surface only its own generic transport Display ("error sending request for url …"), hiding
/// the operator-facing allow-list hint. Boxed as the resolver's error, it rides reqwest's
/// `source()` chain and is recovered by [`reqwest_err`].
#[derive(Debug, Clone)]
struct ScreenRefusal(String);

impl std::fmt::Display for ScreenRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScreenRefusal {}

/// Convert a `reqwest` error into an [`OciError`], PRESERVING a [`ScreenRefusal`] message when
/// the SSRF screen is what rejected the request (U31). Walks the error's `source()` chain; the
/// first `ScreenRefusal` found wins (its message names the refused host + points at
/// `[compute].allow_private_registries`), so a hostname-named internal/metadata registry yields
/// the actionable error instead of reqwest's generic transport string. Falls back to reqwest's
/// own Display when the failure was an ordinary transport error.
fn reqwest_err(e: &reqwest::Error) -> OciError {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(refusal) = err.downcast_ref::<ScreenRefusal>() {
            return OciError::Registry(refusal.0.clone());
        }
        cur = err.source();
    }
    OciError::Registry(e.to_string())
}

/// Build the SSRF-screened pull client, shared across registry + blob + token
/// fetches: a [`ScreeningResolver`] screens every hostname lookup (initial +
/// redirects), and the redirect policy (bounded) requires each hop to be `https`
/// and rejects a hop to a literal non-global IP (which the resolver never sees).
/// Redirects are FOLLOWED — a registry blob GET legitimately `307`s to a CDN — but
/// an SSRF redirect to cloud metadata / an internal host is refused, not chased.
///
/// The client carries the operator's connect + read/idle timeouts (U30) so a
/// dead/stalling registry fails the pull in bounded time; the overall per-request cap is
/// applied per-call to the small control-plane requests only (see [`get_authed`]).
fn screening_client() -> Result<reqwest::Client, OciError> {
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 8 {
            return attempt.error(std::io::Error::other("too many redirects"));
        }
        // Copy what we need as owned values before consuming `attempt`.
        let is_https = attempt.url().scheme() == "https";
        // A redirect to a literal-IP host bypasses the DNS resolver → screen its normalized
        // host here, through the SAME `screen_url_host` helper the initial sites use (operator
        // allow-list + always-blocked-metadata; a non-canonical literal is decoded by the url
        // parser first). Behavior-identical to the prior inline check — a domain redirect is
        // left to the resolver (Ok ⇒ not flagged), a non-global literal is refused.
        let literal_bad = screen_url_host(attempt.url()).is_err();
        let shown = attempt.url().to_string();
        if !is_https {
            attempt.error(ScreenRefusal(format!(
                "refusing non-https redirect to {shown}"
            )))
        } else if literal_bad {
            // Typed so the refusal message survives reqwest's wrapping (U31), same as the
            // resolver (hostname) path — a redirect to a non-global host is the same SSRF class,
            // and carries the SAME actionable `[compute].allow_private_registries` hint (an
            // operator who wants a redirect to an internal CDN allowed adds it to the allow-list).
            attempt.error(ScreenRefusal(format!(
                "refusing redirect to non-global host {shown}: it is not on the \
                 `[compute].allow_private_registries` operator allow-list"
            )))
        } else {
            attempt.follow()
        }
    });
    let t = registry_pull_timeouts();
    let mut builder = reqwest::Client::builder()
        .user_agent("boatramp-compute")
        .dns_resolver(std::sync::Arc::new(ScreeningResolver))
        .redirect(redirect);
    // Bound the pull (U30): a connect timeout (TCP+TLS handshake) and a read/idle timeout
    // (the max no-bytes-flowing gap, which catches "accepts the connection and never
    // answers" without capping a legitimately large blob — it resets per chunk). The overall
    // cap is applied per-request to the small control-plane GETs only (see `get_authed`).
    if let Some(d) = RegistryPullTimeouts::dur(t.connect_secs) {
        builder = builder.connect_timeout(d);
    }
    if let Some(d) = RegistryPullTimeouts::dur(t.read_secs) {
        builder = builder.read_timeout(d);
    }
    builder
        .build()
        .map_err(|e| OciError::Registry(e.to_string()))
}

/// GET `url` with the manifest Accept header, performing a one-shot
/// `WWW-Authenticate: Bearer` token exchange on `401` (anonymous pull).
///
/// `overall` is the per-request total-time cap (U30): `Some(_)` for the small control-plane
/// GETs (manifest), `None` for a blob GET whose legitimately-large body is bounded by the
/// client's idle read timeout instead of a hard overall cap. The connect + read/idle bounds
/// live on the shared `client` ([`screening_client`]).
async fn get_authed(
    client: &reqwest::Client,
    url: &str,
    accept: &str,
    token: &mut Option<String>,
    overall: Option<Duration>,
) -> Result<reqwest::Response, OciError> {
    let send = |bearer: &Option<String>| {
        let mut req = client.get(url).header(reqwest::header::ACCEPT, accept);
        if let Some(d) = overall {
            req = req.timeout(d);
        }
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        req.send()
    };
    let resp = send(token).await.map_err(|e| reqwest_err(&e))?;
    if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(resp);
    }
    // Parse the Bearer challenge and fetch an anonymous token.
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let new_token = fetch_token(client, &challenge).await?;
    *token = Some(new_token);
    send(token).await.map_err(|e| reqwest_err(&e))
}

/// Resolve a `Bearer realm="…",service="…",scope="…"` challenge into a token.
///
/// The realm comes from the (tenant-controlled) registry's `401`, so it is
/// screened before it is fetched: it MUST be `https://` ([`parse_realm`]) and its
/// host must not be (or resolve to) a non-global address — a literal-IP realm via
/// [`screen_pull_url`] (the normalized host, so a non-canonical IPv4 literal is decoded +
/// screened), a hostname via the shared client's [`ScreeningResolver`].
/// So a malicious `realm="http://169.254.169.254/…"` (SSRF to cloud metadata /
/// internal hosts, plus a credential-exfil tail) is refused rather than fetched.
/// The same screened `client` serves the realm GET (its resolver screens the realm
/// host too).
async fn fetch_token(client: &reqwest::Client, challenge: &str) -> Result<String, OciError> {
    let params = challenge.trim_start_matches("Bearer ");
    let mut realm = None;
    let mut query: Vec<(String, String)> = Vec::new();
    for part in params.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "realm" => realm = Some(v),
                "service" => query.push(("service".into(), v)),
                "scope" => query.push(("scope".into(), v)),
                _ => {}
            }
        }
    }
    let realm = realm.ok_or_else(|| OciError::Registry("no realm in auth challenge".into()))?;
    // The realm comes from the (tenant-controlled) registry's 401. Enforce the https scheme
    // (`parse_realm`) AND screen the WHATWG-NORMALIZED realm host the SAME way the GET below
    // connects — a non-canonical IP-literal realm host (`0xa9fea9fe`) would otherwise slip the
    // lexical screen but be decoded + dialed by reqwest without the resolver (Security HIGH).
    parse_realm(&realm)?;
    screen_pull_url(&realm)?;
    // The token exchange is a small control-plane request → bound it with the overall cap (U30)
    // so a never-answering realm host can't stall the pull past the budget.
    let mut req = client.get(&realm).query(&query);
    if let Some(d) = small_request_overall_timeout() {
        req = req.timeout(d);
    }
    let resp = req.send().await.map_err(|e| reqwest_err(&e))?;
    let json: serde_json::Value = resp.json().await.map_err(|e| reqwest_err(&e))?;
    json.get("token")
        .or_else(|| json.get("access_token"))
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| OciError::Registry("no token in auth response".into()))
}

/// The pieces of an OCI image needed to build a bootable rootfs: its resolved
/// **runtime config** (entrypoint/cmd/env/workdir) + the registry coordinates to
/// fetch its layer blobs.
struct ResolvedManifest {
    client: reqwest::Client,
    base: String,
    manifest: serde_json::Value,
    token: Option<String>,
}

/// The subset of an OCI image's runtime config the init needs (the `config`
/// object of the image config blob): the process to run + its environment.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImageConfig {
    /// `Entrypoint` argv (prepended to `cmd`).
    pub entrypoint: Vec<String>,
    /// `Cmd` argv (the default arguments / command).
    pub cmd: Vec<String>,
    /// `Env` as `KEY=VALUE` strings.
    pub env: Vec<String>,
    /// `WorkingDir` the process starts in (empty ⇒ `/`).
    pub workdir: String,
}

/// The OCI image architecture to pull — the **guest** arch, which mirrors the
/// build host's (an x86_64 host boots `amd64` guests via the KVM VMM; an
/// Apple-silicon host boots `arm64` guests via Virtualization.framework). This
/// matches the arch of the `vminit` baked by `build.rs` and the guest kernel, so
/// the rootfs, init, and kernel agree.
fn oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "amd64",
    }
}

/// Resolve `image` to a concrete `linux/<guest-arch>` manifest, performing the
/// anonymous Bearer-token dance. A multi-arch index is followed to its entry for
/// [`oci_arch`] (the host/guest arch).
async fn resolve_manifest(image: &str) -> Result<ResolvedManifest, OciError> {
    let (registry, repo, reference) = parse_reference(image);
    let client = screening_client()?;
    let base = format!("https://{registry}/v2/{repo}");
    // Screen the registry host for SSRF against the WHATWG-NORMALIZED host (the form reqwest
    // resolves + connects to) — NOT the raw lexical string, which a non-canonical IPv4 literal
    // (`0xa9fea9fe`, decimal, octal, short form) slips past while the url parser decodes it to a
    // real address reqwest dials straight (no `ScreeningResolver`). A literal IP is screened
    // here (metadata un-exemptable); a hostname is screened by the resolver at connect.
    screen_pull_url(&base)?;
    let mut token = None;

    // When the ref is an `@<algo>:<hex>` digest pin, the manifest body itself must
    // hash to it — otherwise a MITM / malicious registry can serve a *different*
    // self-consistent manifest (its layer digests all check out against ITS own
    // manifest). Verify the manifest bytes before trusting their layer list. A
    // reference with a `:` is a digest (a tag never contains one).
    let manifest_url = format!("{base}/manifests/{reference}");
    let want = reference.contains(':').then_some(reference.as_str());
    let manifest = fetch_manifest(&client, &manifest_url, &mut token, want).await?;

    let manifest = if manifest.get("manifests").is_some() {
        // An index/list — pick linux/<guest-arch>. The chosen child manifest is
        // ALWAYS verified against the index-provided digest (the index itself was
        // digest-verified above when the ref was a pin).
        let arch = oci_arch();
        let digest = manifest["manifests"]
            .as_array()
            .and_then(|entries| {
                entries.iter().find(|m| {
                    let p = &m["platform"];
                    p["os"].as_str() == Some("linux") && p["architecture"].as_str() == Some(arch)
                })
            })
            .and_then(|m| m["digest"].as_str())
            .ok_or_else(|| OciError::Registry(format!("no linux/{arch} in image index")))?
            .to_string();
        let url = format!("{base}/manifests/{digest}");
        fetch_manifest(&client, &url, &mut token, Some(&digest)).await?
    } else {
        manifest
    };
    Ok(ResolvedManifest {
        client,
        base,
        manifest,
        token,
    })
}

/// Verify `bytes` hash to `digest` (an `<algo>:<hex>` content digest). Supports
/// `sha256` and `sha512`; an **unknown algorithm FAILS CLOSED** (rejected) rather
/// than passing unverified — a caller that believes it pinned `@sha512:…` (or any
/// future algo) must never silently trust registry-supplied bytes. A malformed
/// digest (no `algo:`) is also rejected.
fn verify_digest(bytes: &[u8], digest: &str) -> Result<(), OciError> {
    use sha2::{Digest, Sha256, Sha512};
    let (algo, hex_want) = digest
        .split_once(':')
        .ok_or_else(|| OciError::Registry(format!("malformed content digest {digest}")))?;
    let got = match algo {
        "sha256" => hex::encode(Sha256::digest(bytes)),
        "sha512" => hex::encode(Sha512::digest(bytes)),
        other => {
            return Err(OciError::Registry(format!(
                "unsupported digest algorithm {other:?}: refusing to trust unverifiable content"
            )));
        }
    };
    if !got.eq_ignore_ascii_case(hex_want) {
        return Err(OciError::Registry(format!("digest mismatch for {digest}")));
    }
    Ok(())
}

/// GET a manifest from `url`, verifying its raw bytes against `expect` (a content
/// digest) BEFORE parsing — so a digest-pinned pull trusts only a manifest whose
/// body actually hashes to the pin.
async fn fetch_manifest(
    client: &reqwest::Client,
    url: &str,
    token: &mut Option<String>,
    expect: Option<&str>,
) -> Result<serde_json::Value, OciError> {
    // A manifest is small → cap it with the overall per-request timeout (U30) AND stream it under
    // the TIGHT manifest/config byte ceiling, so a malicious registry cannot OOM the node by
    // streaming an unbounded body in place of a manifest (a manifest declares no size of its own,
    // so `max_manifest_bytes` — not the generous 10 GiB layer ceiling — is what bounds it).
    let resp = get_authed(
        client,
        url,
        MANIFEST_ACCEPT,
        token,
        small_request_overall_timeout(),
    )
    .await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!(
            "manifest GET {}",
            resp.status()
        )));
    }
    let mut bytes: Vec<u8> = Vec::new();
    stream_body(resp, manifest_cap(None), None, "manifest", &mut bytes).await?;
    if let Some(d) = expect {
        verify_digest(&bytes, d)?;
    }
    serde_json::from_slice(&bytes).map_err(|e| OciError::Registry(e.to_string()))
}

/// Fetch + verify a SMALL blob (the image config) by `digest` from `base`, into memory. The
/// body is streamed under `manifest_cap(declared_size)` — the TIGHT manifest/config ceiling, not
/// the generous per-layer one (a config is a KB-scale JSON document) — aborted mid-read if it
/// exceeds the cap, so a registry cannot OOM the node by streaming an unbounded body under a tiny
/// declared size, and verified against `digest` via [`verify_digest`], which fails closed on an
/// unknown algorithm. Used only for the config blob; layer blobs stream to disk via
/// [`fetch_layer_to_file`].
async fn fetch_blob(
    client: &reqwest::Client,
    base: &str,
    digest: &str,
    token: &mut Option<String>,
    declared_size: Option<u64>,
) -> Result<Vec<u8>, OciError> {
    let url = format!("{base}/blobs/{digest}");
    // No per-request overall cap on a blob (U30): a layer may legitimately be large/slow, so it
    // is bounded by the idle read timeout (resets per chunk) + the byte cap + the whole-pull
    // deadline — never severed mid-request-progress.
    let resp = get_authed(client, &url, "*/*", token, None).await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!("blob GET {}", resp.status())));
    }
    let mut bytes: Vec<u8> = Vec::new();
    stream_body(
        resp,
        manifest_cap(declared_size),
        None,
        "config blob",
        &mut bytes,
    )
    .await?;
    verify_digest(&bytes, digest)?;
    Ok(bytes)
}

/// A resolved manifest's layer descriptors in apply order (lowest first): each layer's content
/// `digest` and its manifest-declared compressed `size` (`None` when absent/non-integer — then
/// only the operator per-blob ceiling caps that blob).
fn layer_descriptors(manifest: &serde_json::Value) -> Result<Vec<(String, Option<u64>)>, OciError> {
    manifest["layers"]
        .as_array()
        .ok_or_else(|| OciError::Registry("manifest has no layers".into()))?
        .iter()
        .map(|l| {
            let digest = l["digest"]
                .as_str()
                .ok_or_else(|| OciError::Registry("layer missing digest".into()))?
                .to_string();
            Ok((digest, l["size"].as_u64()))
        })
        .collect()
}

/// Stream a layer blob to `out` on disk, verifying it as it downloads: the body is read in
/// chunks (memory stays O(one chunk), never the whole blob), the running byte count is checked
/// against `blob_cap(declared_size)` and the download ABORTED mid-stream if it is exceeded (a
/// layer past its own declared size is malformed; the operator ceiling backstops), and the
/// content digest is verified incrementally at the end. Returns the bytes written. Fails closed
/// on an unknown digest algorithm BEFORE streaming a single byte.
async fn fetch_layer_to_file(
    client: &reqwest::Client,
    base: &str,
    digest: &str,
    token: &mut Option<String>,
    declared_size: Option<u64>,
    out: &Path,
) -> Result<u64, OciError> {
    // Fail closed on the algorithm up front — never download a blob we cannot verify.
    let (mut hasher, hex_want) = BlobHasher::new(digest)?;
    let url = format!("{base}/blobs/{digest}");
    let resp = get_authed(client, &url, "*/*", token, None).await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!("blob GET {}", resp.status())));
    }
    let mut file = std::io::BufWriter::new(fs::File::create(out)?);
    let n = stream_body(
        resp,
        blob_cap(declared_size),
        Some(&mut hasher),
        "layer blob",
        &mut file,
    )
    .await?;
    use std::io::Write as _;
    file.flush().map_err(OciError::Io)?;
    let got = hasher.finalize_hex();
    if !got.eq_ignore_ascii_case(&hex_want) {
        return Err(OciError::Registry(format!("digest mismatch for {digest}")));
    }
    Ok(n)
}

/// Download the resolved manifest's layers (each STREAMED to a temp file in `layers_dir` under
/// its byte cap + digest verification) and overlay them, lowest first, onto `target`. Each
/// layer's tarball is dropped as soon as it is overlaid, so peak scratch disk stays ~one layer
/// and node memory stays O(one chunk) — no `Vec<Vec<u8>>` of whole layers. The running total
/// across all layers is bounded by the operator whole-image ceiling. The caller owns
/// `layers_dir`'s lifetime (removes it) so the cleanup survives an overall-deadline cancellation.
async fn apply_image_layers_in(
    r: &mut ResolvedManifest,
    target: &Path,
    layers_dir: &Path,
) -> Result<(), OciError> {
    let descriptors = layer_descriptors(&r.manifest)?;
    let lim = registry_pull_limits();
    let max_total = RegistryPullLimits::cap(lim.max_image_bytes);
    // DECOMPRESSED + ENTRY ceilings — the compressed caps above bound the download, NOT how large
    // a layer inflates to, nor how many entries (inodes) it carries. The per-layer `budget` bounds
    // the inflation (zip-bomb guard) AND the hard-link `fs::copy` fallback's copied bytes
    // (copy-amplification guard) AND the tar-entry count (inode-exhaustion guard). The running
    // totals (`rootfs_decompressed`, `entries_total`) are owned `Cell`s that carry ACROSS layers so
    // `max_rootfs_bytes` and `max_tar_entries` span the whole rootfs/image, not just one layer.
    // They are the only budget state held across the per-layer `.await` below (`Cell<u64>` is
    // `Send`); the `DecompBudget` itself — which borrows them as `&Cell` (`!Send`, since `Cell` is
    // `!Sync`) — is built fresh AFTER the await and dropped before the next one, so the pull future
    // stays `Send` (required by the container backend's boxed `run_ephemeral`).
    let layer_cap = RegistryPullLimits::cap(lim.max_decompressed_layer_bytes);
    let rootfs_cap = RegistryPullLimits::cap(lim.max_rootfs_bytes);
    let entries_cap = RegistryPullLimits::cap(lim.max_tar_entries);
    let rootfs_decompressed = Cell::new(0u64);
    let entries_total = Cell::new(0u64);
    let mut total: u64 = 0;
    for (i, (digest, size)) in descriptors.iter().enumerate() {
        let path = layers_dir.join(format!("layer-{i}.tar.gz"));
        let n = fetch_layer_to_file(&r.client, &r.base, digest, &mut r.token, *size, &path).await?;
        total = total.saturating_add(n);
        if let Some(max) = max_total
            && total > max
        {
            return Err(OciError::Registry(format!(
                "image layers exceeded the {max}-byte whole-image pull ceiling; aborting"
            )));
        }
        // Overlay this layer from disk (streaming gunzip), bounding its DECOMPRESSED size per-layer
        // AND the running total across all layers (so a zip-bomb or copy-amplification bomb is
        // aborted mid-inflation, never fully expanded onto disk) AND the per-image entry count,
        // then drop its tarball. A fresh per-layer budget starts `layer_read` at 0 while the owned
        // `Cell` totals (borrowed here, never held across an await) carry forward.
        let budget = DecompBudget {
            layer_read: Cell::new(0),
            layer_cap,
            rootfs_total: &rootfs_decompressed,
            rootfs_cap,
            entries_total: &entries_total,
            entries_cap,
        };
        let f = fs::File::open(&path)?;
        apply_layer_gz_bounded(target, std::io::BufReader::new(f), &budget)?;
        let _ = fs::remove_file(&path);
    }
    Ok(())
}

/// Pull ONLY an image's runtime [`ImageConfig`] — the manifest resolve + the (small)
/// config blob, with no layer download. The container backend uses this to recover the
/// image's `Env` (notably `PATH`) and `WorkingDir` for an ephemeral one-shot whose rootfs
/// is already staged (layers cached), so a bare `pg_dump`/`pg_restore`/`psql` resolves
/// against the image's own `PATH` instead of failing with `127`. Network seam.
pub async fn pull_image_config(image: &str) -> Result<ImageConfig, OciError> {
    // Bound the WHOLE config-only network fetch (manifest resolve + the small config blob) by the
    // operator overall wall-clock deadline, exactly as `build_rootfs`/`build_rootfs_dir` bound the
    // layer pulls. Without this, a registry drip-feeding bytes just under the idle `read_secs` on
    // the manifest or config response holds THIS path — and the serial reconcile loop awaiting it —
    // open indefinitely, the same cross-tenant DoS the layer deadline closes. It downloads no
    // layers, so the wrap is a plain span around the two small fetches.
    with_pull_deadline(async {
        let mut r = resolve_manifest(image).await?;
        parse_image_config(&mut r).await
    })
    .await
}

/// Fetch + parse the image config blob into an [`ImageConfig`].
async fn parse_image_config(r: &mut ResolvedManifest) -> Result<ImageConfig, OciError> {
    let config_desc = &r.manifest["config"];
    let digest = config_desc["digest"]
        .as_str()
        .ok_or_else(|| OciError::Registry("manifest has no config digest".into()))?
        .to_string();
    let declared_size = config_desc["size"].as_u64();
    let bytes = fetch_blob(&r.client, &r.base, &digest, &mut r.token, declared_size).await?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| OciError::Registry(e.to_string()))?;
    let cfg = &json["config"];
    let str_vec = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(ImageConfig {
        entrypoint: str_vec(&cfg["Entrypoint"]),
        cmd: str_vec(&cfg["Cmd"]),
        env: str_vec(&cfg["Env"]),
        workdir: cfg["WorkingDir"].as_str().unwrap_or("").to_string(),
    })
}

/// The freestanding guest init compiled by `build.rs` (see `src/vminit.c`),
/// embedded so the OCI builder can drop it into any rootfs as `/sbin/init` — it
/// mounts the pseudo-filesystems + execs the workload with no libc/shell needed,
/// so even shell-less (scratch/distroless) images boot.
const VMINIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vminit"));

/// Resolve the process the guest runs: the override `entrypoint` (from the spec)
/// if non-empty, else the image's `Entrypoint` + `Cmd`. Returns an error if there
/// is nothing to run (so a broken image fails at build, not at boot).
fn effective_argv(cfg: &ImageConfig, entrypoint: &[String]) -> Result<Vec<String>, OciError> {
    let argv = if !entrypoint.is_empty() {
        entrypoint.to_vec()
    } else {
        let mut v = cfg.entrypoint.clone();
        v.extend(cfg.cmd.iter().cloned());
        v
    };
    if argv.is_empty() {
        return Err(OciError::Registry(
            "image has no entrypoint/cmd and none was supplied".into(),
        ));
    }
    Ok(argv)
}

/// The effective environment: the image's `Env` with `env_override` applied on
/// top (an override replaces the image's same-key entry; new keys are appended),
/// as `KEY=VALUE` strings.
fn effective_env(cfg: &ImageConfig, env_override: &[(String, String)]) -> Vec<String> {
    let mut out = cfg.env.clone();
    for (k, v) in env_override {
        let prefix = format!("{k}=");
        let entry = format!("{k}={v}");
        match out.iter_mut().find(|kv| kv.starts_with(&prefix)) {
            Some(slot) => *slot = entry,
            None => out.push(entry),
        }
    }
    out
}

/// Join `items` NUL-separated (each string followed by a NUL byte) — the format
/// the guest init parses for its argv/env spec files.
fn nul_join(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in items {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

/// The default `PATH` searched for a bare command name (matching common image
/// defaults), used when the image env doesn't set one.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Resolve a bare (no-`/`) `argv[0]` to an absolute path by searching `PATH`
/// within the overlaid rootfs at `root` — the guest init `execve`s directly (no
/// PATH lookup), but OCI exec-form entrypoints are often bare (`nginx`, `httpd`).
/// Leaves an already-pathful or unfound `argv0` unchanged (an unfound one fails
/// visibly in the guest init rather than silently resolving to a wrong path).
fn resolve_argv0(root: &Path, argv0: &str, env: &[String]) -> String {
    if argv0.contains('/') {
        return argv0.to_string();
    }
    let path = env
        .iter()
        .find_map(|kv| kv.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_PATH);
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let rel = dir.trim_start_matches('/');
        if fs::symlink_metadata(root.join(rel).join(argv0)).is_ok() {
            return format!("{}/{argv0}", dir.trim_end_matches('/'));
        }
    }
    argv0.to_string()
}

/// Create a fresh, exclusively-owned staging directory for a rootfs build.
/// Defense-in-depth against a predictable `/tmp` path: the name carries entropy
/// (pid + high-resolution clock + a process-unique counter), creation is
/// **exclusive** (`create_dir` fails `EEXIST` if the name — or a symlink of that
/// name — is pre-planted, so it can't be hijacked), and on unix it is chmod'd
/// `0700` so no other local user can inject symlinks into the work tree mid-unpack
/// (which would otherwise race the containment resolver).
fn make_staging_dir(tag: &str) -> Result<PathBuf, OciError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir();
    let pid = u64::from(std::process::id());
    for _ in 0..128 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("br-rootfs-{pid:x}-{nanos:x}-{seq:x}-{tag}"));
        match fs::create_dir(&dir) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                }
                return Ok(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(OciError::Io(std::io::Error::other(
        "could not create a unique rootfs staging directory",
    )))
}

/// Build an ext4 rootfs at `out` from an OCI `image`: resolve the manifest → fetch the config →
/// **stream** each layer to disk and overlay it → inject a `/sbin/init` that execs the workload
/// (the `entrypoint` override, else the image's `Entrypoint`+`Cmd`; with `env` merged over the
/// image env) + a default `/etc/resolv.conf` → `mke2fs -d`. Orchestrates the network + host-tool
/// seams. The whole network pull is bounded by the operator wall-clock deadline; layers never
/// buffer whole in memory.
pub async fn build_rootfs(
    image: &str,
    entrypoint: &[String],
    env: &[(String, String)],
    out: &Path,
    size_mib: u64,
    volume_mounts: &[String],
) -> Result<(), OciError> {
    let tag = out.file_name().and_then(|n| n.to_str()).unwrap_or("vm");
    let work = make_staging_dir(tag)?;
    // A SEPARATE scratch dir for the downloaded layer tarballs (never inside `work`, which is
    // overlaid into the rootfs). Both dirs are removed below regardless of how the pull ends —
    // including an overall-deadline cancellation that drops the pull future mid-flight.
    let layers_dir = make_staging_dir(&format!("{tag}-layers"))?;
    let result = async {
        // The network-bound pull (manifest + config + every layer overlaid into `work`) runs
        // under the overall wall-clock deadline; the local `write_init` + `mke2fs` do not.
        let config = with_pull_deadline(async {
            let mut r = resolve_manifest(image).await?;
            let config = parse_image_config(&mut r).await?;
            apply_image_layers_in(&mut r, &work, &layers_dir).await?;
            Ok::<_, OciError>(config)
        })
        .await?;
        let argv = effective_argv(&config, entrypoint)?;
        write_init(&work, &argv, &config, env, volume_mounts)?;
        build_ext4(&work, out, size_mib)
    }
    .await;
    let _ = fs::remove_dir_all(&layers_dir);
    let _ = fs::remove_dir_all(&work);
    result
}

/// Inject the boatramp guest init into the overlaid rootfs at `root`: the
/// freestanding [`VMINIT`] binary at `/sbin/init`, the exec spec it reads
/// (`/etc/boatramp/{argv,env,cwd}` — NUL-separated argv/env, the cwd one line),
/// the pseudo-filesystem mount-point dirs (the root boots read-only, so they must
/// pre-exist), and a default `/etc/resolv.conf`.
///
/// Every destination is written through [`contained_write`] /
/// [`contained_create_dir_all`], NOT raw `std::fs` — the rootfs tree is
/// tenant-controlled (a layer can plant `sbin`/`etc`/a mount point as a symlink),
/// and this runs in the privileged node process, so a raw `create_dir_all` +
/// `write` would follow a planted `sbin -> /etc/cron.hourly` and drop a 0755 ELF
/// onto the HOST. The contained writers resolve `RESOLVE_IN_ROOT` and unlink a
/// planted leaf symlink before writing, so every write stays inside `root`.
fn write_init(
    root: &Path,
    argv: &[String],
    cfg: &ImageConfig,
    env_override: &[(String, String)],
    volume_mounts: &[String],
) -> Result<(), OciError> {
    let init = contained_write(root, Path::new("sbin/init"), VMINIT)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&init, fs::Permissions::from_mode(0o755))?;
    }

    // The exec spec the init reads. Resolve a bare argv[0] to an absolute path
    // (the init `execve`s directly, with no PATH search).
    let env = effective_env(cfg, env_override);
    let mut argv = argv.to_vec();
    if let Some(first) = argv.first_mut() {
        *first = resolve_argv0(root, first, &env);
    }
    contained_write(root, Path::new("etc/boatramp/argv"), &nul_join(&argv))?;
    contained_write(root, Path::new("etc/boatramp/env"), &nul_join(&env))?;
    let cwd = if cfg.workdir.is_empty() {
        "/"
    } else {
        &cfg.workdir
    };
    contained_write(root, Path::new("etc/boatramp/cwd"), cwd.as_bytes())?;

    // The init mounts onto these; a read-only root means they must already exist.
    for dir in ["proc", "sys", "dev", "tmp", "run"] {
        contained_create_dir_all(root, Path::new(dir))?;
    }

    // Persistent-volume mount points: each volume attaches as a writable
    // virtio-block device (`/dev/vdb`, `/dev/vdc`, … in order, after the rootfs
    // `vda`). Bake the mount-point dir (read-only root → must pre-exist) + the
    // `source␞target` map the init mounts. Best-effort at runtime.
    let mut mounts_spec: Vec<String> = Vec::with_capacity(volume_mounts.len() * 2);
    for (i, mount) in volume_mounts.iter().enumerate() {
        contained_create_dir_all(root, Path::new(mount.trim_start_matches('/')))?;
        mounts_spec.push(format!("/dev/vd{}", (b'b' + i as u8) as char));
        mounts_spec.push(mount.clone());
    }
    if !mounts_spec.is_empty() {
        contained_write(
            root,
            Path::new("etc/boatramp/mounts"),
            &nul_join(&mounts_spec),
        )?;
    }
    // A default resolver so the workload can do DNS (egress NAT is the node's
    // job). Overridable per deployment — the container backend rewrites
    // resolv.conf post-stage to point at the internal resolver; the VMM bakes it
    // at build, so expose the same knob here. Only written if the image shipped
    // none (resolved RESOLVE_IN_ROOT so a shipped symlink is honored, not escaped).
    if !resolve_in_root(root, Path::new("etc/resolv.conf"))?.exists() {
        contained_write(
            root,
            Path::new("etc/resolv.conf"),
            default_resolv_conf().as_bytes(),
        )?;
    }
    Ok(())
}

/// The default guest `resolv.conf` body. The nameserver defaults to `1.1.1.1` but
/// is overridable via the `BOATRAMP_VM_NAMESERVER` env var (operator-set, not
/// tenant-controlled); only a value that parses as an IP address is honored, so a
/// malformed/newline-bearing override can't inject extra resolv.conf directives.
fn default_resolv_conf() -> String {
    resolv_conf_body(std::env::var("BOATRAMP_VM_NAMESERVER").ok().as_deref())
}

/// Render the guest `resolv.conf` body from an optional nameserver override. Only
/// a value that parses as an IP address is honored (so a malformed or
/// newline-bearing override falls back to `1.1.1.1` rather than injecting a
/// second `nameserver`/other directive). Pure — the testable core.
fn resolv_conf_body(ns_override: Option<&str>) -> String {
    let ns = ns_override
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map_or_else(|| "1.1.1.1".to_string(), |ip| ip.to_string());
    format!("nameserver {ns}\n")
}

/// Materialize an OCI `image` into an unpacked rootfs **directory** at `out`
/// (pull → **stream** each layer to disk → overlay it, honoring whiteouts) — the
/// same overlay as [`build_rootfs`] but stopping before `mke2fs`. The native
/// **container** backend boots from this directory directly (`pivot_root`); no
/// ext4 image, so it needs no `e2fsprogs`. Idempotent: `out` is recreated. The
/// pull is bounded by the operator wall-clock deadline + byte ceilings; layers
/// never buffer whole in memory.
pub async fn build_rootfs_dir(image: &str, out: &Path) -> Result<(), OciError> {
    let _ = fs::remove_dir_all(out);
    fs::create_dir_all(out)?;
    // Scratch dir for the downloaded layer tarballs; removed below regardless of how the pull
    // ends (including an overall-deadline cancellation that drops the pull future mid-flight).
    let layers_dir = make_staging_dir("oci-dir-layers")?;
    let result = with_pull_deadline(async {
        let mut r = resolve_manifest(image).await?;
        apply_image_layers_in(&mut r, out, &layers_dir).await
    })
    .await;
    let _ = fs::remove_dir_all(&layers_dir);
    // On ANY failure (incl. a decompressed-size / zip-bomb abort mid-inflation) remove the PARTIAL
    // rootfs we were unpacking into, so an aborted bomb does not leave its half-inflated bytes
    // filling the node disk — the same cleanup discipline as `build_rootfs` (which always removes
    // its `work` staging dir) and the v0.70.0 streaming `layers_dir` cleanup.
    if result.is_err() {
        let _ = fs::remove_dir_all(out);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reference_strips_tag_when_a_digest_is_present() {
        // `name:tag@digest` — the digest is authoritative; the `:tag` must NOT stay in the
        // repo (else the manifest GET 404s). This is the exact form the digest-pin docs show.
        let (reg, repo, r) = parse_reference("pgvector/pgvector:pg16@sha256:abc123");
        assert_eq!(reg, "registry-1.docker.io");
        assert_eq!(repo, "pgvector/pgvector");
        assert_eq!(r, "sha256:abc123");

        // A single-name official image with both tag and digest → `library/` + stripped tag.
        let (reg, repo, r) = parse_reference("postgres:16@sha256:def456");
        assert_eq!(reg, "registry-1.docker.io");
        assert_eq!(repo, "library/postgres");
        assert_eq!(r, "sha256:def456");

        // A private registry WITH a port + a tag + a digest — the host:port is preserved,
        // only the final-component `:tag` is stripped.
        let (reg, repo, r) = parse_reference("reg.example.com:5000/team/img:v1@sha256:cab");
        assert_eq!(reg, "reg.example.com:5000");
        assert_eq!(repo, "team/img");
        assert_eq!(r, "sha256:cab");
    }

    #[test]
    fn parse_reference_digest_only_and_tag_only_still_work() {
        // Tag-less digest pin (the documented workaround) keeps parsing correctly.
        let (reg, repo, r) = parse_reference("pgvector/pgvector@sha256:aaa");
        assert_eq!(
            (reg.as_str(), repo.as_str(), r.as_str()),
            ("registry-1.docker.io", "pgvector/pgvector", "sha256:aaa",)
        );
        // Plain tag.
        let (reg, repo, r) = parse_reference("pgvector/pgvector:pg16");
        assert_eq!(
            (reg.as_str(), repo.as_str(), r.as_str()),
            ("registry-1.docker.io", "pgvector/pgvector", "pg16",)
        );
        // A registry host with a port, tag-only (the port must not be mistaken for a tag).
        let (reg, repo, r) = parse_reference("reg.example.com:5000/img:v2");
        assert_eq!(
            (reg.as_str(), repo.as_str(), r.as_str()),
            ("reg.example.com:5000", "img", "v2",)
        );
    }

    /// Build an uncompressed tar from `(path, contents)` files + explicit dirs.
    fn tar_with(files: &[(&str, &[u8])], dirs: &[&str]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for dir in dirs {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o755);
            h.set_size(0);
            builder.append_data(&mut h, dir, std::io::empty()).unwrap();
        }
        for (path, contents) in files {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(contents.len() as u64);
            builder.append_data(&mut h, path, *contents).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("br-oci-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn base_layer_unpacks_files_and_dirs() {
        let root = tmpdir("base");
        let layer = tar_with(
            &[("app/run", b"#!/bin/sh\n"), ("etc/conf", b"x")],
            &["app", "etc"],
        );
        apply_layer_tar(&root, &layer[..]).unwrap();
        assert_eq!(fs::read(root.join("app/run")).unwrap(), b"#!/bin/sh\n");
        assert!(root.join("etc/conf").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn whiteout_deletes_a_lower_layer_path() {
        let root = tmpdir("wh");
        apply_layer_tar(&root, &tar_with(&[("a", b"1"), ("b", b"2")], &[])[..]).unwrap();
        // Second layer whites out `a`.
        apply_layer_tar(&root, &tar_with(&[(".wh.a", b"")], &[])[..]).unwrap();
        assert!(!root.join("a").exists(), "a should be whited out");
        assert!(root.join("b").exists(), "b survives");
        assert!(!root.join(".wh.a").exists(), "marker not materialized");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn opaque_whiteout_clears_a_directory() {
        let root = tmpdir("opq");
        apply_layer_tar(
            &root,
            &tar_with(&[("d/old1", b"1"), ("d/old2", b"2")], &["d"])[..],
        )
        .unwrap();
        // Opaque marker in `d` + a new file.
        apply_layer_tar(
            &root,
            &tar_with(&[("d/.wh..wh..opq", b""), ("d/new", b"3")], &["d"])[..],
        )
        .unwrap();
        assert!(!root.join("d/old1").exists());
        assert!(!root.join("d/old2").exists());
        assert_eq!(fs::read(root.join("d/new")).unwrap(), b"3");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn later_layer_overwrites_file() {
        let root = tmpdir("ovr");
        apply_layer_tar(&root, &tar_with(&[("f", b"old")], &[])[..]).unwrap();
        apply_layer_tar(&root, &tar_with(&[("f", b"new")], &[])[..]).unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"new");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hard_link_resolves_relative_to_the_root() {
        // busybox-style: a real binary + applets that are hard links to it. The
        // link target must resolve under the rootfs, not the process CWD.
        let root = tmpdir("hardlink");
        let mut builder = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_mode(0o755);
        dh.set_size(0);
        builder
            .append_data(&mut dh, "bin", std::io::empty())
            .unwrap();
        let content = b"#!busybox\n";
        let mut fh = tar::Header::new_gnu();
        fh.set_mode(0o755);
        fh.set_size(content.len() as u64);
        builder
            .append_data(&mut fh, "bin/busybox", &content[..])
            .unwrap();
        let mut lh = tar::Header::new_gnu();
        lh.set_entry_type(tar::EntryType::Link);
        lh.set_mode(0o755);
        lh.set_size(0);
        builder
            .append_link(&mut lh, "bin/[", "bin/busybox")
            .unwrap();
        // A second applet whose link target is *absolute* — normalized to
        // root-relative (leading `/` stripped), not rejected.
        let mut lh2 = tar::Header::new_gnu();
        lh2.set_entry_type(tar::EntryType::Link);
        lh2.set_mode(0o755);
        lh2.set_size(0);
        builder
            .append_link(&mut lh2, "bin/sh", "/bin/busybox")
            .unwrap();
        let tar = builder.into_inner().unwrap();

        apply_layer_tar(&root, &tar[..]).unwrap();
        assert_eq!(fs::read(root.join("bin/busybox")).unwrap(), content);
        assert_eq!(
            fs::read(root.join("bin/[")).unwrap(),
            content,
            "relative hard link resolved to its target's content"
        );
        assert_eq!(
            fs::read(root.join("bin/sh")).unwrap(),
            content,
            "absolute hard link target normalized to root-relative"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn link_target_normalizes_absolute_and_refuses_escape() {
        let root = Path::new("/rootfs");
        // A relative target and an absolute one both resolve under the root.
        assert_eq!(
            link_target_under_root(root, Path::new("bin/busybox")).unwrap(),
            PathBuf::from("/rootfs/bin/busybox")
        );
        assert_eq!(
            link_target_under_root(root, Path::new("/bin/busybox")).unwrap(),
            PathBuf::from("/rootfs/bin/busybox"),
            "absolute target is treated as root-relative"
        );
        // A `..` escape is refused.
        assert!(matches!(
            link_target_under_root(root, Path::new("../escape")),
            Err(OciError::UnsafePath(_))
        ));
    }

    #[test]
    fn parse_reference_handles_registries_tags_and_library() {
        assert_eq!(
            parse_reference("nginx"),
            (
                "registry-1.docker.io".into(),
                "library/nginx".into(),
                "latest".into()
            )
        );
        assert_eq!(
            parse_reference("nginx:1.27"),
            (
                "registry-1.docker.io".into(),
                "library/nginx".into(),
                "1.27".into()
            )
        );
        assert_eq!(
            parse_reference("ghcr.io/owner/app:v2"),
            ("ghcr.io".into(), "owner/app".into(), "v2".into())
        );
        assert_eq!(
            parse_reference("registry.example.com:5000/team/svc@sha256:abc"),
            (
                "registry.example.com:5000".into(),
                "team/svc".into(),
                "sha256:abc".into()
            )
        );
    }

    #[test]
    fn path_traversal_guard_refuses_escapes() {
        // The tar crate sanitizes `..` when *writing* a fixture, so test the
        // guard directly — it's what protects extraction from a hostile layer.
        assert!(matches!(
            safe_relative(Path::new("../escape")),
            Err(OciError::UnsafePath(_))
        ));
        assert!(matches!(
            safe_relative(Path::new("/etc/passwd")),
            Err(OciError::UnsafePath(_))
        ));
        assert!(matches!(
            safe_relative(Path::new("a/../../b")),
            Err(OciError::UnsafePath(_))
        ));
        // A normal nested path is kept, with `./` stripped.
        assert_eq!(
            safe_relative(Path::new("./app/bin/run")).unwrap(),
            PathBuf::from("app/bin/run")
        );
    }

    #[test]
    fn effective_argv_prefers_override_then_image() {
        let cfg = ImageConfig {
            entrypoint: vec!["/bin/server".into()],
            cmd: vec!["--default".into()],
            ..Default::default()
        };
        // Override wins outright.
        assert_eq!(
            effective_argv(&cfg, &["/run".to_string(), "now".to_string()]).unwrap(),
            vec!["/run".to_string(), "now".to_string()]
        );
        // No override ⇒ Entrypoint then Cmd.
        assert_eq!(
            effective_argv(&cfg, &[]).unwrap(),
            vec!["/bin/server".to_string(), "--default".to_string()]
        );
        // Nothing to run ⇒ a build error, not a broken boot.
        assert!(matches!(
            effective_argv(&ImageConfig::default(), &[]),
            Err(OciError::Registry(_))
        ));
    }

    #[test]
    fn effective_env_overrides_image_and_appends_new() {
        let cfg = ImageConfig {
            env: vec!["PATH=/img/bin".into(), "FOO=bar".into()],
            ..Default::default()
        };
        let env = effective_env(
            &cfg,
            &[
                ("FOO".to_string(), "baz".to_string()), // overrides the image's FOO
                ("EXTRA".to_string(), "1".to_string()), // new key appended
            ],
        );
        assert_eq!(
            env,
            vec![
                "PATH=/img/bin".to_string(),
                "FOO=baz".to_string(),
                "EXTRA=1".to_string(),
            ]
        );
    }

    #[test]
    fn nul_join_terminates_each_string() {
        assert_eq!(
            nul_join(&["/srv".to_string(), "-p".to_string(), "80".to_string()]),
            b"/srv\0-p\080\0"
        );
        assert_eq!(nul_join(&[]), b"");
    }

    #[test]
    fn resolve_argv0_searches_path_in_the_rootfs() {
        let root = tmpdir("argv0");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/httpd"), b"x").unwrap();
        let env = vec!["PATH=/usr/bin:/bin".to_string()];
        // A bare command resolves to its absolute path within the rootfs.
        assert_eq!(resolve_argv0(&root, "httpd", &env), "/bin/httpd");
        // An already-pathful argv0 is left as-is.
        assert_eq!(resolve_argv0(&root, "/sbin/foo", &env), "/sbin/foo");
        // An unfound bare command is left bare (fails visibly in the guest init).
        assert_eq!(resolve_argv0(&root, "nope", &env), "nope");
        fs::remove_dir_all(&root).unwrap();
    }

    // ---- U15 part 1: symlink-traversal containment ----

    /// Build a tar containing a symlink entry `path -> target` (verbatim target).
    fn tar_symlink_then(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
        // Each entry is (kind, path, data): kind "L" = symlink (data is the
        // target as bytes), "F" = regular file, "W" = whiteout/other file.
        let mut builder = tar::Builder::new(Vec::new());
        for (kind, path, data) in entries {
            let mut h = tar::Header::new_gnu();
            if *kind == "L" {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_mode(0o777);
                h.set_size(0);
                let target = std::str::from_utf8(data).unwrap();
                builder.append_link(&mut h, path, target).unwrap();
            } else {
                h.set_mode(0o644);
                h.set_size(data.len() as u64);
                builder.append_data(&mut h, path, *data).unwrap();
            }
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn planted_symlink_unpack_is_contained_in_root() {
        // A layer plants `evil -> <absolute path outside root>`, then writes
        // `evil/pwned`. RESOLVE_IN_ROOT reinterprets the absolute symlink target
        // root-relative, so the write lands INSIDE root — never on the host.
        let root = tmpdir("sym-write");
        let sentinel = tmpdir("sym-write-escape");
        fs::create_dir_all(&sentinel).unwrap();
        let tar = tar_symlink_then(&[
            ("L", "evil", sentinel.to_str().unwrap().as_bytes()),
            ("F", "evil/pwned", b"PWNED"),
        ]);
        apply_layer_tar(&root, &tar[..]).unwrap();
        assert!(
            !sentinel.join("pwned").exists(),
            "the write must NOT have escaped to the host sentinel"
        );
        // It materialized in-root at the chroot-reinterpreted location.
        let landed = resolve_in_root(&root, Path::new("evil/pwned")).unwrap();
        assert!(landed.starts_with(&root), "{landed:?} must be under root");
        assert_eq!(fs::read(&landed).unwrap(), b"PWNED");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn whiteout_through_symlink_is_contained_in_root() {
        // `evil -> <absolute sentinel>`; a whiteout `evil/.wh.victim` stays in-root
        // (the sentinel's HOST file is never deleted).
        let root = tmpdir("sym-wh");
        let sentinel = tmpdir("sym-wh-escape");
        fs::create_dir_all(&sentinel).unwrap();
        fs::write(sentinel.join("victim"), b"keep").unwrap();
        let tar = tar_symlink_then(&[
            ("L", "evil", sentinel.to_str().unwrap().as_bytes()),
            ("W", "evil/.wh.victim", b""),
        ]);
        apply_layer_tar(&root, &tar[..]).unwrap();
        assert!(
            sentinel.join("victim").exists(),
            "the host sentinel's file must NOT have been deleted through the symlink"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn opaque_whiteout_through_symlink_is_contained_in_root() {
        // An opaque whiteout whose dir is a planted absolute symlink is resolved
        // in-root — it never `read_dir`s + wipes the HOST symlink target.
        let root = tmpdir("sym-opq");
        let sentinel = tmpdir("sym-opq-escape");
        fs::create_dir_all(&sentinel).unwrap();
        fs::write(sentinel.join("keep"), b"x").unwrap();
        let tar = tar_symlink_then(&[
            ("L", "evil", sentinel.to_str().unwrap().as_bytes()),
            ("W", "evil/.wh..wh..opq", b""),
        ]);
        apply_layer_tar(&root, &tar[..]).unwrap();
        assert!(
            sentinel.join("keep").exists(),
            "the host sentinel dir must NOT have been cleared through the symlink"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn hard_link_through_symlink_does_not_exfil_host_file() {
        // `evil -> <absolute host file>`; a hard link `loot -> evil`. RESOLVE_IN_ROOT
        // reinterprets the symlink target root-relative, so the link/copy can only
        // ever reach an in-root path (absent here) — the host file is never pulled in.
        let root = tmpdir("sym-link");
        let sentinel = tmpdir("sym-link-escape");
        fs::create_dir_all(&sentinel).unwrap();
        let secret = sentinel.join("secret");
        fs::write(&secret, b"topsecret").unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        // Plant `evil -> <abs path to a host secret>`.
        let mut lh = tar::Header::new_gnu();
        lh.set_entry_type(tar::EntryType::Symlink);
        lh.set_mode(0o777);
        lh.set_size(0);
        builder
            .append_link(&mut lh, "evil", secret.to_str().unwrap())
            .unwrap();
        // A hard link `loot` whose target is the planted symlink.
        let mut hh = tar::Header::new_gnu();
        hh.set_entry_type(tar::EntryType::Link);
        hh.set_mode(0o644);
        hh.set_size(0);
        builder.append_link(&mut hh, "loot", "evil").unwrap();
        let tar = builder.into_inner().unwrap();

        // The in-root reinterpreted target does not exist → the link/copy fails; the
        // load-bearing property is that the host secret is never exfiltrated.
        let _ = apply_layer_tar(&root, &tar[..]);
        let leaked = fs::read(root.join("loot")).ok();
        assert!(
            leaked.as_deref() != Some(b"topsecret".as_slice()),
            "the host file must NOT have been exfiltrated into the image"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn legit_symlink_entry_is_stored_verbatim_not_followed() {
        // A normal symlink entry is created as-is (resolved inside the guest, not
        // the host) — the hardening must not break ordinary images.
        let root = tmpdir("sym-ok");
        let tar = tar_symlink_then(&[("F", "real", b"R"), ("L", "ln", b"real")]);
        apply_layer_tar(&root, &tar[..]).unwrap();
        let meta = fs::symlink_metadata(root.join("ln")).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink stored verbatim");
        assert_eq!(fs::read_link(root.join("ln")).unwrap(), Path::new("real"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(unix)]
    fn resolve_in_root_follows_in_root_symlinks_and_contains_escapes() {
        use std::os::unix::fs::symlink;
        let root = tmpdir("riroot");
        fs::create_dir_all(root.join("usr/sbin")).unwrap();
        // usrmerge: `sbin -> usr/sbin` (relative, in-root) is FOLLOWED (compat).
        symlink("usr/sbin", root.join("sbin")).unwrap();
        assert_eq!(
            resolve_in_root(&root, Path::new("sbin/tool")).unwrap(),
            root.join("usr/sbin/tool"),
            "a legitimate in-root symlink dir must be followed (usrmerge compat)"
        );
        // An absolute-target symlink is reinterpreted root-relative (contained).
        symlink("/etc/cron.d", root.join("escape")).unwrap();
        assert_eq!(
            resolve_in_root(&root, Path::new("escape/x")).unwrap(),
            root.join("etc/cron.d/x"),
            "an absolute symlink target must be chrooted into root"
        );
        // `..` cannot climb above root.
        assert_eq!(
            resolve_in_root(&root, Path::new("usr/../../../../etc")).unwrap(),
            root.join("etc"),
            ".. must be clamped at root"
        );
        // A leaf symlink is returned un-dereferenced for the caller to unlink.
        symlink("/elsewhere", root.join("leaf")).unwrap();
        assert_eq!(
            resolve_parent_in_root(&root, Path::new("leaf")).unwrap(),
            root.join("leaf"),
            "resolve_parent leaves the leaf raw"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(unix)]
    fn contained_write_unlinks_a_planted_leaf_symlink() {
        use std::os::unix::fs::symlink;
        // A planted leaf symlink at the destination must be UNLINKED (not followed)
        // before writing, so the write can't be redirected onto the symlink target.
        let root = tmpdir("cw-leaf");
        let outside = tmpdir("cw-leaf-out");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim");
        fs::write(&victim, b"original").unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        symlink(&victim, root.join("etc/resolv.conf")).unwrap();
        let dest = contained_write(
            &root,
            Path::new("etc/resolv.conf"),
            b"nameserver 10.0.0.1\n",
        )
        .unwrap();
        assert_eq!(
            fs::read(&victim).unwrap(),
            b"original",
            "the host file behind the planted symlink must be untouched"
        );
        assert!(
            !fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(root.join("etc/resolv.conf")).unwrap(),
            b"nameserver 10.0.0.1\n"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    #[cfg(unix)]
    fn write_init_contains_planted_sbin_and_etc_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        // The CRITICAL regression: a hostile layer plants `sbin` + `etc` as
        // absolute symlinks to host dirs. `write_init`'s writes (the 0755 init ELF,
        // the exec spec, resolv.conf) must stay INSIDE root, never landing on the
        // host via the planted symlink.
        let root = tmpdir("wi-sym");
        let sbin_sent = tmpdir("wi-sym-sbin");
        let etc_sent = tmpdir("wi-sym-etc");
        fs::create_dir_all(&sbin_sent).unwrap();
        fs::create_dir_all(&etc_sent).unwrap();
        let tar = tar_symlink_then(&[
            ("L", "sbin", sbin_sent.to_str().unwrap().as_bytes()),
            ("L", "etc", etc_sent.to_str().unwrap().as_bytes()),
        ]);
        apply_layer_tar(&root, &tar[..]).unwrap();

        let cfg = ImageConfig {
            entrypoint: vec!["/bin/true".into()],
            ..Default::default()
        };
        write_init(
            &root,
            &["/bin/true".to_string()],
            &cfg,
            &[],
            &["/data".to_string()],
        )
        .unwrap();

        // Nothing escaped onto the HOST sentinels.
        assert!(
            !sbin_sent.join("init").exists(),
            "the init ELF escaped onto the host via the sbin symlink"
        );
        assert!(
            !etc_sent.join("boatramp").exists(),
            "the exec spec escaped onto the host via the etc symlink"
        );
        assert!(
            !etc_sent.join("resolv.conf").exists(),
            "resolv.conf escaped onto the host via the etc symlink"
        );
        // The init materialized INSIDE root (chroot-reinterpreted), mode 0755.
        let init = resolve_in_root(&root, Path::new("sbin/init")).unwrap();
        assert!(
            init.starts_with(&root) && init.exists(),
            "init must exist inside root: {init:?}"
        );
        assert_eq!(
            fs::symlink_metadata(&init).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sbin_sent);
        let _ = fs::remove_dir_all(&etc_sent);
    }

    // ---- U15 part 2: registry/realm SSRF guard ----

    #[test]
    fn malicious_realm_ssrf_is_refused() {
        // A non-https realm (http, or any other scheme) is refused outright.
        assert!(matches!(
            parse_realm("http://169.254.169.254/token"),
            Err(OciError::Registry(_))
        ));
        assert!(matches!(
            parse_realm("gopher://internal/x"),
            Err(OciError::Registry(_))
        ));

        // URLs whose host is a non-global literal IP are refused by the eager host screen
        // (a literal-IP URL never reaches the DNS resolver). Hermetic — no DNS.
        for ip in [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
        ] {
            assert!(
                matches!(
                    screen_pull_url(&format!("https://{ip}/token")),
                    Err(OciError::Registry(_))
                ),
                "{ip} (link-local/private/loopback) must be refused"
            );
        }
        for ip in ["::1", "fe80::1", "fc00::1"] {
            assert!(
                matches!(
                    screen_pull_url(&format!("https://[{ip}]:443/token")),
                    Err(OciError::Registry(_))
                ),
                "{ip} (v6 loopback/link-local/unique-local) must be refused"
            );
        }

        // A public literal IP passes the eager screen; a hostname passes it too
        // (it is screened later, at DNS resolution, by `ScreeningResolver`).
        screen_pull_url("https://1.1.1.1/token").unwrap();
        screen_pull_url("https://registry.example.com/token").unwrap();
    }

    #[test]
    fn noncanonical_ip_literal_hosts_are_decoded_and_refused() {
        // Security HIGH (parser-differential SSRF bypass): Rust's strict `str::parse::<IpAddr>`
        // REJECTS these non-canonical IPv4 literals, but the WHATWG url parser (reqwest) DECODES
        // them to 169.254.169.254 and connects straight to it — never invoking `ScreeningResolver`.
        // The screen MUST parse the host the same way and refuse them (metadata, un-exemptable).
        for metadata_form in [
            "https://0xa9fea9fe:443/x",      // hex single-number
            "https://2852039166/x",          // decimal single-number
            "https://0251.0376.0251.0376/x", // octal dotted
            "https://169.254.169.254/x",     // canonical (control)
            "https://0xa9.0xfe.0xa9.0xfe/x", // hex dotted
            "https://169.16689150/x",        // short form (a.b where b is 24-bit)
        ] {
            // Sanity: the RAW lexical host would have slipped the old strict parse for the
            // non-canonical forms — prove the normalized screen refuses the connect target.
            assert!(
                matches!(screen_pull_url(metadata_form), Err(OciError::Registry(_))),
                "{metadata_form} decodes to cloud-metadata and MUST be refused"
            );
        }

        // (A benign-looking NON-canonical internal literal — `0x0a2a0009` = 10.42.0.9 — is
        // refused-by-default-unless-allow-listed in `noncanonical_literal_is_permitted_only_when_allow_listed`,
        // which owns the process-global allow-list; kept out of this test so the two never race.)

        // An ambiguous / overflowing host literal fails CLOSED (url parse refuses it).
        assert!(matches!(
            screen_pull_url("https://0xffffffffff/x"),
            Err(OciError::Registry(_))
        ));

        // A normal public registry (hostname) still works — left to the resolver at connect.
        screen_pull_url("https://registry-1.docker.io/v2/library/alpine").unwrap();
        // A public literal IP in canonical form still works.
        screen_pull_url("https://1.1.1.1/v2/x").unwrap();
    }

    #[test]
    fn noncanonical_literal_is_permitted_only_when_allow_listed() {
        // The allow-list honors the DECODED address: `0x0a2a0009` = 10.42.0.9 is refused by
        // default but permitted once the operator allow-lists its /32 — proving the fix routes
        // the normalized literal through the SAME `address_is_refused` decision (allow-list +
        // un-exemptable metadata). Mutates the process-global, so it runs in its own test.
        assert!(matches!(
            screen_pull_url("https://0x0a2a0009:443/x"),
            Err(OciError::Registry(_))
        ));
        install_private_registry_allowlist(&PrivateRegistryAllowlist {
            hosts: vec![],
            cidrs: vec!["10.42.0.9/32".into()],
        })
        .unwrap();
        // Now the decoded internal literal is permitted.
        screen_pull_url("https://0x0a2a0009:443/x").unwrap();
        // But a decoded-metadata literal is STILL refused, even though 169.254.0.0/16 is not
        // allow-listed here — and would be refused even if it were (metadata is un-exemptable).
        assert!(matches!(
            screen_pull_url("https://0xa9fea9fe/x"),
            Err(OciError::Registry(_))
        ));
        // Restore the block-all default so no other test sees the allow-list.
        install_private_registry_allowlist(&PrivateRegistryAllowlist::default()).unwrap();
    }

    #[test]
    fn ipv4_mapped_v6_metadata_is_refused() {
        // `::ffff:169.254.169.254` must be screened via its mapped v4 form
        // (`to_canonical` collapses it back to IPv4).
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(ip_is_disallowed(mapped));
        // v4 multicast (224/4) is also blocked.
        assert!(ip_is_disallowed("224.0.0.1".parse().unwrap()));
        // And a plain public v4 is allowed.
        assert!(!ip_is_disallowed("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_transition_forms_embedding_private_v4_are_refused() {
        let v6 = |a, b, c, d, e, f, g, h| IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));
        // v4-compatible `::169.254.169.254` (cloud metadata) — `to_canonical` does
        // NOT unwrap this, so it must be decoded + screened explicitly.
        assert!(ip_is_disallowed(v6(0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe)));
        // 6to4 `2002::/16` wrapping link-local 169.254.169.254.
        assert!(ip_is_disallowed(v6(0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0)));
        // 6to4 wrapping RFC-1918 10.0.0.1.
        assert!(ip_is_disallowed(v6(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 0)));
        // Teredo `2001:0000::/32` whose obfuscated client v4 is 127.0.0.1
        // (127.0.0.1 XOR 255.255.255.255 = 128.255.255.254 = 80ff:fffe).
        assert!(ip_is_disallowed(v6(0x2001, 0, 0, 0, 0, 0, 0x80ff, 0xfffe)));
        // A genuine global IPv6 (Cloudflare DNS) is still allowed.
        assert!(!ip_is_disallowed(v6(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        )));
        // A 6to4 wrapping a PUBLIC v4 (1.1.1.1) stays allowed (no over-block).
        assert!(!ip_is_disallowed(v6(0x2002, 0x0101, 0x0101, 0, 0, 0, 0, 0)));
    }

    // ---- U25: operator allow-list for private/internal registries ----

    #[test]
    fn private_registry_allowlist_permits_configured_blocks_unconfigured_and_metadata() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        // Fail-closed when UNSET: the empty (default) allow-list refuses every non-global
        // address, exactly as before this opt-in existed.
        let empty = CompiledAllowlist::default();
        assert!(address_is_refused_with(
            Some("registry.internal"),
            ip("10.42.0.9"),
            &empty
        ));
        assert!(address_is_refused_with(None, ip("10.42.0.9"), &empty));
        // A globally-routable address is always fine (allow-list irrelevant).
        assert!(!address_is_refused_with(
            Some("ghcr.io"),
            ip("140.82.121.33"),
            &empty
        ));

        // An operator allow-list naming a host + its CIDRs.
        let allow = CompiledAllowlist::compile(&PrivateRegistryAllowlist {
            hosts: vec!["Registry.Internal".into()], // case-insensitive
            cidrs: vec!["10.42.0.0/16".into(), "fd00::/8".into()],
        })
        .unwrap();

        // Permits the configured host (matched by NAME) resolving into a private address.
        assert!(!address_is_refused_with(
            Some("registry.internal"),
            ip("10.42.0.9"),
            &allow
        ));
        // Permits any address inside an allowed CIDR, even for a host not named.
        assert!(!address_is_refused_with(
            Some("other.host"),
            ip("10.42.1.2"),
            &allow
        ));
        assert!(!address_is_refused_with(
            Some("reg6.internal"),
            ip("fd00::1"),
            &allow
        ));

        // Blocks an UNCONFIGURED private address — a different RFC-1918 range stays refused.
        assert!(address_is_refused_with(
            Some("other.host"),
            ip("192.168.1.1"),
            &allow
        ));
        assert!(address_is_refused_with(
            Some("other.host"),
            ip("172.16.0.1"),
            &allow
        ));
        // A host NOT on the list resolving outside every allowed CIDR is refused.
        assert!(address_is_refused_with(
            Some("evil.test"),
            ip("10.99.0.1"),
            &allow
        ));

        // ALWAYS blocks cloud metadata even when the host IS allow-listed.
        assert!(address_is_refused_with(
            Some("registry.internal"),
            ip("169.254.169.254"),
            &allow
        ));

        // Metadata wins even over a (foolishly) broad CIDR that would contain it.
        let broad = CompiledAllowlist::compile(&PrivateRegistryAllowlist {
            hosts: vec![],
            cidrs: vec![
                "169.254.0.0/16".into(),
                "100.64.0.0/10".into(),
                "fd00::/8".into(),
            ],
        })
        .unwrap();
        assert!(
            address_is_refused_with(Some("x"), ip("169.254.169.254"), &broad),
            "169.254.169.254 metadata wins over a link-local CIDR allow"
        );
        assert!(
            address_is_refused_with(Some("x"), ip("100.100.100.200"), &broad),
            "Alibaba metadata wins over a CGNAT CIDR allow"
        );
        assert!(
            address_is_refused_with(Some("x"), ip("fd00:ec2::254"), &broad),
            "AWS IMDSv6 wins over a ULA CIDR allow"
        );
        // A non-metadata ULA address in the allowed range is still permitted.
        assert!(!address_is_refused_with(
            Some("x"),
            ip("fd00::1234"),
            &broad
        ));
    }

    #[test]
    fn private_registry_allowlist_compile_rejects_a_malformed_cidr() {
        assert!(
            CompiledAllowlist::compile(&PrivateRegistryAllowlist {
                hosts: vec![],
                cidrs: vec!["not-a-cidr".into()],
            })
            .is_err(),
            "a malformed CIDR fails config load CLOSED"
        );
        // The default is empty (block-all).
        let def = PrivateRegistryAllowlist::default();
        assert!(def.hosts.is_empty() && def.cidrs.is_empty());
        let compiled = CompiledAllowlist::compile(&def).unwrap();
        assert!(compiled.hosts.is_empty() && compiled.cidrs.is_empty());
    }

    #[test]
    fn split_host_port_parses_authorities() {
        assert_eq!(
            split_host_port("ghcr.io").unwrap(),
            ("ghcr.io".to_string(), 443)
        );
        assert_eq!(
            split_host_port("reg.example.com:5000").unwrap(),
            ("reg.example.com".to_string(), 5000)
        );
        assert_eq!(
            split_host_port("[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
        assert_eq!(
            split_host_port("[fe80::1]").unwrap(),
            ("fe80::1".to_string(), 443)
        );
        assert!(split_host_port("host:notaport").is_err());
    }

    // ---- A1: manifest digest-pin integrity ----

    #[test]
    fn manifest_digest_verify_sha256_sha512_and_fail_closed() {
        use sha2::{Digest, Sha256, Sha512};
        let body = br#"{"schemaVersion":2,"layers":[]}"#;
        // Correct sha256 AND sha512 pins verify.
        verify_digest(
            body,
            &format!("sha256:{}", hex::encode(Sha256::digest(body))),
        )
        .unwrap();
        verify_digest(
            body,
            &format!("sha512:{}", hex::encode(Sha512::digest(body))),
        )
        .unwrap();
        // A wrong digest pin is refused (a MITM/malicious registry serving a
        // different self-consistent manifest for a pinned ref).
        assert!(matches!(
            verify_digest(
                body,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ),
            Err(OciError::Registry(_))
        ));
        // FAIL CLOSED: an unknown / unsupported algorithm is REJECTED, not waved
        // through as "verified" (an OCI-legal `@sha512:`/future-algo pin the caller
        // believes is enforced must never be trusted-from-registry unverified).
        assert!(matches!(
            verify_digest(body, "sha999:deadbeef"),
            Err(OciError::Registry(_))
        ));
        assert!(matches!(
            verify_digest(body, "md5:abc"),
            Err(OciError::Registry(_))
        ));
        // A malformed digest (no `algo:` prefix) is rejected too.
        assert!(matches!(
            verify_digest(body, "latest"),
            Err(OciError::Registry(_))
        ));
    }

    // ---- minor: overridable VMM nameserver ----

    #[test]
    fn resolv_conf_nameserver_default_override_and_sanitize() {
        // Default when unset.
        assert_eq!(resolv_conf_body(None), "nameserver 1.1.1.1\n");
        // A valid IP override is honored.
        assert_eq!(resolv_conf_body(Some("10.0.0.1")), "nameserver 10.0.0.1\n");
        assert_eq!(resolv_conf_body(Some(" 8.8.8.8 ")), "nameserver 8.8.8.8\n");
        // A malformed / injection attempt falls back to the default (not an IP).
        assert_eq!(
            resolv_conf_body(Some("6.6.6.6\nnameserver 7.7.7.7")),
            "nameserver 1.1.1.1\n"
        );
    }

    // ---- U30: bound the registry pull with timeouts ----

    /// Serialize the tests that mutate the process-global pull timeouts/limits, so the suite's
    /// default parallelism can't let one test observe another's installed values. Poison-tolerant
    /// (a panicking test must not wedge the rest). Held across awaits — the `#[tokio::test]`
    /// current-thread runtime does not require the guard to be `Send`.
    fn pull_globals_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Read an HTTP request's bytes off a loopback test socket (enough to let the client finish
    /// sending before the server responds). A single read captures the small GET on loopback.
    fn drain_http_request(stream: &mut std::net::TcpStream) {
        use std::io::Read as _;
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf);
    }

    #[test]
    fn registry_pull_timeouts_default_and_install_round_trip() {
        let _guard = pull_globals_lock();
        // The built-in defaults are the documented, defensible bounds.
        let def = RegistryPullTimeouts::default();
        assert_eq!(def.connect_secs, 10);
        assert_eq!(def.read_secs, 30);
        assert_eq!(def.response_secs, 120);
        assert_eq!(def.overall_pull_secs, 600);
        // `dur` maps seconds → Duration, and `0` disables a bound.
        assert_eq!(RegistryPullTimeouts::dur(10), Some(Duration::from_secs(10)));
        assert_eq!(RegistryPullTimeouts::dur(0), None);

        // Installing a config is honored by the process-globals the pull reads.
        install_registry_pull_timeouts(RegistryPullTimeouts {
            connect_secs: 3,
            read_secs: 4,
            response_secs: 0,     // disables the per-request overall cap
            overall_pull_secs: 0, // disables the whole-pull deadline
        });
        let got = registry_pull_timeouts();
        assert_eq!(
            (
                got.connect_secs,
                got.read_secs,
                got.response_secs,
                got.overall_pull_secs
            ),
            (3, 4, 0, 0)
        );
        assert_eq!(small_request_overall_timeout(), None, "0 ⇒ no overall cap");
        assert_eq!(overall_pull_timeout(), None, "0 ⇒ no whole-pull deadline");
        // Restore the defaults so no other test observes the mutated global.
        install_registry_pull_timeouts(RegistryPullTimeouts::default());
        assert_eq!(
            small_request_overall_timeout(),
            Some(Duration::from_secs(120))
        );
        assert_eq!(overall_pull_timeout(), Some(Duration::from_secs(600)));
    }

    #[tokio::test]
    // The serialization guard is deliberately held across `.await`: each `#[tokio::test]` runs on
    // its OWN current-thread runtime, so holding a std mutex over an await serializes the
    // process-global pull config across the parallel TEST THREADS without any deadlock risk.
    #[allow(clippy::await_holding_lock)]
    async fn pull_client_fails_in_bounded_time_against_a_dead_endpoint() {
        let _guard = pull_globals_lock();
        // A registry that ACCEPTS the connection and then NEVER answers must not hang the pull
        // forever — the connect+read/idle bounds (and the per-request overall cap) make it fail
        // in bounded time. Hermetic: a loopback listener that accepts + holds the socket without
        // ever writing a response byte. (The SSRF screen does not fire here — reqwest connects to
        // a literal-IP host without consulting `ScreeningResolver`, exactly the surface we test.)
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Accept connections and HOLD them open (never respond) for the test's lifetime.
            let mut held = Vec::new();
            while held.len() < 16 {
                match listener.accept() {
                    Ok((stream, _)) => held.push(stream),
                    Err(_) => break,
                }
            }
            std::thread::sleep(Duration::from_secs(30));
            drop(held);
        });

        // Install tight bounds so a bounded failure is quick + unambiguous.
        install_registry_pull_timeouts(RegistryPullTimeouts {
            connect_secs: 2,
            read_secs: 1,
            response_secs: 2,
            overall_pull_secs: 5,
        });
        let client = screening_client().unwrap();
        let url = format!("http://{addr}/v2/");

        // (a) The shared client's read/idle timeout bounds a never-answering endpoint — no
        // per-request overall cap applied, so this exercises `read_timeout` specifically.
        let start = std::time::Instant::now();
        let res = client.get(&url).send().await;
        let elapsed = start.elapsed();
        assert!(res.is_err(), "a dead endpoint must fail, not hang");
        assert!(
            elapsed < Duration::from_secs(10),
            "read/idle timeout must bound the failure (took {elapsed:?})"
        );

        // (b) The overall per-request cap (`.timeout(...)`) also bounds it — the explicit
        // control-plane cap used for token + manifest GETs.
        let start = std::time::Instant::now();
        let res = client
            .get(&url)
            .timeout(Duration::from_secs(1))
            .send()
            .await;
        let elapsed = start.elapsed();
        assert!(
            res.is_err(),
            "the overall request cap must fail a dead endpoint"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "overall timeout must bound the failure (took {elapsed:?})"
        );

        // Restore the defaults so no other test observes the mutated global.
        install_registry_pull_timeouts(RegistryPullTimeouts::default());
    }

    // ---- U31: typed, message-preserving SSRF refusal on the hostname path ----

    #[tokio::test]
    async fn hostname_ssrf_refusal_carries_the_allowlist_hint() {
        // The HOSTNAME path: a registry named by host that resolves to a non-global address is
        // refused INSIDE the DNS resolver. The refusal must reach the caller as a TYPED,
        // message-preserving error that names the refused host AND points at
        // `[compute].allow_private_registries` — not the generic reqwest transport string that
        // swallowed the hint before (U31). Hermetic: `localhost` resolves to loopback via
        // /etc/hosts with no network.
        let client = screening_client().unwrap();
        let err = client
            .get("http://localhost:9/v2/")
            .send()
            .await
            .expect_err("a loopback-resolving hostname must be refused by the SSRF screen");
        let mapped = reqwest_err(&err);
        let OciError::Registry(msg) = mapped else {
            panic!("expected OciError::Registry, got {mapped:?}");
        };
        assert!(
            msg.contains("localhost"),
            "the typed refusal must name the refused host, got: {msg}"
        );
        assert!(
            msg.contains("allow_private_registries"),
            "the typed refusal must carry the actionable allow-list hint, got: {msg}"
        );
        // It must NOT be the generic reqwest transport string (which would have hidden the hint).
        assert!(
            !msg.starts_with("error sending request"),
            "the generic transport message leaked instead of the typed refusal: {msg}"
        );
    }

    #[test]
    fn reqwest_err_without_a_screen_refusal_falls_back_to_transport_message() {
        // When the failure is an ordinary transport error (no SSRF refusal in the chain),
        // `reqwest_err` falls back to reqwest's own message — it never fabricates a hint.
        let client = reqwest::Client::new();
        // A syntactically bad URL yields a reqwest builder error with no `ScreenRefusal` source.
        let err = client.get("http://[::bad url").build().unwrap_err();
        let OciError::Registry(msg) = reqwest_err(&err) else {
            panic!("expected OciError::Registry");
        };
        assert!(
            !msg.contains("allow_private_registries"),
            "a non-screen error must not gain an allow-list hint, got: {msg}"
        );
    }

    // ---- Security HIGH follow-up: overall deadline + byte ceilings (anti-DoS / anti-OOM) ----

    #[test]
    fn registry_pull_limits_default_install_round_trip_and_blob_cap() {
        let _guard = pull_globals_lock();
        // The built-in ceilings are generous (no real image refused) but finite.
        let def = RegistryPullLimits::default();
        assert_eq!(def.max_layer_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(def.max_image_bytes, 20 * 1024 * 1024 * 1024);
        assert_eq!(def.max_manifest_bytes, 32 * 1024 * 1024);
        assert_eq!(def.max_decompressed_layer_bytes, 32 * 1024 * 1024 * 1024);
        assert_eq!(def.max_rootfs_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(def.max_tar_entries, 500_000);
        // `cap` maps a byte count → ceiling; `0` disables it.
        assert_eq!(RegistryPullLimits::cap(123), Some(123));
        assert_eq!(RegistryPullLimits::cap(0), None);

        // With a 1 KiB per-LAYER ceiling and a distinct 2 KiB per-MANIFEST ceiling installed,
        // `blob_cap` reads the layer knob and `manifest_cap` reads the manifest knob — each is the
        // TIGHTER of the declared size and its own operator ceiling (the two paths are decoupled).
        install_registry_pull_limits(RegistryPullLimits {
            max_layer_bytes: 1024,
            max_image_bytes: 0, // whole-image ceiling disabled
            max_manifest_bytes: 2048,
            max_decompressed_layer_bytes: 0, // decompressed ceilings irrelevant to blob/manifest_cap
            max_rootfs_bytes: 0,
            max_tar_entries: 0,
        });
        assert_eq!(
            blob_cap(None),
            Some(1024),
            "layer ceiling with no declared size"
        );
        assert_eq!(
            blob_cap(Some(512)),
            Some(512),
            "declared size is tighter → wins"
        );
        assert_eq!(
            blob_cap(Some(4096)),
            Some(1024),
            "layer ceiling is tighter → wins"
        );
        assert_eq!(
            blob_cap(Some(0)),
            Some(1024),
            "a 0 declared size is ignored"
        );
        // `manifest_cap` is governed by `max_manifest_bytes`, NOT `max_layer_bytes` (decoupled).
        assert_eq!(
            manifest_cap(None),
            Some(2048),
            "manifest ceiling with no declared size (not the 1 KiB layer ceiling)"
        );
        assert_eq!(
            manifest_cap(Some(512)),
            Some(512),
            "declared config size is tighter → wins"
        );
        assert_eq!(
            manifest_cap(Some(4096)),
            Some(2048),
            "manifest ceiling is tighter → wins"
        );
        assert_eq!(
            manifest_cap(Some(0)),
            Some(2048),
            "a 0 declared size is ignored"
        );

        // Disabling both operator ceilings leaves only the declared size on each path.
        install_registry_pull_limits(RegistryPullLimits {
            max_layer_bytes: 0,
            max_image_bytes: 0,
            max_manifest_bytes: 0,
            max_decompressed_layer_bytes: 0,
            max_rootfs_bytes: 0,
            max_tar_entries: 0,
        });
        assert_eq!(
            blob_cap(None),
            None,
            "no layer ceiling + no declared size ⇒ uncapped"
        );
        assert_eq!(blob_cap(Some(777)), Some(777), "declared size still caps");
        assert_eq!(
            manifest_cap(None),
            None,
            "max_manifest_bytes = 0 + no declared size ⇒ uncapped in memory (time-bounded only)"
        );
        assert_eq!(
            manifest_cap(Some(777)),
            Some(777),
            "the config's declared size still caps even with max_manifest_bytes = 0"
        );

        // Restore the defaults so no other test observes the mutated global.
        install_registry_pull_limits(RegistryPullLimits::default());
        assert_eq!(blob_cap(None), Some(10 * 1024 * 1024 * 1024));
        assert_eq!(manifest_cap(None), Some(32 * 1024 * 1024));
    }

    // ---- v0.71.0 follow-up: DECOMPRESSED-size bound (anti-zip-bomb) ----

    /// A gzip-compressed single-file tar layer that is TINY compressed but inflates to `inflated`
    /// bytes — the zip-bomb shape. The `inflated` zero bytes are STREAMED through the gzip encoder
    /// (never allocated whole), so building a 64 MiB-inflating bomb costs a few KiB of memory.
    fn gz_bomb_layer(name: &str, inflated: u64) -> Vec<u8> {
        use std::io::Read as _;
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(inflated);
        builder
            .append_data(&mut h, name, std::io::repeat(0u8).take(inflated))
            .unwrap();
        let gz = builder.into_inner().unwrap(); // finish the tar (writes the trailer)
        gz.finish().unwrap() // finish gzip → compressed bytes
    }

    /// Gzip-compress an already-built (uncompressed) tar — a legit layer for the "unpacks fine"
    /// path (contrast with [`gz_bomb_layer`], which fabricates a high-ratio bomb).
    fn gz_of(tar: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(tar).unwrap();
        enc.finish().unwrap()
    }

    /// Does `err`'s message — or any error in its `source()` chain — contain `needle`? The tar
    /// extractor wraps our mid-inflation read error with its own "failed to unpack …" context, so
    /// the decompressed-ceiling abort message rides the chain as a source, not the top-level Display.
    fn io_err_chain_contains(err: &std::io::Error, needle: &str) -> bool {
        let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
        while let Some(c) = cur {
            if c.to_string().contains(needle) {
                return true;
            }
            cur = c.source();
        }
        false
    }

    /// Build a per-layer [`DecompBudget`] over caller-owned cross-layer counters, for the bounded
    /// overlay tests. Caps are `None` ⇒ disabled. Build a fresh one per layer (as production does),
    /// reusing the same `rootfs_total`/`entries_total` cells so their ceilings span layers.
    fn test_budget<'a>(
        layer_cap: Option<u64>,
        rootfs_cap: Option<u64>,
        entries_cap: Option<u64>,
        rootfs_total: &'a Cell<u64>,
        entries_total: &'a Cell<u64>,
    ) -> DecompBudget<'a> {
        DecompBudget {
            layer_read: Cell::new(0),
            layer_cap,
            rootfs_total,
            rootfs_cap,
            entries_total,
            entries_cap,
        }
    }

    #[test]
    fn zip_bomb_layer_aborted_during_inflation_without_filling_disk() {
        let _guard = pull_globals_lock();
        // A layer TINY compressed that inflates to 64 MiB — the zip-bomb the compressed byte cap
        // misses. With a 1 MiB per-layer DECOMPRESSED ceiling installed, the overlay must abort
        // DURING inflation, and the partial file must hold ~the cap, NOT the full 64 MiB.
        const INFLATED: u64 = 64 * 1024 * 1024;
        const CAP: u64 = 1024 * 1024;
        let bomb = gz_bomb_layer("bomb.bin", INFLATED);
        assert!(
            (bomb.len() as u64) < CAP,
            "the bomb must be SMALL compressed ({} bytes) or it is not a zip-bomb",
            bomb.len()
        );
        install_registry_pull_limits(RegistryPullLimits {
            max_layer_bytes: 0,
            max_image_bytes: 0,
            max_manifest_bytes: 0,
            max_decompressed_layer_bytes: CAP,
            max_rootfs_bytes: 0,
            max_tar_entries: 0,
        });
        let root = tmpdir("zipbomb");
        // The public `apply_layer_gz` path, which consults the installed global — proves the wiring.
        let res = apply_layer_gz(&root, &bomb[..]);
        install_registry_pull_limits(RegistryPullLimits::default());

        let err =
            res.expect_err("a zip-bomb layer must be aborted mid-inflation, not fully expanded");
        let OciError::Io(e) = &err else {
            panic!("expected OciError::Io from the decompressed-size abort, got {err:?}");
        };
        assert!(
            io_err_chain_contains(e, "per-layer ceiling"),
            "must carry the per-layer decompressed-ceiling abort, got: {e}"
        );
        // Proof it aborted DURING inflation: the on-disk file holds ~the cap, nowhere near 64 MiB.
        let written = fs::metadata(root.join("bomb.bin"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(
            written <= CAP + 1024 * 1024,
            "must abort mid-inflation, not write the whole {INFLATED}-byte bomb (wrote {written})"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn whole_rootfs_decompressed_cap_spans_layers() {
        // Two layers each well UNDER the per-layer cap but whose running DECOMPRESSED total exceeds
        // the whole-rootfs cap — the cross-layer counter must abort the second layer mid-inflation.
        let root = tmpdir("rootfs-cap");
        let l1 = gz_bomb_layer("a.bin", 4 * 1024 * 1024); // 4 MiB inflated
        let l2 = gz_bomb_layer("b.bin", 4 * 1024 * 1024); // 4 MiB inflated
        let layer_cap = 16 * 1024 * 1024; // generous per-layer (neither layer trips it)
        let rootfs_cap = 6 * 1024 * 1024; // whole-rootfs: l1 fits, l1+l2 does not
        let rootfs = Cell::new(0u64);
        let entries = Cell::new(0u64);

        // Layer 1 fits under the whole-rootfs cap. A fresh per-layer budget shares the cross-layer
        // `rootfs`/`entries` totals, exactly as the production overlay builds one budget per layer.
        let budget1 = test_budget(Some(layer_cap), Some(rootfs_cap), None, &rootfs, &entries);
        apply_layer_gz_bounded(&root, &l1[..], &budget1)
            .expect("layer 1 is under the whole-rootfs cap");
        let total = rootfs.get();
        assert!(
            total >= 4 * 1024 * 1024 && total <= rootfs_cap,
            "after layer 1 the running total ({total}) sits between 4 MiB and the 6 MiB rootfs cap"
        );

        // Layer 2 pushes the shared running total over the whole-rootfs cap → aborted mid-inflation.
        let budget2 = test_budget(Some(layer_cap), Some(rootfs_cap), None, &rootfs, &entries);
        let res = apply_layer_gz_bounded(&root, &l2[..], &budget2);
        let err = res.expect_err("the cross-layer running total must abort layer 2");
        let OciError::Io(e) = &err else {
            panic!("expected OciError::Io from the whole-rootfs abort, got {err:?}");
        };
        assert!(
            io_err_chain_contains(e, "whole-rootfs ceiling"),
            "must be the WHOLE-ROOTFS ceiling abort (not the per-layer one), got: {e}"
        );
        // Layer 2's file is bounded — it never fully inflated to 4 MiB.
        let written_b = fs::metadata(root.join("b.bin"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(
            written_b < 4 * 1024 * 1024,
            "layer 2 must abort mid-inflation, not write its whole 4 MiB (wrote {written_b})"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn normal_layer_unpacks_under_generous_decompressed_caps() {
        // A legit layer inflates fine under the generous default-sized decompressed ceilings.
        let root = tmpdir("normal-decomp");
        let gz = gz_of(&tar_with(
            &[("app/run", b"#!/bin/sh\n"), ("etc/conf", b"x")],
            &["app", "etc"],
        ));
        let rootfs = Cell::new(0u64);
        let entries = Cell::new(0u64);
        let budget = test_budget(
            Some(DEFAULT_PULL_MAX_DECOMPRESSED_LAYER_BYTES),
            Some(DEFAULT_PULL_MAX_ROOTFS_BYTES),
            Some(DEFAULT_PULL_MAX_TAR_ENTRIES),
            &rootfs,
            &entries,
        );
        apply_layer_gz_bounded(&root, &gz[..], &budget)
            .expect("a normal layer must unpack under the generous default decompressed caps");
        assert_eq!(fs::read(root.join("app/run")).unwrap(), b"#!/bin/sh\n");
        assert!(root.join("etc/conf").exists());
        let total = rootfs.get();
        assert!(
            total > 0 && total < DEFAULT_PULL_MAX_DECOMPRESSED_LAYER_BYTES,
            "a normal layer's decompressed total ({total}) is well under the cap"
        );
        assert!(
            entries.get() > 0 && entries.get() < DEFAULT_PULL_MAX_TAR_ENTRIES,
            "a normal layer's entry count ({}) is well under the cap",
            entries.get()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_layer_gz_default_globals_unpack_a_normal_layer() {
        // The public `apply_layer_gz` reads the installed global; the GENEROUS default must never
        // refuse a normal layer (the wiring must not regress real pulls).
        let _guard = pull_globals_lock();
        install_registry_pull_limits(RegistryPullLimits::default());
        let root = tmpdir("gz-default");
        let gz = gz_of(&tar_with(&[("bin/true", b"x")], &["bin"]));
        let r = apply_layer_gz(&root, &gz[..]);
        install_registry_pull_limits(RegistryPullLimits::default());
        r.expect("default (generous) globals must not refuse a normal layer");
        assert!(root.join("bin/true").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn decompressed_zero_disables_the_ceiling() {
        // `0` ⇒ disabled: with BOTH decompressed caps off, a high-ratio layer inflates in full
        // (the operator opt-out). This is the knob's documented escape hatch.
        let bomb = gz_bomb_layer("z.bin", 8 * 1024 * 1024); // 8 MiB inflated
        let root = tmpdir("zero-disables");
        let rootfs = Cell::new(0u64);
        let entries = Cell::new(0u64);
        let budget = test_budget(
            RegistryPullLimits::cap(0), // per-layer cap disabled
            RegistryPullLimits::cap(0), // whole-rootfs cap disabled
            RegistryPullLimits::cap(0), // entry cap disabled
            &rootfs,
            &entries,
        );
        apply_layer_gz_bounded(&root, &bomb[..], &budget)
            .expect("disabled (0 → None) decompressed caps must not abort inflation");
        assert_eq!(
            fs::metadata(root.join("z.bin")).unwrap().len(),
            8 * 1024 * 1024,
            "with the caps disabled the whole layer inflates to disk"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // ---- HIGH follow-up: hard-link copy-amplification + entry-count bounding ----

    #[test]
    fn hard_link_copy_amplification_bomb_aborted_and_disk_bounded() {
        // The copy-fallback disk-fill the DECOMPRESSED-byte guard can't see: a Link entry carries
        // NO data payload, so the gunzip guard counts ~0 bytes for it. Once `hard_link` can't (past
        // ext4's EXT4_LINK_MAX ceiling) each further link falls back to `fs::copy`, which reads the
        // target FROM DISK — invisible to the guard. N links → one file `F` would write N fresh
        // F-sized duplicates uncharged. Charging the copied bytes against the SAME per-layer budget
        // must abort once the copies cross the ceiling, with bytes on disk bounded by the cap, NOT
        // the full N×S expansion.
        use tar::{Builder, EntryType, Header};
        const S: u64 = 1024 * 1024; // the single real file F: 1 MiB
        const LINKS: usize = 64; // 64 links → F: would copy 64 MiB if uncharged
        const CAP: u64 = 4 * 1024 * 1024; // per-layer ceiling: only a few copies fit

        let mut builder = Builder::new(Vec::new());
        let content = vec![7u8; S as usize];
        let mut fh = Header::new_gnu();
        fh.set_mode(0o644);
        fh.set_size(S);
        builder.append_data(&mut fh, "F", &content[..]).unwrap();
        for i in 0..LINKS {
            let mut lh = Header::new_gnu();
            lh.set_entry_type(EntryType::Link);
            lh.set_mode(0o644);
            lh.set_size(0);
            builder
                .append_link(&mut lh, format!("link-{i}"), "F")
                .unwrap();
        }
        let gz = gz_of(&builder.into_inner().unwrap());

        let root = tmpdir("copy-amp");
        let rootfs = Cell::new(0u64);
        let entries = Cell::new(0u64);
        let budget = test_budget(Some(CAP), None, None, &rootfs, &entries);

        // Force the copy fallback for THIS thread so every link copies, without fabricating a real
        // 65 000-link ext4 ceiling; production still links first and copies only when it can't.
        FORCE_COPY_FALLBACK.with(|c| c.set(true));
        let res = apply_layer_gz_bounded(&root, &gz[..], &budget);
        FORCE_COPY_FALLBACK.with(|c| c.set(false));

        let err =
            res.expect_err("a copy-amplification bomb must abort once the copies cross the cap");
        let OciError::Io(e) = &err else {
            panic!("expected OciError::Io from the copy-amplification abort, got {err:?}");
        };
        assert!(
            io_err_chain_contains(e, "per-layer ceiling"),
            "must carry the per-layer decompressed-ceiling abort, got: {e}"
        );
        // Disk is bounded: F plus at most ~the cap of copied duplicates — NOT the full 64 MiB.
        let mut on_disk = fs::metadata(root.join("F")).map(|m| m.len()).unwrap_or(0);
        for i in 0..LINKS {
            on_disk += fs::metadata(root.join(format!("link-{i}")))
                .map(|m| m.len())
                .unwrap_or(0);
        }
        assert!(
            on_disk <= 2 * S + CAP,
            "copy-amplification must stay bounded (~F+cap), not the full {}-byte expansion \
             (on disk {on_disk})",
            (LINKS as u64) * S
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn entry_count_bomb_aborted_by_max_tar_entries() {
        // The inode-exhaustion sibling: thousands of tiny (empty) entries, each far under every
        // BYTE ceiling, must abort once the running entry count crosses `max_tar_entries`, with
        // only up to the cap's worth of inodes materialized.
        const ENTRIES: usize = 1000;
        const CAP: u64 = 100;
        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..ENTRIES {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(0);
            builder
                .append_data(&mut h, format!("f{i}"), std::io::empty())
                .unwrap();
        }
        let gz = gz_of(&builder.into_inner().unwrap());

        let root = tmpdir("entry-bomb");
        let rootfs = Cell::new(0u64);
        let entries = Cell::new(0u64);
        let budget = test_budget(None, None, Some(CAP), &rootfs, &entries);
        let res = apply_layer_gz_bounded(&root, &gz[..], &budget);
        let err = res.expect_err("an entry-count bomb must be aborted by max_tar_entries");
        let OciError::Io(e) = &err else {
            panic!("expected OciError::Io from the entry-count abort, got {err:?}");
        };
        assert!(
            io_err_chain_contains(e, "tar-entry ceiling"),
            "must carry the tar-entry ceiling abort, got: {e}"
        );
        // Bounded: the overlay stopped creating inodes at ~the cap, not all 1000.
        let created = fs::read_dir(&root).map(|rd| rd.count()).unwrap_or(0);
        assert!(
            (created as u64) <= CAP + 1,
            "only up to the cap's worth of entries materialized (created {created})"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn real_hard_links_unpack_under_bounded_overlay_and_are_not_charged() {
        // A legit busybox-style layer (one binary + applet hard links) overlays fine through the
        // bounded path, and a SUCCESSFUL hard link shares the inode → charges NO bytes, so the
        // decompressed total reflects only the real file content, never phantom link duplicates.
        use tar::{Builder, EntryType, Header};
        let mut builder = Builder::new(Vec::new());
        let mut dh = Header::new_gnu();
        dh.set_entry_type(EntryType::Directory);
        dh.set_mode(0o755);
        dh.set_size(0);
        builder
            .append_data(&mut dh, "bin", std::io::empty())
            .unwrap();
        let content = b"#!busybox\n";
        let mut fh = Header::new_gnu();
        fh.set_mode(0o755);
        fh.set_size(content.len() as u64);
        builder
            .append_data(&mut fh, "bin/busybox", &content[..])
            .unwrap();
        for applet in ["ls", "sh", "cat"] {
            let mut lh = Header::new_gnu();
            lh.set_entry_type(EntryType::Link);
            lh.set_mode(0o755);
            lh.set_size(0);
            builder
                .append_link(&mut lh, format!("bin/{applet}"), "bin/busybox")
                .unwrap();
        }
        let gz = gz_of(&builder.into_inner().unwrap());

        let root = tmpdir("real-links");
        let rootfs = Cell::new(0u64);
        let entries = Cell::new(0u64);
        let budget = test_budget(
            Some(DEFAULT_PULL_MAX_DECOMPRESSED_LAYER_BYTES),
            Some(DEFAULT_PULL_MAX_ROOTFS_BYTES),
            Some(DEFAULT_PULL_MAX_TAR_ENTRIES),
            &rootfs,
            &entries,
        );
        apply_layer_gz_bounded(&root, &gz[..], &budget)
            .expect("a normal layer with real hard links must unpack under generous caps");
        for applet in ["ls", "sh", "cat"] {
            assert_eq!(
                fs::read(root.join(format!("bin/{applet}"))).unwrap(),
                content,
                "applet hard link resolves to the busybox content"
            );
        }
        // The hard links shared busybox's inode → NOT copied, so only the real tar content was
        // charged (a few hundred bytes), nowhere near a per-link duplication.
        assert!(
            rootfs.get() < 64 * 1024,
            "only the real file content was charged ({} bytes), not link copies",
            rootfs.get()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn registry_pull_limits_serde_round_trips_new_fields_and_partial_default() {
        // A full round-trip preserves the decompressed ceilings AND the new entry-count ceiling.
        let custom = RegistryPullLimits {
            max_layer_bytes: 1,
            max_image_bytes: 2,
            max_manifest_bytes: 3,
            max_decompressed_layer_bytes: 4,
            max_rootfs_bytes: 5,
            max_tar_entries: 6,
        };
        let json = serde_json::to_string(&custom).unwrap();
        let back: RegistryPullLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back, custom);

        // Backward compat: a config written BEFORE the decompressed/entry caps existed still loads —
        // the newer fields fall back to their generous defaults (`#[serde(default)]`).
        let old = r#"{"max_layer_bytes":10,"max_image_bytes":20,"max_manifest_bytes":30}"#;
        let back: RegistryPullLimits = serde_json::from_str(old).unwrap();
        assert_eq!(back.max_layer_bytes, 10);
        assert_eq!(
            back.max_decompressed_layer_bytes,
            DEFAULT_PULL_MAX_DECOMPRESSED_LAYER_BYTES
        );
        assert_eq!(back.max_rootfs_bytes, DEFAULT_PULL_MAX_ROOTFS_BYTES);
        assert_eq!(back.max_tar_entries, DEFAULT_PULL_MAX_TAR_ENTRIES);

        // A config that sets the decompressed caps but PREDATES the entry cap still fills it in.
        let no_entries = r#"{"max_decompressed_layer_bytes":4,"max_rootfs_bytes":5}"#;
        let back: RegistryPullLimits = serde_json::from_str(no_entries).unwrap();
        assert_eq!(back.max_tar_entries, DEFAULT_PULL_MAX_TAR_ENTRIES);

        // `0` round-trips and reads back as "disabled" for every overlay ceiling.
        let zero = r#"{"max_decompressed_layer_bytes":0,"max_rootfs_bytes":0,"max_tar_entries":0}"#;
        let back: RegistryPullLimits = serde_json::from_str(zero).unwrap();
        assert_eq!(
            RegistryPullLimits::cap(back.max_decompressed_layer_bytes),
            None
        );
        assert_eq!(RegistryPullLimits::cap(back.max_rootfs_bytes), None);
        assert_eq!(RegistryPullLimits::cap(back.max_tar_entries), None);
    }

    #[tokio::test]
    // See `pull_client_fails_…`: the guard is deliberately held across await to serialize the
    // process-global pull config across parallel test threads (per-test current-thread runtimes).
    #[allow(clippy::await_holding_lock)]
    async fn oversize_blob_is_aborted_during_download_not_buffered_whole() {
        let _guard = pull_globals_lock();
        // A malicious registry that streams FAR more than the cap must be cut off MID-DOWNLOAD —
        // never buffered whole (the OOM vector). Hermetic loopback server: declares a huge body
        // and streams it; the client must abort after ~the cap with the cap error, and the
        // on-disk file must hold nowhere near the full body.
        const BODY: usize = 8 * 1024 * 1024; // 8 MiB streamed
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\n\r\n");
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let block = vec![b'A'; 64 * 1024];
                let mut sent = 0;
                while sent < BODY {
                    // The client hangs up after the cap → the write errors; stop.
                    if stream.write_all(&block).is_err() {
                        break;
                    }
                    sent += block.len();
                }
            }
        });

        // A 64 KiB operator per-blob ceiling; no declared size; no deadline/idle interference.
        // (The layer path reads `max_layer_bytes`; `max_manifest_bytes` is irrelevant here.)
        install_registry_pull_limits(RegistryPullLimits {
            max_layer_bytes: 64 * 1024,
            max_image_bytes: 0,
            max_manifest_bytes: 0,
            max_decompressed_layer_bytes: 0,
            max_rootfs_bytes: 0,
            max_tar_entries: 0,
        });
        install_registry_pull_timeouts(RegistryPullTimeouts {
            connect_secs: 5,
            read_secs: 5,
            response_secs: 0,
            overall_pull_secs: 0,
        });
        let client = screening_client().unwrap();
        let base = format!("http://{addr}");
        let out = std::env::temp_dir().join(format!("br-oversize-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let mut token = None;
        let res = fetch_layer_to_file(&client, &base, digest, &mut token, None, &out).await;

        let err = res.expect_err("an oversize blob must be aborted, not accepted");
        let OciError::Registry(msg) = err else {
            panic!("expected OciError::Registry, got {err:?}");
        };
        assert!(
            msg.contains("size cap"),
            "must be the mid-download cap abort (not a post-download digest check), got: {msg}"
        );
        // Proof it aborted DURING the read: the file holds nowhere near the 8 MiB body.
        let written = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
        assert!(
            written < 1024 * 1024,
            "must abort mid-stream, not buffer the whole oversize body (wrote {written} bytes)"
        );
        let _ = std::fs::remove_file(&out);

        install_registry_pull_limits(RegistryPullLimits::default());
        install_registry_pull_timeouts(RegistryPullTimeouts::default());
    }

    #[tokio::test]
    // See `pull_client_fails_…`: the guard is deliberately held across await to serialize the
    // process-global pull config across parallel test threads (per-test current-thread runtimes).
    #[allow(clippy::await_holding_lock)]
    async fn slow_drip_blob_is_bounded_by_the_overall_deadline() {
        let _guard = pull_globals_lock();
        // A registry that trickles bytes just UNDER the idle timeout forever would hold a blob —
        // and the serial reconcile loop awaiting it — open indefinitely (the per-chunk idle
        // timeout resets on every byte). The overall WALL-CLOCK deadline must bound it. Hermetic
        // loopback server: drips one byte every 50 ms (well under the 5 s idle timeout), far
        // longer than the 1 s deadline.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                for _ in 0..400 {
                    if stream.write_all(b"A").is_err() {
                        break;
                    }
                    let _ = stream.flush();
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });

        // Idle timeout 5 s (won't fire — bytes flow every 50 ms); no byte cap; deadline 1 s.
        install_registry_pull_timeouts(RegistryPullTimeouts {
            connect_secs: 5,
            read_secs: 5,
            response_secs: 0,
            overall_pull_secs: 1,
        });
        install_registry_pull_limits(RegistryPullLimits {
            max_layer_bytes: 0,
            max_image_bytes: 0,
            max_manifest_bytes: 0,
            max_decompressed_layer_bytes: 0,
            max_rootfs_bytes: 0,
            max_tar_entries: 0,
        });
        let client = screening_client().unwrap();
        let base = format!("http://{addr}");
        let out = std::env::temp_dir().join(format!("br-slowdrip-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let mut token = None;

        let start = std::time::Instant::now();
        let res = with_pull_deadline(fetch_layer_to_file(
            &client, &base, digest, &mut token, None, &out,
        ))
        .await;
        let elapsed = start.elapsed();

        let err = res.expect_err("a slow-drip blob must be aborted by the overall deadline");
        let OciError::Registry(msg) = err else {
            panic!("expected OciError::Registry, got {err:?}");
        };
        assert!(
            msg.contains("deadline"),
            "the abort must be the overall deadline (not the idle timeout), got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the overall deadline must bound the slow-drip (took {elapsed:?})"
        );
        let _ = std::fs::remove_file(&out);

        install_registry_pull_timeouts(RegistryPullTimeouts::default());
        install_registry_pull_limits(RegistryPullLimits::default());
    }

    #[tokio::test]
    async fn redirect_ssrf_refusal_round_trips_with_the_allowlist_hint() {
        // The REDIRECT path (reviewer gap): a registry that 307s to a non-global literal IP is
        // refused inside the redirect screen. Like the resolver (hostname) path, that refusal
        // must reach the caller as a TYPED, message-preserving error carrying the
        // `[compute].allow_private_registries` hint — not reqwest's generic transport string.
        // Hermetic loopback server replies with the redirect; the client follows it into the
        // screen. (No global mutation, so no lock needed.)
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                let _ = stream.write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\n\
                      Location: https://127.0.0.1:1/blob\r\n\
                      Content-Length: 0\r\n\r\n",
                );
            }
        });

        let client = screening_client().unwrap();
        let url = format!("http://{addr}/v2/");
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("a redirect to a non-global literal IP must be refused by the screen");
        let OciError::Registry(msg) = reqwest_err(&err) else {
            panic!("expected OciError::Registry");
        };
        assert!(
            msg.contains("allow_private_registries"),
            "the redirect refusal must carry the actionable allow-list hint, got: {msg}"
        );
        assert!(
            !msg.starts_with("error sending request"),
            "the generic transport message leaked instead of the typed redirect refusal: {msg}"
        );
    }

    // ---- Security LOW follow-ups: config-only deadline (a) + tight manifest/config cap (b) ----

    #[tokio::test]
    // See `pull_client_fails_…`: the guard is deliberately held across await to serialize the
    // process-global pull config across parallel test threads (per-test current-thread runtimes).
    #[allow(clippy::await_holding_lock)]
    async fn oversize_manifest_is_aborted_during_the_read_by_the_manifest_cap() {
        let _guard = pull_globals_lock();
        // A malicious registry that streams FAR more than a KB-scale manifest must be cut off
        // MID-READ by `max_manifest_bytes` — NOT by the generous `max_layer_bytes` (left at 10 GiB
        // here, which would never abort an 8 MiB body: the two caps are decoupled). The manifest
        // read is in memory, so the proof is the mid-download cap error naming "manifest" (a wrongly
        // layer-capped read would instead buffer the 8 MiB whole and then fail to parse it as JSON).
        const BODY: usize = 8 * 1024 * 1024; // 8 MiB streamed as a "manifest"
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\n\r\n");
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let block = vec![b'A'; 64 * 1024];
                let mut sent = 0;
                while sent < BODY {
                    // The client hangs up after the cap → the write errors; stop.
                    if stream.write_all(&block).is_err() {
                        break;
                    }
                    sent += block.len();
                }
            }
        });

        // Tight 64 KiB manifest ceiling; the LAYER ceiling left generous (10 GiB) to prove the
        // manifest path is governed by `max_manifest_bytes`, not `max_layer_bytes`.
        install_registry_pull_limits(RegistryPullLimits {
            max_layer_bytes: 10 * 1024 * 1024 * 1024,
            max_image_bytes: 0,
            max_manifest_bytes: 64 * 1024,
            max_decompressed_layer_bytes: 0,
            max_rootfs_bytes: 0,
            max_tar_entries: 0,
        });
        install_registry_pull_timeouts(RegistryPullTimeouts {
            connect_secs: 5,
            read_secs: 5,
            response_secs: 0,
            overall_pull_secs: 0,
        });
        let client = screening_client().unwrap();
        let url = format!("http://{addr}/v2/repo/manifests/latest");
        let mut token = None;
        let res = fetch_manifest(&client, &url, &mut token, None).await;

        let err = res.expect_err("an oversize manifest must be aborted, not accepted");
        let OciError::Registry(msg) = err else {
            panic!("expected OciError::Registry, got {err:?}");
        };
        assert!(
            msg.contains("manifest") && msg.contains("size cap"),
            "must be the mid-read manifest cap abort (not a parse error from buffering it whole), got: {msg}"
        );

        install_registry_pull_limits(RegistryPullLimits::default());
        install_registry_pull_timeouts(RegistryPullTimeouts::default());
    }

    #[tokio::test]
    // See `pull_client_fails_…`: the guard is deliberately held across await to serialize the
    // process-global pull config across parallel test threads (per-test current-thread runtimes).
    #[allow(clippy::await_holding_lock)]
    async fn normal_manifest_is_unaffected_by_the_manifest_cap() {
        let _guard = pull_globals_lock();
        // A normal KB-scale manifest streams well under the generous default 32 MiB ceiling and
        // parses unchanged — the tight cap refuses no real manifest.
        let manifest_body: &[u8] =
            br#"{"schemaVersion":2,"config":{"digest":"sha256:abc","size":7},"layers":[]}"#;
        let len = manifest_body.len();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(manifest_body);
            }
        });

        install_registry_pull_limits(RegistryPullLimits::default());
        install_registry_pull_timeouts(RegistryPullTimeouts::default());
        let client = screening_client().unwrap();
        let url = format!("http://{addr}/v2/repo/manifests/latest");
        let mut token = None;
        let manifest = fetch_manifest(&client, &url, &mut token, None)
            .await
            .expect("a normal manifest under the default ceiling must parse");
        assert_eq!(manifest["schemaVersion"].as_u64(), Some(2));

        install_registry_pull_limits(RegistryPullLimits::default());
        install_registry_pull_timeouts(RegistryPullTimeouts::default());
    }

    #[tokio::test]
    // See `pull_client_fails_…`: the guard is deliberately held across await to serialize the
    // process-global pull config across parallel test threads (per-test current-thread runtimes).
    #[allow(clippy::await_holding_lock)]
    async fn config_only_fetch_is_bounded_by_the_overall_deadline() {
        let _guard = pull_globals_lock();
        // The config-only path (`pull_image_config`, the ephemeral pg_dump/config helper) downloads
        // no layers — only the manifest + the small config blob — but a registry can still drip-feed
        // bytes just under the idle `read_secs` on THOSE responses forever, holding the path (and the
        // serial reconcile loop awaiting it) open. `pull_image_config` now wraps its fetch in
        // `with_pull_deadline`; this proves that wrapper bounds a slow-drip MANIFEST/config fetch by
        // the wall-clock, not just the idle gap. Hermetic loopback: one byte every 50 ms (well under
        // the 5 s idle timeout), far longer than the 1 s deadline.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                for _ in 0..400 {
                    if stream.write_all(b"A").is_err() {
                        break;
                    }
                    let _ = stream.flush();
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });

        // Idle timeout 5 s (won't fire — a byte flows every 50 ms); deadline 1 s bounds the drip.
        install_registry_pull_timeouts(RegistryPullTimeouts {
            connect_secs: 5,
            read_secs: 5,
            response_secs: 0,
            overall_pull_secs: 1,
        });
        install_registry_pull_limits(RegistryPullLimits::default());
        let client = screening_client().unwrap();
        let url = format!("http://{addr}/v2/repo/manifests/latest");
        let mut token = None;

        let start = std::time::Instant::now();
        let res = with_pull_deadline(fetch_manifest(&client, &url, &mut token, None)).await;
        let elapsed = start.elapsed();

        let err =
            res.expect_err("a slow-drip manifest fetch must be aborted by the overall deadline");
        let OciError::Registry(msg) = err else {
            panic!("expected OciError::Registry, got {err:?}");
        };
        assert!(
            msg.contains("deadline"),
            "the abort must be the overall wall-clock deadline (not the idle timeout), got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the overall deadline must bound the config-only fetch's slow-drip (took {elapsed:?})"
        );

        install_registry_pull_timeouts(RegistryPullTimeouts::default());
        install_registry_pull_limits(RegistryPullLimits::default());
    }
}
