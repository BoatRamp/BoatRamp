//! OCI image → `ext4` rootfs build, behind the `build`
//! feature. No container runtime: pull the image over the registry HTTP API,
//! **overlay** its layers onto a tree (honoring OCI whiteouts), and `mke2fs -d`
//! the result into an ext4 image.
//!
//! The **layer overlay** ([`apply_layer_gz`]) is pure and unit-tested. The
//! registry pull ([`pull_layers`], network) and the ext4 build ([`build_ext4`],
//! the `e2fsprogs` `mke2fs` tool) are host seams.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;

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
pub fn apply_layer_gz(root: &Path, reader: impl Read) -> Result<(), OciError> {
    let gz = flate2::read::GzDecoder::new(reader);
    apply_layer_tar(root, gz)
}

/// As [`apply_layer_gz`] but over an already-decompressed tar stream (the
/// testable core).
pub fn apply_layer_tar(root: &Path, reader: impl Read) -> Result<(), OciError> {
    fs::create_dir_all(root)?;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);
    for entry in archive.entries()? {
        let mut entry = entry?;
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
            if fs::hard_link(&target, &dest).is_err() {
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
    *PRIVATE_REGISTRY_ALLOWLIST
        .write()
        .expect("private-registry allowlist lock poisoned") = compiled;
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
    let allow = PRIVATE_REGISTRY_ALLOWLIST
        .read()
        .expect("private-registry allowlist lock poisoned");
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
/// attacker-controlled), returning its (host, port). Lexical only; the IP screen
/// is [`screen_literal_host`] (literal-IP realm) + [`ScreeningResolver`] (hostname).
fn parse_realm(realm: &str) -> Result<(String, u16), OciError> {
    let rest = realm
        .strip_prefix("https://")
        .ok_or_else(|| OciError::Registry(format!("auth realm must be https, refusing {realm}")))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip any `userinfo@`.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    split_host_port(authority)
}

/// Eagerly refuse a pull host that is a literal non-global IP. The DNS-screening
/// [`ScreeningResolver`] only sees *hostnames* (reqwest never calls a resolver for
/// a literal-IP URL), so a literal-IP registry/realm URL would otherwise skip the
/// screen entirely. A hostname passes here and is screened at resolution time.
fn screen_literal_host(host: &str) -> Result<(), OciError> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<IpAddr>()
        && address_is_refused(Some(h), ip)
    {
        return Err(OciError::Registry(format!(
            "refusing to pull from non-global address {host} (not on the \
             `[compute].allow_private_registries` operator allow-list)"
        )));
    }
    Ok(())
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
                    return Err(format!(
                        "refusing to connect to {host}: resolves to non-global address {} \
                         (not on the `[compute].allow_private_registries` operator allow-list)",
                        sa.ip()
                    )
                    .into());
                }
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Build the SSRF-screened pull client, shared across registry + blob + token
/// fetches: a [`ScreeningResolver`] screens every hostname lookup (initial +
/// redirects), and the redirect policy (bounded) requires each hop to be `https`
/// and rejects a hop to a literal non-global IP (which the resolver never sees).
/// Redirects are FOLLOWED — a registry blob GET legitimately `307`s to a CDN — but
/// an SSRF redirect to cloud metadata / an internal host is refused, not chased.
fn screening_client() -> Result<reqwest::Client, OciError> {
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 8 {
            return attempt.error(std::io::Error::other("too many redirects"));
        }
        // Copy what we need as owned values before consuming `attempt`.
        let is_https = attempt.url().scheme() == "https";
        // A redirect to a literal-IP host bypasses the DNS resolver → screen here (through
        // the same operator allow-list + always-blocked-metadata decision, U25).
        let literal_bad = attempt.url().host_str().is_some_and(|h| {
            let stripped = h.trim_start_matches('[').trim_end_matches(']');
            stripped
                .parse::<IpAddr>()
                .is_ok_and(|ip| address_is_refused(Some(stripped), ip))
        });
        let shown = attempt.url().to_string();
        if !is_https {
            attempt.error(std::io::Error::other(format!(
                "refusing non-https redirect to {shown}"
            )))
        } else if literal_bad {
            attempt.error(std::io::Error::other(format!(
                "refusing redirect to non-global host {shown}"
            )))
        } else {
            attempt.follow()
        }
    });
    reqwest::Client::builder()
        .user_agent("boatramp-compute")
        .dns_resolver(std::sync::Arc::new(ScreeningResolver))
        .redirect(redirect)
        .build()
        .map_err(|e| OciError::Registry(e.to_string()))
}

/// GET `url` with the manifest Accept header, performing a one-shot
/// `WWW-Authenticate: Bearer` token exchange on `401` (anonymous pull).
async fn get_authed(
    client: &reqwest::Client,
    url: &str,
    accept: &str,
    token: &mut Option<String>,
) -> Result<reqwest::Response, OciError> {
    let send = |bearer: &Option<String>| {
        let mut req = client.get(url).header(reqwest::header::ACCEPT, accept);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        req.send()
    };
    let resp = send(token)
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;
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
    send(token)
        .await
        .map_err(|e| OciError::Registry(e.to_string()))
}

/// Resolve a `Bearer realm="…",service="…",scope="…"` challenge into a token.
///
/// The realm comes from the (tenant-controlled) registry's `401`, so it is
/// screened before it is fetched: it MUST be `https://` ([`parse_realm`]) and its
/// host must not be (or resolve to) a non-global address — a literal-IP realm via
/// [`screen_literal_host`], a hostname via the shared client's [`ScreeningResolver`].
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
    let (host, _port) = parse_realm(&realm)?;
    screen_literal_host(&host)?;
    let resp = client
        .get(&realm)
        .query(&query)
        .send()
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;
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
    // Screen the registry host for SSRF (scheme is fixed `https` below; a
    // literal-IP host is screened eagerly, a hostname by the client's resolver).
    let (reg_host, _reg_port) = split_host_port(&registry)?;
    screen_literal_host(&reg_host)?;
    let client = screening_client()?;
    let base = format!("https://{registry}/v2/{repo}");
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
    let resp = get_authed(client, url, MANIFEST_ACCEPT, token).await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!(
            "manifest GET {}",
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;
    if let Some(d) = expect {
        verify_digest(&bytes, d)?;
    }
    serde_json::from_slice(&bytes).map_err(|e| OciError::Registry(e.to_string()))
}

/// Fetch + verify a blob by `digest` from `base`. The blob bytes are verified
/// against `digest` via [`verify_digest`], which fails closed on an unknown
/// algorithm (so a `sha512:` config/layer digest is verified, not waved through).
async fn fetch_blob(
    client: &reqwest::Client,
    base: &str,
    digest: &str,
    token: &mut Option<String>,
) -> Result<Vec<u8>, OciError> {
    let url = format!("{base}/blobs/{digest}");
    let resp = get_authed(client, &url, "*/*", token).await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!("blob GET {}", resp.status())));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;
    verify_digest(&bytes, digest)?;
    Ok(bytes.to_vec())
}

/// Fetch all of a resolved manifest's layer blobs (lowest first).
async fn fetch_layers(r: &mut ResolvedManifest) -> Result<Vec<Vec<u8>>, OciError> {
    let digests: Vec<String> = r.manifest["layers"]
        .as_array()
        .ok_or_else(|| OciError::Registry("manifest has no layers".into()))?
        .iter()
        .map(|l| {
            l["digest"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| OciError::Registry("layer missing digest".into()))
        })
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(digests.len());
    for digest in &digests {
        out.push(fetch_blob(&r.client, &r.base, digest, &mut r.token).await?);
    }
    Ok(out)
}

/// Pull an image's layer blobs (gzip'd tar, lowest first) over the registry HTTP
/// API — anonymous pull with the Bearer-token dance. A multi-arch index resolves
/// to `linux/<guest-arch>` (see [`oci_arch`]). Each blob is verified against its
/// `sha256:` digest. Network seam (not unit-tested). Assumes gzip layers.
pub async fn pull_layers(image: &str) -> Result<Vec<Vec<u8>>, OciError> {
    let mut r = resolve_manifest(image).await?;
    fetch_layers(&mut r).await
}

/// Pull an image's runtime [`ImageConfig`] + its layer blobs. The config blob (a
/// JSON object referenced by `manifest.config.digest`) carries the process to run
/// — `Entrypoint`/`Cmd`/`Env`/`WorkingDir` — which the baked init needs.
pub async fn pull_image(image: &str) -> Result<(ImageConfig, Vec<Vec<u8>>), OciError> {
    let mut r = resolve_manifest(image).await?;
    let config = parse_image_config(&mut r).await?;
    let layers = fetch_layers(&mut r).await?;
    Ok((config, layers))
}

/// Pull ONLY an image's runtime [`ImageConfig`] — the manifest resolve + the (small)
/// config blob, with no layer download. The container backend uses this to recover the
/// image's `Env` (notably `PATH`) and `WorkingDir` for an ephemeral one-shot whose rootfs
/// is already staged (layers cached), so a bare `pg_dump`/`pg_restore`/`psql` resolves
/// against the image's own `PATH` instead of failing with `127`. Network seam.
pub async fn pull_image_config(image: &str) -> Result<ImageConfig, OciError> {
    let mut r = resolve_manifest(image).await?;
    parse_image_config(&mut r).await
}

/// Fetch + parse the image config blob into an [`ImageConfig`].
async fn parse_image_config(r: &mut ResolvedManifest) -> Result<ImageConfig, OciError> {
    let digest = r.manifest["config"]["digest"]
        .as_str()
        .ok_or_else(|| OciError::Registry("manifest has no config digest".into()))?
        .to_string();
    let bytes = fetch_blob(&r.client, &r.base, &digest, &mut r.token).await?;
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

/// Build an ext4 rootfs at `out` from an OCI `image`: pull the image (config +
/// layers) → overlay the layers → inject a `/sbin/init` that execs the workload
/// (the `entrypoint` override, else the image's `Entrypoint`+`Cmd`; with `env`
/// merged over the image env) + a default `/etc/resolv.conf` → `mke2fs -d`.
/// Orchestrates the network + host-tool seams.
pub async fn build_rootfs(
    image: &str,
    entrypoint: &[String],
    env: &[(String, String)],
    out: &Path,
    size_mib: u64,
    volume_mounts: &[String],
) -> Result<(), OciError> {
    let (config, layers) = pull_image(image).await?;
    let argv = effective_argv(&config, entrypoint)?;
    let tag = out.file_name().and_then(|n| n.to_str()).unwrap_or("vm");
    let work = make_staging_dir(tag)?;
    let result = (|| {
        for layer in &layers {
            apply_layer_gz(&work, &layer[..])?;
        }
        write_init(&work, &argv, &config, env, volume_mounts)?;
        build_ext4(&work, out, size_mib)
    })();
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
/// (pull → overlay its layers, honoring whiteouts) — the same overlay as
/// [`build_rootfs`] but stopping before `mke2fs`. The native **container**
/// backend boots from this directory directly (`pivot_root`); no ext4 image,
/// so it needs no `e2fsprogs`. Idempotent: `out` is recreated.
pub async fn build_rootfs_dir(image: &str, out: &Path) -> Result<(), OciError> {
    let layers = pull_layers(image).await?;
    let _ = fs::remove_dir_all(out);
    fs::create_dir_all(out)?;
    for layer in &layers {
        apply_layer_gz(out, &layer[..])?;
    }
    Ok(())
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

        // https realms whose host is a non-global literal IP are refused by the
        // eager literal screen (a literal-IP URL never reaches the DNS resolver).
        // Hermetic — no DNS.
        for ip in [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
        ] {
            let (host, _port) = parse_realm(&format!("https://{ip}/token")).unwrap();
            assert!(
                matches!(screen_literal_host(&host), Err(OciError::Registry(_))),
                "{ip} (link-local/private/loopback) must be refused"
            );
        }
        for ip in ["::1", "fe80::1", "fc00::1"] {
            let (host, _port) = parse_realm(&format!("https://[{ip}]:443/token")).unwrap();
            assert!(
                matches!(screen_literal_host(&host), Err(OciError::Registry(_))),
                "{ip} (v6 loopback/link-local/unique-local) must be refused"
            );
        }

        // A public literal IP passes the eager screen; a hostname passes it too
        // (it is screened later, at DNS resolution, by `ScreeningResolver`).
        let (host, port) = parse_realm("https://1.1.1.1/token").unwrap();
        assert_eq!((host.as_str(), port), ("1.1.1.1", 443));
        screen_literal_host("1.1.1.1").unwrap();
        screen_literal_host("registry.example.com").unwrap();
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
}
