//! OCI image → `ext4` rootfs build, behind the `build`
//! feature. No container runtime: pull the image over the registry HTTP API,
//! **overlay** its layers onto a tree (honoring OCI whiteouts), and `mke2fs -d`
//! the result into an ext4 image.
//!
//! The **layer overlay** ([`apply_layer_gz`]) is pure and unit-tested. The
//! registry pull ([`pull_layers`], network) and the ext4 build ([`build_ext4`],
//! the `e2fsprogs` `mke2fs` tool) are host seams.

use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};

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

/// Join `rel` (already sanitized to `Normal`-only components by [`safe_relative`])
/// onto `root`, **refusing to resolve through a symlink**. Every ancestor
/// component is `lstat`'d and rejected if it is a symlink, so a destination can
/// never be computed *through* a symlink an earlier entry/layer planted (e.g.
/// `work/evil -> /etc`, then `work/evil/passwd`). This is the cross-platform
/// containment the whole unpack relies on — the host `std::fs` calls that follow
/// (`create_dir_all`, `unpack`, `remove_*`, `hard_link`/`copy`) then operate on a
/// path whose parents are verified real directories under `root`, so none of them
/// can be redirected onto the host filesystem.
///
/// With `check_leaf` the final component is screened the same way — used where the
/// resolved path is itself traversed/read (an opaque-whiteout directory to clear,
/// a hard-link *target* to read): those must be real, not a symlink to follow.
/// Otherwise the leaf is returned un-dereferenced and the caller must not follow
/// it (it unlinks-then-creates it with the verified-real parent pinned).
///
/// Non-existent components are allowed (nothing to follow yet); only an existing
/// symlink component is refused. `rel`'s components are all `Normal`; any other
/// kind (defensive — `safe_relative` already rejected them) is refused.
fn contained_path(root: &Path, rel: &Path, check_leaf: bool) -> Result<PathBuf, OciError> {
    let mut cur = root.to_path_buf();
    let comps: Vec<Component> = rel.components().collect();
    let n = comps.len();
    for (i, comp) in comps.into_iter().enumerate() {
        let Component::Normal(name) = comp else {
            return Err(OciError::UnsafePath(rel.display().to_string()));
        };
        cur.push(name);
        let is_leaf = i + 1 == n;
        if (check_leaf || !is_leaf) && fs::symlink_metadata(&cur).is_ok_and(|m| m.is_symlink()) {
            return Err(OciError::UnsafePath(rel.display().to_string()));
        }
    }
    Ok(cur)
}

/// Resolve a tar **hard-link** target into a host path under `root`. A hard link's
/// `linkname` references another member of the *same archive* (the same namespace
/// as member names), so it is always relative to the extraction root — never the
/// process CWD. An absolute target is normalized to root-relative (its leading `/`
/// is stripped, as `tar` does without `--absolute-names`); a `..` that would
/// escape the root is refused. The resolved target is then screened through
/// [`contained_path`] with `check_leaf` — a hard link is `hard_link`'d/`copy`'d
/// (and `copy` *follows* symlinks), so a target that traverses OR lands on a
/// planted symlink (`-> /etc/shadow`) must be refused or it pulls a host file into
/// the image (read/exfil). (A *symlink* entry is different: its target is stored +
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
    contained_path(root, &rel, true)
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
            // Clear the REAL directory; refuse if any component (the dir itself
            // included) is a symlink, so an opaque whiteout can't be redirected to
            // wipe a host directory via a planted symlink.
            let dir = contained_path(root, parent, true)?;
            clear_dir(&dir)?;
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(".wh.") {
            // Pin the parent chain to real directories, then remove the named leaf
            // WITHOUT following it (a symlinked whiteout parent must not let the
            // delete reach outside the rootfs).
            let victim = contained_path(root, &parent.join(target_name), false)?;
            remove_path(&victim)?;
            continue;
        }

        // Resolve the destination with its parent chain pinned to real
        // directories — never resolve a write THROUGH an attacker-planted symlink.
        let dest = contained_path(root, &rel, false)?;
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
        || o[0] == 0 // "this network" 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000) // 100.64.0.0/10 CGNAT
        || o[0] >= 240 // 240.0.0.0/4 reserved
}

/// Is `ip` a non-globally-routable address that must never be a pull target?
/// Blocks loopback, private, link-local (v4 `169.254/16`, v6 `fe80::/10`),
/// unique-local (`fc00::/7`), multicast, and v4-mapped forms of the above —
/// closing SSRF to cloud metadata (`169.254.169.254`) and internal hosts.
fn ip_is_disallowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_disallowed(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ipv4_is_disallowed(mapped);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
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
/// attacker-controlled), returning its (host, port) for IP screening. Lexical
/// only; the IP screen is [`screen_pull_host`].
fn parse_realm(realm: &str) -> Result<(String, u16), OciError> {
    let rest = realm
        .strip_prefix("https://")
        .ok_or_else(|| OciError::Registry(format!("auth realm must be https, refusing {realm}")))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip any `userinfo@`.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    split_host_port(authority)
}

/// Screen a pull target host: resolve it and refuse if it is (or resolves to)
/// any non-globally-routable address — the SSRF block for the registry host and
/// the token realm. For a DNS name the screened socket addrs are returned to PIN
/// into the client (so a re-resolve at connect time can't rebind to a private
/// address — DNS-rebinding defense); a literal IP is screened in place and needs
/// no pin. Blocking DNS (one shot, cold build path).
fn screen_pull_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, OciError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_is_disallowed(ip) {
            return Err(OciError::Registry(format!(
                "refusing to pull from non-global address {host}"
            )));
        }
        return Ok(Vec::new());
    }
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| OciError::Registry(format!("resolving pull host {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(OciError::Registry(format!(
            "pull host {host} did not resolve"
        )));
    }
    for sa in &addrs {
        if ip_is_disallowed(sa.ip()) {
            return Err(OciError::Registry(format!(
                "refusing to pull from {host}: resolves to non-global address {}",
                sa.ip()
            )));
        }
    }
    Ok(addrs)
}

/// Build an HTTP client for `host:port`, screened against SSRF: the host is
/// resolved + IP-screened ([`screen_pull_host`]) and its vetted addrs pinned so
/// the initial connect can't rebind. Redirects are **followed but re-screened at
/// every hop** (bounded): a registry blob GET legitimately `307`s to a CDN, so a
/// blanket no-redirect would break real pulls — but each hop must still be
/// `https` to a globally-routable host, so an SSRF redirect to cloud metadata /
/// an internal host is refused rather than chased.
fn build_screened_client(host: &str, port: u16) -> Result<reqwest::Client, OciError> {
    let pinned = screen_pull_host(host, port)?;
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 8 {
            return attempt.error(std::io::Error::other("too many redirects"));
        }
        // Copy what we need as owned values before consuming `attempt`.
        let scheme = attempt.url().scheme().to_owned();
        let host = attempt.url().host_str().map(str::to_owned);
        let port = attempt.url().port_or_known_default().unwrap_or(443);
        let shown = attempt.url().to_string();
        if scheme != "https" {
            return attempt.error(std::io::Error::other(format!(
                "refusing non-https redirect to {shown}"
            )));
        }
        let Some(h) = host else {
            return attempt.error(std::io::Error::other("redirect without host"));
        };
        match screen_pull_host(&h, port) {
            Ok(_) => attempt.follow(),
            Err(e) => attempt.error(std::io::Error::other(e.to_string())),
        }
    });
    let mut builder = reqwest::Client::builder()
        .user_agent("boatramp-compute")
        .redirect(redirect);
    if !pinned.is_empty() {
        builder = builder.resolve_to_addrs(host, &pinned);
    }
    builder
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
    let new_token = fetch_token(&challenge).await?;
    *token = Some(new_token);
    send(token)
        .await
        .map_err(|e| OciError::Registry(e.to_string()))
}

/// Resolve a `Bearer realm="…",service="…",scope="…"` challenge into a token.
///
/// The realm comes from the (tenant-controlled) registry's `401`, so it is
/// screened before it is fetched: it MUST be `https://` and its host must not be
/// (or resolve to) a non-global address ([`parse_realm`] + [`build_screened_client`]).
/// A dedicated DNS-pinned, redirect-re-screening client is used, so a malicious
/// `realm="http://169.254.169.254/…"` (SSRF to cloud metadata / internal hosts,
/// plus a credential-exfil tail) is refused rather than fetched.
async fn fetch_token(challenge: &str) -> Result<String, OciError> {
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
    let (host, port) = parse_realm(&realm)?;
    let client = build_screened_client(&host, port)?;
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
    // Screen the registry host for SSRF (scheme is fixed `https` below; the host
    // must resolve to a global address) and pin + disable redirects.
    let (reg_host, reg_port) = split_host_port(&registry)?;
    let client = build_screened_client(&reg_host, reg_port)?;
    let base = format!("https://{registry}/v2/{repo}");
    let mut token = None;

    // When the ref is a `@sha256:` digest pin, the manifest body itself must hash
    // to it — otherwise a MITM / malicious registry can serve a *different*
    // self-consistent manifest (its layer digests all check out against ITS own
    // manifest). Verify the manifest bytes before trusting their layer list.
    let manifest_url = format!("{base}/manifests/{reference}");
    let want = reference
        .starts_with("sha256:")
        .then_some(reference.as_str());
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

/// Verify `bytes` hash to `digest` when it is a `sha256:` pin (a tag reference is
/// not hash-verifiable and passes — its config/layer digests are checked
/// downstream against the now-trusted manifest).
fn verify_digest(bytes: &[u8], digest: &str) -> Result<(), OciError> {
    use sha2::{Digest, Sha256};
    if let Some(hex_want) = digest.strip_prefix("sha256:") {
        let got = hex::encode(Sha256::digest(bytes));
        if got != hex_want {
            return Err(OciError::Registry(format!(
                "manifest digest mismatch for {digest}"
            )));
        }
    }
    Ok(())
}

/// GET a manifest from `url`, verifying its raw bytes against `expect` (a
/// `sha256:` digest) BEFORE parsing — so a digest-pinned pull trusts only a
/// manifest whose body actually hashes to the pin.
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

/// Fetch + verify a blob by `digest` from `base`.
async fn fetch_blob(
    client: &reqwest::Client,
    base: &str,
    digest: &str,
    token: &mut Option<String>,
) -> Result<Vec<u8>, OciError> {
    use sha2::{Digest, Sha256};
    let url = format!("{base}/blobs/{digest}");
    let resp = get_authed(client, &url, "*/*", token).await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!("blob GET {}", resp.status())));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;
    if let Some(hex_want) = digest.strip_prefix("sha256:") {
        let got = hex::encode(Sha256::digest(&bytes));
        if got != hex_want {
            return Err(OciError::Registry(format!(
                "blob digest mismatch for {digest}"
            )));
        }
    }
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
    let work = std::env::temp_dir().join(format!(
        "br-rootfs-{}-{}",
        std::process::id(),
        out.file_name().and_then(|n| n.to_str()).unwrap_or("vm")
    ));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work)?;
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
fn write_init(
    root: &Path,
    argv: &[String],
    cfg: &ImageConfig,
    env_override: &[(String, String)],
    volume_mounts: &[String],
) -> Result<(), OciError> {
    let sbin = root.join("sbin");
    fs::create_dir_all(&sbin)?;
    let init = sbin.join("init");
    fs::write(&init, VMINIT)?;
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
    let cfgdir = root.join("etc").join("boatramp");
    fs::create_dir_all(&cfgdir)?;
    fs::write(cfgdir.join("argv"), nul_join(&argv))?;
    fs::write(cfgdir.join("env"), nul_join(&env))?;
    let cwd = if cfg.workdir.is_empty() {
        "/"
    } else {
        &cfg.workdir
    };
    fs::write(cfgdir.join("cwd"), cwd)?;

    // The init mounts onto these; a read-only root means they must already exist.
    for dir in ["proc", "sys", "dev", "tmp", "run"] {
        fs::create_dir_all(root.join(dir))?;
    }

    // Persistent-volume mount points: each volume attaches as a writable
    // virtio-block device (`/dev/vdb`, `/dev/vdc`, … in order, after the rootfs
    // `vda`). Bake the mount-point dir (read-only root → must pre-exist) + the
    // `source␞target` map the init mounts. Best-effort at runtime.
    let mut mounts_spec: Vec<String> = Vec::with_capacity(volume_mounts.len() * 2);
    for (i, mount) in volume_mounts.iter().enumerate() {
        fs::create_dir_all(root.join(mount.trim_start_matches('/')))?;
        mounts_spec.push(format!("/dev/vd{}", (b'b' + i as u8) as char));
        mounts_spec.push(mount.clone());
    }
    if !mounts_spec.is_empty() {
        fs::write(cfgdir.join("mounts"), nul_join(&mounts_spec))?;
    }
    // A default resolver so the workload can do DNS (egress NAT is the node's
    // job). Overridable per deployment — the container backend rewrites
    // resolv.conf post-stage to point at the internal resolver; the VMM bakes it
    // at build, so expose the same knob here.
    let etc = root.join("etc");
    if !etc.join("resolv.conf").exists() {
        fs::write(etc.join("resolv.conf"), default_resolv_conf())?;
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
    fn planted_symlink_unpack_refuses_write_escape() {
        // An earlier entry plants `evil -> <sentinel outside root>`; a later entry
        // `evil/pwned` must NOT be written through it (host-write escape).
        let root = tmpdir("sym-write");
        let sentinel = tmpdir("sym-write-escape");
        fs::create_dir_all(&sentinel).unwrap();
        let tar = tar_symlink_then(&[
            ("L", "evil", sentinel.to_str().unwrap().as_bytes()),
            ("F", "evil/pwned", b"PWNED"),
        ]);
        let err = apply_layer_tar(&root, &tar[..]).unwrap_err();
        assert!(matches!(err, OciError::UnsafePath(_)), "got {err:?}");
        assert!(
            !sentinel.join("pwned").exists(),
            "the write must NOT have escaped through the planted symlink"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn whiteout_through_symlink_refuses_delete() {
        // `evil -> <sentinel>`; a whiteout `evil/.wh.victim` must NOT delete the
        // sentinel's file (host-delete escape).
        let root = tmpdir("sym-wh");
        let sentinel = tmpdir("sym-wh-escape");
        fs::create_dir_all(&sentinel).unwrap();
        fs::write(sentinel.join("victim"), b"keep").unwrap();
        let tar = tar_symlink_then(&[
            ("L", "evil", sentinel.to_str().unwrap().as_bytes()),
            ("W", "evil/.wh.victim", b""),
        ]);
        let err = apply_layer_tar(&root, &tar[..]).unwrap_err();
        assert!(matches!(err, OciError::UnsafePath(_)), "got {err:?}");
        assert!(
            sentinel.join("victim").exists(),
            "the whiteout must NOT have deleted through the planted symlink"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn opaque_whiteout_through_symlink_refuses_clear() {
        // An opaque whiteout whose directory is a planted symlink must refuse,
        // not `read_dir` + wipe the symlink target.
        let root = tmpdir("sym-opq");
        let sentinel = tmpdir("sym-opq-escape");
        fs::create_dir_all(&sentinel).unwrap();
        fs::write(sentinel.join("keep"), b"x").unwrap();
        let tar = tar_symlink_then(&[
            ("L", "evil", sentinel.to_str().unwrap().as_bytes()),
            ("W", "evil/.wh..wh..opq", b""),
        ]);
        let err = apply_layer_tar(&root, &tar[..]).unwrap_err();
        assert!(matches!(err, OciError::UnsafePath(_)), "got {err:?}");
        assert!(
            sentinel.join("keep").exists(),
            "the opaque whiteout must NOT have cleared through the planted symlink"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel);
    }

    #[test]
    fn hard_link_through_symlink_refuses_exfil() {
        // `evil -> <sentinel/secret>` (a symlink to a host file); a hard-link
        // entry `loot` pointing at `evil` must be refused, not copied — otherwise
        // a host file is exfiltrated into the image.
        let root = tmpdir("sym-link");
        let sentinel = tmpdir("sym-link-escape");
        fs::create_dir_all(&sentinel).unwrap();
        let secret = sentinel.join("secret");
        fs::write(&secret, b"topsecret").unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        // Plant the symlink `evil -> <abs path to secret>`.
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

        let err = apply_layer_tar(&root, &tar[..]).unwrap_err();
        assert!(matches!(err, OciError::UnsafePath(_)), "got {err:?}");
        assert!(
            !root.join("loot").exists(),
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
    fn contained_path_allows_real_dirs_refuses_symlinked_parent() {
        let root = tmpdir("contained");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/f"), b"x").unwrap();
        // A real parent chain resolves.
        assert_eq!(
            contained_path(&root, Path::new("a/b/f"), false).unwrap(),
            root.join("a/b/f")
        );
        // A symlinked parent component is refused.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", root.join("a/link")).unwrap();
            assert!(matches!(
                contained_path(&root, Path::new("a/link/x"), false),
                Err(OciError::UnsafePath(_))
            ));
            // With check_leaf, a symlink LEAF is also refused.
            assert!(matches!(
                contained_path(&root, Path::new("a/link"), true),
                Err(OciError::UnsafePath(_))
            ));
            // Without check_leaf, a symlink leaf is returned (caller unlinks it).
            assert_eq!(
                contained_path(&root, Path::new("a/link"), false).unwrap(),
                root.join("a/link")
            );
        }
        let _ = fs::remove_dir_all(&root);
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
        // screen (no DNS needed — hermetic).
        for ip in [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
        ] {
            let (host, port) = parse_realm(&format!("https://{ip}/token")).unwrap();
            assert_eq!(port, 443);
            assert!(
                matches!(screen_pull_host(&host, port), Err(OciError::Registry(_))),
                "{ip} (link-local/private/loopback) must be refused"
            );
        }
        for ip in ["::1", "fe80::1", "fc00::1"] {
            let (host, port) = parse_realm(&format!("https://[{ip}]:443/token")).unwrap();
            assert!(
                matches!(screen_pull_host(&host, port), Err(OciError::Registry(_))),
                "{ip} (v6 loopback/link-local/unique-local) must be refused"
            );
        }

        // A public literal IP passes the screen (and needs no DNS pin).
        let (host, port) = parse_realm("https://1.1.1.1/token").unwrap();
        assert_eq!((host.as_str(), port), ("1.1.1.1", 443));
        assert!(screen_pull_host("1.1.1.1", 443).unwrap().is_empty());
    }

    #[test]
    fn ipv4_mapped_v6_metadata_is_refused() {
        // `::ffff:169.254.169.254` must be screened via its mapped v4 form.
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(ip_is_disallowed(mapped));
        // And a plain public v4 is allowed.
        assert!(!ip_is_disallowed("1.1.1.1".parse().unwrap()));
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
    fn manifest_digest_mismatch_is_refused() {
        use sha2::{Digest, Sha256};
        let body = br#"{"schemaVersion":2,"layers":[]}"#;
        let real = hex::encode(Sha256::digest(body));
        // The correct pin verifies.
        verify_digest(body, &format!("sha256:{real}")).unwrap();
        // A wrong digest pin is refused (a MITM/malicious registry serving a
        // different self-consistent manifest for a pinned ref).
        assert!(matches!(
            verify_digest(
                body,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ),
            Err(OciError::Registry(_))
        ));
        // A tag reference (not a sha256 pin) is not hash-checkable here → passes
        // (its config/layer digests are verified downstream).
        verify_digest(body, "latest").unwrap();
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
