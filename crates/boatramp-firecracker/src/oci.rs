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

/// Resolve a tar **hard-link** target into a host path under `root`. A hard link's
/// `linkname` references another member of the *same archive* (the same namespace
/// as member names), so it is always relative to the extraction root — never the
/// process CWD. An absolute target is normalized to root-relative (its leading `/`
/// is stripped, as `tar` does without `--absolute-names`); a `..` that would
/// escape the root is refused. (Symlinks are different: their target is stored +
/// created verbatim and resolved inside the guest, so they go through `unpack`.)
fn link_target_under_root(root: &Path, link: &Path) -> Result<PathBuf, OciError> {
    let mut out = root.to_path_buf();
    for comp in link.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            // A leading `/` (or `./`) just means "from the archive root".
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => return Err(OciError::UnsafePath(link.display().to_string())),
        }
    }
    Ok(out)
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
            clear_dir(&root.join(parent))?;
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(".wh.") {
            remove_path(&root.join(parent).join(target_name))?;
            continue;
        }

        let dest = root.join(&rel);
        // A replacing entry over an existing dir/symlink: clear it first so
        // `unpack` writes cleanly (e.g. a file replacing a directory).
        if let Ok(meta) = fs::symlink_metadata(&dest) {
            let entry_is_dir = entry.header().entry_type().is_dir();
            if meta.is_dir() && !entry_is_dir {
                remove_path(&dest)?;
            }
        }
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }

        // Hard links (e.g. busybox's applets → `/bin/busybox`) reference another
        // member of this archive, so the target resolves **relative to the rootfs
        // root** ([`link_target_under_root`]); the tar crate's per-entry `unpack`
        // would resolve it relative to the process CWD and fail. Link here (copy
        // as a fallback if linking can't); everything else (files, dirs, symlinks)
        // goes through `unpack`, which writes a symlink's target verbatim.
        if entry.header().entry_type() == tar::EntryType::Link {
            let link = entry
                .link_name()?
                .ok_or_else(|| OciError::Io(std::io::Error::other("hard link without target")))?;
            let target = link_target_under_root(root, &link)?;
            let _ = fs::remove_file(&dest);
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
        (n.to_string(), d.to_string())
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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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

/// Resolve `image` to a concrete `linux/amd64` manifest, performing the anonymous
/// Bearer-token dance. A multi-arch index is followed to its amd64 entry.
async fn resolve_manifest(image: &str) -> Result<ResolvedManifest, OciError> {
    let (registry, repo, reference) = parse_reference(image);
    let client = reqwest::Client::builder()
        .user_agent("boatramp-compute")
        .build()
        .map_err(|e| OciError::Registry(e.to_string()))?;
    let base = format!("https://{registry}/v2/{repo}");
    let mut token = None;

    let manifest_url = format!("{base}/manifests/{reference}");
    let resp = get_authed(&client, &manifest_url, MANIFEST_ACCEPT, &mut token).await?;
    if !resp.status().is_success() {
        return Err(OciError::Registry(format!(
            "manifest GET {}",
            resp.status()
        )));
    }
    let manifest: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OciError::Registry(e.to_string()))?;

    let manifest = if manifest.get("manifests").is_some() {
        // An index/list — pick linux/amd64.
        let digest = manifest["manifests"]
            .as_array()
            .and_then(|entries| {
                entries.iter().find(|m| {
                    let p = &m["platform"];
                    p["os"].as_str() == Some("linux") && p["architecture"].as_str() == Some("amd64")
                })
            })
            .and_then(|m| m["digest"].as_str())
            .ok_or_else(|| OciError::Registry("no linux/amd64 in image index".into()))?
            .to_string();
        let url = format!("{base}/manifests/{digest}");
        let resp = get_authed(&client, &url, MANIFEST_ACCEPT, &mut token).await?;
        resp.json()
            .await
            .map_err(|e| OciError::Registry(e.to_string()))?
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
/// to `linux/amd64`. Each blob is verified against its `sha256:` digest. Network
/// seam (not unit-tested). Assumes gzip layers (the common case).
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
    // A default resolver so the workload can do DNS (egress NAT is the node's job).
    let etc = root.join("etc");
    if !etc.join("resolv.conf").exists() {
        fs::write(etc.join("resolv.conf"), "nameserver 1.1.1.1\n")?;
    }
    Ok(())
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
}
