//! Writing a container's `/etc/resolv.conf` — host-testable.
//!
//! Every co-located container is pointed at the internal resolver on the bridge
//! gateway (see [`crate::dns`]) by writing a `/etc/resolv.conf` into its rootfs at
//! launch. This mirrors the VMM path's resolv.conf (`boatramp-firecracker`'s
//! `oci::build_rootfs` writes `nameserver 1.1.1.1`) but points the guest at the
//! **gateway**, so both internal names and external DNS flow through boatramp's
//! resolver — closing the container backend's missing-resolv.conf gap.
//!
//! The contents are:
//! ```text
//! nameserver <gateway>
//! search <project>.<domain>
//! ```
//! so a guest can resolve a peer either by the bare short name `web` (the `search`
//! suffix makes the stub try `web.<project>.<domain>`) or by the FQDN directly.
//!
//! The write is pure filesystem work with no syscalls beyond `std::fs`, so it is
//! unit-tested against a temp directory on any host.

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

/// Render a container's `resolv.conf` body pointing at the internal resolver
/// `gateway` with a project-scoped `search` domain (`<project>.<domain>`).
///
/// `domain` is the effective internal suffix (`compute.dns_domain`, default
/// `boatramp.internal`). The trailing newline keeps a POSIX-clean file.
pub fn render(gateway: Ipv4Addr, project: &str, domain: &str) -> String {
    let domain = domain.trim_matches('.');
    format!("nameserver {gateway}\nsearch {project}.{domain}\noptions ndots:1\n")
}

/// Write `resolv.conf` into `rootfs` at `/etc/resolv.conf`, creating `/etc` if it
/// is missing and **overwriting** any resolv.conf already staged (an image may ship
/// one pointing at a public resolver — we replace it so the guest uses boatramp's
/// resolver, exactly as the VMM path replaces it).
///
/// Called by the container backend's launch path, which knows the container's
/// project + the bridge gateway. Best-effort at the call site: a failure to write
/// the resolver config should not abort an otherwise-healthy launch (the guest just
/// falls back to whatever the image shipped), so the caller logs rather than fails.
pub fn write(rootfs: &Path, gateway: Ipv4Addr, project: &str, domain: &str) -> io::Result<()> {
    let etc = rootfs.join("etc");
    std::fs::create_dir_all(&etc)?;
    std::fs::write(etc.join("resolv.conf"), render(gateway, project, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_points_at_the_gateway_with_the_project_search_domain() {
        let body = render(Ipv4Addr::new(10, 0, 0, 1), "acme", "boatramp.internal");
        assert!(
            body.contains("nameserver 10.0.0.1\n"),
            "the single nameserver is the bridge gateway (not 1.1.1.1)"
        );
        assert!(
            body.contains("search acme.boatramp.internal\n"),
            "the search domain is project-scoped so a bare short name resolves"
        );
    }

    #[test]
    fn write_creates_etc_and_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            Ipv4Addr::new(10, 0, 0, 1),
            "acme",
            "boatramp.internal",
        )
        .unwrap();
        let got = std::fs::read_to_string(root.join("etc/resolv.conf")).unwrap();
        assert_eq!(
            got,
            render(Ipv4Addr::new(10, 0, 0, 1), "acme", "boatramp.internal")
        );
    }

    #[test]
    fn write_overwrites_an_image_shipped_resolvconf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        // An image that shipped its own public resolver.
        std::fs::write(root.join("etc/resolv.conf"), "nameserver 8.8.8.8\n").unwrap();
        write(root, Ipv4Addr::new(10, 0, 0, 1), "p", "boatramp.internal").unwrap();
        let got = std::fs::read_to_string(root.join("etc/resolv.conf")).unwrap();
        assert!(
            got.contains("nameserver 10.0.0.1"),
            "the staged public resolver must be replaced by the gateway"
        );
        assert!(!got.contains("8.8.8.8"), "the old resolver must be gone");
    }

    #[test]
    fn custom_domain_is_used_in_the_search_line() {
        let body = render(Ipv4Addr::new(10, 0, 0, 1), "acme", "svc.internal");
        assert!(body.contains("search acme.svc.internal\n"));
    }
}
