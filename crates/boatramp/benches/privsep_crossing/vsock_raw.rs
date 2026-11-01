//! Hand-rolled `AF_VSOCK` syscalls (`libc` + `std` only, no `vsock`/`nix` crate) — the same
//! style as `boatramp-server::privsep_link`'s raw `SCM_RIGHTS` code. Standalone on purpose: this
//! file is shared, via `#[path]`, by the full bench binary (the host-side loopback driver) AND
//! the minimal musl-static firecracker guest init (`vsock_guest_main.rs`), which must stay tiny
//! and cannot afford any extra dependency.
//!
//! `AF_VSOCK` (40) and the well-known CIDs are ABI-stable across every Linux architecture, so
//! they're defined here as plain constants rather than pulled from a crate (`libc` has gated
//! `sockaddr_vm`/`AF_VSOCK` support only on some versions/targets; hand-rolling removes that
//! version-coupling entirely). `struct sockaddr_vm` layout: see `linux/vm_sockets.h`.
//!
//! Shared by two different roles that each use only HALF this file's surface (the host-side
//! bench uses `connect_vsock`/`VMADDR_CID_LOCAL`/`VMADDR_CID_HOST`; the guest init uses
//! `bind_vsock`/`VMADDR_CID_ANY`/`listen_vsock`/`accept_vsock`) — `dead_code` would otherwise
//! fire in whichever crate root doesn't call the other side's half.
#![allow(dead_code)]

use std::io;
use std::os::fd::RawFd;

pub const AF_VSOCK: i32 = 40;
pub const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
pub const VMADDR_CID_HOST: u32 = 2;
/// The host-local vsock loopback transport (Linux >= 5.6, module `vsock_loopback`) — lets a
/// single host measure a REAL `AF_VSOCK` round trip with no hypervisor, which is the sanctioned
/// fallback/lower-bound substrate when a real firecracker guest isn't stood up.
pub const VMADDR_CID_LOCAL: u32 = 1;
pub const VMADDR_PORT_ANY: u32 = 0xFFFF_FFFF;

/// Mirrors `struct sockaddr_vm` from `linux/vm_sockets.h`: family + reserved + port + cid + a
/// zero-pad tail sized so the whole struct matches `sizeof(struct sockaddr)` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrVm {
    svm_family: libc::sa_family_t, // u16
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

fn sockaddr_vm(cid: u32, port: u32) -> SockaddrVm {
    SockaddrVm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    }
}

fn last_err(what: &str) -> io::Error {
    io::Error::other(format!("{what}: {}", io::Error::last_os_error()))
}

pub fn socket_vsock() -> io::Result<RawFd> {
    // SAFETY: a plain `socket(2)` call with no pointers.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(last_err("socket(AF_VSOCK)"));
    }
    Ok(fd)
}

pub fn bind_vsock(fd: RawFd, cid: u32, port: u32) -> io::Result<()> {
    let addr = sockaddr_vm(cid, port);
    // SAFETY: `addr` is a valid, fully-initialized sockaddr_vm; its size matches `sockaddr`'s.
    let rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const SockaddrVm).cast(),
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_err("bind(AF_VSOCK)"));
    }
    Ok(())
}

pub fn listen_vsock(fd: RawFd, backlog: i32) -> io::Result<()> {
    // SAFETY: `fd` is a live socket.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc != 0 {
        return Err(last_err("listen(AF_VSOCK)"));
    }
    Ok(())
}

/// Blocks until one connection arrives, returning the accepted fd (its peer CID/port discarded —
/// the benchmark doesn't need them).
pub fn accept_vsock(fd: RawFd) -> io::Result<RawFd> {
    // SAFETY: null addr/addrlen is a valid `accept(2)` call when the peer address isn't wanted.
    let rc = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if rc < 0 {
        return Err(last_err("accept(AF_VSOCK)"));
    }
    Ok(rc)
}

pub fn connect_vsock(fd: RawFd, cid: u32, port: u32) -> io::Result<()> {
    let addr = sockaddr_vm(cid, port);
    // SAFETY: `addr` is valid and correctly sized, as in `bind_vsock`.
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const SockaddrVm).cast(),
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_err("connect(AF_VSOCK)"));
    }
    Ok(())
}

pub fn close_fd(fd: RawFd) {
    // SAFETY: `fd` is a live fd owned by the caller, closed exactly once here.
    unsafe {
        libc::close(fd);
    }
}
