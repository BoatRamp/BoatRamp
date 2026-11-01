//! Shared, dependency-free (`libc` + `std` only) blocking length-delimited frame I/O over a raw
//! fd, and the canonical request/response EXCHANGE used by every byte-carrying substrate
//! (byte-relay, container, vsock). Deliberately standalone (no crate deps beyond `libc`) so the
//! SAME file compiles into both the full bench binary and the minimal musl-static firecracker
//! guest init (`vsock_guest_main.rs`), which must stay tiny.
//!
//! Wire shape, one exchange:
//!   client -> server: 4-byte BE head length + head bytes (the representative RequestHead)
//!   client -> server: 4-byte BE desired response length
//!   server -> client: 4-byte BE response length + response bytes (the served payload)
//! The server loops accepting further exchanges on the same connection until EOF (steady-state
//! "warm" throughput); a fresh connection per call is how "cold"/spawn cost is measured instead.
//!
//! Shared by two roles that each use only HALF this file (the host-side bench uses
//! `client_exchange`/`read_frame`; the guest init uses only `server_loop`) — `dead_code` would
//! otherwise fire in whichever crate root doesn't call the other side's half.
#![allow(dead_code)]

use std::io;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

/// A frame over [`MAX_WIRE_FRAME`] is refused before allocating — same fail-closed shape as the
/// real `privsep_link` frames, sized generously for the largest benchmark payload (2 MiB) plus
/// headroom.
pub const MAX_WIRE_FRAME: usize = 8 * 1024 * 1024;

pub fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is a live, owned (by the caller) socket/stream fd; `buf` is a valid slice.
        let rc = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "peer closed mid-write",
            ));
        }
        buf = &buf[rc as usize..];
    }
    Ok(())
}

pub fn read_exact(fd: RawFd, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is a live fd; `buf` is a valid mutable slice of its own length.
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed (EOF) mid-frame",
            ));
        }
        let n = rc as usize;
        buf = &mut buf[n..];
    }
    Ok(())
}

pub fn write_u32(fd: RawFd, v: u32) -> io::Result<()> {
    write_all(fd, &v.to_be_bytes())
}

pub fn read_u32(fd: RawFd) -> io::Result<u32> {
    let mut b = [0u8; 4];
    read_exact(fd, &mut b)?;
    Ok(u32::from_be_bytes(b))
}

pub fn write_frame(fd: RawFd, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_WIRE_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds MAX_WIRE_FRAME",
        ));
    }
    write_u32(fd, payload.len() as u32)?;
    write_all(fd, payload)
}

/// Reads one length-delimited frame into `buf`, resizing it to the received length first
/// (reused across calls by the hot loop to avoid a fresh allocation every iteration).
pub fn read_frame_into(fd: RawFd, buf: &mut Vec<u8>) -> io::Result<()> {
    let len = read_u32(fd)? as usize;
    if len > MAX_WIRE_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length exceeds MAX_WIRE_FRAME",
        ));
    }
    buf.resize(len, 0);
    read_exact(fd, buf)
}

pub fn read_frame(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    read_frame_into(fd, &mut buf)?;
    Ok(buf)
}

/// Client side of one exchange: send `head`, send the desired response length, then block for
/// and fully read the response — returning the wall-clock elapsed for the WHOLE round trip (the
/// decision-relevant "crossing + serve + return" cost for a byte-carrying substrate) and the
/// response buffer (reused across calls, like `read_frame_into`).
pub fn client_exchange(
    fd: RawFd,
    head: &[u8],
    response_len: usize,
    resp_buf: &mut Vec<u8>,
) -> io::Result<Duration> {
    let t0 = Instant::now();
    write_frame(fd, head)?;
    write_u32(fd, response_len as u32)?;
    read_frame_into(fd, resp_buf)?;
    Ok(t0.elapsed())
}

/// Server side: handle exactly one exchange (read head, read desired length, write that many
/// bytes of `fill`). Returns `Ok(false)` on a clean EOF (peer closed, no partial frame) to let
/// the caller loop until the client disconnects, `Ok(true)` after serving normally.
pub fn server_serve_one(
    fd: RawFd,
    head_buf: &mut Vec<u8>,
    fill: u8,
    resp_scratch: &mut Vec<u8>,
) -> io::Result<bool> {
    match read_frame_into(fd, head_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e),
    }
    let want = read_u32(fd)? as usize;
    if resp_scratch.len() != want {
        resp_scratch.clear();
        resp_scratch.resize(want, fill);
    }
    write_frame(fd, resp_scratch)?;
    Ok(true)
}

/// Runs the server loop until the peer disconnects (EOF) — the steady-state "warm" backend body
/// shared by byte-relay / container / vsock-loopback / vsock-guest.
pub fn server_loop(fd: RawFd, fill: u8) -> io::Result<()> {
    let mut head_buf = Vec::new();
    let mut resp_scratch = Vec::new();
    loop {
        match server_serve_one(fd, &mut head_buf, fill, &mut resp_scratch) {
            Ok(true) => continue,
            Ok(false) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}
