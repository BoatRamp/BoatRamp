//! The privsep feature-link `local` transport (privsep Phase 1 — WS-C; design
//! `PLAN-privsep-phase1.md` §3.3, findings F2 / F5). **SECURITY-CRITICAL — this is the
//! inter-instance link substrate.**
//!
//! The `local` transport is a **root-wired `socketpair(2)`** (`AF_UNIX`, `SOCK_STREAM`): the
//! root creates the pair, hands one end's fd to each instance at spawn, and closes both ends
//! itself. **There is NO named socket on a shared path and NO `0700` directory** (design F2):
//! the two were deliberately dropped. The local-link authority proof is the ROOT-WIRED FD
//! TOPOLOGY — an instance can speak only on the socketpair ends the root handed it, to exactly
//! the peer the root wired it to; it holds no name to dial and (per §2 F6) no Landlock grant to
//! any socket directory. There is **no `SO_PEERCRED` check**: every instance runs as the same
//! node uid, so peer-cred distinguishes no sibling (design F2).
//!
//! Two shapes ride one endpoint:
//! - **control / authority call** — a length-delimited typed FRAME ([`LinkEndpoint::send_frame`]
//!   / [`LinkEndpoint::recv_frame`]). Bounded ([`MAX_FRAME_LEN`]) and fail-closed on oversize.
//! - **serving splice (fd-passing)** — the `listen.*`-holder passes an ACCEPTED CLIENT
//!   connection's fd to the serving backend with `SCM_RIGHTS` ([`LinkEndpoint::send_client_conn`]
//!   / [`LinkEndpoint::recv_client_conn`]). This is **UNIDIRECTIONAL** (frontend→backend) and the
//!   received fd confers **NO authority** (design F5): the receiver treats it as opaque CLIENT
//!   bytes — it never type-dispatches on it, never infers identity from it, never assumes it is
//!   anything but a client socket. **No instance ever sends a link fd, a listener fd, or a
//!   key/secret fd over a link** — the only fd that ever crosses is an accepted client connection.
//!
//! **Linux-only in Phase 1 (like the sandbox).** The mechanism (`socketpair`/`SCM_RIGHTS`) is
//! POSIX, so the real implementation is `cfg(unix)` — it compiles and its frame/fd-pass unit
//! tests run on any Unix host (incl. this darwin dev host), giving the protocol real host
//! coverage; the full fork+spawn+sandbox composition is still gated Linux-only by the fail-closed
//! sandbox install ([`crate::sandbox::enforce_privsep_status`] refuses `Unsupported`). A non-Unix
//! build refuses ([`LinkEndpoint::socketpair`] returns an error) — privsep never runs there.
//!
//! WS-E seam: this is a BYTE transport. The per-capability authority-API GRAMMAR + the
//! verifiable COSE-CWT end-principal context (design §3.4) layer ON TOP of [`send_frame`] /
//! [`recv_frame`] later; this module intentionally stops at bounded, typed-agnostic byte frames.

/// The hard ceiling on a control FRAME's payload (1 MiB). A received length prefix larger than
/// this is a fail-closed error BEFORE any allocation — a compromised or confused peer cannot make
/// the receiver allocate an unbounded buffer. The authority-API grammar (WS-E) rides well under it.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// The hard ceiling on the parsed-request HEAD that rides with a passed client fd (256 KiB) — the
/// same fail-closed bound as [`MAX_FRAME_LEN`], sized for request heads rather than whole frames.
pub const MAX_HEAD_LEN: usize = 256 * 1024;

#[cfg(unix)]
pub use unix_impl::LinkEndpoint;

#[cfg(not(unix))]
pub use stub::LinkEndpoint;

#[cfg(unix)]
mod unix_impl {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

    use super::{MAX_FRAME_LEN, MAX_HEAD_LEN};

    /// The single sentinel data byte that carries a passed client fd (`SCM_RIGHTS` requires ≥1 data
    /// byte). Its value is irrelevant — the receiver reads the ancillary fd, not this byte.
    const SPLICE_CARRIER: u8 = 0xF5;

    /// Map a `SO_RCVTIMEO` timeout (surfaced by the kernel as `EAGAIN`/`EWOULDBLOCK` ⇒
    /// [`io::ErrorKind::WouldBlock`]) to a clear fail-closed [`io::ErrorKind::TimedOut`]; pass any
    /// other error through unchanged.
    fn map_timeout(e: io::Error) -> io::Error {
        if e.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "privsep link: read deadline exceeded mid-frame (fail-closed)",
            )
        } else {
            e
        }
    }

    /// Set `FD_CLOEXEC` on `fd` (one portable path in place of the Linux-only `SOCK_CLOEXEC` /
    /// `MSG_CMSG_CLOEXEC`), fail-closed on error.
    fn set_cloexec(fd: RawFd) -> io::Result<()> {
        // SAFETY: `F_GETFD`/`F_SETFD` take no pointers and only read/tighten this fd's flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// One end of a root-wired `socketpair(2)` link. Owns its fd (closed on drop). All I/O is
    /// BLOCKING — a control call is request/response and not per-request-hot (design §3.1), and
    /// the serving splice hands the received client fd to the async serve loop. The caller runs a
    /// blocking recv loop on a dedicated thread / `spawn_blocking` when bridging into Tokio.
    #[derive(Debug)]
    pub struct LinkEndpoint {
        fd: OwnedFd,
    }

    impl LinkEndpoint {
        /// Create a root-wired `socketpair(2)` (`AF_UNIX`, `SOCK_STREAM`), returning the two ends.
        /// Both are created `CLOEXEC` so they never leak to an unrelated `fork`+`exec`ed child; the
        /// root clears `CLOEXEC` on the specific end it passes to a specific instance (via a
        /// `pre_exec` `dup2` to a fixed fd number — the ONLY place an end becomes inheritable).
        pub fn socketpair() -> io::Result<(Self, Self)> {
            let mut fds: [libc::c_int; 2] = [-1, -1];
            // SAFETY: `fds` is a valid 2-element array the kernel fills with the pair's fds.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: both fds are freshly-created, owned, and otherwise unreferenced.
            let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            // Mark both CLOEXEC so they never leak to an unrelated fork+exec — the root clears it
            // on the ONE end it dup2s to a specific instance. (`SOCK_CLOEXEC` is Linux-only, so a
            // post-creation `fcntl` keeps one portable path; the root spawn window is
            // single-threaded, so the brief non-atomic gap cannot leak to a concurrent fork.)
            set_cloexec(a.as_raw_fd())?;
            set_cloexec(b.as_raw_fd())?;
            Ok((Self { fd: a }, Self { fd: b }))
        }

        /// Reconstruct an endpoint from a raw fd a child inherited at a known fd number (the
        /// counterpart to the root's `pre_exec` `dup2`). **SAFETY:** `fd` must be a live socketpair
        /// end this instance was wired with and owns exclusively.
        ///
        /// # Safety
        /// `fd` must be an open, owned `AF_UNIX`/`SOCK_STREAM` socketpair end with no other owner.
        pub unsafe fn from_inherited_fd(fd: RawFd) -> Self {
            // SAFETY: delegated to the caller's contract above.
            Self {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            }
        }

        /// The raw fd (for the root's `dup2` when wiring a child). Does NOT transfer ownership.
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }

        /// Consume the endpoint, returning the raw fd + relinquishing ownership (the caller must
        /// then close it, or pass it to a child).
        pub fn into_raw_fd(self) -> RawFd {
            self.fd.into_raw_fd()
        }

        // ---- control / authority call: length-delimited typed frames ----

        /// Send one length-delimited frame: a 4-byte big-endian length prefix + `payload`. Refuses
        /// (fail-closed) a payload over [`MAX_FRAME_LEN`] — a symmetric bound with the receiver.
        pub fn send_frame(&self, payload: &[u8]) -> io::Result<()> {
            if payload.len() > MAX_FRAME_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "privsep link frame exceeds MAX_FRAME_LEN",
                ));
            }
            let len = (payload.len() as u32).to_be_bytes();
            self.write_all(&len)?;
            self.write_all(payload)
        }

        /// Receive one length-delimited frame. Reads the 4-byte big-endian length, REFUSES a
        /// length over [`MAX_FRAME_LEN`] BEFORE allocating (fail-closed — no unbounded allocation
        /// from an untrusted peer), then reads exactly that many bytes.
        pub fn recv_frame(&self) -> io::Result<Vec<u8>> {
            let mut len_buf = [0u8; 4];
            self.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_FRAME_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "privsep link frame length exceeds MAX_FRAME_LEN — refusing (fail-closed)",
                ));
            }
            let mut buf = vec![0u8; len];
            self.read_exact(&mut buf)?;
            Ok(buf)
        }

        /// Set (or clear) a receive deadline on this endpoint (`SO_RCVTIMEO`). `Some(d)` makes a
        /// blocking `read` that stalls for longer than `d` fail with [`io::ErrorKind::WouldBlock`];
        /// `None` (or a zero duration) restores indefinite blocking. Used by
        /// [`recv_frame_within`](Self::recv_frame_within) to bound an in-progress frame read
        /// (slowloris defense) without bounding the idle wait between calls.
        pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
            let d = dur.filter(|d| !d.is_zero());
            let tv = libc::timeval {
                // A zeroed timeval means "no timeout" to SO_RCVTIMEO, so `None` clears it.
                // Cast targets are INFERRED from the `timeval` field types (`as _`), not named, so
                // we don't touch the `libc::{time_t,suseconds_t}` aliases that libc deprecates on
                // musl (they go 64-bit in musl 1.2.0); behaviour is identical on glibc + musl.
                tv_sec: d.map_or(0, |d| d.as_secs().min(i64::MAX as u64) as _),
                tv_usec: d.map_or(0, |d| d.subsec_micros() as _),
            };
            // SAFETY: `&tv` points at a live, fully-initialized `timeval` of the passed length; the
            // fd is a live owned socket.
            let rc = unsafe {
                libc::setsockopt(
                    self.fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&tv as *const libc::timeval).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Receive one length-delimited frame like [`recv_frame`](Self::recv_frame), but bound the
        /// time to read an IN-PROGRESS frame by `timeout` (fail-closed `TimedOut`). The idle wait for
        /// the FIRST byte of the next call is deliberately UNBOUNDED — an authority link may sit idle
        /// between infrequent control calls (design §3.1) — so the deadline only fires once a peer has
        /// started sending a frame and then stalls (a slowloris / partial-frame peer cannot pin the
        /// serve thread). The [`MAX_FRAME_LEN`] bound is enforced before any allocation, exactly as in
        /// [`recv_frame`](Self::recv_frame). On any outcome the endpoint is restored to blocking mode.
        pub fn recv_frame_within(&self, timeout: std::time::Duration) -> io::Result<Vec<u8>> {
            let mut len_buf = [0u8; 4];
            // Idle-tolerant: block (no deadline) for the first length byte.
            self.set_read_timeout(None)?;
            self.read_exact(&mut len_buf[..1])?;
            // A call has started arriving — bound the remainder.
            self.set_read_timeout(Some(timeout))?;
            let result = (|| {
                self.read_exact(&mut len_buf[1..]).map_err(map_timeout)?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_FRAME_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "privsep link frame length exceeds MAX_FRAME_LEN — refusing (fail-closed)",
                    ));
                }
                let mut buf = vec![0u8; len];
                self.read_exact(&mut buf).map_err(map_timeout)?;
                Ok(buf)
            })();
            // Restore indefinite blocking regardless of the outcome (best-effort on the error path).
            let _ = self.set_read_timeout(None);
            result
        }

        // ---- serving splice: SCM_RIGHTS fd-passing (UNIDIRECTIONAL, F5) ----

        /// Pass ONE accepted CLIENT connection fd to the peer via `SCM_RIGHTS`, with its parsed
        /// request `head` (empty in the Phase-1 raw-splice shape). **Only a `listen.*`-holder
        /// calls this, frontend→backend** — the only fd that ever crosses a link is a client
        /// connection (never a link / listener / key fd; design F5). Wire form: the fd rides in a
        /// `sendmsg` carrying a SINGLE sentinel data byte ([`SPLICE_CARRIER`] — `SCM_RIGHTS` needs
        /// ≥1 data byte to deliver the ancillary fd; one byte sidesteps any partial-read ambiguity
        /// over an `SCM`/stream boundary), followed by a plain length-delimited head frame (a
        /// 4-byte big-endian length + the bytes). Refuses a head over [`MAX_HEAD_LEN`].
        pub fn send_client_conn(&self, client: BorrowedFd<'_>, head: &[u8]) -> io::Result<()> {
            if head.len() > MAX_HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "privsep link request head exceeds MAX_HEAD_LEN",
                ));
            }
            let fds = [client.as_raw_fd()];
            self.sendmsg_with_fds(&[SPLICE_CARRIER], &fds)?;
            let len = (head.len() as u32).to_be_bytes();
            self.write_all(&len)?;
            if !head.is_empty() {
                self.write_all(head)?;
            }
            Ok(())
        }

        /// Receive ONE passed client connection fd + its request head. The returned [`OwnedFd`] is
        /// treated as **opaque client bytes conferring NO authority** (design F5): the caller
        /// serves it as a client socket and never infers identity from it. Fail-closed if no fd
        /// accompanied the message (a header with no `SCM_RIGHTS`), or the head exceeds
        /// [`MAX_HEAD_LEN`].
        pub fn recv_client_conn(&self) -> io::Result<(OwnedFd, Vec<u8>)> {
            // The fd rides with a single sentinel byte, so no length bytes can be split across the
            // SCM/stream boundary; the head frame follows as ordinary length-delimited bytes.
            let mut carrier = [0u8; 1];
            let (_n, fd) = self.recvmsg_with_fd(&mut carrier)?;
            let Some(fd) = fd else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "privsep link: client-conn message carried no fd (fail-closed)",
                ));
            };
            let mut len_buf = [0u8; 4];
            self.read_exact(&mut len_buf)?;
            let head_len = u32::from_be_bytes(len_buf) as usize;
            if head_len > MAX_HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "privsep link request head exceeds MAX_HEAD_LEN — refusing (fail-closed)",
                ));
            }
            let mut head = vec![0u8; head_len];
            self.read_exact(&mut head)?;
            Ok((fd, head))
        }

        // ---- low-level blocking I/O over the raw fd (EINTR-retrying) ----

        fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
            let fd = self.fd.as_raw_fd();
            while !buf.is_empty() {
                // SAFETY: `fd` is a live owned socket; `buf` is a valid slice of `buf.len()` bytes.
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
                        "privsep link: peer closed mid-write",
                    ));
                }
                buf = &buf[rc as usize..];
            }
            Ok(())
        }

        fn read_exact(&self, mut buf: &mut [u8]) -> io::Result<()> {
            let fd = self.fd.as_raw_fd();
            while !buf.is_empty() {
                // SAFETY: `fd` is a live owned socket; `buf` is a valid mutable slice.
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
                        "privsep link: peer closed (EOF) mid-frame",
                    ));
                }
                let n = rc as usize;
                buf = &mut buf[n..];
            }
            Ok(())
        }

        /// One `sendmsg` carrying `data` plus `fds` as an `SCM_RIGHTS` ancillary message.
        fn sendmsg_with_fds(&self, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
            let fd = self.fd.as_raw_fd();
            let fds_bytes = std::mem::size_of_val(fds);
            // SAFETY: CMSG_SPACE is a pure arithmetic macro over the payload size.
            let cmsg_space = unsafe { libc::CMSG_SPACE(fds_bytes as u32) } as usize;
            let mut cmsg_buf = vec![0u8; cmsg_space];
            let mut iov = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            // SAFETY: a zeroed msghdr is valid; we fill the fields we use below.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_space as _;
            // SAFETY: msg_control points at a `cmsg_space`-byte buffer, so CMSG_FIRSTHDR is valid.
            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            if cmsg.is_null() {
                return Err(io::Error::other(
                    "privsep link: CMSG_FIRSTHDR returned null",
                ));
            }
            // SAFETY: `cmsg` points into our buffer with room for the SCM_RIGHTS header + fds.
            unsafe {
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes as u32) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr(),
                    libc::CMSG_DATA(cmsg).cast::<RawFd>(),
                    fds.len(),
                );
            }
            loop {
                // SAFETY: `msg` is a fully-initialized msghdr referencing live buffers.
                let rc = unsafe { libc::sendmsg(fd, &msg, 0) };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
                return Ok(());
            }
        }

        /// One `recvmsg` into `data`, returning the bytes read + the single received fd (if the
        /// message carried an `SCM_RIGHTS` cmsg). At most ONE fd is accepted; any extra received
        /// fds are closed immediately (defense-in-depth — a sender must pass exactly one).
        fn recvmsg_with_fd(&self, data: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
            let fd = self.fd.as_raw_fd();
            // Room for one fd; MSG_CMSG_CLOEXEC marks any received fd close-on-exec.
            // SAFETY: CMSG_SPACE is pure arithmetic.
            let cmsg_space =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
            let mut cmsg_buf = vec![0u8; cmsg_space];
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr().cast(),
                iov_len: data.len(),
            };
            // SAFETY: a zeroed msghdr is valid; we fill the fields we use.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_space as _;
            let rc = loop {
                // SAFETY: `msg` references live buffers. (`MSG_CMSG_CLOEXEC` is Linux-only; we
                // pass 0 and set FD_CLOEXEC on the received fd below for one portable path.)
                let rc = unsafe { libc::recvmsg(fd, &mut msg, 0) };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
                break rc;
            };
            // Own EVERY delivered fd IMMEDIATELY — before any fallible step — so `Drop` guarantees
            // each is closed on ANY early return below (the EOF path, or a `set_cloexec` error): no
            // fd can leak. (Today the control buffer is sized for exactly one fd, so the kernel
            // delivers ≤1 and `MSG_CTRUNC`-closes surplus SENDER fds; owning-first keeps this sound
            // if that buffer is ever enlarged.)
            let mut owned_fds: Vec<OwnedFd> = Vec::new();
            // SAFETY: `msg` was populated by recvmsg; CMSG_FIRSTHDR/NXTHDR walk its cmsgs.
            let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            while !cmsg.is_null() {
                // SAFETY: `cmsg` is a valid cmsg header from the walk above.
                let (level, ty, len) = unsafe {
                    (
                        (*cmsg).cmsg_level,
                        (*cmsg).cmsg_type,
                        (*cmsg).cmsg_len as usize,
                    )
                };
                if level == libc::SOL_SOCKET && ty == libc::SCM_RIGHTS {
                    // SAFETY: CMSG_LEN(0) is the header size; the remainder is the fd array.
                    let hdr_len = unsafe { libc::CMSG_LEN(0) } as usize;
                    let count = (len - hdr_len) / std::mem::size_of::<RawFd>();
                    // SAFETY: CMSG_DATA points at `count` RawFds inside our cmsg buffer.
                    let data_ptr = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
                    for i in 0..count {
                        // SAFETY: `i < count`, in bounds; each fd is freshly-owned by this process.
                        let raw = unsafe { data_ptr.add(i).read_unaligned() };
                        owned_fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
                // SAFETY: walking to the next cmsg of the same recvmsg buffer.
                cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
            }
            // Orderly EOF: every owned fd drops here (closed) — fail-closed, no leak even if the
            // kernel ever attached an fd to a zero-length read.
            if rc == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "privsep link: peer closed (EOF) before the client-conn message",
                ));
            }
            // Accept exactly ONE fd; surplus (if any) drops → closed. CLOEXEC the accepted client
            // fd (MSG_CMSG_CLOEXEC is Linux-only) so a later re-exec cannot leak it; on a
            // set_cloexec error the accepted fd AND the surplus iterator both drop → closed.
            let mut fds = owned_fds.into_iter();
            let received = match fds.next() {
                Some(first) => {
                    set_cloexec(first.as_raw_fd())?;
                    Some(first)
                }
                None => None,
            };
            drop(fds); // close any surplus fds explicitly
            Ok((rc as usize, received))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::AsFd;

        #[test]
        fn frame_round_trips() {
            let (a, b) = LinkEndpoint::socketpair().expect("socketpair");
            a.send_frame(b"hello authority call").unwrap();
            let got = b.recv_frame().unwrap();
            assert_eq!(got, b"hello authority call");
            // An empty frame is valid (a zero-length payload).
            a.send_frame(b"").unwrap();
            assert_eq!(b.recv_frame().unwrap(), Vec::<u8>::new());
        }

        #[test]
        fn send_frame_refuses_oversize_before_write() {
            let (a, _b) = LinkEndpoint::socketpair().expect("socketpair");
            let huge = vec![0u8; MAX_FRAME_LEN + 1];
            let err = a.send_frame(&huge).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }

        #[test]
        fn recv_frame_refuses_oversize_length_prefix_without_allocating() {
            // Hand-craft an over-limit length prefix on the wire; the receiver must refuse it
            // BEFORE allocating the buffer (fail-closed against an untrusted peer).
            let (a, b) = LinkEndpoint::socketpair().expect("socketpair");
            let bogus = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes();
            a.write_all(&bogus).unwrap();
            let err = b.recv_frame().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        }

        #[test]
        fn recv_frame_within_times_out_on_a_stalled_partial_frame() {
            // A peer that sends a partial length prefix then stalls must not pin the receiver: the
            // in-progress read is bounded, surfacing a fail-closed TimedOut (slowloris defense).
            let (a, b) = LinkEndpoint::socketpair().expect("socketpair");
            // Send ONE length byte, then stall (never send the rest).
            a.write_all(&[0x00]).unwrap();
            let err = b
                .recv_frame_within(std::time::Duration::from_millis(150))
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        }

        #[test]
        fn recv_frame_within_reads_a_complete_frame() {
            // A frame that fully arrives is returned, and the endpoint is restored to blocking mode
            // (a following ordinary recv_frame still works).
            let (a, b) = LinkEndpoint::socketpair().expect("socketpair");
            a.send_frame(b"authority call under a deadline").unwrap();
            let got = b
                .recv_frame_within(std::time::Duration::from_secs(5))
                .unwrap();
            assert_eq!(got, b"authority call under a deadline");
            a.send_frame(b"second").unwrap();
            assert_eq!(b.recv_frame().unwrap(), b"second");
        }

        #[test]
        fn client_fd_passes_with_head_and_is_usable() {
            // Pass one end of a second socketpair as the "client connection" + a head, then prove
            // the received fd is a live, independent socket by round-tripping a byte through it.
            let (link_a, link_b) = LinkEndpoint::socketpair().expect("link pair");
            let (client_near, client_far) = LinkEndpoint::socketpair().expect("client pair");

            link_a
                .send_client_conn(client_far.as_fd_borrow(), b"HEAD-BYTES")
                .unwrap();
            let (recv_fd, head) = link_b.recv_client_conn().unwrap();
            assert_eq!(head, b"HEAD-BYTES");

            // The received fd is the far end of the client pair: writing on `client_near` must be
            // readable through the passed fd (proving it is the real, transferred socket).
            let near = client_near;
            near.send_frame(b"ping").unwrap();
            // Wrap the received raw fd back into an endpoint to read the framed bytes.
            let recv_ep = unsafe { LinkEndpoint::from_inherited_fd(recv_fd.into_raw_fd()) };
            assert_eq!(recv_ep.recv_frame().unwrap(), b"ping");
        }

        #[test]
        fn empty_head_is_valid() {
            let (link_a, link_b) = LinkEndpoint::socketpair().expect("link pair");
            let (_c0, c1) = LinkEndpoint::socketpair().expect("client pair");
            link_a.send_client_conn(c1.as_fd_borrow(), b"").unwrap();
            let (_fd, head) = link_b.recv_client_conn().unwrap();
            assert!(head.is_empty());
        }

        // A tiny borrow helper so the tests can pass an endpoint's fd as the "client" fd.
        impl LinkEndpoint {
            fn as_fd_borrow(&self) -> std::os::fd::BorrowedFd<'_> {
                self.fd.as_fd()
            }
        }
    }
}

#[cfg(not(unix))]
mod stub {
    use std::io;

    /// Non-Unix stub: privsep's `local` transport needs `socketpair`/`SCM_RIGHTS` (POSIX), and
    /// privsep is Linux-only in Phase 1 — so every constructor fails-closed. The argv dispatch +
    /// the fail-closed sandbox install already prevent privsep from running here; this keeps the
    /// crate building on non-Unix targets.
    #[derive(Debug)]
    pub struct LinkEndpoint {
        _never: std::convert::Infallible,
    }

    impl LinkEndpoint {
        pub fn socketpair() -> io::Result<(Self, Self)> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "privsep local transport (socketpair/SCM_RIGHTS) is Unix-only; privsep is \
                 Linux-only in Phase 1",
            ))
        }
    }
}
