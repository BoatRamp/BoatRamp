//! A host **tap** device for the embedded VMM's virtio-net: open
//! `/dev/net/tun`, attach a named tap interface via `TUNSETIFF`
//! (`IFF_TAP | IFF_NO_PI` — raw layer-2 Ethernet frames, no 4-byte packet-info
//! prefix and no virtio-net header offload), and read/write frames.
//!
//! The device's [`VirtioNet`](crate::virtio_net::VirtioNet) backend strips the
//! 12-byte `virtio_net_hdr` on TX and prepends a zero one on RX, so the tap deals
//! in bare frames (hence `IFF_NO_PI` + no `IFF_VNET_HDR`). The host-side plumbing
//! — enslaving the tap to a bridge + assigning the guest-subnet gateway IP — is
//! the orchestrator's job (the [`net`](crate::net)/IPAM layer); this owns just the
//! fd. Opening the tap needs `CAP_NET_ADMIN`, so it's the KVM-host (`compute-live`)
//! seam.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

use crate::embedded_vmm::VmmError;

/// `IFF_TAP` — an Ethernet (layer-2) tap, not a layer-3 `tun`.
const IFF_TAP: i16 = 0x0002;
/// `IFF_NO_PI` — no 4-byte packet-information prefix; the fd carries bare frames.
const IFF_NO_PI: i16 = 0x1000;

/// `struct ifreq` (Linux, 40 bytes): the 16-byte interface name then a union
/// whose first member here is the 16-bit flags word. Only `name` + `flags` are
/// read by `TUNSETIFF`; the rest pads out to the kernel's `sizeof(struct ifreq)`.
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

// `TUNSETIFF` = `_IOW('T', 202, int)` — the request size is `sizeof(int)`, *not*
// `sizeof(ifreq)`, so it's a "bad" ioctl needing the explicit request code.
nix::ioctl_write_ptr_bad!(
    tun_set_iff,
    nix::request_code_write!(b'T', 202, ::std::mem::size_of::<u32>()),
    IfReq
);

/// An open tap fd attached to a named host interface.
pub struct Tap {
    file: File,
    name: String,
}

impl Tap {
    /// Open `/dev/net/tun` and attach the tap interface `name` (created by the
    /// kernel if absent). The interface comes up unconfigured + down; the caller
    /// brings it up and plumbs it into the host network. Needs `CAP_NET_ADMIN`.
    pub fn open(name: &str) -> Result<Self, VmmError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| VmmError::Kvm(format!("open /dev/net/tun: {e}")))?;

        let mut req = IfReq {
            name: [0u8; 16],
            flags: IFF_TAP | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        let raw = name.as_bytes();
        let n = raw.len().min(15); // leave room for the NUL terminator
        req.name[..n].copy_from_slice(&raw[..n]);

        // SAFETY: `req` is a fully-initialized `ifreq` and `file` is the freshly
        // opened `/dev/net/tun` character device; `TUNSETIFF` reads `req` and
        // attaches the fd to the named tap.
        unsafe { tun_set_iff(file.as_raw_fd(), &req) }
            .map_err(|e| VmmError::Kvm(format!("TUNSETIFF {name}: {e}")))?;

        Ok(Self {
            file,
            name: name.to_string(),
        })
    }

    /// The attached interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A second handle to the same tap (a `dup`'d fd) — used to give the device
    /// the TX side while a separate RX poller owns the read side.
    pub fn try_clone(&self) -> Result<Self, VmmError> {
        Ok(Self {
            file: self
                .file
                .try_clone()
                .map_err(|e| VmmError::Kvm(format!("clone tap {}: {e}", self.name)))?,
            name: self.name.clone(),
        })
    }

    /// The raw fd (for `poll`-ing the read side in the RX loop).
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.file).read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.file).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.file).flush()
    }
}
