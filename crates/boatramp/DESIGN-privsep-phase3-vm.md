# DESIGN — privsep Phase-3 substrate: the **VM (vsock)** spawn backend

*Crate-local design note (privsep Phase-3, item 3c). Branch `privsep-phase3-vm`, built on
`feat/privsep` tip `20f8516b` (carries Phases 0–4 + WS-D + WS-E + Wave-2 + the **Container**
substrate, design-note `DESIGN-privsep-phase3-container.md`). Status: **DESIGN-FIRST — `Vm` stays
REFUSED fail-closed.** This pass maps the VM substrate precisely and surfaces the owner + Security
decisions it forces; it lands only SAFE, fail-closed scaffolding (a sharpened refusal + an
`#[ignore]`d fail-closed live gate that inverts later). It does NOT wire the VM backend. TCB-critical;
every load-bearing choice is FLAGGED for owner + Security ratification, not guessed. §8 is the
explicit decision list.*

The Container increment was deliberately design-first because substrate-wiring surfaced an owner +
Security decision on the hosting model (what rootfs/binary runs inside) before any safe wiring was
possible (`DESIGN-privsep-phase3-container.md` §1). **The VM substrate hits the SAME class of
decision, PLUS a transport problem the Container did not have:** the OsProcess/Container transport
passes file descriptors (an `AF_UNIX` socketpair end + the listener fd, and per-request a client fd
over `SCM_RIGHTS`) to hand each instance its root-wired links — and **fd-passing CANNOT cross a VM
boundary** (the guest has its own kernel; an fd is an index into a kernel fd table, meaningless in
another kernel). So the VM substrate needs a **vsock byte-relay transport** in place of the whole
fd-pass topology. This is strictly harder than Container and is the reason `Vm` was deferred when
Container was wired (`DESIGN-privsep-phase3-container.md` §6; `privsep.rs:884-888`).

---

## 0. The question

Wire `[privsep].instances.<name>.substrate = "vm"` so the root supervisor spawns a
privilege-separated feature-instance inside a hardware-virtualized microVM guest (its own kernel —
the strongest wall, surviving a guest-kernel RCE), **preserving every Phase-1 guarantee**
(materialization-by-construction, the per-capability `Enforced` seccomp/Landlock wall, env-blindness,
`FailNodeClosed`, the root-wired link topology, secret-blindness of the root), instead of the current
fail-closed refusal in [`resolve_spawn_backend`](src/privsep.rs) (`privsep.rs:889`, refusing `Vm`).

**Verdict of this pass: the VM substrate cannot be wired end-to-end in this cut.** It is blocked on
(a) a transport re-plumb from fd-passing to a vsock byte-relay (§1), which is a genuinely new link
substrate, not an extension of `privsep_link`; and (b) a hosting-model decision (what guest
kernel + root filesystem runs inside, and how the host's own binary becomes the guest init) that is
TCB-critical and must be ratified by the owner + Security (§2); plus open secret-blindness (§3),
networking (§4), and defense-in-depth (§5) questions. The substrate therefore stays refused
fail-closed, with a sharpened refusal naming the concrete blockers and pointing here. Flagging beats
guessing on the root's spawn sequence and on where key material lives.

### The OsProcess/Container baseline we must not regress (what "preserve every guarantee" means)

The wired `OsProcess` / `Container` backend, in `supervise::run` (`privsep.rs:1992`) +
`spawn_wired_instance` (`privsep.rs:1273`), gives each instance its root-wired world **by passing
open fds across a `fork`+`exec` on ONE shared kernel**:

1. a root-created `socketpair(2)` per `local` link (`LinkEndpoint::socketpair`,
   `privsep_link.rs:105`; `supervise::run` step 1, `privsep.rs:2046-2077`), both ends `CLOEXEC`;
2. the root binds each `listen.*` holder's privileged public listener and keeps the fd open (step 2,
   `privsep.rs:2079-2089`);
3. each inherited end/listener is assigned a globally-unique target fd number above every source fd;
   the per-instance `BOATRAMP_PRIVSEP_FDS` map names `link → fd` + `listener → fd` (step 3,
   `privsep.rs:2091-2134`);
4. `spawn_wired_instance`'s `pre_exec` `dup2`s each `(src → tgt)`, clears `CLOEXEC`, sets
   `PR_SET_PDEATHSIG(SIGKILL)`, drops all caps (Finding 2), then re-execs
   `boatramp __instance <label> --config <path>` (`privsep.rs:1315-1425`);
5. in the child, `run_instance` → `instance_serve` installs the per-capability seccomp + Landlock
   profile itself (fail-closed `Enforced`), reconstructs its endpoints from the inherited fds, and
   serves; a `listen.*` frontend `accept`s client TCP on its inherited listener fd and passes each
   accepted **client** connection fd to the backend over the link with `SCM_RIGHTS`
   (`LinkEndpoint::send_client_conn`/`recv_client_conn`, `privsep_link.rs:257`/`279`,
   **UNIDIRECTIONAL, confers NO authority** — design F5);
6. the root installs its own tightest self-profile AFTER the spawn loop, then supervises: **any child
   exit tears the whole node down (`FailNodeClosed`)** (step 6, `privsep.rs:2263`).

**Every one of those crossings is an fd handover on one shared kernel.** The VM substrate must
deliver the SAME six properties when the instance lives behind a hypervisor with its own kernel —
where steps 1, 2, 4 (the fd dups), and the step-5 `SCM_RIGHTS` splice **cannot happen at all**. That
is the whole difficulty.

---

## 1. Transport re-plumb — the core problem **[FLAG — the load-bearing transport decision]**

Everything an instance receives today is an **fd**. None can cross the VM boundary. Below, each one,
with how it must cross over vsock, which side binds, and how the link's framing + "no authority from
a received fd" invariant (design F5) is preserved.

### 1a. What vsock is, and what the bench already proved

`AF_VSOCK` is a host↔guest socket family addressed by `(CID, port)` — the guest kernel and the host
hypervisor shuttle the bytes; it needs no guest IP stack. The crossing-cost bench already stood up
and measured a REAL vsock byte-relay (`benches/privsep_crossing/vsock.rs`,
`vsock_raw.rs`, `vsock_guest_main.rs`):

- host-side dials the guest through **firecracker's own host-side vsock UDS bridge**: connect to the
  device's `uds_path`, send `CONNECT <port>\n`, read `OK <port>\n`, then the UDS connection is a
  plain byte stream mirroring the guest's `AF_VSOCK` connection on that port
  (`vsock.rs:141-170`, `dial_firecracker_vsock`);
- guest-side (`vsock_guest_main.rs`) binds `AF_VSOCK` on `VMADDR_CID_ANY:5201`, `accept`s, sends a
  one-shot `READY` frame, then runs the SAME length-delimited request/response exchange
  (`wire::server_loop`) every byte-carrying substrate runs;
- the exchange is framed exactly like `privsep_link`'s control frames: a 4-byte big-endian length +
  bytes, with a fail-closed `MAX_WIRE_FRAME` bound BEFORE allocation (`wire.rs:83-112`) — the same
  shape as `privsep_link`'s `MAX_FRAME_LEN` (`privsep_link.rs:39`,`151-181`).
- measured cost (`docs/privsep-substrate-benchmark.md` §3): **~27 µs warm → ~736 µs at 2 MiB**, plus
  **~121 ms VM boot**, vs OsProcess fd-pass **~7 µs flat**. The vsock crossing is a byte-relay (one
  extra copy each way, like `byterelay`), NOT an fd handover — that cost shape is intrinsic (§1d).

So the byte-relay transport is a SOLVED, measured mechanism. What is NOT solved is wiring it into the
privsep link topology so a VM instance gets its real, root-authorized links — and reconciling it with
firecracker's UDS-bridge model and vz's (different) vsock model (§6).

### 1b. The feature-link ends (every `local` link an instance holds)

Today: a root-created `socketpair(2)`; the root `dup2`s one end into the child. Over a VM boundary
the socketpair cannot cross, so **each feature-link becomes a vsock stream** carrying the SAME
`send_frame`/`recv_frame` control frames (`privsep_link.rs:149-245`) — the byte-level protocol is
unchanged; only the carrier changes from a socketpair fd to a vsock connection.

- **Who binds / CID+port assignment [FLAG].** The guest is the natural listener (it has a fixed CID;
  the bench guest binds `VMADDR_CID_ANY:<port>`). The root must assign each VM instance a unique guest
  CID and each of its links a unique guest vsock port, then, for a `local` link whose OTHER end is a
  **host-side** sibling (OsProcess/Container), the root (secret-blind) must run a **host relay** that
  dials the guest CID:port and splices bytes between the host sibling's socketpair end and the vsock
  stream. For a link whose both ends are in (different) VMs, the relay bridges two vsock streams. The
  **CID/port map is the new root-wired topology** — the exact analog of the `BOATRAMP_PRIVSEP_FDS` fd
  map, and equally security-load-bearing: an instance may speak only on the CID:ports the root wired
  it, to exactly the peer the root bridged. This map, the relay's lifecycle, and its fail-closed
  teardown (a relay death must trip `FailNodeClosed`) are **new TCB that must be designed with
  Security.**
- **Authority invariant preserved.** The `local` transport's authority proof is the root-wired fd
  topology, not any name or peer-cred (`privsep_link.rs:5-12`: no named socket, no `SO_PEERCRED`).
  Over vsock the proof becomes the **root-wired CID:port bridging**: the instance holds no CID to dial
  except the one the root handed it, and the root's relay connects it only to its wired peer. This
  must be stated and enforced structurally (a VM instance must NOT be able to dial an arbitrary CID —
  the guest's vsock egress must be confined to the host relay, which is the only peer it can reach;
  see §4). **FLAG: confirm the guest cannot reach a sibling VM's CID directly** (vsock is host↔guest
  by default — guest↔guest needs explicit `vsock_loopback`/routing that must NOT be enabled).

### 1c. The public listener fd (a `listen.*` frontend)

Today: the root binds the privileged TCP listener and `dup2`s the fd into the frontend
(`privsep.rs:2079-2089`,`2123-2128`). A frontend in a VM **cannot receive that host fd.** Two models,
and **which one is an owner app-design decision** (§4):

- **Model A — host relays accepted client connections inward over vsock (frontend stays a POLICY
  POINT).** The root (or a thin root-side acceptor) keeps the bound TCP listener on the host,
  `accept`s each client, and relays the client bytes to the frontend-in-VM over a dedicated vsock
  stream. This is exactly the `byterelay` shape (`benches/privsep_crossing/byterelay.rs:1-4`: "the
  frontend stays a POLICY POINT — it can inspect/transform bytes — rather than splicing a raw fd").
  It preserves the root-binds-privileged-port invariant (the guest never binds :443), costs the
  byte-relay copy, and keeps the frontend able to inspect/transform. **Recommended default to bring
  as INPUT.**
- **Model B — the guest binds inside its own netns.** The microVM gets a tap/bridge + a routable
  guest IP (firecracker `net.rs`; vz vmnet) and binds the port itself. This drags in the FULL
  compute-plane networking machinery (IPAM, bridge, egress NAT) that the Container note already
  flagged as the "wrong seam" for a privsep instance (`DESIGN-privsep-phase3-container.md` §1), plus
  it moves privileged-port binding into the guest — a regression of the "root binds the privileged
  listener; the frontend's profile denies `bind`" invariant. **Not recommended for a first cut.**

### 1d. The `SCM_RIGHTS` client-conn splice (frontend → backend) — the crossing that CANNOT survive

Today the serving hot path is zero-copy: the frontend passes the accepted **client fd itself** to the
backend with `SCM_RIGHTS` (`privsep_link.rs:257`), and the backend serves the real client socket
directly. **This fd cannot cross into a VM backend.** So for a backend-in-VM the splice MUST become a
**vsock byte-relay of the client's bytes** (the frontend/root reads the client socket and writes the
bytes over vsock; reads the response back and writes it to the client). This is why the VM crossing is
a byte-relay cost (~27→736 µs), not the flat ~7 µs fd-pass — **the zero-copy fd handover is
structurally impossible across a hypervisor, and that is the intrinsic price of the VM wall**
(`docs/privsep-substrate-benchmark.md` §3-4). The received-bytes invariant is actually *stronger*
here: the backend receives opaque client BYTES, never an fd, so "a received fd confers no authority"
(F5) is trivially preserved — there is no fd. The request `head` that rides with the splice today
(`send_client_conn`'s `head`, `privsep_link.rs:257`) rides as a leading frame over the vsock stream,
exactly as the bench exchange sends a head frame (`wire.rs:118-129`).

### 1e. Reconciliation with the bench `vsock.rs`

The bench is the faithful lower-level reference: `vsock_raw.rs` is the exact hand-rolled `AF_VSOCK`
syscall surface (same style as `privsep_link`'s raw `SCM_RIGHTS`), and `wire.rs` is the exact
fail-closed framed-byte protocol. The production transport would **lift `wire.rs`'s framing to carry
`privsep_link`'s `send_frame`/`recv_frame` + the client-head frame**, and **lift the firecracker UDS
`CONNECT` bridge** (`vsock.rs:141-170`) into the root's host-side relay. What the bench does NOT
provide — and what this design must add — is (i) the root-wired CID/port TOPOLOGY + relay lifecycle
(§1b), (ii) the listener-inward relay (§1c Model A), (iii) the own-binary guest init that serves a
REAL privsep instance slice rather than the bench's trivial echo server (§2), and (iv) the
secret-blindness reconciliation (§3). **The bench proves the wire is real and measured; it is not the
privsep transport.**

---

## 2. Hosting model — the owner + Security decision **[FLAG — the blocker, like the container's §1]**

**Requirement (same as OsProcess/Container).** The guest must run the **host's own static-musl
`boatramp` binary** in `__instance` mode — NOT an arbitrary OCI/VM image. A VM instance is the same
`boatramp __instance <label>` the OsProcess backend re-execs, only booted inside a microVM with its
own kernel. This forces a guest-image decision that is genuinely ambiguous and TCB-critical, because a
VM — unlike a process or a namespace — needs a **guest kernel** and a **root filesystem / init**, and
the host binary has to BECOME the guest init.

**What the two backends actually boot today (read in full):**

- `boatramp-firecracker`'s production backend (`backend.rs`/`config.rs`) boots a
  `ComputeSpec` → a `BootSource` (kernel + cmdline) + **`drives`** (an `ext4` **rootfs** root device +
  an ephemeral scratch) + a **virtio-net tap** on a host bridge with per-node IPAM
  (`config.rs:60-166`, `lib.rs:1-21`). Env rides as a hex kernel-cmdline fragment
  (`config.rs:101-108`). **There is NO vsock** — `config.rs:107` says a secret binding token "wants
  MMDS/vsock (a later refinement)." This `ComputeSpec`→ext4+IP shape is the compute-plane seam and is
  the **wrong seam** for a privsep instance, exactly as the Container note found `ComputeBackend::
  launch` was (`DESIGN-privsep-phase3-container.md` §1).
- `boatramp-vz`'s backend (macOS) boots the SAME `Artifact::VmImages` (an ext4 rootfs + a guest
  `vmlinux`) via `VZVirtualMachineConfiguration` with a virtio-blk root + virtio-net vmnet NAT +
  serial console (`vz/src/vm.rs:28-70`), each replica in a re-exec'd `boatramp __vz-run` child
  (`vz/src/lib.rs:11-14`). **Also no vsock** — `vz/src/config.rs:99` repeats "wants vsock (a later
  refinement)."
- The bench firecracker harness boots a DIFFERENT, far simpler shape that is the right model for
  privsep: **kernel + initramfs**, `"drives": []`, `rdinit=/init`, a vsock device, NO net
  (`vsock.rs:100-117`). The guest's `/init` IS the boatramp-derived binary (`vsock_guest_main.rs`;
  `guest/build-initrd.sh` cpio-packs the static binary as `/init`). This is **own-binary-as-init**.

**The options (bring as INPUT; owner + Security ratify):**

- **Option A — minimal purpose-built initramfs with the host binary injected as `/init`.** Mirror the
  bench: a tiny cpio initramfs containing just the static-musl `boatramp` as `/init` (+ the config +
  the `SYSTEM_READ_ROOTS` it needs), booted `rdinit=/init`, no root block device, no guest net,
  vsock-only (§1). **Smallest guest TCB** (no distro userland, no OCI pull, no IPAM/bridge), closest
  to the privsep model, and it reuses the firecracker VMM PROCESS + its vsock device — NOT the
  compute-plane `launch()`/`ComputeSpec` path. **Recommended default to bring as INPUT**, for the same
  reason Option C won for Container: it preserves the Phase-1 model with the least new TCB. Cost: a new
  initramfs-assembly path (the bench's `build-initrd.sh` is a lighthouse-only prototype, `lib`
  comment line 15), and the own-binary relocation caveat below.
- **Option B — a full guest rootfs (ext4) with the host binary bind-staged, booted off a root block
  device.** Reuses the compute-plane `BootSource`+`drives` shape (`fc config.rs`), so it inherits the
  rootfs-staging machinery and a larger guest TCB (a userland the privsep instance does not need). Its
  only advantage is reuse of the existing backend boot path — which is also its liability (the wrong
  seam).
- **Option C — firecracker's initrd + kernel-cmdline approach with a stock minimal rootfs.** A middle
  ground; still needs the own-binary-as-init decision and still carries more than Option A.

**The own-binary-as-init relocation caveat [HARD, FLAG].** The bench proved empirically
(`guest/build-initrd.sh:24-28`) that a static **PIE** musl binary **#GP-faults at startup as PID 1**
in a minimal-kernel guest (no dynamic linker to finish the self-relocation); it must be built
`-C relocation-model=static` (**non-PIE**). boatramp's release target is static-musl (`crt-static`)
but is **not guaranteed non-PIE** — so own-binary-as-init may require a **dedicated non-PIE build
artifact** of the same binary, or a relocation-model change to the release build. This is a real
hosting-model constraint, not a detail: it affects the build/release pipeline and must be decided with
the owner. (Also: as PID 1 the init must never exit or the guest kernel panics — `vsock_guest_main.rs:
6-9` — so the instance's `FailNodeClosed`-on-exit semantics change shape inside a VM; see §5/§8.)

**Kernel provenance + verify-before-boot [FLAG — Security].** A VM needs a guest **kernel**, which is
ring-0 code. Both backends already have a `KernelVerifier` gate (`firecracker/kernel_verify.rs`,
`vz/lib.rs:59-75`) that under the strict (multi-tenant) posture requires a content-hash + allow-list +
signature before any guest boots. **The privsep VM substrate MUST route its guest kernel through the
SAME verify-before-boot gate** — a privsep instance is higher-trust than a tenant workload, so its
kernel bar must be AT LEAST as strict. Where the guest kernel comes from (shipped with the release?
operator-supplied? content-addressed in the blob store?) is an owner + Security decision.

**Which backend can support which:** firecracker can do Option A today in prototype (the bench does
exactly that, out-of-process). vz boots only from a kernel + **ext4 rootfs** via `VZLinuxBootLoader`
(`vz/vm.rs:28-34`) and has **no demonstrated initramfs-only path** here, so vz would lean toward
Option B/C — another reason the first cut is firecracker-only (§6).

---

## 3. Secret-blindness across the VM boundary **[FLAG — Security]**

Today the root is **secret-blind**: it parses no bytes, opens no pool, unseals no key
(`privsep.rs:1990-1991`); a `secrets.sealer` instance unseals KEK-sealed key material over a
feature-link under a fail-closed per-link allowlist, and a `token.signer` instance unlocks its key by
asking the sealer over the link (`privsep.rs:2430-2476`, the `PRIVSEP_UNSEAL_ALLOW_ENV` allowlist). The
split is: **the root holds no secret/authority; sealer↔signer is a link conversation.**

**Across a VM boundary this split is PRESERVABLE but introduces a new hazard the owner/Security must
rule on:**

- **The feature-link conversation itself survives** — it is `send_frame`/`recv_frame` byte frames
  (§1b), which relay over vsock unchanged. A sealer-in-VM and a signer-in-VM (or host-side siblings)
  still unseal over their link; the allowlist is still names-only, non-secret
  (`privsep.rs:2038-2041`). So the sealer↔signer split is **not** broken by the transport.
- **The hazard: the host relay sees plaintext link bytes.** A `local` link today is a kernel
  socketpair the root creates but does **not read** — the bytes never transit the root's address
  space. A **vsock relay, by contrast, copies the bytes through the (secret-blind) root process** (§1b
  — the relay splices host-sibling↔vsock). If an unseal response (plaintext key material) crosses a
  relayed link, **the KEK-unsealed key material would transit the root's memory** — breaking the "root
  holds no secret" promise. **This is the central secret-blindness FLAG.** Mitigations to put to
  Security: (i) **co-locate sealer + signer in the SAME VM** so their unseal link is a guest-internal
  socketpair that never hits a host relay (recommended — the relay then only carries client/control
  traffic, never key material); (ii) terminate the relay as an opaque encrypted tunnel the root cannot
  interpret (adds a key-management problem of its own); (iii) forbid a key-material-bearing link from
  being a relayed cross-boundary link at all (a composition-closure lint, fail-closed — the analog of
  the Container per-tenant refusal `DESIGN-privsep-phase3-container.md` §8.2 #6).
- **Where the KEK lives [FLAG].** The host `LocalKek`/envelope today lives on the host. A signer-in-VM
  that must unseal needs either the sealer in-guest with it (mitigation i), or the KEK reachable over a
  link — which, if relayed, re-raises the hazard. **The owner + Security must decide whether a
  key-holding instance (crown jewel / `listen.public-tls`) may run in a VM at all in the first cut, or
  whether VM is initially restricted to key-FREE instances** (e.g. a pure frontend or a `backend.*`
  whose credentials arrive by the managed-DB dynamic-cred path, not a KEK unseal). Restricting VM to
  key-free instances in the first cut sidesteps §3 entirely and is a clean, conservative default to
  bring as INPUT.

---

## 4. Networking / egress **[FLAG — owner app-design, mirrors the container's netns open item]**

A microVM guest has NO host network by default. Two needs, each an owner decision (the exact analog of
the Container net-namespace/egress open item, `DESIGN-privsep-phase3-container.md` §8.2 #3):

- **A `backend.*` instance needs egress** to its real Postgres/KV/blob/messaging store. In a VM with
  no net device it CANNOT reach them. Options: (i) give the guest a tap/bridge + egress (the full
  compute-plane net machinery — heavy, and it widens the guest's reachable surface), or (ii)
  **proxy the backend's store access over vsock through a host-side relay** (keeps the guest
  netless — strongest containment — but needs a per-backend relay, more new TCB), or (iii) **do not
  put `backend.*` instances in a VM in the first cut** (frontends and key-free compute benefit most
  from the VM wall; backends that must reach a DB are the worst fit — recommended conservative
  default). This is the VM analog of "a `backend.*` instance keeps host-net egress" under Container,
  but harder because a VM has no shared kernel to keep.
- **A `listen.*` frontend needs inbound** — covered by §1c (Model A host-relays inbound over vsock;
  Model B gives the guest a routable IP). Model A keeps the guest netless and is recommended.

**The guest's vsock egress must be confined to the host relay** (§1b) so a VM instance cannot dial an
arbitrary CID/port — the vsock equivalent of the `local` transport's "an instance can speak only on
the ends the root wired it." **FLAG for Security: confirm guest↔guest vsock is NOT reachable.**

---

## 5. Landlock / seccomp inside the guest **[mostly carries; shape FLAGGED]**

The per-instance `Enforced` seccomp/Landlock profile is the Phase-1 load-bearing wall and MUST still
install **inside the guest** (`run_instance` refuses to serve unless it reaches `Enforced`,
`privsep.rs:650-652`). Inside a VM:

- **The host↔guest hypervisor boundary becomes the PRIMARY wall** (its own kernel — the whole point of
  the VM substrate; the threat model now excludes a guest-kernel RCE, which Container could not). The
  in-guest per-capability seccomp/Landlock profile becomes **defense-in-depth** on top of the
  hypervisor wall — still installed, still fail-closed, but no longer the sole containment. This is a
  strengthening, not a regression.
- **Shape FLAG: the guest kernel must support Landlock at the required ABI** (the
  `landlock-abi-reporting` trap — a kernel newer OR older than the profile's max ABI changes
  enforcement; `MEMORY.md`/`landlock-abi-reporting.md`). Because the guest kernel is chosen by the
  hosting model (§2), the VM substrate must run the SAME dynamic `ABI::from(kernel)` check inside the
  guest and fail-closed if the chosen guest kernel cannot reach the required ABI. The guest-kernel
  choice (§2) and this ABI floor are coupled.
- **FailNodeClosed shape FLAG.** Inside a VM the instance is PID 1 (own-binary-as-init, §2) and must
  not exit or the guest kernel panics (`vsock_guest_main.rs:6-9`). So "the instance process exits →
  the root's `try_wait` trips `FailNodeClosed`" (`privsep.rs:2263-2302`) must be re-expressed as "the
  GUEST stops / the vsock relay EOFs → the root tears the node down." The root supervises the
  firecracker/vz child process (as the bench does, `vsock.rs:181-205`) + the relay liveness, and a
  guest death or relay EOF must trip `FailNodeClosed` exactly as a child exit does today. Mechanically
  understood, but it is a NEW supervision path that must be designed + live-gated, not assumed.

---

## 6. Firecracker vs vz; is VM Linux-only for now? **[FLAG — recommend Linux/firecracker-only first]**

| decision | firecracker (Linux + `/dev/kvm`) | vz (macOS, Apple silicon) |
|---|---|---|
| guest boot shape (§2) | can boot kernel + **initramfs** `rdinit=/init` today (the bench does it) — supports **Option A** | boots kernel + **ext4 rootfs** via `VZLinuxBootLoader` (`vz/vm.rs:28-34`); no demonstrated initramfs-only path here — leans **Option B/C** |
| vsock transport (§1) | host-side **UDS `CONNECT` bridge** proven in the bench (`vsock.rs:141-170`); `objc2`-free | `VZVirtioSocketDevice` is **not wired** in `vz/vm.rs` (device set is blk/net/console only); objc2-virtualization supports it but with a **different** connect/listen model (host connects to a guest-listening port; a `VZVirtioSocketListener` for the reverse) — a separate port-assignment design |
| net model (§4) | tap/bridge + IPAM (`fc net.rs`) | vmnet NAT (`vz/net.rs`) |
| process model | out-of-process `firecracker` child (bench) or in-process embedded VMM (`embedded_backend`) | re-exec'd `boatramp __vz-run` child per VM (`vz/lib.rs`) |
| kernel verify (§2) | `firecracker/kernel_verify.rs` | `vz/lib.rs:59-75` |

**Recommendation to bring as INPUT: the VM substrate is Linux + firecracker ONLY in the first cut.**
Firecracker already has the proven initramfs + UDS-vsock shape (the bench), the strictest minimal
guest, and the `/dev/kvm` capability-gate pattern the compute plane already uses. vz is a legitimate
follow-on but needs its own vsock wiring + the ext4-vs-initramfs boot decision, and macOS is not the
production serving target. This mirrors the Container substrate's Linux-only posture
(`spawn_wired_instance` refuses a Container spec on non-Linux, `privsep.rs:1300-1307`).

---

## 7. What this cut BUILDS (safe) vs leaves DESIGN-ONLY

**BUILT (this cut — safe, fail-closed, no live wiring):**

1. **This design note** — the primary deliverable.
2. **Sharpened `resolve_spawn_backend` Vm refusal** (`privsep.rs:889`): the message now names the
   concrete blockers — the vsock byte-relay transport is not wired (fd-passing cannot cross the VM
   boundary — the socketpair ends, the listener fd, AND the `SCM_RIGHTS` client splice all need a
   vsock relay), and the hosting-model decision (guest kernel + own-binary-as-init) is pending owner +
   Security ratification — and points at this note. `is_wired(Vm)` stays `false`; OsProcess/Container
   unchanged. The fail-closed posture (no silent downgrade to OsProcess, no partial spawn) is
   preserved exactly. Mirrors how the Container refusal was sharpened before it was wired
   (`DESIGN-privsep-phase3-container.md` §7 item 2).
3. **Unit test** (`resolve_spawn_backend_wires_os_process_and_container_and_refuses_vm`, extended):
   asserts the sharpened Vm refusal names the transport + hosting-model blockers and points to the
   design note, OsProcess/Container stay wired, Vm stays refused.
4. **An `#[ignore]`d fail-closed live gate** `privsep_vm_substrate_refuses_fail_closed_end_to_end`
   (`tests/privsep_live.rs`): forks `boatramp __root` against the known-valid frontend-inversion
   topology whose serving `core` is pinned `substrate: vm`, and asserts the node **refuses fail-closed
   end-to-end** — the root exits non-zero at the pre-spawn substrate-dispatch gate
   (`supervise::run` step 0, `privsep.rs:2019-2021`) BEFORE it binds the public listener or spawns any
   instance, and the port is never served. Marker `PRIVSEP VM SUBSTRATE REFUSED OK`. **This gate
   INVERTS** into a real end-to-end serve gate (marker `PRIVSEP VM SUBSTRATE OK`, asserting a real 200
   from a VM-confined `core` over the vsock relay) once the backend is wired — a header note says so,
   exactly as the Container gate inverted from refuse to serve.
5. **CI wiring** (`.github/workflows/ci.yml` `live-gate-privsep`): the pass-count grep is bumped
   (5 → 6) and the new `PRIVSEP VM SUBSTRATE REFUSED OK` marker is grepped, so a silent skip /
   compile-out fails the merge. (The REFUSE gate needs neither `/dev/kvm` nor sudo — the refusal fires
   before any VM boot — so it runs on the existing ubuntu-latest musl runner; the inverted SERVE gate
   will need lighthouse Linux + `/dev/kvm`.)

**DESIGN-ONLY (flagged above, NOT built — needs owner + Security ratification):**

- §1 the vsock byte-relay transport: the root-wired CID/port topology + host relay (§1b), the
  listener-inward relay (§1c), the client-splice-as-byte-relay (§1d). The load-bearing transport
  blocker.
- §2 the hosting model (Option A/B/C), own-binary-as-init + the non-PIE relocation build artifact, and
  guest-kernel provenance + verify-before-boot. The load-bearing hosting blocker.
- §3 secret-blindness: whether a key-holding instance may run in a VM at all in the first cut, and if
  so how the unseal link avoids transiting the host relay (co-locate sealer+signer in-guest / encrypted
  tunnel / fail-closed lint).
- §4 networking/egress (host-relay-only vs guest-net; whether `backend.*` may run in a VM first).
- §5 the in-guest Landlock ABI floor coupled to the guest-kernel choice; the PID-1 /
  guest-death `FailNodeClosed` re-expression.
- §6 firecracker-only (Linux-only) first cut vs vz follow-on.

**Recommended path forward (INPUT for the owner), in the spirit of Container's Option C:** a
**conservative first cut** — firecracker/Linux only (§6); Option A minimal initramfs with the
non-PIE own-binary as `/init` (§2); vsock transport with a root-side host relay and a root-wired
CID/port topology (§1); **key-FREE instances only** in the first cut (a frontend via Model A, or a
compute instance), deferring key-holding instances until §3's sealer-co-location is designed; no guest
net (host-relay inbound only, §4); the in-guest per-capability profile as defense-in-depth behind the
hypervisor wall (§5). This preserves every Phase-1 guarantee with the hypervisor wall ADDED, at the
measured ~27→736 µs + ~121 ms-boot cost, and confines the new TCB to the relay + the initramfs + the
guest init. But it is a recommendation, not a settled decision — §8 is the ratification list.

---

## 8. The explicit decision list (what must be ratified before the VM backend can be wired)

### OWNER decisions (application design — owner is the sole authority; bring as INPUT, relay the decision)

- **O1 — Is VM an operator-selectable substrate at all, given the cost?** The VM wall costs **~27→736
  µs per request + ~121 ms boot** vs OsProcess fd-pass **~7 µs flat**
  (`docs/privsep-substrate-benchmark.md` §3). It is justified only where the threat model demands a
  hardware wall and the latency/boot budget can absorb it. The owner decides whether to ship VM as a
  substrate option now, or keep it refused as a documented follow-on.
- **O2 — Hosting model (§2):** Option A (minimal initramfs, own-binary-as-init) vs B (full ext4
  rootfs) vs C (initrd + stock rootfs). Recommend A.
- **O3 — Guest-kernel provenance (§2):** shipped-with-release / operator-supplied / content-addressed
  — and the non-PIE own-binary build artifact (does the release build gain a non-PIE static target?).
- **O4 — Networking model (§4):** host-relay-only (guest netless) vs guest-net; and whether `backend.*`
  instances are eligible for VM in the first cut. Recommend host-relay-only, no `backend.*` first.
- **O5 — Scope (§6):** firecracker/Linux-only first cut, vz a follow-on? Recommend yes.

### SECURITY decisions (TCB-critical; the Security review must ratify)

- **S1 — vsock transport authority invariants (§1b/§4):** the root-wired CID/port topology is the new
  authority proof (replacing the root-wired fd topology); confirm a VM instance can reach ONLY its
  wired peer via the root relay, that guest↔guest vsock is NOT reachable, and that a relay death trips
  `FailNodeClosed`. The relay is new TCB in the secret-blind root.
- **S2 — Secret-blindness across the boundary (§3):** does the vsock relay force KEK-unsealed key
  material through the host root's memory? Ratify the mitigation — co-locate sealer+signer in one
  guest (so key material never hits a host relay), and/or restrict VM to key-FREE instances in the
  first cut, and/or a fail-closed composition lint forbidding a key-material link from being a relayed
  cross-boundary link. Confirm the "root holds no secret/authority" promise is preserved.
- **S3 — Guest-kernel verify-before-boot (§2):** the privsep guest kernel must clear a bar at least as
  strict as the compute plane's `KernelVerifier` under the strict posture (it is ring-0 code under a
  higher-trust instance).
- **S4 — In-guest Landlock ABI floor + PID-1 FailNodeClosed (§5):** the guest kernel must support the
  required Landlock ABI (the `ABI::from(kernel)` dynamic check inside the guest, fail-closed), and the
  guest-death / relay-EOF teardown must trip `FailNodeClosed` as reliably as a child exit does today —
  both live-gated on lighthouse (Linux + `/dev/kvm`) before any merge is called clean.

**Note on authority to decide:** O1–O5 are owner application-design calls (relay his decision; do not
settle with a peer). S1–S4 are Security-review calls that LOOP until clean or owner-accepted. The
basic transport/secret-blindness INFRA (S1/S2) is mine to design to full shape — but it cannot be
*wired* until O2/O3 (what runs inside) and S2 (where key material lives) are ratified, because the
transport and the hosting model interact (e.g. sealer-co-location under S2 changes the relay's
role).
