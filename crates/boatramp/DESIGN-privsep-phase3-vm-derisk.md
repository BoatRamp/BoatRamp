# DESIGN — privsep Phase-3 VM substrate: **de-risking pass** (O3b + S2)

*Crate-local de-risk note. Branch `privsep-vm-derisk` (built on the design branch `privsep-phase3-vm`
`1236df3b`, which carries `DESIGN-privsep-phase3-vm.md`). Status: **DE-RISK ONLY — no production
wiring, no fold into `feat/privsep`, no merge, no cut.** The privsep program has a standing rule of NO
cut until the whole program is done; this pass validates the two technical questions flagged for
validation BEFORE the scoped VM first cut is wired, so the wiring can then be sequenced under the
normal verify-loop.*

The owner greenlit (2026-11-10) a scoped VM first cut: **firecracker/Linux only, static parser
frontends only, key-free-or-co-located instances, no backends-in-VM, host-relay networking,
invariant-preserving** (the root wires VM topology but carries no key bytes). Two items in
`DESIGN-privsep-phase3-vm.md` were flagged as needing validation before wiring:

- **O3b** — the non-PIE **init-shim hypothesis** for own-binary-as-init (`DESIGN-privsep-phase3-vm.md`
  §2 "the own-binary-as-init relocation caveat"; O3). **Validated live on lighthouse.** §1 below.
- **S2** — the **secret-blindness wiring design** across the VM boundary
  (`DESIGN-privsep-phase3-vm.md` §3, S2). **Design note drafted** — concrete endpoints + the
  fail-closed composition lint. §2 below.

§3 is the de-risked-vs-still-open summary for sequencing.

---

## 1. O3b — the non-PIE init-shim hypothesis (VALIDATED LIVE)

### 1.1 The question and the hypothesis

Own-binary-as-init (Option A, `DESIGN-privsep-phase3-vm.md` §2) runs the host's own static-musl
`boatramp` binary as the microVM guest's PID 1 (`rdinit=/init`). The flagged caveat: boatramp's
**shipped** release binary is a genuine **static-PIE** (for ASLR), and the bench's
`guest/build-initrd.sh` recorded empirically that a static-**PIE** musl binary `#GP`-faults at startup
as a minimal-kernel guest's direct PID 1 (no dynamic linker to finish self-relocation), which is why
the bench forced its guest init **non-PIE** (`-C relocation-model=static`).

**Confirmed premise (artifact level).** The WS4 build-hardening pass (`docs/privsep-build-hardening.md`
+ the repo-root `.cargo/config.toml` `[target.x86_64-unknown-linux-musl]` section) makes the shipped
musl binary genuine static-PIE: `-C target-feature=-crt-static` yields `readelf -h` → `Type: DYN`,
`file` → "static-pie linked", `FLAGS_1: NOW PIE`, a `GNU_RELRO` segment, **zero `DT_NEEDED`, no
`PT_INTERP`** (fully self-contained, self-relocating at startup via musl `crt1`, with a 5.7 MB /
240,782-entry `R_X86_64_RELATIVE` table). So the release binary IS the static-PIE shape O3b is about.

**The hypothesis to validate:** a ~kilobyte static **NON-PIE** init shim in the initramfs is PID 1
(non-PIE, boots clean), sets up `/proc` etc., and `execve`s the static-PIE `boatramp` in instance mode
— so `boatramp` is reached via a normal `execve` (where musl static-PIE self-relocation works),
**keeping boatramp's ASLR** and avoiding a dual-artifact (PIE + non-PIE) release pipeline. Does the
shim + static-PIE-payload path boot clean in firecracker and preserve ASLR?

### 1.2 Method (faithful proxy, same toolchain + same ELF shape)

Run live on **lighthouse** (`jwk@lighthouse.bytesoba.net`, NixOS, kernel 6.12, `/dev/kvm`), in the
single scratch folder `~/boatramp-agent-tests/privsep-vm-derisk`. The harness and sources are committed
under `docs/privsep-vm-derisk-repro/` on this branch.

- **VMM:** firecracker **1.13.1** (nixpkgs), `--no-api`, `rdinit=/init`, `drives: []`, vsock-free,
  guest serial → `ttyS0` captured. This is the exact minimal **kernel + initramfs** shape
  `DESIGN-privsep-phase3-vm.md` §2 recommends for a privsep guest (Option A), not the compute-plane
  ext4+IP `ComputeSpec` path.
- **Guest kernel:** firecracker CI `vmlinux-5.10.225` (uncompressed ELF; `randomize_va_space = 2` in
  guest, i.e. full ASLR on).
- **Payload (faithful static-PIE proxy):** a Rust binary built with the **repo's exact release
  toolchain and recipe** — `rustc 1.99.1` (the pin in `rust-toolchain.toml`) + `cargo-zigbuild` +
  zig's musl, `RUSTFLAGS="-C target-feature=-crt-static -C relocation-model=pic"`. Result verified
  `readelf -h` → `Type: DYN`, `file` → "static-pie linked", `FLAGS_1: NOW PIE`, **zero `DT_NEEDED`, no
  `PT_INTERP`** — i.e. byte-for-byte the same ELF class, self-relocation mechanism (musl `crt1`
  `_dlstart`/`__dls2` self-relocation) and ASLR shape as the shipped binary. A **large-reloc** variant
  (`RELASZ` 2.42 MB / **100,694** `R_X86_64_RELATIVE` entries) brings the self-relocation table into
  the same order of magnitude as boatramp's real 5.7 MB / 240,782.
- **Shim:** a Rust static **non-PIE** binary (`readelf` → `Type: EXEC`), mounts `/proc`, prints a
  marker, then `execve("/payload", …)`.
- **ASLR signal:** `getauxval(AT_ENTRY)` (the runtime entry address — fixed for non-PIE, randomized
  for PIE+ASLR), corroborated by the executable's load base in `/proc/self/maps`. Each configuration
  booted **twice**; a differing `AT_ENTRY` across boots proves ASLR is live.

*Why the proxy is scientifically sufficient:* the two O3b questions — (a) does musl static-PIE
self-relocation complete when the binary is PID 1 vs reached via `execve`, and (b) does the kernel
apply ASLR to the loaded ET_DYN — are properties of **the musl `crt1` CRT and the Linux ELF loader**,
not of boatramp's application code. The self-relocation runs in `_dlstart`/`__dls2` **before `main`
and before any allocator/jemalloc init**, so if it faulted it would fault regardless of program
content; the proxy exercises that identical path with an identical ELF class, and the large-reloc
variant covers the table-size dimension. The one remaining fidelity gap (booting the literal 185 MB
`boatramp` binary) is noted in §1.5 as the first step of the inverted serve gate.

### 1.3 Experiments and evidence (all boots: zero `#GP`/panic/segfault in any serial log)

| Exp | guest PID 1 | payload | reached `main`? | `AT_ENTRY` boot-1 vs boot-2 | verdict |
|---|---|---|---|---|---|
| **C** control | non-PIE payload (direct) | — | yes | `0x1013030` == `0x1013030` | boots clean; **fixed** entry (no ASLR, expected for non-PIE) — reproduces the bench's "non-PIE boots as PID 1" |
| **A** baseline | **static-PIE** payload (direct) | — | **yes** | `0x7f8318802090` ≠ `0x7f56d52fc090` | **boots clean, ASLR ACTIVE** — the hypothesized `#GP` did **NOT** reproduce on this kernel (see §1.4) |
| **B** the fix | **non-PIE shim** | static-PIE | yes (shim + payload) | `0x7f756a0dd090` ≠ `0x7f068ceb1090` | **shim path works, ASLR PRESERVED** — the O3b hypothesis is validated |
| **D** big-reloc | static-PIE (100,694 relocs) direct | — | yes, `reloc_table_ok=true` | `0x7f6b812cd000` ≠ `0x7fb43b9e2000` | 2.42 MB self-reloc table applies cleanly as PID 1; ASLR active |
| **E** big-reloc+shim | non-PIE shim | static-PIE (100,694 relocs) | yes, `reloc_table_ok=true` | `0x7f46a5d97000` ≠ `0x7fbc91a11000` | shim + large static-PIE: clean boot, relocations correct, ASLR preserved |

Representative serial (Exp B, boot 1): `Run /init as init process` → `SHIM-ALIVE nonpie_init pid=1
mounted_proc exec=/payload` → `PAYLOAD-ALIVE reached_main pid=1` → `PAYLOAD-AT_ENTRY 0x7f756a0dd090`
→ `PAYLOAD-RANDOMIZE_VA 2` → `PAYLOAD-DONE power_off` → `Firecracker exiting successfully.
exit_code=0`.

### 1.4 Verdict — O3b PASS, with one important nuance

**PASS.** The non-PIE init-shim path **boots clean in firecracker and preserves ASLR**: the non-PIE
shim is a clean PID 1, the `execve`'d static-PIE payload completes musl self-relocation (small AND
large relocation tables) and runs with a **randomized load base across boots** (`AT_ENTRY` differs;
guest `randomize_va_space=2`). This validates the mechanism that lets own-binary-as-init keep
boatramp's ASLR without a dual (PIE + non-PIE) release artifact: ship ONE static-PIE `boatramp` plus a
tiny non-PIE shim in the initramfs.

**Nuance (honest finding):** on this exact combination — firecracker 1.13.1 + CI `vmlinux-5.10.225` +
`rustc 1.99.1` musl static-PIE (`-C target-feature=-crt-static`) — the baseline `#GP` **did not
reproduce**: the static-PIE binary booted cleanly as **direct** PID 1 too (Exp A/D), with ASLR. Two
things follow:
1. The bench's `build-initrd.sh` `#GP` note predates WS4 and reflects a different (kernel, musl,
   build-flag) combination — note it also describes the musl *default* as "self-relocating static-PIE",
   whereas WS4 proved by `readelf` that the musl default is actually `Type: EXEC` **non-PIE** and that
   static-PIE only appears with the explicit `-C target-feature=-crt-static`. The `#GP` was real for
   *its* inputs, but it is **not** a property of a modern mainline guest kernel.
2. Whether a shim is *strictly required* therefore depends on the **guest kernel** (O3/S3: guest-kernel
   provenance + verify-before-boot). On a modern mainline guest kernel a static-PIE can be a direct
   PID 1. **Recommendation:** adopt the shim regardless, as kernel-agnostic insurance — it is ~1 KB,
   costs one `execve`, removes the guest-kernel-version dependency of own-binary-as-init entirely, and
   is now proven to preserve ASLR. It also gives a natural home for the minimal PID-1 setup
   (`/proc`, `/sys`, `/dev`, console) and for the PID-1-never-exits discipline
   (`DESIGN-privsep-phase3-vm.md` §5).

### 1.5 Fidelity gap (the one step left, for the serve gate, not the de-risk)

The proxy is faithful to the mechanism (same toolchain, same ELF class, self-relocation up to 100 k
relocs), and the real binary's static-PIE shape is already `readelf`-proven in
`docs/privsep-build-hardening.md`. The only step not done here is booting the **literal** `boatramp`
static-PIE binary via the shim in-guest. That is low-risk (the self-relocation + ASLR are
toolchain/kernel properties the proxy exercises identically) and is exactly the first assertion of the
**inverted serve gate** `DESIGN-privsep-phase3-vm.md` §7 item 4 already scopes to lighthouse + `/dev/kvm`:
build `nix build .#boatramp-static`, pack it (+ the shim) into the initramfs, boot `boatramp __instance`
to a 200 over the vsock relay. It was intentionally NOT run here to avoid building inside the owner's
lighthouse clones (`~/boatramp/*`) — agent work stays in the one scratch folder.

---

## 2. S2 — secret-blindness wiring across the VM boundary (DESIGN NOTE)

### 2.1 The invariant and the hazard (restated precisely)

**Invariant to preserve:** the root supervisor is **secret-blind** — it parses no bytes, opens no
pool, unseals no KEK, and **no plaintext key material ever transits the root's address space**
(`privsep.rs:1990-1991`). The key conversation lives entirely between crown-jewel instances: a
`secrets.sealer` holds the KEK and, on an **unseal**, returns **plaintext** key material over a
feature-link; a `token.signer` with a *sealed* key source asks the sealer to unseal its signing key
over that link (`privsep.rs:2430-2476`; the per-link `PRIVSEP_UNSEAL_ALLOW_ENV` allowlist derived by
`compute_unseal_allowlists`, `privsep.rs:925-…`).

**Why a `local` link is safe today:** a `local` link is a kernel `socketpair(2)` the root *creates*
(`LinkEndpoint::socketpair`) but **never reads** — the bytes pass between the two instances on one
shared kernel and never enter root memory.

**The hazard under a VM endpoint (`DESIGN-privsep-phase3-vm.md` §3):** an fd-passed socketpair cannot
cross a hypervisor boundary (the guest has its own kernel). So any link with a `substrate: Vm`
endpoint must become a **vsock byte-relay**, and the natural relay — the one the root runs because it
owns the topology — **copies the link's bytes through the (secret-blind) root process**. If an
**unseal response (plaintext key material)** crosses such a relayed link, the KEK-unsealed key material
would transit the root's memory → the "root holds no secret" promise is broken.

Define a link as **key-material-bearing** iff its traffic can carry KEK-unsealed plaintext key
material. Structurally, in the shipped vocabulary that is exactly: **a link with one endpoint holding
`secrets.sealer` that is used to serve an unseal** — i.e. a `secrets.sealer`↔`token.signer` unlock link
(the set `compute_unseal_allowlists` already enumerates), and, more generally, any link explicitly
marked `purpose: AuthorityServe` whose crown-jewel endpoint is `secrets.sealer`. (A `token.signer`
`mint_token` or an `image.signer` response carries a *derived* token/signature, not the raw key; those
are sensitive but are not the KEK-unseal hazard §3 names. The lint below targets the KEK-unseal case
and is written to generalize to any future key-material serve.)

### 2.2 The wiring design — which process holds which vsock endpoint

Three principles, in priority order. The approved first cut ("key-free-**or**-co-located instances")
is satisfied entirely by **P1 + P3**; **P2** is the design for a later cut that wants a key holder
reachable across a boundary.

**P1 — Co-locate the key conversation in ONE guest (primary).** Put `secrets.sealer` and its
`token.signer` on the **same instance** (hence the same guest). Their unlock link is then a
**guest-internal `socketpair(2)`** — the root still spawns the instance, but both endpoints share one
guest kernel, so the unseal bytes never leave the guest and never reach a host relay. The root's
host-side vsock relay for that VM carries only **non-key** traffic (the client serving splice +
control frames). This is the exact analog of the already-shipped
`check_sealed_signer_closure` fast path, which treats a **co-resident** sealer+signer as needing **no
link** ("resolve in-process"), and of the composition doc's A∪B "core" instance. **Endpoint map:**
sealer and signer both inside guest *G*; unlock = intra-*G* socketpair (root-created at spawn, never
relayed); root ↔ *G* vsock relay = client/control only.

**P2 — The key HOLDER owns the host-side vsock endpoint (fallback, for a cross-boundary key link).**
If a key-material link must cross a boundary (e.g. a host-side `secrets.sealer` unsealing for a
signer-in-VM), the **root wires but does not relay** it. Concretely: the root sets up the guest's vsock
device + the firecracker host-side UDS bridge and **hands the UDS/vsock endpoint fd to the
`secrets.sealer` instance** (over the sealer's own root-wired link at spawn, the same way every other
inherited fd is passed). The **sealer** then dials `CONNECT <signer_port>` and runs the unseal
conversation **directly** over vsock to the signer-in-VM. The plaintext originates in the sealer (which
legitimately holds it) and goes straight to the guest; **the root never reads it.** The split becomes:
root = *control plane* of the link (assign CID/port, set up the device, confine guest egress to the
relay); sealer = *data plane* endpoint (holds the fd, speaks the bytes). This is the "make the
key-holder itself the host-side vsock endpoint" option — it keeps secret-blindness even when the key
conversation crosses the wall. (P2 is strictly more TCB than P1 and is **not** needed for the first
cut; documented so the first cut's lint does not foreclose it.)

**P3 — Key-free VM instances otherwise (the conservative default).** Any `substrate: Vm` instance that
is **not** self-sufficient for its key unlock under P1 must be **key-free** — a pure static parser
frontend (`listen.*` only, per the approved scope) or a compute instance that holds no group-A
authority and needs no KEK unseal. This sidesteps §3 entirely and is the recommended first cut.

### 2.3 The fail-closed composition lint (the exact rule)

Add a pre-spawn, fail-closed check run **in the root** alongside `check_composition_closure` and
`check_sealed_signer_closure` (same call site, same "surface either refusal identically" treatment).
Proposed name: **`check_vm_secret_blindness_closure(cfg, sealed_signer)`**. It reuses existing
predicates only — `HostAuthority::is_crown_jewel()` / `group() == KeySealer`,
`InstanceSubstrate::Vm`, and the sealer↔signer edge detection already in `compute_unseal_allowlists` /
`check_sealed_signer_closure`.

Define, for the resolved `PrivsepConfig`:
- `is_vm(inst)            ≔ inst.substrate == InstanceSubstrate::Vm`
- a link *L = (a, b)* is **key-material-bearing** iff
  `sealed_signer && ( (holds(a, SecretsSealer) && holds(b, TokenSigner)) || (holds(b, SecretsSealer) && holds(a, TokenSigner)) )`
  — i.e. precisely the links `compute_unseal_allowlists` would wire an unseal allowlist onto; PLUS any
  link with `purpose == AuthorityServe` whose single crown-jewel endpoint holds `SecretsSealer`.
- a link *L = (a, b)* is **root-relayed cross-boundary** iff `a ≠ b` (different instances) **and**
  `is_vm(a) || is_vm(b)` — two capabilities on the *same* instance share one guest (intra-guest
  socketpair, never relayed); a link between two *different* instances where either is a VM crosses the
  hypervisor boundary and is relayed by the root.

**RULE (REFUSE, fail-closed):**

> A **key-material-bearing** link that is **root-relayed cross-boundary** is a hard composition
> refusal — the KEK-unsealed key material would transit the secret-blind root's vsock relay, breaking
> the "root holds no secret/authority" invariant.
>
> *Remedy named in the error:* co-locate `secrets.sealer` and `token.signer` on ONE instance (P1 — the
> unlock resolves in-process / over an intra-guest socketpair), or keep both endpoints on a non-VM
> substrate, or (a later-cut option, not wired in the first cut) wire the sealer as the host-side vsock
> endpoint under P2.

New violation variant (mirroring the existing `SealedSignerUnlinkedToSealer` shape in
`boatramp-types::privsep::CompositionViolation`):

```rust
/// A key-material-bearing link (a `secrets.sealer` ↔ `token.signer` unseal unlock, or an
/// `AuthorityServe` link whose crown jewel is `secrets.sealer`) connects two DIFFERENT instances
/// where at least one is `substrate: Vm`. Over a VM boundary that link is a vsock byte-relay through
/// the SECRET-BLIND root, so the KEK-unsealed plaintext key material would transit the root's memory.
/// Fail-closed (`check_vm_secret_blindness_closure`): co-locate the sealer+signer on one instance
/// (intra-guest socketpair, never relayed), keep both off the VM substrate, or (later cut) wire the
/// sealer as the host-side vsock endpoint so the root wires-but-does-not-relay the key link.
VmKeyMaterialLinkRelayedThroughRoot {
    link: String,
    sealer_instance: String,
    signer_instance: String,
    vm_endpoints: Vec<String>, // which endpoint(s) are substrate: Vm
},
```

**Belt-and-suspenders second tier (first-cut scope enforcement).** To enforce the approved
"key-free-or-co-located" scope directly (so a key holder can never slip into a VM without its sealer):
a `substrate: Vm` instance that holds any **group-A crown jewel** whose unlock is a *sealed* source
must be **self-sufficient** — it must co-reside its `secrets.sealer` (P1). Otherwise REFUSE with a
companion variant `VmKeyHolderNotSelfSufficient { instance }`. In the first cut this reduces to the
simple, ratifiable statement **"a VM instance either holds no group-A key authority, or co-resides the
sealer that unlocks it."**

**Why structural, not textual.** This is an AST/topology-level predicate over the resolved
`PrivsepConfig` (who holds what, which substrate, which endpoints a link connects) — never a parse of
link traffic or a text marker. It is the direct analog of the crown-jewel exclusion
(`is_crown_jewel_exclusion_surface`) and the `check_sealed_signer_closure` the root already runs
fail-closed before any spawn. It composes with, and does not replace, S1 (the root-wired CID/port
authority topology: a VM instance may reach ONLY its wired peer via the relay; guest↔guest vsock not
reachable; a relay death trips `FailNodeClosed`).

---

## 3. De-risked vs still-open (for sequencing under the verify-loop)

**De-risked by this pass (safe to build on):**

- **O3b — own-binary-as-init keeps ASLR via a non-PIE shim.** Proven live on firecracker + `/dev/kvm`:
  the non-PIE shim boots clean as PID 1 and `execve`s a genuine static-PIE payload that self-relocates
  (up to a 2.4 MB reloc table) and runs with ASLR preserved. The release pipeline needs **one**
  static-PIE `boatramp` + a ~1 KB non-PIE shim in the initramfs — **no dual PIE/non-PIE build
  artifact.** Bonus finding: on a modern mainline guest kernel the static-PIE even boots as *direct*
  PID 1, so the shim is kernel-agnostic insurance rather than a hard requirement — adopt it anyway.
- **S2 — secret-blindness is preservable across the boundary, with a concrete fail-closed lint.** The
  key conversation stays off the root relay via P1 (co-locate sealer+signer in one guest → intra-guest
  socketpair) with P3 (key-free VM instances otherwise); the exact refusal predicate +
  `CompositionViolation` variant + call site are specified in §2.3. The approved "key-free-or-co-located"
  scope maps 1:1 onto P1 + P3 and is enforced by the second-tier lint.

**Still open (owner/Security ratification + normal verify-loop — unchanged from
`DESIGN-privsep-phase3-vm.md` §8):**

- **O2/O3 (owner):** confirm Option A (minimal initramfs, own-binary-as-init **via the validated
  shim**) and guest-kernel provenance + verify-before-boot. O3b removes the "do we need a dual build
  artifact?" sub-question — the answer is **no** (one static-PIE binary + shim).
- **S1 (Security):** the vsock transport authority invariants — root-wired CID/port topology as the new
  authority proof, guest↔guest vsock unreachable, relay death ⇒ `FailNodeClosed`. Not touched by this
  pass; must be designed + live-gated.
- **S2 (Security):** ratify the §2.3 lint (and P1/P3 for the first cut; P2 only if a cross-boundary key
  holder is ever wanted). The *design* is de-risked; the *review* loops until clean.
- **S3 (Security):** guest-kernel verify-before-boot bar (ring-0 code under a higher-trust instance) —
  and note O3b's finding that shim-necessity is itself kernel-dependent, so the kernel choice and the
  shim decision are coupled.
- **S4 (Security):** in-guest Landlock ABI floor coupled to the guest kernel + the PID-1 /
  guest-death `FailNodeClosed` re-expression — both live-gated on lighthouse before any merge is clean.
- **Transport build (mine, §1 of the design):** the vsock byte-relay re-plumb — root-wired CID/port
  topology + host relay, listener-inward relay, client-splice-as-byte-relay. Unchanged; this pass
  de-risked the **hosting model** (O3b) and the **secret-blindness wiring** (S2), not the transport
  itself.

**Recommended sequencing** (each step gated + live-verified before the next, no cut until the whole
privsep program is done):
1. Ratify O2/O3 (hosting = Option A + shim; guest-kernel provenance) and the §2.3 S2 lint with Security.
2. Land the §2.3 fail-closed lint (+ unit tests) in the types layer — pure, host-testable, no wiring;
   it refuses an unsafe VM key topology before any transport exists.
3. Build the vsock byte-relay transport + the shim/initramfs assembly; invert the `#[ignore]`d refuse
   gate (`privsep_vm_substrate_refuses_fail_closed_end_to_end`) into the real serve gate, whose FIRST
   assertion is the §1.5 step: boot the literal `boatramp` static-PIE via the shim to a 200 over vsock,
   on lighthouse + `/dev/kvm`.
4. Live-gate S1/S4 (CID/port confinement, guest-death ⇒ `FailNodeClosed`, in-guest Landlock ABI).

---

*Reproduction harness (sources + driver scripts + the exact firecracker boot config) is committed under
`docs/privsep-vm-derisk-repro/` on this branch. Run on lighthouse under
`nix shell nixpkgs#rustup nixpkgs#cargo-zigbuild nixpkgs#zig nixpkgs#gcc nixpkgs#binutils nixpkgs#file
nixpkgs#firecracker nixpkgs#cpio nixpkgs#gzip nixpkgs#curl`.*
