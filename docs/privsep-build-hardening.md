# Release-binary build hardening (privsep Phase 0, WS4)

This records the exploit-mitigation posture of the binaries boatramp actually
ships, per release target, and how each line was verified. It is deliberately
narrow: compiler/linker-level hardening of the binary, not application-level
sandboxing (that's the rest of privsep).

## Toolchain: stable, not nightly

`rust-toolchain.toml` pins `channel = "stable"` (currently rustc 1.99.1), used
by both the Nix dev shell/derivations and the GitHub Actions
`dtolnay/rust-toolchain@stable` step. **This rules out LLVM/Clang-style CFI**
(`-Z sanitizer=cfi`, which additionally needs fat LTO) **and rustc's own stack-
protector codegen option** (`-Z stack-protector=...`): both are `-Z`
(nightly-only) flags, confirmed via `rustc -Z help` on this exact toolchain —
see "Deferred" below. Nothing in this change moves the pinned toolchain or
destabilizes the build to chase either.

## Where the flags actually live

`.cargo/config.toml` (new, repo root), with one `[target.<triple>]` section
per release target. This file is read by every real build path that produces
a shipped binary:

- **macOS + Windows** (`.github/workflows/release.yml`, `build` job, the
  `kind != linux` branch): a plain `cargo build --release --target <triple>`
  invoked directly on the native GitHub runner — no Nix. Standard cargo config
  discovery applies.
- **Linux musl** (`nix build .#boatramp-static`, `nix/package-musl.nix`): a
  crane derivation that runs `cargo zigbuild --release --target <triple>
  --features jemalloc -p boatramp` inside the Nix sandbox. `cargo-zigbuild` is
  a thin `cargo` subcommand wrapper and performs the same config discovery a
  bare `cargo build` would, over the **full workspace source tree** (the
  derivation's `src` is `flake.nix`'s `workspaceSrc`, built with
  `lib.cleanSourceWith` + `lib.cleanSourceFilter` — which excludes VCS/editor
  junk but **not** dotdirs like `.cargo/`, so `.cargo/config.toml` reaches the
  sandbox unmodified). Confirmed by direct test: running `cargo zigbuild
  --release --target x86_64-unknown-linux-musl --features jemalloc -p
  boatramp` against this worktree (the same command the derivation runs)
  picks up the new `rustflags` and links — see the musl section below for the
  `readelf` evidence.
- **macOS's `nix/package.nix`** (`rustPlatform.buildRustPackage`) is a
  separate, non-release path (`nix build .#default` / the stock
  `overlays.default` consumed by downstream Nix users) — it is **not** what
  the GitHub release pipeline ships for macOS, which builds directly via cargo
  on the native runner (see above). It reads the same `.cargo/config.toml`
  (same mechanism), but since Darwin has no `[target.*]` section (see below),
  this is moot either way.
- `[profile.release]` in the workspace `Cargo.toml` (`lto = "thin"`,
  `strip = true`) is untouched; it's orthogonal to the linker/ASLR/RELRO
  flags below and didn't need to change.

## Per-target posture

### Linux musl — `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`

Backs `nix build .#boatramp-static`, the OCI images, and the Linux release
archives/`.deb`/`.rpm`.

| Mitigation | Status | How verified |
|---|---|---|
| PIE / ASLR | **Added** — `-C target-feature=-crt-static` (see "the static-PIE finding" below) | `readelf -h` on the real, full `boatramp` binary (built with `cargo zigbuild --release --target x86_64-unknown-linux-musl --features jemalloc -p boatramp`, the exact `nix/package-musl.nix` command) → `Type: DYN (Position-Independent Executable file)`. |
| Full RELRO + BIND_NOW | **Added explicitly** — `-C relro-level=full` | `readelf -d` on that same binary → `FLAGS_1: NOW PIE` (both `DF_1_NOW` and `DF_1_PIE` set) and a `GNU_RELRO` program header with nonzero size. |
| Non-exec stack (NX) | **Added** — `-C link-args=-Wl,-z,noexecstack` | Not a rustc default; added because it isn't guaranteed once C FFI objects (aws-lc-sys/cmake, ring, libsql-ffi/sqlite — all built by their own C build systems, not rustc) enter the link. Confirmed: `readelf -l` → `GNU_STACK` segment flags `RW` (no `E`). |
| Stack canaries | **Not available on stable** — see Deferred | `nm` on a locally compiled binary (default rustc flags) shows no `__stack_chk_fail`; only appears when forcing the nightly-only `-Z stack-protector=all` via `RUSTC_BOOTSTRAP=1` (not used for the real build — see Deferred). Also confirmed absent on the vendored C side: the live `zig cc` invocations compiling `aws-lc-sys` carry no `-fstack-protector*` flag (see Deferred for the macOS contrast). |
| CFI | **Not available on stable** — see Deferred | `-Z sanitizer=cfi` confirmed nightly-only (`rustc -Z help`, only reachable via `RUSTC_BOOTSTRAP=1`, which is not used for the shipped build). |
| W^X | Implied by the RELRO + NX-stack combo above (no segment is ever both writable and executable post-relocation) | Read off the same `readelf -l` program-header dump: no segment has both `W` and `E`. |

**The static-PIE finding** (this is the "test it, don't assume" item): rustc's
target-spec metadata for this target (`rustc -Z unstable-options --print
target-spec-json --target x86_64-unknown-linux-musl`) reports
`position-independent-executables: true` and `crt-static-default: true`,
which *reads* like "static-PIE is already the default." **It is not.** Tested
directly: the baseline `cargo zigbuild --release --target
x86_64-unknown-linux-musl --features jemalloc -p boatramp` (no extra flags,
rustc's actual defaults in effect) links successfully but produces
`Type: EXEC` — a plain static, **non**-PIE executable — confirmed with
`readelf -h`/`file` on that binary. Adding `-C relocation-model=pic` alone
(the "make the default explicit" theory) does not change this either —
verified on a minimal test crate before touching the real build.

What *does* work, found by testing several flag combinations on a minimal
crate first, then confirmed on the real, full `boatramp` binary: **`-C
target-feature=-crt-static`**. This tells rustc not to force fully-static
linking at the Rust level, and on this exact target/toolchain (rustc 1.99 +
`zig cc` 0.17's bundled musl sysroot via `cargo-zigbuild`), the linker
resolves that to genuine **static-PIE** rather than to a dynamically-linked
`ld-musl-*.so.1` binary — the terminology `file(1)` itself uses
(`static-pie linked`). Confirmed on the real binary:

```
$ file target/x86_64-unknown-linux-musl/release/boatramp
… ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped

$ readelf -h target/x86_64-unknown-linux-musl/release/boatramp | grep Type
  Type:                              DYN (Position-Independent Executable file)

$ readelf -d target/x86_64-unknown-linux-musl/release/boatramp
Dynamic section at offset 0xb0c63c0 contains 20 entries:
  Tag        Type                         Name/Value
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 …
# readelf -d | grep -i needed  → (no output: zero DT_NEEDED entries)
# readelf -l | grep -i interp  → (no output: no PT_INTERP segment)

$ readelf -l target/x86_64-unknown-linux-musl/release/boatramp
  GNU_RELRO      0x000000000ad2d210 0x000000000ad2f210 0x000000000ad2f210
                 0x00000000003c4f40 0x00000000003c5df0  R      0x1
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000001000000  RW     0x0
```

This matters beyond "PIE is on": `-C target-feature=-crt-static` sounds like
it should reintroduce a dynamic-libc dependency (that's its usual meaning —
link against musl's `libc.so` instead of embedding it statically), which
would defeat the entire reason this project builds against musl in the first
place (`nix/package-musl.nix`'s own header: "musl links statically, so the
image is just the binary — no glibc/loader closure"). **It does not, on this
target/toolchain**: zero `DT_NEEDED` entries, no `PT_INTERP` segment — still
fully self-contained, no runtime loader, no shared library dependency. The
binary gets real ASLR *and* keeps the "it's just the binary" property. Also
checked: nothing in boatramp's own source conditions on
`cfg(target_feature = "crt-static")` (`grep -rn "crt-static\|crt_static"` over
`crates/`/`examples/` is empty), so this doesn't silently change any of
boatramp's own code paths — only the musl-target linking strategy.

`aarch64-unknown-linux-musl` was built and verified the same way (same
`.cargo/config.toml` section, same command with `--target
aarch64-unknown-linux-musl --features jemalloc -p boatramp`) and shows the
identical posture: `file` reports `ELF 64-bit LSB pie executable, ARM
aarch64, … static-pie linked`; `readelf -h` → `Type: DYN`; `readelf -d` →
`FLAGS_1: Flags: NOW PIE` with zero `DT_NEEDED` entries; `readelf -l` shows
both the `GNU_RELRO` segment and a `GNU_STACK` segment with `RW` (not `RWE`)
flags. Both release-matrix Linux arches link successfully with the real,
full `--features jemalloc -p boatramp` build and come out static-PIE,
full-RELRO+BIND_NOW, NX-stack, with zero runtime library dependencies.

**Honest trade-off, not benchmarked**: the static-PIE `x86_64` binary is
~3% larger than the static-EXEC baseline built moments earlier in the same
session (185,688,792 vs. 179,908,008 bytes) — static-PIE's self-relocating
startup needs a much larger relocation table (`RELASZ` went from "no dynamic
section at all" to 5,778,768 bytes / 240,782 entries) that musl's own crt1
processes once at process start, and Rust's codegen for a PIE binary
typically uses a slightly more indirect TLS access model than a fixed-address
static binary can use. Neither was measured in this pass (no startup-latency
or steady-state benchmark was run); flagging it so it isn't silently assumed
free.

### macOS — `x86_64-apple-darwin`, `aarch64-apple-darwin`

Built directly via `cargo build --release --target <triple>` on the native
GitHub macOS runners (`macos-15-intel`, `macos-14`) — not through Nix.

| Mitigation | Status | Notes |
|---|---|---|
| PIE / ASLR | **Always on — OS-mandatory**, not a flag | `rustc -Z unstable-options --print target-spec-json --target {x86_64,aarch64}-apple-darwin` reports `position-independent-executables: None` — the field doesn't apply because Apple's linker (`ld`) has produced PIE-only executables unconditionally on 64-bit macOS for years; there is no supported way to opt out, and none is needed. **Verified on a real build**: this task's own `cargo build -p boatramp --release --target aarch64-apple-darwin --features tls,handlers,cluster,s3,cloudflare-kv,compression,bundler,oidc` (the exact command `release.yml`'s macOS leg runs) linked successfully, and `otool -hv` on the resulting binary shows `MH_MAGIC_64 ARM64 … PIE MH_HAS_TLV_DESCRIPTORS` in the Mach header flags. |
| RELRO / BIND_NOW | **N/A — ELF-only concept; structurally superseded** | Mach-O has no RELRO segment type. `otool -l` on the built binary shows an `LC_DYLD_CHAINED_FIXUPS` load command — the modern dyld "chained fixups" format, which binds and integrity-checks what used to be lazily-resolved pointers through an immutable, bounds-checked chain. This is the actual structural answer to the GOT/lazy-pointer-overwrite attack class RELRO+BIND_NOW defends against on ELF, and it's on by default for this target/deployment combo — not a `rustflags` input. |
| Non-exec stack (NX) / W^X | **On — OS-enforced**, not a flag | XNU enforces W^X at the page-protection level; Mach-O's standard ABI never maps the stack executable. No equivalent of `-z noexecstack` exists to pass because there is nothing to turn on — it's not optional on this OS. |
| Code-signature requirement | **On — OS-mandatory**, found while verifying | Beyond what was asked, but relevant: `codesign -dv` on the freshly linked (pre-`release.yml`-signing) binary already shows `flags=0x20002(adhoc,linker-signed)` — arm64 macOS requires every executable to carry at least an ad-hoc signature straight out of the linker, before `release.yml`'s own `codesign --force --sign -` step runs. Binary-integrity enforcement is baked into the ABI here, independent of any flag. |
| Stack canaries | **Rust codegen: not available on stable** (see Deferred) — **but vendored C deps get them for free here** | `nm` on this build's binary shows `___stack_chk_fail` / `___stack_chk_guard` as referenced (undefined, resolved against `libSystem`) symbols. That's not from Rust's codegen (confirmed `-Z stack-protector`-gated and unused — see Deferred); it's because Apple's Clang (unlike upstream/zig's Clang — see the Linux musl table) defaults to `-fstack-protector-strong` for C/C++ compilation, so the vendored C deps built by `cc`/`cmake` for this target (aws-lc-sys, ring, libsql-ffi/sqlite, zstd-sys, lz4-sys, blake3, psm) pick up canaries automatically, with no `rustflags` change needed or possible. |
| CFI | **Not available on stable** — same as Linux | See Deferred. **Not** Hardened Runtime either — see below. |
| Hardened Runtime | **Deliberately out of scope here** | `release.yml` ad-hoc code-signs the macOS binary (`codesign --force --sign -`) *specifically without* `--options runtime`, because Hardened Runtime requires Developer-ID notarization, which this pipeline doesn't do (see the existing comment in `release.yml`: "no Apple approval; no `--options runtime` — hardened runtime is for Developer-ID notarization"). Turning that on is an owner-level distribution decision (Apple Developer ID enrollment + notarization pipeline), not a `rustflags`/linker change — flagged as a residual item, not silently added. |

### Windows — `x86_64-pc-windows-msvc`

Built directly via `cargo build --release --target x86_64-pc-windows-msvc
--features "$feats"` on the native `windows-latest` GitHub runner.

| Mitigation | Status | How verified |
|---|---|---|
| ASLR (`/DYNAMICBASE`) | **Added explicitly** via `-C link-args=/DYNAMICBASE ...` | link.exe's own default for a modern toolset already enables this; passed explicitly so the posture doesn't rest silently on an external default. **Not independently verified on a built binary** — no Windows/MSVC cross-linker is available in this sandbox (see Residual risk). |
| DEP (`/NXCOMPAT`) | **Added explicitly** | Same caveat as above. |
| `/HIGHENTROPYVA` | **Added explicitly** (requires `/DYNAMICBASE`, also passed) | Same caveat. |
| Control Flow Guard (CFG) | **Added** — `-C control-flow-guard=yes` | This is the genuine, **stable** (not `-Z`-gated) forward-edge CFI mechanism this toolchain supports: `rustc -C help` lists `control-flow-guard=val -- use Windows Control Flow Guard (default: no)` as a stable codegen option (verified on this exact rustc 1.99.1). It is Windows-specific and coarser than LLVM CFI, but it is real, shipping-grade, stable-toolchain forward-edge CFI — unlike `-Z sanitizer=cfi`, it needed no nightly toolchain and no LTO change. |
| RELRO/BIND_NOW | N/A — PE has no RELRO concept | — |
| Stack canaries (`/GS`) | **Not verified either way on this build** | MSVC's own `/GS` stack-protection is a *cl.exe* convention; rustc's codegen for `*-msvc` targets does not go through `cl.exe` and whether LLVM emits an equivalent `stackprotector` attribute by default for this target was not checked (no Windows toolchain available here to test). Treated as unverified, not claimed. |

**Residual risk**: none of the three `windows-msvc` linker flags above were
verified by actually linking a `.exe` and inspecting its PE headers (e.g. with
`dumpbin /headers` or `llvm-readobj --coff-headers`) — there is no MSVC
`link.exe`, and no working `lld-link` + Windows import libraries, available in
this macOS/Nix sandbox. The flags are standard, well-documented MSVC linker
switches and `-C control-flow-guard` is a stable rustc option whose valid
values were confirmed directly against this rustc build (`rustc -C
control-flow-guard=bogus ...` → `error: incorrect value ... expected
either a boolean, 'checks', or 'nochecks'`), but the **end-to-end link on the
real target was not exercised**. The next Windows release-leg CI run is the
first real confirmation; if any of these three raw `link-args` values turn out
to be rejected by `link.exe`'s argument parsing (unlikely — they're exact,
unmodified MSVC switches), that run will fail loudly rather than silently
ship an unhardened binary, because it's a required job in the release matrix.

## Deferred (honestly, not faked)

| Mechanism | Why deferred |
|---|---|
| LLVM/Clang-style CFI (`-Z sanitizer=cfi`) | Requires nightly rustc **and** fat LTO (the workspace currently uses `lto = "thin"`). boatramp is pinned to **stable** (`rust-toolchain.toml`); moving to nightly or changing the LTO mode to chase this is explicitly out of scope per this task's own instructions. Windows' `-C control-flow-guard=yes` (above) is the one genuinely-available, stable-toolchain forward-edge CFI for this release matrix; Linux/macOS have no stable-toolchain equivalent today. |
| rustc stack-protector codegen (`-Z stack-protector=all/strong/basic`) | Also `-Z`-gated (nightly-only) on this rustc version — confirmed via `rustc -Z help` and by direct test (`nm` on a binary built with vs. without the flag; see the Linux musl table). Classic stack-smashing canaries are consequently **not** inserted into boatramp's compiled Rust code by this build, on any target. This is a materially smaller gap than it looks for a memory-safe-by-default codebase: canaries defend against the C-style "overflow a stack buffer past its bounds" bug class, and safe Rust's bounds-checked slice/array indexing panics instead of silently corrupting the stack for that same bug class. The residual exposure is (a) `unsafe` blocks in boatramp's own code and (b) the vendored C dependencies compiled by their own build systems (`aws-lc-sys` via cmake, `ring`, `libsql-ffi`/sqlite) — those are built by `cc`/`cmake` invocations outside rustc's `RUSTFLAGS`, so this change does not (and structurally cannot, via `.cargo/config.toml`) affect whether they get their own canaries. **Empirically this splits by platform**: on the actual Linux musl build, the `zig cc` invocations compiling `aws-lc-sys`'s C sources (observed directly in the running build) carry no `-fstack-protector*` flag — upstream/zig's bundled Clang does not default it on, so those C objects are canary-free too. On the actual macOS build, `nm` on the linked binary shows live `___stack_chk_fail`/`___stack_chk_guard` references — Apple's Clang *does* default to `-fstack-protector-strong`, so the same vendored C deps get canaries there "for free," with no `rustflags` input from this change. A deliberate future investigation (pinning `-fstack-protector-strong` into the vendored C builds' own `CFLAGS` for musl, to close that asymmetry) is a reasonable follow-up, not claimed as done here. |
| macOS Hardened Runtime / notarization | Requires a Developer-ID signing identity + Apple notarization submission, which the release pipeline deliberately doesn't do today (ad-hoc signing only, for the `com.apple.security.virtualization` entitlement). An owner-level distribution decision, not a compiler-flag change. |
| Windows PE header verification | No MSVC linker available in this build environment; see "Residual risk" above. |

## Summary table

| Target | PIE/ASLR | RELRO+BIND_NOW | NX stack | W^X | Canaries | CFI |
|---|---|---|---|---|---|---|
| x86_64/aarch64-unknown-linux-musl | **on — added** (`-C target-feature=-crt-static`; was `EXEC` by default, link-verified as static-PIE) | on (added, link-verified) | on (added, link-verified) | on (implied) | **not available (stable)**; vendored C deps also unprotected here (zig's Clang defaults off) | **not available (stable)** |
| x86_64/aarch64-apple-darwin | on (OS-mandatory, link-verified) | N/A (Mach-O; chained fixups supersede it, verified present) | on (OS-enforced) | on (OS-enforced) | Rust codegen: **not available (stable)**; vendored C deps **are** protected here (Apple Clang defaults `-fstack-protector-strong`, verified via `nm`) | **not available (stable)**; Hardened Runtime deferred (owner decision) |
| x86_64-pc-windows-msvc | on (added, **not link-verified**) | N/A (PE) | DEP on (added, **not link-verified**) | — | not verified | **on** — Control Flow Guard (`-C control-flow-guard=yes`, stable) |
