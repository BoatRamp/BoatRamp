# privsep Phase-3 frontend substrate — crossing-cost benchmark & operator guidance

Scope: the measured frontend→backend `local`-shape **crossing cost** across the candidate isolation
substrates, and how an operator uses it to choose the `[privsep].instances.<name>.substrate` for an
inverted frontend (design `PLAN-privsep-fabric-composition.md` **decision 1** + `PLAN-privsep-phase1.md`
§7). The owner decision (2026-11-02) is that the frontend substrate is **operator-selectable** across
OS-process / container / VM — **not a hard pick** — chosen per node from a real hot-path measurement
rather than an estimate. This document is that measurement, plus the re-run recipe so it stays a
maintained guidance tool.

The benchmark **measures only — it does not recommend a substrate.** It holds the served work constant
(a synthetic accepted-client connection + a representative ~300-byte parsed `RequestHead` + a
real-sized response body) and measures the per-request delta each substrate's wall imposes on the
handoff from the exposed byte-parser (frontend) to the backend holding authority.

## 1. What the crossing cost is (and why it is the right number)

A Phase-3 inverted frontend parses untrusted bytes holding no keys/backends, then hands the backend a
connection to serve (design §3.1 "serving splice", the per-request-hot path). Caveat 2 of the program
is explicit: that splice **cannot afford an E2EE RTT per request**, so a co-located split uses the
`local` shape. The substrate (OS process / container / VM / wasm) is the WALL around the frontend, and
each wall charges a different price at exactly that per-request crossing. That price — not boot time,
not throughput of the served handler — is what decides whether a given wall is affordable on a given
node's serving hot path. The benchmark isolates it.

The harness lives at `crates/boatramp/benches/privsep_crossing/` (`[[bench]] privsep_crossing`,
`harness = false` — a standalone CLI, not a criterion suite). It BUILDS on every target boatramp builds
(musl/CI included); every substrate self-checks its live kernel feature at run time and reports **N/A
with the reason** instead of fabricating a number or failing the build — the same lighthouse-gated
pattern as `crates/boatramp/tests/privsep_live.rs`. Only an explicit `cargo bench … -- run` on a real
kernel (lighthouse) produces live numbers.

## 2. The substrates measured

| substrate (`--substrates`) | wall | crossing mechanism |
| --- | --- | --- |
| `fdpass` | OS process, separate address space + per-capability seccomp/Landlock | the **built Phase-1 `local` transport, unmodified** — the real `privsep_link::LinkEndpoint` `SCM_RIGHTS` fd-pass. The accepted-client fd never re-crosses after handoff. |
| `byterelay` | OS process | plain `socketpair(2)`; request head + response body cross as bytes (one extra copy each way; the frontend stays a post-filter policy point) |
| `container` | namespace/cgroup (`unshare --fork`; needs `CAP_SYS_ADMIN`) | the SAME byte-relay, backend in fresh net/pid/mount/uts/ipc namespaces — isolates the namespace-boundary tax alone |
| `vsock-loopback` | none (kernel `AF_VSOCK` host-local loopback) | sanctioned VM LOWER BOUND: real `AF_VSOCK` syscalls, zero hypervisor-exit cost |
| `vsock-firecracker` | hardware-virtualized microVM, its own guest kernel | a real firecracker VM (kernel+initramfs, no block device), guest PID 1 on `AF_VSOCK`, dialed via firecracker's vsock bridge |
| `wasm` | wasmtime linear-memory boundary | classic-module copy-in / call / copy-out (no splice fast-path); the Phase-4 per-tenant analogue |

Payload sizes (`--sizes`): the four real serving shapes — **1 KiB** (API JSON), **64 KiB** (typical
page), **512 KiB**, **2 MiB** (image-serve). Each cell reports **warm** (steady-state p50/p99 over a
persistent backend) and **cold** (fresh-backend spawn/setup) **separately** — spawn cost matters
independently for Phase-4 per-tenant instances, so it is never blended into the per-request number.

## 3. Measured results (lighthouse)

Live run on `lighthouse.bytesoba.net` (the owner's NixOS Linux/Docker box; see `[[linux-dev-box-lighthouse]]`),
the authoritative measurement host per `[[bench-host-divergence]]` (a dedicated box, not a same-box /
trivial-envelope repro). Figures are the steady-state p50 crossing unless noted; **re-run (§5) for the
exact table on your own kernel** — these capture the SHAPE, which is what the decision turns on.

| substrate | warm crossing, 1 KiB → 2 MiB | cold / spawn | the finding |
| --- | --- | --- | --- |
| `fdpass` (OS-process `SCM_RIGHTS`) | **~7 µs, FLAT** across all four sizes | sub-millisecond process spawn | the fd-pass hands over the connection itself, so the cost does **not** move with response size — the flatness IS the result |
| `byterelay` (OS-process socketpair) | **~6 µs → ~147 µs** (grows with payload) | sub-millisecond | one extra copy each way; cheap at API sizes, the copy dominates at image sizes |
| `container` (namespaced byte-relay) | **~6 µs → ~147 µs** (+ a small namespace tax) | namespace setup | the namespace/cgroup WALL adds almost nothing to the steady-state crossing over byte-relay |
| `vsock-firecracker` (microVM) | **~27 µs → ~736 µs** | **~121 ms VM boot** | the hypervisor crossing is ~4× the socketpair at small sizes and grows faster; the boot cost is the Phase-4 per-tenant gate |
| `vsock-loopback` (VM lower bound) | between `byterelay` and `vsock-firecracker` | n/a (no boot) | the floor a real VM's vsock can approach with zero hypervisor-exit cost |
| `wasm` (linear-memory copy) | copy-bound, grows with payload, **no splice fast-path** | per-`Instance` instantiation (Engine+Module shared) | strongest memory wall, but every byte is copied in and out of linear memory — re-run for the exact column |

**Headline shape:** fd-pass is flat and cheapest (~7 µs) because it moves the connection, not the
bytes; byte-relay and container are within noise of each other and of fd-pass at API sizes but pay the
copy at image sizes (~147 µs at 2 MiB); the VM wall costs ~4–5× the per-request crossing **and** a
~121 ms boot, so it is justified only where the threat model demands a hardware wall and the latency
budget can absorb it (high-threat multi-tenant), with the flat monolith / OS-process split the default
elsewhere.

## 4. Choosing a substrate (operator guidance)

The substrate is a **per-instance** config choice (`substrate: OsProcess | Container | Vm`); pick it
from the node's threat model and the serving latency budget, in that order:

- **`OsProcess` (default, WIRED today).** The separate address space + the fail-closed per-capability
  seccomp/Landlock profile already contain a frontend RCE from reaching any key/backend/control
  authority — at ~7 µs flat (fd-pass) it is free on the hot path. The right default for almost every
  node, and the only substrate the Phase-3 foundation cut spawns.
- **`Container`.** Add namespace/cgroup confinement when the threat model wants a kernel-visible
  boundary (resource caps, a scoped mount/net view) but excludes kernel-escape. The steady-state
  crossing is essentially unchanged from `OsProcess`; the cost is operational (image/runtime), not
  per-request. *(Spawn backend is a follow-on — see §6.)*
- **`Vm` (firecracker / VZ).** A hardware wall that survives even a guest-kernel RCE. Reserve it for
  **high-threat multi-tenant** frontends whose latency budget can absorb ~4–5× the per-request crossing
  (hundreds of µs at image sizes) and the ~121 ms boot. Not a blanket choice (program caveat 4 — the
  `in` axis stacks overhead per boundary; isolate the riskiest surfaces only). *(Spawn backend is a
  follow-on — see §6.)*
- **wasm frontend.** Only for pure parse/transform surfaces that need no native splice/sendfile
  fast-path — the copy-in/copy-out cost is real and grows with payload. The hand-rolled HTTP/2 + TLS
  that Phase 3 targets wants a native fast-path, so wasm is not its home (plan §Phase-3).

Whichever is chosen, the inverted frontend is the **same batteries-included binary** booted in a
least-authority posture (`frontend` = `listen.public-tls` + `listen.http-parse` + `exec.wasmtime`, no
keys/backends) — never a specialized build (program caveat 5).

## 5. Running the benchmark (lighthouse)

```sh
# On lighthouse. Process/namespace/wasm substrates (container needs CAP_SYS_ADMIN ⇒ sudo):
sudo cargo bench -p boatramp --bench privsep_crossing -- \
  --substrates fdpass,byterelay,container,wasm \
  --sizes 1KiB,64KiB,512KiB,2MiB \
  --frontend-cpu 2 --backend-cpu 3 --csv

# Add the real microVM substrate (needs a guest kernel + the initramfs from guest/build-initrd.sh):
sudo cargo bench -p boatramp --bench privsep_crossing -- \
  --substrates vsock-loopback,vsock-firecracker \
  --fc-bin "$(command -v firecracker)" \
  --fc-kernel /path/to/vmlinux \
  --fc-initramfs /path/to/privsep-guest-initramfs \
  --vm-cold-iterations 5 --csv
```

CPU-pin both ends (`--frontend-cpu`/`--backend-cpu`, applied via `sched_setaffinity` so it reaches
forked/re-exec'd/namespaced children too) for a stable number. Omitting a `--fc-*` path (or a guest
that fails to boot) reports `vsock-firecracker` as N/A with the reason rather than guessing.

## 6. Status — what is wired vs. a reported follow-on

- **WIRED (Phase-3 foundation):** the `substrate` config vocabulary + lint + the supervisor's
  spawn-backend dispatch seam; **`OsProcess`** is the fully-wired backend (the root's fork+exec over the
  `local` socketpair). The benchmark compiles everywhere and runs live on lighthouse.
- **Follow-on (DECOMPOSED):** the `Container` and `Vm` spawn backends reuse the existing
  `boatramp-container` and `boatramp-firecracker` / `boatramp-vz` compute-plane backends. Until that
  wiring lands, the supervisor **refuses** a `Container`/`Vm` instance fail-closed (naming the backend
  it reuses) rather than silently downgrading to an OS process — a silent downgrade would discard the
  operator's chosen wall. The crossing numbers above are what justify prioritizing that wiring for the
  nodes that need the stronger wall.
