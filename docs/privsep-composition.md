# privsep phase 1: a hardened, security-first composition

Scope: operator guidance for composing a boatramp node into least-authority privsep instances.
This is **not** a spec change — it stays faithful to the shipped capability vocabulary
(`boatramp_types::privsep::HostAuthority`, design §1.2) and the composition-closure lint the root
runs fail-closed before any spawn (`check_composition_closure`, design §5 F7/F8). It explains the
difference between a composition the lint *accepts* and one that is actually *secure*, and gives a
hardened exemplar.

Absent a `[privsep]` section the node boots the single-process monolith, unchanged — this document
matters only when an operator chooses to compose. For the mechanism (instances, links, the root
supervisor, the fd topology) see `PLAN-privsep-phase1.md`; for the enumerated authorities and their
blast radii, `HostAuthority::doc()` prints a one-line description of each.

## 1. Why the live-gate demo is NOT a secure composition

The `privsep_live` end-to-end gate (`crates/boatramp/tests/privsep_live.rs`) stands up a two-instance
composition whose `edge` instance holds **every** listener plus both execution authorities plus both
control authorities:

```
"edge": capabilities: [
    "listen.public-tls", "listen.http-parse", "listen.mail", "listen.overlay",
    "listen.s3ingress", "listen.inbound-tcp", "listen.gateway",   // group C (untrusted-byte parsers)
    "exec.wasmtime", "exec.compute",                              // group D (execution)
    "control.admin-api", "acme.dns-control",                      // group E (control)
]
```

That is a **mechanism proof** — it demonstrates the socketpair link, the privileged listener bind +
fd-pass, the `SCM_RIGHTS` splice, and the fail-closed per-instance sandbox end-to-end. It is **not** a
secure-composition exemplar, and an operator must not copy it:

- `listen.http-parse` is the single most-exposed, fuzzed surface on the node (the hand-rolled HTTP/2 +
  HTTP/1 parser running directly on attacker bytes). A memory-safety break there is the most likely
  RCE boatramp has.
- On that `edge` instance, a parser RCE lands in the **same address space** as `exec.compute` (re-execs
  the compute workers → runs arbitrary workloads), `exec.wasmtime` (the JIT), and `control.admin-api`
  (the `/api/*` mutation surface). So the parser RCE immediately reaches `execve` and the control
  plane. The isolation wall bought nothing against the most-probable RCE, because the dangerous
  authorities co-reside with the parser.

The composition-closure lint **accepts** this layout: its hard exclusion is only
`{A} × {C ∪ D ∪ E}` (a *crown jewel* must not co-reside with a parser/exec/control surface). It has no
rule against C, D and E co-residing with **each other**, because the design's load-bearing isolation
target is the crown-jewel keys. The lint is necessary, not sufficient — the rest is the operator's
composition discipline, which this document supplies.

## 2. The isolation rules

Read "group" as the `HostAuthority` blast-radius group (design §1.2): **A** crown-jewel key/sealer,
**B** backend creds/pools, **C** untrusted-byte listeners, **D** execution, **E** control.

1. **The untrusted-byte parser stands alone.** `listen.http-parse` (and each other `listen.*`
   attacker-facing parser — `listen.public-tls`, `listen.mail`, `listen.overlay`, `listen.s3ingress`,
   `listen.inbound-tcp`, `listen.gateway`) is the RCE frontier. Give the parser instance **nothing but
   the parser** — no key, no pool, no `execve`, no control surface. Isolated, a parser RCE can only
   forward typed/parsed bytes inward over its link; it holds no authority to steal.

2. **Split TLS termination from HTTP parsing.** `listen.public-tls` holds the live private cert key in
   memory; `listen.http-parse` is the fuzzed parser. The vocabulary splits them on purpose (design §6
   decision 5) so the most-fuzzed surface is walled even from the cert key. In a hardened layout they
   are **separate instances**: the TLS terminator forwards the decrypted byte stream to the parser,
   which holds no cert key.

3. **Each crown jewel is isolatable alone, and the lint keeps it away from every exposed surface.**
   The six group-A authorities — `secrets.sealer`, `token.signer`, `image.signer`,
   `overlay.dial-signer`, `s3ingress.root`, `cluster.join-signer` — must never co-reside with a C, D
   or E authority; the lint enforces exactly `{A} × {C ∪ D ∪ E}` fail-closed. A crown jewel RCE is the
   highest-value compromise on the fleet (every tenant's secrets, or forged authz for any principal),
   so a crown jewel holder parses no attacker bytes, runs no JIT/compute, and serves no control plane.

4. **The thing that runs workloads holds no keys.** `exec.compute` (spawns the firecracker / VZ /
   container workers) and `exec.wasmtime` (the JIT) each go on their **own** instance, sibling-split
   out of every key holder. A wasmtime escape or a compute-plane compromise then lands in an instance
   holding no crown jewel and no backend credential.

5. **Backends split by data plane.** Put `backend.kv`, `backend.sql`, `backend.blob` and
   `backend.messaging` each on its own instance, and keep them off the untrusted-byte and execution
   surfaces (rule 1/4). The lint flags co-residence of a backend with a listener/exec surface as a
   **warning** (`BackendCoResidentWithExposed`, design §5 F8); a hardened node heeds it. `backend.kv`
   especially — it is the control-plane source of truth (site config, deploy manifests, tokens and
   sealed-cred ciphertext at rest) — belongs away from anything attacker-facing.

6. **Keep the root the TCB floor.** The root supervisor holds bootstrap authority only: it resolves
   the topology, lints it, binds the privileged listeners, creates the links, spawns + supervises, and
   installs its OWN tightest self-profile (no network, no key-lock, `execve` Landlock-pinned to its
   own binary; design §4.3). It unseals no KEK, opens no pool, and parses no untrusted bytes — do not
   push any serving/authority logic into it.

## 3. A hardened composition (illustrative RON)

A least-authority layout that applies the rules above. Instance names are arbitrary operator handles;
what matters is each instance's capability **set**. Every capability is hosted exactly once (the lint
requires the union to equal the full set), no crown jewel touches an exposed surface, and the parser
is alone.

```ron
privsep: (
    instances: {
        // --- untrusted-byte frontier (group C), each parser walled ---
        "tls":       ( capabilities: ["listen.public-tls"],  sandbox: Strict, links: ["tls-to-http"] ),
        "http":      ( capabilities: ["listen.http-parse"],  sandbox: Strict, links: ["tls-to-http", "http-to-kv", "http-to-sql", "http-to-blob"] ),
        "mail":      ( capabilities: ["listen.mail"],        sandbox: Strict, links: ["mail-to-bus"] ),
        "overlay":   ( capabilities: ["listen.overlay"],     sandbox: Strict, links: [] ),
        "s3in":      ( capabilities: ["listen.s3ingress"],   sandbox: Strict, links: ["s3in-to-blob"] ),
        "rawtcp":    ( capabilities: ["listen.inbound-tcp"], sandbox: Strict, links: [] ),
        "gateway":   ( capabilities: ["listen.gateway"],     sandbox: Strict, links: [] ),

        // --- execution (group D), isolated — hold no keys ---
        "wasm":      ( capabilities: ["exec.wasmtime"],      sandbox: Strict, links: [] ),
        "compute":   ( capabilities: ["exec.compute"],       sandbox: Strict, links: [] ),

        // --- control (group E) ---
        "admin":     ( capabilities: ["control.admin-api"],  sandbox: Strict, links: ["admin-to-kv"] ),
        "acme":      ( capabilities: ["acme.dns-control"],   sandbox: Strict, links: [] ),

        // --- backend data planes (group B), each on its own instance ---
        "kv":        ( capabilities: ["backend.kv"],         sandbox: Strict, links: ["http-to-kv", "admin-to-kv"] ),
        "sql":       ( capabilities: ["backend.sql"],        sandbox: Strict, links: ["http-to-sql"] ),
        "blob":      ( capabilities: ["backend.blob"],       sandbox: Strict, links: ["http-to-blob", "s3in-to-blob"] ),
        "bus":       ( capabilities: ["backend.messaging"],  sandbox: Strict, links: ["mail-to-bus"] ),

        // --- crown jewels (group A), each isolatable alone ---
        "sealer":    ( capabilities: ["secrets.sealer"],       sandbox: Strict, links: ["sealer-to-signer"] ),
        "signer":    ( capabilities: ["token.signer"],         sandbox: Strict, links: ["sealer-to-signer"] ),
        "imgsign":   ( capabilities: ["image.signer"],         sandbox: Strict, links: [] ),
        "ovlsign":   ( capabilities: ["overlay.dial-signer"],  sandbox: Strict, links: [] ),
        "s3root":    ( capabilities: ["s3ingress.root"],       sandbox: Strict, links: [] ),
        "cluster":   ( capabilities: ["cluster.join-signer"],  sandbox: Strict, links: [] ),
    },
    // Links carry authority calls + the serving splice. Only links actually used are declared; a
    // parser links only INWARD to the backends/signers it must reach, never to another parser.
    links: {
        "tls-to-http":      ( from: "tls",    to: "http",   transport: Local ),
        "http-to-kv":       ( from: "http",   to: "kv",     transport: Local ),
        "http-to-sql":      ( from: "http",   to: "sql",    transport: Local ),
        "http-to-blob":     ( from: "http",   to: "blob",   transport: Local ),
        "mail-to-bus":      ( from: "mail",   to: "bus",    transport: Local ),
        "s3in-to-blob":     ( from: "s3in",   to: "blob",   transport: Local ),
        "admin-to-kv":      ( from: "admin",  to: "kv",     transport: Local ),
        "sealer-to-signer": ( from: "sealer", to: "signer", transport: Local ),
    },
)
```

Notes:

- `sandbox: Strict` clamps each instance harder than `Derived` (it drops the shared world-writable
  temp grant, so an instance writes only under its own state subtree). Under `[privsep]` every
  instance's profile is required `Enforced` fail-closed regardless — a kernel that can deliver only a
  partial sandbox refuses the whole node (design §2 F6). `Off` is dev-only.
- This maximal split is the *limit* of the model, not a requirement. An operator may coarsen it —
  e.g. group the rarely-exposed listeners, or co-locate the data-plane backends — as long as the two
  hard rules hold: **(a)** no crown jewel co-resides with any C/D/E surface (the lint enforces this),
  and **(b)** the untrusted-byte parser co-resides with nothing it would hand an RCE.
- The `local` (socketpair) transport is the Phase-1 default; it has no crypto/TCP overhead, so a
  co-located split does not regress the serving hot path. `tcp`/`overlay` carry the same API for a
  cross-host split (a follow-on).

## 4. The signer-key unlock closure (a composition requirement)

If the control-plane auth signer is a **sealed** key source (`serve.signer = Sealed(key_ref:
"path:<file>")`, the "KEK-file now" owner decision), the composition MUST contain a `secrets.sealer`
reachable from the `token.signer` instance — the signer never holds the KEK, so it asks the sealer to
unseal its key over a feature-link. The root enforces this fail-closed before any spawn
(`check_sealed_signer_closure`): a sealed-key signer with no linked sealer is a hard refusal. In the
layout above, `sealer-to-signer` satisfies it; the root wires the sealer a per-link unseal allowlist
scoped to exactly that `key_ref`, and the sealer enforces it fail-closed. (`AwsKms`/ambient signers
need no sealer; they resolve their key themselves.)

## 5. What the composition does NOT contain, and the honest residual

- **No inline / env-valued secret.** Under `[privsep]` every §1.2 key input must be a `path:` / KMS
  reference; an inline or env-valued key is a hard load refusal (the root's secret-blind screen,
  design F1/F11). Each instance resolves its OWN secret inputs behind its own Landlock grant — the
  root never dereferences them and never couriers a live credential, env or otherwise.
- **Design-accepted residual — the sealer+KV split is confidentiality, not integrity.** Splitting
  `secrets.sealer` from `backend.kv` protects the *confidentiality* of sealed credentials: a
  `backend.kv` RCE sees only ciphertext without the sealer. It does **not** protect control-plane
  *integrity* — a `backend.kv` RCE can still tamper plaintext tenancy rows / deploy manifests. That
  integrity rests on boatramp's structural tenancy discipline, not on the privsep wall (design §5
  inv4 RESIDUAL). This is why `backend.kv` belongs on its own instance, far from any attacker-facing
  surface (rule 5) — the split narrows, but does not erase, a KV-RCE blast radius. The sealer+KV
  A×B co-residency the model *permits* (Finding 4, owner-design sanctioned) is the floor, not the
  recommendation; a hardened node keeps them apart.

## 6. Checklist

- [ ] `listen.http-parse` (and every `listen.*`) holds the parser and nothing else.
- [ ] `listen.public-tls` (cert key) is a separate instance from `listen.http-parse`.
- [ ] No crown jewel (A) shares an instance with any listener (C), exec (D), or control (E) — the
      lint refuses this, but design the topology so you never hit the refusal.
- [ ] `exec.wasmtime` and `exec.compute` are isolated and hold no keys.
- [ ] Backends (B) are split per data plane and kept off the exposed surfaces (heed the F8 warning).
- [ ] `backend.kv` is isolated far from any attacker-facing surface (the integrity residual).
- [ ] A sealed-key `token.signer` has a linked `secrets.sealer` (the closure lint requires it).
- [ ] Every parser links only inward to the backends/signers it must reach, never to another parser.
</content>
</invoke>
