# Functions: the compute primitive

Everything boatramp runs is a **function**: a portable
[WASI 0.2 component](https://component-model.bytecodealliance.org/) plus the
capabilities it is granted. A function is the one artifact the engine executes.
What differs between "a handler", "a consumer", "a cron", and "an invoked
function" is not the code — it is the **trigger** that reaches it.

This is the mental model to carry through the rest of the docs:

> **One primitive, two views.** A function is the compute noun. A *handler* is a
> function reached by an HTTP **route**; a *consumer* is one reached by a **queue**
> topic; a *cron* is one reached by a **timer**; an *invoked* function is one
> reached by name. Same component, same sandbox, same bindings — different door.

You have almost certainly already written a function: a
[handler](../how-to/deploy-handler.md) *is* one, viewed through a route. Nothing
about that changes. The function framing just names the thing the route triggers,
so the same component can also be invoked directly, put on a schedule, or wired
into a [workflow](../how-to/workflows.md) — without being rewritten.

## Why a component, not a container image

A boatramp function is a standards-based WASI component, and that is the whole
point of the portability claim. The same `.wasm` runs unmodified on boatramp, on
another WASI 0.2 host (`wasmtime`, Spin, `workerd`), and — because the contract is
the component model, not a boatramp API — it is not locked to us. Instantiation is
sub-millisecond, the memory footprint is small, and the sandbox is strong: the
guest can only touch the host capabilities you grant (`wasi:keyvalue`,
`sql`, `wasi:blobstore`, `wasi:messaging`). Reach for a function first.

## Triggers: the many doors to one function

A **trigger** is a separate thing from the function it fires, and many triggers
can point at the same function version. That is what lets one component be both a
route *and* a cron:

| Trigger | The familiar name | What fires it |
| --- | --- | --- |
| Route | *handler* | an HTTP request matching a host + path |
| Queue | *consumer* | a message on a topic |
| Timer | *cron* | a schedule |
| Invoke | *(the FaaS verb)* | a call by function name |
| Webhook | — | a signature-verified inbound POST |
| Stream | *stream* | host-native SSE / WebSocket fan-out (no component) |

A site's `handlers`, `consumers`, `crons`, and `streams` in `project.cfg` *are*
functions with triggers — they desugar to exactly that, with no behavioural
change. You keep authoring them the familiar way; the engine runs one path.

## Site-scoped vs. top-level functions

A function has an **owner**, and the owner sets how it is addressed and versioned:

- A **site-scoped** function is part of a site's deployment. It versions and rolls
  back *atomically with the deploy* (deploy-pinned), and it is the shape you get
  from a `handlers` / `consumers` entry. This is the default and needs no new
  concept — it is your handler.
- A **top-level** function is owned by a project/tenant, not a single deploy. It
  carries its **own** version line — deploy a new component version, `alias` a
  label like `prod` at a version, `rollback` independently — and it is invoked by
  name. This is the FaaS surface: see
  [Deploy & invoke a function](../how-to/functions.md).

## The runtime is a knob, not a different thing

The [three isolation substrates](./compute-model.md) — an in-process Wasm sandbox,
a shared-kernel container, or a hardware-isolated microVM — are a per-function
**runtime** choice, not three different kinds of compute. `wasm` is the default
and scales to zero by instantiation; a function that needs to run an arbitrary
Linux program, or stronger isolation for untrusted code, selects `microvm` or
`container`. The trigger, the versioning, and the addressing are the same
whichever substrate runs it.

## Where to go next

- Write one as a route: [Write your first handler](../tutorials/first-handler.md).
- Deploy and call one by name: [Deploy & invoke a function](../how-to/functions.md).
- Chain several with retries and rollback:
  [Orchestrate functions with workflows](../how-to/workflows.md).
- Pick a runtime substrate:
  [Compute: functions and their runtimes](./compute-model.md).
