# Reach services over the overlay (service tunneler)

The service tunneler turns `boatramp tunnel` on your workstation into a client
for overlay services: you reach a cluster's private services by name — for
example `db.svc.<cluster>.<zone>` — without exposing them publicly and without
hand-managing ports. It has two front-ends:

- **SOCKS5** (default) — a loopback proxy. No special privilege; point a
  SOCKS-aware client (or `HTTPS_PROXY`) at it.
- **TUN** (`--tun`) — a real virtual network interface, so *any* program on the
  machine reaches in-zone names transparently, with split-DNS. This needs
  elevated privilege to create the device.

Both dial under **your** overlay identity, so treat the local front-end as
sensitive (see [Security](#security) below).

## SOCKS5 (no privilege)

```console
$ boatramp tunnel
# SOCKS5 on 127.0.0.1:1080, auto-generated local credential
```

The proxy resolves overlay service names and dials them for you. Add
`--http-connect` for an `HTTPS_PROXY`-style `CONNECT` front-end on `:1081`.

## TUN virtual interface (`--tun`)

```console
$ boatramp tunnel --tun --cluster my-cluster
# virtual interface up; names under svc.my-cluster.internal resolve into it
```

`--cluster` defaults to your project (`[publish].project`); `--dns-zone`
defaults to `internal` (RFC 8375); `--cidr` defaults to `100.64.0.0/10`. Opening
the device needs privilege, which differs by OS:

| OS      | Privilege            | Device              | Split-DNS                      |
|---------|----------------------|---------------------|--------------------------------|
| Linux   | `CAP_NET_ADMIN`/root | kernel TUN          | `systemd-resolved` / resolv.conf |
| macOS   | root (`sudo`)        | utun                | `/etc/resolver/<zone>`         |
| Windows | Administrator        | Wintun (wintun.dll) | NRPT rule → `127.0.0.1:53`     |

On a clean exit — Ctrl-C, the console closing, or sign-out/shutdown — the tunnel
removes its device, route, and DNS override. If it is killed hard, revert
whatever it left behind with:

```console
$ boatramp tunnel --cleanup   # same privilege as the run; safe with no marker
```

### Windows

1. Use the Windows release archive (`boatramp-x86_64-pc-windows-msvc.zip`). It
   ships `wintun.dll` next to `boatramp.exe` — the TUN front-end loads it at run
   time from the executable's own directory, so **keep the two files together**.
   `wintun.dll` is the official WireGuard-signed build, redistributed unmodified;
   `boatramp.exe` itself is not yet code-signed. (See `WINTUN.txt` in the
   archive.)
2. Open an **elevated** terminal — right-click Windows Terminal or PowerShell →
   *Run as administrator*. Creating the Wintun adapter, installing the route,
   and applying the NRPT split-DNS rule all require elevation; without it
   `boatramp tunnel --tun` fails up front with a privilege error rather than
   running degraded.
3. Run it:

   ```powershell
   PS> .\boatramp.exe tunnel --tun --cluster my-cluster
   ```

The NRPT rule scopes **only** your zone (`svc.<cluster>.<zone>`) to the tunnel's
embedded resolver on `127.0.0.1:53`; the rest of the system's DNS is untouched,
and the rule is removed on exit (or by `--cleanup`).

## Security

The tunnel is a privileged, host-mutating client. It:

- opens a virtual network device and installs a route for the configured CIDR;
- overrides host DNS **for the configured zone only**, reverting it on exit;
- binds its SOCKS/`CONNECT` front-ends to loopback and generates a local
  credential by default — because the proxy dials under your overlay identity, a
  non-loopback bind is refused unless you pass `--allow-non-loopback`, and the
  local credential can be disabled only with `--no-local-auth` (single-user
  hosts only), and caps concurrent accepted connections (SOCKS + `CONNECT`
  combined) via `--max-connections` to bound a local client opening connections
  faster than they are served.

Run it under the least privilege that works, and prefer the SOCKS front-end when
a single application — rather than the whole machine — needs overlay access.

**Hardening (v0.50.0).** The TUN netstack now drops an inbound IPv4 frame whose **source**
address is unspecified (`0.0.0.0`) at ingress, before it reaches `smoltcp`. A crafted fresh-SYN
with that source previously made the embedded netstack build a reply whose *destination* was
also `0.0.0.0`, tripping an internal `smoltcp` assertion and aborting the whole poll loop — a
remotely-reachable, single-packet DoS against every connection the tunnel was carrying. Found by
the `fuzz_netstack_ingress` fuzz target; fixed at boatramp's own ingress boundary (no client
action needed — update to v0.50.0 or later).
