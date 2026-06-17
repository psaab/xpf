# Plan of Action — #1918: tunnel keepalive `probeICMP` reports route-existence as liveness

- **Issue**: #1918 (bug) — `probeICMP` (`pkg/routing/tunnel.go`) never sends/receives an
  ICMP echo; both code paths return `true` on socket-open, so a dead GRE/IPIP peer behind a
  valid route is reported up forever and `LinkSetDown` never fires.
- **Revision**: r3 (converged)
- **Status**: PLAN-READY (pending 3-way convergence)
- **Branch**: `research/1918-probe-real-liveness`
- **Mode**: `/research` — STOP at PLAN-READY. No PR, no production code.

---

## 1. Problem Statement

`probeICMP(addr string) bool` (worktree HEAD `pkg/routing/tunnel.go:1025-1051`) is documented as
"sends a single ICMP echo request and returns true if the host responds." It does neither:

- **Primary path**: `net.DialTimeout("ip4:icmp"|"ip6:ipv6-icmp", addr, 3s)` opens a raw ICMP
  socket and returns `true` the instant the socket opens. No `WriteTo`, no `ReadFrom`. A dead
  peer behind a valid route reads up.
- **Fallback path** (no `CAP_NET_RAW`): `net.DialTimeout("udp", addr:1, 3s)` — a connectionless
  UDP "dial" never touches the wire; it returns `true` whenever a route to `addr` exists. The
  inline comment concedes "only means the route exists… close enough."

Net effect: the keepalive is a **route-existence check, not a liveness check.**

The consumer `keepaliveLoop` (`tunnel.go:980-1021`) treats this boolean as ground truth:
- On `ok==true`: resets `Failures`, and on a prior-down→up edge calls `LinkSetUp`.
- On `ok==false`: increments `Failures`; at `Failures >= MaxRetries` (default 3) flips `Up=false`
  and calls `LinkSetDown`.

Because `ok` is structurally always `true` whenever the route exists, the fail-safe
`LinkSetDown` is unreachable for the common "route up, peer dead" failure. Traffic keeps flowing
to a black hole; no operator/HA reaction is triggered. Status (`KeepaliveUp`/`KeepaliveInfo`,
`tunnel.go:1116+ GetStatus`) reports `up` forever.

**Secondary defect (real, in scope):** `keepaliveLoop` holds `state.mu` (`tunnel.go:991`
`Lock` → `:1019` `Unlock`) **across** the netlink side effects `LinkByName` + `LinkSetUp`
(`:1001`) / `LinkSetDown` (`:1015`). A slow/blocked netlink op therefore blocks `GetStatus`'s
`ks.mu.Lock()` (`GetStatus` reads each `KeepaliveState` under `mu`), turning a status read into
a netlink-latency hazard. This grows as more readers/policy hooks touch keepalive state.

## 2. Root Cause

The original author wrote a reachability *probe stub* and never finished it: the socket is
opened but the echo round-trip was left as a TODO ("ping utility would be better but adds exec
overhead"). The fallback compounds the error by treating a connectionless UDP dial — which does
zero network I/O — as a reachability signal. The boolean return type also erases the
distinction between "confirmed dead" and "could not probe (no privilege)", so the loop has no
way to choose a safe default for the un-probeable case; it defaults to up.

## 3. In-Repo Precedent (the design anchor)

A **correct, tested** ICMP liveness prober already exists at `pkg/cluster/monitor.go:341-422`
(`Monitor.probeICMP`). It:

- Uses **unprivileged datagram ICMP** sockets: `udp4` / `udp6` via `icmp.ListenPacket` from
  `golang.org/x/net/icmp` (already a direct dep, `go.mod:14` `golang.org/x/net v0.47.0`). This
  needs **no `CAP_NET_RAW`** when the kernel `net.ipv4.ping_group_range` admits the daemon's
  gid (Linux datagram-ICMP "ping sockets"); it does NOT require root.
- Builds a real `icmp.Message{Type: Echo, Body: &icmp.Echo{ID, Seq, Data}}`, `WriteTo` the
  destination, sets an **800 ms read deadline**, `ReadFrom`, `icmp.ParseMessage`, and validates
  `parsed.Type == replyType`.
- Injects an `icmpConn` interface + `icmpDialer func(network) (icmpConn, error)` field for
  deterministic tests (`monitor.go:81-87`).

**This is the pattern to follow.** The tunnel fix is essentially "port the monitor prober into
the tunnel domain, fix the two gaps the monitor prober itself has (see §5), and add a typed
result + safe default for the un-probeable case."

## 4. Goal / Success Criteria

1. The tunnel keepalive sends a real ICMP echo and only reports the peer **alive** on a
   matching echo reply within a bounded deadline.
2. When ICMP cannot be performed (no `ping_group_range`, no `CAP_NET_RAW`, socket error), the
   prober returns a distinct **Unsupported** result; the loop applies an explicit, configurable
   policy (default: fail-safe — see §6 Option F) and surfaces it distinctly in status
   (`KeepaliveInfo = "unknown (ICMP probe unavailable)"`), never `up`.
3. A dead peer behind a valid route transitions the tunnel to down after `MaxRetries`
   consecutive failures, firing **exactly one** `LinkSetDown`.
4. The up/down transition is computed under `state.mu`; the lock is released **before** any
   netlink call. `GetStatus` never blocks behind a netlink op.
5. Reply matching binds the reply to *this* probe (ID + Seq), so concurrent tunnel probers on a
   shared socket / stray replies cannot satisfy the wrong probe.
6. Deterministic unit tests via an injected prober cover: alive, dead→down-after-N + exactly
   one `LinkSetDown`, recovery→up + exactly one `LinkSetUp`, Unsupported→not-up, and
   status-read-does-not-block-behind-slow-netlink.

## 5. Gaps in the precedent that THIS fix must NOT inherit

The monitor prober is the right shape but has two latent defects a hostile reviewer will (and
did) flag — the tunnel prober must fix them, and a follow-up should fix the monitor:

- **(5a) No reply ID/Seq match.** `monitor.go` accepts any `EchoReply` of the right type. On a
  shared datagram-ICMP socket the kernel demuxes by the kernel-assigned port→ID, but two probes
  on the *same* `icmpConn` (or a delayed reply to a prior probe) can cross-satisfy. The tunnel
  prober MUST set a unique `Seq` per probe and a stable per-prober `ID`, and require
  `echo.ID == want.ID && echo.Seq == want.Seq` on the reply, looping `ReadFrom` until deadline
  to discard non-matching datagrams. (Datagram-ICMP rewrites the on-wire ID to the socket port;
  on read, `x/net/icmp` returns the *kernel-substituted* ID. Plan must verify this empirically
  during /engineer and match on the value the kernel actually returns — see §10 Risk R3.)
- **(5b) No VRF binding.** Tunnels can be bound to a routing-instance VRF (`tunnel.go:106`
  `vrfBinder`, `:126` `appliedRI`). An unbound probe socket routes via the default FIB, which
  may reach (or fail to reach) the peer by a path unrelated to the tunnel's VRF — producing a
  false up/down. The prober must be able to bind the probe socket to the tunnel's VRF device
  (`SO_BINDTODEVICE` to `vrf-<instance>`), analogous to `pkg/rpm`'s `vrfDialer`. The keepalive
  must therefore be told the tunnel's `appliedRI` (thread it through `startKeepalive`).

## 6. Design — Multiple Path Options

The design branches on three independent axes. The plan recommends one combination (§7) but
records all so the user can choose at `/engineer` time.

### Axis A — Probe mechanism

- **Option A1 — datagram ICMP (`udp4`/`udp6`) via `x/net/icmp` [RECOMMENDED].** Mirrors
  `pkg/cluster/monitor.go`. No `CAP_NET_RAW` when `ping_group_range` admits the gid. Lowest
  overhead, no fork. Already proven in-tree.
- **Option A2 — raw ICMP (`ip4:icmp`) via `x/net/icmp`.** Works only with `CAP_NET_RAW`.
  Strictly worse than A1 for privilege; keep only as an *automatic* second attempt if datagram
  open fails AND the daemon happens to hold `CAP_NET_RAW` (some deploys grant it for LLDP/VRRP,
  see `pkg/lldp/README.md`).
- **Option A3 — exec `ping`.** Fork per probe; VRF handled by `ip vrf exec` (the existing
  `pkg/cli/cli_request.go:49` pattern). Rejected as the *primary* mechanism: fork overhead per
  tunnel per interval, brittle output parsing, busybox/iputils ping divergence. Keep documented
  as a last-resort manual escape hatch only; do NOT implement now.

### Axis B — Result type

- **Option B1 — typed enum [RECOMMENDED].** `type ProbeResult int` with
  `ProbeAlive | ProbeDead | ProbeUnsupported`. The loop switches on it. Cleanly carries the
  "could not probe" signal that the bool destroys.
- **Option B2 — `(alive bool, err error)`.** `err != nil` means unsupported/transport failure.
  Workable but conflates "dead" (no reply, `err==nil`, `alive=false`) with "unsupported"
  (`err!=nil`) less legibly than B1. Slightly less ceremony. Acceptable fallback.

### Axis C — Policy for `ProbeUnsupported`

- **Option C1 — fail-safe-on-unknown but DO NOT count as failure / DO NOT flap
  [RECOMMENDED].** On `ProbeUnsupported`: do **not** increment `Failures`, do **not** call
  `LinkSetDown`, do **not** call `LinkSetUp`; hold the prior `Up` value but set
  `KeepaliveInfo = "unknown (ICMP probe unavailable)"` and `KeepaliveUp = nil` (the original
  "no signal" sentinel) so status never lies "up". Rationale: an unprobeable host is a
  *configuration/privilege* problem, not a peer-death signal — repeatedly tearing the link down
  because we lack privilege would be a self-inflicted outage. Surface it loudly in status +
  one-shot `slog.Warn` (deduped) so the operator fixes `ping_group_range`/caps.
- **Option C2 — fail-closed (treat Unsupported as Dead).** Counts toward `MaxRetries` → tunnel
  goes down. Rejected: turns a missing capability into a guaranteed tunnel outage on every
  deploy that didn't set `ping_group_range`; far worse than the status quo for availability.
- **Option C3 — operator-selectable.** Add `set ... keepalive on-probe-unavailable
  (hold|down)` config knob. Defer — out of scope for the bug fix; file as follow-up if an
  operator actually wants fail-closed. Default behavior is C1.

### Axis D (lock fix, not optional) — transition-under-lock, netlink-outside-lock

Restructure `keepaliveLoop` tick body to: (1) take `state.mu`, compute the new `Up` value +
whether a `LinkSetUp`/`LinkSetDown`/none transition is needed + snapshot fields, (2) `Unlock`,
(3) perform the single netlink call outside the lock. This both fixes the secondary bug and
guarantees "exactly one LinkSet* per transition" (the decision is made once under the lock).

### Axis E — package split (issue's optional suggestion)

The audit floated a `pkg/routing/tunnel/keepalive/` package. **Rejected for this fix.** The
probe semantics + lock scope are the substance; a package move is churn that complicates review
and bisect. Keep everything in `tunnel.go` (or a sibling `tunnel_keepalive.go` in the same
package if `tunnel.go` size warrants — a pure file split, no new package). File a separate
Refactor issue if the split is still wanted.

## 7. Recommended Combination

**A1 + (auto A2 fallback if CAP_NET_RAW present) + B1 + C1 + D + 5a + 5b**, kept in-package.

Concretely:

1. New typed prober with injected transport, in `pkg/routing`:
   ```
   type ProbeResult int
   const ( ProbeAlive ProbeResult = iota; ProbeDead; ProbeUnsupported )

   type tunnelProber interface {
       Probe(addr string, vrf string, id int, seq int, deadline time.Duration) ProbeResult
   }
   ```
   Production impl uses `icmp.ListenPacket("udp4"/"udp6", ...)`, optional
   `SO_BINDTODEVICE(vrf-<instance>)`, `WriteTo`, deadline `ReadFrom`-loop matching ID+Seq,
   `ParseMessage`, returns Alive on matched reply, Dead on deadline-with-no-match, Unsupported
   on `ListenPacket`/socket error. A test prober is injected on `tunnelManager`.
2. `keepaliveLoop` calls `prober.Probe(...)`, switches on the result per C1, computes the
   transition under `state.mu`, releases, then does the single netlink call (D).
3. `startKeepalive` gains the tunnel's `appliedRI` (VRF) so the prober binds correctly; thread
   it from the apply site that already knows the routing-instance.
4. `GetStatus` keepalive rendering gains an `Unsupported`/`unknown` arm; `KeepaliveUp` stays
   `*bool` and is left `nil` for the unknown case.
5. Per-prober monotonic `Seq` (atomic) + stable `ID` (e.g. derived from tunnel name hash, low
   16 bits) so replies bind to the probe.

## 8. Blast Radius / Files

- `pkg/routing/tunnel.go` — replace `probeICMP`; restructure `keepaliveLoop` tick; extend
  `KeepaliveState`/`startKeepalive` with VRF; add prober field + injection. (Possibly split the
  keepalive bits into `pkg/routing/tunnel_keepalive.go`, same package.)
- `pkg/routing/routing.go` — `GetKeepaliveState` passthrough unchanged; verify apply site
  passes VRF into `startKeepalive`.
- `pkg/routing/tunnel_test.go` / `routing_test.go` — `routing_test.go:896,901` currently call
  `probeICMP("127.0.0.1")` / `probeICMP("not-an-ip")` expecting the old bool. These tests
  **encode the bug** (127.0.0.1 "responds" only because the socket opens). They MUST be
  rewritten against the injected prober. New tests per §4.6.
- `pkg/cli/cli_show_interfaces.go:54`, `pkg/grpcapi/server_show_security_text.go:115` — consume
  `KeepaliveInfo`; no signature change, but verify the "unknown" string renders sensibly.
- Docs: tunnel/keepalive module doc (find under `docs/`) updated to state real-liveness
  semantics + `ping_group_range` requirement + Unsupported behavior.
- **Follow-up (separate issue, do NOT fix here):** apply 5a (ID/Seq match) to
  `pkg/cluster/monitor.go:341`.

## 9. Test Plan

Unit (deterministic, injected prober — no real network):
- `Alive` every tick → `Up` stays true, zero `LinkSet*`.
- `Dead` for `MaxRetries` ticks → exactly one `LinkSetDown`, `Up=false`, `Failures==MaxRetries`.
- `Dead`×N then `Alive` → exactly one `LinkSetUp` on recovery, `Failures` reset.
- `Unsupported` → never `LinkSetDown`/`LinkSetUp`, `KeepaliveUp==nil`,
  `KeepaliveInfo` contains "unknown", `Failures` not incremented (C1).
- ID/Seq match: prober fed a reply with wrong ID/Seq → treated as no-match (Dead path), correct
  reply → Alive.
- Lock-scope: a netlink op blocked in `LinkSetDown` (fake `ops` that blocks) must NOT block a
  concurrent `GetStatus` (assert `GetStatus` returns within a short timeout while
  `LinkSetDown` is parked). This is the regression test for the secondary bug.

Integration / manual (at `/engineer`, on a tunnel test path — NOT smoke-cluster-blocking):
- Bring up a GRE tunnel to a live peer → keepalive up.
- Drop the peer (firewall the echo / down the far end) while the route stays → after
  `MaxRetries*interval` the tunnel goes admin-down (one `LinkSetDown`), status shows
  "down (N consecutive failures)".
- Restore peer → recovers, one `LinkSetUp`.
- Run as a non-root daemon with `ping_group_range` unset → status shows "unknown (ICMP probe
  unavailable)", tunnel NOT torn down (C1).

## 10. Risks & Mitigations

- **R1 — `ping_group_range` not set in test/prod env.** Datagram ICMP fails → everything
  Unsupported → C1 holds links up but status screams "unknown". Mitigation: document the sysctl
  in the module doc + systemd unit notes; the A2 auto-fallback covers `CAP_NET_RAW` deploys;
  C1 ensures no self-outage. Verify the test VM's `net.ipv4.ping_group_range` during /engineer.
- **R2 — VRF probe binding.** `SO_BINDTODEVICE` to `vrf-<instance>` requires the device to
  exist when the prober opens the socket. For a tunnel not in a VRF, no bind (default FIB).
  Mitigation: open the socket per-probe (cheap) so a late-created VRF is picked up; tolerate
  bind failure as Unsupported rather than crashing.
- **R3 — datagram-ICMP ID rewrite.** The kernel substitutes the on-wire ID with the socket's
  ephemeral port for `udp4`/`udp6` ping sockets; `x/net/icmp` returns that substituted ID on
  read. Matching on a *self-chosen* ID may therefore never match. Mitigation: match primarily
  on **Seq** (preserved end-to-end) and on Data payload echo (carry a per-probe nonce in
  `Echo.Data` and require it back); treat ID as advisory. Empirically confirm during /engineer
  with a loopback echo before locking the match predicate. (This is why §5a says "verify what
  the kernel actually returns".)
- **R4 — read-loop starvation / deadline.** If many stray datagrams arrive, the
  match-or-discard `ReadFrom` loop must respect the absolute deadline (set once,
  `SetReadDeadline(now+T)`, re-check each iteration) so a flood can't extend a probe past its
  budget. Bound total probe time to one interval minus margin.
- **R5 — interval vs deadline coupling.** A 1 s interval with an 800 ms deadline leaves little
  slack. Keep the deadline a fraction of interval (e.g. `min(800ms, interval/2)`) and document
  the floor.

## 11. Rollback / Out-of-Scope

- Rollback: pure Go change in `pkg/routing`; revert the commit. No persisted state, no wire
  protocol, no config grammar change (C1/C3 keeps the bug fix knob-free; C3 deferred).
- Out of scope: package split (E, separate Refactor issue); monitor.go 5a fix (separate
  follow-up issue); `on-probe-unavailable` config knob (C3, follow-up); IPv6-only nuances
  beyond mirroring the monitor's `udp6` path; #1912 cold-ENCAP blackhole and #1914 endpoint-ID
  collision (explicitly distinct per the issue).
