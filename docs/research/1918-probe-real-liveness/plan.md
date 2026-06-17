# Plan of Action — #1918: tunnel keepalive `probeICMP` reports route-existence as liveness

- **Issue**: #1918 (bug) — `probeICMP` (`pkg/routing/tunnel.go`) never sends/receives an
  ICMP echo; both code paths return `true` on socket-open, so a dead GRE/IPIP peer behind a
  valid route is reported up forever and `LinkSetDown` never fires.
- **Revision**: r2 (SMR r2 PLAN-READY; N1 folded; pending Codex+AGY r2 re-review)
- **Status**: PLAN-READY candidate (pending r2 three-way re-review)
- **Branch**: `research/1918-probe-real-liveness`
- **Mode**: `/research` — STOP at PLAN-READY. No PR, no production code.

## Changelog r1 → r2

- **F1 (all three reviewers):** removed the contradictory `echo.ID == want.ID` predicate. The
  authoritative reply-match is now **Seq + Data-nonce only**; ID is ignored on datagram sockets
  (kernel rewrites it to the socket port) and advisory-only on raw. §5a/§7/R3 made consistent.
- **AGY #2 (decisive architectural correction):** the keepalive probes the tunnel's **outer
  underlay `Destination`**, which routes in the **global/underlay** table — NOT the tunnel's
  overlay VRF. r1's §5b "bind the probe socket to `vrf-<instance>`" was backwards and is
  **removed**. Default: no `SO_BINDTODEVICE`; the probe routes exactly like the encapsulated
  tunnel traffic does (global FIB). See new §5b.
- **AGY #3 + Codex F2 (privilege catch-22 / no Control hook):** dissolved for the common case
  by dropping overlay-VRF binding. The rare "underlay itself lives in a VRF" case is documented
  as out-of-scope (follow-up), so no custom pre-bind socket constructor is needed now.
- **Codex F3 (VRF in runner identity):** mostly moot now that VRF is not a probe input. The
  runner identity (`matches()`, `tunnel.go:78-86`) is unchanged; §5b documents why VRF need not
  enter it.
- **Codex F4 + AGY #5 (Axis D over-claim):** Axis D rewritten. Added explicit handling for
  `LinkByName` failure (do NOT latch `Up=false` on a netlink lookup error — retry next tick) and
  a same-name link-replacement TOCTOU guard (ifindex/generation check). The "exactly one
  LinkSet*" claim is now scoped to "per *successful* transition" with the invariant stated.
- **C1 rename + transient/structural split (Codex F5 + AGY #4):** renamed C1 to
  **hold-on-unknown**. Split `ProbeUnsupported` into **structural** (no `ping_group_range` / no
  cap — a config problem, hold) vs **transient** (EMFILE/ENOBUFS/FD exhaustion — a local
  resource problem). Transient unsupported is bounded: after a sustained-unknown window it
  escalates to a loud status + does NOT silently hold up forever. `KeepaliveUp==nil` contract
  clarified: nil now means "configured but liveness unknown" as well as "not configured";
  status string disambiguates.
- **Nits (Codex F6):** fixed dangling "§6 Option F" → "Axis C"; `pkg/rpm` function is
  `probeDialer` (rpm.go:21) not `vrfDialer`.

---

## 1. Problem Statement

`probeICMP(addr string) bool` (worktree HEAD `pkg/routing/tunnel.go:1025-1051`) is documented as
"sends a single ICMP echo request and returns true if the host responds." It does neither:

- **Primary path**: `net.DialTimeout("ip4:icmp"|"ip6:ipv6-icmp", addr, 3s)` opens a raw ICMP
  socket and returns `true` the instant the socket opens. No `WriteTo`, no `ReadFrom`. A dead
  peer behind a valid route reads up.
- **Fallback path** (no `CAP_NET_RAW`): `net.DialTimeout("udp", addr:1, 3s)` — a connectionless
  UDP "dial" never touches the wire; it returns `true` whenever a route to `addr` exists.

Net effect: the keepalive is a **route-existence check, not a liveness check.**

Consumer `keepaliveLoop` (`tunnel.go:980-1021`) treats this boolean as ground truth:
on `ok==true` it resets `Failures` and on a down→up edge calls `LinkSetUp`; on `ok==false` it
increments `Failures` and at `Failures >= MaxRetries` (default 3) flips `Up=false` +
`LinkSetDown`. Because `ok` is structurally always true when the route exists, the fail-safe
`LinkSetDown` is unreachable for the common "route up, peer dead" failure. Traffic black-holes;
status (`KeepaliveUp`/`KeepaliveInfo`, `GetStatus` ~`tunnel.go:1116`) reports up forever.

**Secondary defect (real, in scope):** `keepaliveLoop` holds `state.mu` (`tunnel.go:991`
`Lock` → `:1019` `Unlock`) **across** the netlink side effects `LinkByName` + `LinkSetUp`
(`:1001`) / `LinkSetDown` (`:1015`). A slow/blocked netlink op therefore blocks `GetStatus`'s
`ks.mu.Lock()`, turning a status read into a netlink-latency hazard.

## 2. Root Cause

An unfinished probe stub: the socket is opened but the echo round-trip was left as a TODO. The
fallback compounds the error by treating a connectionless UDP dial — zero network I/O — as
reachability. The `bool` return also erases "confirmed dead" vs "could not probe", so the loop
defaults to up.

## 3. In-Repo Precedent (design anchor)

`pkg/cluster/monitor.go:341-422` (`Monitor.probeICMP`) is a correct, tested ICMP prober:
- Unprivileged **datagram ICMP**: `udp4`/`udp6` via `icmp.ListenPacket` from `golang.org/x/net/icmp`
  (`go.mod:14` `golang.org/x/net v0.47.0`). No `CAP_NET_RAW` when `net.ipv4.ping_group_range`
  admits the daemon gid; not root.
- Real `icmp.Message{Echo}` → `WriteTo` → **800 ms read deadline** → `ReadFrom` →
  `icmp.ParseMessage` → `parsed.Type == replyType`.
- Injected `icmpConn` interface + `icmpDialer` field for deterministic tests
  (`monitor.go:81-87`).

This is the pattern to follow — with the two precedent gaps fixed (§5).

## 4. Goal / Success Criteria

1. The keepalive sends a real ICMP echo and reports the peer **alive** only on a reply that
   matches *this* probe within a bounded deadline.
2. When ICMP cannot be performed, the prober returns a distinct **Unsupported** result; the loop
   applies hold-on-unknown (§6 Axis C, C1) and surfaces it as `KeepaliveInfo = "unknown (ICMP
   probe unavailable)"` with `KeepaliveUp = nil`, never `up`.
3. A dead peer behind a valid route transitions to down after `MaxRetries` consecutive
   real-Dead probes, firing **exactly one** `LinkSetDown` per successful transition.
4. The up/down decision is computed under `state.mu`; the lock is released **before** any netlink
   call. `GetStatus` never blocks behind a netlink op.
5. Reply matching binds the reply to *this* probe via **Seq + a per-probe nonce in `Echo.Data`**
   (NOT ID — datagram sockets rewrite ID to the socket port).
6. A `LinkByName` lookup error during a transition does NOT latch `Up` to the new value — it is
   retried next tick (no spurious permanent down/up from a transient netlink hiccup).
7. Deterministic unit tests via an injected prober cover alive / dead→down + exactly-one
   LinkSetDown / recovery→up + exactly-one LinkSetUp / unsupported→not-up / Seq+nonce mismatch →
   not-alive / status-read-does-not-block-behind-slow-netlink / LinkByName-error→no-latch.

## 5. Gaps in the precedent THIS fix must NOT inherit

- **(5a) Reply matching — Seq + Data-nonce, NOT ID.** Linux `IPPROTO_ICMP` datagram ("ping")
  sockets overwrite the outbound echo `id` with the socket's source port (`ping_v4_sendmsg`
  sets `id = inet->inet_sport`; IPv6 likewise); `x/net/icmp`'s `ParseMessage`/`parseEcho`
  returns the bytes as received, i.e. the kernel-substituted port-id, not any
  application-chosen id (verified against `x/net@v0.47.0/icmp/echo.go:39-50`). Therefore the
  prober MUST set a unique monotonic **Seq** per probe AND carry a random per-probe **nonce in
  `Echo.Data`**, and require BOTH to match on the reply. ID is ignored on datagram sockets
  (advisory-only on the raw fallback). The `ReadFrom` loop discards non-matching datagrams until
  the absolute deadline. (`monitor.go` matches only `Type` — the defect this fix avoids; a
  separate follow-up applies 5a to monitor.go.)
- **(5b) Probe target is the UNDERLAY endpoint; route it in the underlay/global table — do NOT
  bind to the overlay VRF.** The keepalive pings the tunnel's outer `Destination` (the remote
  underlay endpoint), which the kernel resolves in the underlay routing domain (default/global
  table) — exactly where the tunnel's own encapsulated packets are resolved. Binding the probe
  socket to the tunnel's *overlay* VRF (`vrf-<instance>`, the routing-instance for inner traffic)
  would look up the underlay peer in a table that does not contain it → false Dead/Unsupported.
  **Default design: no `SO_BINDTODEVICE`; the probe socket uses the global table, matching tunnel
  encap.** This also dissolves the unprivileged-`SO_BINDTODEVICE` catch-22 (datagram ping sockets
  bind on `ListenPacket`; an unprivileged post-bind `SO_BINDTODEVICE` would `EPERM`). The rare
  case where the *underlay* itself lives in a management/underlay VRF is **out of scope** here
  (documented follow-up); it would need a custom pre-bind socket constructor analogous to
  `pkg/rpm`'s `probeDialer` (`rpm.go:21`, which sets `SO_BINDTODEVICE` in `Dialer.Control` —
  correct for RPM because RPM probes *inside* a routing instance, unlike a tunnel underlay probe).

## 6. Design — Multiple Path Options

### Axis A — Probe mechanism

- **A1 — datagram ICMP (`udp4`/`udp6`) via `x/net/icmp` [RECOMMENDED].** Mirrors `monitor.go`.
  No `CAP_NET_RAW` when `ping_group_range` admits the gid. Lowest overhead, no fork.
- **A2 — raw ICMP (`ip4:icmp`) auto-fallback if datagram open fails AND `CAP_NET_RAW` held.**
  Some deploys grant `CAP_NET_RAW` (LLDP/VRRP, `pkg/lldp/README.md`). On raw sockets a
  self-chosen ID *is* preserved, so the raw path may also match on ID; keep the match predicate
  Seq+nonce for uniformity.
- **A3 — exec `ping`.** Rejected as primary (fork-per-tick at N tunnels, output parsing,
  busybox/iputils divergence). Not implemented.

### Axis B — Result type

- **B1 — typed enum [RECOMMENDED].** `ProbeAlive | ProbeDead | ProbeUnsupported`. Carries the
  "could not probe" signal the bool destroys. (Optionally split `ProbeUnsupported` into
  `Structural` vs `Transient` — see Axis C — via a sub-field or two enum members.)
- **B2 — `(alive bool, err error)`.** Acceptable fallback; less legible than B1.

### Axis C — Policy for `ProbeUnsupported`

- **C1 — hold-on-unknown [RECOMMENDED] (renamed from r1's "fail-safe").** On
  *structural* Unsupported (`ping_group_range` unset / missing cap — a configuration problem):
  do NOT increment `Failures`, do NOT `LinkSetDown`/`LinkSetUp`; hold the prior `Up` value, set
  `KeepaliveUp = nil` and `KeepaliveInfo = "unknown (ICMP probe unavailable)"`; emit a deduped
  one-shot `slog.Warn` so the operator fixes the sysctl/caps. Rationale: tearing the link down
  because the daemon lacks probe privilege is a self-inflicted outage worse than the status quo.
  - **Transient Unsupported escalation (addresses AGY #4):** if Unsupported is caused by a
    *transient local resource* error (EMFILE/ENOBUFS/ENFILE on `ListenPacket`), treat it as
    "unknown" for status but bound the hold: after a sustained-unknown window (e.g.
    `MaxRetries × interval`) escalate to a louder status (`KeepaliveInfo = "unknown (probe
    socket error: <errno>)"`) and a `slog.Error`. Do NOT silently hold "up" forever on a
    resource error that may be masking a real peer death. We still do not `LinkSetDown` purely
    on inability-to-probe (that would amplify a local FD leak into a network outage), but the
    operator is now alarmed. (Distinguishing structural vs transient is by errno classification
    at `ListenPacket` time.)
  - **Startup posture (SMR r2 N1):** `startKeepalive` initializes `state.Up = true`
    (`tunnel.go:955`). On a daemon restart under structural-Unsupported (no `ping_group_range`),
    every keepalive therefore starts at `Up=true` and C1 holds it there — the kernel link
    retains its apply-time admin state (up), and status reads `"unknown (ICMP probe
    unavailable)"`, NOT `"up"`. This is intentional: it matches the pre-fix availability posture
    while telling the truth in status. /engineer must NOT "fix" this into start-down-when-
    unprobeable, which would black-hole every tunnel on a privilege-less boot.
- **C2 — fail-closed (Unsupported ⇒ Dead, counts toward MaxRetries).** Rejected as default:
  a missing `ping_group_range` on a deploy takes every keepalive tunnel down. Strictly worse
  for availability than today.
- **C3 — operator-selectable `set ... keepalive on-probe-unavailable (hold|down)`.** Deferred
  follow-up; default behavior is C1.

### Axis D (mandatory) — transition-under-lock, netlink-outside-lock, with error + TOCTOU guards

Rewrite the `keepaliveLoop` tick body:

1. Under `state.mu`: classify the probe result, update `Failures`/`LastSuccess`/`LastFailure`,
   and decide the transition. The transition is recorded as an intent
   (`wantUp bool` + `changed bool`) and `state.Up` is flipped to the new value **in the same
   locked section** so a later tick observing the new `Up` will not re-fire. Preserve the
   existing edge guards (`if !state.Up` for recovery, `if state.Up && Failures>=MaxRetries`
   for down). Snapshot the fields status needs.
2. `Unlock`.
3. If `changed`: `LinkByName(tunnelName)`; **if the lookup errors, do NOT keep the flipped `Up`
   committed** — re-acquire `mu`, revert `state.Up` to its pre-decision value (so the transition
   is retried next tick), and skip the netlink call. (Fixes Codex F4: a transient `LinkByName`
   failure must not permanently strand the in-memory state out of sync with the link.)
4. **Same-name TOCTOU guard (Codex F4 / #1884 recreate race):** the link may have been deleted
   and recreated under the same name by a concurrent `Apply` while this stale runner ran.
   Capture the link's `ifindex` (or a per-runner generation token set at `startKeepalive`) and
   only apply `LinkSetUp/Down` if it still matches; otherwise drop the action (the new runner
   owns the new link). The existing #848 drain already bounds this, but the ifindex check makes
   it explicit and cheap.
5. Perform the single `LinkSetUp`/`LinkSetDown` outside the lock.

Invariant (now provable): *for each runner, the (decision + `Up` write) is a single locked
section; netlink runs after unlock keyed to `changed`; on `LinkByName` error the `Up` write is
reverted so no transition is lost; the ifindex guard prevents acting on a replaced link.* Hence
at most one **successful** `LinkSet*` per real transition, and no permanent desync from a
transient netlink error. (AGY #5 confirmed there is no concurrent writer to `state.Up` other
than this goroutine, so step 1's in-lock flip is race-free; `Apply` only *reads* `state.Up`
under the lock. Redundant `LinkSetUp` on an already-up link is a kernel no-op, a benign backstop.)

### Axis E — package split

Rejected for this fix (churn, harder bisect). Keep in `tunnel.go` or a sibling
`tunnel_keepalive.go` **in the same `routing` package** (pure file split, no new package). File
a separate Refactor issue if the `pkg/routing/tunnel/keepalive/` split is still wanted.

## 7. Recommended Combination

**A1 + (auto A2 if CAP_NET_RAW) + B1 + C1(with transient-escalation) + D + 5a + 5b**, in-package.

1. New typed prober with injected transport in `pkg/routing`:
   ```
   type ProbeResult int
   const ( ProbeAlive ProbeResult = iota; ProbeDead; ProbeUnsupported )
   // (optionally carry an UnsupportedKind: Structural | Transient)

   type tunnelProber interface {
       Probe(addr string, seq int, nonce []byte, deadline time.Duration) (ProbeResult, error)
   }
   ```
   Production impl: `icmp.ListenPacket("udp4"/"udp6", ...)` (NO `SO_BINDTODEVICE`; global table —
   §5b), build `icmp.Echo{Seq, Data: nonce}`, `WriteTo` the underlay `Destination`, set the
   absolute deadline, `ReadFrom`-loop discarding datagrams until one has matching `Seq` AND
   `Data==nonce` → Alive; deadline with no match → Dead; `ListenPacket`/socket error →
   Unsupported (classify errno structural vs transient). A test prober is injected on
   `tunnelManager`.
2. `keepaliveLoop` calls `prober.Probe(...)` and runs the Axis-D tick.
3. Per-prober/runner monotonic `Seq` (atomic) + fresh random nonce per probe.
4. `GetStatus` keepalive rendering gains the unknown arm; `KeepaliveUp` stays `*bool`, left
   `nil` for unknown.

`startKeepalive` / `matches()` are **unchanged** (VRF is not a probe input — §5b), so Codex F3
does not require a runner-identity change.

## 8. Blast Radius / Files

- `pkg/routing/tunnel.go` — replace `probeICMP`; restructure `keepaliveLoop` tick per Axis D;
  add prober field + injection; status unknown arm. (Optional same-package
  `tunnel_keepalive.go` split.)
- `pkg/routing/routing.go` — `GetKeepaliveState` passthrough unchanged.
- `pkg/routing/routing_test.go:896,901` — currently call `probeICMP("127.0.0.1")` /
  `probeICMP("not-an-ip")` expecting the old bool; these **encode the bug** and MUST be rewritten
  against the injected prober. New tests per §4.7.
- `pkg/cli/cli_show_interfaces.go:54`, `pkg/grpcapi/server_show_security_text.go:115` — consume
  `KeepaliveInfo`; verify the "unknown" string renders sensibly (no signature change).
- Docs: tunnel/keepalive module doc updated — real-liveness semantics, `ping_group_range`
  requirement, underlay-table probe (not overlay VRF), Unsupported behavior.
- **Follow-ups (separate issues, NOT here):** apply 5a (Seq/nonce match) to `pkg/cluster/monitor.go`;
  C3 config knob; underlay-in-a-VRF binding case; `pkg/routing/tunnel/keepalive/` package split.

## 9. Test Plan

Unit (deterministic, injected prober — no real network):
- `Alive` every tick → `Up` stays true, zero `LinkSet*`.
- `Dead` ×`MaxRetries` → exactly one `LinkSetDown`, `Up=false`, `Failures==MaxRetries`.
- `Dead`×N then `Alive` → exactly one `LinkSetUp` on recovery, `Failures` reset.
- `Unsupported(structural)` → never `LinkSet*`, `KeepaliveUp==nil`, info contains "unknown",
  `Failures` unchanged.
- `Unsupported(transient)` sustained ≥ window → escalated status string + still no `LinkSetDown`.
- Seq/nonce match: reply with wrong Seq or wrong nonce → not Alive; correct → Alive.
- `LinkByName` error on a transition tick → `Up` not latched, retried next tick, eventual
  exactly-one `LinkSet*` when lookup succeeds.
- Lock-scope regression: a `LinkSetDown` parked in a blocking fake `ops` must NOT block a
  concurrent `GetStatus` (assert `GetStatus` returns within a short timeout while down is parked).
- Same-name TOCTOU: runner sees an ifindex change → drops its `LinkSet*`.

Integration / manual (at `/engineer`; tunnel test path, NOT smoke-cluster-blocking):
- GRE tunnel to a live peer → keepalive up. Kill the peer (firewall echo / down far end) while
  the route stays → after `MaxRetries×interval` the tunnel goes admin-down (one `LinkSetDown`),
  status "down (N consecutive failures)". Restore → recovers, one `LinkSetUp`.
- Non-root daemon with `ping_group_range` unset → status "unknown (ICMP probe unavailable)",
  tunnel NOT torn down (C1 structural).

## 10. Risks & Mitigations

- **R1 — `ping_group_range` not set in test/prod.** Datagram ICMP fails → structural Unsupported
  → C1 holds links up, status "unknown". Mitigation: document the sysctl in the module doc +
  systemd notes; A2 covers `CAP_NET_RAW` deploys; verify the test VM's
  `net.ipv4.ping_group_range` during /engineer.
- **R2 — underlay-in-a-VRF.** If the tunnel's *underlay* is itself in a VRF, the unbound global
  probe takes the wrong table → false Unsupported/Dead. Out-of-scope (follow-up, §5b); the
  common deployment has the underlay in the global table where the tunnel encap resolves.
- **R3 — datagram-ICMP ID rewrite (the F1 root).** Resolved: match on Seq + Data-nonce only; ID
  ignored on datagram. Confirm round-trip on loopback during /engineer before locking the
  predicate; keep the nonce small (~8 bytes) so responders echo it faithfully.
- **R4 — read-loop starvation / deadline.** Set `SetReadDeadline(now+T)` once; re-check the
  absolute deadline each `ReadFrom` iteration so a datagram flood can't extend a probe past its
  budget. Bound total probe time below the interval.
- **R5 — interval vs deadline coupling.** Keep the deadline a fraction of interval
  (`min(800ms, interval/2)`); document the floor.
- **R6 — transient FD exhaustion masking real death (AGY #4).** Mitigated by C1's
  transient-escalation: bounded-window loud status + `slog.Error`, never a silent forever-hold.

## 11. Rollback / Out-of-Scope

- Rollback: pure Go change in `pkg/routing`; revert the commit. No persisted state, no wire
  protocol, no config grammar change (C3 deferred).
- Out of scope: package split (E); `monitor.go` 5a fix; `on-probe-unavailable` knob (C3);
  underlay-in-a-VRF binding (R2); #1912 cold-ENCAP blackhole and #1914 endpoint-ID collision
  (distinct per the issue).
