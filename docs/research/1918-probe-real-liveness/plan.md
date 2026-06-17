# Plan of Action — #1918: tunnel keepalive `probeICMP` reports route-existence as liveness

- **Issue**: #1918 (bug) — `probeICMP` (`pkg/routing/tunnel.go`) never sends/receives an
  ICMP echo; both code paths return `true` on socket-open, so a dead GRE/IPIP peer behind a
  valid route is reported up forever and `LinkSetDown` never fires.
- **Revision**: r6 (AGY r5 deadlock note folded — runner never takes `t.mu`, gen token is
  `atomic.Uint64`; AGY r5 PLAN-READY; SMR r5 PLAN-READY; pending Codex r5 confirmation on r5/r6)
- **Status**: PLAN-READY candidate (AGY r5 + SMR r5 READY; Codex r5 in flight)
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

## Changelog r2 → r3

- **AGY r2 #5 (source-address bind, MAJOR):** the probe socket must bind to the tunnel's local
  source IP (`TunnelConfig.Source`), not the wildcard the `monitor.go` precedent uses, so the
  echo egresses from the tunnel endpoint and the reply routes back correctly (new §5c). Threads
  `tc.Source` through `startKeepalive` → runner → prober; adds `source` to `keepaliveRunner` and
  `matches()` so a source change restarts the runner. Prober signature gains a `source` arg.
- **SMR r2 N1 (startup posture):** folded into §6 Axis C / §10 R1 (already in r2's late edit).

## Changelog r3 → r4

- **Codex r2 NF1 (HIGH, source bind):** independently converged with AGY r2 #5 — already folded
  as §5c in r3. (Two reviewers caught the same gap → high confidence.)
- **Codex r2 NF2 (MEDIUM, optimistic-flip window):** Axis D rewritten to **commit-after-success**
  — `Up` is mutated only after the netlink op succeeds, so a racing `Apply`/`GetStatus` never
  observes an uncommitted `Up`. The flip-then-revert design is gone (nothing to revert).
- **Codex r2 NF3 (HIGH, ifindex-reuse bypass):** the recreate guard is now a per-tunnel
  monotonic **generation token** captured at `startKeepalive` and bumped by `Apply` on
  create/recreate — NOT an action-time `LinkByName().Index`, which a stale runner would read as
  the new link and wrongly pass.
- **Codex r2 NF4 (MEDIUM, errno classification):** §6 Axis C now gives a complete structural vs
  transient errno table with **UNRECOGNIZED → TRANSIENT (escalate)** as the total default, so a
  resource storm cannot be silently held as structural.

## Changelog r4 → r5

- **Codex r4 F7 (HIGH, gen-guard TOCTOU):** the generation check (step 4, under `t.mu`) cannot
  protect a `LinkSet*` syscall (step 5, outside any lock) that a concurrent `Apply` recreate
  races — if the kernel reuses the ifindex, a stale runner downs the replacement. Verified real
  against the actual code: `Apply` recreates the link (`tunnel.go:461-482`) **before** it drains
  the old runner (`startKeepalive`'s `<-runner.done`, `tunnel.go:519`, reached only at
  `tunnel.go:542+`). r5 resolves it by an `Apply` **reordering**: cancel + drain the existing
  runner BEFORE the `LinkByName`/`LinkDel`/`LinkAdd` recreate, so no stale runner goroutine
  exists during the recreate. The drain is the real serializer (it already exists; it just runs
  too late). `linkGen` is kept as defense-in-depth. Codex's alternative ("hold `t.mu` across the
  `LinkSet*`") is rejected — it reintroduces the lock-across-netlink hazard #1918 exists to fix.

## Changelog r5 → r6

- **AGY r5 Finding #1 (deadlock note):** r5's gen-token step-4 said the runner "re-reads
  `t.linkGen[tunnelName]` under `t.mu`". If a tick blocks on `t.mu.Lock()` while `Apply` blocks
  on `<-runner.done` (the drain), they deadlock. r6 makes the gen token an **`atomic.Uint64`**
  the runner reads lock-free (`Load()`); the runner **never acquires `t.mu`**. AGY r5 was
  otherwise PLAN-READY; this is the one implementation constraint it surfaced.

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
- **(5c) Bind the probe socket to the tunnel's local SOURCE IP (AGY r2 #5).** The probe MUST
  egress from the tunnel's configured local endpoint, `TunnelConfig.Source`
  (`pkg/config/types_routing.go:296`, "local tunnel endpoint IP"). Bind it via the
  `ListenPacket` listen address: `icmp.ListenPacket("udp4", tc.Source)` (the library's own
  documented form, `x/net/icmp/listen_posix.go:32` `ListenPacket("udp4", "192.168.0.1")`), NOT
  the wildcard `0.0.0.0`/`::` the `monitor.go` precedent uses. Wildcard would let the kernel pick
  any local egress IP, which on a multi-homed / secondary-IP / policy-routed firewall can differ
  from the tunnel source — causing (1) ingress-filter drops at the peer/path when the echo does
  not originate from the expected endpoint, (2) the reply routing back to the wrong local IP and
  failing the probe, and (3) validating a path different from the one the encapsulated tunnel
  traffic actually uses. Binding to `tc.Source` makes the probe traverse the same source→dest
  path as the tunnel's outer encap. This requires threading `tc.Source` into `startKeepalive`
  (→ runner → prober). Because Source is now a probe input, a Source change must restart the
  runner: add `source` to `keepaliveRunner` and to `matches()` (`tunnel.go:78-86`) so an
  apply that changes only the tunnel source re-creates the keepalive. (Edge case: if `tc.Source`
  is empty/unset — auto-selected tunnels — fall back to wildcard bind and note it in status; a
  bind error on `tc.Source` is classified `ProbeUnsupported(structural)` per Axis C.)

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
    operator is now alarmed.
  - **Errno classification at `ListenPacket`/bind time (Codex r2 NF4 — must be complete and
    total).** STRUCTURAL (config/capability — one-shot Warn, hold indefinitely):
    `EPERM`, `EACCES` (no `ping_group_range`/cap), `EAFNOSUPPORT`, `EPROTONOSUPPORT`,
    `EPROTOTYPE`, `EADDRNOTAVAIL` (the bound `tc.Source` is not a local address — a config
    error). TRANSIENT (local resource — bounded-window escalation to `slog.Error`):
    `EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`, `EINTR`. **Default for any UNRECOGNIZED errno =
    TRANSIENT** (escalate), so a resource storm can never be silently mis-bucketed as a held
    structural — this closes NF4's `ENOMEM`-mis-as-structural counterexample by construction.
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

### Axis D (mandatory) — transition-under-lock, netlink-outside-lock, COMMIT-AFTER-SUCCESS

r3's "flip `Up` under lock, then revert on `LinkByName` error" exposed a window where a
concurrent `Apply` reads the optimistically-flipped `Up` (`tunnel.go:531-538` `skipUp`) and acts
on it before the revert lands (Codex r2 **NF2**). r4 uses a **commit-after-success** order
instead: the in-memory `Up` is mutated only once the netlink op has succeeded. Rewrite the
`keepaliveLoop` tick body:

1. Under `state.mu`: classify the probe result; update `Failures`/`LastSuccess`/`LastFailure`
   (pure counters, safe to commit now); compute the **transition intent** without yet writing
   `Up`: `wantUp := <recovery edge: !Up && alive>` or `wantDown := <Up && Failures>=MaxRetries>`.
   Snapshot the fields status needs and the runner's `gen` token (see step 4). `Unlock`.
   *`Up` is NOT changed yet* — so a racing `Apply`/`GetStatus` sees the still-current value, never
   an uncommitted one (fixes NF2).
2. If neither `wantUp` nor `wantDown`: done (no netlink, no `Up` write).
3. Else `LinkByName(tunnelName)`. On error: do nothing (no `Up` write, no netlink) — the
   transition is naturally retried next tick because `Up` was never changed. (This also fixes
   Codex F4 without the revert window: there is nothing to revert.)
4. **Defense-in-depth recreate guard via generation token — the runner MUST NOT take `t.mu`
   (Codex r2 NF3 + AGY r5 deadlock note).** With drain-before-recreate (the F7 fix below) the
   primary guarantee already holds; the gen token is belt-and-suspenders. It must be implemented
   so the runner tick **never acquires `t.mu`** — otherwise a tick blocked on `t.mu.Lock()` while
   `Apply` blocks on `<-runner.done` deadlocks (AGY r5 Finding #1). Implementation: the
   `tunnelManager`'s per-tunnel generation counter is an **`atomic.Uint64`** (e.g.
   `linkGen map[string]*atomic.Uint64`, the map structure mutated only under `t.mu` by `Apply`,
   but the counter `.Add(1)`/`.Load()` are atomic). `startKeepalive` captures the current
   `.Load()` value into the runner (by value, no shared map access at tick time — pass the
   `*atomic.Uint64` into the runner). Before the netlink op the runner does a lock-free
   `gen.Load()` and, if it differs from its captured value, **drops the action**. Note: an
   action-time `LinkByName().Attrs().Index` is NOT a safe substitute (a stale runner would read
   the *new* link's reused ifindex and pass). The gen `Load()` plus drain-before-recreate is the
   correct combination; the gen check alone is insufficient (that was F7), and `t.mu` in the
   runner is forbidden (AGY r5).
5. Perform the single `LinkSetUp`/`LinkSetDown` outside `state.mu`, **capturing its error**.
   `LinkSetUp`/`LinkSetDown` themselves return errors (`tunnel.go:24-25`) — those errors are
   handled here, not ignored (Codex r3 blocker).
6. **Commit ONLY on netlink success:** if the `LinkSet*` call returned nil, re-acquire `state.mu`,
   set `state.Up = wantUp_value`, `Unlock`. **If `LinkSet*` returned an error: log it and DO NOT
   write `Up`** — `Up` retains its pre-transition value, so the guard in step 1
   (`Up && Failures>=MaxRetries` for down, `!Up && alive` for recovery) still fires next tick and
   the transition is retried until the netlink op succeeds. This is the key difference from r3,
   which committed `Up` before the netlink op and only reverted on `LinkByName` failure — leaving
   a permanent desync when `LinkSetDown`/`LinkSetUp` itself errored (Codex r3 counterexample:
   dead peer → `Up=false` committed → `LinkSetDown` transient error → kernel stays up but later
   dead ticks see `Up==false` and never retry). In r4, `Up` is never written until the kernel op
   succeeds, so a `LinkSet*` error is just a retried transition, never a lost one. `Failures`
   for the down case is committed in step 1 (status shows climbing failures even while
   `LinkSetDown` keeps erroring — desired); `Failures` reset happens on the alive branch in step 1.

**F7 (Codex r4) — the gen guard alone is NOT race-free; the real serializer is draining the
stale runner BEFORE the recreate.** Codex r4's counterexample: the step-4 gen check is under
`t.mu`, but the step-5 `LinkSet*` syscall is outside any lock; a concurrent `Apply` can run its
`LinkDel`+`LinkAdd` recreate (`tunnel.go:461-482`) in the window between the stale runner's gen
check and its `LinkSet*` syscall, and if the kernel reuses the ifindex, the stale runner downs
the *replacement* link. This is real because today `Apply` recreates the link
(`tunnel.go:461-482`) **before** it drains the old runner — the drain happens inside
`startKeepalive` (`<-runner.done`, `tunnel.go:519`) which `Apply` only reaches at
`tunnel.go:542+`. So a stale runner can be mid-`LinkSet*` while `Apply` recreates the link.

The gen token cannot fix a syscall that is already in flight. The correct fix is a small
**`Apply` reordering** (in scope for /engineer): when a per-tunnel apply is going to recreate or
replace the link, **cancel + drain the existing keepalive runner FIRST** (move the
cancel/`<-done` ahead of the `LinkByName`/`LinkDel`/`LinkAdd` block, `tunnel.go:461`), so no
stale runner goroutine exists during the recreate. After the drain, the old runner is guaranteed
not to issue any further `LinkSet*` (its goroutine has returned). The new runner is started after
`finishTunnelLocked` as today. This makes "at most one runner can act on the link" true by
construction — the drain is the serializer, and it already exists; it just runs too late.

The `linkGen` token is retained as a **defense-in-depth** belt-and-suspenders for the identity-
unchanged retain path and any future code path that does not drain-before-recreate, but the
*primary* guarantee is drain-before-recreate. (Alternative considered and rejected: holding
`t.mu` across the keepalive `LinkSet*` — that reintroduces the exact lock-across-netlink hazard
this issue exists to fix, and Codex's "hold t.mu across check AND LinkSet*" suggestion is
therefore not acceptable. Drain-before-recreate achieves the same safety without any
lock-across-netlink.)

Invariant (now provable): *a runner only issues `LinkSet*` while it is the live runner for the
current link generation, because `Apply` drains the prior runner before recreating the link;
`Up` transitions only after the keying netlink op succeeds; no observer ever sees an uncommitted
`Up`; a `LinkByName`/netlink error leaves `Up` unchanged so the transition retries.* Hence at
most one **successful** `LinkSet*` per real transition, no NF2 optimistic-flip window, no NF3
ifindex-reuse bypass, and no F7 recreate-during-syscall window. (No concurrent writer to
`state.Up` other than this goroutine — `Apply`/`GetStatus` only read it under the lock — so the
two short locked sections in steps 1 and 6 cannot race a competing writer. Redundant `LinkSetUp`
on an already-up link is a kernel no-op, a benign backstop.)

> Note: `Failures` for the down case is committed in step 1 before the netlink op, so status can
> show climbing failures even if `LinkByName` is transiently failing — desired. The `Up` flip is
> the only state gated on netlink success.

### Axis E — package split

Rejected for this fix (churn, harder bisect). Keep in `tunnel.go` or a sibling
`tunnel_keepalive.go` **in the same `routing` package** (pure file split, no new package). File
a separate Refactor issue if the `pkg/routing/tunnel/keepalive/` split is still wanted.

## 7. Recommended Combination

**A1 + (auto A2 if CAP_NET_RAW) + B1 + C1(with transient-escalation) + D + 5a + 5b + 5c**,
in-package.

1. New typed prober with injected transport in `pkg/routing`:
   ```
   type ProbeResult int
   const ( ProbeAlive ProbeResult = iota; ProbeDead; ProbeUnsupported )
   // (optionally carry an UnsupportedKind: Structural | Transient)

   type tunnelProber interface {
       // source = tunnel local endpoint IP (TunnelConfig.Source) bound as the
       // listen address; "" → wildcard. dst = underlay Destination.
       Probe(source, dst string, seq int, nonce []byte, deadline time.Duration) (ProbeResult, error)
   }
   ```
   Production impl: `icmp.ListenPacket("udp4"/"udp6", source)` — bind to the tunnel local
   source IP (§5c), NO `SO_BINDTODEVICE`; global table (§5b) — build `icmp.Echo{Seq, Data: nonce}`,
   `WriteTo` the underlay `Destination`, set the
   absolute deadline, `ReadFrom`-loop discarding datagrams until one has matching `Seq` AND
   `Data==nonce` → Alive; deadline with no match → Dead; `ListenPacket`/socket error →
   Unsupported (classify errno structural vs transient). A test prober is injected on
   `tunnelManager`.
2. `keepaliveLoop` calls `prober.Probe(...)` and runs the Axis-D tick.
3. Per-prober/runner monotonic `Seq` (atomic) + fresh random nonce per probe.
4. `GetStatus` keepalive rendering gains the unknown arm; `KeepaliveUp` stays `*bool`, left
   `nil` for unknown.

VRF is NOT a probe input (§5b), so Codex F3's VRF-in-identity concern does not apply. However,
the tunnel **source** IS now a probe input (§5c): `startKeepalive` gains a `source` parameter
threaded from `tc.Source` at the call site (`tunnel.go:547`), `keepaliveRunner` gains a `source`
field, and `matches()` (`tunnel.go:78-86`) gains a `r.source == tc.Source` clause so a
source-only config change restarts the runner.

## 8. Blast Radius / Files

- `pkg/routing/tunnel.go` — replace `probeICMP`; restructure `keepaliveLoop` tick per Axis D
  (commit-after-success); add prober field + injection; add `source` to `keepaliveRunner` +
  `matches()` (§5c); add `linkGen map[string]*atomic.Uint64` to `tunnelManager` (map mutated under `t.mu`, counter Add/Load atomic; runner reads lock-free — never takes `t.mu`, AGY r5) bumped in `Apply` on
  link create/recreate and captured at `startKeepalive` (§6 Axis D step 4, defense-in-depth);
  **reorder `Apply` to cancel+drain the existing keepalive runner BEFORE the
  `LinkByName`/`LinkDel`/`LinkAdd` recreate block (`tunnel.go:461`)** so no stale runner issues
  `LinkSet*` during a recreate (§6 Axis D F7); thread `tc.Source` at the `startKeepalive` call
  site (`tunnel.go:547`); status unknown arm. (Optional same-package `tunnel_keepalive.go` split.)
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
- Same-name recreate (NF3): bump `linkGen[tunnel]` mid-flight → runner's gen mismatch → drops
  its `LinkSet*` (does not down/up the replacement link).
- Drain-before-recreate (F7): a fake `ops` that blocks inside `LinkSetDown` simulates a stale
  runner mid-syscall; assert `Apply`'s recreate path cancels+drains the runner before issuing
  `LinkDel`, so the recreate cannot interleave with the stale runner's `LinkSet*` (the drain
  blocks `Apply` until the parked `LinkSetDown` returns and the goroutine exits). Verifies the
  reordering, not just the gen token.
- `LinkSet*` error retry (Codex r3 blocker): fake `ops.LinkSetDown` returns an error on the
  transition tick → `state.Up` stays `true` → next dead tick retries; when `LinkSetDown` later
  succeeds, exactly one effective down transition. Symmetric for `LinkSetUp` on recovery.
- NF2 no-uncommitted-`Up`: a concurrent `GetStatus`/`Apply`-`skipUp` read interleaved between the
  probe classification and the netlink op must observe the pre-transition `Up` (never an
  optimistic value) — assert via a fake `ops` that signals when it is inside `LinkSetDown` and a
  concurrent `GetStatus` reads the old `Up`.
- Source bind (§5c): injected prober asserts it receives the tunnel's `tc.Source` as the bind
  arg; `matches()` returns false when only `tc.Source` changes (runner restarts); empty
  `tc.Source` → wildcard fallback, bind error on a set source → `ProbeUnsupported(structural)`.

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
