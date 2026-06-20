# #1993 — Compile-failure cold-boot FRR transit blackhole: research plan

**Status: DRAFT v1 (draft-fanout, pre-review)**

Branch: `research/1993-frr-coldboot-blackhole`
Plan doc: `docs/research/1993-frr-coldboot-blackhole/plan.md`
Issue: #1993 (follow-up from PR #1991 / #1960 fail-closed boot; raised by the
AGY adversarial review of #1991, focus area 3)

---

## 1. Issue framing

On a **cold reboot** with a PRESENT, previously-committed `active.json` that no
longer **compiles** (`ActiveConfig()==nil` + `EverCommitted()==true`, the #1960
fail-closed tuple), the daemon enters bootstrap mode and:

- does NOT arm the dataplane (`dp.Start` suppressed) and leaves `ip_forward` at
  its default — **no transit forwarding**, AND
- does NOT run the `enterBootstrapMode()` teardown (deliberately: that teardown
  is reserved for the Item-1b confirmed-commit rollback). It "freezes in
  last-known-good" so the box stays reachable at its existing mgmt address.

But `frr` is an **independent systemd service**. It starts from its persisted
`/etc/frr/frr.conf` — whose `! BEGIN/END BPFRX MANAGED CONFIG` section was
written by the last successful `applyConfig`. Freeze-in-last-known-good leaves
that section intact. So on cold boot:

- `systemd-networkd` brings the data interfaces up (stale `10-xpf-*.network`),
- `frr` forms BGP/OSPF/IS-IS peerings and **re-advertises last-good prefixes**,
- peers route transit to this node's **physical interface IPs**, and the node
  (dataplane unarmed) **silently blackholes 100% of it**.

Had the teardown's `d.frr.Clear()` run, peerings would not form and upstream /
peers would **fail over to the redundant HA partner**. The issue asks to make
the cold-boot fail-closed path a *refinement*: "stop advertising and let the
partner take over" instead of "attract traffic and blackhole."

### What is NOT in scope of the bug
- **VIP / RETH data path already fails over.** #1960 leaves `ActiveConfig()`
  nil → no cluster manager → no VRRP → RETH/VIP traffic already goes to the
  partner. The blackhole is specific to **FRR-advertised routes to this node's
  *physical* interface IPs**, not the VIP path.
- **Standalone (non-HA) boxes:** blackhole == no service, which IS the expected
  fail-closed outcome there (no partner). The fix must not change standalone
  behavior in a way that *adds* surprise (it stops advertising, which is fine —
  a standalone box with an uncompilable config has no transit anyway).
- **Not a regression from #1960.** FRR is independent of the xpfd boot class;
  the pre-#1960 NORMAL/claim-all path advertised the same way and was otherwise
  worse (mis-binding interfaces, nil-config dataplane arm). This is a
  pre-existing cross-daemon coordination gap that #1960 made *visible* by
  formalizing the safe state.

---

## 2. Honest scope / value

**Value:** real availability bug for HA deployments running dynamic routing
(BGP/OSPF/IS-IS) on physical-interface IPs. On a power-event cold boot of a
node whose committed config silently stopped compiling (e.g. an unresolved
group/feed/apply-group reference that a binary bump made stricter), that node
attracts and blackholes transit instead of letting the partner carry it.
Blast radius for HA-with-dynamic-routing is "100% of transit routed via this
node's physical IPs until an operator notices and fixes the config."

**Scope:** small. The candidate fix is on the order of ~10-20 lines of Go in
the cold-boot bootstrap branch plus tests + a README/doc edit. It is a
slow-path, boot-time-only change. No hot path, no dataplane, no wire format, no
HA state-machine code.

**This is a safety refinement, not a perf change.** There is no throughput or
latency number to move. If reviewers conclude the perf gain / scope is too
small to justify the churn, PLAN-KILL is acceptable. The counter-argument for
shipping: the failure mode is a silent 100%-transit blackhole on a HA box that
is *supposed* to fail over, the fix reuses an already-proven primitive
(`d.frr.Clear()`), and it closes a gap the README currently carries as a known
limitation with a customer-visible footnote.

---

## 3. What's already shipped (do not re-do)

- **#1960 / PR #1991:** `classifyLoadError` → `loadCompileFailed`,
  `configCompileFailed` plumbed into `computeBootClass` (forces
  `bootClassBootstrap`, overriding even the HA-node guard), `shouldBootstrapFromFile`
  skip-on-compile-failure, loud Error log. (`pkg/daemon/bootstrap.go`,
  `pkg/daemon/daemon_run.go` ~L224-312.)
- **#1922 `enterBootstrapMode()`** ALREADY clears the FRR managed section as
  step (3): `if d.frr != nil { d.frr.Clear() }` (`bootstrap.go` ~L287-292).
  But this function is ONLY called from the Item-1b confirmed-commit rollback
  (`daemon_apply.go` ~L308). The cold-boot compile-failed path sets
  `d.bootstrapMode.Store(true)` directly (`daemon_run.go` ~L289) and never
  calls it.
- **`frr.Manager.Clear()`** (`pkg/frr/manager.go` L483) writes an EMPTY managed
  section to `frr.conf` AND runs `reloadLocked()` (frr-reload.py), which is
  exactly what drops peerings. It propagates `ErrFRRReloadDegraded` (it does not
  swallow it). The `frrExecutor` interface + `frrConf` field are test seams.
- **Recovery is already wired:** the first compilable `commit confirmed`
  re-renders FRR via `applyConfigLocked` → `applyFRRConfig(assembleFRRConfig(...))`
  (`daemon_apply.go` L957-965). So a cold-boot `Clear()` is fully reversible —
  the operator's fix re-installs the managed section + reloads.
- **README** already documents this exact gap as "Known limitation (#1993)"
  with the predicted fix (`pkg/daemon/README.md` L119-131).

---

## 4. Concrete design

### Root cause (one line)
The cold-boot compile-failed branch flips the bootstrap flag but skips the
FRR-managed-section clear that `enterBootstrapMode()` performs, so the
last-good `frr.conf` keeps advertising on an unarmed node.

### Where the fix goes
`pkg/daemon/daemon_run.go`, the `bootClass == bootClassBootstrap` branch
(~L288-302), specifically the `configCompileFailed` sub-case. There is an
**ordering subtlety**: at L288 the FRR manager does NOT yet exist —
`d.frr = frr.New()` is constructed later at L422 (inside the
`!d.opts.NoDataplane` manager-init block). The clear MUST therefore be deferred
to *after* `d.frr` is created, not done inline at L289.

Two viable insertion points (see Multiple Path Options for the full tradeoff):
either set a flag at L294 and act on it right after L422, or move the clear into
the FRR-init block guarded by a `configCompileFailed` check.

### Candidate code (sketch — not final; for review only)

In the bootstrap branch, record intent:
```go
// daemon_run.go, inside `if configCompileFailed { ... }` (~L294)
clearFRRForFailClosedBoot := configCompileFailed // narrow the trigger
```
After FRR manager construction (~L422, immediately after `d.frr = frr.New()`):
```go
// #1993: on a compile-failure COLD boot, the last-good frr.conf managed
// section is still on disk and FRR (an independent service) will form
// peerings + re-advertise last-good prefixes for routes this unarmed node
// cannot forward — a transit blackhole. Clear ONLY the managed section so
// peers fail over to the HA partner. We deliberately do NOT run the rest of
// enterBootstrapMode()'s teardown (networkd .network removal, dataplane
// detach): freeze-in-last-known-good for mgmt reachability is intentional.
// The first compilable `commit confirmed` re-renders FRR via applyFRRConfig,
// so this is reversible.
if clearFRRForFailClosedBoot && d.frr != nil {
    if err := d.frr.Clear(); err != nil {
        // Includes ErrFRRReloadDegraded — log, do not abort boot.
        slog.Warn("fail-closed boot: failed to clear FRR managed section "+
            "(node may still advertise last-good routes until operator fixes config)",
            "err", err)
    } else {
        slog.Warn("fail-closed boot: cleared FRR managed section so peers fail " +
            "over to the HA partner instead of blackholing transit to this node")
    }
}
```

### Why "clear only FRR" and NOT the full `enterBootstrapMode()` teardown
The cold-boot fail-closed path is *intentionally* a freeze-in-last-known-good:
keep the `10-xpf-*.network`/`.link` files (so mgmt stays on its EXISTING IP, not
bootstrap fxp0-DHCP) and keep interface identity. Running the full
`enterBootstrapMode()` teardown here would:
- remove the takeover `.network` files and link-cycle toward bootstrap fxp0,
  potentially changing the mgmt IP out from under a connected operator, and
- detach a (in cold boot, not-yet-started) dataplane — harmless but noise.

So the fix is the surgical *subset* of the teardown that addresses #1993: just
the FRR managed-section clear. This is the issue's preferred Option 1.

### Idempotency / interaction with `enterBootstrapMode()`
If a later Item-1b rollback DOES call `enterBootstrapMode()`, its
`d.frr.Clear()` is idempotent against an already-empty managed section
(`writeManagedSection("")` on a file with no markers is a no-op rewrite +
reload). No double-clear hazard.

---

## 5. Public API preservation

- **No gRPC / REST / CLI surface change.** No proto edits, no new RPCs, no
  cmdtree changes, no config-schema (`setSchema`) leaves.
- **No change to `frr.Manager`'s public API.** `Clear()` already exists and is
  already called from `enterBootstrapMode()`. The plan only adds a second
  caller on the cold-boot path.
- **No change to `computeBootClass` / `classifyLoadError` / `shouldBootstrapFromFile`
  signatures.** The decision (compile-failed → bootstrap) is unchanged; only a
  side effect (clear FRR) is added to the chosen branch.
- **`bootClass` enum doc comment** already states bootstrap means "no FRR
  managed-section" (`bootstrap.go` L105) — this fix makes the cold-boot path
  actually honor that documented contract, so it is a correctness alignment,
  not a contract change.

---

## 6. Hidden invariants to preserve

- **HA / failover ordering:** the fix must run on the cold-boot path of an
  HA node BEFORE FRR has a chance to advertise — i.e. the `Clear()` (which
  reloads FRR with an empty managed section) must happen early in `Run`, right
  after `d.frr = frr.New()` and BEFORE the daemon settles into its run loop.
  FRR itself may already be up and advertising from its own systemd start
  (independent of xpfd ordering) — `Clear()`'s frr-reload.py is what tears those
  peerings down. The earlier in `Run` this fires, the shorter the blackhole
  window. It does NOT touch VRRP/cluster (those are already nil on this path),
  so there is no RG-state / rg_active / blackhole-route ordering interaction.
- **Boot-class invariant:** the change is INSIDE the already-chosen
  `bootClassBootstrap` + `configCompileFailed` branch. It must not alter the
  predicate result, must not fire on `bootClassNormal`, and must not fire on the
  *no-config* bootstrap sub-case (a fresh box has no last-good managed section
  to clear — though `Clear()` there is a harmless no-op, scoping the trigger to
  `configCompileFailed` keeps fresh-install boot byte-identical).
- **Hot-path allocation:** N/A — boot-time-only, runs once.
- **Byte order:** N/A — no packet / map / wire fields.
- **Dual-AST:** N/A — no parser / set-syntax path touched.
- **Freeze-in-last-known-good for mgmt:** must NOT remove `.network`/`.link`
  files or link-cycle. Only the FRR managed section is cleared. This is the
  load-bearing distinction from `enterBootstrapMode()`.
- **`ErrFRRReloadDegraded` handling:** a degraded reload must be logged, not
  fatal — boot must proceed (mgmt reachability beats a perfectly-clean FRR
  reload). The degraded-retry goroutine that `Clear()` may arm must still be
  reaped at shutdown (`d.frr.Stop()` is already called in the shutdown path,
  `daemon_run.go` L1442).
- **`d.opts.NoDataplane`:** FRR is constructed only inside `if !d.opts.NoDataplane`
  (L409-422). The clear must be guarded by `d.frr != nil` so a `NoDataplane`
  test/daemon does not nil-panic.

---

## 7. Risk table (4-class)

| Risk | Class | Likelihood | Impact | Mitigation |
|------|-------|-----------|--------|------------|
| Clear fires on the wrong boot class (e.g. a normal boot) and wipes a working FRR managed section | **Correctness** | Low | High (would blackhole a HEALTHY node) | Scope strictly to `configCompileFailed` within the `bootClassBootstrap` branch; unit test asserts no-clear on normal/no-config boots |
| Ordering: clear runs but FRR re-reads stale `frr.conf` later / a race re-advertises | **Correctness/HA** | Low | Med | `Clear()` rewrites `frr.conf` on disk THEN reloads; no later xpfd code re-writes the managed section until the first good commit. FRR has no other reload trigger in this state |
| `Clear()` reload is DEGRADED (frr-reload.py unavailable) → managed section removed from file but peerings linger | **HA** | Low | Med | `Clear()` already writes the empty section to disk (so a subsequent FRR restart converges) and propagates `ErrFRRReloadDegraded`; log loudly; the degraded-retry loop re-attempts |
| Standalone box surprise: operator expected last-good routes to persist | **Operational** | Low | Low | Standalone with uncompilable config has no transit anyway; document that fail-closed now also stops advertising. Mgmt unchanged |
| Double-clear / goroutine leak if Item-1b rollback later calls `enterBootstrapMode()` | **Resource** | Very low | Low | `Clear()` is idempotent; `Stop()` reaps the retry goroutine at shutdown |
| Regression to the #1960 freeze-in-last-known-good mgmt benefit | **Correctness** | Low | High | The fix does NOT remove `.network`/`.link` or link-cycle; only FRR is cleared. Covered by a test asserting networkd files untouched (see test plan) |

---

## 8. Test plan

### Unit (Go, `pkg/daemon`, no lab)
The existing `applyBodyForTest` seam + the `frr.Manager` test seams
(`frrExecutor` interface, settable `frrConf` path) make this fully unit-testable.

1. **`TestColdBootCompileFailedClearsFRR`** — construct a `Daemon` with a
   `frr.Manager` whose `frrConf` points at a temp file pre-seeded with a
   `! BEGIN/END BPFRX MANAGED CONFIG` block and a fake `frrExecutor` that
   records `FrrReloadPy` calls. Drive the cold-boot compile-failed branch (or a
   small extracted helper, see below) and assert: (a) the managed section is
   gone from the temp `frr.conf`, (b) the fake executor saw exactly one reload.
2. **`TestColdBootNormalDoesNotClearFRR`** — same harness, `configCompileFailed=false`
   (normal / no-config bootstrap): assert the managed section is UNTOUCHED and
   the executor saw zero reloads. This is the critical "don't wipe a healthy
   node" guard.
3. **`TestColdBootCompileFailedLeavesNetworkdIntact`** — assert the fix does NOT
   remove `10-xpf-*.network`/`.link` files (freeze-in-last-known-good preserved).
   May reuse a temp `linkDir` seam if one exists; otherwise assert via the
   absence of a networkd-reload side effect.
4. **`TestClearFRRReloadDegradedDoesNotAbortBoot`** — fake executor returns
   `ErrFRRReloadDegraded`; assert boot continues (no error propagated out of the
   branch) and the warning is logged.

**Testability refactor (recommended):** extract the clear decision+action into a
small pure-ish helper, e.g.
`(d *Daemon) clearFRRForFailClosedBoot(compileFailed bool)`, so the unit tests
hit the helper directly rather than the whole `Run`. This mirrors the
`shouldBootstrapFromFile` / `computeBootClass` extraction discipline #1960 used
and keeps the test from needing a full daemon stand-up.

### Does it need the loss-cluster lab / `make test-failover` / multi-increment?
- **Loss-cluster lab:** NOT strictly required for correctness — the logic is
  unit-testable. BUT a **single confirmatory lab pass is strongly advised**
  because the failure mode is cross-daemon (FRR + peers) and the win is
  "partner takes over." A realistic validation needs a node with dynamic routing
  on a physical IP + a peer/partner. The loss userspace cluster does run an HA
  pair; whether it has a BGP/OSPF peer advertising into it on physical IPs is an
  open question (OQ-3). If it does not, the lab pass can only confirm "managed
  section cleared + FRR reloaded + mgmt still reachable," not the full
  end-to-end "peer fails over."
- **`make test-failover`:** advisable as a no-regression gate (the change is in
  the boot path of an HA-capable daemon), even though it does not directly
  exercise the compile-failed cold boot. Per CLAUDE.md, any change touching the
  boot/failover path SHOULD pass `make test-failover` before commit.
- **Multi-increment:** NO — this is a single, small PR.

### Manual / lab repro (if a lab pass is done)
On an HA node: commit a good config with BGP/OSPF on a physical IP; corrupt the
committed DB so it parses but does not compile (or use a binary that rejects a
previously-tolerated stanza); cold-reboot; observe (a) `frr.conf` managed
section cleared + peerings down, (b) the partner attracts the transit, (c) mgmt
still reachable at the existing address, (d) fix the config + `commit confirmed`
→ FRR re-renders and the node rejoins.

---

## 9. Multiple path options

### Option A — Clear FRR on the compile-failed cold-boot path (issue Option 1)
Add `d.frr.Clear()` (managed-section-only) right after `d.frr = frr.New()`,
gated on `configCompileFailed`. **Most surgical**, reuses a proven primitive,
preserves freeze-in-last-known-good for mgmt. **Tradeoff:** there is a small
window between FRR's own systemd start (which may advertise immediately) and
xpfd reaching the clear — the blackhole exists for that window, then collapses.
Acceptable (the partner takes over within the routing protocol's hold time once
peerings drop). **Recommended.**

### Option B — Reuse `enterBootstrapMode()` wholesale on the cold-boot path
Call the existing `enterBootstrapMode()` instead of just `Clear()`.
**Tradeoff:** REGRESSES the #1960 freeze-in-last-known-good mgmt benefit — it
removes `.network` files and link-cycles toward bootstrap fxp0-DHCP, which can
change the mgmt IP out from under a connected operator. The #1960 design
explicitly chose NOT to do this on cold boot. **Reject** unless review decides
the mgmt-IP-stability benefit is not worth the cross-daemon complexity (it is).

### Option C — Gate FRR advertisement on dataplane-armed status (issue Option 2)
Teach the FRR render to suppress route advertisement unless the dataplane is
armed / XDP attached ("don't advertise what you can't forward"). **Tradeoff:**
much larger surface — touches `assembleFRRConfig` / the render path, needs an
"armed" signal threaded into FRR, and changes the steady-state advertise logic
(risk of suppressing legitimately on a transient unarmed window). More general
(covers other unarmed states) but disproportionate for this bug. **Defer** as a
possible future generalization; not this PR.

### Option D — Stop/mask `frr.service` during compile-failure bootstrap (issue Option 3)
`systemctl stop`/`mask frr` while in compile-failure bootstrap; unmask on first
good commit. **Tradeoff:** coarser (kills FRR entirely, including any
operator-appended non-managed config outside the markers), introduces a
service-lifecycle dependency xpfd does not otherwise own, and must be carefully
reversed. The managed-section clear (Option A) achieves the same "stop
advertising" without touching the service or operator content. **Reject.**

**Recommended path: Option A.**

---

## 10. Out of scope

- Generalizing "don't advertise what you can't forward" to all unarmed states
  (Option C) — separate, larger work.
- Any change to the VIP/RETH/VRRP failover path (already correct on this boot
  class).
- Any change to the `ErrConfigDBUnreadable` (#1917 D1) fatal-exit path.
- Changing the freeze-in-last-known-good mgmt behavior or the bootstrap
  lifeline/protected-set logic.
- FRR degraded-reload retry semantics (already shipped in #1880).
- Standalone-box behavior beyond "also stops advertising" (no partner to fail
  over to; documenting the change is enough).

---

## 11. Open questions (for adversarial review)

1. **FRR start-before-xpfd window.** FRR is an independent service and may
   advertise last-good prefixes from its own systemd start *before* xpfd reaches
   the `Clear()`. How long is that window in practice on the appliance (systemd
   ordering of `frr.service` vs `xpfd.service`)? Is it short enough that the
   routing protocol's failover (peer hold-down after the clear drops peerings)
   makes the residual blackhole acceptable, or do we also need an
   `After=`/`Before=` unit ordering so xpfd's clear precedes FRR forming
   peerings? (If FRR must be ordered after xpfd, that is a unit-file change
   beyond the Go fix.)

2. **Is `Clear()` early enough, and is "right after `frr.New()`" the right
   spot?** The manager is built at ~L422; the run loop / settling happens far
   later. Is there any code between L422 and the clear insertion point that
   could itself re-render or rely on the managed section? Should the clear move
   even earlier (e.g. a dedicated step immediately after `d.frr = frr.New()`),
   and does `Clear()`'s frr-reload.py 15s context risk stalling boot if
   frr-reload.py hangs?

3. **Can the loss cluster actually validate the win?** Does the loss userspace
   cluster have a dynamic-routing peer advertising into a node on a *physical*
   IP (the exact blackhole vector), or only RETH/VIP paths (which already fail
   over)? If the former is absent, the lab pass can only confirm
   "section cleared + mgmt up," not "peer fails over." Is a unit-test-only
   validation acceptable for merge, with the lab pass as confirmatory-not-gating?

4. **Degraded-reload correctness on a fail-closed boot.** If frr-reload.py is
   unavailable at boot (`ErrFRRReloadDegraded`), the managed section is removed
   from `frr.conf` on disk but the *running* FRR may still hold the old
   peerings until it restarts. Does the degraded-retry loop reliably converge in
   this state, or does the node keep advertising indefinitely? Should the
   fail-closed boot, on a degraded clear, escalate (e.g. also drop the data
   interfaces or stop frr.service) rather than just retry?

5. **Operator-appended FRR config interaction.** `Clear()` removes only the
   xpf-managed markers and preserves operator content outside them. But the
   *operator's* own BGP/OSPF stanzas (if any, outside the markers) would still
   advertise. Is that in scope (the issue says "stop attracting transit"), or do
   we explicitly only own the managed section and accept that operator-authored
   routing config keeps advertising?

6. **Does this need a metric / log signal?** Should the fail-closed FRR clear
   bump a Prometheus counter (e.g. `xpf_failclosed_frr_cleared_total`) or set a
   gauge so an operator/alerting notices the node is in fail-closed-no-advertise
   state, rather than only a one-shot boot log line that scrolls away?

7. **Cluster `SyncApply` recovery path.** Recovery via local `commit confirmed`
   re-renders FRR. Does a recovery via cluster `SyncApply` from the primary
   (the other bootstrap-exit trigger) ALSO re-render FRR through the same
   `applyFRRConfig` path, or could a synced node exit bootstrap without
   re-installing its managed section?

---

## 12. Claude self-SMR (hostile)

**Strongest objection to my own plan:** the win may be partly illusory because
of the FRR-start-before-xpfd ordering window (OQ-1). FRR comes up as an
independent systemd service and can re-advertise last-good prefixes the instant
its peerings establish — potentially *seconds before* xpfd finishes Store.Load,
manager construction, and reaches the `Clear()`. During that window the node
still attracts and blackholes transit. If the fix only collapses the blackhole
"eventually" (after the clear + peer hold-down), then for short-lived flows /
fast cold boots the improvement over the status quo is smaller than the issue
implies, and a *complete* fix actually requires a systemd unit-ordering change
(`xpfd` clears FRR `Before=` FRR forms peerings) — which the issue's "Option 1"
framing does not mention. A reviewer could argue the Go-only fix is necessary
but not sufficient.

**Second objection:** the entire failure mode requires a fairly specific
combination — HA deployment + dynamic routing on *physical* interface IPs +
a committed config that parses but stops compiling + a *cold* reboot (not a
restart). Each is plausible; the conjunction may be rare enough that the churn
(even small) is hard to justify versus leaving the documented known-limitation
footnote in place. This is the PLAN-KILL case.

**Rebuttals:**
- On OQ-1: even an "eventually collapses" clear is strictly better than "never
  collapses" (today FRR advertises until an operator manually intervenes). The
  routing-protocol hold-down after peerings drop is the same failover mechanism
  HA already relies on. The unit-ordering refinement (if OQ-1 confirms it
  matters) is a small, separable follow-up; it does not block the Go fix.
- On rarity: the impact when it does hit is a silent 100%-transit blackhole on
  a box that is *supposed* to fail over — exactly the catastrophic-but-rare
  class HA exists to defend against. The fix reuses a proven primitive
  (`d.frr.Clear()`) and is ~15 lines + tests.

**Disposition: PLAN-DRAFTED-ready-for-review** (Option A), with one caveat that
shifts it toward **LIKELY-DEFER-LAB-for-confirmation**: the *merge* can proceed
on unit tests alone (the logic is unit-testable and the primitive is proven),
but a **single confirmatory loss-cluster pass + `make test-failover`** should
gate the final sign-off to (a) verify the cross-daemon "peer fails over" claim
if the lab topology supports it (OQ-3) and (b) measure the FRR-ordering window
(OQ-1) to decide whether a follow-up systemd unit-ordering change is needed.
This is NOT a multi-increment feature and NOT a PLAN-KILL (the impact justifies
the small churn), but it is lab-confirmation-sensitive rather than purely
unit-closeable.
