# Claude SMR plan review — round 5 — #6749 armed-state plan v6 (6969b6167)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v6 restructure — tri-state provenance,
coherent-vector invariant, common S4', arm rollback, Go arm-sync defer
gate, `complete_deferred` provenance.

**Verdict: PLAN-READY-WITH-NITS** — every structural attack I mounted
was absorbed (trace below). Three nits to fold without a re-review:
one logging-rate hazard the rollback newly makes recurrent, one
documented corner for the no-link-cycle completion path, one test
addition for the idempotent re-arm path. If Codex/AGY r5 surface a
real hole, this verdict is void and we iterate.

---

## Attack trace (what I tried, and why it fails to break v6)

1. **Unowned-producer hunt (plan Q1).** Re-enumerated every path to
   `registered && !armed` under v6: planner marks (S1/S2/S3/S4'/S5 →
   `pending`), operator verbs (`operator`), global fan-outs (`none` —
   global ownership, D-visible), C1 convergence (arms), lifecycle init
   (no bindings), rebind (never sets state), #2794 disarmed leg (no
   state production). Every non-forwarding state has exactly one of
   the three owners. No fourth producer found. The arm-Err path:
   S4' marks (pending) + global rollback — owned.
2. **Coherent-vector hunt (plan Q2).** Every vector mutation:
   full-apply replan (replaces), same-plan leg (retains vector +
   replaces snapshot with an EQUAL plan key → same identities),
   defer same-plan leg (same), #3789 pre-teardown restore (restores
   existing_bindings WITH the previous snapshot — coherent by
   construction), post-teardown failure (v6 replans from the restored
   snapshot — coherent by construction), bump_fib (no plan touch).
   No divergence found. The sysfs-drift re-entry (rx_queues==0
   resolved live at the failure-path replan): the drift changes the
   LAYOUT the next reconcile will bind, not an authorization — extra
   identities appear as S5-pending (fail-closed) and the next apply's
   plan key hashes the same live value (consistent by #3007).
3. **S4' on carried slots (my own Q7 to Codex).** Established box,
   plan change, post-teardown reconcile failure: carried slots were
   armed=true (carry); S4' marks them unarmed+pending. Master parity
   would keep them armed against dead workers (the contraction-lie —
   `enabled=true` with no live workers). S4' forces `enabled=false`
   on every shape — the truthful posture, and the convergence
   re-arms them on the next successful armed reconcile. Coherent,
   and strictly more truthful than master on the contraction shape.
4. **Arm-verb paths.** Boot arm: global=true → reconcile Err → S4'
   marks + rollback to false → Go desired-loop retries (bounded by
   #6165) — production retry achieved without new debt machinery.
   Re-arm after operator global disarm: same shape (prev=false).
   Idempotent re-arm on an already-true global (explicit operator
   verb): on Err, rollback restores TRUE, S4' marks pending →
   `enabled=false`; the desired-sync no-ops (global==desired), but
   the pending-aware deficit predicate fires on the next same-plan
   apply and any rebind converges — bounded, no stranding. On Ok the
   fan-out is idempotent. All three paths coherent.
5. **Defer-window completeness (plan Q3).** `rethMACPending=true`
   requires the current MAC to differ, so programming it (link
   down/set/up) cycles the link → NotifyLinkCycle fires →
   provenance-tagged rebind converges. The corner: the link was
   ALREADY down (no cycle event) — no completion until the next
   commit/rebind/HA event; slots pend (fail-closed), and the
   interface-down state is independently alarmed (cluster link
   tracking / watchdog). Acceptable, but the plan should say it
   (nit N2).
6. **#5134 republish (plan Q4).** Debt loop republishes
   `DeferWorkers=false` with a bumped generation against stored
   defer=true: plan key equal (defer is not a key input) → same-plan
   leg → previous_defer=true → reconcile → stored-after-swap is
   non-deferred → convergence passes without the flag. That IS the
   intended completion: the republish carries the newest config, so
   converging its pending slots is correct. No flag needed because
   the apply's own defer flag is the provenance.
7. **Tri-state transitions.** Operator re-arm of a claimed slot →
   `none` (armed); a later flap marks pending (not operator) →
   recovers + converges — matching the operator's last expressed
   intent (armed). Operator unregister → claim → flap → recovery
   restores the exact claim. Global disarm → `none` on registered →
   flap → S2 re-marks pending → recovery re-registers → re-arm
   converges. Every transition lands in an owned state.
8. **Disposition table spot-audit.** Rows B2/M9 (coherent vector
   replaces the gate — the same-name/new-ifindex and failed-
   contraction counterexamples now resolve to the restored plan's
   ifindex and re-appearing A-only identities — verified against
   replan semantics), B3 (tri-state), B4 (common S4' + pending-aware
   predicate), B5 (rollback → existing desired-loop), B6 (verified
   the sync has no defer check on master at manager_ha.go:601-607;
   the v6 gate is the fix), M7 (additive `complete_deferred`, only
   NotifyLinkCycle sets it — verified both rebind senders,
   process_linkcycle.go:220 vs maps_sync.go:1484). All hold.

## Nits (fold without a re-review)

- **N1 (logging rate):** the rollback makes the Go desired-loop
  RETRY a failed arm each tick; when the #6165 required-protocol
  gate refuses the retry (stale-protocol window), the poll logs
  `slog.Warn("userspace dataplane forwarding sync failed")` at 1/s
  (process_status.go:241) — a flood the project's logging rules
  forbid in spirit (the pre-existing path had it only for persistent
  sync errors; the rollback widens the trigger set). The
  implementation should edge-trigger this warn (fire on the
  false→true transition of the error state, clear on success) in the
  same PR.
- **N2 (documented corner):** §5-C's defer completion should note
  the already-down-link corner: `rethMACPending` implies a MAC
  change, which implies a link cycle — EXCEPT when the link was
  already down, where completion waits for the next
  commit/rebind/HA event and the interface-down state is the
  independently-alarmed primary problem.
- **N3 (test addition):** §9 item 14(iv) should ALSO pin the
  idempotent re-arm path: explicit `set_forwarding_state(true)` on
  an already-true global with a forced reconcile Err → global
  restored to true, S4' marks survive, the next same-plan apply's
  pending-aware deficit predicate fires the recovery reconcile.

## Required for convergence

Nothing structural. If Codex + AGY r5 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N3 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
