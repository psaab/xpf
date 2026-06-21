# Plan of Action — #2118: `show security policies hit-count` reads 0 for all rules

- **Issue:** #2118 (bug) — per-policy hit-count display reads 0 even when traffic was permitted/denied.
- **Base:** origin/master `5fa964c13`.
- **Research branch:** `research/2118-policy-hit-count`.
- **Revision:** r3 (post hostile reviewer A+B + SMR-r1; folds: second increment site mod.rs:2342, H2-primary re-rank for deny rows, Option-B file:line fix, synthetic-counter note for default line, missing-smoke-doc caveat, "0 may be 1" disambiguation, MissingNeighbor over-count risk + test).
- **Status:** PLAN-READY.
- **Mode:** `/research` — STOP at PLAN-READY. No code, no PR, no production-source edits.

---

## 1. Problem statement

`show security policies hit-count` (and the local-CLI equivalent, and the
structured gRPC `show security zones` policy block) display **0 packets / 0
bytes for every rule**, even when the 2026-06-20 security-matrix smoke
actively permitted and denied traffic through those rules. The aggregate
flow counters work correctly in the same run: `show security flow
statistics` shows `Policy deny` and `Sessions created` incrementing
(0→8 on a blocked flow, 0→6 on the negative control). So the dataplane
tracks permit/deny in aggregate but the per-policy hit-count table is dead.

Operators rely on per-policy hit counts to confirm which rule matched and
to find dead/shadowed rules. A table that always reads 0 is misleading
(looks like no rule ever matched). Observability/display defect, not a
forwarding defect.

**Evidence caveat:** the originating smoke doc
(`docs/smoke/security-matrix-2026-06-20.md`) referenced by the issue is
NOT present in this branch or origin/master — only the concrete numbers
survive (issue body: Policy deny 0→8, 0→6; Sessions created increments).
The plan does not treat that doc as a citable artifact; Step 1's live
reproduction is the authoritative evidence source. (The live checkout has
the file as an uncommitted artifact; it is not in the repo history.)

---

## 2. Key finding — the plumbing already exists end-to-end

This is the single most important result of the research. Per-rule hit
counting is **not** a missing feature waiting to be built. A complete
increment → snapshot → wire → read → display chain is present in the
current tree and has existed since #1407 (scheduler-rule counter
preservation). Static analysis confirms every link:

| Stage | Location | Verified behavior |
|-------|----------|-------------------|
| Counter type | `userspace-dp/src/policy.rs:208` `PolicyRuleCounter{packets,bytes:AtomicU64}` | lock-free atomics, `Relaxed` |
| Per-rule increment | `userspace-dp/src/policy.rs:1068` `rule.hit_counter.add(packet_len)` inside `try_match_rule` | fires on `src_ok && dst_ok` (after app-match); UNCONDITIONAL (no `count`/stats gate) |
| Match call site #1 | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1110` `evaluate_policy_result_with_len(&worker_ctx.forwarding.policy, …)` | reached on `ForwardingDisposition::ForwardCandidate` (new-session slow path), once per new flow |
| Match call site #2 | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2342` (#1913 `MissingNeighbor` cold path) | runs policy eval for an unresolved-neighbor cold packet that "never seeds a session, never buffers in pending_neigh" (comment :2318-2326) — so it can re-evaluate and re-increment **per packet** until the neighbor resolves. SECOND increment site; the §7/§11 invariant must account for it |
| Counter store (identity across reload) | `userspace-dp/src/policy.rs:236-268` `PolicyCounterStore` = `Arc<Mutex<FxHashMap<String,Arc<PolicyRuleCounter>>>>`; `rule_hit_counter()` reuses the SAME Arc by `rule_id` | counts survive recompile/reorder; pruned only on rule deletion via `reconcile_rules` (policy.rs:244) |
| Arc sharing worker↔coordinator | `PolicyRule::clone` (policy.rs:203) clones `hit_counter` as an Arc clone; coordinator stores `Arc::new(self.forwarding.clone())` into the worker-visible ArcSwap (coordinator/mod.rs:352) | worker increment and coordinator snapshot hit the SAME atomic |
| Coordinator snapshot | `coordinator/mod.rs:746` `self.forwarding.policy.counter_snapshots()` → policy.rs:502 | reads the live Arcs |
| Status assembly | `server/helpers.rs:241` `state.status.policy_rule_counters = state.afxdp.policy_rule_counters()` | called by `refresh_status` |
| Status reply (every non-suppressed request) | `server/handlers/mod.rs:164-166` `refresh_status(); response.status = Some(guard.status.clone())` | the `"status"` poll arm itself is empty (mod.rs:85) but the generic post-match block refreshes |
| Wire struct (Rust) | `userspace-dp/src/protocol/security.rs:272` `PolicyRuleCounterStatus{rule_id,packets,bytes}` with `#[serde(default)]`; carried by `ProcessStatus.policy_rule_counters` (`#[serde(rename="policy_rule_counters", default)]`, control.rs:360) | numeric, serde-default — #1961-safe |
| Wire struct (Go) | `pkg/dataplane/userspace/protocol.go:1145` `PolicyRuleCounterStatus{RuleID,Packets,Bytes}` (`json:"…,omitempty"`); `ProcessStatus.PolicyRuleCounters` (`json:"policy_rule_counters,omitempty"`) | numeric, omitempty — #1961-safe |
| Go poll loop populates `m.lastStatus` | `process.go:399` `statusLoop` ticks 1 Hz → `applyHelperStatusLocked` (maps_sync.go:326) → ends with `recordHelperStatusLocked(status)` (maps_sync.go:774) → `m.lastStatus = *status` (manager.go:1114) | full copy; preserves `PolicyRuleCounters` |
| Go read path | `pkg/dataplane/userspace/policycounters.go:53` `ReadPolicyCounters(policyID)` → `policyRuleIDForCounter(cfg,policyID)` reconstructs `stablePolicyRuleID(from,to,name)` → indexes `buildPolicyRuleCounterIndex(&m.lastStatus)[ruleID]` | unit-tested green (`manager_test.go:50` `TestReadPolicyCountersUsesHelperPolicyRuleCounters`) |
| rule-id format parity | Go `stablePolicyRuleID` `"%s->%s/%s"` (policies.go:550) == Rust `stable_policy_rule_id` `"{}->{}/{}"` (policy.rs:1082); Rust prefers the wire `rule_id` Go already sent (policy.rs:1079) | identical keys |
| gRPC text display | `pkg/grpcapi/server_show_policies_text.go:66-72` computes `ruleID = policySetID*MaxRulesPerPolicy + i`, calls `ReadPolicyCounters(ruleID)` | round-trip-consistent with the read path's `% MaxRulesPerPolicy` decompose |
| Local-CLI display | `pkg/cli/cli_show_security.go:52-54` same `ReadPolicyCounters(ruleID)` | same path |
| Structured gRPC | `pkg/grpcapi/server_show_zones.go:98-99` sets proto `PolicyRule.HitPackets/HitBytes` from `ReadPolicyCounters` | proto fields 8/9 exist |

**Conclusion:** the Go read path is correct and unit-tested; the Rust
increment, store, snapshot, and wire fields all exist; the key formats
match on both sides. The end-to-end chain *should* produce nonzero
counts. Yet the live smoke observed 0. The defect is therefore a
**live-only runtime bug** in one specific link that static reading cannot
disambiguate, plus a **policy-parity/consistency gap** (next section).

This is what makes #2118 PLAN-READY but NOT a one-line fix: the
implementation must *reproduce live and localize* before changing code.

---

## 3. The #2008 M4 parity context (load-bearing for the design)

On the SAME day as the smoke (2026-06-20, commit `908e874c2`), #2008 M4
established the intended Junos semantics:

> "Junos maintains per-policy hit counters only when `security policies
> policy-stats system-wide enable` is configured (default off)."

M4 gated the **Prometheus** collector (`metrics_counters.go:131`, early
return when `!cfg.Security.PolicyStatsEnabled`) but did **not** gate the
two text/structured display paths:
- `pkg/grpcapi/server_show_policies_text.go::showPoliciesHitCount`
- `pkg/cli/cli_show_security.go::showPoliciesHitCount`
- `pkg/grpcapi/server_show_zones.go` policy block

…and it did **not** gate the **Rust increment** (`policy.rs:1068` fires
regardless of the knob). `PolicyStatsEnabled` is **never transmitted to
the helper** (no occurrence in `pkg/dataplane/userspace/`).

Two consequences relevant to #2118:

1. **The smoke very likely ran with `policy-stats` OFF** (the smoke doc
   does not enable it). Under intended Junos parity, 0 is *correct* when
   the knob is off — but the CLI/gRPC display paths don't enforce the
   knob, so they *would* have shown the (ungated) live counts if the
   chain were actually incrementing. They showed 0, so either the live
   increment→snapshot→display chain is broken, OR the knob being off
   should suppress display (and the CLI path's failure to do so is a
   separate inconsistency bug that happens to read 0 only because the
   chain is broken).

2. The clean Junos-parity end-state is: **per-policy hit counts are
   maintained AND displayed only when `policy-stats system-wide enable`
   is set; 0/absent otherwise — uniformly across CLI, gRPC, and
   Prometheus.** #2118's fix should converge on that, not bolt a
   second, inconsistent always-on path next to M4's gated one.

---

## 4. Root-cause hypotheses (ranked) — to be confirmed live in Step 1

**GATING FORK (do this FIRST).** The smoke doc does not show `set
security policies policy-stats system-wide enable`, and #2008 M4 (§3)
makes per-policy counts a knob-gated feature in the Prometheus path.
**Step 1 action #0 = re-run the smoke WITH the knob enabled.** If the
table populates with the knob on, #2118 collapses to H4 (display paths
ignore the knob; the "0" was the knob off + the chain fine). If it still
reads 0 with the knob ON and explicit rules matched, the live increment
chain is genuinely broken (H1b/H3). This fork decides the fix shape and
MUST be resolved before any code change.

Evidence from deeper disposition-path tracing
(poll_descriptor/mod.rs:1700-1796): the increment-bearing call
`evaluate_policy_result_with_len` (:1110) drives BOTH the permit branch
(session create, :1715) AND the deny branch (`PolicyDenied`, :1769) for
new flows. So for a flow matching an EXPLICIT permit/deny rule, the
increment is on the SAME slow path that creates the session / sets
PolicyDenied. H1a (permit bypasses policy eval) is therefore UNLIKELY for
ordinary new TCP/UDP flows. **There is a SECOND eval/increment site at
mod.rs:2342** (MissingNeighbor cold path, #1913); the deny case can ride
either site.

Ranked live hypotheses:

- **H2 (PRIMARY for the DENY rows; confirmed correct-behavior, not a
  bug): the BLOCK traffic hit the implicit DEFAULT-DENY, not an explicit
  deny rule.** The loss userspace cluster config
  (`docs/ha-cluster-userspace.conf:176`) has `default-policy deny-all`
  and ONLY explicit PERMIT rules — **no explicit deny rules at all**. The
  aggregate `policy_deny` increments for ANY deny including the default
  (mod.rs:1732, in the deny `else` branch), but the per-rule
  `hit_counter` increments ONLY on an explicit `try_match_rule` match;
  the default fall-through (policy.rs:959-962, `policy_id: 0`) increments
  NOTHING. So `Policy deny 0→8` aggregate + per-rule 0 on the deny side
  is **correct** — there is no explicit deny rule to attribute to. The
  ONLY genuinely anomalous rows are the explicit PERMIT rules (lan→wan
  allow) that should read ≥1 after sessions were created. Step 1 must
  target those PERMIT rows specifically.
- **H0 (resolve first): the smoke ran with `policy-stats` OFF.** Junos
  parity ⇒ 0 is the intended read when off. The re-run with the knob ON
  tells us whether a real increment-chain bug exists in the permit rows
  or whether #2118 is purely the H4 display-gate inconsistency.
- **H2b (disambiguation, cheap): "0" may actually be "1".** The permit
  increment fires once per NEW flow on the slow path. A single sustained
  iperf3 TCP flow bumps the matched permit rule by exactly packets=1 /
  ~60 bytes — trivially misread as 0 in a wide table. Step 1 MUST read
  the EXACT value (and bytes), and drive MANY distinct flows (or many
  short connections), not a single long flow, before declaring "still
  0".
- **H1b: worker `Forwarding` clone policy Arcs diverge from the
  coordinator's after a snapshot rebuild.** Coordinator owns `forwarding:
  ForwardingState` (mod.rs:197), stores `Arc::new(self.forwarding.clone())`
  into the worker ArcSwap (mod.rs:352). `PolicyRule::clone` shares the
  counter Arc and the `PolicyCounterStore` reuses Arcs by rule_id across
  rebuild, so identity SHOULD hold — but the store-to-ArcSwap ordering on
  the snapshot-refresh leg is the residual live risk. Verify worker and
  coordinator point at the same Arcs after an apply.
- **H1a (down-ranked): an ICMP-embedded / prebuilt-frame / NAT-reversed
  permit bypasses policy eval** (mod.rs:1078 "Permit without policy
  check"). Only relevant if the smoke permits rode those branches.
- **H3: `m.lastSnapshot.Config` nil/stale at read time** ->
  `policyRuleIDForCounter` returns empty -> silent 0. Low probability
  (config set on apply, manager.go:705/818); eliminate with a fallback
  to `store.ActiveConfig()`.
- **H4 (parity, independent of any live bug): CLI/gRPC display paths
  ignore `policy-stats` while Prometheus honors it** — real regardless of
  H0; fixed by design in §6 Step 3.

Step 1 of `/engineer` resolves H0/H2/H1b/H3 empirically before any code
change; H4 is fixed by design.

**MINOR — implicit-deny hit count is an xpf decision, not asserted Junos
parity.** "Count the default-action path" (§6 Step 2, §8) is a deliberate
xpf enhancement to be confirmed against a real vSRX, NOT established
parity. If unconfirmed, drop it and count explicit rules only.

---

## 5. Goals / non-goals

**Goals**
- `show security policies hit-count` (CLI + gRPC text), `show security
  policies hit-count from-zone X to-zone Y`, the structured gRPC zones
  block, and the Prometheus `policy_hits_total` all report the SAME
  nonzero per-rule counts for permitted/denied traffic **when
  `policy-stats system-wide enable` is configured**.
- All four display surfaces uniformly report 0/absent when the knob is
  off (Junos parity; closes the M4 display-side inconsistency).
- `clear security policies hit-count` zeroes the live counters.
- Counts attributed to the correct rule across config reload / HA sync;
  no misattribution after a recompile (rule identity = stable
  `from-zone→to-zone/name` key).
- Regression coverage so the table can never silently return to all-0.

**Non-goals**
- No new wire-protocol fields if the existing `policy_rule_counters`
  array is sufficient (it is — see §2). Avoid net-new surface.
- No per-packet policy re-evaluation for established sessions (perf).
- No change to aggregate flow counters (they already work).
- No HA session-sync semantics change.

---

## 6. Path options

### Option A (RECOMMENDED): reproduce-then-fix the existing chain + unify the policy-stats gate

1. **Step 1 — live reproduce + localize (no code yet).** On the loss
   userspace cluster (or standalone VM), with a config that has explicit
   permit AND deny rules and `set security policies policy-stats
   system-wide enable`, drive sustained iperf3/known flows that create
   sessions, then read `show security policies hit-count`. Instrument
   minimally (a temporary `slog.Debug`/`eprintln!` at the increment site
   and at `counter_snapshots`, plus dump `m.lastStatus.PolicyRuleCounters`
   length) to determine which link is dead. This confirms H2 vs H1b vs
   H3 and whether the smoke's 0 was simply the knob being off / the
   deny-row default-deny (H2) being correct-0. Read the EXACT permit-row
   value (H2b) and drive MANY flows, not one. Instrument BOTH increment
   sites (mod.rs:1110 and mod.rs:2342).
2. **Step 2 — fix the localized defect.** Expected to be small. The
   intended invariant must hold at BOTH increment sites (mod.rs:1110 and
   mod.rs:2342):
   - If H1b: re-store the rebuilt `Forwarding` into the worker-visible
     ArcSwap after snapshot refresh (ordering fix), or assert Arc
     identity via the `PolicyCounterStore` on the rebuild leg.
   - If H1a (only if Step 1 shows the permit rode a bypass branch):
     ensure the increment covers that permit disposition too.
   - If H3: make `ReadPolicyCounters` fall back to `store.ActiveConfig()`
     when `m.lastSnapshot.Config` is nil, or surface a debug counter.
   - MissingNeighbor over-count (mod.rs:2342, §7 caveat): decide
     count-once-per-flow vs count-each-admitted-packet and apply at both
     sites consistently.
   - OPTIONAL, gated on a real-vSRX confirmation (§4 MINOR): surface a
     hit count on the implicit default line. This is NOT a `rule_hit_
     counter("")` entry — the default fall-through has no `from→to/name`
     rule_id and `buildPolicyRuleCounterIndex` skips empty RuleIDs
     (policycounters.go:16-18). It needs a SEPARATE synthetic counter
     (e.g. a reserved key per zone-pair, or reuse the aggregate
     `policy_denied`). Do NOT route it through the existing string store.
     Drop entirely if vSRX does not show it.
3. **Step 3 — unify the policy-stats gate (H4).** Gate the CLI + gRPC
   text + structured-zones display paths on `cfg.Security.
   PolicyStatsEnabled` exactly as `collectPolicyCounters` does, so all
   four surfaces agree. Optionally also gate the Rust increment on a
   transmitted `policy_stats_enabled` snapshot flag to avoid maintaining
   counters that are never displayed (matches the M4 comment "the
   firewall does not maintain them") — but ONLY if §7 confirms the flag
   plumbing is cheap; otherwise keep the increment always-on (it is a
   single relaxed atomic) and gate only the display.
4. **Step 4 — regression coverage** (§8).

*Pros:* reuses the entire existing, #1961-safe wire surface; smallest
diff; converges on the M4 parity end-state. *Cons:* requires a live
diagnosis pass before the fix is known (acceptable — that is exactly what
`/research`→`/engineer` is for).

### Option B: rebuild a fresh per-rule counter array keyed by positional `policy_id`

Add a parallel counter mechanism keyed by the positional `policy_id`
(u32) rather than the stable `rule_id` string. *Rejected:* duplicates an
existing, working store; positional `policy_id`s SHIFT when rules are
reordered or inserted/deleted (the ID is `policySetID*MaxRulesPerPolicy +
ruleIndex`, policies.go:47 — a positional ID, so it moves with the rule's
ordinal), so counts would misattribute after an edit — the exact failure
the stable-`rule_id` design already avoids. More wire surface, worse
correctness.

### Option C: sampling / approximate counts

1-in-N sampled increments. *Rejected:* hit-count is an exactness contract
(operators diff before/after to prove a rule matched); a single relaxed
atomic add is already negligible (§7), so sampling buys nothing and
breaks the contract.

### Option D: PLAN-KILL

*Rejected.* The chain mostly exists; the cost is a small localized fix
plus a parity unification, not a large new surface. The feature is a
core Junos-parity observability primitive operators depend on. Not worth
killing.

---

## 7. Hot-path cost

- Increment is one `fetch_add(1, Relaxed)` + a conditional
  `fetch_add(bytes, Relaxed)` (policy.rs:215) on the **new-session slow
  path** (poll_descriptor:1110, `ForwardCandidate`), NOT per packet for
  established sessions. Cost is in the noise relative to the cold-path
  histogram + session install already on that path.
- **CAVEAT (second site, mod.rs:2342):** the `MissingNeighbor` cold path
  re-evaluates policy per packet for a flow whose neighbor is unresolved
  (it does not seed a session or buffer). For an explicit-rule match in
  that window the counter is bumped once per packet until the neighbor
  resolves — a transient OVER-COUNT, not a per-packet steady-state cost
  (once the neighbor resolves the flow takes the normal session path).
  Step 2 must decide the intended invariant (count-once-per-flow vs
  count-each-admitted-packet) and make BOTH sites obey it; the simplest
  correct choice is to keep counting each admitted packet (it is a hit
  count, and the aggregate counters already count packets), and document
  that an unresolved-neighbor burst inflates the count — OR suppress the
  increment on the MissingNeighbor re-eval. Resolve in Step 1/2.
- If Step 2 relocates the increment to the disposition/session-install
  point, keep it on the same once-per-flow slow path; do NOT add it to
  the per-packet established fast path.
- If Step 3 transmits a `policy_stats_enabled` flag, it is a single bool
  in `ConfigSnapshot` (apply-time, not hot-path); the runtime check is a
  load of one bool. Negligible. The relaxed atomic add is cheap enough
  that gating the *increment* on the flag is optional — gating *display*
  is sufficient for parity.
- No new locks; the `PolicyCounterStore` mutex is touched only at
  parse/clear/reconcile time, never on the packet path. Snapshot read is
  a per-rule atomic load under no lock.

---

## 8. Test plan

- **Go unit:** extend `manager_test.go` (read path already covered) with
  a gate test: `ReadPolicyCounters`/display returns 0 when
  `PolicyStatsEnabled` is false, nonzero when true, for the SAME
  populated `m.lastStatus`. Mirror `TestCollectPolicyCountersGatedOn
  PolicyStats` (added by M4) for the CLI/gRPC text paths.
- **Golden test (regression spine):** add `policies-hit-count` (and the
  zone filter variant) to `goldenShowTopics`
  (`pkg/grpcapi/server_show_golden_test.go:71`) with a runtime
  `PolicyRuleCounters` fixture so a future all-0 regression FAILS the
  golden. Today this topic is absent — that is why the bug shipped.
- **Rust unit:** in `policy_tests.rs`, assert `try_match_rule` (or the
  relocated increment site) bumps the snapshotted counter for a permit
  AND a deny; assert `counter_snapshots` reflects it; assert reconcile
  preserves counts across a reorder and drops on delete. (Some of these
  likely exist; fill the gaps found in Step 1.)
- **Rust two-site invariant test:** assert the chosen invariant holds at
  BOTH increment sites — specifically that a permitted flow whose
  neighbor is initially unresolved (driving the mod.rs:2342
  MissingNeighbor path) does not violate the count-once-vs-count-each
  decision from §6 Step 2. This is the test that would have caught the
  second-site omission.
- **Live smoke (the acceptance gate):** on the loss userspace cluster
  with `policy-stats enable`: explicit permit + explicit deny rules,
  sustained iperf3 + a blocked probe, then `show security policies
  hit-count` shows nonzero on the matched permit and deny rules and on
  the implicit-deny line; `clear security policies hit-count` zeros them;
  re-run repopulates. Disable the knob → all four surfaces read 0.
  Confirm via `show security flow statistics` deltas that the same
  traffic drove the aggregate counters (cross-check). Must also pass
  `make test-failover` if Step 2 touches any shared `Forwarding`/coordinator
  path (it may, under H1b).

---

## 9. Rule identity across reload / HA-sync

- Identity is the stable string `from-zone→to-zone/name` (Go
  `stablePolicyRuleID`, Rust `stable_policy_rule_id`, identical format;
  Rust prefers the wire `rule_id` Go already populates). Positional
  `policy_id` is NOT used for counter identity.
- `apply_snapshot` is a FULL policy replace; `PolicyCounterStore.
  reconcile_rules` (policy.rs:244) retains counters whose `rule_id` is
  still present and drops the rest. So a rule that keeps its
  zone-pair+name keeps its count across recompile/reorder; a renamed or
  deleted rule loses it. **Divergence from Junos:** Junos resets
  per-policy hit counts on a commit that changes the policy; xpf
  PRESERVES them across recompile as long as identity is unchanged. The
  plan **keeps the preserve-on-recompile behavior** (it is more useful
  and already shipped) but must **document the divergence** in
  `docs/feature-gaps.md` / the security-policy module doc, and note it in
  the issue. (Resetting on every commit is explicitly a non-goal — it
  would make the counter useless for long-running rules.)
- HA sync: counters are node-local (not session-synced). After failover
  the new master accumulates its own counts; document that per-policy
  hit counts are per-node, not cluster-aggregated (matches Junos
  per-node behavior).

---

## 10. Files in scope (anticipated; finalized by Step 1)

- `userspace-dp/src/policy.rs` — increment site / default-action count
  (if H1a).
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` and/or
  `userspace-dp/src/afxdp/disposition.rs` — relocate/extend increment to
  cover all permit/deny dispositions (if H1a).
- `userspace-dp/src/afxdp/coordinator/{mod.rs,snapshot_refresh.rs}` —
  ArcSwap store ordering (only if H1b).
- `pkg/grpcapi/server_show_policies_text.go`,
  `pkg/cli/cli_show_security.go`, `pkg/grpcapi/server_show_zones.go` —
  honor `PolicyStatsEnabled` (H4).
- `pkg/dataplane/userspace/{protocol.go,builder.go,policies.go}` — only
  if transmitting a `policy_stats_enabled` flag (optional, §6 Step 3).
- Tests: `pkg/grpcapi/server_show_golden_test.go` (+testdata),
  `pkg/dataplane/userspace/manager_test.go`, `userspace-dp/src/
  policy_tests.rs`.
- Docs: `docs/feature-gaps.md` (preserve-on-recompile divergence;
  per-node counts), the security-policy module doc, `_Log.md`.

---

## 11. Risk / rollback

- **Risk:** there are TWO increment sites (mod.rs:1110 ForwardCandidate,
  mod.rs:2342 MissingNeighbor). The MissingNeighbor site can re-evaluate
  policy per packet for an unresolved-neighbor flow, transiently
  over-counting an explicit-rule match. *Mitigation:* §6 Step 2 fixes the
  invariant at BOTH sites; a Rust unit/integration test (§8) asserts a
  permitted flow with an initially-unresolved neighbor does not violate
  the chosen invariant. Any relocation of the increment must enumerate
  both sites.
- **Risk:** gating the increment on a transmitted flag (optional Step 3)
  could lose counts if the flag races a snapshot. *Mitigation:* prefer
  gating DISPLAY only; keep increment always-on (cheap atomic).
- **Risk (H1b fix):** touching the coordinator ArcSwap store path can
  affect forwarding. *Mitigation:* mandatory `make test-failover` +
  sustained-iperf smoke; keep the change to ordering only.
- **Rollback:** display-gate + test additions are pure-Go and trivially
  revertible; the Rust increment fix is localized. No wire-format
  bump (reuses `policy_rule_counters`), so no cross-version concern; the
  existing serde-default/omitempty discipline already covers old↔new.

---

## 12. Recommendation

**Option A.** The feature is ~90% built and #1961-safe on the wire. Two
verified facts reshape the work from "build a counter" to "diagnose +
unify":

1. The DENY-row 0s are CORRECT behavior, not a bug: the loss cluster has
   only explicit permit rules + `default-policy deny-all`, so the BLOCK
   rode the implicit default-deny which increments the aggregate but no
   per-rule counter (H2, primary). The ONLY genuinely anomalous rows are
   the explicit PERMIT rows.
2. The static increment→snapshot→wire→read→display chain is intact and
   Go-unit-tested, with TWO increment sites (mod.rs:1110, :2342). So the
   permit-row 0 is either the `policy-stats` knob being off (H0/H4
   display-gate inconsistency), "0 is really 1" (H2b, single-flow), or a
   live Arc-divergence (H1b).

The work is therefore: (1) a live diagnosis pass that reads the EXACT
permit-row values with `policy-stats enable` and many flows to settle
H0/H2b/H1b/H3; (2) a small localized Rust fix IF a real break is found
(most likely H1b ordering, or nothing if it was H0/H2b); (3) unify the
`policy-stats` gate across CLI/gRPC/Prometheus to the #2008 M4
Junos-parity end-state (a real bug regardless of the live outcome); (4)
add the golden + live regression that should have caught this; and (5)
handle the second increment site / MissingNeighbor over-count invariant.
PLAN-READY.
