# Plan-of-action — #5145 DNAT precedence: most-specific-wins vs Junos first-match

## 1. Status

`v2 — PLAN-KILL (Option A)` — converged 2026-07-16.

Research-only. Stops at PLAN-KILL. No production code touched.

### Convergence & verdict (r2)

Reviewers converged on **PLAN-KILL of Option A** (the reverse-to-first-match
rewrite). Two independent architectural blockers — both verified firsthand
against the code — make Option A unshippable as designed:

- **B1 — flat global ordinal cannot honor Junos rule-set selection.** Junos
  selects the single most-specific rule-set by `from`-context (interface > zone
  > RI), then first-matches *within that rule-set*. Option A's global-candidate
  argmin filters out the non-matching most-specific rule-set and picks the
  lower-ordinal row from a *less*-specific rule-set — i.e. it silently
  implements undocumented **rule-level fall-through**. The snapshot/wire/Rust
  structures carry a rule name + 3 context fields but **no rule-set identity**
  (protocol.go:680; destination.rs `DnatEntry` ~65), so a two-stage
  select-rule-set-then-first-match cannot be expressed. A faithful design needs
  `(effective_rule_set_id, context_rank, rule_index)` + two-stage lookup, and
  the no-matching-rule-in-selected-set behavior pinned by a primary Juniper doc
  or a vSRX trace (still an open citation — §11 Q1).
- **B2 (decisive) — a winning `off` does not un-register the overlapping
  translate VIP → the motivating case fails end-to-end.** `destination_ips_scoped`
  (destination.rs:1028-1083) skips only `entry.off` rows and exports **every**
  non-off translate destination into the firewall-local sets
  (forwarding_build/mod.rs:479-486), with **no** awareness of a
  higher-precedence covering `off`. A winning exemption collapses to the same
  `None` as "no rule," so the poll path keeps the original destination
  (poll_descriptor/mod.rs ~1596-1602), which — being registered as a local VIP
  by the still-present `/32` translate — takes `LocalDelivery` before FIB
  lookup (forwarding/mod.rs ~1468-1543). **The exempt host is consumed by the
  firewall stack instead of routed.** So Option A, as designed (lookup
  precedence only), does not even achieve the security goal it exists for. The
  plan's "local-address registration unaffected" claim (§7) is false. Fixing
  this requires precedence-aware local-ownership or carrying an explicit
  `Exempt` outcome into forwarding — both violate Option A's "lookup API
  unchanged / registration unaffected" premise.

Supporting findings (each independently sufficient to fail the plan as written):
- **HA mechanism named wrong.** Synced sessions ARE safe, but because the
  resolved `NatDecision.rewrite_dst` is replayed through **session state**
  (traced eventstream → cluster sync_protocol → manager_ha → server/helpers →
  upsert_synced_session), **not** via the `dnat_table` BPF publish the plan
  cited (`publish_dnat_table_entry` returns early unless `rewrite_src` exists —
  it is reverse-SNAT steering). Fresh / missed / independently-created sessions
  during a rolling mixed-version window still diverge, and the all-zero
  fallback must run the **exact** current algorithm (not merely "deterministic
  insertion order"). A real semantic/activation gate is required — an additive
  JSON field is decode-compatible, not a semantic gate.
- **Cost "LOW" is unproven.** Per-session-miss is confirmed, but "negligible"
  is not: the global argmin must scan all **six** buckets (three exact-host +
  three prefix sub-tiers), denied/dropped misses can pay repeatedly, and Juniper
  lists destination-NAT capacities up to 51,200 rules on some platforms. No
  table-size / session-rate / large-prefix-bucket benchmark exists.
- **Test-masking trap.** Rust snapshot fixtures use `..Default()` → all-zero
  ordinals → they become legacy-mode inputs; old tests stay green while
  production Go emits nonzero ordinals and behaves differently. Production-
  semantics tests must stamp ordinals or build via the Go path.
- **Reversed contracts undercounted.** #3164 longest-prefix, exact-port>
  wildcard-port, concrete-proto>IP-only, and last-wins dedup all flip to
  first-wins; the plan enumerated only one LPM test.

**Reviewer verdicts (r1 → convergence):**
- **Codex-lane (hostile, evidence-backed):** PLAN-KILL (Option A) → re-plan
  around a re-scoped Option C. `codex-plan-r1.md`.
- **Claude SMR (hostile):** r1 ITERATE leaning-to-C; **r2 concurs PLAN-KILL**
  after firsthand-verifying B2 (the LocalDelivery blocker it had missed).
  `claude-smr-plan-r1.md`, `claude-smr-plan-r2.md`.
- **AGY:** infra-blocked all round (MCP headless permission auto-deny; direct
  CLI `--print` timed out with no output) — documented retries, proceed 2-of-3
  per `feedback_codex_infra_must_retry`. AGY-alone was never relied on; the
  convergence rests on the strong Codex + Claude SMR pair.

**Go-forward (NOT plan-ready — recommendations only):**
1. **Option C (proportionate)** — keep most-specific-wins; add a **commit-time
   lint** that makes a shadowed broad `off`/translate operator-visible (strict
   error at commit; tolerant warn on lenient/peer-sync load). This needs its
   **own concrete plan** — disposition (strict vs warn), an overlap model over
   the *canonical expanded* match space (address/app/proto/port/source/range
   expansion, current exact/wildcard/proto-any/prefix precedence), scope
   (within-rule-set first), dynamic-feed handling, and tests. Not shippable from
   the 3-line sketch in §11.
2. **File the B2 LocalDelivery interaction as a separate latent bug** — it may
   already affect the "common" more-specific-`/32`-off idiom when a covering
   translate prefix expands to include the off host (bounded prefix expansion,
   destination.rs:1043-1077). Independent of #5145's precedence question.

The remainder of this document (the original v1 Option A design) is retained
below for context; it is the **killed** approach.

---

## 1a. (v1) Status — superseded

`DRAFT v1 — pending adversarial plan review` (Codex + AGY + Claude SMR)

## 2. Issue framing

`userspace-dp/src/nat/destination.rs` resolves destination-NAT precedence by
**most-specific-match-wins across probe tiers**, not by Junos configured-order
first-match. The lookup (`DnatTable::lookup_with_counter`,
destination.rs ~615-690) probes four tiers via a short-circuiting `.or_else`
chain:

1. exact `(proto, dst, port)` hash
2. wildcard-port `(proto, dst, 0)` hash
3. proto-any `(PROTO_ANY, dst, 0)` hash
4. longest-prefix-match over the non-host prefix table

The **first tier with any match wins**; lower tiers are never probed. Within
the prefix tier, the **longest** matching prefix wins (`best_in_tier`,
destination.rs ~862-889), config order only breaking ties among equal-length
prefixes.

Consequence (the reported security defect): a broad, *earlier* `then
destination-nat off` exemption that lands in a lower tier is **bypassed** by a
later, more-specific translate rule in a higher tier. Example, single rule-set:

```
rule-set rs { from zone untrust;
  rule exempt  { match destination-address 10.0.0.0/24;  then destination-nat off; }   # broad, prefix tier
  rule web     { match destination-address 10.0.0.5/32;  then destination-nat pool P; } # specific, exact tier
}
```

Junos evaluates `rs`'s rules top-to-bottom, first-match-stop: `exempt` matches
`10.0.0.5` (∈ /24) first → **no translation**. xpf: the `/32` exact-tier
translate is probed before the `/24` prefix tier → **translates** → the
exemption is silently bypassed (fail-open). This is labeled `security` because
an operator's exemption of a host inside a translated block does not hold.

The divergence also affects **translate-vs-translate** (a later specific
translate beats an earlier broad translate), not only off-vs-translate.

The behavior is **documented as intentional** in destination.rs:747-756 (added
by #3852 review, commit 6e8b99f1f) and the off-exemption short-circuit was added
by #3844 (commit bfc707611). So this issue asks us to **revisit a deliberate,
documented design decision**, not to fix an oversight.

## 3. Honest scope/value framing

The win is **Junos parity + closing a fail-open exemption surprise**, not
performance. Concretely:

- **Blast radius of the current behavior**: only bites configs where a
  `destination-nat off` (or a broad translate) is written **less specific than**
  a translate rule it is meant to shadow, *and* the two rules land in different
  probe tiers (different prefix length, or exact-port vs wildcard-port vs
  proto-any). The **common** exemption idiom — a `/32` off written *more*
  specific than the translated block — already works today (the more-specific
  off wins). So the practical exposure is the *unusual* "broad-off-before-
  specific-translate" ordering.
- **Parity value**: xpf's charter is to clone vSRX using native Junos syntax.
  An operator who lifts a working vSRX destination-NAT config expects
  configured-order first-match. The current model can silently invert their
  intent.
- **Security value**: the fail-open is real but narrow (see blast radius). It is
  a hardening, not an acute exploit.

*If reviewers conclude the parity/security gain is too small to justify the
churn and the mixed-version/regression risk, PLAN-KILL is an acceptable
verdict* — and is made concrete as **Path Option C** below (doc + commit-time
lint, zero dataplane-semantics change).

## 4. What's already shipped / partially batched

The plan must compose with a dense history in this exact code:

- **#3844** (bfc707611): `then destination-nat off` installs a real snapshot
  entry (`Off=true`), the Rust lookup maps it to `DnatOutcome::Exempt`, and
  `Exempt` short-circuits the `.or_else` chain — giving *within-tier* "matched
  rule wins, stop." The insertion dedup (`insert_entry`, `insert_prefix_slot`)
  keeps an off entry and a translate entry with an otherwise-identical match as
  **distinct** so the exemption is not deduped away (destination.rs ~918-930,
  ~972-975).
- **#3852** (6e8b99f1f): the cross-tier most-specific-wins comment
  (destination.rs:747-756) was *added deliberately* to document the divergence.
  Reversing it is the substance of this issue.
- **#3096**: interface / routing-instance `from` scope carried as
  `from_interface` / `from_routing_instance`, AND-ed via `scope_ok`.
- **#3164**: longest-prefix-match prefix table (`DnatPrefixSlot`,
  `match_prefix_lpm`, `best_in_tier`).
- **#3437 / #3449 / #3450 / #3726 / #3857 / #4074 / #5102 / #5629**: a large
  set of fail-closed / L4-match / port-range / ICMP-identity guards in the Go
  snapshot builder (`buildDestinationNATSnapshotsWithFeeds`,
  nat_destination.go) and the Rust entry identity. Any ordinal added must be
  **orthogonal** to these — it is a new sort key, not a change to match
  semantics.
- **Go emission order is already configured order.**
  `buildDestinationNATSnapshotsWithFeeds` iterates
  `cfg.Security.NAT.Destination.RuleSets` (config/declaration order, after
  #3096 from-scope expansion) then `rs.Rules` (config order). The
  `sort.SliceStable(rulesets, …)` in `compiler_validate_strict_nat.go` operates
  on **local copies for error reporting only** and does not mutate compiled
  order. So the raw material for an ordinal already flows in config order; what
  is missing is (a) a from-context precedence sort and (b) the ordinal field
  itself.

## 5. Concrete design

### 5.1 The precedence model we are matching (Junos)

Junos destination-NAT precedence is **two-level**:

1. **Rule-set selection by `from`-context specificity**: interface > zone >
   routing-instance. The most-specific rule-set (by context *type*, not by match
   content) is chosen.
2. **Within the chosen rule-set**: rules evaluated top-to-bottom, **first match
   wins, stop**.

> **OPEN CITATION (blocks final semantics; see §11 Q1):** does Junos *fall
> through* to a less-specific rule-set when the most-specific rule-set's
> `from`-context matches but **no rule inside it** matches the packet? The plan
> must pin this against a Juniper doc before implementation. The chosen design
> below is **correct for the common cases regardless** and only this exotic
> edge depends on the answer.

xpf today models neither level faithfully: it uses **match-specificity across
tiers** (plus zone-specific-beats-zone-wildcard, plus longest-prefix) and falls
back to config-order only as a within-tier tiebreak. Notably, xpf does **not**
rank interface > zone > RI — those are AND-gates (`scope_ok`), not precedence.

### 5.2 Key insight: a single **context-ranked global ordinal** subsumes all three axes

Assign every emitted snapshot entry one monotonically increasing `ordinal`,
where emission order is:

```
sort rule-sets stably by from-context rank:
    interface-scoped      -> rank 0   (most specific)
    zone-scoped           -> rank 1
    routing-instance      -> rank 2
    fully unscoped/global -> rank 3   (least specific)
  (stable: ties keep config declaration order)
then, within each rule-set, rules in config order
then, within a rule, the existing per-(dest,port,proto,term) expansion
```

Then the Rust lookup selects the **lowest-ordinal** matching candidate across
*all* tiers. This single key correctly reproduces:

- **within-rule-set first-match** — same rule-set ⇒ ordinals in config order ⇒
  earliest config rule wins (fixes the reported bug, incl. off-vs-translate and
  the prefix-tier longest-wins divergence);
- **interface > zone > RI** — lower context rank ⇒ lower ordinal ⇒ wins
  (an improvement; xpf does not do this today);
- **zone-specific beats zone-wildcard** — subsumed: a zone/interface-scoped
  entry has a lower context rank than an unscoped one.

The head-start's "single global ordinal in configured emission order" is almost
this — the **refinement research contributes is that emission must be
context-rank-sorted first**, else a raw config-order ordinal would newly
*violate* Junos context precedence when rules span rule-sets of different `from`
types.

### 5.3 Go side (control plane)

1. **Wire field (additive).** Add to `DestinationNATRuleSnapshot`
   (`pkg/dataplane/userspace/protocol.go`):
   ```go
   // Ordinal is the Junos precedence rank of this rule, lowest-wins.
   // Encodes (from-context rank, within-config sequence). Additive wire
   // field (#1961 byte-aligned evolution): an older helper that ignores it
   // decodes 0 for every entry and falls back to the pre-#5145
   // most-specific-wins order (see §7 HA note). omitempty-safe since the
   // first rule may legitimately be ordinal 0.
   Ordinal uint32 `json:"ordinal"`
   ```
   (Use a non-`omitempty` tag so ordinal 0 is always transmitted; a `,omitempty`
   uint32 would elide the first rule's 0 and be indistinguishable from an old
   peer — see §7.)
2. **Context rank + ordinal assignment** in
   `buildDestinationNATSnapshotsWithFeeds`: before the emit loop, compute each
   rule-set's context rank from `rs.FromInterface`/`rs.FromZone`/
   `rs.FromRoutingInstance`; iterate rule-sets in `(rank, declaration-order)`
   order; maintain a monotonically increasing counter stamped onto every emitted
   entry. Because one rule expands to many entries (multi-dest, multi-port,
   multi-proto), **all entries of one rule share the rule's ordinal** — the
   sort key is the rule, not the expanded entry. Simplest: stamp
   `ordinal = ruleSeq` where `ruleSeq` increments once per rule in the sorted
   walk.
3. **Do not** change any existing fail-closed / match logic. Ordinal is purely a
   new sort key.

### 5.4 Rust side (dataplane)

1. **Decode** `ordinal: u32` onto `DnatEntry` and `DnatPrefixSlot`
   (`from_snapshots`, destination.rs ~285).
2. **Lookup rewrite** (`lookup_with_counter`, destination.rs ~615-690): replace
   the short-circuit `.or_else` tier chain with a **best-per-tier-then-min-
   ordinal** engine:
   - Each of the four tiers returns its **lowest-ordinal matching candidate**
     (not zone-specific-first / not longest-prefix). Within a tier this is one
     linear scan tracking the min ordinal among entries that satisfy
     `scope_ok` ∧ `source_matches` ∧ `l4_extra_matches` (∧ prefix `contains` for
     the prefix tier).
   - Across the ≤4 tier-winners, select the global **lowest ordinal**.
   - Map the winner's `to_outcome()` to `Exempt`/`Translate` exactly as today.
   This is **best-per-tier then argmin-ordinal**, not a full candidate gather —
   O(entries) per session miss, same asymptotic cost as today's per-tier scans.
3. **Insertion**: when two entries collide on identity+key, keep the
   **lowest-ordinal** one (config-first) rather than "later replaces earlier."
   The #3844 off-vs-translate distinctness guards are retained unchanged (off
   and translate are never deduped onto each other).
4. **Zone-specific/zone-wildcard tiering removed** as a *separate* selection
   axis — it is subsumed by ordinal (see §5.2). This deletes the
   `best_in_tier(true).or_else(best_in_tier(false))` two-pass and the
   zone-specific-first `.find()` first-arm; both collapse into a single
   min-ordinal scan. (Reviewers: verify this subsumption holds for the
   interface/RI-scoped-but-no-zone entries — those have `from_zone` empty but a
   lower context rank baked into the ordinal.)

### 5.5 Cost (critical mitigant)

The DNAT **rule-table** lookup is **per-session-miss, not per-packet**. Verified
firsthand: the single production caller is
`poll_descriptor/mod.rs:1558`, inside the session-miss handler
(`telemetry.counters.session_misses += 1` at line 1387). Established sessions
carry a cached reverse-NAT entry in the `dnat_table` BPF map and never re-run
the rule lookup. So the added scan cost (all four tiers instead of an early
short-circuit) is amortized **once per new session**, over tables that are
small in practice (handful to dozens of rules). This substantially defuses the
"gather is more expensive than short-circuit" objection.

## 6. Public API preservation

- Go: `DestinationNATRuleSnapshot` gains one additive field; all existing fields
  and JSON tags unchanged. `buildDestinationNATSnapshots(WithFeeds)` signatures
  unchanged.
- Rust: `DnatTable::lookup` / `lookup_with_counter` / `lookup_with_counter_scoped`
  public signatures unchanged (internals only). `from_snapshots` signature
  unchanged.
- No gRPC/proto surface change (snapshot is the internal userspace-dp wire, JSON
  over the control socket).

## 7. Hidden invariants the change must preserve

- **Fail-closed match semantics (#3437/#3449/#3450/#3726/#3857/#4074/#5102)**:
  ordinal is orthogonal; none of the source/dest/port/ICMP/pool guards move.
- **#3844 off-vs-translate distinctness**: an off entry and a translate entry
  with an otherwise-identical match stay distinct; ordinal does not collapse
  them.
- **HA session-sync portability (mixed-version, #2239/#3931)**: the wire field is
  additive, so an old helper decoding a new snapshot ignores `ordinal` (defaults
  0) and applies pre-#5145 most-specific-wins; a new helper decoding an old
  snapshot sees all-zero ordinals and — **this is the trap** — would treat every
  rule as equal precedence. The plan must ensure the all-zero case degrades to a
  *deterministic* order (e.g. insertion order), not undefined. During a rolling
  HA upgrade the two nodes could resolve a **freshly, independently created**
  session differently (one first-match, one most-specific). **Mitigant**:
  synced sessions carry the *resolved* translation via the `dnat_table` BPF map
  publish (`publish_dnat_table_entry`), so the peer does **not** re-run the rule
  lookup for a synced session — only sessions created independently on each node
  during the upgrade window differ, which is the normal failover semantics
  anyway. **Reviewers must confirm** session-sync carries the resolved DNAT
  decision (not a re-lookup) before we conclude a version gate is unnecessary
  (§11 Q2).
- **Determinism**: two rules that tie on ordinal must never exist (ordinal is a
  dense per-rule sequence); the min-ordinal argmin must be deterministic on any
  residual tie (keep first-scanned).
- **Local-address (proxy-ARP/ND) registration**: unaffected — off entries remain
  excluded, translate entries still register `destination_ips`.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED–HIGH** | Reverses documented #3852 behavior. Any config relying on most-specific-wins (broad-off-after-specific-translate, or longest-prefix beating an earlier broad translate) changes disposition. Cross-rule-set resolution *also* changes (now interface>zone>RI + config order). Mitigated by: the change moves *toward* documented Junos semantics; extensive unit coverage; per-rule-set common idiom already matches. |
| Lifetime / borrow-checker | **LOW** | `u32` field; scans borrow `&self` as today. No new lifetimes. |
| Performance regression | **LOW** | Lookup is per-session-miss (verified §5.5), not per-packet; best-per-tier scans are O(entries), same asymptotics; adds a 4-way min-ordinal compare. Negligible at session-creation rate on small tables. |
| Architectural mismatch | **MED** | The multi-rule-set fall-through edge (§5.1 open citation) is the one place the single-ordinal model may diverge from Junos. If Junos does *not* fall through, a pure lowest-ordinal argmin is wrong in that exotic case and a rule-set-scoped selection would be needed. Bounded and flaggable — not a #961-style dead-end. |

## 9. Test plan

- `cargo build` clean; full `userspace-dp` cargo suite green (the DNAT suite is
  large: `tests_destination.rs`, `tests_dnat_proto.rs`, `tests_l4_match.rs`,
  `tests_scope.rs`, `tests_counter.rs`, `tests_pool.rs`).
- **New unit tests** (the load-bearing verification, since smoke is blocked —
  §9.1):
  1. broad-off (/24) *before* specific-translate (/32) in one rule-set ⇒ off
     wins (the reported bug);
  2. broad-translate before specific-translate, same rule-set ⇒ earlier wins;
  3. exact-port off before wildcard-port translate ⇒ off wins;
  4. proto-any off before exact-proto translate ⇒ off wins;
  5. two prefixes, shorter configured earlier ⇒ shorter (earlier) wins (reverses
     longest-prefix-in-tier);
  6. interface-scoped rule-set vs zone-scoped rule-set both matching ⇒
     interface wins (interface>zone precedence);
  7. specific-off-more-specific-than-translate (the common idiom) ⇒ still off
     wins (no regression);
  8. all-zero-ordinal decode (old-peer snapshot) ⇒ deterministic fallback order.
- Go: `go test ./pkg/dataplane/userspace/... ./pkg/config/...` — snapshot
  builder emits ordinals in context-ranked config order.
- **`make test` runs both legs** (Go + Rust cargo) per project rule.

### 9.1 Smoke deferral (explicit)

This is a Rust dataplane change → cluster iperf/functional smoke is **blocked by
the loss-cluster shim-ABI wall** (pinned cpumap=16 vs repo 256; verify-dataplane
fail-closes every cluster-deploy — see `project_loss_cluster_shim_abi_wall`).
The plan's confidence rests on the **design review + unit tests**, not live
smoke. This deferral is noted so the `/engineer` PR does not block on
unreachable smoke; a functional DNAT-precedence smoke should run when the ABI
wall clears.

## 10. Out of scope (explicitly)

- **Source-NAT and static-NAT precedence** — this issue is destination-NAT only.
  Source-NAT precedence (#4161 was a different scope) is a separate audit.
- **Multi-rule-set fall-through final semantics** — if §11 Q1's citation shows
  Junos does not fall through, the rule-set-scoped selection refinement is a
  follow-up; the shipped fix is correct for the within-rule-set case (the
  reported bug) and no worse than today for the exotic fall-through edge.
- **NAT rule-set from-context precedence for source/static NAT** — out of scope.
- **Any change to the fail-closed match guards** — untouched.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Junos fall-through citation.** Does Junos evaluate only the single
   most-specific rule-set (and apply no NAT if it has no matching rule), or does
   it fall through to less-specific rule-sets? A Juniper doc citation is
   required. If "no fall-through," is the lowest-ordinal argmin wrong in the
   exotic edge, and does that justify a rule-set-scoped selection instead? **Is
   the whole issue better scoped to within-rule-set only, leaving cross-rule-set
   untouched?**
2. **HA mixed-version.** Is the additive-ordinal + all-zero-fallback sufficient,
   or does the semantics change require a version gate? Does session-sync carry
   the *resolved* DNAT decision (so synced sessions don't diverge across a
   rolling upgrade), or does the peer re-run the rule lookup? (This determines
   whether a flag-day is needed — §7.)
3. **Match-engine cost.** Is "best-per-tier then argmin-ordinal, once per session
   miss" genuinely negligible, or is there a pathological table (thousands of
   prefix rules) where the full per-tier scan hurts session-establishment rate?
   Is there a cheaper design that still reverses tier precedence?
4. **Is the parity gain worth reversing a documented decision?** #3852
   deliberately documented most-specific-wins. The common exemption idiom
   already works. Does the narrow fail-open (broad-off-before-specific-translate)
   justify MED–HIGH behavioral-regression risk + an HA-window semantics change?
   **Would Path Option C (below) — keep most-specific-wins, add a commit-time
   lint that warns when a broad `off`/translate is shadowed by a more-specific
   later translate in the same rule-set — deliver the security value at a
   fraction of the risk?**
5. **Ordinal as the sole key vs a tie-breaker.** Is collapsing zone-specific/
   zone-wildcard + interface>zone>RI + config order all into one context-ranked
   ordinal actually equivalent to Junos, or does folding context rank and config
   sequence into one integer lose a case (e.g. two rule-sets of the same context
   type both matching)? Should context rank and config index be *separate* keys
   compared lexicographically instead of a single fused integer?

### Path Options (for reviewer selection)

- **Option A (RECOMMENDED)** — context-ranked global ordinal + best-per-tier
  argmin-ordinal lookup (§5.2–5.4). Most parity-faithful; fixes the reported bug
  and the cross-rule-set precedence gap. MED–HIGH regression risk.
- **Option B** — within-rule-set ordinal only; preserve current cross-tier
  tiering *across* rule-sets. Lower regression surface but ill-defined (still
  needs a cross-rule-set winner rule) and not more correct than A. Documented
  for completeness; likely rejected.
- **Option C (PLAN-KILL candidate)** — keep most-specific-wins; add a
  commit-time lint that flags when a `then destination-nat off` (or a broad
  translate) in a rule-set is shadowed by a more-specific *later* translate,
  making the fail-open **operator-visible** at commit with zero dataplane /
  wire / HA change. Lowest risk; parity gap remains but is no longer a silent
  surprise. Valid if reviewers judge A's churn unjustified.
