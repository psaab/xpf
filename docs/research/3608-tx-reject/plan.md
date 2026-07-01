# Plan: output firewall-filter `then reject` on the TX/CoS path — active reject vs silent drop (#3608)

## 1. Status

CONVERGED v2 — **PLAN-DEFER**. 3-of-3 reviewers (Claude SMR + Codex + AGY) agree:
implement **option (c)** (commit-time warning) as the immediate increment; keep
#3608 open with **option (a)** (active reject synthesis) as the deferred
design-of-record, gated on the prerequisites in §10.

Research-only. No PR, no production source changes in this pass. Implementation
begins only on an explicit `/engineer 3608` after manual approval.

Base: origin/master `a2c524281` (research worktree
`.claude/worktrees/3608-research`, branch `research/3608-tx-reject`).
Reviews: `claude-smr-plan-r1.md` (READY-w/revisions) → `claude-smr-plan-r2.md`
(converged DEFER), `codex-plan-r1.md` (DEFER-c), `agy-plan-r1.md` (DEFER-c).

## 2. Issue framing

On the TX/CoS forwarding path, a **transit** packet matching an OUTPUT
firewall-filter terminal `then reject` term is realized as a **silent drop**
instead of an **active reject** (TCP RST for TCP, ICMP/ICMPv6 admin-prohibited
unreachable otherwise). The security boundary IS enforced — the packet never
egresses — but the source sees a timeout rather than an RST/unreachable.

Input-filter, lo0/host-bound, and policy `then reject` are already active
(#2089 policy, #2521 filter input/lo0, #3071 zone-tcp-rst, #3445 lo0 nft).
Output firewall-filter reject on the transit egress path is the remaining
residual, documented but (until #3608) untracked (M11).

Folds: **M11** (issue-history entry for the follow-up), **L05** (reusable
reject-reply synthesis independent of inbound descriptor ownership).

## 3. Honest scope/value framing (why DEFER)

**The win:** Junos parity + operator diagnostics — the remote endpoint gets an
RST/unreachable instead of a timeout for output-filter `then reject`.

**Not a security fix.** The drop already denies the traffic correctly. Severity
**Medium** (Codex H03) — a parity/observability gap on an ALREADY-enforced
action, not an open hole.

**Why the converged verdict is DEFER, not READY:** the active-reject synthesis
(option a) is feasible but NOT the low-cost slam-dunk v1 implied. Five costs
(detailed in §5.4 / §8), each verified against source by Codex + AGY:
1. cross-module helper API boundary (`SessionKey` vs `SessionFlow`, `pub(super)`
   visibility);
2. the borrow/precedent claim was overstated (#2301 builds an owned Vec, does not
   hold a UMEM slice across the tx_pipeline mutation);
3. reflection source-address is an unresolved PRODUCT decision (TCP RST spoofs
   the original destination);
4. the shared Reject rate-limiter caps aggregate, not fairness — output reject
   would starve policy/input reject diagnostics;
5. a pre-existing NAT-tuple output-filter evaluation mismatch means active reject
   in NAT cases would fire on a match set that already diverges from Junos.

For a Medium diagnostic niche where the drop already enforces, these push option
(a) under the value bar for now. Option (c) captures the operator-visible gap
cheaply and immediately.

## 4. What's already shipped / partially batched

The forward/TX path already synthesizes-and-reflects a generated reply back out
the ingress interface (#2301/#2328 egress-MTU PTB, `tx/dispatch/mod.rs:1135-1185`)
and the reusable reject interface exists (#2521, `enqueue_filter_reject_reply`).
So the pieces exist — but see §5.4 for why reusing them at the transit-reject
sites is more than wiring:

- #2301 (`292ae40cf`, 2026-06-21) predates #2521 (`541b7d9f5`, 2026-06-24), so the
  #2521 README "lacks packet context" note was a scoping decision, not a hard
  blocker. HOWEVER, #2301's pattern builds an OWNED `Vec` reply and enqueues after
  the ingress borrow ends — it does NOT prove that a UMEM slice can be held while
  mutating `ingress_binding.tx_pipeline` (Codex #3). Reflection at the transit
  sites would need an owned-frame copy first.
- `enqueue_filter_reject_reply(..., flow: &SessionFlow, ...)` (`reject_reply.rs
  :70-78`) is `pub(super)` in `poll_descriptor`; `PendingForwardRequest` carries
  `flow_key: Option<SessionKey>` (`types/tx.rs:73-84`), not a `SessionFlow`. The
  dispatch/slow-path sites cannot call it as-is (Codex #2).

## 5. Concrete design

### 5.1 Root cause (file:line, current master)

`CoSTxSelection` / `CachedTxSelectionDescriptor` carry only `drop: bool`, set by
collapsing the action:
- `tx/cos_classify.rs:230` (cached):
  `drop: output_result.action != FilterAction::Accept`
- `tx/cos_classify.rs:412` (runtime):
  `drop = output_result.policer_drop || output_result.action != Accept`

`FilterAction` (`filter/mod.rs:42`) is `Accept | Discard | Reject`; the `Reject`
variant is present at compute time and discarded.

### 5.2 Live drop sites (CORRECTED from v1 — key research finding)

There are **two** live transit-reject drop sites, not three. Verified: every
production `PendingForwardRequest` sets `cos_tx_selection_resolved: true`
(`forward_request.rs:232`, `icmp.rs:268`, `poll_descriptor/mod.rs:1998`); there is
NO `cos_tx_selection_resolved: false` setter, so
`pending_forward_needs_cos_tx_selection` (`dispatch/cos.rs:165`) is always false
and the `if cos.drop` at **`tx/dispatch/mod.rs:136` is DEAD CODE** in production
(Codex #1, AGY #1, SMR B1).

Live sites:
1. **HOT cached** — `poll_descriptor/flow_cache_hit.rs:181`
   (`if tx_selection.drop || policer_action.drop`). Has the original
   `packet_frame` (line 92), the ingress `tx_pipeline`, `meta`, `flow:
   &SessionFlow`, `forwarding`, counters. The established-flow arm (most packets).
2. **SLOW build** — `forward_request.rs:215` (`if cos.drop { return None }`),
   surfaced to callers `poll_descriptor/mod.rs:3444` (main transit forward-
   candidate, first packet, carries NAT) and `:1057` (fabric-return). The builder
   does NOT own `tx_pipeline`/counters, so an Option-API change
   (`ForwardBuildOutcome { Request | Drop | Reject }`) is required across all
   callers incl. `flow_cache_hit.rs:402` (Codex non-blocking, SMR B1).

Sites that must be EXCLUDED (generated-reply drops — NOT transit traffic; already
correctly silent, must never synthesize a reject): `poll_descriptor/mod.rs:1973`
(generated ICMP-error, `Prebuilt`), `tx/dispatch/mod.rs:1150` (#2328 PTB classify),
`classify_generated_reply` internal drop (`reject_reply.rs:222`). (SMR B2.)

### 5.3 Gating invariant for a `reject` discriminator (if option a is later built)

Add `reject: bool` to `CoSTxSelection` + `CachedTxSelectionDescriptor` (in-memory
only; no wire/proto impact), set **solely** from `output_result.action ==
FilterAction::Reject` — decoupled from BOTH policer paths
(`output_result.policer_drop` at cos_classify.rs:412 AND the per-packet
`policer_action.drop` at flow_cache_hit.rs:158). Synthesis fires iff `reject ==
true`; a policer-only drop of an accepted packet keeps `reject == false` and stays
silent (AGY #2). `reject ⟹ drop` always; the transit frame is always dropped
regardless of synthesis outcome (fail-closed).

### 5.4 Option comparison (the design fork)

- **(a) Active reject synthesis at the two live sites (DEFERRED design-of-
  record).** Recover the `Reject` signal (§5.3), copy the original inbound frame
  to an owned buffer, reconstruct a `SessionFlow`, widen/hoist
  `enqueue_filter_reject_reply`, add the `ForwardBuildOutcome` enum, wire at
  flow_cache_hit.rs:181 + the mod.rs:3444/1057 callers. Correct for the non-NAT
  common case; carries the five costs in §3/§8. **Deferred**, gated on §10.
- **(b) Move the reject decision pre-TX.** The egress output filter is keyed on
  the post-routing egress ifindex, only known after routing — i.e. exactly where
  forward_request already runs. A "reject once at establishment" variant
  under-generates vs Junos (which rejects every packet); a "cache the signal,
  synthesize per-packet" variant IS option (a). **Rejected as a distinct path.**
- **(c) Commit-time warning, keep the drop (RECOMMENDED, ship now).** Emit a
  commit-time WARNING that an interface `filter output ... then reject` is
  realized as a drop the userspace dataplane cannot actively reject, naming
  interface/unit/filter/term. Hook: `pkg/config/compiler_validate_warn.go`,
  mirroring the #3445 lo0-mirror-modifier and #3295 no-catch-all warn-not-reject
  precedents. Warn-only on BOTH strict and lenient paths (#1960 no-brick); EXCLUDE
  lo0/host-bound interfaces (they actively reject via #2521/#3445). Small,
  low-risk, operator-visible.

## 6. Public API preservation

- No gRPC/HTTP/proto/CLI change. `filter output ... then reject` already
  parses/compiles; option (c) only adds a warning string. Option (a)'s `reject`
  field is on `pub(super)`/`pub(in crate::afxdp)` in-process structs — not
  serialized to disk/wire/control-socket.
- Option (c) is warn-only, never a new reject; lenient path unchanged (#1960).

## 7. Hidden invariants the change must preserve

Option (c): the warning must NOT fire for lo0/host-bound (#2521/#3445 reject
there); must be warn-only (never reject at commit — the config is valid, it
degrades); must fire on BOTH v4 and v6 output-filter bindings.

Option (a), if later built: `reject` set only from `action == Reject` (§5.3);
synthesis only on a live transit frame at the two live sites, never on
`Prebuilt`/generated frames (§5.2); reply egresses the ingress interface; no
reply loop (`classify_generated_reply` fails closed); hot path adds only a field
read on the accept path.

## 8. Risk assessment (4-class)

Option (c) — the recommended increment:

| Class | Level | Detail |
|-------|-------|--------|
| Behavioral regression | LOW | Warn-only; no dataplane change; config still compiles. |
| Lifetime / borrow | N/A | Go config compiler; no unsafe. |
| Performance | NONE | Commit-time only. |
| Architectural mismatch | LOW | Exact #3445/#3295 warn-not-reject precedent. |

Option (a) — why it is deferred (the five costs):

| # | Cost | Evidence |
|---|------|----------|
| 1 | Cross-module API boundary | `flow_key: Option<SessionKey>` (types/tx.rs:73-84) vs `flow: &SessionFlow` (reject_reply.rs:70-78); helper is `pub(super)`. |
| 2 | Borrow pattern not free | #2301 builds an owned Vec + enqueues after borrow ends (dispatch/mod.rs:1135-1185); needs an owned-frame copy. |
| 3 | Reflection semantics = product decision | TCP RST spoofs original dest (frame/tcp.rs:555-627); ICMP from ingress primary (icmp.rs:541-560). |
| 4 | Shared limiter caps aggregate, not fairness | one Reject bucket (reject_reply.rs:167-179, icmp_ratelimit.rs 1000/s) → output reject starves policy/input reject. |
| 5 | Pre-existing NAT-tuple mismatch | egress filter evaluated on pre-NAT key (forward_request.rs:175); NAT64 v4 filter sees v6 key. |
| — | Hot-path touch | flow_cache_hit.rs:181 is the established-flow arm. |

## 9. Test plan

Option (c) (at `/engineer` time):
- Go unit: an interface `filter output` whose filter has a `then reject` term
  emits the warning (v4 and v6); a `then discard`/`then accept` term does NOT; an
  lo0/host-bound `then reject` does NOT (excluded); strict AND lenient both
  warn-and-compile (never reject). Fail-on-revert: remove the check → no warning.
- Smoke: `commit` a config with `set interfaces reth0.80 unit 80 family inet
  filter output block term t ... then reject`; confirm the commit succeeds with
  the warning shown; confirm traffic is still dropped.

Option (a) (only if later approved) — full Rust suite + loss-cluster smoke
(tcpdump for the inbound RST/ICMP on the source); NAT/NAT64 reflection-family
checks; fail-closed (budget/bucket/fragment/inbound-RST); no-loop; policer-gating.

## 10. Out of scope / follow-ups

- **Option (a)** deferred, gated on: (i) demand for the hot-path touch; (ii) a
  decision on reflection source-address semantics (§8 #3); (iii) a fairness/budget
  answer for the shared Reject limiter — **own follow-up** (per-source or
  per-interface reject budget so output reject cannot starve policy/input reject,
  Codex #5 / AGY N3); (iv) resolution of the **pre-existing NAT-tuple output-filter
  evaluation mismatch** — **own issue** (forward_request.rs:175 evaluates the
  egress filter on the pre-NAT key; Junos uses post-NAT; NAT64 mismatches family,
  AGY N1). These last two are pre-existing and orthogonal to reject-vs-drop.
- Fabric-redirected egress output filters (peer owns the egress filter).
- A distinct `output_filter_reject_sent` counter (reuse `filter_reject_sent` if
  (a) is ever built).
- **M11:** RESOLVED by #3608 existing. `docs/issues/issue-history.md` is GENERATED
  from GitHub (`/sync-history`), not hand-edited, so #3608 appears on the next
  regen; no manual doc row (and none permitted under the `/research`
  no-production-source rule).

## 11. Open questions — RESOLVED at convergence

1. Value vs hot-path touch → **DEFER; ship (c) now** (3-of-3).
2. Site-3 shape → `ForwardBuildOutcome` enum across mod.rs:3444/1057 +
   flow_cache_hit.rs:402 (broader than v1 admitted) — deferred with (a).
3. Site-2 frame availability → moot; site 2 (dispatch/mod.rs:136) is DEAD code.
4. Reflection source-address → unresolved PRODUCT decision; prerequisite for (a).
5. Backscatter fairness → shared bucket is insufficient; **own follow-up** before
   (a).
6. Counter attribution → reuse `filter_reject_sent`; revisit with (a).
7. Deferred cos.rs path → confirmed unreachable for reject (dead site 2).
