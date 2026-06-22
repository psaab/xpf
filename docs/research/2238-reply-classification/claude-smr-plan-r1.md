# Claude SMR — hostile plan review r1 — #2238

Role: adversarial reviewer. I am trying to FAIL this plan, not bless it. The
default disposition is "this is wrong until proven otherwise."

Verdict: **PLAN-READY with required dispositions folded into plan r2** (the
plan already reflects these — this file is the audit trail of what I attacked
and why each survived or changed the plan).

---

## A1 — [MAJOR → resolved] Fail-OPEN on parse failure contradicts the project's fail-closed dogma

The plan (§6.2) says: if the bytes→key parser fails, emit the reply
UNCLASSIFIED (no drop, default queue). The whole project is fail-closed
(CLAUDE.md, engineering-style §"Overflow / failure policy"). A reviewer will
reflexively flag this.

**My attack:** an output filter `then discard protocol icmp` is a security
control. If the parser fails, we emit the ICMP error the operator wanted
suppressed → security bypass. Fail-OPEN here = the bug, restated.

**Counter (why it survives):** the bytes were built ~microseconds earlier by
OUR builder from a frame WE already parsed. A parse failure is a 100%-internal
logic bug, not adversary-controlled. Two sub-cases:
- If we fail-CLOSED (drop), a parser bug silently eats ALL generated replies of
  that shape — a far worse, harder-to-diagnose outage (control plane goes
  quiet, no counter unless we add one anyway).
- If we fail-OPEN + counter, the reply still flows (degraded: default queue, no
  filter) and the counter screams.

**Disposition:** KEEP fail-open BUT this is genuinely arguable; the plan now
(§6.2) explicitly invites reviewers to challenge it and states the threat model
(internal-only). I will accept Codex/AGY overriding to fail-closed IF they also
require the dedicated counter — either way the counter is mandatory. The one
thing that is NOT acceptable is silent-anything. **Plan must keep the counter
unconditional.** ✅ it does.

## A2 — [MAJOR → resolved] "ports = 0 for ICMP" can mis-key an output filter

`generated_reply_session_key` sets ports=0 for ICMP. If an operator's egress
output filter has a term `from { protocol icmp; destination-port 0; }` or a
range that includes 0, classification could match spuriously.

**Attack:** prove the filter eval treats port 0 as a real value, not "absent".

**Investigation needed → folded into plan §9/§11 test:** the existing transit
path ALREADY keys ICMP with whatever ports the meta carries (ICMP meta ports
are 0 today too). So this is not a NEW divergence — ICMP-with-port-0 is the
status quo for transit. The plan's risk table (§11) and test (§9.1 "ICMP term +
port term coexist") cover it. **Disposition:** acceptable; the fix does not
make ICMP port-keying worse than transit. Reviewers must confirm
`evaluate_filter_ref_tx_selection_*` does not treat a `destination-port`
constraint as matching protocol-ICMP traffic (it shouldn't, because the term
also requires `protocol icmp` which has no L4 ports — but a malformed
port-only term is the edge). ✅ flagged for /engineer.

## A3 — [MEDIUM, DISAGREE with plan's deferral] Embedded-ICMP NAT path should be IN scope

The plan (§10) defers `poll_descriptor/mod.rs:1182` (embedded-ICMP NAT
reversal) as a sibling. I attack this: the issue's TITLE says "ICMP-unreachable
/ Time-Exceeded ... bypass output-filter/CoS/DSCP" — the embedded-ICMP NAT
reply is an ICMP error that ALSO classifies on the trigger
(`resolve_cos_tx_selection_at(..., meta, Some(&flow.forward_key), ...)`). It is
the SAME bug shape. Deferring it leaves the issue half-fixed.

**Plan's counter (§10):** it is a *forwarded/NAT-reversed* frame, not
host-originated; the issue body enumerates only host-generated replies
(Time Exceeded, reject, SYN-cookie). Pulling the NAT path in widens blast
radius into NAT.

**My disposition:** I partially CONCEDE but require the plan to (a) explicitly
name it as a known-identical sibling (done, §1.1 + §10) and (b) file the
sibling issue as part of `/engineer`'s deferred list, not "maybe later." This
is the engineering-style "don't silently defer" rule. The plan now records it
as a named follow-up with a concrete reason. **Acceptable IF the follow-up is
actually filed.** I will NOT block PLAN-READY on folding it in — the host-
generated set is a coherent, shippable unit, and the NAT path's trigger-tuple
classification is arguably less wrong (the NAT-reversed frame's tuple ≈ the
trigger's reversed tuple, and it IS a transit frame so input-mirror covers it).

## A4 — [MEDIUM → resolved] Path B claims "zero hot-path cost" — verify the reject/cookie paths are truly cold

The plan asserts reject/cookie are `#[cold] #[inline(never)]`. I verified from
the source quotes in the plan: `enqueue_policy_reject_reply` and
`enqueue_syn_cookie_reply` are both `#[cold] #[inline(never)]`. Time Exceeded
fires only when `packet_ttl_would_expire == Some(true)` (TTL≤1), a rare
exception. **Disposition:** claim stands. BUT — the NEW parser
`generated_reply_session_key` must NOT be force-inlined into any hot caller; it
is only called from cold paths, so leave it un-attributed (LTO is off per
CLAUDE.md memory, so no accidental cross-module inline). Add to plan §8? Minor;
noted here for /engineer.

## A5 — [MEDIUM → resolved] Time Exceeded egress-ifindex change is a behavior change riding in a bug fix

The plan (§4.3) corrects Time Exceeded to classify on `target_ifindex` (real
egress) instead of `ingress_ident.ifindex`. That is a SECOND behavior change.
engineering-style §"Narrow scope": "Bug fix and behaviour choice do not ride in
the same PR."

**Attack:** split it out.

**Counter:** it is not a behaviour *choice* — it is part of the SAME bug.
Classifying a generated reply on the wrong INTERFACE's output filter is the
identical defect class as classifying it on the wrong TUPLE. The issue is
"classified by the trigger, not the generated packet"; the trigger's
*interface* is as wrong as the trigger's *tuple* when `bind_ifindex` differs.
**Disposition:** KEEP in scope; the plan (§4.3, §11) calls it out explicitly as
a correctness component with its own test. A reviewer wanting it split is
reasonable but I judge it the same bug. If Codex insists, it is a trivial split.

## A6 — [LOW → resolved] Counter wire-contract: don't repeat #1961

New counters cross the Go↔Rust snapshot wire. The plan (§8, §11) already cites
#1961/#1976/#1977 and requires `protocol_wire_v1.json` regen + decode test +
reflection guard. ✅ Good. I add: the counters should be `u64` saturating, and
the Go side must use the `WireUint8List`/numeric-wire discipline if any list is
added (none is — these are scalar counters, low risk).

## A7 — [LOW] "mirror deferred" leaves `mirror_clone: false` looking like a bug

Deferring mirror means the next reviewer sees `mirror_clone: false` and
re-opens this. The plan (§4.4) requires a code comment cross-referencing the
follow-up issue. ✅ Sufficient. Ensure the comment names the issue number once
filed.

## A8 — [LOW] Acceptance test "no ICMP error reaches the source" needs the right env

The §9.5 feature validation uses the standalone VM. Time Exceeded requires a
TTL-expiring transit flow. The standalone VM topology (CLAUDE.md) supports
trust↔untrust transit; a `ping -t 1` through it expires TTL at the firewall.
Output filter on the egress (untrust) interface. Feasible. ✅ No smoke cluster
needed for the classification logic (pure unit tests carry the weight).

---

## Things I tried to break and could NOT

- **Double-counting filter counters:** Path B reuses
  `resolve_cos_tx_selection_at` (runtime-counted) exactly once per generated
  reply, same as transit charges once per forward. No double-count. ✅
- **HA/fabric state leak:** classification reads only per-node `ForwardingState`
  + the local bytes. No synced/shared state. Fabric Time Exceeded is already
  suppressed (`FABRIC_INGRESS_FLAG`). ✅
- **Allocation on hot path:** parser works over `&[u8]`, returns a stack
  `SessionKey` + `ForwardPacketMeta` (Copy-ish small structs). No per-packet
  alloc; and it is cold anyway. ✅
- **Budget-gate ordering:** budget check stays BEFORE build/classify; a reject
  flood cannot starve transit TX frames via classification (classification does
  not take a frame). ✅

---

## Required for PLAN-READY (all reflected in plan r2)

1. Parse-failure handling is explicit + counter is unconditional (A1). ✅
2. Embedded-ICMP NAT sibling is NAMED as a follow-up, not silently dropped
   (A3). ✅
3. Time Exceeded egress-ifindex correction is justified as same-bug, with a
   test (A5). ✅
4. Wire-contract regen + decode test mandated for new counters (A6). ✅
5. Mirror deferral carries a code-comment cross-ref to the filed follow-up
   (A7). ✅
6. ICMP-port-0 keying confirmed not-worse-than-transit + edge test (A2). ✅

## Open questions for Codex / AGY (genuine disagreement welcome)

- **Q1:** fail-open vs fail-closed on internal parse failure (A1). I lean
  fail-open + counter; willing to be overruled to fail-closed + counter.
- **Q2:** pull the embedded-ICMP NAT path into THIS PR or defer (A3). I defer;
  argue me out of it if the NAT-reversed tuple classification is materially
  wrong in a way input-mirror does not cover.
- **Q3:** split the Time Exceeded egress-ifindex correction into its own PR
  (A5). I keep it in; trivially splittable if required.

**SMR r1 verdict: PLAN-READY (Path B).** No architectural defect found that
blocks planning. The three open questions are tuning, not blockers.
