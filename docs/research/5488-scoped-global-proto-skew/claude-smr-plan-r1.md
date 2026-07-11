# Claude SMR — hostile plan review r1 (#5488)

Reviewing: `docs/research/5488-scoped-global-proto-skew/plan.md` r1 @ base `4e0c7f74cf0d`.
Stance: adversarial. Goal is to break Path C's "uniformly fail-closed" claim and
to test whether a version bump is truly avoidable.

## Verdict

**PLAN-READY-WITH-REQUIRED-REVISIONS.** The plan is directionally correct and
Path C's deny/reject widening genuinely discharges the STATED invariant (deny
coverage never silently narrows) — but two material facts are missing and MUST
be folded into r2 before this is `/engineer`-ready. Neither kills Path C; both
sharpen the A-vs-C decision. First-pass PLAN-READY would have been a soft-pass;
these are the corrections.

## Findings

### F1 (MATERIAL) — "version 3" is a THREE-generation collision, not two.

The plan frames the skew as pre-#4626 vs post-#4626. That understates it.
`git log` proves `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3` has been fixed since
`8477cf1a6` (#1567, the protocol-module split), and BOTH scoped-global commits
landed on top of it WITHOUT a bump:
- `eb42f8404` #3148 — introduced the SINGULAR `match_from_zone/match_to_zone`.
- `572952745` #4626 M03 — introduced the PLURAL `match_from_zones/…_zones`.

So version 3 spans (at least) three helper generations:
- **gen1** (pre-#3148): no scoped-global support — ignores BOTH singular and
  plural → treats every global as any-zone on both sides.
- **gen2** (#3148 … #4626): honors the SINGULAR field only.
- **gen3** (#4626+): honors the PLURAL, prefers it.

Consequence for Path C, per verdict, across generations:

| Verdict | gen1 (ignores scope) | gen2 (singular only) | gen3 (plural) |
|---|---|---|---|
| deny/reject → singular `""` | any-zone deny = **over-deny (fail-closed)** | empty→any-zone = **over-deny (fail-closed)** | correct |
| permit → singular first-zone | any-zone permit = **OVER-PERMIT (FAIL-OPEN)** | first-zone = under-permit (fail-closed) | correct |

**The deny/reject widening is robust across ALL three v3 generations** (gen1 and
gen2 both resolve empty/absent from-scope to any-zone → over-deny). This is the
key result: Path C fully discharges the #5488 invariant, which is explicitly
about DENY coverage ("the trust→untrust deny silently vanishes").

**But Path C's permit-narrow is NOT robust against gen1**: a gen1 helper ignores
the singular field, so a scoped-global PERMIT becomes an any-zone permit =
fail-OPEN. This is a PRE-EXISTING fail-open (gen1 predates #3148/#4626; it was
never covered) and is OUTSIDE #5488's named scope (deny coverage), but the plan
must not claim Path C is "uniformly fail-closed for every verdict across every
old helper" — it is uniformly fail-closed for deny/reject across all v3 gens,
and for permit only against singular-honoring (gen2+) helpers. Only a version
bump (Path A) fail-closes gen1's scoped-permit hole.

**Required r2 change:** add the three-generation table; scope the Path C safety
claim precisely (deny/reject robust across all v3 gens; permit-narrow robust
only vs gen2+); state that gen1's scoped-permit over-permit is pre-existing,
out of #5488's deny-coverage scope, and closed only by Path A.

### F2 (MATERIAL) — the SYMMETRIC skew direction (helper newer than Go).

The plan analyzes only the new-Go/old-helper direction (Go emits plural, old
helper ignores it). The reverse — **old Go (pre-#4626, emits singular-only, no
plural) driving a NEW gen3 helper** — also narrows the deny: gen3's
`effective_match_zones` finds an empty plural and falls back to the singular
first-zone → deny resolves to `{first-zone}` → `trust→untrust` deny vanishes =
fail-open. This happens on a node where the helper binary was upgraded BEFORE
xpfd (helper-first partial deploy). Snapshots are node-local (each Go drives its
own helper), so this is a real node-local partial-upgrade state.

- **Path C cannot fix this** — it changes what NEW Go emits; it cannot
  retroactively change already-shipped OLD Go (which emits singular-first).
- **Path A closes it** — a v4 gen3 helper rejects the old Go's v3 snapshot via
  the strict `!=` gate → fail-closed.
- **Path B does not close it** — old Go has no capability-check code, so it
  publishes anyway and the new helper falls back to singular.

Like F1, this is pre-existing (old Go always emitted singular-first), so Path C
does not REGRESS it — but the plan's recommendation section must be honest that
**only Path A closes BOTH skew directions and the gen1 permit hole**, whereas
Path C closes exactly the #5488-named direction (new-Go/old-helper deny
narrowing) with zero deploy cost.

**Required r2 change:** add the symmetric-direction analysis; update the
recommendation to state explicitly that Path C is a COMPLETE fix for the #5488
invariant (deny coverage, new-Go/old-helper) and a NON-REGRESSION for the
symmetric/gen1 cases, while Path A is the only path that closes the entire
multi-generation v3 collision — at the all-configs flag-day cost.

### F3 (CONFIRMED, not a defect) — deny-widen ordering is safe.

I tried to break deny-widening with policy ordering. Widening a scoped deny to
any-zone can only ADD denied zone-pairs; under Junos first-match it can shadow a
LATER permit (→ that pair is denied = fail-closed) but can never permit a pair
that was denied. An EARLIER permit still wins on both helpers (unchanged). No
ordering produces a fail-open from deny-widening. Path C's deny direction holds.

### F4 (CONFIRMED, not a defect) — host-inbound widen is availability-only.

A scoped host-inbound deny (`to-zone junos-host` from `[dmz trust]`) keeps
to-singular = `junos-host` (single token, unchanged) and widens from → `""`.
gen2 still sees `to-zone=junos-host` → arms the host gate → applies the deny
from any zone. That can shadow a later mgmt host-inbound permit → mgmt lockout,
which is an AVAILABILITY regression, never fail-open (losing your own SSH is not
a security hole). The plan's Q3 already flags this; keep it, but the correct
framing is "availability, fail-closed," which the plan gets right.

### F5 (NIT) — quantify gen1 reachability or stop implying two generations.

The plan should either (a) note gen1 (pre-#3148) helpers may be rare/EoL and the
practical concern is gen2, or (b) not assert two-generation framing. Given the
version has been 3 since #1567, the honest statement is "an unknown number of
v3 helper generations exist; the deny-coverage fix (Path C widen) is robust
across all of them; the version bump is the only way to make version-3 a
truthful capability statement."

### F6 (CONFIRMED) — Path A blast radius is correctly stated.

I verified the strict `!=` gate (`snapshot.rs:25,376`) and the unconditional
`Version: ProtocolVersion` stamp (`builder.go:32,79`, `manager_generation.go:112`).
The plan's claim that Path A is a hard flag-day for ALL configs is correct, and
the observation that it silently retargets the `>= ProtocolVersion`
scheduler/NAT gates (`manager_compile.go:551-593`) to require 4 is correct and
well-surfaced.

## Bottom line

Path C remains the recommendation for discharging the #5488 invariant at zero
deploy cost, and my hostile pass could NOT find a fail-open in the deny/reject
widening across any v3 generation or ordering. The recommendation must be
qualified: Path C is a complete, non-regressing fix for the named defect (deny
coverage under new-Go/old-helper skew); Path A is the only path that ALSO closes
the symmetric helper-first direction and gen1's pre-existing scoped-permit
over-permit — paying the #5364 all-configs flag-day. Fold F1+F2 into plan r2 and
re-run convergence.
