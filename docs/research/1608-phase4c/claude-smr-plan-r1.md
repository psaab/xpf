# Claude SMR plan-review r1 — #1608 v3 (research)

**Reviewer:** Claude SMR (domain SMR + CPU arch/design + SW design patterns)
**Posture:** HOSTILE. The history (v1 6-fatal kill, v2 10-fatal kill) is a
strong prior that the design surface is deep and a soft pass is wrong.
**Verdict:** **PLAN-KILL-CONFIRMED** (Path A), with Path D as the reopen
criterion. The plan's own recommendation is correct; I verified the
load-bearing claims against `origin/master @ 6bdf9d73e` and they hold.

## Verified factual claims (with line evidence)

### Claim: neg_neigh gate fires before policy eval for unresolved dst — TRUE
`poll_descriptor/mod.rs:2392` `ForwardingDisposition::MissingNeighbor =>`
opens the arm; `:2418` `let fast_fail = neg_neigh_gate(...)`; `:2433-2442`
`if fast_fail { ... binding.scratch.scratch_recycle.push(desc.addr);
continue; }`. The `continue` (`:2442`) skips the session-install policy
eval at `:2522` (`evaluate_policy_with_len`). So a negatively-cached,
unresolved, un-expired dst never reaches policy eval. **#1660 genuinely
short-circuits the dead-host flood class before the policy scan.**

### Claim: live/resolved dst still hits policy eval every cold packet — TRUE
The canonical new-flow policy decision is at `:1393`
`evaluate_policy_result_with_len(...)` in the ForwardCandidate slow path,
which is NOT the MissingNeighbor arm and never consults `neg_neigh`. A
flood to a resolvable dst (the victim service, or the firewall's own
on-link subnet) reaches `:1393` per packet. **This is the only residual
threat #1608 uniquely addresses** — Section 4's table is accurate.

### Claim: cold path is still a linear zone-pair scan post-#1606 — TRUE
`policy.rs:885-899`: `if let Some(indices) = state.zone_pair_index.get(&key)
{ for &idx in indices { ... try_match_rule(&state.rules[idx], ...) } }`.
`try_match_rule` (`policy.rs:926`) does the inactive gate, then
`compiled_apps.matches` (O(1)), then `policy.rs:944-949`
`source_v4_match_any || source_literal_v4.contains(src) ||
source_book_idxs.iter().any(|&i| state.books[i as usize].v4.contains(src))`.
Address-book bodies are shared via `state.books` (the #1606 dedup); the
rule-count-linear part is the outer `for &idx in indices`. **The plan's
Section 2 topology is exact.**

### Claim: #1623 DAG never shipped; only scaffolding — TRUE
`policy.rs:182-185` carries `source_prefixes_v{4,6}: Option<Arc<[PrefixV4]>>`
with a doc comment (`:170-181`) stating "NOT consumed by the hot path in
this PR (zero-touch on `evaluate_policy`)". The multi-stage DAG is absent
from `evaluate_policy_result_with_len`. **The chartered fix for the
rule-count-linear cost (#1609/#1623) was PLAN-KILLED; the cost remains.**

### Claim: cold-path bottleneck unmeasured — TRUE (premise corrected r1→r2)
`docs/userspace-jit-design.md` "Measurement plan" (~:639) lists the
*method* but has **no populated Scale Target A1/A2/B1/B2 rows**. My r1
draft cited #1615's 870 Kpps container ceiling as the blocker; **Codex
r1 correctly flagged that as stale** — #1615 is CLOSED and the
multi-thread flooder now reaches ~2.94-4.4 M pps
(`docs/pr/1615-flooder-multithread-virtio/measurements.md:23,55`). I
accept the correction. It does NOT change my verdict — it strengthens
it: the measurement is now *achievable* and was simply never run, so
there is no tooling excuse for shipping a mechanism against an
unmeasured cold path. **The cold path was never driven to saturation;
its position on the bottleneck frontier is unknown despite the tooling
now existing.**

### Claim: VerdictCacheEntry math exceeds 256 KB budget — PLAUSIBLE, carry-forward
v2's reviewers established `VerdictCacheEntry`=96 B with alignment padding
(two `IpAddr` = 17 B each + zone IDs + ports + protocol + verdict +
generation, aligned). 4 K × 96 B = 384 KB alone, over the 256 KB issue
budget before adding 4c.1's bucket table. I did not re-derive the exact
layout in v3 (no struct exists yet), but the v2 convergent number stands
as the prior; Section 8 honestly flags the budget is unmeetable at 4 K
entries.

## Why PLAN-KILL is the correct verdict (not PLAN-READY for B or C)

1. **No measured win.** Every prior dataplane-perf PLAN-KILL in this repo
   (the per-5-tuple fairness family, #1545, #1317, #966-969) died on the
   same axis: a mechanism defending an unmeasured or sub-noise cost. The
   #1605 kill already showed the established path's dominant costs are
   memcpy/NAPI/syscalls/poll_binding, not rule eval. No cold-path
   flamegraph under flood exists. Shipping B or C now repeats the
   anti-pattern the project has killed ~10 times.
2. **#1660 already covers the headline attack.** The SYN-flood-to-random-
   host example in the issue body is the dead/unresolved-dst class, now
   short-circuited. The residual (live-dst flood) is real but
   undemonstrated to saturate a worker at realistic rule counts.
3. **The design surface is deep and unstable.** Two unified designs died
   on 16 combined structural fatals; #1609's DAG died on 6 rounds of
   escalating defects. The probability that a v3 B/C closes cleanly
   without a measured target to anchor sizing/threshold decisions is low.
4. **The gating premise failed.** Parking assumed #1607 measurement +
   #1609 DAG would make v3 "narrow." Neither delivered. The plan is
   honest that the preconditions are unmet.

## Reopen criterion (Path D)

Resolve #1615 (or run the flooder from a non-container source >2.5 Mpps),
populate the Scale Target table, and demonstrate a live-dst cold flood
saturates a worker. THEN Path C (rate-limit, the only mechanism adding
something #1660 lacks) is the higher-value reopen; Path B (verdict cache)
second, gated on the zone-pair scan cost being shown to bite.

## Residual nits (non-blocking — the verdict is KILL regardless)

- N1: Section 8 should state the exact v2 layout numbers it inherits
  rather than "v2 established," so a future author does not re-derive.
- N2: Section 4's table should note the ForwardCandidate vs MissingNeighbor
  *disposition* distinction explicitly (it is the mechanism by which
  #1660 covers one class and not the other), since that is the crux.
