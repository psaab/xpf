# Claude SMR plan-review r2 — Phase 4 reconsidered under the 1M-policies frame

**VERDICT: PLAN-NEEDS-MAJOR (revised from r1 PLAN-KILL).**

The user has reframed the Phase 4 question:

> When doing this JIT, we need to evaluate how things will behave if
> there's 1M security policies and how we would evaluate those at
> line rate.

Plan v1 (and SMR r1) focused on Phase 4's *narrow* surface as written
in the design doc: per-flow JIT of the **rewrite function**. Under
that framing the verdict is correctly PLAN-KILL — the descriptor
path already saturates the rewrite arm and Cranelift saves <1% of one
core.

But the doc's Section "Where a JIT wins" lists FIVE distinct
sub-targets, and the design's "+30-50%" claim was always for the
*aggregate* of those — not just the rewrite arm. The five
sub-targets are:

1. **Per-flow compiled fast-path** (rewrite) — already absorbed by
   Phase 1. SMR r1 verdict stands: not worth Cranelift.
2. **Policy decision trees** — design doc claims Phase 2 done, but
   inspection shows the production path is still a **linear scan**
   within the zone-pair (`policy.rs:429-457`). With 1M policies this
   is a real cliff.
3. **NAT rule compilation** — same shape as policy: linear scan of
   NAT rule sets per session creation.
4. **Screen inlining** — Phase 5 done; no further work.
5. **Frame rewrite templates** — same as #1; already absorbed.

The user's 1M-policies framing pulls **#2 and #3** back into scope.
These are not what plan v1 addresses; plan v1 should be revised to
either explicitly defer them or fold them in.

## Self-correction note

In SMR r1 I wrote (F5):
> Verified: `userspace-dp/src/prefix_set.rs:180-225` defines
> `PrefixTrieV4` and `PrefixTrieV6`. But
> `userspace-dp/src/policy.rs:2` imports `PrefixSetV4` and
> `PrefixSetV6` (the linear/hashmap form), NOT the trie. ... the
> trie types are dead code on master.

**AGY r1 caught this and was correct.** I missed that `PrefixSetV4`
is itself an enum (`prefix_set.rs:33-47`) with three variants:
`MatchAny | Linear(Vec<PrefixV4>) | Trie(PrefixTrieV4)`. The
`from_prefixes` constructor dispatches to `Trie(...)` when
`prefixes.len() > PREFIX_SET_LINEAR_MAX` (lines 65-73), and
`PrefixSetV4::contains` (lines 78-83) routes the runtime call into
the trie path automatically:

```rust
pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
    match self {
        Self::MatchAny => true,
        Self::Linear(v) => v.iter().any(|p| p.contains(ip)),
        Self::Trie(t) => t.contains(ip),
    }
}
```

So Phase 3 (address-book trie) **IS shipped** for the per-rule
address-set match. The plan v1 F5/Question 7 recommendation to split
Phase 3 out as a standalone PR is OBSOLETE — the work is already
done. I missed this on r1. **Self-correction accepted.**

The remaining open question is policy-LIST iteration, not
per-rule address matching. Those are different scaling axes:

- **N addresses per rule**: handled by `PrefixSet*::contains` →
  trie when N > linear-threshold. Already O(log N).
- **M rules per zone-pair**: still linear-scan in
  `evaluate_policy_result_with_len` (`policy.rs:429-442`).

It's the M-rules axis that the user's 1M-policies scenario hits.

## Hostile re-analysis under the 1M-policies framing

### Production traffic model for 1M policies

At 1M security policies, the deployment shape is typically:

- High zone-pair count: dozens to hundreds of pairs (DC fabric with
  zones per tenant + per-tier).
- Per-zone-pair rules: still O(thousands) — e.g., 100k tenants × 10
  rules each, split across zones.
- Hit-rate skew: 99% of traffic matches the first few rules in each
  zone-pair (default-permit at the top, with deny-specific
  exceptions). The 1M total is a coverage statement, not an
  evaluation cost statement.

### Where the 1M scan actually lands

`evaluate_policy_result_with_len` is called on **session miss**
(verified: callers at `poll_descriptor/mod.rs:1375` and `:2393`,
both on miss/setup paths, never on cache hit). Established TCP
sessions hit the flow cache and bypass policy entirely.

So 1M policies costs O(M_per_zone_pair) **only at new-session
rate**, not at the 1.92 Mpps line rate. Two scaling regimes to
consider:

**Regime A: bulk-flow traffic (TCP transfers, sustained UDP)**

New-session rate is bounded by application behaviour — typically
1k-10k new sessions/sec at scale. At 10k conn/sec × 1k rules linear
scan × ~10ns per rule = ~100ms of CPU/sec for policy eval. On a 6
worker VM, that's ~17ms per worker per second — about 1.7% of one
core. **This is a real cost but bounded.** Phase 4 helps here, but
not by much.

**Regime B: short-flow / scan / DDoS traffic**

New-session rate spikes to 100k-1M conn/sec. At 1M conn/sec × 1k
rules linear scan × ~10ns per rule = 10 seconds of CPU per
wall-clock second — **dataplane melts**. Phase 4 here would matter,
but ONLY if the JIT compile cost itself amortises. It doesn't
under DDoS — 100 µs Cranelift compile per zone-pair-decision-tree,
under 100k-1M conn/sec churn, means **the JIT compiler thread
saturates a core before doing useful work**.

The salvage that actually scales is NOT per-flow Cranelift.

### Per-zone-pair, config-time decision-tree compile

The shape that scales to 1M policies is a **config-time** compile
(once at config apply, not per session):

- At config apply, for each zone-pair index, build a static
  decision-tree representation that exploits structure:
  - Rules grouped by protocol → 1-byte dispatch (no comparison).
  - Within protocol, rules grouped by port range → binary-search
    or interval tree.
  - Within port range, rules ordered by address-set selectivity →
    short-circuit on first non-match.
- The tree is built ONCE per config (amortised across all sessions
  for that config generation). Per-session eval is O(log M) instead
  of O(M).

Importantly: **this does NOT require Cranelift.** The decision tree
can be a plain data structure (sorted Vec of intervals + per-leaf
rule index) that the interpreted eval walks. Cranelift would emit a
match cascade for the same tree, saving the data-load overhead — but
that's the same 2-3 ns/decision savings as the rewrite-arm
question, applied to a path that runs at session-creation rate, not
line rate. Net win is much smaller than the data-structure work.

### The actual Phase 4 reframing

The Phase 4 that makes sense under the 1M-policies framing is:

**Phase 4a (Cranelift JIT for per-flow rewrite): PLAN-KILL.**
SMR r1 verdict stands.

**Phase 4b (Per-zone-pair decision-tree builder, NO Cranelift):
PLAN-PROMOTE.**
A static decision-tree data structure built at config apply,
replacing the linear scan in `evaluate_policy_result_with_len`.
Estimated benefit: O(log M) eval at session-miss time, scaling to
1M policies cleanly. No JIT, no PROT_EXEC, no compile-storm risk.
This is a substantial body of work that should get its OWN plan
under a new sub-issue of #1605 or a fresh policy-perf issue.

**Phase 4c (Cranelift JIT on top of Phase 4b): DEFERRED.**
Only revisit AFTER Phase 4b lands and is measured. If the data
structure work alone gets new-session-eval below ~1µs, Cranelift's
additional 2-3ns wins per evaluation are still negligible. Most
likely outcome: never revived.

### Test plan adjusted for 1M-policies framing

- Build a synthetic config with 1M rules across 100 zone-pairs (10k
  per pair); benchmark `evaluate_policy_result_with_len` on master
  vs proposed Phase 4b. Goal: session-creation latency p99 < 5µs.
- DDoS stress: 1M conn/sec session creation rate, measure dataplane
  CPU. Phase 4b must keep dataplane responsive; Phase 4a (Cranelift)
  must not be in the path.
- Confirm flow-cache hit path is unchanged (it is — established
  flows don't touch policy eval).

## Revised verdict

VERDICT: PLAN-NEEDS-MAJOR.

Plan v1 should be revised to:

1. Acknowledge that the design doc's "+30-50%" Phase 4 estimate
   was aggregate over five sub-targets, not just rewrite.
2. Split Phase 4 into 4a (rewrite-JIT) and 4b (policy
   decision-tree builder) — adopt the user's 1M-policies framing
   explicitly.
3. Mark Phase 4a as PLAN-KILL with the analysis from SMR r1 plus
   the kill criterion: "Phase 1 descriptors already saturate the
   rewrite arm; 0.4-0.6% of one core remaining is below noise".
4. Mark Phase 4b as PLAN-PROMOTE-TO-NEW-ISSUE: the right next
   surface to address 1M-policies. Phase 4b is NOT Cranelift —
   it's a static data-structure transformation.
5. Remove F5/Question 7 (Phase 3 trie integration) — already
   shipped (`prefix_set.rs:78-83` dispatches to trie). My SMR r1
   F5 was wrong and is corrected here.
6. Remove the RCU epoch barrier section — TX path doesn't re-call
   rewrite functions, so any per-rewrite-call lifetime is
   adequate. (Moot if Phase 4a stays killed.)
7. Update `docs/userspace-jit-design.md`:
   - Flip Phase 4 status to two rows: 4a "KILLED 2026-05-26" and
     4b "OPEN — separate plan".
   - Add a Decision section entry citing this review.
   - Correct the "Phase 3 not started" to "DONE 2026-XX-XX — see
     prefix_set.rs::PrefixSet*::from_prefixes".

The plan needs MAJOR revision (split + scope expansion + Phase 3
correction). One more round of plan-review is justified after the
revision.

## Open question carried into r3

The plan v3 must answer: at 1M policies, is the per-zone-pair
decision-tree builder a Phase 4b sub-issue, or is it a fresh
"policy-eval perf" issue independent of the JIT umbrella? Either is
defensible. The deciding factor is whether Phase 4a is ever expected
to revive — if not, the JIT umbrella is closed and Phase 4b lives
under its own issue.
