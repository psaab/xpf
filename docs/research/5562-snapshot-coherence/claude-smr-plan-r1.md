# Claude SMR — HOSTILE plan review r1 — #5562 snapshot coherence

Reviewing `docs/research/5562-snapshot-coherence/plan.md` r1. Posture: adversarial. I
verified every mechanism claim against the tree at `4e0c7f74c` and stress-tested Path D
against both interleavings and both generation axes.

## Verdict: **PLAN-NEEDS-MINOR**

The diagnosis is correct and Path D is the right fix — sound, minimal, deterministically
testable. But the plan has one **wrong** invariant (the no-`Default` compile-time guard is
not viable), two missing correctness arguments a hostile code reviewer will demand, and one
unstated cross-issue dependency. None change the recommendation; all must land in r2.

## What I verified as correct

1. **Store order** — validation-first in BOTH paths: snapshot_refresh.rs L303→L304;
   reconcile/snapshot.rs L476→L480. ✓
2. **Read order** — validation-first: loop_body/mod.rs L364→L372; setup.rs L111→L112. ✓
3. **Stamp source vs decision source** — stamp from `validation` (flow_cache.rs L535-537);
   decision from `forwarding` (poll_binding gets both, L790/L794). Invalidation gate
   L873-874 compares generations. ✓
4. **fib decoupling** — `bump_fib_generation` (coordinator/mod.rs L907-914) stores ONLY
   validation, never rebuilds forwarding. ✓ This is the load-bearing fact that kills Path A
   and forces the split-source of Path D. Confirmed.
5. **Readers** — `shared_validation`: workers only (L364, L111); status reads fib via
   `self.validation` accessor, not the ArcSwap. `ha.forwarding`: workers + the GRE tunnel aux
   thread (tunnel.rs) which never stamps the cache. ✓
6. **ForwardingState has no generation field.** ✓ (grep clean.)

## Findings requiring r2 changes

### F1 (MAJOR-within-plan, corrects a wrong invariant) — the no-`Default` guard in §7.1/§11.4 is not viable
`ForwardingState::default()` is load-bearing: `ha_state.rs` constructs the forwarding
ArcSwap with `ArcSwap::from_pointee(ForwardingState::default())` at coordinator init, and the
worker's pre-first-apply state relies on it. You **cannot** remove `Default` to force every
builder to set `config_generation`. The guard §7.1 proposes is therefore unimplementable as
written. Replace it with: (a) `config_generation` defaults to `0` (matches
`ValidationState::default().config_generation == 0`, so pre-apply stamp/lookup are coherent
at 0); (b) a **test** asserting `forwarding.config_generation == snapshot.generation` after
same-plan refresh, full reconcile, AND disarmed refresh; (c) a grep-time check that the
builder(s) — not the struct literals — set it, since all real forwarding comes through
`build_forwarding_state_*` (forwarding_build/mod.rs L154+). Fix §7.1, §8 row 1, §11.4.

### F2 (MINOR, missing proof) — Path D must show BOTH generation axes are coherent under a full apply
A hostile code reviewer will immediately ask: a full config apply bumps BOTH
`config_generation` (→ forwarding, store B) AND `fib_generation` (→ validation, store A). Add
the explicit both-axes trace to §5 Path D:
- Forward torn read (validation=NEW fib F_N, forwarding=OLD config C_{N-1}): decision under
  C_{N-1}; stamp = (C_{N-1}, F_N). After forwarding→C_N, lookup = (C_N, F_N). `C_{N-1} != C_N`
  → **evict**. Closed by the config axis. ✓
- Inverse torn read (validation=OLD fib F_{N-1}, forwarding=NEW config C_N): decision under
  C_N; stamp = (C_N, F_{N-1}). After validation→F_N, lookup = (C_N, F_N). `F_{N-1} != F_N` →
  **evict** (transient, re-eval under live policy). ✓
- fib-only bump (forwarding unchanged, validation F→F+1): single atomic, stamp and lookup both
  read the one `validation.fib_generation`; advance → evict. ✓
The point: config_generation from forwarding + fib_generation from validation is coherent on
every schedule because each axis is sourced from exactly one atomic and the stamp/lookup read
the same worker-local of that atomic. State this, don't leave it implicit.

### F3 (MINOR, unstated dependency) — Path D's equality gate rests on #5169 monotonicity
The invalidation is an **equality** compare (`stamp.config_generation != lookup.config_generation`).
That only guarantees invalidation if `config_generation` never *rolls back* to a value a live
entry still carries. #5169 (CLOSED) enforces monotonicity at the control plane. Path D
inherits that dependency: if a rolled-back generation were ever published, an entry stamped
with the old value could false-hit. Add to §7 as a precondition and to §4 as the reason
#5169 is a *load-bearing* predecessor, not just "related."

### F4 (MINOR, pre-empt the obvious cheaper idea) — record why reordering the two stores does NOT fix it
Reviewers will ask "why not just store/read forwarding-first?" Answer in §5: reordering does
not create atomicity. With forwarding-first stores + forwarding-first reads, a worker can
still load forwarding=OLD, then both stores land, then load validation=NEW → NEW-validation +
OLD-forwarding persists. Reordering only shuffles which schedule is persistent; it never
removes the torn pair. This is why a real coherence mechanism (D) is required.

### F5 (NIT, tighten "smallest blast radius") — the insert site already has both locals
At the insert (flow_cache.rs ~L430-542) the function ALREADY takes both `forwarding` (used
at L437/L466/L472) and `validation` (L536). So Path D at the insert is a one-token source
swap: `forwarding.config_generation` in place of `validation.config_generation`. The only
real signature churn is `FlowCacheLookup::for_packet` (L169), and `forwarding` is in scope at
its call site (poll_descriptor/flow_cache_hit.rs, under poll_binding). Say this explicitly —
it strengthens the recommendation and shrinks the perceived change.

### F6 (NIT) — note the fix is directionally symmetric
The plan frames the bug as fail-open (permit cached, DENY raced). If deny decisions are also
cacheable, the inverse is a persistent fail-*closed* (a raced new PERMIT stays denied). Path
D's generation-mismatch eviction is symmetric and closes both directions; add one sentence so
reviewers don't think the fix is permit-only.

## Attacks that did NOT land (Path D holds)

- "Does the worker load stay torn under D?" No — decision, stamp config_generation, and
  lookup config_generation all read one worker-local `forwarding` Arc; a single `.load()`
  result cannot tear against itself. Coherence is structural, not fenced.
- "Does keeping fib in validation reopen a race?" No — one atomic, read once per tick; see F2.
- "Simpler fix?" Reordering fails (F4). A bundle (A) reintroduces the fib-clone cost. B is
  strictly dominated. D is the floor.

## Required for r2 → PLAN-READY

Fix F1 (wrong invariant — must correct), fold F2/F3/F4 into §5/§7, tighten F5/F6. No design
change; the recommendation (Path D) stands. If Codex/AGY surface a load-bearing correctness
hole in D I have not, escalate to PLAN-NEEDS-MAJOR; otherwise r2 with F1-F4 addressed is
PLAN-READY.
