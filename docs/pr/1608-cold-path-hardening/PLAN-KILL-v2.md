# #1608 v2 PLAN-KILL — round 2

**Reviewers:** Codex r2 + AGY r2 + Claude SMR r3 (3/3 PLAN-KILL).

Date: 2026-05-27.

This is the SECOND consecutive plan-round PLAN-KILL on #1608. Per
the `/engineer` protocol, this stops here and escalates to the user.
A v3 will only be drafted on explicit user authorization.

## Round 1 (v1) — killed 3/3 on 6 fatal axes
See `PLAN-KILL.md` for the v1 details.

## Round 2 (v2) — killed 3/3 on a different set of fatals
v2 addressed 5 of 6 v1 axes correctly in primitive choice (per-
destination keying, full policy-key cache, line numbers, fixed-
point math, deferred acceptance) but introduced new structural
defects revealed by hostile re-review:

### Convergent fatals on v2

**F-V2-1 — Rate-limit drop hits policy-Deny path = 1 Mpps event DoS.**
AGY F2 + Claude SMR r3 Axis 3. The plan wraps the rate gate INSIDE
`evaluate_policy_with_verdict_cache` and returns `PolicyAction::Deny`
on rate-limit. That return propagates through `policy_result.action`
at `poll_descriptor/mod.rs:1810-1821` to `emit_policy_deny_event`
per dropped packet — 1 million events/sec under flood. Self-defeating
defensive-depth.

**F-V2-2 — `poll_descriptor.rs:2393` rate-deny does not actually drop.**
Codex N2 + Claude SMR r3 Axis 3. At the session-install slow-path
call site (line 2393), a non-Permit return only skips the inner NAT
calculation. Execution continues to missing-neighbor session install
at lines 2467-2484. A rate-limit Deny from the helper FAILS to drop
the packet. The plan's "mechanical wrapper" is structurally
insufficient at one of the two intended insertion points.

**F-V2-3 — Eviction-storm grants full burst credit on every packet.**
AGY F1 + Claude SMR r3 Axis 1. Under high-entropy destination spray,
the 512-set × 4-way table thrashes. Plan v2 says `new bucket starts
with tokens_ns = burst_ns = 1_000_000_000_000`. Every cache-miss-
init grants a full burst. Attacker spraying 2048+ destinations
defeats the rate limit completely.

**F-V2-4 — Bucket key omits zone/profile, breaking per-zone Junos
screen-profile semantics.** Codex N1. The CLI surface is per-screen-
profile (which is per-zone via `ScreenProfileSnapshot.zone`), but
the bucket table is keyed only by `dst_ip`. Two zones with different
configured rates cannot coexist on a shared destination. Profile-
disabled-in-zone-A is collateral-rate-limited by zone-B's bucket.
Cannot represent Junos semantics without re-keying.

**F-V2-5 — Default-deny cache skip = 0% hit rate on the attack class
#1608 defends.** AGY F4. Plan v2 §1 axis 3 explicitly skips cache
insert when `result.policy_id == 0` (default-deny). Under a cold-path
flood that doesn't match any permit rule (which is the typical attack
shape), 100% of packets evaluate to default-deny and 100% miss the
cache. The verdict cache delivers ZERO value under the exact attack
it claims to defend. The "stuck on stale default-deny after rule add"
justification is empty — `config_generation` bumps already invalidate
on commit.

**F-V2-6 — `mem::size_of` const_assert values are wrong; v2 won't
build.** AGY F3 + Codex r2 Axis 5. The plan asserts:
- `DestBucketEntry == 48` (actually 56: TokenBucket is 32 B not 24
  B since `tokens_ns:u64 + burst_ns:u64 + last_refill_ns:u64 +
  rate_pps:u32` aligns to 32; plus Option<IpAddr>=24).
- `VerdictCacheEntry == 88` (actually 96 with explicit padding
  computation — 8-byte aligned struct with the field list).

Both const_asserts fail at compile. Plan would not produce a built
artifact.

**F-V2-7 — Ownership boundary mismatch: per-binding state but per-
worker budget claim.** Codex N6. Plan v2 puts `ColdPathGate` on
`BindingWorker` (per-binding) but claims a 184 KB "per-worker"
budget. A worker polling N bindings gets N × 184 KB ≈ N × 208 KB
corrected. The budget proof is at the wrong ownership level.

**F-V2-8 — Cache-hit accounting API does not exist.** Codex N4.
`PolicyEvaluationResult` carries `action + policy_id`, NOT
`rule_idx`. `PolicyRuleCounter::add` is `fn`-private to
`policy.rs`. The plan's `state.rules[hit.rule_idx as usize]
.hit_counter.add(packet_len)` cannot compile against the existing
API. Plan does not specify the required API changes.

**F-V2-9 — `mem::size_of<PolicyRule>` assert misses semantic
field additions.** Codex N5 + AGY F5 + Claude SMR r3 Axis 2.
PolicyRule contains heap types (Vec, Arc, String); adding a new
match criterion inside `compiled_apps` or activating the existing
`scheduler_name` field for time-of-day match doesn't change
`mem::size_of`. The proxy invariant doesn't catch the bugs it
claims to defend against. Plan must include a full #1431-style
CACHE-KEY INVARIANT comment listing every match dimension —
NOT a layout-size proxy.

**F-V2-10 — Helper signature omits `now_ns`.** Codex N3 + Claude
SMR r3 Axis 4. The bucket math correctly requires `now_ns`. The
plan's helper signature does not pass it. Either receive it (cheap,
batch-cached at `poll_descriptor.rs:448`) or call `clock_gettime`
per cold-path packet (expensive). Plan unspecified.

## Provenance

- Plan v2: `docs/pr/1608-cold-path-hardening/plan.md` (HEAD 7e6a596ca)
- Codex r2: `docs/pr/1608-cold-path-hardening/codex-plan-r2.md`
  (task-mpokuixd-yvxfw0; verdict PLAN-KILL)
- AGY r2: `docs/pr/1608-cold-path-hardening/agy-plan-r2.md`
  (adversarial-review-mpokum1e-f1gn74; verdict PLAN-KILL)
- Claude SMR r2 (initial, self-corrected): `claude-smr-plan-r2.md`
- Claude SMR r3 (self-correction after Codex+AGY): `claude-smr-plan-r3.md`

## What this means for the issue

#1608 stays OPEN with `plan-kill` label. The defensive-depth goal is
real; both PLAN-KILLs have laid out a credible v3 spec. The next
revision MUST address all 10 v2 fatals on top of the 6 v1 fatals.

Two consecutive PLAN-KILLs on different designs suggests the
underlying issue scope ("cold-path hardening as a single mechanism")
may be too coarse. A v3 might decompose into:

1. Silent rate-limit drop path (own PR) — outside policy engine,
   counter-only, no event emit, no session install.
2. Verdict cache (own PR) — full key, cache default-deny, proper
   API for hit-counter accounting, real CACHE-KEY INVARIANT block.
3. Wiring + tuning (third PR if needed) — operator config surface,
   per-zone aware keys, ownership boundary.

This is the right framing for the user to consider before
authorizing v3.

## Action

- Issue body / PR: NO PR opened. Branch `refactor/1608-cold-path-
  hardening` preserved at HEAD for the eventual v3 author.
- Issue label: add `plan-kill` (already attached? — verify).
- Memory file: log "v2 PLAN-KILL — 3/3 convergent on 10 new fatals;
  v3 requires user authorization."
- Escalate to user with this doc.
