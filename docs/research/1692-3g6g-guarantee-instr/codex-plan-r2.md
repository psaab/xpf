codex
The checkout is on the expected branch at `234c3112b57c8bd875c305cb1e62adad4d5de639`. I’m locating the rebuilt section, changelog, and each r1 finding now so the verdict can be tied to exact lines.
exec
/bin/bash -lc 'rg -n "REBUILT|CHANGE LOG|share_integral|snapshot_epoch|Relaxed|L2|CONFIRMED DEAD|L1|backlog|queued_bytes|p1_admit|eligible_visits|Σ|sum|Phase-1|share-cap|demand-bound" docs/research/1692-3g6g-guarantee-instr/plan.md' in /home/ps/git/bpfrx
 succeeded in 0ms:
10:> v2 CHANGE LOG: Codex r1 + Claude-SMR r1 both PLAN-NEEDS-MAJOR with a
11:> shared CRITICAL: §4 v1's `Σ share_i vs class_rate` discriminator is
12:> mathematically CONSTANT (`Σ my_share_i = cap` by construction —
13:> `total_flows = Σ my_count`, so the per-worker shares sum to the full cap
16:> L1-by-design from L1-fixable, and §8 KILL-exit #1 was unreachable.
18:> per-worker BACKLOG (`queued_bytes_i`) + per-worker DEMAND. Other folded
19:> findings: (Codex F4 / SMR F5) L2 root-FCFS is DEAD not provisional —
20:> aggregate `park_root=0` over a monotonic saturating-add sum proves every
24:> (`mod.rs:1561`), NOT a bare Relaxed load; (SMR F2) v1's table was blind
46:2. **per-worker `quantum_sum` miscompute** — code-FALSIFIED by Codex r1:
47:   `quantum_sum` (`queue_service/mod.rs:794-797`) is summed over
51:   quanta, 100m+1g+3g+6g fit well inside `0.7 × quantum_sum`.
69:`shaping-rate 25g`, all classes backlogged:
82:exactly tracking the unguaranteed priority-low 24g. The small4 sum-shape
87:relegation: 3g/6g ARE admitted via the guaranteed Phase-1 path, yet under-
122:### Layer L1 — v8 per-worker fair-share lease (`acquire_v8`)
129:my_share[i] = cap × active_flow_buckets[i] / Σ_j active_flow_buckets[j]
139:likely NON-firing condition: shaper-bound peers consume ~90% of share.
142:3g rate by `Σ active_flow_buckets`, but if a worker's local
143:backlog/demand exceeds `my_share` while OTHER workers with the same class
146:`Σ_i min(demand_i, my_share_i) < class_rate`. This is the
151:### Layer L2 — root FCFS pool ordering (root token bucket / `SharedCoSRootLease`) — CONFIRMED DEAD
154:`select_*` walk consuming `root.tokens` (`queue_service/mod.rs:856`,
159:v1 kept L2 alive "on the narrow chance the aggregate masks a per-worker
164:`coordinator/mod.rs:1039`). A saturating-add sum of non-negative terms is
167:because there is nothing to hide. **L2 is dead, not provisional.** The
170:candidate set to: the demand-bound null (precedence-0), L3 (per-worker
171:budget), and L1 (v8 share-cap).
173:### Layer L3 — per-worker waterfill Phase-1 budget (selector)
177:Phase-1 budget = `(quantum_sum × 0.7).floor()` (`:804`), consumed
179:Codex r1 falsified the v2 "owner-local-eligible quantum_sum" theory —
180:`quantum_sum` is global. BUT the selector's CONSUMPTION walk (`:817-959`)
182:queue's CURRENT `hot.tokens` — which L1 (the v8 lease) just gated. So L3
183:and L1 are COUPLED: if L1 starves a worker's 3g `hot.tokens`, L3 sees
185:**Candidate failure mode:** the per-worker Phase-1 budget split, computed
186:from a GLOBAL `quantum_sum` but consumed against L1-gated tokens, causes
189:is distinct from L1's share cap.
191:### Why these three produce DISTINCT signatures — the consumer success criterion
193:**The instrumentation PASSES its consumer test iff it produces a counter
194:signature that uniquely identifies L1, L2, or L3 (or proves the ~52% is
197:`feedback_review_scaffolding_against_consumer`). The discriminating
218:   `worker/mod.rs:1031-1036` summed across ALL v8 queues that worker
221:   lease grant worker 4 FOR 6g this window" — exactly the L1 question.
224:   but folded to per-class** via `merge_cos_queue_owner_profile_sum`
225:   (`worker/cos/mod.rs:481-486`). For L2 (root) the aggregate `park_root=0`
226:   is conclusive (monotonic-sum, §2-L2); for L3 (queue-token) the
229:4. **`drain_sent_bytes` is per-queue, summed across workers.** We have
231:   per-worker `delivered_i` vs `share_integral_i` (the L1 deciding ratio).
234:   `queue.hot.queued_bytes` is worker-local and never surfaced
239:   demand-bound discriminator (§4 outcome 0).
241:The gap is uniform: **everything is per-class-summed; nothing is
243:tier needs per-(class, worker) visibility — including backlog — to decide
244:which of {demand-bound, L1, L3} explains a specific worker's 3g/6g shard.
247:## 4. Worked distinct-signature table (the disambiguation proof) — REBUILT v2
250:was a CONSTANT (`Sum my_share_i = cap` always — see v2 CHANGE LOG), and it
257:per-worker `share_integral_i` = the lease's TOTAL grant CEILING the worker
258:was entitled to over the window, in bytes (sum over epochs of
267:- `backlog_i` — per-worker class backlog presence
268:  (`queue.hot.queued_bytes` > 0 for a sustained fraction of the window).
269:  The DEMAND proxy: a worker with persistent backlog has offered load it
270:  could not ship; a worker with ~0 backlog is demand-bound
273:- `share_integral_i` — windowed lease entitlement ceiling (NEW).
275:- `p1_admit_i`, `p2_admit_i`, `eligible_visits_i` — per-(class,worker)
277:- `park_root_i` — confirmation only (L2 dead, section 2-L2).
280:| Outcome | `backlog_i` (busy workers) | `granted_i` vs `share_integral_i` | `delivered_i` vs `granted_i` | `p1_admit_i` vs `eligible_visits_i` | `park_root_i` |
282:| **(0) DEMAND-BOUND null -> PLAN-KILL** | **~0 on the under-delivering workers** (no backlog; #1630 cause-2 transport floor) | `granted_i < share_integral_i` (lease WILLING, worker did not ask) | `delivered_i ~= granted_i` | `p1_admit_i ~= eligible_visits_i` (visits + admits, but queue empties) | 0 |
283:| **(L1) v8 share-cap** | **> 0 sustained** on workers whose `delivered_i ~= share_integral_i` (capped WITH backlog) AND >=1 OTHER worker has `granted_i < share_integral_i` (idle slice the capped worker cannot borrow) | `granted_i ~= share_integral_i` on busy workers (lease grants exactly the ceiling, my_room->0) | `delivered_i ~= granted_i` | `p1_admit_i ~= eligible_visits_i` | 0 |
284:| **(L3) Phase-1 budget fault** | **> 0 sustained** | `granted_i < share_integral_i` (lease willing, selector under-requests) | `delivered_i ~= granted_i` | **`p1_admit_i << eligible_visits_i`** — selector VISITS 3g every epoch but Phase-1 budget exhausts before honoring it past <=1 frame | 0 |
287:- **`backlog_i ~= 0`** uniquely fingerprints outcome (0): no other outcome
289:- **`p1_admit_i << eligible_visits_i`** uniquely fingerprints (L3): the
290:  selector visits but does not honor (budget fault). (0) and (L1) both
292:- **`granted_i ~= share_integral_i` WITH backlog AND a peer with
293:  `granted_i < share_integral_i`** uniquely fingerprints (L1): the lease
297:Decision rule (consumer criterion, ordered so a multi-signal read is still
299:1. If the under-delivering busy workers have `backlog_i ~= 0` ->
301:   #1220). Confirm with `p1_admit_i ~= eligible_visits_i`.
302:2. Else if `p1_admit_i << eligible_visits_i` on a backlogged worker ->
303:   **L3** Phase-1 budget fault. FIXABLE (re-derive the Phase-1 boundary
306:3. Else (`granted_i ~= share_integral_i` WITH backlog, some peer under its
307:   ceiling, `bypass_arms ~= 0`) -> **L1** v8 share-cap. Sub-decide:
308:   - if the desired behavior is "let the backlogged worker borrow the idle
316:`park_root_i` is a sanity confirmation that L2 is dead (must be 0;
317:non-zero would mean the section 2-L2 monotonic-sum argument is wrong and
338:1. `phase1_admissions_i`, `phase2_admissions_i`, `eligible_visits_i` —
343:   sum.
345:   worker (stop the `merge_cos_queue_owner_profile_sum` fold for this
354:4. `share_integral_i` — NEW: the windowed lease entitlement ceiling.
359:   writer of `queue.hot.tokens`/`telemetry`), `share_integral_i +=
362:   must use the existing seqlock snapshot path (`snapshot_epoch_v8`,
363:   `mod.rs:1561`), NOT a bare Relaxed load (Codex r1 F3 / SMR F4): the
364:   worker already calls `acquire_v8` → `snapshot_epoch_v8` on the hot path,
368:   single-reader (status path) → Relaxed accumulator + the status path's
374:  add); the `backlog` + `share_integral` + `granted` + `delivered` set is
391:and dumps the per-(queue,worker) `{backlog (queued_bytes), phase1_admit,
392:phase2_admit, eligible_visits, drain_sent, v8_granted, share_integral,
394:proxy (`backlog`) added per SMR r1 F2. Bypasses the Prometheus
410:  snapshot (`snapshot_epoch_v8`, `mod.rs:1561`), which the worker already
411:  performs every `acquire_v8` call — the `share_integral_i` accumulator
413:  SMR F4). A bare Relaxed load of `worker_fair_share[worker_id]` would tear
434:least new hot-path code (`backlog`/`phase1/2_admit`/`eligible_visits`/
436:`v8_granted` per-class needs a 1-u64-add accumulator and `share_integral`
437:needs a per-epoch add that piggybacks the existing `snapshot_epoch_v8`
468:## 7. Disambiguation success criterion (the consumer contract)
472:the four outcomes {(0) demand-bound, (L1) v8 share-cap, (L3) Phase-1
473:budget fault, (L2-confirm) park_root non-zero ⇒ model incomplete} is
475:INDEPENDENT: `backlog_i≈0` uniquely picks (0), `p1_admit_i≪
476:eligible_visits_i` uniquely picks (L3), and `granted_i≈share_integral_i`
477:with backlog + an under-ceiling peer uniquely picks (L1). A counter set
481:against the `feedback_review_scaffolding_against_consumer` failure: the
484:§2-L2 monotonic-sum proof) the three-layer model is incomplete → file a
491:   have `backlog_i ≈ 0` AND `p1_admit_i ≈ eligible_visits_i`. The 3g/6g
497:2. **L1 v8 share-cap, BY-DESIGN (§4 outcome L1):** `granted_i ≈
498:   share_integral_i` WITH sustained `backlog_i`, ≥1 peer under its
500:   active-flow-proportional slice and refuses to let a backlogged worker
507:   §2-L2 proof) OR the fingerprint columns are mutually contradictory
508:   (e.g. backlog>0 AND p1_admit≈visits AND granted<share_integral with no
515:   `share_integral` via the seqlock snapshot, the instrument is infeasible
518:The ONLY non-KILL outcome is **(L3) Phase-1 budget fault** (`p1_admit_i ≪
519:eligible_visits_i` on a backlogged worker): the selector visits 3g every
520:epoch but the `quantum × fraction` Phase-1 budget exhausts before honoring
522:the fix (re-derive the Phase-1 boundary from configured RATES — #1614
529:  (eligibility-gated Phase-1, Phase-2 epoch hardening, v8-lease fairness,
530:  rate-derived Phase-1 boundary) are all GATED behind this
541:- [ ] Per-(class, worker) `{backlog (queued_bytes), phase1_admit,
542:      phase2_admit, eligible_visits, drain_sent, v8_granted,
543:      share_integral, park_root, park_queue}` is observable for the
544:      shared-exact tier (≥2.5G classes) on reth0.80. `backlog` (the DEMAND
545:      proxy) and `share_integral` (windowed lease ceiling) are the two
548:      per-epoch `share_integral` add that piggybacks the EXISTING
549:      `snapshot_epoch_v8` seqlock read (no new seqlock read, no new atomic
552:- [ ] The §4 decision rule selects exactly one of {(0) demand-bound, (L1)
553:      v8 share-cap, (L3) Phase-1 budget fault} on the `small4+24g`
555:- [ ] If the rule selects (0) demand-bound or (L1) by-design → PLAN-KILL

exec
/bin/bash -lc 'rg -n "CRITICAL|F2|F3|F4|F5|Σ|share_i|my_share|L2|L1|backlog" docs/research/1692-3g6g-guarantee-instr/codex-plan-r1.md' in /home/ps/git/bpfrx
 succeeded in 0ms:
5:1. **CRITICAL: §4’s L1-by-design discriminator is code-false.**  
6:   The table claims `Σshare_i < class_rate` because “idle-worker shares (0 flows → 0 share) leave the rate undistributed” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:223)). But the code does not reserve shares for idle workers. It computes `total_flows` by summing active buckets and then allocates each worker from that denominator: `worker_active_flow_buckets.iter().map(...).sum::<u64>().max(1)` and `my_share = new_cap * my_count / total_flows` ([rotate_epoch_v8.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:207), [rotate_epoch_v8.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:306)). Therefore zero-flow workers get zero share and do not make `Σshare` materially less than cap. This breaks the main L1-by-design vs L1-fixable decision rule.
8:2. **HIGH: `share_i` is an epoch gauge, but the plan compares it to window counters.**  
9:   §4 defines `delivered_i` as `drain_sent_bytes` and `granted_i` as granted bytes, both naturally pre/post deltas, but `share_i` is a “v8 my_share snapshot” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:215)). The code recomputes share every v8 epoch, with `EPOCH_DURATION_NS = 200_000` ([mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:241)) and stores a new per-worker value during rotation ([rotate_epoch_v8.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:293)). A single post-run gauge cannot be compared to 30s `delivered`/`granted` deltas unless the plan also integrates share over the same window or records enough epoch/cap timing to normalize it. As written, the table can produce arbitrary false “delivered < share” or “delivered ≈ share” outcomes.
11:3. **HIGH: Option B’s proposed `my_share` read is not race-free as specified.**  
14:4. **HIGH: L2 cannot be “hidden by the SUM” when the summed counter is zero.**  
15:   The plan keeps L2 alive because a per-worker `drain_park_root_tokens` split “could still reveal a single worker hitting root starvation that the SUM hides” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:139)). That is impossible for these monotonic nonnegative counters: coordinator aggregation uses `saturating_add` for `root_token_starvation_parks` ([coordinator/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs:1039)), and queue rows add `drain_park_root_tokens` the same way ([queue_row.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/cos/queue_row.rs:228)). If aggregate `park_root=0`, every contributing worker row is zero. Either L2 is already killed by existing telemetry, or the plan needs a different root-FCFS ordering counter.
17:5. **MAJOR: The L1-fixable row is internally contradictory, so §4 is not a distinct-signature proof.**  
18:   The row says `delivered_i ≈ share_i` and `granted_i ≈ share_i`, while also saying `Σshare_i ≈ class_rate` but “`delivered < Σshare`” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:224)). For the workers the table scopes itself to, “worker `i` that has ≥1 active 3g flow” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:213)), those predicates cannot all hold. If workers leave granted tokens unspent, then `delivered_i ≈ share_i` is false on those workers. This is exactly the kind of identical/undecidable L1-vs-L3 region the consumer criterion forbids.
24:The plan is not ready because §4 and §7 do not yet meet the consumer bar: the proposed counter signatures do not actually distinguish L1-by-design, L1-fixable, L2, and L3.

exec
/bin/bash -lc 'nl -ba docs/research/1692-3g6g-guarantee-instr/codex-plan-r1.md' in /home/ps/git/bpfrx
 succeeded in 0ms:
     1	PLAN-NEEDS-MAJOR
     2	
     3	**Findings**
     4	
     5	1. **CRITICAL: §4’s L1-by-design discriminator is code-false.**  
     6	   The table claims `Σshare_i < class_rate` because “idle-worker shares (0 flows → 0 share) leave the rate undistributed” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:223)). But the code does not reserve shares for idle workers. It computes `total_flows` by summing active buckets and then allocates each worker from that denominator: `worker_active_flow_buckets.iter().map(...).sum::<u64>().max(1)` and `my_share = new_cap * my_count / total_flows` ([rotate_epoch_v8.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:207), [rotate_epoch_v8.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:306)). Therefore zero-flow workers get zero share and do not make `Σshare` materially less than cap. This breaks the main L1-by-design vs L1-fixable decision rule.
     7	
     8	2. **HIGH: `share_i` is an epoch gauge, but the plan compares it to window counters.**  
     9	   §4 defines `delivered_i` as `drain_sent_bytes` and `granted_i` as granted bytes, both naturally pre/post deltas, but `share_i` is a “v8 my_share snapshot” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:215)). The code recomputes share every v8 epoch, with `EPOCH_DURATION_NS = 200_000` ([mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:241)) and stores a new per-worker value during rotation ([rotate_epoch_v8.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:293)). A single post-run gauge cannot be compared to 30s `delivered`/`granted` deltas unless the plan also integrates share over the same window or records enough epoch/cap timing to normalize it. As written, the table can produce arbitrary false “delivered < share” or “delivered ≈ share” outcomes.
    10	
    11	3. **HIGH: Option B’s proposed `my_share` read is not race-free as specified.**  
    12	   The plan says to sample `worker_fair_share[worker_id]` with “a single Relaxed load” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:286)). The actual safe reader pattern is seqlock-based: it reads `epoch_seq`, loads `cap/share/grace`, executes an Acquire fence, then re-reads `epoch_seq` before accepting the snapshot ([mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1561)). The code explicitly documents why the fence exists to avoid torn cross-epoch data ([mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1574)). A diagnostic accessor can be added, but the plan’s “single Relaxed load” claim is unsafe.
    13	
    14	4. **HIGH: L2 cannot be “hidden by the SUM” when the summed counter is zero.**  
    15	   The plan keeps L2 alive because a per-worker `drain_park_root_tokens` split “could still reveal a single worker hitting root starvation that the SUM hides” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:139)). That is impossible for these monotonic nonnegative counters: coordinator aggregation uses `saturating_add` for `root_token_starvation_parks` ([coordinator/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs:1039)), and queue rows add `drain_park_root_tokens` the same way ([queue_row.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/cos/queue_row.rs:228)). If aggregate `park_root=0`, every contributing worker row is zero. Either L2 is already killed by existing telemetry, or the plan needs a different root-FCFS ordering counter.
    16	
    17	5. **MAJOR: The L1-fixable row is internally contradictory, so §4 is not a distinct-signature proof.**  
    18	   The row says `delivered_i ≈ share_i` and `granted_i ≈ share_i`, while also saying `Σshare_i ≈ class_rate` but “`delivered < Σshare`” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:224)). For the workers the table scopes itself to, “worker `i` that has ≥1 active 3g flow” ([plan.md](/home/ps/git/bpfrx/docs/research/1692-3g6g-guarantee-instr/plan.md:213)), those predicates cannot all hold. If workers leave granted tokens unspent, then `delivered_i ≈ share_i` is false on those workers. This is exactly the kind of identical/undecidable L1-vs-L3 region the consumer criterion forbids.
    19	
    20	**Verified Claims**
    21	
    22	Claims 1, 2, and 3 are mostly verified: the ≥2.5G shared-exact routing gate is real ([worker/cos/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/cos/mod.rs:31), [worker/cos/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/cos/mod.rs:168), [cross_binding.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/cross_binding.rs:69)); `acquire_v8` primary is capped by `my_effective_share` and surplus requires bypass ([mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1203), [mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1320)); current counters are indeed summed or too coarse for per-class/per-worker v8 attribution ([coordinator/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs:1048), [coordinator/status.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/status.rs:382), [worker/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/mod.rs:1031)).
    23	
    24	The plan is not ready because §4 and §7 do not yet meet the consumer bar: the proposed counter signatures do not actually distinguish L1-by-design, L1-fixable, L2, and L3.
    25	tokens used
