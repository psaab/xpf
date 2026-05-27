# #1562 — fresh-deploy warm-up dip in cos-off-ipv4-push (#1477 Gate 6)

**Status:** KILLED v3 — both Codex (round-1 PLAN-NEEDS-MAJOR) and
Gemini (round-1 PLAN-KILL) reject the plan's central premise. Per
SKILL.md convergence rule, when Gemini's KILL is grounded in
codebase evidence that invalidates the issue's framing (not just
this plan's framing), the right outcome is to record PLAN-KILL,
close #1562 as not-a-bug, and not re-plan around a false premise.

## KILL summary

The issue body and #1477 Gate 6 evidence both describe the 15.014
Gbps dip as a **"fresh-deploy warm-up"** phenomenon — the
hypothesis being that cold caches / first-touch AF_XDP /
unsettled cpufreq / NUMA migration cause the second matrix
iteration to dip 30% below iteration 1.

Gemini's round-1 review (task-mpni08vw-jgfd5s, PLAN-KILL) caught
that **the matrix runner already pre-warms the path**:

```
# scripts/userspace-ha-validation.sh:770
warm_up_cell "$label" "$target" "$family_arg" "$direction" "$port"
validate_cell "$label" "$target" "$family_arg" "$direction" "$min_gbps" "$port"
```

`warm_up_cell` (lines 673-688) runs a full unmeasured iperf3 pass
via `run_iperf_json` before any measured iteration. So:

- The **first measured iteration** ("iter 1 = 21.580 Gbps") was
  actually the SECOND traffic flow on the path. The path was
  already warm.
- The **second measured iteration** ("iter 2 = 15.014 Gbps")
  was the THIRD traffic flow. The path was definitively warm.

`feedback_cross_binding_impossible.md` per-binding warm-up costs,
AF_XDP first-touch TX-ring fill, cpufreq ramp on Intel, page-cache
warmup — none of those mechanisms can cause iter 3 to dip after
iter 2 hit 21.58 Gbps. Once warm, classical warm-up costs are
paid.

A 30% drop in iter 2 (third measured flow) after a clean iter 1
(second measured flow) is **not** a warm-up phenomenon. It's
either:

- **Environmental flake** — thermal throttling after ~15s of
  line-rate load (warmup 5s + iter 1 5s + ~5s ramp into iter 2);
  kernel scheduler jitter; fabric latency spike disrupting TCP
  RWND on iter 2.
- **Sustained-load dataplane state** — but this would manifest
  on every iter 2 across multiple runs, and the project has
  many smoke matrix runs from this validator stream
  (including #1530 Run 2 on the same code paths at 23.3 Gb/s
  cos-off v4 P=12 push, https://github.com/psaab/xpf/issues/1530#issuecomment-4545216044)
  that DID NOT dip. So this isn't a reproducible code path.

#1562's framing as "fresh-deploy warm-up dip" is **provably
incorrect**.

## Codex round-1 findings (PLAN-NEEDS-MAJOR)

Independently of Gemini's KILL premise, Codex flagged the v1
plan as insufficient: 9 datapoints too weak, must capture iter 3,
"warm-up" magnitude doesn't fit classical mechanisms,
destroy/create not actually "fresh deploy". v2 of this plan
addressed each, but Gemini's deeper finding makes the entire
direction wrong, not just under-instrumented.

## Final disposition

**Close #1562 as not-a-bug** (NOT "explained by #1594 + #1598" —
that hypothesis from the user prompt was also empirically false:
#1594 fixed a different code path; #1598 is for the uncapped CoS
class on port 5211; neither touches the cos-off port 5201 cell
that recorded 15.014 Gbps).

The right disposition is:

1. The matrix runner already pre-warms — no "warm-up fix" can
   help.
2. The 15.014 Gbps reading was an environmental moment at
   `13fa1009` validation time (likely thermal throttling /
   kernel scheduler jitter / fabric latency spike), not a
   reproducible code-path event.
3. If a future Gate 6 validation reproduces the iter-2 dip on a
   fresh deploy, the right framing is **post-iter-1 degradation**
   (not warm-up), and the investigation should look at thermal /
   scheduler / fabric latency state — not dataplane code.
4. Gate 6 acceptance can either:
   - Accept that any one cell may flake and retry once (peak ≥
     18 Gbps + median ≥ 18 Gbps OR retry-on-fail with 2/3
     pass), OR
   - Stay strict and require fresh-validation reruns to drop
     the rare flake. Either is reasonable; both belong in a
     **runner improvement issue** filed separately, not #1562.

No code changes proposed by this plan. No PR will be opened.

## Round-1 review summary

## Round-1 review summary

- **Codex** (task-mpni0sde-cd5e8m): PLAN-NEEDS-MAJOR. Major
  objections: 9 datapoints is too weak to PLAN-KILL (~28% upper
  bound on failure probability remains); must capture iter 3 not
  abort at iter 2; "warm-up" is wrong frame for a 30% iter-2 drop
  (AF_XDP first-touch / cpufreq / NUMA all settle in <1s or show
  chronic skew, not iter-2-specific dip); Phase B must be
  pre-shaped (decision table mapping evidence → fix path);
  destroy/create may leave host-side state warm (CPU governor,
  IRQ placement, bridges/veth, caches, qdisc/offload) — must
  call it "cluster recreate on warm host" not "fresh deploy";
  gate-metric collection in Phase A should be sufficient to
  evaluate per-iter 18 Gbps vs median/min/peak alternatives.
- **Gemini** (task-mpni08vw-jgfd5s, gemini-3.1-pro-preview):
  **PLAN-KILL**. Premise itself is wrong — the matrix runner
  already calls `warm_up_cell` at line 770 of
  `scripts/userspace-ha-validation.sh` before `validate_cell`.
  The first measured iteration (21.58 Gbps) was the second
  traffic flow on the path. Iter 2's 15.014 Gbps dip is not
  warm-up. Quoted file:line evidence for every claim.

The two reviewers converge: **the issue's framing is wrong, no
plan around the "warm-up" framing can produce a useful fix.**
Codex's objections were on plan rigor; Gemini's KILL is on the
premise. The Gemini PLAN-KILL is the binding outcome.

## Round-1 → v2 changes

1. Raised sample size: **3 deploys × 5 iters = 15 datapoints** with
   a continue-on-failure runner that records iter 3 (and iters 4-5)
   even after a sub-threshold iter.
2. Reframed "warm-up" as **"fresh-cycle iter-2 degradation pattern"**;
   the design space now includes RG transition state, server
   lifecycle (iperf3 backend state across iterations), and lab
   environment volatility, not just classical cold-cache.
3. **Pre-shaped Phase B decision table** mapping evidence pattern
   to candidate fix.
4. Renamed reproduction step to **"Cluster recreate on warm host"**
   to acknowledge incus VM recreate does not reset host CPU
   governor, IRQ, bridge state, qdisc, or page cache. Added
   explicit pre-condition logging for those.
5. Phase A also now collects **all five iteration measurements per
   cell + cell-level statistics (peak/median/min)** so the gate
   metric design can be reviewed without a separate measurement.

This plan answers the question: **what should we do about #1562?** The
default proposed action is *not* a code fix but a reproduction sweep
on current master, because the cross-references the issue points at
(#1594, #1598/#1600) do not turn out to explain the failure once the
smoke harness target source is traced precisely. If reproduction
shows the dip is gone, this is PLAN-KILL → close #1562 as
superseded. If reproduction reproduces, the plan upgrades into a
real fix proposal.

## Issue framing

#1477 Gate 6 (smoke matrix mode) at SHA `13fa1009` recorded:

```
==> running cos-off-ipv4-push push iperf port 5201 iteration 1/3
cos-off-ipv4-push run 1: 21.580 Gbps  ...  retr=2
==> running cos-off-ipv4-push push iperf port 5201 iteration 2/3
cos-off-ipv4-push run 2: 15.014 Gbps  ...  retr=0   <-- BELOW THRESHOLD
```

Threshold: ≥ 18.000 Gbps per iteration. Iter 1 passed, iter 2 dipped
to 15.014 Gbps, gate aborted. Warm-cluster Gate 1 manual run on the
same SHA against the same target hit 23.374 Gbps.

`docs/pr/1373-retire-ebpf-dataplane/evidence-1477-source-removal-20260526-13fa1009ea60/userspace-phase-cycle.log`
is the canonical artifact.

Filed as fresh-deploy warm-up dip; closure was relaxed so the
retirement umbrella (#1373) could land.

## Cross-reference triage: do #1594 / #1598 / #1600 explain it?

The user prompt hypothesizes that #1594 (smoke-harness `IPERF_TARGET4`
realignment from `172.16.100.200` → `172.16.80.200`) might explain the
15 Gbps measurement, because a wrong target would cap at ~9.4 Gb/s.
**Walking the code carefully, the hypothesis does not hold.**

### Two distinct target plumbing paths

1. **`test/incus/loss-userspace-cluster.env`** —
   `IPERF_TARGET4`/`IPERF_TARGET6`. Sourced by the HA destructive /
   failover / connectivity scripts:
   `test-failover.sh`, `test-ha-crash.sh`,
   `test-restart-connectivity.sh`, `test-active-active.sh`,
   `test-double-failover.sh`, `test-chained-crash.sh`,
   `test-stress-failover.sh`, `test-private-rg.sh`,
   `test-connectivity.sh`. This is the path #1594 fixed. At
   `13fa1009` this said `172.16.100.200`; PR #1594 (merged
   2026-05-26 23:15Z) repointed to `172.16.80.200`.

2. **`scripts/userspace-ha-validation.sh`** lines 20-21:

   ```bash
   V4_TEST_TARGET="${V4_TEST_TARGET:-172.16.80.200}"
   V6_TEST_TARGET="${V6_TEST_TARGET:-2001:559:8585:80::200}"
   ```

   This is the smoke-matrix runner — the script driven by
   `scripts/userspace-phase-cycle.sh --smoke-matrix` which produced
   `userspace-phase-cycle.log`. **It hard-codes the canonical target;
   it does not source the env file's `IPERF_TARGET4`.** The
   `userspace-phase-cycle.sh` driver only forwards
   `BPFRX_CLUSTER_ENV` for VM identity (which `INCUS_REMOTE`/`VM0`/
   `VM1` to talk to) — not for iperf3 target selection.

### Direct evidence of target at 13fa1009

The `evidence-1477-source-removal-20260526-13fa1009ea60/cos-off/v4-push.json`
artifact (a separate manual Gate 1 run on the same SHA) has:

```
"remote_host": "172.16.80.200"
```

and `avg_gbps: 23.37` — proving the canonical target was reachable
and fast at `13fa1009`. The 15 Gbps Gate 6 iter-2 dip also went to
this target, because the matrix runner does not honor the env file's
target.

### #1598 / #1600 don't apply either

#1598 / #1600 fix a CoS-on funnel on uncapped class (port 5211). The
failing cell here is `cos-off-ipv4-push port 5201`. CoS configuration
is fully torn down before the matrix's cos-off pass — the precheck
line `cos-off precheck: ok` immediately above iter 1 confirms it.
Port 5211 is not in use during this cell; cross-binding funnel is
not in the loop.

### Net of triage

The cleanest explanation in the user prompt (15 Gbps = wrong-target
cap) doesn't hold up to the harness wiring. The 15 Gbps was on the
canonical fast path on the canonical target. Either:

- **It's a real warm-up phenomenon** that reproduces post-master, or
- **It's an environmental flake** at the moment of the 13fa1009
  validation that doesn't reproduce.

The plan therefore makes reproduction the gate, not code.

## Honest scope/value framing

Absolute scale: a single iteration was 15.01 Gbps where the threshold
was 18.0 Gbps. The same matrix run with `warm` cells in the same
session would have averaged near 21 Gbps. The risk impact is on the
**#1477 Gate 6 acceptance** path (i.e. the merge-gate framing of the
retirement umbrella), not on production traffic — fresh deploys of
production firewalls are extremely rare and don't hit this validator.

If the dip reproduces and the root cause is a fixable cold-cache /
JIT / NUMA warm-up artifact, the value of the fix is **eliminating a
gate flake** on a high-stakes validator. If the dip doesn't
reproduce post-master, the value of #1562 is **zero** — close it.

*If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.* In fact, PLAN-KILL is
the expected outcome of this round if reproduction shows clean
matrix runs.

## What's already shipped / relevant prior work

- **PR #1594** (merged 2026-05-26 23:15Z, e07f733a6 ancestor): fixed
  the env-file `IPERF_TARGET4` inheritance bug. Affects HA failover /
  connectivity scripts, **not** `userspace-ha-validation.sh`'s smoke
  matrix path. The fix is real and correct in its scope but does not
  explain #1562.
- **PR #1598 / #1600**: CoS uncapped-class funnel fix on port 5211.
  Different code path; not in scope for cos-off port 5201.
- **#1561**: first-snapshot CoSBatch race. Touches the helper's
  first-snapshot path — overlap with this issue's "first-deploy"
  framing exists, but the failing matrix cell is CoS-**off** so the
  CoSBatch first-snapshot path is dormant. Cross-reference but not
  causal.
- **Userspace-dp warm-up characteristics**: `feedback_cross_binding_impossible.md`
  notes per-binding AF_XDP UMEM ownership; first-traffic per binding
  has TX-ring fill and PageCache warm-up costs. No prior
  characterization of how many iterations are needed to settle, but
  Gate 1's same-SHA manual run hit 23 Gbps after a full deploy +
  CoS-symmetric application, which itself produces traffic that
  pre-warms the path.

## Proposed action: reproduction sweep on current master

### Step 1 — Cluster recreate on warm host

```bash
export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
sg incus-admin -c "./test/incus/cluster-setup.sh destroy"
sg incus-admin -c "./test/incus/cluster-setup.sh create"
sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"
```

Naming note: this is **cluster recreate on warm host**, not
"fresh deploy." Incus VM `destroy → create` resets the VM kernel
and userspace but does NOT reset the incus host's CPU frequency
governor, IRQ placement, bridges/veth plumbing, qdisc state, or
page cache. A production fresh deploy is on cold hardware; this
reproduction is on warm hardware. We acknowledge the limitation
and capture host-side state to disambiguate (Step 3).

Do *not* apply CoS config (matches cos-off precondition). Do *not*
run any iperf3 before the measurement.

### Step 2 — Direct iperf3 loop (5 iterations, continue-on-failure)

The standard matrix runner aborts on the first sub-threshold cell.
For root-cause work we want all iterations. Drive iperf3 directly:

```bash
# 5 iterations of cos-off-ipv4-push on port 5201 against the
# canonical target. All iterations captured regardless of result.
for iter in 1 2 3 4 5; do
  echo "=== iter $iter ==="
  sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -J -c 172.16.80.200 -P 12 -t 5 -p 5201" \
    | tee /tmp/1562-run${RUN}-iter${iter}.json
done
```

Notes:
- `-P 12` matches the smoke matrix's parallel stream count
  (canonical 12-stream gate from SKILL.md).
- `-t 5` matches the 5s iteration duration in Gate 6.
- Port 5201 matches the failing cell.
- 5 iterations (not 3) so we see whether iter 2 is a *specific*
  event or whether iter ≥2 stays in the dip regime.

### Step 3 — Pre-condition state capture before each iteration

```bash
# Per VM, before each iteration:
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- \
  bash -c 'cat /proc/loadavg; \
            grep MHz /proc/cpuinfo | head; \
            cpupower frequency-info 2>&1 | grep -E \"current CPU|governor\"; \
            ip -s link show ge-0-0-2 2>&1; \
            ethtool -S ge-0-0-2 2>&1 | grep -iE \"rx_packets|tx_packets|drop|error|xdp\" | head -20'" \
  | tee /tmp/1562-run${RUN}-iter${iter}-fw0-precond.txt

# Host-side state (incus host, captures the warm-host limitation):
cat /proc/loadavg /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>&1 || true
```

### Step 4 — Repeat 3 times (3 destroy/create cycles)

15 iterations total (3 cycles × 5 iters). Far stronger statistical
power than v1's 9 datapoints. If all 15 ≥ 18 Gbps, the 95% upper
bound on per-iteration failure probability is ~18% — still not
"impossible" but well below the failing-cell-every-deploy regime.

### Step 5 — Interpret with decision table

| Pattern | Verdict | Phase B path |
|---|---|---|
| All 15 ≥ 18 Gbps | **PLAN-KILL.** Close #1562 as superseded by unknown post-`13fa1009` change OR environmental change. Document. | None — issue closed. |
| Iter 1 ≥ 18, iter 2 always dips (<18) across all 3 cycles, iter 3-5 recover ≥18 | Real **iter-2 specific** pattern, not classical warm-up. | **Phase B-1**: iperf3 backend state across iterations / RG transition diagnosis / neighbor table flap. NOT a dataplane fix. |
| Iter 1 ≥ 18, iter 2-5 all dip across all 3 cycles | Sustained degradation after iter 1; not warm-up but post-iter-1 regime change. | **Phase B-2**: instrument xpf-userspace-dp counters (per-binding TX-ring, scratch_*, retry counters) to see what changed at iter 2. |
| Iter 1 mixed (≥18 sometimes, <18 sometimes), no consistent iter index | Environmental flake. Lab / kernel / firmware noise. | **Phase B-3**: relax Gate 6 to peak ≥ 18 + median ≥ 18 instead of per-iter, OR add documented pre-warm sweep. |
| Iter 1 dips, iter 2+ recover | Cold-cache / cpufreq / NUMA warm-up classical pattern. | **Phase B-4**: pre-warm 1s iperf3 before Gate 6 OR threshold relaxation. |
| Dip correlates with cpufreq state (governor lag, MHz mismatch with load) | cpufreq governor issue. | **Phase B-5**: lab cpufreq fix / governor pinning. Outside #1562 scope (lab config). |
| Dip correlates with NIC counter anomaly (xdp drops, TX errors, retransmits in dipped iter) | Hardware / firmware path. | **Phase B-6**: NIC-specific characterization. Outside #1562 scope. |
| Dip correlates with RG transition / VRRP role flap during iter 2 | Cluster state transition. | **Phase B-7**: HA quiet-period before Gate 6 matrix. |

The decision table makes Phase B's space concrete without
committing to a specific fix.

## Concrete design

There is **no code design** in this plan v1 — the proposed action is
measurement, not modification.

If reproduction confirms a real warm-up phenomenon, the design space
is:

- **Pre-warm sweep in the matrix runner:** drop a 1-second iperf3
  before the recorded 3-iteration window. Cheapest fix, no
  dataplane change.
- **Threshold relaxation with rationale:** lower the 18 Gbps
  per-iteration gate to 14 Gbps (peak/median ≥ 18 Gbps). Cheapest
  fix in terms of code churn but masks the underlying behavior.
- **Dataplane fix:** identify the cold-cache / first-traffic
  state and lift the per-binding TX-ring / page-cache / cpufreq
  cost. Most expensive, likely high-risk for a small (rare)
  win.

The "fix" comes from this plan only if Phase B reproduction
demands it.

## Public API preservation

N/A — measurement plan only.

## Hidden invariants the change must preserve

If Phase B ends up modifying the smoke matrix runner:

- The matrix-runner test target stay canonical `172.16.80.200`
  (i.e. don't dilute the gate by changing target).
- The 18 Gbps threshold is the project's documented Gate 6
  baseline. Any relaxation must be justified by reproduction
  data and documented in `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`.
- The "fresh deploy" matrix flow is the *production*
  representative flow. A pre-warm sweep that bypasses cold-cache
  state would invalidate the gate's "did we regress cold-start
  throughput?" semantics.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression risk | LOW | Pure measurement in Phase A; no code touched. |
| Lifetime / borrow-checker risk | N/A | No Rust changes proposed in Phase A. |
| Performance regression risk | LOW | Re-running the matrix can't regress production. |
| Architectural mismatch risk (#961 / #946 P2) | LOW | This is not a refactor; it's a measurement to decide if a fix is even warranted. The "architectural premise" being tested is "the dip exists post-master", which is empirically falsifiable. |

## Test plan

Phase A (this plan):
- [x] cargo build clean on master (sanity, verified)
- [ ] Cluster destroy/create/deploy clean × 3 cycles
- [ ] Direct iperf3 loop 5 iterations per cycle (continue-on-failure)
- [ ] Capture pre-condition state per iteration (load, cpufreq,
      ethtool counters, NIC stats)
- [ ] Capture host-side cpufreq governor + load
- [ ] Tabulate 15 iterations + classify against decision table

Phase B (only if Phase A reproduces a non-environmental pattern):
- Plan v3 follows from the decision-table verdict (B-1..B-7).

## Out of scope (explicitly)

- Any change to #1598 / #1600. Not in this plan's loop.
- Any change to PR #1594. Already merged.
- Modifying `userspace-ha-validation.sh` to source the env file's
  `IPERF_TARGET4`. The hard-coded canonical target is correct for
  the smoke matrix (matches `docs/ha-cluster-userspace.conf`).
- Changes to dataplane code. Phase A is measurement only.

## Open questions for adversarial review (PLAN-KILL invitations)

1. **Is there a path from #1594 to #1562 that I'm missing?**
   Specifically: does `userspace-phase-cycle.sh` or any helper it
   transitively invokes source `IPERF_TARGET4` from the env file
   for its iperf3 invocation? I walked
   `scripts/userspace-ha-validation.sh` lines 20-21 (hard-coded
   canonical target) and `scripts/userspace-phase-cycle.sh` (only
   passes `BPFRX_CLUSTER_ENV` for VM identity), but if a transitive
   call reaches the env file's target var, the plan's central
   premise is wrong.

2. **Is the difference between Gate 1's 23 Gbps and Gate 6's 21 →
   15 Gbps explained by Gate 1 running AFTER Gate 2-5 (which
   themselves push traffic and warm caches)?** I.e. is Gate 6
   actually colder than Gate 1 simply because of test ordering?
   If so, PLAN-KILL → fix is "run a 1-second pre-warm iperf3
   before Gate 6", trivial.

3. **Are the per-binding AF_XDP UMEM warm-up costs documented
   anywhere?** I'm asserting based on
   `feedback_cross_binding_impossible.md` that first-traffic per
   binding has TX-ring fill cost, but I have no per-binding
   timing measurement to back that. If the project knows
   first-traffic settles in <100 ms, the "warm-up phenomenon"
   framing is wrong and we're looking at something else
   (cpufreq, NUMA migration).

4. **Is iteration 2 of cos-off-ipv4-push the ONLY iteration that
   dipped, or did iteration 3 also dip and just not get
   recorded because the runner aborted on iter 2?** The log
   shows iter 2 aborts. We need iter 3 to distinguish "iter 2 is
   a specific event" from "every iteration 2 onwards is in the
   dip regime".

5. **Is there a #1561 (first-snapshot CoSBatch race) overlap I'm
   missing?** Issue body says "Related to but distinct from
   #1561 (first-snapshot CoSBatch crash). Both touch the helper's
   first-snapshot path." But #1562 is CoS-OFF, where the
   first-snapshot CoSBatch is a no-op. Unless the
   first-snapshot path has *other* state besides CoSBatch
   (which the issue body hints at) that affects cos-off
   throughput.

6. **Is "destroy/create/deploy" actually representative of fresh
   deploy semantics?** *(v1 question, retained.)* Plan v2
   acknowledges the gap in Step 1 naming and captures host-side
   state in Step 3.

7. **(NEW in v2)** Is the 30% iter-2 drop magnitude consistent
   with any single classical warm-up mechanism? AF_XDP first-touch
   TX-ring fill: should settle in <100ms, well within iter 1.
   cpufreq ramp on Intel: <500ms with ondemand governor.
   Page-cache for the dataplane binary: filled by deploy. NUMA
   migration: chronic skew, not iter-2-specific. The plan
   acknowledges this in the "honest scope" section but the
   reframing question deserves explicit reviewer pushback —
   should the issue be renamed away from "warm-up"?

8. **(NEW in v2)** Is 15 datapoints enough for PLAN-KILL when the
   alternative hypothesis is "rare flake"? With 15 clean
   datapoints, the 95% one-sided upper bound on failure
   probability is ~18%. If the iter-2 event has true probability
   <18% it can still survive Phase A. Is that acceptable?
   Reviewer judgment: yes, if all 15 pass we close #1562 with
   "could not reproduce; if dip returns, reopen with fresh
   evidence."

9. **(NEW in v2)** The plan does not propose modifying
   `userspace-ha-validation.sh` to capture iter 3+. Instead Step 2
   bypasses the matrix runner with a direct iperf3 loop.
   Should the runner itself learn continue-on-failure to make
   future Gate 6 evidence richer? Reviewer call: in scope for
   #1562 or separate runner-improvement issue?
