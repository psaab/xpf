# #1562 — fresh-deploy warm-up dip in cos-off-ipv4-push (#1477 Gate 6)

**Status:** DRAFT v1 — pending adversarial plan review.

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

### Step 1 — Tear down + recreate (truly fresh)

```bash
export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
sg incus-admin -c "./test/incus/cluster-setup.sh destroy"
sg incus-admin -c "./test/incus/cluster-setup.sh create"
sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"
```

Do *not* apply CoS config (matches cos-off precondition). Do *not*
run any iperf3 before the measurement (no human warm-up).

### Step 2 — Run the actual matrix smoke

```bash
sg incus-admin -c "BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./scripts/userspace-phase-cycle.sh --smoke-matrix" \
  2>&1 | tee /tmp/1562-reproduction-run1.log
```

This is the same script that produced the 15.014 Gbps measurement.
It runs cos-off-ipv4-push at port 5201, 3 iterations, 5s each.
Capture all three iterations even if one passes the 18 Gbps gate
(the smoke runner aborts on first sub-threshold, but we want the
full distribution — so wrap iperf3 manually if the runner short-
circuits).

### Step 3 — Repeat reproduction 3 times

A single run is not enough to distinguish "real warm-up" from
"environmental flake". Run the destroy-create-deploy-matrix loop
three times. Record all 9 iterations (3 fresh deploys × 3
iterations).

### Step 4 — Interpret

Outcomes:

| All 9 iterations ≥ 18 Gbps | → PLAN-KILL. #1562 is explained by something between `13fa1009` and current master (could be #1594-adjacent fixes, could be Linux/firmware/lab change). Close as superseded. |
| First iteration ≥ 18, iter 2-3 dips on every fresh deploy | → Real warm-up phenomenon, repeatable. Upgrade plan into Phase B: instrument to find root cause (per-binding TX-ring fill state, page-cache, cpufreq governor, ksoftirqd migration). |
| Sporadic dip (1 of 3 deploys) | → Environmental flake. Document and either relax Gate 6 (peak/median pass criterion) or add a documented warm-up sweep before Gate 6 measurement. Close #1562 with documented relaxation. |
| Different cell fails (e.g. iter 1 dips, iter 2 OK) | → Not warm-up but something else (RG transition state, neighbor table, cpufreq). Investigate. |

### Pre-conditions on master

Capture environment state per reproduction run:

```bash
# Per VM:
incus exec loss:xpf-userspace-fw0 -- cat /proc/cpuinfo | grep -E "MHz|model name" | head
incus exec loss:xpf-userspace-fw0 -- cpupower frequency-info 2>&1 | head -20
incus exec loss:xpf-userspace-fw0 -- ip -d link show ge-0-0-2  # WAN
incus exec loss:xpf-userspace-fw0 -- ip -d link show ge-0-0-0  # fab0 IPVLAN parent
incus exec loss:xpf-userspace-fw0 -- ethtool -i ge-0-0-2
incus exec loss:xpf-userspace-fw0 -- ethtool -k ge-0-0-2 | grep -i offload
incus exec loss:xpf-userspace-fw0 -- cat /proc/sys/net/core/busy_poll
incus exec loss:xpf-userspace-fw0 -- numactl --hardware | head -10
```

These attach to the reproduction log so reviewers can cross-check
"the WAN interface in production-like state" before/after each
iteration.

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
- [ ] cargo build clean on master (sanity)
- [ ] cargo test --release pass (sanity)
- [ ] Cluster destroy/create/deploy clean × 3 runs
- [ ] Smoke matrix → capture all iterations of cos-off-ipv4-push
- [ ] Capture pre-condition state per run (cpufreq, ethtool, NUMA)
- [ ] Tabulate 9 iterations + summarize verdict

Phase B (only if Phase A reproduces dip):
- Plan v2 follows from root-cause hypothesis.

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
   deploy semantics?** A production fresh deploy is on a brand-
   new VM with no prior kernel/firmware/JIT state. Incus VMs
   reset to a snapshot, which is similar but not identical.
   If the warm-up phenomenon is rooted in something that
   doesn't reset across `destroy → create` (e.g. host-side
   caches), the reproduction won't reflect production.
