# Research Plan: #1365 — 100E100M high-rate classes fail cwnd-settle before mouse latency probe

- **Status:** DRAFT v1 (draft-fanout, not yet reviewed)
- **Issue:** #1365
- **Branch:** `research/1365-100e100m-10g-cwnd-settle`
- **Author:** Claude (research)
- **Date:** 2026-06-20
- **Disposition (self-SMR):** LIKELY-DEFER-LAB — a concrete code-side
  root cause for the *reported* symptom is identified (harness env
  mismatch), but confirming it AND answering the broader "does the
  high-rate gate need an adaptive settle budget vs is the shaper
  unstable" question requires the loss userspace cluster. See §12.

---

## 1. Issue framing

Per #1365: after #1353/#1358/#1361 and the #1364 drain-timeout work,
the canonical 100E100M mouse-latency matrix can validate the default
5201 / 1 Gbps class, but the *first higher-rate class tried* —
described in the issue as "5202 / 10 Gbps" — never reaches the mouse
probe window. The loaded cell (`N=100, M=100`) returns
`0/15 valid, all INVALID-cwnd-not-settled`; the idle cell
(`N=0, M=100`) passes. Verdict: `INSUFFICIENT-DATA`.

The issue is explicitly **not** a mouse-latency PASS/FAIL. It is a
*harness/methodology* defect: the loaded high-rate cell invalidates
during the cwnd-settle gate, **before** the probe driver ever starts,
so no latency data is produced. The acceptance criteria ask to:

1. Add high-rate settle diagnostics to the artifact (final
   settle-window aggregate, per-flow min/median/max, retransmits,
   reason threshold).
2. Decide whether high-rate 100E100M should use an adaptive/longer
   settle budget or should fail as unstable.
3. Produce a gate-grade 5202 exact artifact that reaches the mouse
   probe, OR document why that shape is not a valid mouse-latency
   qualification target.
4. Only after exact reaches the probe, repeat with
   `MOUSE_COS_SURPLUS_SHARING=1`.

### 1.1 Key finding from code walk (changes the framing)

The issue's command shape is **internally inconsistent**, and this is
the dominant root cause of the reported symptom:

```bash
ELEPHANT_PORT=5202          # → forwarding-class iperf-1g
SHAPER_BPS=10000000000      # → 10 Gbps settle threshold
```

`test/incus/cos-iperf-config.set` term 2 maps **destination-port 5202
→ forwarding-class `iperf-1g`**, whose scheduler `scheduler-1g` is
`transmit-rate 1.0g` + `transmit-rate exact`. Per
`docs/cos-traffic-shaping.md` an `exact` reservation **caps aggregate
transmitted bytes** for the class (line 109) and **never receives
surplus by default** (line 194). So the entire iperf-1g class — across
all 100 elephant streams combined — is hard-capped at ~1 Gbps
aggregate.

The cwnd-settle gate
(`mouse_latency_orchestrate.build_cwnd_settle_diagnostics`) requires
the last-3 `[SUM]` interval rows to satisfy
`min_bps >= 0.7 * SHAPER_BPS`. With `SHAPER_BPS=10e9` that floor is
**7 Gbps**, but the class can deliver at most ~1 Gbps. The gate can
therefore **never** pass with this port/bps pairing — it is
arithmetically impossible, independent of any shaper or fairness
behavior.

Two corollaries:

- **There is no 10 Gbps exact class in the fixture.** The schedulers
  are 100m, 1g, 3g, 6g, 9g, 12g, 15g, 18g, 21g, 24g, uncapped (ports
  5201, 5202, 5203…5211). A "10 Gbps class" does not exist; the
  closest exact caps are 9g (port 5205) and 12g (port 5206). The
  issue's "5202 / 10 Gbps" label conflates a 1g-class port with a
  10G threshold.
- The header comment in `test-mouse-latency.sh` already states the
  rule that was violated: *"SHAPER_BPS MUST move with ELEPHANT_PORT
  because the cwnd-settle and collapse gates compare against it."*
  The reported run did not honor it.

This reframes the issue from "high-rate classes are unstable" to "the
canonical high-rate command shape used in the run was misconfigured;
separately, the gate offers no guardrail against that misconfiguration
and may also be genuinely too strict for legitimate high-rate
100-flow cells." Both deserve treatment; only the first is a sure
thing.

---

## 2. Honest scope & value

This is a **LAB/test-harness** issue. It touches only
`test/incus/*` (the mouse-latency harness) and `docs/*`. It does
**not** touch production Go control-plane or Rust dataplane source. It
has **no** HA/failover/boot/byte-order/hot-path implications in the
shipping product — the only "hot path" here is the shell/python
harness, and the only "failover" concern is that the harness must keep
*invalidating* reps that see real RG transitions (it already does, and
this plan must not weaken that).

Value: the harness is the gate that decides whether CoS algorithm work
(#1359 surplus-sharing, the #1829 telemetry phase) is even worth
pursuing on the high-rate classes. Right now the gate produces
`INSUFFICIENT-DATA` for everything above 1g, so the entire high-rate
half of the 12-cell matrix is unmeasurable. Fixing the harness unlocks
that measurement. But the *direct* fix (use a matching port/bps, or
auto-derive bps from port) is small.

> If reviewers conclude the perf gain/scope is too small to justify
> the churn, PLAN-KILL is acceptable. A defensible minimal outcome is:
> document the env-shape contract in the issue + the harness header,
> close #1365 as "command-shape misconfiguration; high-rate cells are
> measurable with a matching SHAPER_BPS," and let #1359/#1829 own any
> real shaper questions. The code changes below are an *optional*
> hardening layer on top of that documentation outcome.

---

## 3. What's already shipped

- **#1397 (`c8a21b5c9`)** already added the settle diagnostics
  artifact requested by acceptance item (1):
  `build_cwnd_settle_diagnostics` emits `cwnd-settle.json` with the
  final aggregate window (`window_bps`, `window_bps_min/max/mean`,
  `window_spread_ratio`, `window_min_utilization`), per-flow
  `mean_bps` min/median/max, `retransmits_total`, per-stream
  `cwnd_bytes_last`, slowest/fastest streams, and the threshold
  block (`min_aggregate_bps`, `max_aggregate_spread_ratio`,
  `shaper_bps`). The driver writes it at SETTLE_BUDGET
  (`test-mouse-latency.sh` step 5, `--out .../cwnd-settle.json`) and
  records `cwnd_settle_ok`/`cwnd_settle_elapsed_s` in `manifest.json`
  even on INVALID. **So acceptance item (1) is substantially done** —
  this plan should treat it as "verify it captures what's needed at
  10G-class scale," not "build it."
- The gate logic itself: last `window_rows=3` SUM rows, spread
  `<= 0.15`, min utilization `>= 0.7`. Evaluated **once**, at exactly
  `SETTLE_BUDGET` (default 20s), from a single snapshot
  (`iperf3-settle.txt`).
- Env-shape validation already enforces digits-only `SHAPER_BPS`,
  `ELEPHANT_PORT`, `MOUSE_PORT`; it does **not** enforce that they are
  *mutually consistent* — that is the gap.
- `#1364` bounds the probe `writer.drain()` (merged) — unrelated to
  the settle gate; it only affects the probe phase the cell never
  reaches.

---

## 4. Concrete design (code-level)

The work has up to four independently-shippable layers. The plan
recommends doing 4A + 4B (small, high-confidence) and treating
4C/4D as gated on lab evidence.

### 4A. Env-shape consistency guard (the direct root-cause fix)

In `test-mouse-latency.sh`, after the existing digits-only validation,
add a consistency check that rejects (or auto-derives) a `SHAPER_BPS`
that cannot match the class implied by `ELEPHANT_PORT`. Two sub-paths:

- **4A-i (preferred): auto-derive SHAPER_BPS from ELEPHANT_PORT** via
  a single source-of-truth port→class→rate table that mirrors
  `cos-iperf-config.set`. If the caller sets `SHAPER_BPS` explicitly,
  validate it equals the derived value (± a small tolerance) and
  `ABORT` with an actionable message otherwise. This removes the
  footgun entirely: the canonical matrix command no longer has to
  hand-pair port and bps.
- **4A-ii (minimal): validate only.** Keep `SHAPER_BPS` mandatory but
  `ABORT` when `SHAPER_BPS` is grossly inconsistent with the class
  cap (e.g. floor `0.7*SHAPER_BPS` exceeds the class `transmit-rate`).

The table belongs in one place. Options for where:
- a small `port_class_rate.py` consulted by both the driver and any
  wrapper (single SSOT, testable), OR
- a generated map emitted from `cos-iperf-config.set` at run start
  (no drift by construction, but more moving parts).

### 4B. Make the failure self-explanatory at the gate

Today the INVALID marker is just `cwnd-not-settled`; the *reason* lives
only in `cwnd-settle.json`. Enrich the INVALID reason / manifest so an
operator scanning markers immediately sees *why* (e.g.
`cwnd-not-settled-aggregate-too-low` vs `…-spread`). The
`build_cwnd_settle_diagnostics` `reasons[]` list already distinguishes
`aggregate-too-low` from `aggregate-window-spread`; surface the
dominant reason in the marker filename and `invalid_reason`. This is
acceptance item (1) finished + made legible.

### 4C. Adaptive / longer settle budget (gated on lab evidence)

The acceptance asks to *decide* between adaptive-settle and
fail-as-unstable. The decision needs data the harness must first
collect (see §4E). The design space (MULTIPLE PATHS — pick after lab):

- **Path C1 — fixed-longer budget.** Bump `SETTLE_BUDGET` for
  high-flow cells (e.g. 40–60s when `N >= 64`). Simplest; risks
  inflating wall time (the 6h matrix cap, `test-mouse-latency-matrix`
  §4.7) and still failing if instability is real.
- **Path C2 — poll-until-settled with a deadline.** Replace the
  single-snapshot-at-SETTLE_BUDGET evaluation with a loop: pull
  `iperf3-settle.txt`, run `settle-diagnostics`, and stop as soon as
  the gate passes OR a hard deadline (`SETTLE_MAX`) elapses. Records
  *time-to-settle* as a first-class metric. Most informative;
  moderate harness change; must respect the existing
  `incus file pull` cost cadence (do not pull every 100ms).
- **Path C3 — relax the gate for high-flow cells.** Keep the budget,
  widen `max_aggregate_spread_ratio` or lower `min_aggregate_utilization`
  for `N >= 64`. Cheapest but weakens the gate's meaning; only
  defensible if lab shows the spread at 100 flows is inherent fan-out
  jitter, not shaper instability. Highest risk of masking a real
  regression — disfavored unless evidence is strong.

The correct path is **undetermined without the lab**: C2's
time-to-settle metric is itself the evidence that decides between C1
and C3, so C2 is the recommended *first* lab instrument even if the
final shipped form is C1.

### 4D. Pick a real high-rate qualification target (gated on lab)

Acceptance item (3) wants a "gate-grade 5202 exact artifact that
reaches the probe." Because 5202 is the 1g class, the literal request
is satisfied by running 5202 with `SHAPER_BPS=1000000000`. To exercise
a genuinely *high-rate* class, the matrix must point at a high-rate
port (e.g. 5205/9g or 5206/12g) with the matching bps. Decide with the
lab which high-rate class is the meaningful qualification target for
the mouse-latency tail (it should be a class whose elephant load
actually contends with best-effort mice). Document the chosen target
in `docs/cos-validation-notes.md`.

### 4E. Settle-evidence enrichment to drive the §4C/§4D decision

Even before changing the gate, run the existing diagnostics at
high-flow scale and capture, per rep: time-series of the SUM aggregate
across the whole settle window (not just the last 3 rows), per-flow
retransmit totals, per-flow cwnd distribution, and the
`window_spread_ratio` trajectory. This is the dataset the reviewers
need to answer "adaptive vs unstable." Most of the fields already
exist in `cwnd-settle.json`; the gap is capturing the **trajectory**
(multiple snapshots over the settle window), which Path C2 provides
naturally.

---

## 5. Public API preservation

- No production gRPC/REST/CLI surface is touched. The only "API" is
  the harness env-var contract (`ELEPHANT_PORT`, `SHAPER_BPS`,
  `MOUSE_*`, `MOUSE_LATENCY_*`). Preservation rules:
  - **Backward-compatible default.** Default `ELEPHANT_PORT=5202`,
    default `SHAPER_BPS=1e9` already agree (both 1g) — do not break
    the no-env-var invocation.
  - If 4A-i auto-derives bps, an explicitly-set matching `SHAPER_BPS`
    must still be accepted (do not force callers to drop it — existing
    scripts and the issue's own command set it).
  - `manifest.json` / `cwnd-settle.json` schema is consumed by
    `mouse_latency_aggregate.py` and the `*_test.py` suites. Any new
    field must be additive; existing keys/types must not change
    (the aggregator and tests assert on them).
  - The INVALID-marker *prefix* `cwnd-not-settled` is matched by
    `mouse_latency_aggregate_test.py` (`assertTrue(any("cwnd-not-settled"
    in r ...))`). If 4B appends a reason suffix, keep `cwnd-not-settled`
    as a prefix so that substring match still holds.

---

## 6. Hidden invariants

- **HA/failover ordering.** The harness invalidates any rep with an
  in-window RG transition or VRRP MASTER/BACKUP event (steps 3, 9, 10
  of `test-mouse-latency.sh`). A longer/adaptive settle budget (4C)
  **extends the in-rep window**, which increases the chance of
  catching an unrelated cluster flap and invalidating a rep that would
  otherwise be good. The plan must keep the RG-poll end-time
  (`DURATION + SETTLE_BUDGET + SLACK + 5`) in sync with any settle
  budget change, or the poll loop will stop before the rep ends and
  silently lose HA coverage. This is the single most important
  invariant: **do not let a settle-budget change leave HA detection
  windows shorter than the actual rep.**
- **Hot-path allocation.** N/A to product code. For the harness:
  Path C2 must not `incus file pull` per tick (the loss cluster
  control socket / incus exec path is the contended resource — pull
  cadence should stay >= ~1–2s, mirroring the existing 1Hz RG poll).
- **Boot-class.** N/A — no daemon boot path touched.
- **Byte-order.** N/A — no wire/struct code.
- **Dual-AST / config compiler.** N/A — `cos-iperf-config.set` is
  applied via the existing `apply-cos-config.sh` path; this plan does
  not add config-mode grammar. If 4A reads the rate table *from*
  `cos-iperf-config.set`, the parser must tolerate both `1.0g` and
  `100m` unit forms and the `transmit-rate exact` second line.
- **Surplus-sharing ordering.** Acceptance item (4) ("only after exact
  reaches the probe, repeat with surplus") implies a strict
  dependency: do not attempt the surplus run until the exact high-rate
  artifact is gate-grade. The plan preserves that ordering.
- **CoS-wipe-on-deploy.** Every cluster deploy wipes CoS; the harness
  re-applies via `apply-cos-config.sh` per rep (step 1). Any new
  high-rate target must exist in the applied fixture, or the firewall
  filter will not classify the elephant port and the class cap will
  not engage.

---

## 7. Risk table

| Risk | Class | Likelihood | Impact | Mitigation |
|------|-------|-----------|--------|------------|
| 4A auto-derive drifts from `cos-iperf-config.set` if the fixture port grid changes | Correctness | Med | Med — silent wrong threshold | Single SSOT table + a unit test that cross-checks the table against `cos-iperf-config.set` terms |
| Longer settle (4C) widens HA-flap exposure → more spurious INVALID reps, longer matrix wall time vs 6h cap | Methodology | Med | Med | Keep RG-poll end-time synced to actual rep length; cap `SETTLE_MAX`; only extend for `N>=64` |
| Relaxing the gate (4C/C3) masks a real shaper regression | Correctness | Low-Med | High | Disfavor C3; require lab evidence that spread is inherent fan-out jitter before relaxing |
| Pulling `iperf3-settle.txt` too often (4C/C2) starves the incus control path / contends with other agents on the shared loss cluster | Performance (lab) | Med | Med | Pull cadence >= 1–2s; honor the cluster lock protocol (`with-cluster.sh`) |
| New manifest/diagnostics fields break `mouse_latency_aggregate.py` or `*_test.py` | Correctness | Low | Med | Additive-only schema; run the python test suite; keep `cwnd-not-settled` marker prefix |
| The reported instability at 100 flows is *real* (shaper/scheduler), not a gate-strictness artifact — fixing the harness then surfaces a true #1359-class regression | Scope | Med | High (good kind — finds a real bug) | Treat as a *handoff to #1359/#1829*, not in-scope here; this plan's deliverable is the evidence + a measurable gate, not a scheduler fix |

---

## 8. Test plan

### 8.1 Unit / offline (no lab)
- Extend `mouse_latency_orchestrate_test.py`: assert
  `build_cwnd_settle_diagnostics` produces `aggregate-too-low`
  when `SHAPER_BPS` exceeds the achievable class cap (the exact #1365
  scenario, replayed from a synthetic 1g-capped iperf3 text against a
  10G `shaper_bps`), and `aggregate-window-spread` for a jittery
  window. These run under `make test` / `python3 -m pytest` with no
  cluster.
- Add a 4A table test: every elephant port in `cos-iperf-config.set`
  terms resolves to a `transmit-rate` that the harness table agrees
  with (drift guard).
- `test_mouse_latency_shell_test.py`: assert the new
  consistency-guard / auto-derive lines exist (it already asserts on
  the script's settle lines).

### 8.2 Lab (loss userspace cluster) — **REQUIRED**
This issue cannot be *closed* on unit tests alone; the acceptance
items (2)(3)(4) are inherently empirical. Lab protocol in §9.

### 8.3 make test-failover
- **Not required by the change itself** (no cluster/VRRP/session-sync
  product code is touched). However, any 4C settle-budget change alters
  the HA-detection window inside the harness, so a single
  `make test-failover` run is a cheap sanity check that the cluster is
  healthy and that the harness still correctly *invalidates* a rep that
  overlaps a deliberate failover. This is a harness-correctness check,
  not a product-regression gate.

### 8.4 Multi-increment?
4A + 4B are one small PR. 4C + 4D + 4E are a second PR that is
*evidence-gated* and should not start until the lab run (§9) produces
the time-to-settle dataset. So this is naturally **two increments**;
the first is shippable and useful on its own (it makes the high-rate
cells measurable and self-explanatory).

---

## 9. Lab measurement protocol (loss cluster)

Engineering needs the lab for this. Exact protocol:

1. **Cluster + lock.** Use the shared loss userspace cluster
   (`loss:xpf-userspace-fw0/fw1`). Wrap all work in the cluster lock:
   `./test/incus/with-cluster.sh "1365 high-rate settle" -- <cmds>`.
   Never hand-roll `incus file push`. Re-apply CoS after any deploy
   (deploy wipes CoS): `./test/incus/apply-cos-config.sh
   loss:xpf-userspace-fw0`.

2. **Reproduce the reported failure (control).** Run the issue's exact
   misconfigured shape to confirm the arithmetic diagnosis:
   ```bash
   ELEPHANT_PORT=5202 SHAPER_BPS=10000000000 \
   MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
   MOUSE_LATENCY_GATE_PERCENTILE=p999_us \
   MOUSE_PROBE_CONNECTION_MODE=persistent MOUSE_PROBE_MIN_INTERVAL_MS=20 \
   ./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-1365-control-<ts>
   ```
   Expected: `0/15 valid, cwnd-not-settled`, and `cwnd-settle.json`
   shows `window_bps_min` ~1 Gbps against `min_aggregate_bps` 7 Gbps —
   i.e. `aggregate-too-low`, proving the threshold mismatch, not
   shaper jitter.

3. **Matched 1g shape (proves the class is fine).** Same port, matched
   bps:
   ```bash
   ELEPHANT_PORT=5202 SHAPER_BPS=1000000000 \
   MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
   MOUSE_PROBE_CONNECTION_MODE=persistent MOUSE_PROBE_MIN_INTERVAL_MS=20 \
   ./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-1365-5202-1g-<ts>
   ```
   Expected: the loaded cell reaches the probe (settles near 1 Gbps
   with spread <= 15%). If it does, the "high-rate class is unstable"
   hypothesis is refuted for 1g.

4. **Genuine high-rate class (the real question).** Point at a
   high-rate port with matched bps, e.g. 9g:
   ```bash
   ELEPHANT_PORT=5205 SHAPER_BPS=9000000000 \
   MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
   MOUSE_PROBE_CONNECTION_MODE=persistent MOUSE_PROBE_MIN_INTERVAL_MS=20 \
   ./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-1365-5205-9g-<ts>
   ```
   Capture `cwnd-settle.json` for every rep. Three outcomes:
   - **Settles within 20s** → no harness change needed beyond 4A/4B;
     the original failure was purely the bps mismatch. Disposition
     collapses to "documentation + guard."
   - **Settles but needs > 20s** → adaptive/longer budget (Path C1/C2)
     is justified; capture time-to-settle to size the budget.
   - **Never settles, high spread + rising retransmits** → genuine
     shaper instability at 9g×100 flows; hand off to #1359/#1829 and
     document the high-rate class as fail-as-unstable.

5. **Surplus repeat (ordering-gated).** Only after step 4 yields a
   gate-grade exact artifact that reaches the probe, repeat with
   `MOUSE_COS_SURPLUS_SHARING=1` (this feeds #1359).

6. **Env shape contract — the load-bearing rule for whoever runs
   this:** `SHAPER_BPS` MUST equal the `transmit-rate` of the class
   that `ELEPHANT_PORT` maps to in `cos-iperf-config.set`:
   - 5201→1e8 (100m), 5202→1e9 (1g), 5203→3e9, 5204→6e9, 5205→9e9,
     5206→1.2e10, 5207→1.5e10, 5208→1.8e10, 5209→2.1e10, 5210→2.4e10,
     5211→uncapped (no exact cap — settle gate against 5211 is not
     meaningful; do not use it as a qualification target).

---

## 10. Out of scope

- Any change to the CoS scheduler / shaper Rust code
  (`userspace-dp/src/afxdp/...`). If the lab shows real high-rate
  instability, that is #1359/#1829 territory, not #1365.
- Changing `cos-iperf-config.set` to *add* a literal 10G exact class.
  The grid is intentional (1/3/6/9/12/15/18/21/24g); adding 10g to
  match the issue's mislabel would be cargo-culting the typo.
- The surplus-sharing p99.9 product question (#1359) and the
  win-min telemetry phase (#1829 / `cos-validation-notes.md`
  Phase-1 gate). #1365 only needs the harness to *reach* the probe.
- IPv6 / dual-stack settle behavior (the matrix is v4-only per #905
  §2; not regressing here).
- The probe driver, drain bound (#1364), and aggregator gate logic
  (`mouse_latency_aggregate.py`), except for additive field consumption.

---

## 11. Open questions (for adversarial review)

1. **Is the reported failure 100% the bps mismatch, or is there a
   *second* real instability hiding behind it?** The arithmetic proves
   the gate could never pass at 5202/10G regardless — but that means
   the run produced **no** evidence about whether 100 flows on a
   genuine high-rate class settle. We cannot answer "adaptive vs
   unstable" until the lab runs step 4 (§9). Should the plan commit to
   a path before that, or stay strictly evidence-gated?

2. **Auto-derive (4A-i) vs validate-only (4A-ii)?** Auto-deriving
   `SHAPER_BPS` from `ELEPHANT_PORT` removes the footgun but creates a
   second SSOT that can drift from `cos-iperf-config.set`. Validate-only
   keeps the caller responsible but lets a matched-but-wrong pair slip.
   Which is the right ergonomics/safety tradeoff for a lab harness?

3. **Does extending the settle budget (4C) materially raise the
   spurious-INVALID rate from HA flaps on the shared loss cluster?**
   The cluster is shared; longer reps = wider exposure to *other
   agents'* deploys/failovers. Is a fixed-longer budget (C1) actually
   *worse* for matrix completion than just documenting the matched
   shape and keeping 20s?

4. **What is the right high-rate qualification target?** 9g (5205)?
   12g (5206)? Or should the mouse-latency tail be measured against
   the *uncapped* class (5211) where elephants genuinely saturate the
   link and best-effort mice are most stressed — even though the
   settle gate's `0.7*shaper` floor has no meaning for an uncapped
   class? Does the whole "settle against a shaper" premise even apply
   to the contention case the mouse-latency test is supposed to model?

5. **Is the cwnd-settle gate the right precondition at all for
   high-flow cells?** The gate exists to ensure the elephants are in
   steady state before measuring mouse tail latency. At 100 flows on a
   shaped class, "steady state" may legitimately be a higher-variance
   regime (per-flow fan-out across 6 workers, per
   `docs/fairness-regimes.md`), so a tight ±15% aggregate-spread gate
   may be the wrong shape entirely. Should the gate move from
   "aggregate near shaper" to "aggregate *stable* (low drift) over a
   window," decoupled from the absolute shaper value?

6. **Should #1365 be split or merged with #1359?** The harness-reach
   problem (#1365) and the surplus-sharing tail-latency problem
   (#1359) share the same matrix and the same high-rate cells. Is
   there churn savings in doing the harness hardening as part of the
   #1359 campaign rather than standalone?

---

## 12. Claude self-SMR (hostile)

**Strongest objection to my own plan:** The headline "root cause" —
the 5202/10G bps mismatch — may be *known and intentional* to whoever
filed #1365. The issue author clearly ran a deliberate command and
labeled it "5202 / 10 Gbps"; they may have *meant* to stress-test the
gate, or may already know 5202 is 1g and used 10G as a "settle to
whatever the link gives" proxy. If so, my central finding is a
restatement of something obvious to them, and the *real* ask is the
substantive one: "do high-rate 100-flow cells need an adaptive settle,
or are they unstable?" — which I **cannot answer without the lab**. So
the plan risks over-indexing on a documentation/guard fix (4A/4B) that
feels satisfying but sidesteps the question the issue actually cares
about.

**Second objection:** even 4A/4B is arguably not worth a PR. The
harness header *already documents* the SHAPER_BPS-must-move rule. Maybe
the entire fix is a one-line correction to the canonical matrix command
in whatever runbook produced the issue, plus a note on the issue — no
code at all. The code-side hardening (a consistency guard) protects
against a class of operator error that has occurred exactly once, on a
LAB-only script, run by experts.

**Counter to my own objections:** the arithmetic is checkable and
load-bearing regardless of intent — the gate *provably* cannot pass at
5202/10G, so any future run with that shape wastes up to 15 reps × 30s
of shared-cluster time producing `INSUFFICIENT-DATA`. A cheap guard
(4A) that fails fast with an actionable message is worth more than its
size on a shared, contended lab resource. And 4B (legible INVALID
reasons) is pure upside. But the substantive adaptive-vs-unstable
decision is genuinely lab-gated.

**Explicit disposition: LIKELY-DEFER-LAB.**
- The *first increment* (4A consistency guard + 4B legible INVALID
  reasons + unit tests + doc of the env-shape contract) is shippable
  offline and small, and it directly prevents the reported
  `INSUFFICIENT-DATA` footgun. If reviewers want it, it can proceed as
  a standalone PR without the lab.
- The *issue cannot be closed* — and the core acceptance items (2),
  (3), (4) cannot be answered — without the loss userspace cluster
  running §9 steps 2–5. That dataset (especially step 4's
  time-to-settle at a genuine high-rate class) is what decides between
  adaptive-budget (C1/C2), gate-relax (C3), fail-as-unstable, or
  "no change needed beyond the guard."
- If the lab step 4 shows real shaper instability at high flow counts,
  the substantive work is **not #1365's** — it hands off to #1359 /
  #1829, and #1365 closes as "harness now reaches the probe; high-rate
  instability tracked in #1359."

Secondary disposition note: if reviewers judge 4A/4B too small to
justify a PR, **PLAN-KILL with a documentation-only outcome** (fix the
runbook command + annotate the issue) is acceptable and explicitly
endorsed in §2.
