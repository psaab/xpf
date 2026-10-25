# WAN Smart Queueing (SQM) Cookbook

Operator recipe for fq_codel/CAKE-class "smart queueing" on WAN uplinks
using the shipped userspace CoS engine. This is the #1828 Option C
deliverable (research plan `docs/research/1828-wan-sq/plan.md` v3 @
`d68a7fa5f`, branch `research/1828-wan-sq`).

This document is a **recipe**, not a design doc. The engine design —
hierarchical shaping, MQFQ flow fairness, admission AQM — lives in
[`docs/cos-traffic-shaping.md`](cos-traffic-shaping.md) and
[`docs/fairness-regimes.md`](fairness-regimes.md).

## Do NOT reach for `tc`

The settled boundary verdict (hostile-verified 3-way, posted on
[#1828](https://github.com/psaab/xpf/issues/1828#issuecomment-4673450296)):
kernel `fq_codel`/CAKE qdiscs on xpf dataplane uplinks are a **NO-OP for
forwarded traffic**. Both AF_XDP TX modes bypass the kernel qdisc layer
entirely — every forwarded-traffic transmit terminates at the XSK ring,
never enqueues into a qdisc. `tc qdisc add ... cake bandwidth 450mbit`
on a dataplane interface shapes only the trickle of host-originated
(slow-path) traffic and silently does nothing to the gigabits of
forwarded traffic. Smart queueing on xpf is done **in the userspace CoS
engine**, configured through `class-of-service` — that is what this
cookbook covers.

## What "smart queueing" means here

CAKE's product is one line that buys bandwidth shaping, per-flow
fairness, AQM, and sane defaults. The xpf mapping:

| CAKE property | xpf status | How |
|---|---|---|
| Bandwidth shaping | **shipped** | `class-of-service interfaces <if> unit <u> shaping-rate <bw>` — root token-bucket shaper per interface unit |
| Per-flow fairness ("fq") | **shipped, zero-config under contention** | MQFQ per-flow buckets on all shaped queues (#1735); the bare-shaping default queue promotes lazily when a second distinct flow contends (see nuance below) |
| AQM | **partial** | admission-path AQM is shipped: per-flow share caps, a 5 ms flow-fair aggregate delay clamp, and depth-threshold ECN CE marking. Which cap/ECN arm applies is regime-dependent (see "phrased honestly" below): the BDP-aware cap and per-flow ECN arm engage on different queue regimes, not both everywhere. Dequeue-time sojourn CoDel is #1829 Phase 2 (evidence-gated, not yet shipped) |
| DiffServ tiers | **shipped, multi-line** | forwarding-classes + classifiers + schedulers + scheduler-maps (see the DiffServ variant below) |
| Per-host isolation (`triple-isolate`) | **absent** | flow keying is the 5-tuple only; not planned |
| Ack-filter | **absent** | no ACK thinning anywhere in the TX path; not planned |
| Overhead compensation (`overhead`/`atm`) | **absent** | shaping accounts payload bytes, not wire bytes — tracked as [#1849](https://github.com/psaab/xpf/issues/1849) |
| Download-direction shaping | **shipped per egress interface** | no ifb redirect hack needed — shape the LAN-side egress unit (see below) |

## The upload (WAN egress) one-liner

```
set class-of-service interfaces reth0 unit 80 shaping-rate 450m
```

That single line admits the unit into the CoS engine and materializes a
**synthetic default best-effort queue** sized to the shaping rate. No
forwarding-classes, schedulers, or scheduler-maps are required.

Engine anchors, for the skeptical:

- **Admission**: the `contributes_usable_cos_state` gate in
  `userspace-dp/src/afxdp/forwarding_build/cos.rs` admits an interface
  on `cos_shaping_rate_bytes_per_sec > 0` alone.
- **Synthetic queue**: the same builder pushes a `queue_id 0`
  best-effort queue (`guarantee_enabled: true`, non-exact,
  `transmit_rate` = the shaping rate) when no scheduler-map queues
  exist. See also the synthetic-default-queue contract in
  [`docs/cos-traffic-shaping.md`](cos-traffic-shaping.md) ("Current
  Userspace Test Recipe" notes).
- **Per-flow fairness**: `maybe_promote_best_effort` in
  `userspace-dp/src/afxdp/cos/queue_ops/push.rs` (lazy MQFQ promotion,
  #1735); eligibility is set for every admitted queue in
  `userspace-dp/src/afxdp/cos/admission.rs` (`flow_fair_eligible`).
- **Admission AQM**: `cos_queue_flow_share_limit` (per-flow share
  cap — BDP-aware `max(fair_share×2, bdp_floor)` only on queues in
  the shared-exact service regime, #914; other flow-fair queues get
  the rate-unaware fair-share cap), `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS`
  (5 ms flow-fair aggregate delay clamp), and
  `apply_cos_admission_ecn_policy` (depth-threshold ECN CE marking —
  the per-flow arm fires only on flow-fair queues *outside* the
  shared-exact regime; shared-exact and legacy queues use the
  aggregate arm, deliberately: MQFQ already deprioritizes throttled
  flows' drain position, and per-flow marking on top would
  double-signal the same flow), all in
  `userspace-dp/src/afxdp/cos/admission.rs`.

### What it buys — phrased honestly

- **Always**: root shaping at 450 Mbit with bounded burst. The queue
  forms in xpf's shaped queue (which we control) instead of the
  upstream CPE/modem buffer (which we don't). This is the core SQM
  move and it is unconditional.
- **As soon as a second distinct flow contends**: per-flow MQFQ
  fairness (work-conserving DRR-class scheduling over 4096 flow
  buckets keyed by the 5-tuple), a per-flow share cap, and the 5 ms
  flow-fair delay clamp engage automatically via lazy promotion.
  Which *flavor* of cap and ECN you get depends on the queue's
  service regime, and the two upgrades do not coincide:
  - Queues serviced through the **shared multi-worker exact path**
    (typically higher shaping rates that exceed what one worker
    drains alone — the 3g LAN-side example below lands here) get the
    **BDP-aware** share cap (#914) but **aggregate** ECN marking.
  - Queues outside that regime (lower rates a single worker can
    service — the 450m/900m WAN examples here) get the rate-unaware
    fair-share cap but **per-flow** ECN marking.
  Both regimes have a functioning cap + ECN signal; neither has both
  premium variants at once. This is intentional engine behavior, not
  a configuration knob.
- **Single-flow nuance**: a bare-shaped queue **starts as a FIFO** and
  promotes to per-flow MQFQ only when a SECOND distinct flow arrives
  (the hash-free front-key probe in `push.rs`). Until then the
  per-flow share caps, the 5 ms flow-fair clamp, and the per-flow ECN
  arm are not active — a single flow gets aggregate admission ECN
  only, which is the correct congestion signal for one flow. There is
  no operator action here; it is just what "lazy promotion" means.

## The download direction (LAN egress) — no ifb needed

Classic SQM scripts shape ingress by redirecting through an `ifb`
pseudo-device. xpf does not need that: forwarded "download" traffic
**egresses the LAN-side AF_XDP interface**, so a `shaping-rate` on the
LAN unit shapes the download direction natively with the exact same
synthetic-queue mechanics:

```
set class-of-service interfaces reth1 unit 0 shaping-rate 900m
```

**Caveat — shaping is per egress interface.** There is no single global
download budget spanning multiple LAN/VLAN egresses: each egress unit
needs its own rate, and concurrent downloads to different LAN segments
can sum above the WAN's real downstream rate (each segment is
individually shaped, but the aggregate is not). This is the same
per-interface semantics as CAKE on a LAN interface. An aggregate-root
shaper across egresses would be a future engine feature — not claimed
here. For the common single-LAN-segment deployment this caveat is moot.

## Picking the rate

- Shape at **85-95% of the contracted/measured uplink rate** — the
  standard SQM headroom that keeps the bottleneck queue in xpf instead
  of the CPE. Start at 90%, walk up while bufferbloat telemetry (below)
  stays clean.
- The margin also covers what xpf does **not** model: the shaper is
  average-rate with bounded burst and accounts **payload bytes**, not
  wire bytes + per-packet framing. On low-rate framed uplinks
  (PPPoE/DSL/DOCSIS) small-packet-heavy mixes occupy more wire than
  the token bucket sees — stay nearer 85% there. CAKE-style per-packet
  overhead compensation is tracked as
  [#1849](https://github.com/psaab/xpf/issues/1849).
- Burst defaults to `max(shaping_rate_bytes / 100, 64 * MTU)` (about
  10 ms of rate); override with
  `set class-of-service interfaces <if> unit <u> shaping-rate burst-size <bytes>`
  if you need tighter or looser bursting. An explicit burst-size is
  honoured as configured even below the 96 KB default floor (floored
  only at one max frame, #16545) — the tighter bursting this knob
  promises on low-rate uplinks.

## DiffServ variant (EF/BE tiers)

If you want CAKE's `diffserv3/4`-style tiers instead of one fair
best-effort aggregate, use the existing multi-class surface:
forwarding-classes + a DSCP (or 802.1p) classifier + per-class
schedulers (`transmit-rate`, `priority`, optional `surplus-sharing`) +
a scheduler-map bound to the shaped unit. The worked example lives in
[`docs/cos-traffic-shaping.md`](cos-traffic-shaping.md) ("Junos-Style
Configuration" example: `ef-sched`/`be-sched` + `scheduler-maps my-map`
+ unit `shaping-rate`). Per-flow MQFQ fairness applies inside every
shaped class queue too (#1735) — tiers and flow fairness compose.

Two deliberate non-mappings, so nobody copies the wrong knob into an
SQM config:

- **`equal-flow-enforcement` is NOT the CAKE fairness analogue.** It is
  a non-work-conserving strict per-flow-equality clip with deliberate
  throughput loss, valid only on a positive exact-rate scheduler
  without surplus-sharing — a strict-SLA/measurement mode (see
  [`docs/fairness-regimes.md`](fairness-regimes.md)). CAKE's flow
  isolation is work-conserving — that is MQFQ, already automatic.
- **`transmit-rate exact`** per class is the SLA/measurement regime,
  not the WAN-SQM regime; this cookbook uses plain shaping (+ surplus
  sharing where classes appear).

## Reusable template via `apply-groups`

xpf's shipped config-template mechanism (`groups` + `apply-groups`,
`pkg/config/ast_groups.go`) makes the recipe reusable without any new
macro layer:

```
set groups wan-sqm class-of-service interfaces reth0 unit 80 shaping-rate 450m
set groups wan-sqm class-of-service interfaces reth1 unit 0 shaping-rate 900m
set apply-groups wan-sqm
```

Deactivate SQM in one line (`delete apply-groups wan-sqm`), re-enable
in one line, keep the rates versioned in one place.

## What to watch

- `show class-of-service interface` — the shaper binding, per-queue
  rates, and the admission counters
  (`Drops: flow_share=N buffer=N ecn_marked=N`). A growing
  `ecn_marked` under load is the AQM doing its job on ECN-capable
  flows.
- **MQFQ engagement**: Prometheus
  `xpf_userspace_cos_active_flow_count{ifindex,queue_id,worker_id}` —
  distinct active flows (~650 ms window) per CoS queue. A value > 1 on
  the shaped queue means lazy promotion has engaged and per-flow
  fairness is live. Aggregated views:
  `xpf_fairness_active_flows{ifindex,queue_id}` and the
  `xpf_userspace_cos_flow_fair_{buckets_occupied,flows_active}` pair
  (collision diagnosis, see
  [`docs/fairness-regimes.md`](fairness-regimes.md)).
- **Bufferbloat instrument** (#1829 Phase 1, shipped in PR #1846):
  per-queue dequeue-time sojourn gauges —
  `xpf_userspace_cos_sojourn_windowed_min_ns` (the standing-queue
  estimator: persistently above ~5 ms under load = standing queue),
  with `xpf_userspace_cos_sojourn_ewma_ns` / `_peak_ns` as supporting
  context. If windowed-min stays near 0 while shaped and loaded, you
  have no bufferbloat inside xpf; check the upstream device or lower
  the shaping rate.

## What is NOT covered (and where it is tracked)

- **CoDel on the shaped queue** — #1829 Phase 2, evidence-gated on the
  Phase 1 sojourn telemetry. A per-scheduler `codel-target` knob exists
  in the compiler today but is **inert** (write-only in the engine),
  and the bare-shaping synthetic queue hardcodes `codel_target_ns: 0`
  (`forwarding_build/cos.rs`). As of #4218 the leaf is typed (so
  `codel-target banana` is rejected at commit and `set ... codel-target
  ?` completes) and a **commit warning** fires when it is set, stating
  the value is accepted but has no runtime effect. When/if Phase 2
  ships, the planned `smart-queueing` unit leaf (#1828 Option B, gated
  rider) becomes the way to arm CoDel on a bare-shaped unit without
  rewriting into scheduler-maps. Do not set `codel-target` expecting AQM
  today.
- **`priority-low-min-share` (#1614 A2)** — typed + validated at commit
  (#4219) and completes, but the dataplane does **not** enforce it: it
  is wire-surface only (no `cap_eff` reservation exists — #4220). A
  commit warning surfaces the inertness; enforcement is deferred
  research. `docs/fairness-regimes.md` acceptance gate 2 is marked
  DEFERRED/NOT-IMPLEMENTED accordingly.
- **Per-packet overhead compensation** (CAKE `overhead`/`atm`) —
  [#1849](https://github.com/psaab/xpf/issues/1849); until then use
  the 85-95% headroom guidance above.
- **Per-host isolation** (CAKE `triple-isolate`) and **ack-filter** —
  not planned; flow fairness is 5-tuple-keyed MQFQ.
- **Ingress policing / auto-rate detection** — out of scope (#1828
  plan §11).

## Validation recipe (loss userspace cluster)

Fixture: [`test/incus/sqm-cookbook-config.set`](../test/incus/sqm-cookbook-config.set)
— the bare WAN one-liner on the cluster's WAN unit (`reth0` unit 80,
the reth0.80 / 172.16.80.0/24 path). A compile guard
(`pkg/config/sqm_cookbook_fixture_test.go`) pins that the fixture
parses and compiles on the production flat-set path.

Remember the standing gotchas: **deploy wipes CoS** (re-apply after
every deploy), and the iperf3 target is **172.16.80.200** (never
172.16.100.x). Run on the RG0 primary (`loss:xpf-userspace-fw0`).

```bash
# 1. Apply the fixture atomically (same pattern as apply-cos-config.sh:
#    strip to `set` lines, one candidate, commit check first, then
#    commit — the delete below makes the candidate idempotent).
grep '^set ' test/incus/sqm-cookbook-config.set > /tmp/sqm-cookbook.set
incus file push /tmp/sqm-cookbook.set \
    loss:xpf-userspace-fw0/tmp/sqm-cookbook.set
incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli <<'EOF'
configure
delete class-of-service
load merge /tmp/sqm-cookbook.set
commit check
commit
exit
quit
EOF

# 2. Verify the shaper is live.
incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c \
    "show class-of-service interface"

# 3. Multi-flow run through the shaped WAN path. -P 8, not -P 2: lazy
#    promotion needs two distinct flows on the SAME worker queue, and
#    the cluster's WAN VF spreads flows across 6 RSS queues — with
#    only 2 flows they land on the same worker ~1/6 of the time
#    (observed live: 2 flows -> two workers each reporting
#    active_flow_count 1, assertion (b) empty). 8 flows over 6 queues
#    pigeonhole at least one worker into >=2 flows, making (b)
#    deterministic.
iperf3 -c 172.16.80.200 -P 8 -t 20

# 4. Pinned assertions.
#    (a) Shape held: iperf3 aggregate ~= the fixture's shaping-rate
#        (3g fixture rate => ~2.8-3.0 Gbit/s SUM; line rate ~23 Gbit/s
#        would mean the shaper is NOT live).
#    (b) MQFQ promotion engaged: at least one active_flow_count sample
#        on the shaped queue is > 1. Sample WHILE step 3 runs (or
#        immediately after) — the gauge decays as flows go idle.
incus exec loss:xpf-userspace-fw0 -- \
    curl -s http://127.0.0.1:8080/metrics | \
    grep '^xpf_userspace_cos_active_flow_count' | awk '$2 > 1'
#    Non-empty output = promotion engaged (per-flow fairness live).
#    (c) Optional bufferbloat reading while step 3 runs:
incus exec loss:xpf-userspace-fw0 -- \
    curl -s http://127.0.0.1:8080/metrics | \
    grep '^xpf_userspace_cos_sojourn_windowed_min_ns'

# 5. Clean restore: remove the stanza, verify line rate returns.
incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli <<'EOF'
configure
delete class-of-service
commit
exit
quit
EOF
iperf3 -c 172.16.80.200 -P 2 -t 10   # expect unshaped line rate again
```

Note the fixture deliberately uses `shaping-rate 3g` (not the
cookbook's 450m WAN example) so the shaped-vs-unshaped distinction is
unambiguous on the 23 Gbit/s lab path while the run still completes
quickly; the mechanics under test (synthetic queue + lazy MQFQ
promotion) are rate-independent.
