# CoS admission validation — methodology and current baseline

This file documents how to validate changes to the userspace-dp CoS admission path
(anything that touches `cos_flow_aware_buffer_limit`,
`cos_queue_flow_share_limit`, `apply_cos_admission_ecn_policy`, or the
admission block in `enqueue_cos_item`). Read it before opening a PR that
claims to move TCP fairness, retransmit count, or cwnd-collapse numbers on
the 16-flow iperf3 workload — otherwise you are likely to repeat the
mistake described in #725 or the VLAN-offset bug resolved in #728.

Current validation fixture map: iperf ports 5200..5211 and TCP echo
ports 6200..6211 share the same CoS class index. 5200/6200 are
best-effort/root-shaped, 5201/6201 are 100M exact, 5202/6202 are 1G
exact, then 5203..5210 / 6203..6210 step through 3G, 6G, 9G, 12G, 15G,
18G, 21G, and 24G exact. 5211/6211 are uncapped except for the
interface root shaper. Older measurements below may cite the pre-grid
class names (`iperf-a`/`iperf-b`/`iperf-c`) and queue IDs.

## vSRX CoS show commands (#4228 Gap 7)

In addition to `show class-of-service interface` (the detailed per-queue
runtime dump described below), xpf renders the four Junos-style CoS
operational commands whose backing data already existed but had no
operational-tree surface. All are pure presentation over existing data —
`cfg.ClassOfService` (the compiled config) and `CoSQueueStatus` (the
userspace status) — with no dataplane change:

- `show interfaces queue [<interface>]` — per-egress-queue Queued /
  Transmitted / Dropped counters, sourced from `CoSQueueStatus`
  (`QueuedPackets/Bytes`, `DrainSentBytes`, the admission-drop counters).
  Optional interface filter; a physical-name selector (`ge-0-0-2`)
  matches the unit-qualified runtime label (`ge-0-0-2.80`).
  `FormatInterfacesQueue` distinguishes three states so operator
  uncertainty is never laundered into "no CoS" (#5326): (1) a status
  *fetch error* (helper down, control socket unavailable, decode error)
  renders `error retrieving class-of-service queue status: <err>` — the
  CoS runtime state is UNKNOWN, not empty; (2) a successful but empty
  snapshot renders the legitimate `No class-of-service queues active`;
  (3) a successful non-empty snapshot renders the per-queue counters.
  Callers (`pkg/cli` and the gRPC `ShowText` path) pass the status
  *error* through to the formatter — a nil status must not conflate
  "unreachable" with "empty".
- `show class-of-service classifier [name <n>] [type <dscp|ieee-802.1>]`
  — the configured classifiers, rendering the code point as 6-bit binary
  (DSCP) or 3-bit binary (802.1p PCP), with forwarding-class and loss
  priority (defaulting to `low` when the config omits it).
- `show class-of-service scheduler-map [<name>]` — each scheduler-map's
  forwarding-class -> scheduler bindings, resolved to the scheduler's
  transmit rate, priority, buffer, and exact flag plus the mapped queue.
- `show class-of-service forwarding-class` — the forwarding-class to
  queue table (ID == queue, per the FC<->queue bijection).
- `show class-of-service rewrite-rule [name <n>] [type <dscp|ieee-802.1|
  inet-precedence|exp>]` (#6848) — the configured egress rewrite rules.
  Added after the four above; see the next section for why it is not just
  a fifth table.

`clear class-of-service statistics` is deferred (#4228 Gap 7 note): the
userspace CoS queue counters have no stat-reset RPC — they reset only on
config change — so a reset path is a separate follow-up.

## `show class-of-service rewrite-rule` and the inert-rule problem (#6848)

The rewrite-rule view is the one Junos CoS show command the Gap 7 pass
did not land, and it matters more now than it did then. When #4228 was
written `rewrite-rules` held only `dscp`. Since then the config models
three more families — `ieee-802.1` (#4228 Gap 4), `inet-precedence` and
`exp` (#4316) — and **all three are accepted-but-inert**: they commit
clean and have no runtime effect, because the userspace dataplane
rewrites DSCP on egress only.

That left an operator able to configure four kinds of rewrite rule,
three of which do nothing, with no operational command to display any of
them. The only signal was a commit-time advisory that scrolls past once
(`pkg/config/compiler_validate_warn.go`: `ieee-802.1` at :1360,
`inet-precedence` at :1346, `exp` at :1350).

So the renderer reports **enforcement as a column**, not a footnote — with
**three** states, not two:

1. **`dscp` and bound** by some unit — actually applied on egress.
2. **`dscp` and bound by nothing** — configured, no runtime effect. The
   dataplane builds the rewrite table only for the rule an interface
   references (`tables.dscp_rewrite_rules.get(&iface.cos_dscp_rewrite_rule)`,
   `forwarding_build/cos.rs`), so an unbound rule rewrites nothing.
3. **Any other code-point type** — the dataplane rewrites dscp only.

State 2 was originally collapsed into state 1: `Enforced` was computed from the
code-point TYPE alone, so an unbound dscp rule printed `Enforced: yes`. That is
the accepted-but-inert failure class one level in — reproduced inside the
command written to expose it — and worse than having no command, because it
turns an unanswered question into a confidently wrong answer. Both fixtures
omitted the interface binding and asserted `Enforced: yes`, so the tests pinned
the defect rather than the contract; `Enforced: yes` must be **earned** by a
real binding.

Scanning `CoSInterface.Units` alone is sufficient for the bound-rule set: the
compiler folds an interface-level binding into every configured unit
(`applyCoSInterfaceLevelBindings`), which is why the snapshot builder iterates
Units too.

So the renderer reports **enforcement as a column**, not a footnote:

```
Rewrite rule: rw-dscp, Code point type: dscp, Enforced: yes
  Forwarding class  Loss priority  Code point
  best-effort       low            000000
  premium           low            101110

Rewrite rule: rw-pcp, Code point type: ieee-802.1, Enforced: no (accepted
for Junos compatibility; the dataplane rewrites dscp only)
  Forwarding class  Loss priority  Code point
  premium           high           101
```

Two implementation facts worth knowing before changing this:

- **The four families do not carry equal data.** `dscp` and `ieee-802.1`
  compile to full entry lists (forwarding-class, loss-priority,
  code-point). `inet-precedence` and `exp` record only rule NAMES
  (`ClassOfServiceConfig.INetPrecedenceRewriteRules` / `EXPRewriteRules`)
  — the compiler builds no runtime structure because nothing consumes
  one. Those two render a `Code points not modeled` line rather than an
  empty table, which would imply a fidelity the config does not have.
  `TestShowTextCoSRewriteRuleNameOnlyFamiliesAreProducible6848` authors a
  rule *with* a code point in real set syntax and asserts it does not
  surface, so this stays honest if the compiler ever starts modeling
  them.
- **The family list lives in THREE places, and the config schema is the
  authority.** They are `format.CoSRewriteRuleTypes`, the cmdtree `type`
  completion children, and the renderer's own hardcoded per-family
  branches in `FormatCoSRewriteRules`. Adding a family means editing all
  three. Until #6858 the note here said "editing one list; the test fails
  if the other is not updated" — that was false in the direction that
  matters: the test compared the first two, nothing but that test read
  `CoSRewriteRuleTypes`, and deleting `appendNameOnly("exp", …)` from the
  renderer left the whole suite green.

  Both checks now measure against `schemaClassOfService["rewrite-rules"]`
  (`pkg/config/schema_cos.go`) — the families an operator can actually
  commit — and both live in `pkg/cmdtree`, the only package that can see
  the schema, the renderer and the tree at once (`pkg/config` cannot
  import `format`, because `format` imports `config`):
  `TestCoSRewriteRuleTypeChildrenMatchRenderer` for the two lists, and
  `TestCoSRewriteRuleRendererCoversEverySchemaFamily`, which commits a
  rule of every schema family and renders it, for the branches. A fifth
  family added to the schema fails all three until it is handled.

`cosRewriteRuleEnforcement` (`pkg/dataplane/userspace/format/cos_show.go`)
is the enforced/inert mapping; it returns the rendered `Enforced:` string,
not a bool. **A family that starts being enforced must flip there in the
same change that drops its commit advisory**, or this command will report
a working rewrite as inert. That biconditional is asserted over every
committable family by
`TestCoSInertAdvisoryAgreesWithRenderedEnforcement6858`
(`pkg/dataplane/userspace/format`), so the two halves cannot move apart
silently — before #6858, deleting the ieee-802.1 advisory reddened exactly
one test, in `pkg/config`, and the formatter stayed green.

`Enforced:` has THREE states, not two. For a `dscp` rule the answer also
depends on whether anything **the dataplane will read** binds it:

- **`yes`** — some CONFIGURED logical interface unit references the rule.
- **`no (not bound — no interface unit references this rule)`** — the rule
  is configured and nothing binds it. An unbound rule rewrites nothing:
  the runtime table is populated only for the rule an interface
  references (`tables.dscp_rewrite_rules.get(&iface.
  cos_dscp_rewrite_rule)`, `forwarding_build/cos.rs`).
- **`no (not bound — class-of-service interfaces <if> unit <n> is not a
  configured logical interface unit)`** — the operator DID write a
  binding, but against an interface or unit that has no `interfaces`
  stanza (#6858 round 3).

That third state is not hypothetical. `set class-of-service interfaces
ge-9-9-9 unit 0 rewrite-rules dscp rw` COMMITS with no `interfaces
ge-9-9-9` anywhere — one typo in an interface name, or a unit number that
does not match the logical unit, is enough. The commit does warn
(`compiler_validate_warn.go:1586` / `:1599`, "class-of-service interface
%s is bound but not configured under [interfaces]"), and that advisory is
precisely the "scrolls past once" signal this whole command exists to
replace with a standing operational view. A warning at commit time is not
a licence for the show command to answer the question wrongly six months
later.

**The predicate must mirror `buildInterfaceSnapshots`**
(`pkg/dataplane/userspace/interfaces.go`). That builder walks
`cfg.Interfaces.Interfaces` and, for each REAL logical unit, reads
`cfg.ClassOfService.Interfaces[name].Units[unitNum]` to stamp
`CoSDSCPRewriteRule` onto the snapshot — so `cosBoundDSCPRewriteRules`
walks from the same side. Walking `cos.Interfaces` instead (the shape it
had before round 3) reported `Enforced: yes` for a binding the helper can
never see, which is the dangerous direction: it converts an unanswered
question into a confidently wrong "DSCP remarking is happening". The
reason names the dead reference, because an operator who did write the
binding reads a bare "not bound" as "you forgot to bind it" and looks in
the wrong place. `TestFormatCoSRewriteRulesDanglingInterfaceBindingIsNotEnforced6858` pins both dangling shapes plus the bound positive control.

The command still answers from CONFIG, not from the live snapshot, so
`yes` means "the dataplane is given this rule for this unit", not "this
packet was remarked". Conditions that live only in the helper's own
admission gate — a rewrite rule whose forwarding-classes do not intersect
the queues the interface materializes, for instance — are out of its
reach; see #7063.

Renderers live in `pkg/dataplane/userspace/format/cos_show.go` (the
shared SSOT used by both the local CLI in `pkg/cli` and the gRPC
`ShowText` path in `pkg/grpcapi`); the operational-tree entries and
tab-completion are in `pkg/cmdtree/tree.go`.

### The `name` / `type` filter grammar is single-sourced (#6858)

`show class-of-service classifier` and `show class-of-service
rewrite-rule` take the same optional `name <n>` / `type <t>` filters, and
also accept a **leading bare token** as the name (that is what completion
offers under the command, so it is what an operator submits after
tab-completing). All three surfaces call the same functions in
`pkg/cmdtree/cos_filter_topic.go`:

| surface | calls |
|---|---|
| local CLI (`pkg/cli`) | `ParseCoSNameTypeArgs` |
| remote CLI (`cmd/cli`) | `ParseCoSNameTypeArgs` then `CoSNameTypeTopic` |
| gRPC server (`pkg/grpcapi`) | `ParseCoSNameTypeTopic` |

Before #6858 the grammar was written three times, and the two arg parsers
had already drifted — `pkg/cli` honored a trailing `name` keyword over a
leading bare token and `cmd/cli` did not — under a comment asking editors
to keep the mirrored test tables in step.

The topic encoding also lost data. It joined params with `,` and split on
`,`, but a rule or classifier NAME may contain a comma: `set
class-of-service rewrite-rules dscp "rw,x"` commits and reads back as
`rw,x`. Remotely the name truncated at the comma, so the server rendered
the rule named `rw` — a *different* rule — or, where `rw` named nothing,
reported that the operator's rule did not exist. The flaw was pre-existing
(`cos-classifier` carried it since #4228) and both commands share the one
decoder, so #6858 fixed both.

Values are now percent-escaped for `% , = :` and space, and unescaping is
tolerant of a bare `%` that is not a valid escape. A name containing none
of those encodes byte-identically to the old form, so ordinary topics are
unchanged on the wire. Mixed-version behaviour for a comma-bearing name
degrades to "no match" rather than the wrong rule — visibly wrong instead
of confidently wrong; `cli` and `xpfd` ship together anyway.

Parity is therefore one property, not a pair of mirrored tables:
`ParseCoSNameTypeTopic` inverts `CoSNameTypeTopic`
(`TestCoSNameTypeTopicRoundTrip6858`). The per-surface tests assert
*wiring* — that each surface routes through these functions —
rather than restating the grammar:
`TestLocalCoSRewriteRuleFilterWiring6858` (`pkg/cli`, drives the real
dispatcher), `TestCoSNameTypeTopic6848` (`cmd/cli`), and
`TestCoSRewriteRuleLocalRemoteParity6858` (`pkg/grpcapi`), which renders
the same operator tokens through both paths and requires identical output
for both commands.

The grammar fails closed for trailing tokens and missing keyword values
(#11834). For example, `... classifier type dscp tyep` and `... classifier
name` return a usage error instead of silently dropping the typo or filter
and displaying the broader unfiltered result. The shared parser returns
these errors to both CLI frontends before either renders output.

## How to read admission drop counters live

Since #724, `show class-of-service interface` renders three per-queue
counters on an indented `Drops:` line:

```
Queue  Owner  Class    ...  Buffer     Queued pkts  Queued bytes  ...
4      1      iperf-a  ...  1.19 MiB   299          443.24 KiB    ...
       Drops: flow_share=1923  buffer=0  ecn_marked=0
```

Definitions (from `CoSQueueDropCounters` in `userspace-dp/src/afxdp/types.rs`):

- `flow_share` — packets dropped because a single flow's bucket already holds
  its entire `share_cap` worth of bytes. The dominant failure mode on
  flow-fair exact queues under multi-flow load **before** ECN marking
  landed end-to-end.
- `buffer` — packets dropped because aggregate queue depth exceeded
  `buffer_limit`. Usually zero because #716 + #720 keep the aggregate
  nowhere near the cap.
- `ecn_marked` — count of successful ECN CE marks. Zero when either
  (a) the threshold never trips, or (b) no ECT packets reach the
  firewall, or (c) the marker is reading the wrong byte (see #728 —
  the VLAN-offset bug made the marker dormant even with ECT(0)
  on the wire).

Zero-valued counters are still printed. That is deliberate: an operator
needs to see the zero to confirm the counter is wired and the drop path
simply is not firing, versus the telemetry being broken.

The CLI joins configured CoS interfaces to live userspace runtime rows by
configured name first, then by the binding egress ifindex. Reverse egress
configs can display as a physical unit such as `ge-0-0-1.0` while the runtime
snapshot carries a different alias for the same ifindex; the ifindex fallback
keeps those reverse-path counters visible instead of reporting
`Runtime: unavailable`.

`show chassis cluster data-plane userspace` also prints an aggregate CoS
admission attribution beside the generic `TX errors` counter:

```
TX errors:                 332019
TX errors non-admission:   50
CoS queue drops lifetime:  331969
CoS admission drops:       331969
CoS flow-share drops:      111471
CoS buffer drops:          220498
CoS ECN marked:            16496600
TX shared recycle unk:     0
```

`TX errors` remains the generic superset used by the dataplane's error
paths. CoS admission drops intentionally still increment it because a packet
was not transmitted, but the adjacent `TX errors non-admission` line subtracts
the binding-scoped `CoS queue drops lifetime` counter from the binding-scoped
`TX errors` counter so AF_XDP/ring/shared-UMEM failures are not confused with
expected shaper backpressure. Those two counters share the same lifetime and
survive CoS config resets. The binding-scoped CoS subset includes admission
rejects and reset-time CoS queue drains.

The formatter deliberately does not subtract the current-runtime
`CoS admission drops` reason split from `TX errors`; those reason counters live
on the active CoS runtime and reset on CoS config commits. If the
binding-scoped CoS subset briefly appears larger than `TX errors` during a
publication window, the formatter clamps `TX errors non-admission` to zero.
Treat that as sample skew unless it persists across later snapshots.

The summary `CoS admission drops`, `CoS flow-share drops`, `CoS buffer drops`,
and `CoS ECN marked` lines are aggregate sums across the current CoS runtime's
interfaces and queues. They are useful for explaining the active scheduler
epoch, but they can reset after a CoS config commit. If `CoS queue drops
lifetime` is larger than the current reason split, a prior epoch or reset-time
queue drain likely contributed. Treat non-zero lifetime CoS queue drops as a
shaping or buffering question first; treat non-zero non-admission TX errors as
the higher-severity transmit-path question.

### Reading them during an iperf3 run

```bash
# 16-flow iperf3 in background
incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5201 -i 0 >/dev/null 2>&1 &

sleep 10   # let the queue fill and the counters move

# Read the live counters mid-test
incus exec loss:xpf-userspace-fw0 -- \
  /usr/local/sbin/cli -c "show class-of-service interface"

wait   # let iperf3 finish
```

The counters are monotonic from process start. For a delta over a run,
snapshot before and after and subtract.

## gRPC server-side capture

AF_XDP bypasses the kernel network stack, so `tcpdump` on the firewall
netdev (`reth0`, `reth0.80`, physical member `ge-0-0-0`) **does not see
bulk data-plane traffic** — it only sees slow-path packets that fell back
through the kernel. This makes firewall-side netdev captures useless for
confirming what reached or left the dataplane on the hot path.

The `iperf-grpc-tcpdump` skill in `.codex/skills/iperf-grpc-tcpdump/SKILL.md`
solves this by running `tcpdump` on the iperf3 **server** over a gRPC
capture endpoint at `172.16.80.200:50051`, synchronised with LAN/WAN
captures on the active firewall and an iperf3 run from the client.

Ad-hoc capture (no iperf3 coordination) looks like:

```bash
grpcurl -plaintext -d '{"iface":"eth0","duration_s":30,"filter":"tcp port 5201"}' \
  172.16.80.200:50051 capture.CaptureService/Run > server-grpc.txt
```

For the full orchestrated run (server + LAN + WAN + iperf3 + stats
before/after), use the skill's helper:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4 --parallel 16 --duration 30
```

This capture path is how #728 was diagnosed: server-side tcpdump
confirmed ECT(0) bits were present on ingress frames **before** the
firewall's marker ran, which ruled out "the endpoint doesn't negotiate
ECN" and pointed directly at the marker's L3 offset. Without the gRPC
capture we would have spent another round chasing phantom endpoint
problems. Use it whenever a local tcpdump shows `tos 0x0` on a VLAN
subinterface before concluding "ECN isn't negotiating" — the real packet
on the wire may say otherwise.

## Choosing a fix path

When the counters show something different from the current baseline
(see below), the pathology and the right fix may be different. Before
pulling a row out of the table below, **check per-queue cap
utilisation first**: pull the queue's configured `transmit_rate_bytes`
from `show class-of-service interface`, divide the measured 16-flow
aggregate by it, and only attribute residual fairness jitter to TCP
physics (per-flow ratio ≥ ~1.2×, retrans non-zero, rate ratio > 1.2×)
*after* confirming the queue is delivering ≥ 95 % of its cap. If the
queue is under-delivering, the residual is scheduler misbehaviour
masquerading as TCP jitter — pre-#754 the 1 Gbps queue sat at 60 %
of cap and the jitter signal was an artefact of the ECN threshold
firing on every cwnd-growth attempt (see the "1 Gbps queue over-
throttle fix (post-#754)" section below).

The decision tree:

| `flow_share` | `buffer` | `ecn_marked` | Interpretation | Likely fix |
|---|---|---|---|---|
| low (~10s/flow/30s) | 0 | high (~100k/30s) | Current post-#728 baseline. ECN holds cwnd at the knee; residual drops are microburst arrivals the marker couldn't catch in time. **Verify queue delivers ≥ 95 % of cap before concluding "residual is TCP physics" — if cap utilisation < 95 %, the mark rate is the bug (see #754).** | #709 owner-worker hotspot / #718 Option B CoDel for the microburst residual. |
| high | low | 0 | Per-flow cap too tight; no ECN to soften it. Before concluding "endpoint doesn't negotiate ECN", run a gRPC server-side capture (see above) — #728 was this symptom caused by a VLAN-offset bug, not by the endpoint. | Confirm ECT on the wire via gRPC capture, then: fix marker if ECT present; otherwise ECN end-to-end, or CoDel (non-ECN AQM), or relax per-flow cap. |
| high | low | high | ECN fires but TCP still drops — ECN signal not enough | Lower ECN threshold, or combine with rate-based pacing |
| low | high | any | Aggregate cap tripping — bufferbloat | Revisit #720 clamp; look at operator `buffer-size` setting |
| 0 | 0 | 0 | Nothing is dropping; problem is elsewhere | Look at #709 (owner worker), #712 (CPU pinning), or network-layer loss |

#1312 pinned the canonical iperf fixture buffers for the low-rate exact
classes after reverse `-P 12` reproduced high retransmits with equal-flow
disabled: `scheduler-100m` uses `buffer-size 500k` and
`scheduler-1g` uses `buffer-size 4m`.

When `buffer-size` is omitted, queue `base` comes from
`max(transmit_rate_bytes/100, 96_000)` (10 ms of bytes with a 96 KB
floor), then `cos_flow_aware_buffer_limit` applies flow-aware expansion
and the #717 5 ms envelope clamp:
`base.max(prospective_active * 24 KB).min(delay_cap.max(base))`, where
`delay_cap = transmit_rate_bytes * 5 ms`.

These fixture overrides intentionally sit above that implicit cap because
the exact flow-fair admission gates need enough aggregate and per-flow
headroom to avoid persistent tail-drop at 12 active TCP flows. They also
trade latency headroom for retransmit suppression (`500k` at 100M ≈ 40 ms
residence; `4m` at 1G ≈ 32 ms at full queue). Treat changes to these
fixture values as admission-policy changes and rerun the q1/q2 reverse
sweep before trusting low-rate fairness evidence.

## Pre-buffer-sizing dominant failure mode on this workload

**Observed 2026-04-17, post-#728.** This is a dated snapshot, not
timeless methodology. Re-measure before citing these numbers in a new PR.

Fixture: `test/incus/cos-iperf-config.set`, 1 Gbps exact queue on queue 4,
16-flow iperf3, `net.ipv4.tcp_ecn=1` end-to-end, 30-second runs.

| Counter | Value |
|---|---|
| Rate ratio (max/min across flows) | 1.28× |
| Retransmits / 30 s | ~114 k |
| `flow_share_drops` / 30 s | ~75 (≈12 per flow) |
| `buffer_drops` / 30 s | 0 |
| `ecn_marked` / 30 s | ~97,349 |
| cwnd steady state | 8–17 KB |
| Queue depth steady state | ~150 KB (≈1.5 ms queueing latency) |

The admission path is doing what it was designed to do: ECN holds every
flow at the fairness knee (cwnd ≈ 12 KB), aggregate queueing stays around
1.5 ms, and packet drops are rare.

The residual ~12 `flow_share` drops per flow per 30 s are not the
RTO-driven collapse #704 was about — they come from microburst arrivals
where several packets from the same flow land in the same enqueue tick
faster than CE marks can propagate back through the TCP ack clock. The
remaining levers for this residual are the ones already tracked:

- **#709 (owner-worker hotspot)** — pinning the admission path to a
  dedicated worker reduces enqueue-tick variance, which reduces the
  microburst window.
- **#718 Option B (CoDel)** — adds a second AQM dimension that reacts
  to sojourn time, catching bursts that ECN threshold-based marking
  misses.

Neither is structurally required. The current baseline is a healthy,
fair, ECN-paced queue; the residual is the tail of what AQM can do
without rate pacing on the sender.

## History: the "ECN never negotiated" fire drill

**Resolved 2026-04-17 via #728 (VLAN-aware L3 offset).**

An earlier version of this doc documented a "limitation" that the
iperf3 server at `172.16.80.200` did not negotiate ECN, leaving
`ecn_marked=0` regardless of client/firewall `tcp_ecn` settings. That
was wrong. The server negotiates ECN correctly and ECT(0) packets were
reaching the firewall. The real bug was a hard-coded `TX_L3_OFFSET = 14`
in both Local and Prepared markers; on a VLAN subinterface
(`reth0 unit 80`) the frame carries an 802.1Q tag and L3 lives at
offset 18. The marker was reading the VLAN TCI byte, which rarely
matches ECT(0)/ECT(1), so the RFC 3168 NOT-ECT early-return fired on
every packet.

The lesson: **do not conclude "ECN isn't negotiated" from a
firewall-side tcpdump that shows `tos 0x0`**. AF_XDP means the
firewall-side capture doesn't see dataplane traffic at all, and even a
local client-side capture can be misleading if the path crosses a VLAN
boundary. Use the gRPC server-side capture at `172.16.80.200:50051` to
disambiguate where in the chain the ECT bits are being lost (or
mis-read).

The verification command still works — the conclusion to draw from it
is narrower than before:

```bash
# Capture 4 packets from an in-progress iperf3 run and look at tos.
# tos 0x0 in both directions does NOT by itself mean ECN is not
# negotiating — it may mean you are reading the wrong interface or
# hitting the #728 class of bug. Cross-check with a server-side gRPC
# capture before committing to that conclusion.
incus exec <client> -- tcpdump -v -c 4 -n 'tcp port 5201'
```

## Reading the owner-profile counters

Since #709 (Option E), `show class-of-service interface` renders a
second indented line under each queue row whose owner is a single
worker. This gives operators a latency view of the owner-worker
drain path without having to scrape Prometheus or attach perf:

```
Queue  Owner  Class    ...  Buffer     Queued pkts  Queued bytes  ...
4      1      iperf-a  ...  1.19 MiB   299          443.24 KiB    ...
       Drops: flow_share=75  buffer=0  ecn_marked=97349
       OwnerProfile: drain_p50=1us  drain_p99=16us  drain_invocations=1234
       Binding telemetry: redirect_p99=2us  owner_pps=12345  peer_pps=6789
```

Field meanings (from `BindingLiveState` in `userspace-dp/src/afxdp/umem.rs`):

- `drain_p50 / drain_p99` — p50/p99 of the time spent inside
  `drain_shaped_tx` across its servicing tick. Sampled on EVERY
  invocation, bucketed into power-of-two ns buckets from 1 µs to
  ~16 ms. Lower bound of the bucket containing the Nth percentile
  sample is reported — it is a ballpark, not an exact stat.
- `redirect_p99` — p99 of the time spent in
  `BindingLiveState::enqueue_tx_owned` (the redirect-inbox push path
  peer workers use to deliver packets to the owner). Sampled 1-in-256
  on each producer to keep the common case allocation- and
  timer-free.
- `owner_pps` — packets the owner sourced itself on the window
  (accumulator, cleared by
  `clear statistics class-of-service`).
- `peer_pps` — packets peer workers redirected into the owner's
  MPSC inbox on the same window. Ratio tells the operator whether
  the owner is sourcing the bulk of the work itself or acting
  mostly as a fan-in point for peer redirects.

### What the shape means for #709

The plan (`docs/pr/709-owner-hotspot/plan.md` §3) lays out a decision
tree that converts these counters into a fix path:

- **drain_p99 ≈ drain_p50 (flat right tail).** The owner drain is
  not the bottleneck. Close #709 as not-needed; keep #712 for CPU
  jitter.
- **drain_p99 ≥ 10× drain_p50 (fat right tail).** The owner has a
  head-of-line stall — most drains finish fast but a long tail of
  slow ones accumulates. Data supports Option B (work-stealing
  off-owner drain). The structural fix is worth the complexity.
- **drain_p99 is fine but redirect_p99 > 1 ms.** Unusual post-#715
  (the MPSC inbox is lock-free); if seen, pivot to a smaller
  producer-side fix rather than Option B.
- **drain_p99 ~ µs but owner_pps >> peer_pps.** The owner is
  overloaded with its own RX/forward/NAT work and only does a small
  amount of cross-worker redirect drain — Option C (RSS retargeting)
  or Option D (owner rotation) becomes more justified because the
  issue is "owner doing 2× work" not "inbox latency".

The guideline is the same one `engineering-style.md` sets out for
all perf PRs: read the counters, then decide. Iterating on fixes
without reading them is how we ship dormant code.

### Operational gotchas

- **Non-exact / shared_exact queues have no `OwnerProfile` latency
  line.** The latency histogram is per-binding on the owner's
  `BindingLiveState`; if there is no single owner binding
  (shared_exact at ≥ 2.5 Gbps, or non-exact queues), the CLI
  suppresses that row. Queue-scoped `DrainShape` counters still render
  when non-zero. For best-effort/exact contention, compare
  `guarantee`, `surplus`, and
  `nonexact_while_exact_backlogged`; a rising non-exact/exact-backlog
  delta means best-effort or uncapped service ran while exact queues on
  the same shaped interface still had demand.
- **The counters are process-monotonic.** For a windowed delta on
  live traffic, snapshot before and after and subtract — same as
  the `Drops:` line.
- **Prometheus:** the same data flows out as
  `xpf_cos_drain_latency_ns_bucket{ifindex, queue_id, bucket_hi_ns}`,
  `xpf_cos_redirect_acquire_ns_bucket{...}`,
  `xpf_cos_drain_invocations_total{ifindex, queue_id}`,
  `xpf_cos_owner_pps{ifindex, queue_id}`,
  `xpf_cos_peer_pps{...}`,
  `xpf_userspace_cos_drain_guarantee_sent_bytes_total{...}`,
  `xpf_userspace_cos_drain_surplus_sent_bytes_total{...}`, and
  `xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total{...}`.
  Expected cardinality per the plan: ≤ 8192 series per histogram.

## Reading the park-reason counters for surplus-sharing tail latency (#1359)

The four per-queue park-reason counters carried on the CoS snapshot are
also exported to Prometheus (#1359 surfaced them — they were previously
wire-only). They attribute *why* a CoS queue stalled, which is the
diagnostic acceptance item for the #1359 surplus-sharing mouse-latency
investigation:

- `xpf_userspace_cos_root_token_starvation_parks_total{ifindex, queue_id}`
  — the queue was parked at the shaper because the **shared root** token
  bucket was empty (someone else is holding the shared root rate).
- `xpf_userspace_cos_queue_token_starvation_parks_total{ifindex, queue_id}`
  — the queue was parked because its **own per-queue** token bucket was
  empty (this queue is hitting its own rate cap — a *different* cause).
- `xpf_userspace_cos_drain_park_root_tokens_total{...}` /
  `xpf_userspace_cos_drain_park_queue_tokens_total{...}` — the per-batch
  drain-loop equivalents (a finer-grained view of the same root-vs-queue
  split, counted inside `drain_shaped_tx` rather than at the shaper).

**How to read the surplus-sharing tail.** Under the reduced 100E100M
matrix, strict-exact passes the p99.9 mouse gate (~7-8 ms) while
surplus-sharing produces 29-51 ms tails. To attribute the tail, take a
windowed delta (snapshot before/after the loaded cell, subtract) on the
best-effort / mouse queue row:

- A **rising `root_token_starvation_parks`** delta on the mouse queue
  while a surplus-sharing borrower (the elephant) is draining is the
  fingerprint of **root-surplus arbitration**: the borrower spent the
  shared root tokens the mouse needed, so the mouse parked waiting for
  the root bucket to refill. This is the leading #1359 hypothesis
  (work-conservation borrows root rate → standing queue → mouse tail),
  and these counters confirm or refute it without a code change.
- A rising `queue_token_starvation_parks` with a *flat*
  `root_token_starvation_parks` would instead point at the mouse hitting
  its OWN cap — not a surplus side effect — and would refute the
  borrow-starvation story.

This is diagnostic telemetry only; it changes no scheduling decision.
Pair it with `queued_bytes` (standing-queue residence) and the
`drain_surplus_sent_bytes` borrow volume to separate root-surplus
arbitration from CPU contention or timer-wheel wake delay. See the #1359
research plan (`research/1359-surplus-sharing-mouse-latency`) for the
full candidate-cause table.

## Reading the sojourn telemetry (#1829 Phase 1)

Every shaped queue now measures per-packet **sojourn** — the time an
item spends in the CoS queue, `now_ns - enqueue_ns`, stamped at the
admission choke point (`enqueue_cos_item`) and sampled at the
committed-prefix TX settle points — a packet is sampled exactly once,
on the attempt that actually ships it; partial/zero TX-insert
rollbacks are never sampled. This is the measurement-first half of the
FQ-CoDel plan: Phase 2 (the CoDel control law on `codel-target`) is
**gated on this telemetry's live evidence** and does not exist yet —
setting `codel-target` today still changes nothing.

Three per-queue values, on the wire (`CoSQueueStatus`), the CLI, and
Prometheus:

| Field | Prometheus gauge | Meaning |
|---|---|---|
| `sojourn_windowed_min_ns` | `xpf_userspace_cos_sojourn_windowed_min_ns` | **The gate metric.** Minimum sojourn over the last 1-2 100 ms windows (two-bucket flip-flop) — CoDel's standing-queue estimator. |
| `sojourn_ewma_ns` | `xpf_userspace_cos_sojourn_ewma_ns` | Shift-add EWMA (α=1/8) over pops. Supporting context only. |
| `sojourn_peak_ns` | `xpf_userspace_cos_sojourn_peak_ns` | Lifetime max (same contract as `active_flow_buckets_peak`). |

```
show class-of-service interface reth0.80
    Queue 4 ...
           Drops: flow_share=0  buffer=0  ecn_marked=312
           Sojourn: win_min=1.8ms  ewma=2.5ms  peak=9.0ms
```

How to read it:

- **`win_min` persistently above `codel-target` (default candidate
  5 ms) for ≥ one 100 ms window = standing-queue evidence** — the
  §6.1d gate criterion (a) for proceeding with Phase 2. A transient
  burst inflates `ewma`/`peak` but NOT `win_min`; only a queue that
  never drains below the value for a whole window moves the minimum.
- **`win_min` = 0 means "no standing queue"**, in one of two ways: no
  pops in the last ~2 windows at snapshot time (the export is
  evaluated against the snapshot pass's `now_ns`, so a stale reading
  cannot outlive the backlog that produced it), or items popping with
  ~zero queueing delay. Either way: no CoDel case on this queue.
- `ewma`/`peak` are **biased high by scheduler service gaps** (a
  single 10 ms gap between visits inflates both while the true
  standing queue is zero) — that is exactly why the windowed minimum
  is the gate metric (plan AGY r2 F2). Use them only to size the
  distribution, never as standing-queue evidence.
- Aggregation is **MAX-merge** at both layers (worker instances →
  worker row; workers → coordinator row): the row reports the
  worst-instance value, which is what a per-worker Phase-2 CoDel
  would act on. It is NOT an average across the interface.
- The CLI line appears only after the queue has recorded at least one
  sample (`peak > 0`); idle queues stay clean. The Prometheus gauges
  emit unconditionally (a `win_min` 0 on a busy queue is the gate
  evidence's strongest negative result and must be visible).

Phase-1 gate procedure (plan §6.1d): re-run the #1359 100E100M
surplus-sharing matrix and the per-class sweep with this telemetry
deployed, capture `win_min` per queue per regime concurrently with
the mouse-latency probes, and proceed to Phase 2 only if (a) some
shaped queue sustains `win_min` above target for ≥ one interval in a
regime we care about AND (b) those excursions correlate in time with
the failing p99.9 probe cells. If (a) fails everywhere, Phase 2 is
PLAN-KILLED and #1829 closes with this telemetry as the deliverable.

## Reading the waterfill trace counters (#1628)

For interfaces in `oversubscription-policy guarantee-rate` mode the
two-phase waterfill selector
(`select_exact_cos_guarantee_queue_waterfill`) carries per-class trace
counters. They surface on `show class-of-service interface` and
Prometheus to make the #1630-verified root cause — multi-worker
queue-ownership fragmentation + the Phase-1/Phase-2 split — empirically
visible. They are **diagnostic only**: the scheduler reads none of them,
and they are zero on the default Proportional (legacy RR) path.

Since #4408 that selector is an orchestrator over three named phases in
`userspace-dp/src/afxdp/cos/queue_service/mod.rs`, which is where each
counter below is actually bumped:

| Phase fn | Counters it bumps |
|---|---|
| `refill_waterfill_epoch` | `epochs` |
| `waterfill_phase1_select` | `phase1_admit`, `phase1_budget_breaks`, and the Phase-1 half of `eligible_visits` |
| `waterfill_phase2_select` | `phase2_admit` and the Phase-2 half of `eligible_visits` |

`phase1_no_progress` belongs to none of the three: it is bumped — and
`phase1_admit` correspondingly decremented — by
`apply_phase1_waterfill_honor_refund`, which
`service_exact_guarantee_queue_direct_with_info` invokes after a Phase-1
honor that transmitted zero bytes. The #4408 split was pure motion; no
counter semantics changed.

```
show class-of-service interface reth0.80
  ...
  Waterfill:                epochs=412 phase1_budget_breaks=9 min_epochs_per_worker=3
    Queue 5 ...
           Waterfill:    phase1_admit=0  phase2_admit=512  eligible_visits=540  phase1_no_progress=44
```

Per-queue (a queue has ONE owner worker, so the row reflects that
worker):

- `phase1_admit` / `phase2_admit` — admissions via the Phase-1
  (small-first honored) vs Phase-2 (descending residual) walk.
- `eligible_visits` — times the selector reached this queue eligible and
  evaluated it (both phases, BEFORE the token gate).
- `phase1_no_progress` (hb166 T-2) — times Phase 1 HONORED this queue but
  it made ZERO TX progress, so the budget debit and the honored bit were
  refunded. Climbing here while `phase1_admit` stays flat on a backlogged
  small class = TX-ring pressure eating the guarantee pass (the
  #1630/#4256 mid-rate-residual signal). It is the direct counterpart to
  `phase1_admit`: `phase1_admit` counts Phase-1 visits that made TX
  progress, `phase1_no_progress` counts the ones that did not.

Per-interface (summed across workers, except the MIN):

- `epochs` — completed Phase-1 budget refills (cluster SUM).
- `phase1_budget_breaks` — times Phase 1 ran out of budget mid-walk and
  fell into Phase 2 (cluster SUM). High breaks-per-epoch = Phase 1
  routinely can't honor the ascending set.
- `min_epochs_per_worker` — coordinator MIN of each worker's per-binding
  MIN over its bindings WITH active exact-guarantee backlog (so a healthy
  binding cannot mask a sibling binding locked in Phase 2 within one
  worker). A LOW value vs `epochs` is the single-stalled-selector flag;
  `0` is a HARD lock-in (a backlogged binding that completed zero epochs).
  An idle interface with no active-backlog candidate carries the
  `u64::MAX` sentinel, which Prometheus SUPPRESSES (no series) and the CLI
  renders as `none` — so any emitted value, including `0`, is a real
  lock-in signal and alertable with `< N`.

**Interpretation contract — these are EVIDENCE, not standalone
fingerprints.** `phase1_admit=0, phase2_admit>0` is a Phase-2 lock-in
ONLY when combined with, on the same queue row:

- `queued_bytes > 0` (the class has backlog), AND
- `root_token_starvation_parks` / `queue_token_starvation_parks` rising
  (it is being parked), AND
- the class is SMALL — its configured `transmit-rate` fits within the
  interface Phase-1 budget (`shaping-rate × guarantee-fraction`).

For a LARGE class above the Phase-1 cutoff the identical shape
(`phase1=0, phase2>0, backlog, parks`) is HEALTHY rate-limiting — it was
never meant to win Phase 1. A class with zero `queued_bytes` and no parks
is simply idle on that owner, not starved (a token-parked backlogged
queue is `!runnable` and skipped at the eligibility gate, so it shows LOW
`eligible_visits` — pair with the park counters to tell parked from
idle).

Prometheus: `xpf_userspace_cos_waterfill_phase1_admissions_total`,
`..._phase2_admissions_total`, `..._eligible_visits_total`,
`..._phase1_selected_no_progress_total` (per `{ifindex, queue_id}`);
`xpf_userspace_cos_waterfill_epochs_total`,
`..._phase1_budget_breaks_total`, and the gauge
`xpf_userspace_cos_waterfill_min_epochs_per_worker` (per `{ifindex}`).

## CPU pinning layout for the loss lab

**Measured 2026-04-17 for #712 Option A.** Conclusion: the
`CPUAffinity=` directive on `xpfd.service` is a no-op on the 6-core
loss userspace lab because `userspace-dp` re-pins its workers inside
the process after systemd's mask is applied. Keep this section dated;
re-measure if any of the three blockers below move.

### Intended layout on the 6-core lab

The host is a 6-CPU VM. NIC IRQ distribution on fw0 under 16-flow
iperf3 load, sampled from `/proc/interrupts`:

- mlx5_comp0 (WAN VF RX q0) → CPU 0, ~800 M interrupts
- mlx5_comp1 (WAN VF RX q1) → CPU 1, ~900 M interrupts
- mlx5_comp2..5 (WAN VF RX q2..5) → CPUs 2..5, ~500-900 M each
- virtio-input/output q0..5 → pinned 1-per-CPU across CPUs 0..5

Each CPU carries NIC IRQ load; CPUs 0-1 are the hottest. The recipe in
`docs/712-cpu-pinning-recipe.md` §"6-core host" reserves CPUs 0-1 for
IRQ + housekeeping and gives xpfd and its four dp workers CPUs 2-5:

```
[Service]
CPUAffinity=2 3 4 5
```

### Why that recipe is a no-op today

`xpf-userspace-dp` calls `pin_current_thread(worker_id)` in
`userspace-dp/src/afxdp/neighbor.rs`, which issues
`sched_setaffinity(0, CPU_SET(worker_id % nproc))` per worker **after**
systemd has installed the unit mask. `nproc` (via
`std::thread::available_parallelism()`) correctly reports 4 when the
process is launched with `CPUAffinity=2 3 4 5`, but the call pins each
worker to absolute CPU `worker_id % 4` — i.e. CPU 0, 1, 2, 3 — not to
the 0th..3rd CPU of the allowed set. Result: the four hot-path workers
land on CPUs 0-3 regardless, colliding with `mlx5_comp0` and
`mlx5_comp1`. The Go main and the dp aux threads (state-writer,
event-stream, slowpath, neigh-monitor) do honour the mask and run on
CPUs 2-5.

### Measurement

16-flow iperf3 × 30 s × 3 runs, client
`cluster-userspace-host`, target `172.16.80.200`, CoS fixture
`test/incus/cos-iperf-config.set` applied, fw0 primary. Computed with
`/tmp/712-pinning/analyze.py` (iperf3 `-J` on the client; per-flow CoV
is the standard deviation of the per-second bps samples on each stream,
divided by that stream's mean).

| Metric | Pre-pin mean | Post-pin mean | Δ |
|---|---|---|---|
| Rate ratio (max/min per-flow) | 1.39× | 1.45× | +4% (worse) |
| Retransmits / 30 s | 181 k | 204 k | +13% (worse) |
| Per-flow CoV mean | 14.3% | 15.9% | +1.6 pp (worse) |
| Per-flow CoV max | 25.4% | 26.4% | +1.0 pp (flat) |

All deltas within run-to-run noise. No metric moved in a good
direction. Acceptance criterion from #712 — per-flow stdev/mean ≤ 10% —
was not met pre-pin (~14%) and not closer post-pin. Per
`engineering-style.md` §"Hot-path coding discipline", the directive
was reverted in the same PR; the recipe doc lives on as design intent.

### Blockers before Option A can land as a win

1. ~~`pin_current_thread` must pick the Nth allowed CPU, not absolute
   CPU N.~~ **Fixed in #740.** Workers correctly honour the inherited
   mask as of master `b5e7fc2f`. Verified during the #741 retry below.
2. Option B (kernel cmdline `isolcpus=`+`nohz_full=`) would remove
   kernel timers and RCU callbacks from worker CPUs entirely. It
   requires a cmdline edit and reboot, so deployment shape has to opt
   in. Tracked as a follow-up to #712 (#739). After the #741 retry
   this is the next lever to try on this hardware.
3. Option D (cgroup cpuset) is softer and does not require a cmdline
   change but needs operator decisions about which cpuset holds which
   non-xpfd process. Tracked as a follow-up to #712.

## CPU pinning retry post-#740

**Measured 2026-04-17 for #712 Option A retry (#741).** Conclusion:
with the #740 fix in place, workers correctly pin to CPUs 2-5 — but
the aggregate iperf3 metrics still do not move by the #712 thresholds
on this hardware. The layout is verified as applied; the 6-core lab
does not benefit from systemd-level pinning alone.

### Verification (Phase 3)

Taken live with `CPUAffinity=2 3 4 5` loaded, xpfd running, before
the Phase 4 iperf3 runs:

```
pid 65616's current affinity mask: 3c

65619 ctrl-c         cpus_allowed=2-5 psr=3
65620 iou-wrk-...    cpus_allowed=2-5 psr=5
65628 neigh-monitor  cpus_allowed=2-5 psr=2
65621 session-socket cpus_allowed=2-5 psr=2
65618 xpf-event-strea cpus_allowed=2-5 psr=2
65622 xpf-slowpath   cpus_allowed=2-5 psr=3
65617 xpf-state-write cpus_allowed=2-5 psr=4
65616 xpf-userspace-d cpus_allowed=2-5 psr=5
65624 xpf-userspace-w cpus_allowed=2   psr=2
65625 xpf-userspace-w cpus_allowed=3   psr=3
65626 xpf-userspace-w cpus_allowed=4   psr=4
65627 xpf-userspace-w cpus_allowed=5   psr=5
```

Every worker on its own CPU in {2,3,4,5}; `psr` matches
`cpus_allowed` one-to-one. No worker lands on CPU 0 or 1. The
pre-#740 failure mode — workers on CPUs 0-3 regardless of the unit
mask — does not recur.

### Phase 4 measurement

Same fixture as #737: 3 × 30 s × 16-flow iperf3, client
`cluster-userspace-host`, target `172.16.80.200`, CoS fixture
`test/incus/cos-iperf-config.set` applied, fw0 primary,
`net.ipv4.tcp_ecn=1` end-to-end. Per-flow CoV = per-second bps
stdev / mean per stream, mean across streams (16 streams per run).

Per-run raw values:

| Run | Ratio | Retrans / 30 s | CoV mean | CoV max |
|---|---|---|---|---|
| Pre  1 | 1.370× | 198,317 | 16.3% | 26.4% |
| Pre  2 | 1.365× | 186,389 | 15.3% | 26.9% |
| Pre  3 | 1.383× | 245,724 | 18.9% | 27.0% |
| Post 1 | 1.288× | 264,493 | 17.4% | 27.6% |
| Post 2 | 1.492× | 179,843 | 16.7% | 32.5% |
| Post 3 | 1.419× | 257,562 | 14.6% | 25.4% |

Aggregate:

| Metric | Pre-pin mean | Post-pin mean | Δ |
|---|---|---|---|
| Rate ratio (max/min per-flow) | 1.373× | 1.400× | +2% (worse, within noise) |
| Retransmits / 30 s | 210 k | 234 k | +11% (worse, within noise) |
| Per-flow CoV mean | 16.8% | 16.2% | -0.6 pp (better, within noise) |
| Per-flow CoV max | 26.8% | 28.5% | +1.7 pp (worse, within noise) |

### Decision

Per #712's keep/revert/defer thresholds (also cited verbatim in the
#741 task brief):

- **Keep** requires: ratio improves ≥ 5%, OR per-flow CoV mean drops
  ≥ 3 pp on 2+ runs, OR retrans drops ≥ 15%. **None satisfied.**
- **Revert** if no metric moves above thresholds. Three of four
  metrics moved in the *worse* direction within noise; CoV mean
  improved 0.6 pp, far below the 3 pp threshold.
- **Defer** is for "small movement without any metric going worse".
  That condition is not met either — ratio + retrans + CoV max all
  regressed.

**Decision: revert the directive.** Same engineering outcome as #737,
different mechanism. #737 revert was forced by the pin logic bug;
#741 revert is forced by the hardware. The recipe lives on as design
intent; the next lever is #739 (kernel cmdline isolcpus/nohz_full).

### Why the pin doesn't help on this lab

IRQ layout sampled mid-run (abbreviated from `/proc/interrupts`):

- `virtio11-input.0..5` (one of the NICs) — each pinned to its own
  CPU across CPUs 0-5, each carrying tens of thousands of interrupts
  per run.
- `virtio12-input.0..5` — same 1-per-CPU spread, hundreds of
  thousands of interrupts per CPU per run (LAN-side).
- `virtio5-virtqueues` → CPU 2, 65 k interrupts.

CPUs 2-5 carry virtio RX interrupts for four of the six virtio
queues; moving xpfd workers onto those CPUs collides with the same
softirq work that was running there before. The pin moves the
workload alongside its IRQs rather than away from them. To actually
separate the worker from kernel timer + softirq preemption you need
either (a) `isolcpus=2-5` on the cmdline (Option B, #739), or (b)
`ethtool`-level RSS reshape to park the RX queues on CPUs 0-1 so
CPUs 2-5 are truly quiet (out of scope per the recipe).

Until one of those lands, the 14-18% per-flow CoV on this lab is the
floor for `CPUAffinity=` alone.

## Gotchas the deploy wipes

The cluster deploy path (`cluster-setup.sh deploy`) wipes the CoS
config every run — the bootstrapped `xpf.conf` does not carry the
iperf CoS fixture. After every deploy, re-apply:

```bash
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
```

The loader script lives at `test/incus/apply-cos-config.sh` and is
documented inline. It is intentionally strict on `load merge` / `commit`
since #716 — if you see a validation error, stop and investigate rather
than re-running. The accompanying fixture at
`test/incus/cos-iperf-config.set` covers both `family inet` and
`family inet6` classifier state.

### How the loader detects a failed apply (#6440)

That strictness could not actually work before #6440, and it is worth
understanding why, because the same trap catches any script driving this
CLI.

The loader runs the CLI by piping a heredoc into it:

```bash
incus exec "$TARGET" -- /usr/local/sbin/cli <<EOF
configure
delete class-of-service
load merge /tmp/cos-iperf-sets.set
commit check
...
```

**That form is a REPL, not a batch runner.** `cmd/cli`'s read loop prints
`error: <msg>` for a failed command, continues to the NEXT line, and the
process still exits 0. So gating a phase on the session's exit status
detects nothing. (`cli -c "<one command>"` is the opposite — it
`os.Exit(1)`s on a dispatch error. Only the piped-stdin form swallows.)

The failure #6440 recorded: `load merge` failed, leaving a candidate that
held only the loader's `delete class-of-service ...` lines. Deleting is
valid, so `commit check` passed and `commit` committed the deletes —
**wiping CoS instead of applying it**. The first check that noticed
anything was the post-commit `show class-of-service interface` grep, which
reported the misleading "no shaper/scheduler binding" and exited 6. Every
CoS measurement taken after such a run was silently taken against
un-applied config.

The loader now verifies the CLI's own **success markers** in each captured
transcript (`test/incus/cos-apply-lib.sh`):

| verb | marker printed only on success |
|---|---|
| `load merge` | `load merge complete` |
| `commit check` | `configuration check succeeds` |
| `commit` | `commit complete` (or `commit complete: <summary>`) |
| `rollback N` | `configuration rolled back` |

Positive markers are checked rather than scanning for `error:` lines
because the loader's delete list is idempotent by design: its `delete`
lines legitimately error with a path-not-found on a fresh post-deploy box
where CoS was already wiped. Those benign errors must not fail the apply,
and they do not disturb the markers.

Two consequences worth knowing:

- **`rollback` is verified too.** Every rollback site previously announced
  "live state reverted" from the `then` branch of an `if` on the session's
  exit status — i.e. unconditionally. The loader could report a clean
  revert over a rollback that never happened. It now says
  `live state reverted (verified)` only when both markers appear, and
  escalates to `MANUAL INTERVENTION REQUIRED` otherwise.
- **Exit 6 now means what it says.** A CLI/daemon reachability failure
  during the readback exits 6 with an explicit "this is a CLI/daemon
  reachability failure, NOT a CoS binding failure" line, and a new exit 3
  covers "xpfd never became reachable" (the loader waits for the gRPC
  listener before the first commit — a deploy restarts xpfd, and #6440 also
  recorded a commit-check dying on connection-refused).

`make test-cos-apply-lib` self-tests all of this hermetically (mocked
incus, canned transcripts — no cluster). The marker strings are a
cross-language contract; `cmd/cli/cos_apply_markers_6440_test.go` pins
both halves (printed on success, withheld on failure) and fails if the
shell library and the CLI ever disagree.

Opt-in injectors layered onto the selected fixture: the
`--surplus-sharing` flag (#915) and `COS_EQUAL_FLOW=1` (#1831,
follow-up to #1766/#1745) each append one presence-only scheduler
flag line — `surplus-sharing` or `equal-flow-enforcement` (#1304)
respectively — per transmit-rate-exact scheduler. They are mutually
exclusive (the compiler rejects a scheduler carrying both). Default
invocations apply the fixture unchanged; equal-flow enforcement stays
default-OFF unless `COS_EQUAL_FLOW=1` is exported:

```bash
COS_EQUAL_FLOW=1 ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
```

See also the "CoS deploy preserves config" bullet in
[`engineering-style.md`](engineering-style.md#project-specific-reminders).

## 1 Gbps queue over-throttle fix (post-#754)

**Measured 2026-04-18.** This section records the live measurement
around the #754 rate-aware per-flow ECN threshold change. Read the
#754 issue body for the root-cause design brief; the numbers here are
the empirical keep/revert evidence.

### Context

The pre-#754 per-flow threshold was `share_cap × 1/5`. On the 16-flow
/ 1 Gbps exact queue that landed at ~15 KB per flow — right in TCP
cubic's 8–80 KB steady-state cwnd operating band. Every cwnd-growth
attempt ran the flow's bucket past the mark threshold, so ECN CE
fired continuously and TCP could not hold cwnd high enough to fill
its share.

The fix re-parameterises the per-flow arm to `fair_share_rate ×
COS_ECN_MARK_HEADROOM_MS / 1000`, clamped into
`[COS_FLOW_FAIR_MIN_SHARE_BYTES, share_cap]`. At 62.5 Mbps fair share
(1 Gbps / 16 flows) with 5 ms headroom that yields a 39 KB threshold
— near the top of the cwnd operating band, so marks only fire on
real bursts. At 625 Mbps fair share (10 Gbps / 16 flows) the same
formula gives 391 KB, scaling with the queue's drain rate. The
aggregate arm keeps the `buffer_limit × 1/5` fraction — `buffer_limit`
is sized as `rate × residence` upstream so it scales correctly in
the buffer axis.

### Phase 1 — pre-fix baseline (origin/master `e8e7533a`)

16-flow iperf3, 30 s, `cluster-userspace-host` → `172.16.80.200`,
`tcp_ecn=1` end-to-end, CoS fixture via
`./test/incus/apply-cos-config.sh`. Queue 4 (`iperf-a`, 1 Gbps cap,
1.19 MB buffer).

| Run | Port | Duration | Aggregate | Rate ratio (max/min) | Retrans |
|---|---|---|---|---|---|
| 1 | 5201 | 30 s × 16 | **1.055 Gbps** | 1.534× | 162,145 |
| 2 | 5201 | 30 s × 16 | **1.179 Gbps** | 1.487× | 284,734 |
| 3 | 5201 | 30 s × 16 | **1.024 Gbps** | 1.476× | 123,527 |
| — | 5202 | 30 s × 16 | **9.542 Gbps** | 5.533× | 8 |
| — | 5201 | 5 s × 1 | **1.447 Gbps** | — | 23,522 |

Pre-fix queue-4 counter snapshot (accumulated):
`flow_share_drops=13 229 225, buffer=0, ecn_marked=16 366 893`.

Counter deltas over the ~125 s of Phase 1 workload:
`flow_share_drops=682, buffer=0, ecn_marked=243 307`.

**Observation that contradicted the #754 hypothesis.** The issue body
predicted pre-fix 5201 aggregate ≈ 0.60 Gbps (60 % of cap). At the
time of my measurement (post-#750 head), the baseline was already
delivering 1.02–1.18 Gbps across three runs — the single-flow reached
1.45 Gbps, which is ABOVE the 1 Gbps cap, indicating the CoS
scheduler was not rate-limiting 5201 to its configured cap at the
time of the baseline snapshot. This means the symptom described in
#754 had already shifted between issue-writing and live measurement;
the rate-aware fix was therefore applied against a workload that was
not exhibiting the #754 dominant failure mode.

### Phase 3 — post-fix measurement

Same fixture, `pr/754-rate-aware-ecn-threshold` deployed via
`BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
./test/incus/cluster-setup.sh deploy all`. CoS re-applied, counters
baseline captured at T0.

| Run | Port | Duration | Aggregate | Rate ratio (max/min) | Retrans |
|---|---|---|---|---|---|
| 1 | 5201 | 30 s × 16 | **1.110 Gbps** | 1.449× | 184,469 |
| 2 | 5201 | 30 s × 16 | **1.126 Gbps** | 1.277× | 188,467 |
| 3 | 5201 | 30 s × 16 | **1.113 Gbps** | 1.455× | 215,678 |
| — | 5202 | 30 s × 16 | **9.542 Gbps** | 4.515× | 0 |
| — | 5201 | 5 s × 1 | **0.956 Gbps** | — | 0 |

Counter deltas during the 3 × 30 s 5201 runs (90 s of queue-4
workload, before the 5202 run):
`flow_share_drops_delta = +828, buffer_drops_delta = 0,
ecn_marked_delta = +101 260`.

Normalised per-second comparison with Phase 1 (Phase 1 queue-4
workload ≈ 95 s, Phase 3 = 90 s):

| Counter | Phase 1 (per 30 s) | Phase 3 (per 30 s) | Δ |
|---|---|---|---|
| flow_share_drops | ~215 | ~276 | **+28 %** |
| ecn_marked | ~76 834 | ~33 753 | **−56 %** |
| buffer_drops | 0 | 0 | unchanged |

### Keep / revert decision

Against the #754 acceptance criteria:

| Criterion | Target | Measured | Met? |
|---|---|---|---|
| 5201 aggregate ≥ 0.95 Gbps on ≥ 2 of 3 runs | 0.95 Gbps | 1.11, 1.13, 1.11 Gbps | YES (3/3) |
| Single-flow 5201 reaches ≥ 900 Mbps | 900 Mbps | 955 Mbps | YES |
| Rate ratio ≤ 1.58× | 1.58× | 1.28–1.45× | YES |
| 5202 aggregate ≥ 9.12 Gbps | 9.12 Gbps | 9.54 Gbps | YES |
| `flow_share_drops` Δ drops ≥ 80 % | −80 % | **+28 %** | **NO** |
| `ecn_marked` Δ drops ≥ 50 % | −50 % | −56 % | YES |
| `cargo test` suite green | pass | pass (700 + 26 ECN) | YES |

Six of seven criteria pass. The `flow_share_drops` criterion is the
one that fails: the counter went up 28 % rather than down 80 %. The
mechanism is predictable — the new per-flow threshold sits at 39 KB
instead of ~15 KB, so ECN marks fire much less often (confirmed by
the 56 % drop in `ecn_marked`) and TCP cwnd grows unimpeded further
into the per-flow share cap before being hard-dropped by
`flow_share_exceeded`. In the regime where aggregate throughput is
already at cap, reducing marker pressure pushes drops from the
"marker fires, TCP halves cwnd gracefully" mode into the "TCP hits
cap, packet drops, recovery" mode. The trade-off is visible in the
counter delta even though the primary throughput metric is at target.

**Decision: REVERT** per the #754 §"Acceptance criteria" language
("Keep if ALL"). The primary #754 symptom (0.60 Gbps at cap) was not
reproducible on the measured baseline (already at 1.02–1.18 Gbps),
so the rate-aware fix cannot "move" the primary metric in the way
the issue predicted. The ecn_marked reduction (−56 %) is real and
structurally justified by the rate-aware shape, and six of the seven
acceptance-criteria thresholds are met — but the
`flow_share_drops ≥ 80 % reduction` bar is a hard ALL-must-hold
invariant that was not cleared (the counter went UP 28 % instead).
This is the engineering-style rule — "Do NOT keep the fix if the
data doesn't support it. Revert and file a follow-up if the
rate-aware formula itself needs a different parameterisation" — in
action. The PR landing this section is opened as a measurement
artefact with `--- revert` in the title, so future readers can
re-verify the baseline and the fix shape without having to re-run
the full methodology from scratch.

A follow-up issue should track: (a) why the live workload's
pre-fix delivery drifted from the 0.60 Gbps described in the #754
issue body to the 1.02–1.18 Gbps observed on this measurement, and
(b) whether a smaller `COS_ECN_MARK_HEADROOM_MS` (closer to 2 ms)
would retain the ecn_marked drop without regressing
`flow_share_drops`. Both are parameterisation questions that the
rate-aware shape alone cannot answer.

### Future levers

If the live workload drifts back into the under-delivery regime the
#754 issue described, re-measure with this methodology. The
rate-aware formula is still the right shape; the HEADROOM_MS
parameter (currently 5 ms) can be tuned between 1 ms (more
aggressive marking, lower flow_share_drops) and 50 ms (lazier
marking, more aggregate delivery). The compile-time assertion
`COS_ECN_MARK_HEADROOM_MS ∈ [1, 50]` guards the sensible band; any
future retune outside that envelope fails the build rather than
landing silently.

## Refs

- #704 — umbrella cwnd-collapse symptom
- #709 — owner-worker hotspot (remaining lever for microburst residual)
- #716 — flow-aware admission cap
- #718 — ECN CE marking at CoS admission (Local variant) + Option B CoDel tracker
- #720 — latency-envelope clamp
- #721 — aggregate ECN threshold
- #722 — per-flow ECN mark threshold
- #724 — surface admission drop counters (unblocked this methodology)
- #725 — validation-pipeline gap findings (live data + path forward)
- #727 — ECN marking on Prepared CoS variant (closed the Local-only gap)
- #728 — VLAN-aware L3 offset + threshold tune (resolved the dormant-marker symptom)
- #754 — rate-aware per-flow ECN threshold (this section)
- #712 — CPU pinning + IRQ isolation (Option A measured no-op on this lab; see "CPU pinning layout for the loss lab")

## TX-CoS / fabric-queue selection on non-first IP fragments (#2357)

A non-first IP fragment (IPv4 fragment-offset != 0; IPv6 Fragment Header
type 44 with offset != 0) carries **no L4 header** — the bytes at the
post-IP-header offset are payload, not TCP/UDP ports. #2344 already makes
such a fragment *flowless* on the policy/session path
(`parse_session_flow_from_bytes` returns `None`), so it forwards
route-based with no policy/NAT/session.

The TX-side CoS queue / fabric-queue / output-filter selection re-derives
a tuple from metadata independently of that gate. Before #2357 a forwarded
non-first fragment therefore got its egress queue, DSCP rewrite, fabric
target binding, and output-filter verdict computed from payload bytes
interpreted as ports — different fragments of one datagram could land on
different queues (reordering / reassembly stress), and a port-matching
terminal output-filter term could spuriously `discard` a fragment.

#2357 gates the meta fallback at the TX-CoS sites:

- `forward_request.rs::build_live_forward_request_from_frame` — when the
  gated `flow` is `None` AND `frame_is_non_first_fragment(frame, meta)`
  (the #2344 family-aware predicate), the TX path passes `flow_key = None`
  to `resolve_cos_tx_selection_at` (→ interface `default_queue`, no
  output-filter / port evaluation) and `expected_ports = None`, and
  `fabric_queue_hash` is called with `non_first_fragment = true` so it
  hashes a fragment-stable **3-tuple** (protocol + L3 src/dst from
  metadata, which the XDP shim copies from the IP header present on every
  fragment) with **no ports** — every fragment of one datagram selects the
  same fabric target binding.
- `poll_descriptor/mod.rs` pending-neigh buffering — a buffered fragment
  stores `flow_key = None` so the later `retry_pending_neigh` flush also
  selects the default queue with no port-filter eval.

The gate fires **only** for an actual non-first fragment. A legitimate
flowless TCP/UDP packet (real L4 header, no session yet) still gets its
meta/frame-derived ports and full CoS/filter selection — the gate is the
`frame_is_non_first_fragment` predicate, not a blanket "every `None` flow
→ default queue". `coordinator/inject.rs` (emit-on-wire control-plane
packets) is unaffected: it stamps a validated real tuple and is never
reached by a forwarded payload-ported fragment.

Regression tests live in `userspace-dp/src/afxdp/tests.rs`
(`non_first_fragment_v4_not_dropped_by_port_matching_output_filter`,
`non_first_fragment_v6_not_dropped_by_port_matching_output_filter`,
`flowless_non_fragmented_tcp_still_hits_port_matching_output_filter`,
`fabric_queue_hash_non_first_fragment_is_port_independent_3tuple`,
`pending_neigh_fragment_buffers_no_flow_key`) and fail if the gate is
reverted.

### The flowless tuple must be POST-NAT (#7656)

The `flow_key = None` path above answers "which ports" (none). It did not
answer **which family, which addresses, which protocol** — those fell back
to the ingress `meta`. For every NAT that rewrites addresses that fallback
is stale, and under **NAT64** it is a different address family: the packet
arrives IPv6 and leaves IPv4.

The consequence was operator-visible and audit-relevant. An interface
`filter output` is applied on the egress interface AFTER NAT (#3642), so
family and tuple must both be post-NAT. On the flowless arm they were not:

    first fragment  (has a flow_key)  -> egress v4 filter, post-NAT tuple
    non-first frag  (flowless)        -> ingress v6 filter, PRE-NAT tuple

Both leave as IPv4 on the same interface, so a v4 output filter saw the
first fragment and not the rest — and a v6 filter matched a packet that
left as IPv4, which is a *wrong* record rather than a missing one.

The fix synthesizes an L3-only post-NAT wire key
(`forward_request::l3_wire_session_flow_from_frame`) from the verified frame,
`meta` and this packet's `decision.nat`, put through the same `forward_wire_key`
the flow-bearing path uses. A native-fragment sentinel is resolved from the IP
header before the wire key is built. The NAT decision does not depend on there
being a flow, so the egress family is derivable exactly where it was previously
guessed. Family, addresses and protocol — including the NAT64
`ICMPV6`<->`ICMP` swap — therefore move **together by construction**,
across all four consumers: the per-family tx-selection enable gate, the
output-filter family lookup, the term match inputs, and the filter-log
event's attributed tuple. The same key is threaded through the
`neighbor_dispatch` buffered-frame retransmit, which had the identical
defect.

**Do not reduce this to a family-only change.** Selecting the v4 filter
while still matching pre-NAT v6 addresses makes every `from
source-address` / `destination-address` term stop matching, so the filter
is *less* correct than before while an address-less fixture stays green.
That was measured: the half-fix passes
`nat64_flowless_fragment_uses_the_egress_family_output_filter_7656` (whose
terms are address-less) and reds
`nat64_flowless_fragment_output_filter_matches_the_postnat_tuple_7656`,
which carries a v4 `destination-address 8.8.8.8/32` term precisely to bind
it.

Scope: the flow **cache** replay arm is unaffected for NAT64 —
`flow_cache::should_cache` excludes NAT64 (`&& !decision.nat.nat64`), so a
NAT64 flow is never cached. Its equivalent pre-NAT address staleness under
plain SNAT/DNAT (a v4 SNAT'd fragment logging its pre-translation source)
is real but family-invariant. It was split out as #8367 and is settled
below.

### Plain SNAT/DNAT — the non-NAT64 half (#8367)

Two things were owed here, and they turned out to be different in kind.
Neither is what the issue title suggests, which is worth stating plainly
before someone re-derives it.

**The fresh flowless arm was already correct — and untested.**
`forward_request.rs` builds `flowless_wire_flow` with
`l3_wire_session_flow_from_frame(frame, meta, decision.nat)`, and the
`forward_wire_key` inside it rewrites `src_ip`/`dst_ip` from
`nat.rewrite_src`/`rewrite_dst` **unconditionally** — only the address
FAMILY and the ICMP/ICMPv6 protocol swap sit behind `if nat.nat64`. So
#7656 fixed plain SNAT/DNAT on this arm as a side effect the day it
landed. But every #7656 cell is NAT64, so the behaviour was right *by side
effect* with nothing to notice it regressing: narrowing
`l3_wire_session_flow_from_frame` to `if nat.nat64 { forward_wire_key(..) }
else { pre.forward_key }` — the exact scope boundary #7656's own body drew
— left the whole suite green.

`flowless_snat_egress_output_filter_matches_the_postnat_tuple_8367`
(`tests_fragment.rs`) binds it end to end: interface SNAT lan -> wan, one
datagram, `from source-address` terms carrying the pre- and the post-NAT
source in turn, the flow-bearing first fragment as the positive control
and the flowless non-first fragment as the subject. It asserts the event
COUNT (which binds the site that decides whether the term MATCHES) and the
event's `src_ip` (which binds the site that decides which tuple the record
CARRIES) — two different reads of the same key that revert independently,
so a cell asserting only that a log exists would pass on a record
attributed to the wrong tuple.

**The cached flowless arm was stale, and unreachable.**
`resolve_cached_cos_tx_selection_impl`'s flowless arm read the ingress
`meta` in all three places. It could not be reached with a wrong tuple in
production, though, and that changes what the fix is for: `flow_cache.rs`
always seeds with a flow key, and the only caller that reached the
flowless arm — `mirror_cos_queue_id` — consumed `.queue_id` alone, which
is computed before and independently of the filter block. The staleness
was a trap armed for the next caller, not a live defect, and it would have
presented as "the output filter matched the wrong address" long after the
commit that armed it.

That framing is why the arm was not simply emptied. #6055 populated
`.drop` / `.reject` / `.filter_log` here DELIBERATELY, so a future caller
would fail CLOSED rather than wave a would-be-dropped fragment past an
egress `then discard`; returning "not evaluated" would restore exactly the
fail-open #6055 removed. A pre-NAT tuple, though, makes those fields
*confidently wrong* rather than merely absent, which is worse than either.

#8367 resolves that by making the key REQUIRED instead of patching the
three reads. `CachedTxTuple` has two variants — `Flow { egress_wire_key,
ingress_flow_key }` and `Flowless { wire_l3 }` — and both carry a post-NAT
key as a required field; there is no entry point that lets it be omitted.
The mirror path asks for what it actually consumes
(`resolve_cached_cos_tx_queue_id`, byte-identical result: behavior-
aggregate classification is 5-tuple independent), so nothing can obtain a
filter verdict without supplying the tuple that verdict must be computed
on. Bound by `cached_flowless_output_filter_matches_the_postnat_source_8367`
and `cached_flowless_output_filter_reads_family_and_protocol_from_the_wire_key_8367`
in `cos_classify_tests.rs`.
