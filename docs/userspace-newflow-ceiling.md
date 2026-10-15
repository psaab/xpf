# New-Flow (Connection-Rate) Ceiling Harness

**Status: the code ships; the measurement is OWED.** Everything described
here is built and unit-tested, but the loss-userspace-cluster run has **not**
been performed. No connection-rate number for this dataplane exists yet, and
nothing in this document should be cited as one. See
[Running it](#running-it-on-the-loss-userspace-cluster).

## Why this exists

`docs/userspace-perf-compare.md` and the `perf-test` skill measure **bulk
throughput** — a handful of elephant flows saturating the wire. That load
puts essentially **zero** pressure on the per-NEW-flow install path, which is
a completely different regime: every new transit flow allocates a SNAT
translation, publishes into the cross-worker shared session maps, and fans a
replica out to every sibling worker's command queue.

Four cross-worker synchronization points sit on that path:

| Site | What serializes | Scope |
|---|---|---|
| SNAT pool allocator `live` mutex | flow-map insert + persistent-lease lifecycle (the residual after the #2852 Phase-1 lock-free port claim) | per pool |
| `publish_shared_session` | up to three shared-map mutexes **per publish call** (`sessions`, `nat_sessions`, `forward_wire_sessions`) | process |
| `replicate_session_upsert` | one sibling command-queue mutex **per worker, per replication call** | process |
| `event_stream` `producer_seq_lock` (#9169) | wire-seq allocation **and the frame ENCODE** for every session delta, Open as well as Close — #3878 F-152 requires the allocation and the channel enqueue to be atomic together, so the encode is inside the critical section | process |

**The fourth row was added in #9169 and its absence was the expensive kind of
gap.** A run bound by that mutex WOULD report a real new-flows/sec plateau with
all three named sites COLD, which reads as "not lock-bound" and sends the next
reader somewhere else. That sentence is a COUNTERFACTUAL, not a result: no such
run has been performed, here or for any other site — see the status line at the
top of this document. What IS established is the static bound and the absence of
a counter. This document's own standard is that a measurement "has to say
*which* site saturated"; a site with no counter cannot be named, and a model
missing a site does not report a hole — it reports innocence.

#9169 is deliberately an INSTRUMENT and not a remedy. The bound is static and
proven; no benchmark is offered and none is claimed. "Encode outside the lock"
is not directly available (`F: FnOnce(u64) -> EventFrame` consumes the sequence
number, so encoding first means allocating first, which reintroduces the #3878
F-152 ordering and F-153 rollback hazards the lock exists to close), so the
remedy needs design and the measurement comes first. Candidate designs:
reserve the sequence under the lock and encode outside it with an
ordered-commit ring, or shard the sequence per producer with a merge at the
reader.

**Read those two rows as per CALL, not per connection.** A normal connection
does not perform one publish and one replication: the forward flow and its
reverse companion are separate entries, so the per-connection acquisition count
and replication fan-out are MULTIPLES of the per-call figures above. The
multiplier is not uniform either — `shared_sessions` is taken unconditionally
but the `nat_sessions` and `forward_wire_sessions` arms are both gated on
`!entry.metadata.is_reverse` (`afxdp/shared_ops.rs`), so a forward publish takes
up to three maps where a reverse publish takes exactly one.

No per-connection total is asserted here on purpose. Deriving one means
counting the publish and replication calls a real connection makes across the
install path, its reverse companion, and any promote / HA-import / tunnel
install that also publishes — and that count has not been measured. Anyone
quoting a per-connection cost should measure it against
`xpf_userspace_shared_session_publishes_total` and
`xpf_userspace_session_replication_upserts_total` over a known number of
connections, and say that it is measured.

#2852 Phase-2 (SNAT-allocator sharding) targets only the first. The
conclusion #4800 reached before any code was written is that this is
**architecturally insufficient on its own**: publish and the N-way
replication fan-out serialize every new flow regardless of what the allocator
does. So a measurement that only reports "new flows/sec plateaued at N"
settles nothing — it has to say *which* site saturated, and be capable of
saying *more than one did*.

## What was added

### Instrumentation (`userspace-dp`)

Cheap monotonic counters, no timing on the hot path. Every lock site
try-locks first: on an uncontended mutex that is the same single CAS `lock()`
already cost, so the **lock itself** is unchanged, and only a failed CAS pays
the extra contended increment on top of a block that was going to happen
anyway.

The acquisition counters, however, are bumped **unconditionally**, so the
uncontended path is not free. Measured in atomic read-modify-writes: an
uncontended `lock_live()` goes from 1 to 2, and one forward
`publish_shared_session` goes from 3 (three `lock()` CASes) to 7 — the call
counter plus one relaxed increment and one CAS per shared map. All relaxed, no
timing, no allocation, and confined to the cold new-flow-install path, but
"the fast path is unchanged" would be an overstatement and is not the claim.

Per pool, on `SourceNatPoolStatus` (Prometheus labels `pool`, `rule`):

| Series | Meaning |
|---|---|
| `xpf_userspace_source_nat_pool_live_lock_acquisitions_total` | acquisitions on the production allocate/reserve/release/rollback/GC paths — the **denominator** |
| `xpf_userspace_source_nat_pool_live_lock_contended_total` | the subset that found the mutex held and blocked |

The ~1s status-poll snapshot takes the same mutex and is **deliberately not
counted**: it reads these very counters, and counting it would dilute every
ratio with the observer.

Process-global, on `ProcessStatus`:

| Series | Meaning |
|---|---|
| `xpf_userspace_event_stream_producer_seq_lock_acquisitions_total` | producer acquisitions of `producer_seq_lock` — one per session delta plus one per lossless-retry attempt — the **denominator** for site 4 |
| `xpf_userspace_event_stream_producer_seq_lock_contended_total` | the subset that found the mutex held and blocked |
| `xpf_userspace_shared_session_publishes_total` | publish calls — the publish-leg new-flow rate |
| `xpf_userspace_shared_session_publish_lock_acquisitions_total` | shared-map acquisitions **scoped to publish only** |
| `xpf_userspace_shared_session_publish_lock_contended_total` | the blocked subset |
| `xpf_userspace_session_replication_upserts_total` | replication calls |
| `xpf_userspace_session_replication_enqueued_total` | individual sibling enqueues, counted immediately BEFORE each acquisition so `contended/enqueued` is a ratio over acquisitions actually ATTEMPTED at any instant, not over a fan-out booked up front; at rest `enqueued/upserts` is the **live-sibling multiplier** (dead-worker legs skipped by #12192 are excluded), not necessarily the configured sibling count |
| `xpf_userspace_session_replication_lock_contended_total` | sibling-queue acquisitions that blocked |
| `xpf_userspace_session_replication_queue_depth_sum` | sum of the per-call **worst** sibling-queue depth; `Δsum / Δupserts` is the mean worst-sibling depth per replication CALL (not per connection — see the per-call note above) — **the backlog statistic** |
| `xpf_userspace_session_replication_queue_depth_max` | process-lifetime high-water. **Operator context only** — see below |

Per worker:

| Series | Meaning |
|---|---|
| `xpf_userspace_worker_new_flow_installs_total` | locally-learned transit forward-flow installs on this worker |

Scoping choices that are load-bearing:

* `remove_shared_session`, HA promote/demote and read-side lookups take the
  same shared-map mutexes but go through the **uncounted** helper. On a
  connection-rate run every flow is created *and* torn down, so folding
  removal in would roughly double the denominator and halve every reported
  ratio.
* The tunnel, TX-drain, HA and cross-binding CoS enqueues take the same
  sibling-queue mutexes and are likewise excluded from the replication
  contention count.
* **Site 4 counts PRODUCERS only.** The I/O thread's replay-gap `FullResync`
  seq allocation (#5267, `event_stream/connection.rs`) takes the same
  `producer_seq_lock` and is deliberately excluded: it is not a producer and
  fires once per reconnect, so folding it into the denominator would dilute
  the ratio with the observer — the same reasoning that keeps
  `remove_shared_session` out of the publish denominator. Its blocking effect
  on producers is still visible, because it appears as producer CONTENTION,
  which is the number that matters. The dormant drain-poison resync
  (`handle_drain_request`, no live caller) allocates outside the lock and is
  not an acquisition at all.
* The per-worker install counter excludes reverse companions, peer-synced
  imports, promotes and local-delivery caches, so it stays directly
  comparable to the offered connection rate.

**Contention and depth are different findings.** Contention says producers
collided on a mutex; depth says the consuming worker is not draining as fast
as producers enqueue. They have different remedies (sharding vs. drain rate),
so the harness reports both and the analyzer can name them separately.

**Depth is measured as a window MEAN, never as the lifetime peak.** The
`..._queue_depth_max` gauge is a process-lifetime `fetch_max`: it never
falls, so it cannot be differenced across a window — a zero delta spans
everything from "no backlog" to "a backlog up to the previous all-time high"
— and one spike leaves the absolute value elevated for the life of the
helper. Reading it as a window value made every cell after the first spike
report a replication backlog, which is a systematic bias toward naming the
exact site the #2852 decision turns on. The analyzer keys the backlog verdict
on `Δqueue_depth_sum / Δupserts`, which is differenceable by construction and
carries nothing into the next cell; the lifetime max is reported for
operators and never votes.

### Analysis (`test/incus/newflow_ceiling_analyze.py`)

Turns two counter snapshots into a rate **and** an attribution. Tested
against synthetic snapshot pairs in `newflow_ceiling_analyze_test.py`; no
derivation lives in the shell.

* `culprits` is a **list**, ratio-descending. The expected real-world answer
  is "publish and replicate saturate before NAT does", and a classifier that
  could only report one winner would hide half of that.
* A site with zero acquisitions reports `ratio: None`, not `0.0` — "never
  taken" and "taken but never blocked" are different findings.
* Cold sites stay in the table with their ratios, so "NAT never blocked" is
  evidenced rather than inferred from an omission.

Verdicts, and the exit codes the harness propagates:

| Verdict | Exit | When |
|---|---|---|
| `VALID` | 0 | the window measured the install path |
| `INCONCLUSIVE` | 2 | something else bound first (see below) |
| `INVALID` | 1 | the window measured nothing usable |

**Site 4 needs a helper built with #9169, and a zero denominator there is a
BUILD statement, not a measurement.** `producer_seq_lock` is on the
unconditional path of every session delta, so a window that installed flows
through a connected event stream cannot have taken it zero times. If
`event_stream_producer_seq` reports `n/a (never taken)` on a loaded run, read
that as "this helper does not report the site" (or "the event stream was down
for the whole window") and re-deploy both halves — never as innocence. The
analyzer refuses outright when the two series are ABSENT from the scrape,
which is the pre-#9169 helper paired with a pre-#9169 daemon; the mixed case
(new daemon, old helper) emits the pair as a hard zero, and only this sentence
distinguishes it.

`INVALID`: non-positive or sub-minimum window; helper restarted mid-window
(pid change or a backwards counter); **zero pool-mode SNAT allocations** —
which means the pool-mode rule was not in effect or no new flows reached it,
and is emphatically *not* a measured rate of zero; an **offered rate of zero
or below**, since a generator that produced no parseable report is not a
measurement; and any **missing required snapshot input** (`t`, `helper_pid`,
`workers`).

That last class is worth stating on its own, because it is the recurring bug
shape in this layer: **a missing input degrading into a value that happens to
skip a check rather than trip it.** Five instances were found and closed
together — the sticky lifetime high-water above; `--offered-rate 0` leaving
`accept_ratio` at None and thereby skipping the generator-bound check; a
missing `t` defaulting to 0.0 and inflating the window to ~1.7e9 seconds; a
missing `helper_pid` skipping the restart comparison; and an absent
per-worker series leaving `installs` empty so that **both** cross-worker
gates were skipped. When adding a gate, add its input to
`REQUIRED_SNAPSHOT_KEYS` and ask what an absent value does: if the answer is
"the gate does not run", the gate fails open.

`INCONCLUSIVE`: pool port exhaustion (a capacity ceiling, not a lock one);
accepted flows below 95% of the REQUESTED rate (the generator,
client NIC or target bound first); fewer than 3 of the 6 RX queues carrying
installs (RSS-distribution-limited); or one worker taking >60% of installs
(single-core-bound, not cross-worker-lock-bound).

That last pair matters: without them, a run steered onto one RX queue reports
a high contention ratio and reads as a cross-worker lock bound — the exact
mis-attribution this issue exists to avoid.

### Generator (`test/incus/newflow-gen`)

A standalone Rust crate (outside the dataplane workspaces, same rationale as
`test/incus/cold-path-flooder`: a regression in a test binary must not block
dataplane builds).

* **Completes handshakes.** A SYN flood exercises the screen path and the
  half-open window and never reaches SNAT allocation, publish or replication.
  The three sites under test are on the *install* path, so the generator
  opens, completes and tears down real short-lived connections.
* **Sweeps a destination port range.** RSS on the cluster's mlx5 VFs hashes
  the 4-tuple; one destination port steers everything at one RX queue.
* **`--close=rst` by default** (SO_LINGER(0)), so the *client* avoids a
  TIME_WAIT per flow and does not exhaust its ephemeral range in seconds.
  The firewall still holds the RST-closed session for `TCP_RST_TIMEOUT_NS`
  (2s), so an offered rate R implies roughly `R * 2` live sessions — bound
  the rate sweep so peak occupancy stays well under `max_sessions`.
* **It is a blocking-connect thread pool**, therefore bounded by thread count
  and RTT rather than by the firewall. This is declared, not hidden: the
  analyzer compares installed flows against the REQUESTED rate and marks a
  cell INCONCLUSIVE when they fall short — so a generator that cannot reach
  the requested rate refuses the cell instead of passing its own ceiling off
  as the firewall's. (Comparing against the generator's ACHIEVED rate, which
  the harness did until #6927 r3, makes that ratio ~1 by construction and
  disables the check entirely.) A generator ceiling shows up
  as a refusal to conclude. Raise `--threads`, or drive from more than one
  client host.

## Running it on the loss userspace cluster

**Attempted 2026-09-06 and BLOCKED.** The historical attempt had three
preconditions unsatisfied on the loss cluster. The client source-bind gap is
fixed by `--src-bind` / harness `SRC_BIND`; the pool capacity and operator
baseline blockers remain. The measurement is still owed.

Off-cluster, everything passes: `newflow_ceiling_analyze_test` OK,
`newflow-gen` 13/13, and the harness `--dry-run` resolves every host, the target
and the analyzer. The blockers are all in the cluster's committed state.

**1. Client source binding is available; the operator must assign a pool-prefix
address for the run.** The committed `pool-snat` rule in rule-set `lan-to-wan`
matches `source-address 10.0.61.240/28`. The LAN host's normal address,
`10.0.61.102`, is outside that prefix, so unbound traffic takes the sibling
interface-mode `rule snat` instead and yields zero pool allocations. The
generator client now supports `--src-bind <IP>` and the harness accepts
`SRC_BIND=<IP>`; after an authorized operator temporarily assigns (for example)
`10.0.61.241/28` to the LAN host, run the harness with `SRC_BIND=10.0.61.241`.
Without both the temporary address and explicit bind, the pool still sees no
traffic and the analyzer refuses the cell. The harness does not mutate host
addresses itself.

**2. The pool holds 1000 ports.** `pool-snat-pool` is `172.16.80.7/32` with
`port range 30000 to 30999`. The documented sweep is 5000–80000 flows/sec; a
sustained rate R with hold time H needs R x H concurrent ports, so this pool
caps out roughly two orders of magnitude below the interesting range. The
harness names port exhaustion explicitly as a refusal ("a capacity ceiling, not
a lock ceiling"), so this would not silently corrupt a number — it would refuse
every cell. **That is the failure mode to want**, and it is why no figure is
quoted here.

**3. The default WAN target is not an instance on this cluster.**
`IPERF_TARGET4=172.16.80.200` answers from the wire (fw0 pings it, neighbour
`f6:f0:06:10:77:d5`) but is not an incus instance on `loss:`, so the sink cannot
be started on it. This one is surmountable: `loss:xpf-mouse-target` holds
`172.16.80.201` on the same VLAN-80 subnet and `TARGET_IP` is overridable.

The pool-capacity blocker still needs a cluster-owner decision and any
configuration change must not be made by the measurement run itself.

### What this harness can and cannot attribute

Stated because the #9053 cohort lists **seven** cost sites, and a run of this
harness would speak to two of them plus one that has no row of its own. A
measurement reported against all seven would be the #4800-class trap the
harness's own header warns about.

| Site | This harness |
|---|---|
| NAT allocator `live` mutex | **attributed** (the pool path is the driven path) |
| `replicate_session_upsert` fan-out | **attributed** (`session_replication_upserts_total`) |
| `publish_shared_session` | **attributed** (`shared_session_publishes_total`) |
| `publish_live_session_entry` (up to 6 serial `bpf()` per install) | not attributed — no per-syscall counter |
| `remove_shared_session` (3 nested map mutexes) | not attributed — it is on the CLOSE path, and the sweep drives opens |
| `snapshot_shared_session_entries` + `replay_synced_sessions` | not attributed — a reconcile/bring-up path this sweep never enters |
| source-NAT `matches` O(R) scan | not attributed — one rule-set of 2 rules here; R is not varied |
| bulk HA import | not attributed — no peer bulk transfer during the sweep |

So even an unblocked run answers **which of three synchronization sites
saturates first**, which is what #2852 Phase-2 is gated on. It is not a
per-connection cost for the other five, and nothing should cite it as one.

The loss cluster is shared and lock-protected. The harness sources the
`cluster-cell.sh` preamble, so it queues behind another agent's deploy or
smoke rather than colliding. Never kill another holder; never `rm` the lock.

```bash
# 0. Build + unit-test everything off-cluster first.
cargo test --release --manifest-path test/incus/newflow-gen/Cargo.toml
(cd test/incus && python3 -m unittest newflow_ceiling_analyze_test)
./test/incus/newflow-ceiling-harness.sh --pool <pool> --rule <rule> --dry-run

# 1. Deploy the dataplane build carrying the #4800 counters.
make cluster-deploy

# 2. Push the generator to the LAN host and the WAN target.
cargo build --release --manifest-path test/incus/newflow-gen/Cargo.toml
#    ...then `incus file push` the binary to both, as /usr/local/bin/newflow-gen.

# 3. Start the sink on the WAN target over the destination port range.
newflow-gen --mode sink --bind 172.16.80.200 --ports 5300-5363

# 4. Commit a pool-mode source-NAT rule on the WAN egress path and CONFIRM
#    it: `show security nat source pool <pool>` must list it. The harness
#    refuses to run without it and deliberately does NOT mutate the NAT
#    config itself — a half-applied rewrite must never be mistaken for a
#    dataplane result.

# 5. Sweep.
./test/incus/newflow-ceiling-harness.sh --pool <pool> --rule <rule> \
    --rates 5000,10000,20000,40000,80000 --duration 30 --threads 32
```

### Which node it measures, and when it refuses to run (#6962)

The harness reads NAT-pool and Prometheus counters off ONE node, so it has to
pick the node that installs the flows before any traffic starts. It asks BOTH
nodes for `show chassis cluster status` and takes the answer from each node's
OWN row — `show chassis cluster status` prints both nodes' rows on whichever
node you ask, so a pattern with no node token in it matches the PEER's row.
That was the #6962 defect: the selection matched node1's `primary` row inside
node0's output and always chose `$FW0`, whoever was actually primary. It failed
to a plausible value, not to an error — the run completed, and the analyzer
refused the cells three layers later as if the dataplane were at fault.

"Primary" here means primary for EVERY redundancy group the status reports, not
for some group. The measured path spans two of them on this cluster — reth0
(WAN) is `redundancy-group 1` and reth1 (LAN) is `redundancy-group 2`
(`docs/ha-cluster-userspace.conf`) — so a node owning only one installs part of
the flows and its counters describe half a measurement. There is deliberately
no `--rg` selector: the harness reads one node's counters for the whole path,
so "measure the node that owns RG N only" is not a question its output can
answer.

It therefore refuses, before taking any traffic, when:

* **no node** is primary for every RG (a split/active-active cluster), or
* **both** nodes claim to be (split-brain), or
* neither node's status can be read at all.

Each refusal prints both nodes' verdicts, because the cost of a wrong choice is
a wasted run under the shared cluster lock and the log has to be enough to tell
the cases apart. The verdict and the selection live in
`test/incus/newflow-ceiling-lib.sh`; `make test-newflow-ceiling-lib` proves them
on fixtures where the two nodes carry DIFFERENT states, which is the only shape
in which the anchoring is observable — a fixture with both nodes in the same
state passes with or without it.

### What proves the run was valid

Per cell, under `artifacts/newflow-ceiling/<UTC>/rate-<N>/`:

1. `analysis.txt` says `verdict: VALID`. Anything else is not a data point
   about the install path — read the `!` reasons and fix the setup.
2. `analysis.json` shows a non-zero `new_flows_per_sec` derived from a
   non-zero pool-allocation delta (proving the pool-mode SNAT rule was
   actually in effect and actually carried the traffic).
3. `replication_queue_depth_mean` is present and is what any backlog culprit
   rests on. `replication_queue_depth_max_lifetime` is context only; if it is
   high but the mean is low, the peak predates this cell and says nothing
   about it (`replication_queue_depth_new_record` tells you whether this
   window set the record).
4. `active_workers >= 3` and `max_worker_share <= 0.60` (proving the
   cross-worker path was genuinely exercised).
5. `replication_fanout` reports the live sibling count (equal to the configured
   worker count for this all-live run).
6. `accept_ratio >= 0.95` against the REQUESTED rate (not the achieved one —
   achieved/achieved is ~1 by construction and gates nothing).
7. `generator.json` accounts for every attempt:
   `attempted == established + refused + timed_out + other_errors`. Check this
   BY HAND — the harness does not assert it, it reads only
   `established_per_sec`.

**The ceiling** is the highest cell that came back `VALID` and unsaturated,
followed by a higher cell that came back `VALID` and saturated. A sweep with
no `VALID` cells has no ceiling and must be reported as such.

### What the result decides

* If `nat_allocator_live_mutex` appears in `culprits` **and** publish and
  replicate do not, #2852 Phase-2 allocator sharding is worth reopening.
* If publish and/or replicate saturate at or below the NAT ratio — the
  outcome #4800 predicts — allocator sharding alone cannot move the ceiling,
  and the Phase-2 design must be re-scoped to shard *all* per-new-flow
  cross-worker state, or dropped.
* If nothing saturates at the highest sustainable offered rate, the install
  path is not lock-bound at rates this cluster can generate, and the honest
  report is the generator's ceiling plus "no saturation observed below it".

## Signals that already exist, so a cost review does not re-propose them (#9053)

A review of the per-new-flow cost path proposed an "O(1)-per-worker
bulk-invalidation signal" for `DeleteSynced` storms as a missing mechanism. It
is not missing — it ships, and it is discoverable only from the source today,
which is how a reviewer reached the opposite conclusion. Named here because
this is the document that reader reaches first.

- **`SESSION_DELETE_DROP_EPOCH` (#8586)** is that signal. It is deliberately
  keyed on refused **deletes** rather than on queue depth: upsert-driven cap
  pressure "would fire continuously through normal traffic and reconcile
  nothing", so a depth-keyed signal would be noise exactly when the dataplane
  is busy.
- **`replicate_session_delete_repairing` (#8114/#8576)** already resolves the
  refused worker's id and runs its NAT teardown on its behalf. Measured
  remainder: **0 repaired-drops across 30,786 refusals.**
- The residual those two leave is the window between a refusal and the refused
  worker's next epoch read, and that is stated at the site.

The general point for anyone costing this path: check for a shipped counter
before proposing one. A proposal that duplicates a mechanism costs more than
the gap it claims to close, because it also retires the question.

## Related

* `docs/fairness-regimes.md` — the 6-RX-queue / 6-worker denominator every
  per-worker claim normalizes against.
* `docs/userspace-perf-compare.md` — bulk-throughput methodology (the
  different regime this harness complements).
* `docs/research/2852-portalloc/microbench-results.md` — the allocator
  microbenchmark this end-to-end measurement is meant to validate against.
