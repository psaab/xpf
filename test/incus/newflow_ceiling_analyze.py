"""Turn two helper counter snapshots into a new-flow rate AND an attribution.

This is the analysis half of the #4800 connection-rate harness. The shell
driver (`newflow-ceiling-harness.sh`) only collects; every derivation lives
here so it can be fed synthetic snapshot pairs and asserted, rather than
buried in shell arithmetic that nothing tests.

Why the attribution matters more than the rate
----------------------------------------------
A number that says "new flows/sec plateaued at N" settles nothing. Four
cross-worker synchronization points sit on every transit install:

* the SNAT pool allocator's residual `live` map mutex (#2852 Phase 1),
* `publish_shared_session` (up to three shared-map mutexes per flow),
* the N-way `replicate_session_upsert` fan-out (one sibling queue mutex per
  worker, per flow),
* the event stream's process-global `producer_seq_lock` (#9169), held across
  the frame ENCODE for every session delta -- Open as well as Close. It was
  absent from this model until #9169, so a run bound by it would report a
  plateau with all three other sites cold, which reads as "not lock-bound".
  (Counterfactual: no such run has been performed. The bound is static.)

#2852 Phase-2 sharding targets only the first. If publish and replication
saturate before the allocator does, sharding the allocator alone moves
nothing — which is precisely the conclusion #4800 exists to test. So
`analyze` never reports a single winner: it reports EVERY site over the
saturation threshold, in descending order, plus the full per-site table so a
reader can see the ones that stayed cold.

Why it can report failure
-------------------------
A harness that cannot fail is worse than none. `analyze` returns
`INVALID` when the run did not measure what it claims to (no pool-mode SNAT
allocations at all, a counter that went backwards because the helper
restarted, a non-positive or too-short window) and `INCONCLUSIVE` when
something OTHER than the install path bound first (allocator exhaustion, a
generator that never reached its offered rate, traffic landing on too few RX
queues). Only `VALID` results may be used to argue about the install path,
and even then `saturated=False` with an empty culprit list is a real and
common answer.

No refusal may be disabled by its own input going missing
---------------------------------------------------------
Every gate here is only as trustworthy as the value it reads, and the
recurring bug shape is a MISSING INPUT DEGRADING INTO A VALUE THAT HAPPENS
TO SKIP THE CHECK rather than trip it. Five instances were found and closed
together:

* the sibling queue depth was read as a process-lifetime high-water, so one
  spike in an earlier cell made every later cell report a replication
  backlog — biased toward naming the exact site the #2852 Phase-2 decision
  turns on. Now keyed on a differenceable window MEAN;
* an unparseable generator report reached here as `--offered-rate 0`, which
  left `accept_ratio` at None and skipped the generator-bound check, so a
  broken generator produced a firewall number. Now INVALID;
* a missing `t` defaulted to 0.0, which either killed the window or inflated
  it to ~1.7e9 seconds and yielded a near-zero rate that still read VALID;
* a missing `helper_pid` skipped the restart comparison outright;
* an absent per-worker series left `installs` empty, and the `if installs`
  guards skipped BOTH cross-worker gates — the two that stop a run steered
  onto a single RX queue reading as a cross-worker lock bound.

The last three are refused up front by `REQUIRED_SNAPSHOT_KEYS`. When adding
a gate, add its input there too, and ask what an absent value does: if the
answer is "the gate does not run", the gate fails open.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Defaults. Every one is overridable; the harness records the values it used
# in the run artifact so a reported ceiling can be re-derived.
# ---------------------------------------------------------------------------

#: A lock site counts as saturated when this fraction of its acquisitions had
#: to block. 10% blocked acquisitions on a mutex held for a map insert is
#: already a serialization regime, not noise; below that the site is reported
#: with its ratio but not named a culprit.
DEFAULT_SATURATION_RATIO = 0.10

#: The sibling replication queue counts as backlogged at this MEAN
#: worst-sibling depth per replicated flow (`Δqueue_depth_sum / Δupserts`).
#: Steady-state depth is O(1) — the consuming worker drains every poll — so a
#: double-digit mean means the consumer is persistently behind, which is a
#: different failure from producers colliding on the queue mutex.
#:
#: A MEAN, deliberately, not a peak. The helper's `..._queue_depth_max` is a
#: process-lifetime high-water: it never falls, so it cannot be differenced
#: across a window and one spike leaves it elevated for the life of the
#: process. Reading it as a window value made every cell after the first
#: spike report a replication backlog — a systematic bias toward naming the
#: exact site the #2852 Phase-2 decision turns on. The sum is differenceable
#: by construction and carries nothing into the next window.
DEFAULT_QUEUE_DEPTH_BACKLOG = 16.0

#: Minimum measurement window. Shorter windows let one status-poll jitter
#: dominate the rate.
DEFAULT_MIN_WINDOW_S = 5.0

#: Accepted new flows must reach this fraction of the offered rate, when the
#: generator reports one. Below it the generator (or the client NIC, or the
#: target) bound first and the firewall was never the constraint.
DEFAULT_MIN_ACCEPT_RATIO = 0.95

#: The loss userspace cluster's mlx5 VFs expose 6 combined RX queues -> 6
#: workers (docs/fairness-regimes.md). A cross-worker contention claim needs
#: traffic on more than a couple of them.
DEFAULT_MIN_ACTIVE_WORKERS = 3

#: A single worker taking more than this share of installs means RSS steered
#: the load onto one queue: the ceiling is that worker's core, not a
#: cross-worker lock.
DEFAULT_MAX_WORKER_SHARE = 0.60

VALID = "VALID"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"


class SnapshotError(ValueError):
    """A snapshot is structurally unusable (missing series, unparseable)."""


# ---------------------------------------------------------------------------
# Snapshot model
# ---------------------------------------------------------------------------

#: (site name, contended series, acquisitions series). The acquisition series
#: is the DENOMINATOR; a site whose denominator is missing cannot be
#: attributed and is reported as such rather than silently scored 0.
LOCK_SITES = (
    # #17036: since #15956 the allocator has two counted lock domains.
    # Each is its own site with its own denominator; the legacy summed
    # live_lock pair is scraped for monotonicity/continuity only and
    # must never vote as a culprit (it mixes the two domains).
    (
        "nat_allocator_flow_shard",
        "pool.flow_shard_lock_contended_total",
        "pool.flow_shard_lock_acquisitions_total",
    ),
    (
        "nat_allocator_live_write",
        "pool.live_write_lock_contended_total",
        "pool.live_write_lock_acquisitions_total",
    ),
    (
        "publish_shared_session",
        "publish.lock_contended_total",
        "publish.lock_acquisitions_total",
    ),
    (
        "replicate_session_upsert",
        "replicate.lock_contended_total",
        "replicate.enqueued_total",
    ),
    # #9169 — the FOURTH site. Every session delta (Open as well as Close)
    # allocates its wire sequence number and encodes its frame inside the
    # helper's process-global `producer_seq_lock`: #3878 F-152 requires the
    # allocation and the channel enqueue to be atomic together, so the encode
    # is INSIDE the critical section. It was absent from this model, which
    # meant a run that saturated here would have reported a plateau with all
    # three named sites cold and nothing to attribute it to.
    (
        "event_stream_producer_seq",
        "event_stream.lock_contended_total",
        "event_stream.lock_acquisitions_total",
    ),
)

#: Every counter that must never go backwards. A decrease means the helper
#: restarted mid-run (counters are process-lifetime), which invalidates the
#: window regardless of how healthy the numbers look.
MONOTONIC_FIELDS = (
    "pool.allocations_total",
    "pool.exhaustion_total",
    "pool.flow_shard_lock_acquisitions_total",
    "pool.flow_shard_lock_contended_total",
    "pool.live_write_lock_acquisitions_total",
    "pool.live_write_lock_contended_total",
    "pool.live_lock_acquisitions_total",
    "pool.live_lock_contended_total",
    "publish.publishes_total",
    "publish.lock_acquisitions_total",
    "publish.lock_contended_total",
    "replicate.upserts_total",
    "replicate.enqueued_total",
    "replicate.lock_contended_total",
    "replicate.queue_depth_sum",
    "replicate.queue_depth_max",
    # #9169 site 4.
    "event_stream.lock_acquisitions_total",
    "event_stream.lock_contended_total",
)

#: Snapshot keys that are REQUIRED to be present and usable, over and above
#: the counters above. Each one gates a refusal, and a gate whose own input
#: can go missing is a gate that fails open — the failure mode this whole
#: layer exists to prevent. `t` bounds the window (a missing one silently
#: becomes 0.0 and either kills the window or inflates it to ~1.7e9 seconds,
#: yielding a rate near zero that still reads VALID); `helper_pid` is the
#: only direct restart detector; `workers` is the sole input to BOTH
#: cross-worker gates, so an absent per-worker series would let a run steered
#: onto a single RX queue pass as a cross-worker lock bound.
REQUIRED_SNAPSHOT_KEYS = ("t", "helper_pid", "workers")


def _get(snapshot: Mapping, dotted: str) -> int:
    """Read a dotted path out of a snapshot, raising if absent.

    Absent is an ERROR, not a zero: a missing series means the scrape did not
    see the helper (or the helper predates the counter), and scoring that as
    "no contention" would report a clean result for a run that measured
    nothing.
    """
    node = snapshot
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            raise SnapshotError(f"snapshot missing required series {dotted!r}")
        node = node[part]
    if not isinstance(node, (int, float)) or isinstance(node, bool):
        raise SnapshotError(f"series {dotted!r} is not numeric: {node!r}")
    return int(node)


@dataclass
class SiteAttribution:
    """One synchronization site's blocked-acquisition share over the window."""

    name: str
    contended_delta: int
    acquisitions_delta: int
    #: contended/acquisitions over the window, or None when the site was not
    #: exercised at all (zero acquisitions). None is NOT 0.0: "never taken"
    #: and "taken and never blocked" are different findings.
    ratio: Optional[float]
    saturated: bool

    def as_dict(self) -> Dict:
        return {
            "site": self.name,
            "contended_delta": self.contended_delta,
            "acquisitions_delta": self.acquisitions_delta,
            "ratio": self.ratio,
            "saturated": self.saturated,
        }


@dataclass
class Analysis:
    verdict: str
    reasons: List[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    new_flows_per_sec: float = 0.0
    offered_flows_per_sec: Optional[float] = None
    accept_ratio: Optional[float] = None
    sites: List[SiteAttribution] = field(default_factory=list)
    #: EVERY saturated site, ratio-descending. A list, not a winner: the
    #: interesting real-world answer is "publish and replicate both saturated
    #: before NAT did", and a single-winner report would hide half of it.
    culprits: List[str] = field(default_factory=list)
    #: Mean worst-sibling queue depth per replicated flow over THIS window
    #: (Δqueue_depth_sum / Δupserts). The only depth reading any verdict
    #: rests on. None when nothing replicated.
    replication_queue_depth_mean: Optional[float] = None
    #: Process-lifetime high-water. OPERATOR CONTEXT ONLY — see the module
    #: docstring; it cannot be differenced and must never gate a culprit.
    replication_queue_depth_max_lifetime: int = 0
    #: Whether THIS window set a new all-time depth record.
    replication_queue_depth_new_record: bool = False
    replication_fanout: Optional[float] = None
    worker_installs: Dict[str, int] = field(default_factory=dict)
    active_workers: int = 0
    max_worker_share: Optional[float] = None

    @property
    def saturated(self) -> bool:
        return bool(self.culprits)

    def as_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "elapsed_s": self.elapsed_s,
            "new_flows_per_sec": self.new_flows_per_sec,
            "offered_flows_per_sec": self.offered_flows_per_sec,
            "accept_ratio": self.accept_ratio,
            "saturated": self.saturated,
            "culprits": list(self.culprits),
            "sites": [s.as_dict() for s in self.sites],
            "replication_queue_depth_mean": self.replication_queue_depth_mean,
            "replication_queue_depth_max_lifetime": self.replication_queue_depth_max_lifetime,
            "replication_queue_depth_new_record": self.replication_queue_depth_new_record,
            "replication_fanout": self.replication_fanout,
            "worker_installs": dict(self.worker_installs),
            "active_workers": self.active_workers,
            "max_worker_share": self.max_worker_share,
        }


def analyze(
    before: Mapping,
    after: Mapping,
    *,
    offered_flows_per_sec: Optional[float] = None,
    saturation_ratio: float = DEFAULT_SATURATION_RATIO,
    queue_depth_backlog: float = DEFAULT_QUEUE_DEPTH_BACKLOG,
    min_window_s: float = DEFAULT_MIN_WINDOW_S,
    min_accept_ratio: float = DEFAULT_MIN_ACCEPT_RATIO,
    min_active_workers: int = DEFAULT_MIN_ACTIVE_WORKERS,
    max_worker_share: float = DEFAULT_MAX_WORKER_SHARE,
) -> Analysis:
    """Derive the new-flow rate and the bottleneck attribution for one cell.

    ``before``/``after`` are normalized snapshots (see
    :func:`parse_prometheus_text`). Returns an :class:`Analysis` whose
    ``verdict`` is the first thing a caller must read: only ``VALID`` results
    describe the install path.
    """
    # --- inputs the refusals below depend on --------------------------------
    # FIRST, before anything reads them. Every check further down is only as
    # trustworthy as its input, and each of these previously degraded to a
    # default that DISABLED its check rather than tripping it: a missing `t`
    # became 0.0 (window either zero or ~1.7e9 seconds), a missing
    # `helper_pid` skipped the restart comparison outright, and an absent
    # `workers` map skipped BOTH cross-worker gates. Absent input is a
    # collection failure, and a collection failure is not a measurement.
    missing = []
    for snap_name, snap in (("before", before), ("after", after)):
        for k in REQUIRED_SNAPSHOT_KEYS:
            if snap.get(k) is None:
                missing.append(f"{snap_name}.{k}")
    if missing:
        return Analysis(
            verdict=INVALID,
            reasons=[
                "snapshot is missing input(s) that gate a refusal, so those "
                "refusals could not run: " + ", ".join(missing)
            ],
        )
    if not after["workers"] and not before["workers"]:
        return Analysis(
            verdict=INVALID,
            reasons=[
                "no per-worker new-flow install series in either snapshot: the "
                "RSS-distribution and worker-skew gates have no input, so a "
                "run steered onto a single RX queue could not be distinguished "
                "from a genuine cross-worker result"
            ],
        )
    if offered_flows_per_sec is not None and offered_flows_per_sec <= 0:
        return Analysis(
            verdict=INVALID,
            reasons=[
                f"offered rate is {offered_flows_per_sec}: zero (or negative) "
                "offered load is not a measurement. A generator that produced "
                "no parseable output must fail the cell, not silently disable "
                "the generator-bound check"
            ],
        )

    elapsed = float(after["t"]) - float(before["t"])

    # --- structural validity ------------------------------------------------
    # Checked before any rate is computed, so an invalid run never gets to
    # print a plausible-looking number.
    if elapsed <= 0:
        return Analysis(
            verdict=INVALID,
            reasons=[f"non-positive measurement window ({elapsed:.3f}s)"],
            elapsed_s=elapsed,
        )

    before_pid = before["helper_pid"]
    after_pid = after["helper_pid"]
    if before_pid != after_pid:
        return Analysis(
            verdict=INVALID,
            reasons=[
                f"helper restarted mid-window (pid {before_pid} -> {after_pid}); "
                "counters are process-lifetime and the deltas are meaningless"
            ],
            elapsed_s=elapsed,
        )

    regressions = []
    for f in MONOTONIC_FIELDS:
        if _get(after, f) < _get(before, f):
            regressions.append(f)
    if regressions:
        return Analysis(
            verdict=INVALID,
            reasons=[
                "counter(s) went backwards, so the helper restarted or the "
                "scrape crossed processes: " + ", ".join(sorted(regressions))
            ],
            elapsed_s=elapsed,
        )

    allocations = _get(after, "pool.allocations_total") - _get(
        before, "pool.allocations_total"
    )
    if allocations <= 0:
        return Analysis(
            verdict=INVALID,
            reasons=[
                "zero pool-mode SNAT allocations over the window: either the "
                "pool-mode source-NAT rule was not in effect, or no new flows "
                "reached it. This is NOT a measured rate of 0"
            ],
            elapsed_s=elapsed,
        )

    if elapsed < min_window_s:
        return Analysis(
            verdict=INVALID,
            reasons=[
                f"measurement window {elapsed:.3f}s is below the {min_window_s}s "
                "floor; status-poll jitter would dominate the rate"
            ],
            elapsed_s=elapsed,
        )

    # --- rate + attribution -------------------------------------------------
    result = Analysis(verdict=VALID, elapsed_s=elapsed)

    # --- worker distribution (needed for the rate below) -------------------------------------------------
    before_workers = before.get("workers", {}) or {}
    after_workers = after.get("workers", {}) or {}
    installs: Dict[str, int] = {}
    for worker in sorted(set(before_workers) | set(after_workers), key=str):
        delta = int(after_workers.get(worker, 0)) - int(before_workers.get(worker, 0))
        if delta < 0:
            result.verdict = INVALID
            result.reasons.append(
                f"worker {worker} new-flow install counter went backwards; "
                "the helper restarted mid-window"
            )
            return result
        installs[str(worker)] = delta
    result.worker_installs = installs
    total_installs = sum(installs.values())
    result.active_workers = sum(1 for v in installs.values() if v > 0)
    if total_installs > 0:
        result.max_worker_share = max(installs.values()) / total_installs

    # The reported flow rate is INSTALLED flows, summed from the per-worker
    # `new_flow_installs` counters — NOT `pool.allocations_total`.
    #
    # A pool allocation is taken BEFORE pair admission (nat/allocator.rs) and a
    # refusal rolls it back without decrementing the cumulative counter, so the
    # allocation delta counts attempts, not installs. 100k SYNs with 90k refused
    # and 10k committed reported 100k new flows/s — a ceiling measurement that
    # is 10x the flows the firewall actually installed, in exactly the overload
    # regime this harness is pointed at. The Rust side already proves the two
    # diverge: the admission-refusal test asserts a rolled-back NAT decision
    # with `new_flow_installs == 0`.
    #
    # The allocation delta is still required to be > 0 above — that gate answers
    # "was the pool-mode SNAT rule in effect at all", which is a different
    # question and still worth refusing on.
    result.new_flows_per_sec = total_installs / elapsed
    result.offered_flows_per_sec = offered_flows_per_sec
    if offered_flows_per_sec:
        result.accept_ratio = result.new_flows_per_sec / offered_flows_per_sec

    deltas = {
        f: _get(after, f) - _get(before, f) for f in MONOTONIC_FIELDS
    }

    for name, contended_key, acq_key in LOCK_SITES:
        contended = deltas[contended_key]
        acquisitions = deltas[acq_key]
        ratio = (contended / acquisitions) if acquisitions > 0 else None
        result.sites.append(
            SiteAttribution(
                name=name,
                contended_delta=contended,
                acquisitions_delta=acquisitions,
                ratio=ratio,
                saturated=ratio is not None and ratio >= saturation_ratio,
            )
        )

    upserts = deltas["replicate.upserts_total"]
    if upserts > 0:
        result.replication_fanout = deltas["replicate.enqueued_total"] / upserts
        # THE backlog statistic: mean worst-sibling depth per replicated flow
        # over THIS window. Differenceable by construction, so nothing an
        # earlier cell did can leak into this one.
        result.replication_queue_depth_mean = (
            deltas["replicate.queue_depth_sum"] / upserts
        )

    # Reported for operators, never a verdict input. A process-lifetime
    # high-water cannot be differenced (it never falls, so a zero delta spans
    # "no backlog" through "a backlog up to the previous all-time high") and
    # its absolute value stays elevated for the life of the helper after one
    # spike. `replication_queue_depth_new_record` says only whether THIS
    # window set a new all-time high — context for the mean above, not a
    # substitute for it.
    result.replication_queue_depth_max_lifetime = _get(
        after, "replicate.queue_depth_max"
    )
    result.replication_queue_depth_new_record = deltas["replicate.queue_depth_max"] > 0

    # Culprits: every saturated site, ratio-descending. Ties keep LOCK_SITES
    # order so the output is deterministic.
    ordered = sorted(
        (s for s in result.sites if s.saturated),
        key=lambda s: (-(s.ratio or 0.0), [n for n, _, _ in LOCK_SITES].index(s.name)),
    )
    result.culprits = [s.name for s in ordered]
    if (
        result.replication_queue_depth_mean is not None
        and result.replication_queue_depth_mean >= queue_depth_backlog
    ):
        # A distinct culprit from the replication MUTEX: same subsystem,
        # different remedy (drain rate vs. lock sharding). Keyed on the
        # WINDOW MEAN, never on the lifetime high-water.
        result.culprits.append("replicate_session_upsert_queue_backlog")

    # --- things that bound BEFORE the install path did -----------------------
    # These downgrade to INCONCLUSIVE rather than INVALID: the run happened
    # and its numbers are real, they just do not describe the install path.
    if deltas["pool.exhaustion_total"] > 0:
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"{deltas['pool.exhaustion_total']} allocator exhaustion events: the "
            "pool ran out of ports, so this is a pool-capacity ceiling, not a "
            "lock ceiling"
        )
    if result.accept_ratio is not None and result.accept_ratio < min_accept_ratio:
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"accepted {result.new_flows_per_sec:.0f}/s of an offered "
            f"{offered_flows_per_sec:.0f}/s ({result.accept_ratio:.1%} < "
            f"{min_accept_ratio:.0%}): the generator, client NIC or target bound "
            "first, so the firewall was not the constraint"
        )
    if installs and result.active_workers < min_active_workers:
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"only {result.active_workers} of {len(installs)} workers installed "
            f"flows (minimum {min_active_workers}): RSS-distribution-limited, so "
            "a cross-worker contention claim is not supported"
        )
    if (
        result.max_worker_share is not None
        and result.max_worker_share > max_worker_share
    ):
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"one worker took {result.max_worker_share:.1%} of installs (ceiling "
            f"{max_worker_share:.0%}): single-worker-bound, so the ceiling is one "
            "core rather than a cross-worker lock"
        )

    return result


# ---------------------------------------------------------------------------
# Prometheus scrape -> normalized snapshot
# ---------------------------------------------------------------------------

_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)\s*$"
)
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def _samples(text: str, metric: str) -> List[tuple]:
    """Return [(labels_dict, value)] for one metric family in a scrape."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE.match(line)
        if not m or m.group("name") != metric:
            continue
        labels = dict(_LABEL.findall(m.group("labels") or ""))
        try:
            value = float(m.group("value"))
        except ValueError:
            continue
        out.append((labels, value))
    return out


def _scalar(text: str, metric: str) -> int:
    rows = _samples(text, metric)
    if not rows:
        raise SnapshotError(f"scrape has no series {metric!r}")
    if len(rows) > 1:
        raise SnapshotError(f"expected one {metric!r} series, saw {len(rows)}")
    return int(rows[0][1])


def parse_prometheus_text(
    text: str,
    *,
    timestamp: float,
    pool_name: Optional[str] = None,
    rule_name: Optional[str] = None,
    helper_pid: Optional[int] = None,
) -> Dict:
    """Normalize one `/metrics` scrape into the snapshot `analyze` consumes.

    ``pool_name``/``rule_name`` select the pool under test. Selecting it here
    rather than summing every pool is deliberate: a firewall with a second,
    idle pool would otherwise contribute a huge uncontended acquisition count
    and dilute the ratio of the pool actually carrying the load.
    """

    def pool_metric(metric: str) -> int:
        rows = _samples(text, metric)
        if pool_name is not None:
            rows = [r for r in rows if r[0].get("pool") == pool_name]
        if rule_name is not None:
            rows = [r for r in rows if r[0].get("rule") == rule_name]
        if not rows:
            raise SnapshotError(
                f"scrape has no {metric!r} series for pool={pool_name!r} "
                f"rule={rule_name!r} — the pool-mode SNAT rule is not in effect"
            )
        if len(rows) > 1:
            raise SnapshotError(
                f"{metric!r} matched {len(rows)} pools; pass pool/rule to select one"
            )
        return int(rows[0][1])

    worker_rows = _samples(text, "xpf_userspace_worker_new_flow_installs_total")
    if not worker_rows:
        # An absent per-worker series is a collection failure, not "zero
        # workers". Returning {} here would leave both cross-worker gates
        # with no input, and a gate with no input is a gate that does not run.
        raise SnapshotError(
            "scrape has no xpf_userspace_worker_new_flow_installs_total series: "
            "the RSS-distribution and worker-skew gates would have nothing to "
            "evaluate. Check the helper build carries the #4800 counters"
        )
    workers = {labels.get("worker_id", "?"): int(value) for labels, value in worker_rows}

    return {
        "t": float(timestamp),
        "helper_pid": helper_pid,
        "pool": {
            "name": pool_name,
            "rule": rule_name,
            "allocations_total": pool_metric(
                "xpf_userspace_source_nat_pool_allocations_total"
            ),
            "exhaustion_total": pool_metric(
                "xpf_userspace_source_nat_pool_exhaustions_total"
            ),
            "flow_shard_lock_acquisitions_total": pool_metric(
                "xpf_userspace_source_nat_pool_flow_shard_lock_acquisitions_total"
            ),
            "flow_shard_lock_contended_total": pool_metric(
                "xpf_userspace_source_nat_pool_flow_shard_lock_contended_total"
            ),
            "live_write_lock_acquisitions_total": pool_metric(
                "xpf_userspace_source_nat_pool_live_write_lock_acquisitions_total"
            ),
            "live_write_lock_contended_total": pool_metric(
                "xpf_userspace_source_nat_pool_live_write_lock_contended_total"
            ),
            "live_lock_acquisitions_total": pool_metric(
                "xpf_userspace_source_nat_pool_live_lock_acquisitions_total"
            ),
            "live_lock_contended_total": pool_metric(
                "xpf_userspace_source_nat_pool_live_lock_contended_total"
            ),
        },
        "publish": {
            "publishes_total": _scalar(text, "xpf_userspace_shared_session_publishes_total"),
            "lock_acquisitions_total": _scalar(
                text, "xpf_userspace_shared_session_publish_lock_acquisitions_total"
            ),
            "lock_contended_total": _scalar(
                text, "xpf_userspace_shared_session_publish_lock_contended_total"
            ),
        },
        # #9169 site 4: the event-stream producer-seq lock pair. `_scalar`
        # raises when the series is absent, which is the intended behaviour —
        # a helper built before #9169 does not emit these, and scoring that
        # build as "never contended" would report a clean fourth site for a
        # run that could not have measured one.
        "event_stream": {
            "lock_acquisitions_total": _scalar(
                text,
                "xpf_userspace_event_stream_producer_seq_lock_acquisitions_total",
            ),
            "lock_contended_total": _scalar(
                text,
                "xpf_userspace_event_stream_producer_seq_lock_contended_total",
            ),
        },
        "replicate": {
            "upserts_total": _scalar(
                text, "xpf_userspace_session_replication_upserts_total"
            ),
            "enqueued_total": _scalar(
                text, "xpf_userspace_session_replication_enqueued_total"
            ),
            "lock_contended_total": _scalar(
                text, "xpf_userspace_session_replication_lock_contended_total"
            ),
            "queue_depth_sum": _scalar(
                text, "xpf_userspace_session_replication_queue_depth_sum"
            ),
            "queue_depth_max": _scalar(
                text, "xpf_userspace_session_replication_queue_depth_max"
            ),
        },
        "workers": workers,
    }


# ---------------------------------------------------------------------------
# Human report
# ---------------------------------------------------------------------------


def render(a: Analysis) -> str:
    lines = [f"verdict: {a.verdict}"]
    for r in a.reasons:
        lines.append(f"  ! {r}")
    lines.append(f"window: {a.elapsed_s:.2f}s")
    lines.append(f"new flows/sec (installed transit flows): {a.new_flows_per_sec:.0f}")
    if a.offered_flows_per_sec:
        lines.append(
            f"offered flows/sec: {a.offered_flows_per_sec:.0f} "
            f"(accepted {a.accept_ratio:.1%})"
        )
    lines.append("")
    lines.append("contention by site (blocked / acquisitions):")
    for s in a.sites:
        ratio = "n/a (never taken)" if s.ratio is None else f"{s.ratio:.2%}"
        flag = "  <-- SATURATED" if s.saturated else ""
        lines.append(
            f"  {s.name:<26} {s.contended_delta:>12} / {s.acquisitions_delta:<14} {ratio}{flag}"
        )
    mean = (
        "n/a"
        if a.replication_queue_depth_mean is None
        else f"{a.replication_queue_depth_mean:.1f}"
    )
    lines.append(f"  replication queue depth, WINDOW MEAN: {mean}   <- the verdict input")
    record = " (new record set this window)" if a.replication_queue_depth_new_record else ""
    lines.append(
        f"  replication queue depth, process-lifetime high-water: "
        f"{a.replication_queue_depth_max_lifetime}{record}"
    )
    lines.append(
        "    ^ operator context only — a lifetime max cannot be differenced "
        "and never gates a culprit"
    )
    if a.replication_fanout is not None:
        lines.append(f"  live-sibling fan-out (enqueued/upserts): {a.replication_fanout:.2f}")
    lines.append("")
    if a.culprits:
        lines.append("saturated: " + ", ".join(a.culprits))
    else:
        lines.append("saturated: none — no site reached the saturation threshold")
    if a.worker_installs:
        spread = " ".join(f"{w}={n}" for w, n in sorted(a.worker_installs.items()))
        lines.append(f"per-worker installs: {spread}")
        lines.append(
            f"  active workers: {a.active_workers}  max share: "
            f"{a.max_worker_share:.1%}"
            if a.max_worker_share is not None
            else f"  active workers: {a.active_workers}"
        )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("before", help="JSON snapshot taken before the traffic cell")
    p.add_argument("after", help="JSON snapshot taken after the traffic cell")
    p.add_argument(
        "--offered-rate",
        type=float,
        default=None,
        help="generator-reported offered new flows/sec, if known",
    )
    p.add_argument("--saturation-ratio", type=float, default=DEFAULT_SATURATION_RATIO)
    p.add_argument("--queue-depth-backlog", type=float, default=DEFAULT_QUEUE_DEPTH_BACKLOG)
    p.add_argument("--min-window", type=float, default=DEFAULT_MIN_WINDOW_S)
    p.add_argument("--min-accept-ratio", type=float, default=DEFAULT_MIN_ACCEPT_RATIO)
    p.add_argument("--min-active-workers", type=int, default=DEFAULT_MIN_ACTIVE_WORKERS)
    p.add_argument("--max-worker-share", type=float, default=DEFAULT_MAX_WORKER_SHARE)
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = p.parse_args(argv)

    with open(args.before, encoding="utf-8") as f:
        before = json.load(f)
    with open(args.after, encoding="utf-8") as f:
        after = json.load(f)

    a = analyze(
        before,
        after,
        offered_flows_per_sec=args.offered_rate,
        saturation_ratio=args.saturation_ratio,
        queue_depth_backlog=args.queue_depth_backlog,
        min_window_s=args.min_window,
        min_accept_ratio=args.min_accept_ratio,
        min_active_workers=args.min_active_workers,
        max_worker_share=args.max_worker_share,
    )
    print(json.dumps(a.as_dict(), indent=2) if args.json else render(a))
    # Exit codes are the harness's fail gate: 0 only for a run that measured
    # the install path, 2 for a run that measured something else, 1 for a run
    # that measured nothing.
    return {VALID: 0, INCONCLUSIVE: 2}.get(a.verdict, 1)


if __name__ == "__main__":
    sys.exit(main())
