#!/usr/bin/env python3
"""Continuous one-node RG-move soak (#18583, regression matrix row H11).

This is the operator's own pattern made rigorous. The operator runs, from ONE
node, forever:

    for n in $(seq 10000); do
        incus exec xpf-userspace-fw0 -- cli -c \
            "request chassis cluster failover redundancy-group 2 node $[n%2]"
        sleep 5
    done

Every HA gate before this one resynced both node clocks from the orchestrator
first, or did a few moves and restored. On 2026-10-31 that loop failed every
`node 1` move with a fabric-auth clock error and printed "already primary" for
every `node 0` move, and traffic never reached node1. Nothing had tested it.

What this harness does, per move:

  * issues `request chassis cluster failover redundancy-group <rg> node <t>`
    on the SAME node every time (SOAK_FROM), alternating t, then waits SOAK_SLEEP
    seconds after the CLI returns, exactly like the loop above. With
    SOAK_FORM=untargeted-away a move AWAY from that node is the untargeted
    `redundancy-group <rg>` instead (#18559: H1's form);
  * scores the CLI text;
  * polls BOTH nodes' own `show chassis cluster status` until the target is
    primary and the other node secondary/secondary-hold in both views, and the
    target's `Forwarding: rg-active=` line is active and the other's inactive;
  * keeps sampling both views for the rest of the window, recording any
    sample in which both nodes claim the RG (dual-active) or the RG leaving
    the target after landing. During a move the two nodes are read one
    after the other, the commanded TARGET first, so a clean handoff cannot
    be read as dual-active (#19041);
  * reads each helper's own `ha_groups[].forwarding_active` (active AND an
    unexpired lease) once the views converged;
  * proves the TRAFFIC moved: the target node's RETH members (from the
    helper's per-binding RX+TX counters) carry the packets between landing
    and the window's end and the other node's do not, and the LAN host's
    neighbour entry for the LAN VIP resolves to the target node's MAC;
  * attributes IPv4 and IPv6 ping loss / longest ping gap and the worst
    iperf3 per-stream stall to the move's window, all on the LAN host's
    clock;
  * with routed targets set (#19050), does the same for destinations no
    connected subnet covers (the default route, a non-default static), and
    records the new WAN owner's host-originated routed-path lag on its own
    clock. Every routed probe must answer before the first move, or its
    cells are VOID for the run. The host-originated probe (host4) is SCORED
    (#19050 review R4 F2 / R14-1): a WAN-handing move with no routed reply
    from the new owner FAILs; a lag over SOAK_MAX_HOST4_LAG_MS is a COST; a
    routed reply from a node that does not hold the WAN address (the
    standby at baseline, the new owner before its gateway answers, the old
    owner after it stopped answering) FAILs, because that is a default the
    node must not have; and a WAN move whose new owner never reaches its
    gateway is VOID, never PASS.

It never touches a clock. The preflight measures inter-node skew and reports
it, because a skewed cluster is exactly what the operator's loop hit.

Verdicts (one per move):

  PASS  every check held.
  COST  the move was correct but its transition cost exceeded the budget: a
        ping gap over SOAK_MAX_GAP_MS or a stream stall over
        SOAK_MAX_STALL_MS from which the stream recovered. That is #18559's
        known cost, judged master-relative like row H10; SOAK_STRICT_COST=1
        scores it as a FAIL.
  FAIL  a CLI error; "already primary" when the precondition held; any other
        unexpected CLI text; the move did not land within the bound; it left
        the target or went dual-active inside the window; the helper
        disagrees with the status views; the traffic did not follow (RETH
        counters or the LAN neighbour entry on the old node, nothing in the
        window's tail); a stream that never recovered; a traffic generator
        that stopped.
  VOID  the precondition did not hold: before a move to node t, the RG was not
        cleanly owned by the other node. A failed move therefore costs ONE
        FAIL, and the next move (back to where the RG still is) is VOID, not a
        second FAIL — the user's "already primary" line was that cascade. A
        harness or precondition fault for the whole run (no clean owner, a
        busy or dead traffic target, a Python error, SIGTERM) is a VOID run.

Exit status: 0 every move PASS or COST; 1 any FAIL; 2 no FAIL but a VOID move,
a void run, or a check disabled (SOAK_TRAFFIC=0, SOAK_HELPER_CHECK=0).
The last line, "rg-move-soak: <n> passed, <m> failed", is what the
smoke-cells ledger adapter scores.

Pure functions (parsers, verdicts, summary) are covered hermetically by
rg_move_soak_test.py; `Soak` takes an injectable cluster and clock so the
orchestration itself is driven there by a fake cluster too.
"""

import argparse
import concurrent.futures
import json
import os
import re
import inspect
import shlex
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
import udp_session_probe

PASS, FAIL, VOID, COST = "PASS", "FAIL", "VOID", "COST"

# ---------------------------------------------------------------------------
# `show chassis cluster status` parsing
# ---------------------------------------------------------------------------

_RG_HEADER = re.compile(r"^Redundancy group:\s*(\d+)\s*,")
_NODE_ROW = re.compile(r"^node(\d+)\s+\d+\s+(\S+)")
_FWD = re.compile(r"^\s+Forwarding:\s+(.*)$")


@dataclass
class RGView:
    """One node's own view of one redundancy group."""

    roles: Dict[int, str] = field(default_factory=dict)
    # Each node prints a `Forwarding:` line only under its OWN row; this is
    # that node's dataplane-applied state ("active"/"inactive"), plus any
    # trailing DIVERGENCE text. `forwarding_node` is the node whose row the
    # line sits under (#19041): only a node's OWN line speaks for it.
    forwarding: Optional[str] = None
    forwarding_node: Optional[int] = None
    forwarding_extra: str = ""
    duplicate: bool = False


def parse_status(text: str) -> Dict[int, RGView]:
    """Parse one node's status into {rg: RGView}.

    Exact `Redundancy group: N ,` headers (never a substring: RG1 must not
    match RG10). A duplicated node row or Forwarding line marks the view
    duplicate, which every consumer treats as unreadable.
    """
    views: Dict[int, RGView] = {}
    rg: Optional[int] = None
    last_node: Optional[int] = None
    for line in (text or "").splitlines():
        m = _RG_HEADER.match(line)
        if m:
            rg = int(m.group(1))
            views.setdefault(rg, RGView())
            last_node = None
            continue
        if rg is None:
            continue
        m = _NODE_ROW.match(line)
        if m:
            node, role = int(m.group(1)), m.group(2).lower()
            v = views[rg]
            if node in v.roles:
                v.duplicate = True
            v.roles[node] = role
            last_node = node
            continue
        m = _FWD.match(line)
        if m and last_node is not None:
            v = views[rg]
            if v.forwarding is not None:
                v.duplicate = True
            value, extra = "", []
            for tok in m.group(1).split():
                if tok.startswith("rg-active="):
                    value = tok[len("rg-active="):]
                elif not tok.startswith("vrrp-master="):
                    extra.append(tok)
            v.forwarding = value
            v.forwarding_node = last_node
            v.forwarding_extra = " ".join(extra).lstrip("- ").strip()
    return views


NON_OWNER_ROLES = ("secondary", "secondary-hold")
FORWARDING_VALUES = ("active", "inactive")


def own_forwarding(view: RGView, node: int) -> Optional[str]:
    """`node`'s OWN Forwarding value: the line under node's own row, never
    a line under the peer's row (#19041)."""
    return view.forwarding if view.forwarding_node == node else None


@dataclass
class Ownership:
    """The joint reading of both nodes' own views for one RG."""

    owner: Optional[int]  # the single clean owner, or None
    dual_active: bool
    detail: str


def rg_ownership(rg: int, view0: Dict[int, RGView], view1: Dict[int, RGView]) -> Ownership:
    """Decide who owns `rg` from node0's and node1's OWN status output.

    Ownership needs BOTH views (the #18503 rule): node0's view alone scores a
    dual-primary split as healthy. Each node's role comes from its own view;
    forwarding comes from each node's own `Forwarding:` line.
    """
    v0, v1 = view0.get(rg), view1.get(rg)
    if v0 is None or v1 is None:
        return Ownership(None, False, f"RG{rg} missing from {'node0' if v0 is None else 'node1'} view")
    if v0.duplicate or v1.duplicate:
        return Ownership(None, False, f"RG{rg} view has duplicate rows")
    r0, r1 = v0.roles.get(0), v1.roles.get(1)
    f0, f1 = own_forwarding(v0, 0), own_forwarding(v1, 1)
    detail = f"node0={r0 or 'missing'}/{f0 or 'missing'} node1={r1 or 'missing'}/{f1 or 'missing'}"
    extras = [e for v, f in ((v0, f0), (v1, f1)) if f is not None for e in (v.forwarding_extra,) if e]
    if extras:
        detail += " (" + "; ".join(extras) + ")"
    dual = (r0 == "primary" and r1 == "primary") or (f0 == "active" and f1 == "active")
    if dual:
        return Ownership(None, True, detail)
    if not views_readable(rg, view0, view1):
        return Ownership(None, False, detail + " (unreadable: a node's own role row or own Forwarding "
                                              "value is missing or not active/inactive)")
    if extras:
        return Ownership(None, False, detail)
    if r0 == "primary" and r1 in NON_OWNER_ROLES and f0 == "active" and f1 == "inactive":
        return Ownership(0, False, detail)
    if r1 == "primary" and r0 in NON_OWNER_ROLES and f1 == "active" and f0 == "inactive":
        return Ownership(1, False, detail)
    return Ownership(None, False, detail)


def views_readable(rg: int, view0: Dict[int, RGView], view1: Dict[int, RGView]) -> bool:
    """Both nodes' own views carry `rg` exactly once, each with that node's
    OWN role row and its OWN `Forwarding: rg-active=` value, which must be
    `active` or `inactive` (#19041). An RG header alone, a Forwarding line
    under the peer's row, or an unknown value is not a reading."""
    v0, v1 = view0.get(rg), view1.get(rg)
    if v0 is None or v1 is None or v0.duplicate or v1.duplicate:
        return False
    return (v0.roles.get(0) is not None and v1.roles.get(1) is not None
            and own_forwarding(v0, 0) in FORWARDING_VALUES and own_forwarding(v1, 1) in FORWARDING_VALUES)


# ---------------------------------------------------------------------------
# CLI result
# ---------------------------------------------------------------------------

CLI_OK, CLI_ALREADY, CLI_ERROR, CLI_OTHER = "ok", "already", "error", "other"
# #18559: the untargeted form's local-resign replies. Accepted only for an
# untargeted move (SOAK_FORM=untargeted-away). Such a command tells the truth
# but confirms no commit, so the UDP probe checkpoints at the observed landing.
#   CLI_TRIGGERED  the plain pre-#18559 text: a pre-#18559 build. With
#                  SOAK_EXPECT_TRANSFER=1 (a post-#18559 build) it FAILs.
#   CLI_FALLBACK   a post-#18559 build that did NOT run the transfer: the
#                  request never reached the peer ("peer unreachable; resigned
#                  locally, break-before-make"), the peer also claimed the RG,
#                  or a derived resign found the group had already left this
#                  node ("Redundancy group N is no longer primary on this node
#                  ...; Nothing to resign", an OK reply: it moved by election,
#                  not make-before-break). The move did not exercise the path
#                  the soak measures, so it is VOID with that reason, never a
#                  silent PASS and never "unexpected CLI output".
CLI_TRIGGERED = "triggered"
CLI_FALLBACK = "fallback"
CLI_CLASSES = (CLI_OK, CLI_TRIGGERED, CLI_FALLBACK, CLI_ALREADY, CLI_ERROR, CLI_OTHER)

_CLI_OK_RE = re.compile(r"Manual failover completed for redundancy group (\d+) \(transfer committed\)")
_CLI_TRIGGERED_RE = re.compile(r"Manual failover triggered for redundancy group (\d+)$")
# The two notes are clusterfailover.ResignNoteUnreachable / ResignNoteDualActive.
_CLI_FALLBACK_RE = re.compile(r"Manual failover triggered for redundancy group (\d+) "
                              r"\((peer unreachable; resigned locally, break-before-make"
                              r"|the peer is also primary; resigned locally)\)$")
# clusterfailover.UntargetedNoLongerPrimaryMessage (#18559 cycle 3). The Go
# cell TestSoakReplyNotesMatchGo18559 keeps its fixed fragments in sync.
_CLI_NO_LONGER_PRIMARY_RE = re.compile(r"^Redundancy group (\d+) is no longer primary on this node \(now [^)]*\); "
                                       r".*Nothing to resign")

# SOAK_FORM values. "targeted" (the default) issues every move as
# `redundancy-group <rg> node <target>`. "untargeted-away" issues a move AWAY
# from the issuing node as the operator's untargeted form
# `redundancy-group <rg>` (run on that node, which owns the RG), and a move
# back TO it as `... node <issuer>`: the "fail over away from me, then bring
# it back" loop. H1 (test-failover) issues its planned moves untargeted.
FORM_TARGETED, FORM_UNTARGETED_AWAY = "targeted", "untargeted-away"
FORMS = (FORM_TARGETED, FORM_UNTARGETED_AWAY)


def move_command(rg: int, target: int, issuer: int, form: str) -> Tuple[str, bool]:
    """The CLI command for one RG move, and whether it is the untargeted form."""
    if form == FORM_UNTARGETED_AWAY and target != issuer:
        return f"request chassis cluster failover redundancy-group {rg}", True
    return f"request chassis cluster failover redundancy-group {rg} node {target}", False


def classify_cli(rc: int, out: str, rg: int, untargeted: bool = False) -> Tuple[str, str]:
    """Classify one `request chassis cluster failover ...` result.

    The CLI can print `error: ...` and still exit 0, so the TEXT decides, and
    a nonzero rc is an error whatever the text says. `... triggered ...` is
    accepted only for an untargeted move.
    """
    text = (out or "").strip()
    first = text.splitlines()[0] if text else ""
    if rc != 0 or re.search(r"(^|\n)\s*error:", text) or "rpc error" in text:
        return CLI_ERROR, first or f"rc={rc}"
    if "is already primary on node" in text:
        return CLI_ALREADY, first
    m = _CLI_OK_RE.search(text)
    if m and int(m.group(1)) == rg:
        return CLI_OK, first
    m = _CLI_TRIGGERED_RE.search(first)
    if untargeted and m and int(m.group(1)) == rg:
        return CLI_TRIGGERED, first
    m = _CLI_FALLBACK_RE.search(first)
    if untargeted and m and int(m.group(1)) == rg:
        return CLI_FALLBACK, first
    m = _CLI_NO_LONGER_PRIMARY_RE.search(first)
    if untargeted and m and int(m.group(1)) == rg:
        return CLI_FALLBACK, first
    return CLI_OTHER, first or "(no output)"


def cli_error_hint(text: str) -> str:
    """Name the class of a CLI failure so a table reader can act on it."""
    t = text or ""
    if "fabric RPC authentication failed" in t or "ahead of ours" in t or "behind ours" in t:
        return "fabric-auth clock skew between nodes (fix NTP; see docs/ha-rg-move-correctness.md)"
    if "clock" in t.lower() and "skew" in t.lower():
        return "inter-node clock skew"
    if "cannot connect to peer" in t:
        return "fabric RPC to the peer failed"
    if "barrier" in t or "fenced" in t or "refus" in t:
        return "transfer refused at the peer barrier/fence"
    return ""


# ---------------------------------------------------------------------------
# Traffic parsing (LAN host clock)
# ---------------------------------------------------------------------------

_PING = re.compile(r"^\[(\d+\.\d+)\].*icmp_seq=(\d+)")


def parse_ping(text: str) -> List[Tuple[float, int]]:
    """`ping -D` replies as (lan_ts, unwrapped_seq), in arrival order."""
    out: List[Tuple[float, int]] = []
    wrap, prev = 0, None
    for line in (text or "").splitlines():
        m = _PING.match(line)
        if not m:
            continue
        ts, seq = float(m.group(1)), int(m.group(2))
        if prev is not None and seq + wrap < prev - 32768:
            wrap += 65536
        seq += wrap
        prev = seq
        out.append((ts, seq))
    return out


@dataclass
class PingGap:
    start: float  # LAN ts of the last reply before the gap
    end: float  # LAN ts of the first reply after it
    lost: int


def ping_gaps(replies: List[Tuple[float, int]]) -> List[PingGap]:
    """Every consecutive reply pair, with the seqs missing between them."""
    gaps: List[PingGap] = []
    for (t0, s0), (t1, s1) in zip(replies, replies[1:]):
        if s1 <= s0:  # duplicate / reordered reply: not a gap
            continue
        gaps.append(PingGap(t0, t1, s1 - s0 - 1))
    return gaps


@dataclass
class StreamRun:
    stream: int
    start: float  # LAN ts
    seconds: float
    to_end: bool = False  # still stalled at the last interval: the stream died


def parse_iperf_stream(text: str) -> Tuple[List[Tuple[float, float, Dict[int, float], float]], bool, bool]:
    """Parse arrival-stamped `iperf3 --json-stream` output.

    Each line is `<lan_arrival_ts> <json event>` (the LAN host stamps lines as
    they arrive). Returns (intervals, started, ended), with each interval as
    (lan_start, lan_end, {stream: bps}, sum_bps). Absolute time is anchored by
    the median of (arrival - interval end) — robust to one slow flush.
    """
    raw = []
    started = ended = False
    for line in (text or "").splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        try:
            arrival = float(parts[0])
            ev = json.loads(parts[1])
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(ev, dict):
            continue
        name = ev.get("event")
        if name == "start":
            started = True
        elif name == "end":
            ended = True
        if name != "interval":
            continue
        data = ev.get("data") or {}
        summ = data.get("sum") or {}
        if summ.get("omitted"):
            continue
        streams: Dict[int, float] = {}
        span = None
        for s in data.get("streams", []):
            try:
                streams[int(s.get("socket", s.get("id")))] = float(s["bits_per_second"])
                span = (float(s["start"]), float(s["end"]))
            except (KeyError, TypeError, ValueError):
                continue
        try:
            span = (float(summ["start"]), float(summ["end"]))
            sum_bps = float(summ["bits_per_second"])
        except (KeyError, TypeError, ValueError):
            sum_bps = sum(streams.values())
        if span is None:
            continue
        raw.append((arrival, span[0], span[1], streams, sum_bps))
    if not raw:
        return [], started, ended
    anchor = statistics.median(a - e for a, _, e, _, _ in raw)
    return [(anchor + s, anchor + e, st, sb) for _, s, e, st, sb in raw], started, ended


def stream_stalls(intervals, low_bps: float) -> Tuple[List[StreamRun], List[StreamRun]]:
    """Runs of consecutive intervals under `low_bps`, per stream and aggregate.

    A stream absent from an interval it was present in before counts as low
    (iperf3 omits nothing on its own, so an absent socket is a dead one).
    """
    per: List[StreamRun] = []
    agg: List[StreamRun] = []
    seen = set()
    open_runs: Dict[int, StreamRun] = {}
    agg_run: Optional[StreamRun] = None
    for start, end, streams, sum_bps in intervals:
        seen |= set(streams)
        dur = end - start
        for sid in sorted(seen):
            low = streams.get(sid, 0.0) < low_bps
            run = open_runs.get(sid)
            if low:
                if run is None:
                    open_runs[sid] = run = StreamRun(sid, start, 0.0)
                run.seconds += dur
            elif run is not None:
                per.append(run)
                del open_runs[sid]
        if sum_bps < low_bps:
            if agg_run is None:
                agg_run = StreamRun(-1, start, 0.0)
            agg_run.seconds += dur
        elif agg_run is not None:
            agg.append(agg_run)
            agg_run = None
    for run in open_runs.values():
        run.to_end = True
        per.append(run)
    if agg_run is not None:
        agg_run.to_end = True
        agg.append(agg_run)
    return per, agg



def iperf_error(text: str) -> Optional[str]:
    """The first `error` event's text in an arrival-stamped json-stream log."""
    for line in (text or "").splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        try:
            ev = json.loads(parts[1])
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(ev, dict) and ev.get("event") == "error":
            return str(ev.get("data"))[:200]
    return None


# ---------------------------------------------------------------------------
# Per-move verdict
# ---------------------------------------------------------------------------

FAMILIES = ("v4", "v6")


@dataclass
class Budget:
    converge_s: float = 5.0
    max_gap_ms: float = 1000.0
    max_stall_ms: float = 2000.0
    tail_s: float = 1.0
    low_bps: float = 1_000_000.0
    # traffic-follow: the target node's RETH members must carry at least
    # follow_min_pkts between landing and the window's end, and the other
    # node's at most follow_max_other_ratio of that.
    follow_min_pkts: int = 500
    follow_max_other_ratio: float = 0.10
    # A recovered single-stream stall is COST only up to this; beyond it the
    # move FAILs however it recovered (seat AF: COST needs an upper bound).
    max_cost_stall_ms: float = 10000.0
    # SOAK_EXPECT_TRANSFER=1 (#18559): the build under test runs the
    # untargeted form on the owner as a transfer, so a plain "triggered"
    # local-resign reply on an away-move is a FAIL.
    expect_transfer: bool = False
    # #19050 (R14-1): the new WAN owner's host-originated routed lag over
    # this is a COST. Master measured 544-1184 ms (udp/loss); the #19050
    # activation-fix prototypes measured 0-28 ms (D1, dropped) and 0-4.5 ms
    # (the B spike), so the default separates the two.
    max_host4_lag_ms: float = 250.0


@dataclass
class RGMoveResult:
    rg: int
    target: int
    pre_owner: Optional[int]
    pre_detail: str
    cli_class: str
    cli_first: str
    cli_rc: int
    cli_seconds: float
    landed_s: Optional[float]  # seconds from issue until both views agreed, None if never
    last_detail: str
    dual_active: bool  # a sample in which both nodes claimed the RG (#19041: target read first)
    helper: Optional[Dict[int, Optional[bool]]] = None  # node -> helper rg active, at landing
    reverted: str = ""  # non-empty: the joint view left the target after landing, in-window
    # Traffic-follow evidence, read after landing and at the window's end:
    # RETH-member packet deltas per node, and which node the LAN host's
    # neighbour entry for the LAN VIP resolves to.
    member_delta: Optional[Dict[int, Optional[int]]] = None
    neigh_node: Optional[Dict[str, Optional[int]]] = None
    follow_expected: bool = False  # the RG has RETH members to measure
    # #19041: dual-active samples seen in the move's window (each one FAILs
    # the move), and the first one's reading, with the read order.
    dual_samples: int = 0
    dual_detail: str = ""


@dataclass
class MoveRecord:
    index: int
    target: int
    issuer: int
    t_issue_lan: float
    t_next_lan: float
    rgs: List[RGMoveResult]
    traffic: Optional[Dict[str, Dict]] = None  # family -> facts
    udp_probe: Optional[Dict] = None  # per-CLI sequence + firewall Session ID verdicts
    # #19050: routed-destination probes (name -> facts, LAN clock) and the
    # host-originated route lag on the move's target (its own clock).
    routed: Optional[Dict[str, Dict]] = None
    host4: Optional[Dict] = None
    verdict: str = ""
    reasons: List[str] = field(default_factory=list)


def traffic_for_window(t0: float, t1: float, gaps: List[PingGap], replies: List[Tuple[float, int]],
                       stalls: List[StreamRun], agg: List[StreamRun], intervals,
                       budget: Budget) -> Dict:
    """The traffic facts for one family in one move window [t0, t1) on the LAN clock."""
    win_gaps = [g for g in gaps if t0 <= g.start < t1]
    lost = sum(g.lost for g in win_gaps)
    max_gap = max((g.end - g.start for g in win_gaps), default=None)
    tail0 = max(t0, t1 - budget.tail_s)
    tail_replies = sum(1 for ts, _ in replies if tail0 <= ts < t1)
    win_stalls = [s for s in stalls if t0 <= s.start < t1]
    worst = max(win_stalls, key=lambda s: s.seconds, default=None)
    died = sorted({s.stream for s in win_stalls if s.to_end})
    # Every stream whose stall in this window exceeds the per-stream budget:
    # COST is ONE stream backing off, never several (seat AF).
    over = sorted({s.stream for s in win_stalls if s.seconds * 1000.0 > budget.max_stall_ms})
    win_agg = [s for s in agg if t0 <= s.start < t1]
    agg_zero = sum(s.seconds for s in win_agg)
    agg_worst = max((s.seconds for s in win_agg), default=0.0)
    tail_iv = [iv for iv in intervals if iv[0] >= tail0 and iv[1] <= t1 + 1e-6]
    tail_bps = statistics.mean(iv[3] for iv in tail_iv) if tail_iv else None
    covered_ping = bool(replies) and replies[0][0] <= t0 and replies[-1][0] >= tail0
    covered_iperf = bool(intervals) and intervals[0][0] <= t0 + 0.2 and intervals[-1][1] >= tail0
    return {
        "ping_lost": lost,
        "ping_max_gap_ms": None if max_gap is None else round(max_gap * 1000.0, 1),
        "ping_tail_replies": tail_replies,
        "worst_stall_ms": 0.0 if worst is None else round(worst.seconds * 1000.0, 1),
        "worst_stall_stream": None if worst is None else worst.stream,
        "died_streams": died,
        "stalled_streams": over,
        "agg_zero_ms": round(agg_zero * 1000.0, 1),
        "agg_worst_ms": round(agg_worst * 1000.0, 1),
        "tail_gbps": None if tail_bps is None else round(tail_bps / 1e9, 2),
        "ping_covered": covered_ping,
        "iperf_covered": covered_iperf,
    }


# ---------------------------------------------------------------------------
# #19050: routed-destination and host-originated probes
# ---------------------------------------------------------------------------

@dataclass
class RoutedProbe:
    """A LAN-host ping to a destination NO connected subnet covers.

    The connected-target ping above measures the path to a WAN subnet the
    firewall is attached to. Most real traffic is ROUTED: it leaves through
    the default route (or another static) to a next hop. After an RG move
    the new WAN owner's FRR-rendered default lags its connected prefixes by
    1.4-4.8 s on loss (#19050), so a probe that never leaves a connected
    subnet cannot see whether routed traffic paid for that lag.

    gap_fails: a ping gap over SOAK_MAX_GAP_MS FAILs the move, as the
    connected ping does. False for a destination beyond the lab (the public
    resolver, an external router), whose path has losses the cluster did
    not cause: there the gap is a COST, judged master-relative, and only
    "no replies in the window's tail" (routed traffic did not resume) FAILs.
    """
    name: str
    target: str
    family: str  # "v4" | "v6"
    interval_s: float = 0.01
    gap_fails: bool = True


def routed_for_window(t0: float, t1: float, gaps: List[PingGap], replies: List[Tuple[float, int]],
                      budget: Budget) -> Dict:
    """One routed probe's ping facts for one move window [t0, t1), LAN clock."""
    t = traffic_for_window(t0, t1, gaps, replies, [], [], [], budget)
    return {k: t[k] for k in ("ping_lost", "ping_max_gap_ms", "ping_tail_replies", "ping_covered")}


def routed_reasons(routed: Optional[Dict[str, Dict]], budget: Budget) -> Tuple[List[str], List[str]]:
    """(FAIL reasons, COST reasons) from one move's routed-probe facts. A
    probe VOIDed by its baseline control contributes nothing here: the run
    already exits 2 for it (it is a disabled check, never a PASS)."""
    reasons: List[str] = []
    costs: List[str] = []
    for name, t in sorted((routed or {}).items()):
        if t.get("void"):
            continue
        what = f"routed {name} ({t.get('target')})"
        if not t.get("ping_covered", False):
            reasons.append(f"{what} ping did not cover the move window (ping died or never started)")
            continue
        if t.get("ping_tail_replies", 0) == 0:
            reasons.append(f"routed traffic did not resume: no {what} replies in the last {budget.tail_s:g}s of the window")
        gap = t.get("ping_max_gap_ms")
        if gap is not None and gap > budget.max_gap_ms:
            msg = f"{what} ping gap {gap:g} ms > {budget.max_gap_ms:g} ms ({t.get('ping_lost')} lost)"
            if t.get("gap_fails", True):
                reasons.append(msg)
            else:
                costs.append(msg + " (off-lab path: COST, judged master-relative)")
    return reasons, costs


_HOST_REPLY = re.compile(r"^\[(\d+\.\d+)\] \d+ bytes from ")


def parse_host_ping(text: str) -> List[float]:
    """Reply timestamps from a node-side `ping -D` loop. The loop restarts
    ping whenever it exits (a route that blackholes makes ping fail at
    connect() and exit), so sequence numbers restart and error lines are
    interleaved; only the reply timestamps matter here."""
    out = []
    for line in text.splitlines():
        m = _HOST_REPLY.match(line)
        if m:
            out.append(float(m.group(1)))
    out.sort()
    return out


def host_route_lag(anchor: List[float], routed: List[float], t0: float, t1: float,
                   pre_s: float = 1.0) -> Dict:
    """The new WAN owner's own routed-path delay for one move, on ITS clock.

    `anchor` is the node's ping to its connected WAN gateway, `routed` its
    ping to a destination reached only via the default route. A standby
    reaches neither (it holds no WAN address, and its default is the cluster
    Null0). After the move hands it the WAN RG, the connected route lands with
    the address; the routed one waits for the default (#19050). The lag
    between the two first replies is the routed window host-originated
    traffic sees, and needs no cross-node clock: both stamps are the node's.
    t0/t1 bound the search only (mapped onto the node's clock by the
    measured offset; `pre_s` absorbs its error)."""
    if any(t0 - pre_s <= x < t0 for x in anchor):
        return {"status": "N/A", "detail": "the target already reached its WAN gateway before the move "
                                          "(it already owned the WAN RG)"}
    a = next((x for x in anchor if t0 <= x < t1), None)
    if a is None:
        return {"status": "N/A", "detail": "the target never reached its WAN gateway in the window "
                                          "(this move did not hand it the WAN RG)"}
    r = next((x for x in routed if t0 <= x < t1), None)
    out = {"status": "MEASURED", "anchor_s": round(a - t0, 3)}
    if r is None:
        out.update(routed_s=None, lag_ms=None,
                   detail="no routed reply before the window ended: host-originated routed traffic "
                          "had no usable default for the rest of the window")
        return out
    out.update(routed_s=round(r - t0, 3), lag_ms=round(max(0.0, r - a) * 1000.0, 1))
    return out


# A routed reply this far ahead of the gateway reply is a leak, not ping
# phase: both loops run at 10 ms, and a node that gains its address and its
# default together answers both within a few intervals (the #19050
# activation-fix prototypes: 0-28 ms).
HOST4_LEAK_GRACE_S = 0.25


def host4_move(anchor_t: List[float], routed_t: List[float], t0_t: float, t1_t: float,
               anchor_o: List[float], routed_o: List[float], t0_o: float, t1_o: float,
               pre_s: float = 1.0, tail_s: float = 1.0) -> Dict:
    """#19050 (R4 F2): the host-originated facts for one move. `_t` is the
    move's target node and `_o` the other node, each on its own clock.

    A node that does not hold the WAN address must not reach a routed
    destination: its only default is the cluster Null0. A routed reply from
    one means some other route resolved its default (R4 F1): LEAK, which
    FAILs the move. Checked for the target before its gateway first answers,
    and for the old owner after its gateway stops answering. A move that
    took the WAN off the other node but whose target never reached its
    gateway is VOID: the window has no evidence either way."""
    out = host_route_lag(anchor_t, routed_t, t0_t, t1_t, pre_s)
    if out["status"] == "MEASURED":
        a = t0_t + out["anchor_s"]
        early = next((x for x in routed_t if t0_t <= x < a - HOST4_LEAK_GRACE_S), None)
        if early is not None:
            return {"status": "LEAK", "anchor_s": out["anchor_s"], "routed_s": round(early - t0_t, 3),
                    "detail": f"the new owner got a routed reply {a - early:.2f}s before its WAN gateway answered: "
                              "it had a usable default before it held the WAN address"}
    owned_before = any(t0_o - pre_s <= x < t0_o for x in anchor_o)
    in_window = [x for x in anchor_o if t0_o - pre_s <= x < t1_o]
    lost = owned_before and not any(t1_o - tail_s <= x < t1_o for x in anchor_o)
    if lost:
        last = max(in_window)
        late = next((x for x in routed_o if last + HOST4_LEAK_GRACE_S < x < t1_o), None)
        if late is not None:
            return {"status": "LEAK", "routed_s": round(late - t0_o, 3),
                    "detail": f"the old owner got a routed reply {late - last:.2f}s after its WAN gateway stopped "
                              "answering: it kept a usable default after losing the WAN address"}
        if out["status"] == "N/A" and "never reached" in out.get("detail", ""):
            return {"status": "VOID", "detail": "the WAN left the other node but the target never reached its WAN "
                                                "gateway in the window: no host-originated evidence for this move"}
    return out


def follow_reasons(r: RGMoveResult, budget: Budget) -> List[str]:
    """Did the TRAFFIC move with the RG? Status and helper views say who
    should forward; these readings say who did (#18587 review B1)."""
    out: List[str] = []
    other = 1 - r.target
    if r.follow_expected:
        d = r.member_delta or {}
        tgt, oth = d.get(r.target), d.get(other)
        if tgt is None or oth is None:
            out.append(f"RG{r.rg} traffic-follow unmeasured: helper per-interface counters unreadable (node{r.target}={tgt} node{other}={oth})")
        elif tgt < budget.follow_min_pkts or oth > max(budget.follow_max_other_ratio * tgt, budget.follow_min_pkts / 10):
            out.append(f"RG{r.rg} traffic did not follow to node{r.target}: RETH-member packets after landing "
                       f"node{r.target}={tgt} node{other}={oth}")
    for fam, node in (r.neigh_node or {}).items():
        if node is None:
            # The preflight proved the entry resolvable; losing it mid-run
            # means the follow check could not read this move (seat AF).
            out.append(f"RG{r.rg} traffic-follow unmeasured: the LAN host's {fam} neighbour entry "
                       "resolves to no RETH MAC this move")
        elif node != r.target:
            out.append(f"RG{r.rg} traffic did not follow to node{r.target}: the LAN host's {fam} neighbour entry "
                       f"for the LAN VIP still resolves to node{node}'s MAC")
    return out


def move_verdict(rec: MoveRecord, budget: Budget, traffic_enabled: bool) -> Tuple[str, List[str]]:
    """Score one move.

    VOID (precondition) dominates. Then every correctness FAIL reason. COST is
    narrow (seat AF): ONE stream's stall over budget, from which it
    recovered, while ping and the aggregate stayed within budget — #18559's
    TCP-backoff cost, judged master-relative like row H10. A ping gap or an
    aggregate (all-stream) outage over budget is a FAIL: that is the traffic
    stopping, not a cost. So is a stall past max_cost_stall_ms, or a stream
    that never recovers.

    The precondition is the state observed at the end of the previous move's
    window (or the preflight), so it costs no extra reads and is the same
    evidence the previous verdict was built from.
    """
    reasons: List[str] = []
    udp_void_reason: Optional[str] = None
    for r in rec.rgs:
        if r.pre_owner != 1 - r.target:
            where = "unowned/unreadable" if r.pre_owner is None else f"on node{r.pre_owner}"
            reasons.append(f"precondition: RG{r.rg} was {where} before a move to node{r.target} ({r.pre_detail})")
    if reasons:
        return VOID, reasons
    if rec.udp_probe is not None:
        probe_status = rec.udp_probe.get("status")
        probe_detail = rec.udp_probe.get("detail", "UDP probe verdict has no detail")
        if probe_status == "VOID":
            udp_void_reason = probe_detail
        elif probe_status in ("RECREATED", "LOST"):
            reasons.append(probe_detail)
        elif probe_status != "SURVIVED":
            return VOID, [f"unknown UDP probe status {probe_status!r}: {probe_detail}"]
    costs: List[str] = []
    fallback_void: List[str] = []
    for r in rec.rgs:
        if r.cli_class == CLI_FALLBACK:
            fallback_void.append(f"RG{r.rg} untargeted move did not run the transfer ('{r.cli_first}'); "
                                 "the make-before-break path was not exercised")
        elif r.cli_class == CLI_TRIGGERED and budget.expect_transfer:
            reasons.append(f"RG{r.rg} untargeted move resigned locally ('{r.cli_first}') on a build expected to "
                           "run the transfer (SOAK_EXPECT_TRANSFER=1)")
    for r in rec.rgs:
        other = 1 - r.target
        if r.cli_class == CLI_ERROR:
            hint = cli_error_hint(r.cli_first)
            reasons.append(f"RG{r.rg} CLI error: {r.cli_first}" + (f" [{hint}]" if hint else ""))
        elif r.cli_class == CLI_ALREADY:
            reasons.append(f"RG{r.rg} CLI said already primary ('{r.cli_first}') but the RG was on node{other}")
        elif r.cli_class == CLI_OTHER:
            reasons.append(f"RG{r.rg} unexpected CLI output: {r.cli_first}")
        if r.dual_active:
            reasons.append(f"RG{r.rg} dual-active: both nodes claimed it in one sample during the move window "
                           f"({r.dual_detail or 'no detail'}; {r.dual_samples} such sample(s))")
        if r.landed_s is None:
            reasons.append(f"RG{r.rg} did not land on node{r.target} within {budget.converge_s:g}s of the CLI returning (last: {r.last_detail})")
            continue
        # The landing is credited when the sample that saw it finished,
        # which can be past the bound (#19041).
        after_cli = r.landed_s - r.cli_seconds
        if after_cli > budget.converge_s + 1e-3:
            reasons.append(f"RG{r.rg} landed on node{r.target} {after_cli:.2f}s after the CLI returned, "
                           f"past the {budget.converge_s:g}s bound")
        if r.reverted:
            reasons.append(f"RG{r.rg} left node{r.target} after landing, inside the window ({r.reverted})")
        if r.helper is not None:
            want = {r.target: True, other: False}
            bad = [f"node{n}={'unreadable' if r.helper.get(n) is None else r.helper.get(n)}"
                   for n in (0, 1) if r.helper.get(n) is not want[n]]
            if bad:
                reasons.append(f"RG{r.rg} helper ha_groups[].forwarding_active disagrees with status (want node{r.target}=True): {' '.join(bad)}")
        if traffic_enabled:
            reasons.extend(follow_reasons(r, budget))
    if traffic_enabled:
        for fam, t in sorted((rec.traffic or {}).items()):
            if not t.get("ping_covered", False):
                reasons.append(f"{fam} ping did not cover the move window (ping died or never started)")
            if not t.get("iperf_covered", False):
                reasons.append(f"{fam} iperf3 did not cover the move window (streams died or the client exited)")
            if t.get("died_streams"):
                reasons.append(f"{fam} stream(s) {t['died_streams']} stalled in this window and never recovered")
            if t.get("ping_covered") and t.get("ping_tail_replies", 0) == 0:
                reasons.append(f"traffic did not follow: no {fam} ping replies in the last {budget.tail_s:g}s of the window")
            if t.get("iperf_covered") and (t.get("tail_gbps") or 0.0) * 1e9 < budget.low_bps:
                reasons.append(f"traffic did not follow: {fam} iperf3 aggregate under {budget.low_bps / 1e6:g} Mbit/s in the window tail")
            gap = t.get("ping_max_gap_ms")
            if gap is not None and gap > budget.max_gap_ms:
                reasons.append(f"{fam} ping gap {gap:g} ms > {budget.max_gap_ms:g} ms ({t.get('ping_lost')} lost)")
            agg_worst = t.get("agg_worst_ms") or 0.0
            if agg_worst > budget.max_gap_ms:
                reasons.append(f"{fam} aggregate outage: every stream under {budget.low_bps / 1e6:g} Mbit/s for {agg_worst:g} ms > {budget.max_gap_ms:g} ms")
            stall = t.get("worst_stall_ms") or 0.0
            over = t.get("stalled_streams") or []
            if len(over) > 1 and not t.get("died_streams"):
                reasons.append(f"{fam} {len(over)} streams {over} stalled over {budget.max_stall_ms:g} ms in this window "
                               "(COST is one stream backing off, not several)")
            elif stall > budget.max_cost_stall_ms and not t.get("died_streams"):
                reasons.append(f"{fam} stream {t.get('worst_stall_stream')} stalled {stall:g} ms > {budget.max_cost_stall_ms:g} ms (past the COST cap)")
            elif stall > budget.max_stall_ms and not t.get("died_streams"):
                costs.append(f"{fam} stream {t.get('worst_stall_stream')} stalled {stall:g} ms > {budget.max_stall_ms:g} ms (recovered; ping and aggregate within budget)")
        r_reasons, r_costs = routed_reasons(rec.routed, budget)
        reasons.extend(r_reasons)
        costs.extend(r_costs)
    # #19050: a routed probe whose baseline control failed has no evidence
    # for this move. Like a VOID UDP probe, it never lets the move PASS.
    routed_void = [f"routed probe {n} VOID: {t['void']}" for n, t in sorted((rec.routed or {}).items())
                   if t.get("void")] if traffic_enabled else []
    # #19050 (R14-1, R4 F2): host4 is scored, not reported.
    h4 = (rec.host4 or {}) if traffic_enabled else {}
    h4_status = h4.get("status")
    if h4_status == "LEAK":
        reasons.append(f"host4 routed reply from a node without the WAN address: {h4.get('detail')}")
    elif h4_status == "MEASURED" and h4.get("lag_ms") is None:
        reasons.append("host4: the new WAN owner got no routed reply in the window (its kernel default never "
                       "became usable)")
    elif h4_status == "MEASURED" and h4["lag_ms"] > budget.max_host4_lag_ms:
        costs.append(f"host4 routed lag {h4['lag_ms']:g} ms > {budget.max_host4_lag_ms:g} ms on the new WAN owner")
    if h4_status == "VOID":
        routed_void.append(f"host4 VOID: {h4.get('detail')}")
    if reasons:
        if udp_void_reason:
            reasons.append(f"UDP probe evidence VOID: {udp_void_reason}")
        reasons.extend(f"VOID evidence: {f}" for f in fallback_void + routed_void)
        return FAIL, reasons + costs
    if udp_void_reason or fallback_void or routed_void:
        return VOID, fallback_void + ([udp_void_reason] if udp_void_reason else []) + routed_void
    if costs:
        return COST, costs
    return PASS, []


def _dist(vals: List[float]) -> Optional[Dict]:
    if not vals:
        return None
    return {"median": statistics.median(vals), "p95": sorted(vals)[int(0.95 * (len(vals) - 1))], "max": max(vals)}


def format_routed_table(moves: List[MoveRecord]) -> Optional[str]:
    """#19050: one line per move for the routed and host-originated probes,
    or None when neither ran."""
    names = sorted({n for m in moves for n in (m.routed or {})})
    if not names and not any(m.host4 for m in moves):
        return None
    hdr = f"{'#':>4} {'to':>3}" + "".join(f" {n + ' gap':>10}" for n in names) + f" {'host4 lag_ms':>13}"
    lines = ["routed probes (#19050):", hdr]
    for m in moves:
        row = f"{m.index:>4} {m.target:>3}"
        for n in names:
            t = (m.routed or {}).get(n, {})
            g = t.get("ping_max_gap_ms")
            row += f" {('VOID' if t.get('void') else '-' if g is None else f'{g:.0f}'):>10}"
        h = m.host4 or {}
        if h.get("status") == "MEASURED":
            cell = "none" if h.get("lag_ms") is None else f"{h['lag_ms']:.0f}"
        else:
            cell = h.get("status", "-")
        row += f" {cell:>13}"
        lines.append(row)
    return "\n".join(lines)


def summarize(moves: List[MoveRecord], traffic_enabled: bool, disabled: List[str], strict_cost: bool) -> Dict:
    counts = {PASS: 0, COST: 0, FAIL: 0, VOID: 0}
    for m in moves:
        counts[m.verdict] = counts.get(m.verdict, 0) + 1
    by_dir: Dict[str, Dict[str, int]] = {}
    for m in moves:
        d = by_dir.setdefault(f"to node{m.target}", {PASS: 0, COST: 0, FAIL: 0, VOID: 0})
        d[m.verdict] += 1
    cli_classes: Dict[str, int] = {}
    for m in moves:
        for r in m.rgs:
            cli_classes[r.cli_class] = cli_classes.get(r.cli_class, 0) + 1
    out: Dict = {"moves": len(moves), "counts": counts, "by_direction": by_dir, "disabled_checks": disabled,
                 # #18559: reply types (ok = transfer committed, triggered =
                 # pre-#18559 local resign, fallback = post-#18559 local
                 # resign that did not run the transfer).
                 "cli_classes": cli_classes}
    scored = [m for m in moves if m.verdict != VOID]
    landed = [r.landed_s for m in scored for r in m.rgs if r.landed_s is not None]
    clis = [r.cli_seconds for m in scored for r in m.rgs]
    if landed:
        out["landed_s"] = {"median": round(statistics.median(landed), 2), "max": round(max(landed), 2)}
    if clis:
        out["cli_s"] = {"median": round(statistics.median(clis), 2), "max": round(max(clis), 2)}
    if traffic_enabled and scored:
        for fam in FAMILIES:
            fams = [m.traffic[fam] for m in scored if m.traffic and fam in m.traffic]
            if not fams:
                continue

            def dist(key):
                vals = [t.get(key) for t in fams if t.get(key) is not None]
                if not vals:
                    return None
                return {"median": statistics.median(vals), "p95": sorted(vals)[int(0.95 * (len(vals) - 1))], "max": max(vals)}
            out[fam] = {k: dist(k) for k in ("ping_lost", "ping_max_gap_ms", "worst_stall_ms")}
        # #19050: routed-destination probes, per probe name.
        names = sorted({n for m in scored for n in (m.routed or {})})
        for name in names:
            rows = [m.routed[name] for m in scored if m.routed and name in m.routed and not m.routed[name].get("void")]
            gaps = [t["ping_max_gap_ms"] for t in rows if t.get("ping_max_gap_ms") is not None]
            lost = [t["ping_lost"] for t in rows if t.get("ping_lost") is not None]
            out.setdefault("routed", {})[name] = {
                "ping_max_gap_ms": _dist(gaps), "ping_lost": _dist(lost), "moves": len(rows)}
        host = [m.host4 for m in scored if m.host4]
        if host:
            measured = [h for h in host if h.get("status") == "MEASURED"]
            lags = [h["lag_ms"] for h in measured if h.get("lag_ms") is not None]
            out["host4"] = {"measured": len(measured),
                            "no_routed_reply": sum(1 for h in measured if h.get("lag_ms") is None),
                            "not_applicable": sum(1 for h in host if h.get("status") == "N/A"),
                            "leak": sum(1 for h in host if h.get("status") == "LEAK"),
                            "void": sum(1 for h in host if h.get("status") == "VOID"),
                            "lag_ms": _dist(lags)}
    reasons: Dict[str, int] = {}
    for m in moves:
        for r in m.reasons:
            key = re.sub(r"\d+(\.\d+)?", "N", r.split(":")[0] if r.startswith("precondition") else r)[:110]
            reasons[key] = reasons.get(key, 0) + 1
    out["reason_classes"] = dict(sorted(reasons.items(), key=lambda kv: -kv[1]))
    # #19041: dual-active samples seen (every one FAILs its move).
    out["dual_samples"] = sum(r.dual_samples for m in moves for r in m.rgs)
    if counts[FAIL] or (strict_cost and counts[COST]):
        out["exit"] = 1
    elif counts[VOID] or disabled:
        out["exit"] = 2
    else:
        out["exit"] = 0
    return out


def format_table(moves: List[MoveRecord], traffic_enabled: bool) -> str:
    hdr = f"{'#':>4} {'to':>3} {'rg':>5} {'cli':>8} {'cli_s':>6} {'land_s':>6}"
    if traffic_enabled:
        hdr += f" {'lost':>5} {'gap_ms':>7} {'stall_ms':>8} {'tail_G':>6} {'v6lost':>6} {'v6gap':>6} {'udp':>10}"
    hdr += "  verdict  reason"
    lines = [hdr]
    for m in moves:
        rg = ",".join(str(r.rg) for r in m.rgs)
        cli = ",".join(r.cli_class for r in m.rgs)
        cli_s = max((r.cli_seconds for r in m.rgs), default=0.0)
        land = [r.landed_s for r in m.rgs]
        land_s = "-" if any(x is None for x in land) else f"{max(land):.2f}"
        row = f"{m.index:>4} {m.target:>3} {rg:>5} {cli:>8} {cli_s:>6.2f} {land_s:>6}"
        if traffic_enabled:
            t = (m.traffic or {}).get("v4", {})
            t6 = (m.traffic or {}).get("v6", {})
            gap = t.get("ping_max_gap_ms")
            gap6 = t6.get("ping_max_gap_ms")
            row += (f" {t.get('ping_lost', '-'):>5} {('-' if gap is None else f'{gap:.0f}'):>7}"
                    f" {t.get('worst_stall_ms', 0):>8.0f} {('-' if t.get('tail_gbps') is None else t['tail_gbps']):>6}"
                    f" {t6.get('ping_lost', '-'):>6} {('-' if gap6 is None else f'{gap6:.0f}'):>6}")
            udp_status = (m.udp_probe or {}).get("status", "-")
            row += f" {udp_status:>10}"
        row += f"  {m.verdict:<7}  {m.reasons[0] if m.reasons else ''}"
        lines.append(row)
        for extra in m.reasons[1:]:
            lines.append(" " * 9 + "+ " + extra)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Live cluster access
# ---------------------------------------------------------------------------

def helper_summary(r):
    """Reduce the helper's `status` reply to what the soak scores. Runs ON the
    firewall (shipped as HELPER_SNIPPET) and hermetically in the cells.

    `ha`: forwarding_active per RG, not active — the helper forwards on
    active AND an unexpired lease (userspace-dp runtime.rs), exported as
    forwarding_active; an older helper without it falls back to active.
    `if`: RX+TX packets per interface summed over queues; the binding key is
    `interface` (an `ifname` fallback is kept for other builds)."""
    st = r.get("status", r)
    ifs = {}
    for b in st.get("bindings", []):
        n = b.get("interface") or b.get("ifname")
        if n:
            ifs[n] = ifs.get(n, 0) + int(b.get("rx_packets") or 0) + int(b.get("tx_packets") or 0)
    return {"ha": {str(g.get("rg_id")): bool(g.get("forwarding_active", g.get("active")))
                   for g in st.get("ha_groups", [])}, "if": ifs}


HELPER_SNIPPET = "import json, socket\n" + inspect.getsource(helper_summary) + r"""
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect("/run/xpf/userspace-dp.sock")
s.sendall(json.dumps({"type": "status"}).encode() + b"\n")
buf = b""
while True:
    d = s.recv(1 << 20)
    if not d:
        break
    buf += d
    try:
        r = json.loads(buf)
        break
    except ValueError:
        pass
print(json.dumps(helper_summary(r)))
"""

_SET_MEMBER = re.compile(r"^set (?:groups \S+ )?interfaces (\S+) gigether-options redundant-parent (reth\d+)\s*$")
_SET_RETH_RG = re.compile(r"^set (?:groups \S+ )?interfaces (reth\d+) redundant-ether-options redundancy-group (\d+)\s*$")
_LINK_MAC = re.compile(r"^\d+:\s+([^:@\s]+)[@:].*link/ether ([0-9a-f:]{17})")
_NEIGH_MAC = re.compile(r"lladdr ([0-9a-f:]{17})")


def rg_members(config_set: str) -> Dict[int, List[str]]:
    """{rg: [Linux member names]} from `show configuration | display set`."""
    reth_rg = {}
    members: Dict[str, List[str]] = {}
    for line in (config_set or "").splitlines():
        m = _SET_RETH_RG.match(line.strip())
        if m:
            reth_rg[m.group(1)] = int(m.group(2))
            continue
        m = _SET_MEMBER.match(line.strip())
        if m:
            members.setdefault(m.group(2), []).append(m.group(1).replace("/", "-"))
    out: Dict[int, List[str]] = {}
    for reth, rg in reth_rg.items():
        # An RG with a RETH but no members found keeps an EMPTY list, so the
        # caller can tell "nothing to measure" from "could not measure".
        out.setdefault(rg, []).extend(sorted(set(members.get(reth, []))))
    return out


def link_macs(ip_o_link: str) -> Dict[str, str]:
    """{mac: ifname} from `ip -o link`."""
    out: Dict[str, str] = {}
    for line in (ip_o_link or "").splitlines():
        m = _LINK_MAC.match(line)
        if m and m.group(2) != "00:00:00:00:00:00":
            out.setdefault(m.group(2), m.group(1))
    return out


_DEFAULT_VIA = re.compile(r"^default (?:nhid \d+ )?via (\S+) dev (\S+)", re.M)


def parse_default_route(text: str) -> Optional[Tuple[str, str]]:
    m = _DEFAULT_VIA.search(text or "")
    return (m.group(1), m.group(2)) if m else None


def neigh_mac(text: str) -> Optional[str]:
    m = _NEIGH_MAC.search(text or "")
    return m.group(1) if m else None


def host_ping_loop(rid: str, kind: str, dst: str, duration_s: int) -> str:
    """#19050: a node-side `ping -D` that survives a blackholed route. ping
    exits at connect() when the route is a blackhole (the standby's cluster
    Null0 default), so the loop restarts it every 50 ms until the deadline;
    the first reply after a move is what host_route_lag reads."""
    d = shlex.quote(dst)
    return (f"echo $$ > /tmp/r-soak-{rid}.host{kind}.pid; end=$(( $(date +%s) + {int(duration_s)} ));"
            f" while [ $(date +%s) -lt $end ]; do"
            f" ping -4 -D -i 0.01 -W 1 -w $(( end - $(date +%s) )) {d} 2>&1; sleep 0.05; done")


def host_ping_stop(rid: str) -> str:
    return (f"for p in /tmp/r-soak-{rid}.host*.pid; do [ -f $p ] || continue;"
            f" pkill -INT -P $(cat $p) 2>/dev/null; kill $(cat $p) 2>/dev/null; done; sleep 1;"
            f" rm -f /tmp/r-soak-{rid}.host*.pid")


class IncusCluster:
    """Talks to the live cluster through `incus exec` only."""

    def __init__(self, fw: Dict[int, str], lan: str, mouse_target: str, timeout: float = 30.0):
        self.fw = fw
        self.lan = lan
        self.mouse_target = mouse_target
        self.timeout = timeout

    def _exec(self, ref: str, argv: List[str], timeout: Optional[float] = None) -> Tuple[int, str]:
        try:
            p = subprocess.run(["incus", "exec", ref, "--"] + argv, capture_output=True, text=True,
                               timeout=timeout or self.timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return 124, f"error: incus exec {ref} timed out"

    def _socket_rows(self, port: int, state: str, listening: bool = False) -> Tuple[Optional[List[str]], str]:
        flags = "-Htnl" if listening else "-Htn"
        rc, out = self._exec(self.mouse_target, [
            "sh", "-c", f"ss {flags} state {state} '( sport = :{port} )'"
        ], timeout=10)
        if rc != 0:
            return None, out.strip() or f"ss exited {rc}"
        return [line for line in out.splitlines() if line.strip()], ""

    def prepare_iperf(self, ports: List[int], timeout: float = 10.0) -> Optional[str]:
        """Reset only mouse iperf servers holding stale client sockets."""
        stale = {}
        for port in sorted(set(ports)):
            rows, error = self._socket_rows(port, "established")
            if rows is None:
                return f"cannot inspect ESTABLISHED sockets on {self.mouse_target}:{port}: {error}"
            if rows:
                stale[port] = len(rows)
        if not stale:
            return None

        for port, count in stale.items():
            unit = f"mouse-iperf3@{port}.service"
            rc, out = self._exec(self.mouse_target, ["systemctl", "restart", unit], timeout=10)
            if rc != 0:
                detail = out.strip() or f"systemctl exited {rc}"
                return f"could not restart {unit} after finding {count} ESTABLISHED sockets: {detail}"

        pending = set()
        deadline = time.monotonic() + timeout
        while True:
            pending.clear()
            # Recheck every reset port on every pass: a client may reconnect
            # to a listener that became ready while another port was draining.
            for port in sorted(stale):
                listeners, error = self._socket_rows(port, "listening", listening=True)
                if listeners is None:
                    return f"cannot verify LISTEN on {self.mouse_target}:{port} after reset: {error}"
                established, error = self._socket_rows(port, "established")
                if established is None:
                    return f"cannot verify zero ESTABLISHED sockets on {self.mouse_target}:{port}: {error}"
                if not listeners or established:
                    pending.add(port)
            if not pending:
                return None
            if time.monotonic() >= deadline:
                ports_text = ", ".join(str(port) for port in sorted(pending))
                return f"mouse iperf reset timed out waiting for LISTEN with zero ESTABLISHED sockets on port(s) {ports_text}"
            time.sleep(0.2)

    def cli(self, node: int, cmd: str) -> Tuple[int, str]:
        return self._exec(self.fw[node], ["cli", "-c", cmd])

    def status(self, node: int) -> str:
        return self._exec(self.fw[node], ["cli", "-c", "show chassis cluster status"])[1]

    def config_set(self, node: int) -> str:
        # The CLI has no top-level `show configuration | display set`; RETH
        # members live under groups node0/node1, the RETH->RG binding under
        # interfaces.
        return "\n".join(self._exec(self.fw[node], ["cli", "-c", f"show configuration {part} | display set"])[1]
                         for part in ("groups", "interfaces"))

    def links(self, node: int) -> str:
        return self._exec(self.fw[node], ["ip", "-o", "link"])[1]

    def helper(self, node: int) -> Optional[Dict]:
        rc, out = self._exec(self.fw[node], ["python3", "-c", HELPER_SNIPPET], timeout=15)
        if rc != 0:
            return None
        try:
            raw = json.loads(out.strip().splitlines()[-1])
            return {"ha": {int(k): v for k, v in raw.get("ha", {}).items()}, "if": raw.get("if", {})}
        except (ValueError, IndexError, AttributeError):
            return None

    def neigh(self, addr: str, dev: str = "") -> str:
        fam = "-6" if ":" in addr else "-4"
        return self._exec(self.lan, ["ip", fam, "neigh", "show", addr] + (["dev", dev] if dev else []), timeout=10)[1]

    def lan_v6_router(self) -> Optional[Tuple[str, str]]:
        """The LAN host's IPv6 default router (the RA link-local), which is
        what its IPv6 traffic actually uses — not the global LAN VIP."""
        return parse_default_route(self._exec(self.lan, ["ip", "-6", "route", "show", "default"], timeout=10)[1])

    def clock(self, ref: str) -> Optional[float]:
        rc, out = self._exec(ref, ["date", "+%s.%N"], timeout=10)
        try:
            return float(out.strip()) if rc == 0 else None
        except ValueError:
            return None

    def chrony(self, node: int) -> str:
        rc, out = self._exec(self.fw[node], ["sh", "-c", "chronyc -n tracking 2>&1 | grep -E 'Reference ID|Leap status|System time'"], timeout=10)
        return " | ".join(line.strip() for line in out.splitlines())

    def popen_lan(self, script: str, outfile: str):
        f = open(outfile, "w")
        return subprocess.Popen(["incus", "exec", self.lan, "--", "sh", "-c", script], stdout=f,
                                stderr=subprocess.STDOUT), f

    def lan_sh(self, script: str) -> Tuple[int, str]:
        return self._exec(self.lan, ["sh", "-c", script], timeout=20)

    def popen_node(self, node: int, script: str, outfile: str):
        """#19050: a long-running probe in a firewall node's default instance."""
        f = open(outfile, "w")
        return subprocess.Popen(["incus", "exec", self.fw[node], "--", "sh", "-c", script], stdout=f,
                                stderr=subprocess.STDOUT), f

    def node_sh(self, node: int, script: str) -> Tuple[int, str]:
        return self._exec(self.fw[node], ["sh", "-c", script], timeout=20)

    def _udp_probe_paths(self, run_id: str) -> Tuple[str, str, str]:
        root = f"/tmp/r-soak-{run_id}.udp"
        return root, f"{root}/udp_session_probe.py", f"{root}/probe.log"

    def udp_probe_start(self, run_id: str, target: str, port: int) -> Optional[str]:
        """Install and start the one-socket UDP sender on the LAN host."""
        root, script, _log = self._udp_probe_paths(run_id)
        source = os.path.join(os.path.dirname(__file__), "udp_session_probe.py")
        rc, out = self._exec(self.lan, ["mkdir", "-p", root])
        if rc != 0:
            return f"could not create UDP probe directory: {out.strip()}"
        try:
            copied = subprocess.run(["incus", "file", "push", source, f"{self.lan}{script}"],
                                    capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._exec(self.lan, ["rm", "-rf", root])
            return f"could not copy UDP probe runner to LAN host: {exc}"
        if copied.returncode != 0:
            self._exec(self.lan, ["rm", "-rf", root])
            return f"could not copy UDP probe runner to LAN host: {(copied.stderr or copied.stdout).strip()}"
        rc, out = self._exec(self.lan, ["python3", script, "start", "--target", target,
                                        "--port", str(port), "--run-id", run_id,
                                        "--logfile", f"{root}/probe.log",
                                        "--pidfile", f"{root}/probe.pid"])
        if rc != 0:
            self._exec(self.lan, ["rm", "-rf", root])
            return f"could not start UDP probe sender: {out.strip()}"
        return None

    def udp_probe_snapshot(self, run_id: str) -> Optional[str]:
        _root, _script, logfile = self._udp_probe_paths(run_id)
        rc, out = self._exec(self.lan, ["cat", logfile], timeout=10)
        return out if rc == 0 and out.strip() else None

    def udp_probe_session_id(self, node: int, probe_snapshot: str) -> Tuple[Optional[str], Optional[str]]:
        """Read the exact local UDP flow's stable dataplane Session ID.

        The query names the probe's tuple and an explicit limit (#19038). The
        bare `show security flow session` stops at 100 rows per node, in hash
        order, which hid the probe on whichever node hashed it late; the soak
        reported that as "absent on synced standby".
        """
        try:
            query = udp_session_probe.session_query_for_probe(probe_snapshot)
        except ValueError as exc:
            return None, f"could not build the flow-session query for node{node}: {exc}"
        rc, out = self._exec(self.fw[node], ["cli", "-c", query], timeout=20)
        if rc != 0:
            return None, f"could not capture flow sessions on node{node}: {out.strip()}"
        try:
            session_id = udp_session_probe.session_id_for_probe(probe_snapshot, out)
        except ValueError as exc:
            return None, f"could not parse flow-session capture on node{node}: {exc}"
        return session_id, None

    def udp_probe_stop(self, run_id: str) -> None:
        root, script, _log = self._udp_probe_paths(run_id)
        self._exec(self.lan, ["python3", script, "stop", "--pidfile", f"{root}/probe.pid"])
        self._exec(self.lan, ["rm", "-rf", root])


def measure_offset(clock_fn, ref: str, now_fn=time.time, samples: int = 5) -> Optional[Tuple[float, float]]:
    """NTP-style offset of `ref` against this host: (offset_s, rtt_s) of the
    minimum-RTT sample. Positive offset = `ref` is ahead."""
    best = None
    for _ in range(samples):
        a = now_fn()
        r = clock_fn(ref)
        b = now_fn()
        if r is None:
            continue
        cand = (r - (a + b) / 2.0, b - a)
        if best is None or cand[1] < best[1]:
            best = cand
    return best


# ---------------------------------------------------------------------------
# The soak
# ---------------------------------------------------------------------------


class VoidRun(Exception):
    """The run cannot measure what it claims to (a precondition or harness
    fault). Scored VOID, never FAIL."""


@dataclass
class Config:
    moves: int = 20
    sleep_s: float = 5.0
    rgs: str = "2"
    issuer: int = 0
    budget: Budget = field(default_factory=Budget)
    traffic: bool = True
    helper_check: bool = True
    strict_cost: bool = False
    restore: bool = True
    target4: str = ""
    target6: str = ""
    iperf4_on_mouse_target: bool = False
    iperf6_on_mouse_target: bool = False
    lan_vip4: str = ""
    iperf_port: int = 5211
    iperf6_port: int = 5210
    iperf_streams: int = 8
    iperf6_streams: int = 2
    poll_s: float = 0.2
    warmup_s: float = 3.0
    outdir: str = ""
    run_id: str = ""
    form: str = FORM_TARGETED
    # #19050: routed-destination probes from the LAN host, and the
    # host-originated probe pair run on BOTH nodes (host4_target via the
    # default route, host4_anchor the connected WAN gateway).
    routed: List[RoutedProbe] = field(default_factory=list)
    host4_target: str = ""
    host4_anchor: str = ""


class Soak:
    def __init__(self, cfg: Config, cluster, now_fn=time.time, sleep_fn=time.sleep, log=print, mono_fn=None):
        self.cfg = cfg
        self.c = cluster
        # #19041: `now` is MONOTONIC and serves every deadline and duration,
        # so a wall-clock step cannot stretch or shrink a bound. `wall` is
        # time.time() and only maps moments onto the LAN host's traffic logs
        # and measures clock offsets. A test that injects now_fn and no
        # mono_fn drives both from its fake clock.
        self.wall = now_fn
        self.now = mono_fn or (time.monotonic if now_fn is time.time else now_fn)
        self.sleep = sleep_fn
        self.log = log
        self.lan_offset = 0.0  # LAN clock minus this host's clock
        self.members: Dict[int, List[str]] = {}
        self.macs: Dict[str, Tuple[int, str]] = {}
        self.traffic_started = False
        self.terminated = False
        self.udp_probe_started = False
        self.udp_probe_baseline: Optional[str] = None
        self.v6_router: Optional[Tuple[str, str]] = None
        # #19050: per-probe baseline VOID reasons, and each node's clock
        # offset (node clock minus this host's), for the host-originated
        # probe's window bounds.
        self.routed_void: Dict[str, str] = {}
        self.host4_void: Optional[str] = None
        self.host4_leak: Optional[str] = None
        self.node_offset: Dict[int, float] = {0: 0.0, 1: 0.0}
        self.node_procs: List = []

        self.move_commands_issued = 0

    # -- helpers --------------------------------------------------------

    def views(self, first: Optional[int] = None) -> Tuple[Dict[int, RGView], Dict[int, RGView]]:
        """Both nodes' own status, as (node0's view, node1's view).

        `first` given (#19041): read node `first`, THEN the other node, one
        after the other. During a move `first` is the commanded target. Two
        reads never share an instant. In parallel, a clean handoff could be
        read as the old owner primary just before it and the target primary
        just after it: a dual-active sample with no real overlap. With the
        target read at T1 and the old owner at T2 > T1, that cannot happen.
        If the target claims the RG at T1, a clean (break-before-make)
        handoff had already released it on the old owner before T1, so the
        old owner reads released at T2.
        - So a dual-active sample in this order means the old owner claimed
          the RG after the target did: a real overlap. Or the target let go
          again between T1 and T2 while the old owner took it back, which is
          a failed move too.
        - An overlap is seen only if this sample's T1 AND T2 both fall
          inside it. The soak misses an overlap that started earlier and ends
          between the two reads, one that falls between samples (the poll
          sleep plus the reads), and one that ends before the first sample
          after the CLI returns (the CLI call is never sampled). Serial
          reads put T1 and T2 about one full read apart, so the shortest
          detectable overlap is about one read. That is the price of never
          false-flagging a clean handoff (docs/ha-rg-move-correctness.md,
          "Sampling both nodes").

        `first` None: read both in parallel. That is for readings that only
        ask who owns the RG and never score dual-active (preflight, the
        owner refresh, the restore poll)."""
        if first is None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                f0, f1 = ex.submit(self.c.status, 0), ex.submit(self.c.status, 1)
                return parse_status(f0.result()), parse_status(f1.result())
        a = parse_status(self.c.status(first))
        b = parse_status(self.c.status(1 - first))
        return (a, b) if first == 0 else (b, a)

    def helpers(self) -> Dict[int, Optional[Dict]]:
        if not self.cfg.helper_check:
            return {0: None, 1: None}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            h = {n: ex.submit(self.c.helper, n) for n in (0, 1)}
            return {n: f.result() for n, f in h.items()}

    def resolve_rgs(self, v0: Dict[int, RGView]) -> List[int]:
        spec = self.cfg.rgs.strip().lower()
        if spec == "all":
            return sorted(v0)
        return [int(x) for x in re.split(r"[ ,]+", spec) if x]

    def lan_time(self, t_local: float) -> float:
        return t_local + self.lan_offset

    def families(self) -> List[Tuple[str, str, int, int]]:
        out = [("v4", self.cfg.target4, self.cfg.iperf_port, self.cfg.iperf_streams)]
        if self.cfg.target6:
            out.append(("v6", self.cfg.target6, self.cfg.iperf6_port, self.cfg.iperf6_streams))
        return out

    def _path(self, kind: str, fam: str) -> str:
        if kind in ("route", "host"):
            # #19050: fam is the probe name ("r4") or "<node>-<anchor|routed>".
            return os.path.join(self.cfg.outdir, f"{kind}-{fam}.log")
        suffix = "" if fam == "v4" else "6"
        return os.path.join(self.cfg.outdir, f"ping{suffix}.log" if kind == "ping" else f"iperf{suffix}.jsonl")

    # -- preflight ------------------------------------------------------

    def preflight(self) -> Tuple[Optional[str], Dict]:
        info: Dict = {}
        v0, v1 = self.views()
        rgs = self.resolve_rgs(v0)
        info["rgs"] = rgs
        if not rgs:
            return "no redundancy groups in node0's status", info
        owners = {}
        for rg in rgs:
            own = rg_ownership(rg, v0, v1)
            owners[rg] = own
            info.setdefault("owners", {})[rg] = own.owner
            if own.owner is None:
                return f"RG{rg} has no single clean owner at preflight ({own.detail})", info
        offs = {}
        for name, ref in (("node0", self.c.fw[0]), ("node1", self.c.fw[1]), ("lan", self.c.lan)):
            offs[name] = measure_offset(self.c.clock, ref, self.wall)
        info["clock"] = {k: (None if v is None else {"offset_s": round(v[0], 3), "rtt_s": round(v[1], 3)})
                         for k, v in offs.items()}
        if offs["lan"] is None:
            return "cannot read the LAN host clock", info
        self.lan_offset = offs["lan"][0]
        if offs["node0"] and offs["node1"]:
            info["node1_minus_node0_s"] = round(offs["node1"][0] - offs["node0"][0], 2)
        for n in (0, 1):
            if offs[f"node{n}"]:
                self.node_offset[n] = offs[f"node{n}"][0]
        info["chrony"] = {n: self.c.chrony(n) for n in (0, 1)}
        # #18585 builds print the heartbeat-measured peer offset; record it
        # beside the harness's own measurement (absent on older builds).
        info["peer_clock_line"] = {}
        for n in (0, 1):
            m = re.search(r"^Peer clock offset: .*$", self.c.status(n) or "", re.M)
            if m:
                info["peer_clock_line"][n] = m.group(0)
        # Traffic-follow inputs: which interfaces carry each RG, and which
        # node owns each MAC the LAN host can resolve the VIP to.
        self.members = rg_members(self.c.config_set(0))
        info["rg_members"] = {rg: self.members.get(rg) for rg in rgs}
        if self.cfg.traffic and self.cfg.helper_check:
            for rg in rgs:
                # RG0 is the control-plane group (no RETH). Every data RG must
                # map to members, or the counter check would switch itself off.
                if rg > 0 and not self.members.get(rg):
                    return (f"RG{rg} maps to no RETH member interfaces in the configuration "
                            f"({'a RETH with no members' if rg in self.members else 'no RETH bound to it was parsed'}), "
                            "so the traffic-follow check cannot measure it"), info
        for n in (0, 1):
            for mac, ifname in link_macs(self.c.links(n)).items():
                self.macs[mac] = (n, ifname)
        self._owners = {rg: o for rg, o in owners.items()}
        return None, info

    # -- traffic --------------------------------------------------------

    def start_traffic(self, duration_s: int):
        rid = self.cfg.run_id
        stamp = ("import sys,time\n"
                 "for l in sys.stdin:\n"
                 "    sys.stdout.write('%.6f %s' % (time.time(), l)); sys.stdout.flush()\n")
        self.procs = []
        for fam, target, port, streams in self.families():
            t = shlex.quote(target)
            v = "-6" if fam == "v6" else "-4"
            iperf = (f"sh -c 'echo $$ > /tmp/r-soak-{rid}.iperf{fam}.pid; exec iperf3 {v} -c {t} -p {port}"
                     f" -P {streams} -t {duration_s} -i 0.1 --json-stream --forceflush'"
                     f" | python3 -u -c {shlex.quote(stamp)}")
            ping = f"echo $$ > /tmp/r-soak-{rid}.ping{fam}.pid; exec ping {v} -D -i 0.01 -W 1 -w {duration_s} {t}"
            self.procs.append(self.c.popen_lan(ping, self._path("ping", fam)))
            self.procs.append(self.c.popen_lan(iperf, self._path("iperf", fam)))
        for p in self.cfg.routed:
            v = "-6" if p.family == "v6" else "-4"
            ping = (f"echo $$ > /tmp/r-soak-{rid}.route{p.name}.pid; exec ping {v} -D -i {p.interval_s:g} -W 1"
                    f" -w {duration_s} {shlex.quote(p.target)}")
            self.procs.append(self.c.popen_lan(ping, self._path("route", p.name)))
        if self.cfg.host4_target and self.cfg.host4_anchor:
            for n in (0, 1):
                for kind, dst in (("anchor", self.cfg.host4_anchor), ("routed", self.cfg.host4_target)):
                    self.node_procs.append(self.c.popen_node(
                        n, host_ping_loop(rid, kind, dst, duration_s), self._path("host", f"{n}-{kind}")))
        self.traffic_started = True

    def stop_traffic(self):
        if not self.traffic_started:
            return
        self.traffic_started = False
        rid = self.cfg.run_id
        self.c.lan_sh(f"for p in /tmp/r-soak-{rid}.*.pid; do"
                      f" [ -f $p ] && kill -INT $(cat $p) 2>/dev/null; done; sleep 2;"
                      f" rm -f /tmp/r-soak-{rid}.*.pid")
        if self.node_procs:
            for n in (0, 1):
                self.c.node_sh(n, host_ping_stop(rid))
        for p, f in self.procs + self.node_procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
            f.close()

    def _read(self, path: str) -> str:
        try:
            with open(path) as f:
                return f.read()
        except OSError:
            return ""

    def traffic_preflight(self) -> Optional[str]:
        """After the warmup, every family must be answering and streaming. A
        busy or unreachable iperf3 server, or a dead target, is VOID: nothing
        a move did caused it (#18587 review B4)."""
        for fam, target, port, _ in self.families():
            ptxt, itxt = self._read(self._path("ping", fam)), self._read(self._path("iperf", fam))
            err = iperf_error(itxt)
            if err:
                return f"{fam} iperf3 to {target}:{port} failed before any move: {err}"
            intervals, _, _ = parse_iperf_stream(itxt)
            good = [iv for iv in intervals if iv[3] >= self.cfg.budget.low_bps]
            if len(good) < 5:
                return f"{fam} iperf3 to {target}:{port} is not streaming after {self.cfg.warmup_s:g}s warmup ({len(good)} good intervals)"
            if len(parse_ping(ptxt)) < 20:
                return f"{fam} ping to {target} is not answering after {self.cfg.warmup_s:g}s warmup"
        self.routed_baseline()
        return None

    def routed_baseline(self):
        """#19050: the same-run positive control. A routed probe that does not
        answer before any move cannot score a move: its cells are VOID for the
        whole run (a disabled check, exit 2), never PASS."""
        for p in self.cfg.routed:
            replies = parse_ping(self._read(self._path("route", p.name)))
            need = max(5, min(20, int(0.3 * self.cfg.warmup_s / p.interval_s)))
            if len(replies) < need:
                self.routed_void[p.name] = (f"routed {p.name} ping to {p.target} answered {len(replies)} times in the "
                                            f"{self.cfg.warmup_s:g}s warmup (need {need}): its baseline control failed")
        if not (self.cfg.host4_target and self.cfg.host4_anchor):
            return
        got = {n: (len(parse_host_ping(self._read(self._path("host", f"{n}-anchor")))),
                   len(parse_host_ping(self._read(self._path("host", f"{n}-routed")))))
               for n in (0, 1)}
        owners = [n for n in (0, 1) if got[n][0] >= 20]
        if len(owners) != 1 or got[1 - owners[0]][0] != 0:
            self.host4_void = (f"host4 anchor ping to {self.cfg.host4_anchor} cannot tell the WAN owner from the "
                               f"standby at baseline (replies node0={got[0][0]} node1={got[1][0]}; exactly one "
                               "node must answer)")
        elif got[owners[0]][1] < 20:
            self.host4_void = (f"host4 routed ping to {self.cfg.host4_target} from the WAN owner node{owners[0]} "
                               f"answered {got[owners[0]][1]} times at baseline: its positive control failed")
        elif got[1 - owners[0]][1] != 0:
            # R4 F2: the standby holds no WAN address, so its routed ping
            # must stay silent. A reply means another route resolved its
            # default (R4 F1): a defect, not a missing control.
            self.host4_leak = (f"the standby node{1 - owners[0]} answered {got[1 - owners[0]][1]} routed pings to "
                               f"{self.cfg.host4_target} at baseline without holding the WAN address")

    def start_udp_probe(self) -> Optional[str]:
        """Start one long-lived datagram socket and prove its pre-move baseline."""
        problem = self.c.udp_probe_start(self.cfg.run_id, self.cfg.target4, udp_session_probe.PORT)
        if problem:
            return problem
        self.udp_probe_started = True
        self.sleep(0.5)
        baseline = self.c.udp_probe_snapshot(self.cfg.run_id)
        if baseline is None:
            return "UDP sequence probe produced no pre-move snapshot"
        try:
            parsed = udp_session_probe.parse_log(baseline)
        except ValueError as exc:
            return f"UDP sequence probe baseline is malformed: {exc}"
        if not parsed.sent or not parsed.replies or not parsed.boot_ids or not parsed.socket_tuple:
            return "UDP sequence probe did not exchange a complete pre-move baseline"
        self.udp_probe_baseline = baseline
        return None
    def udp_probe_before_move(self, target_node: int) -> Dict:
        """Require the synced target-side session, then checkpoint just before CLI."""
        def void(detail):
            return {"status": "VOID", "detail": detail, "metrics": {}}
        if not self.udp_probe_started:
            return void("UDP sequence probe was not running before the move")
        if self.udp_probe_baseline is None:
            return void("UDP sequence probe has no usable cumulative baseline")
        session_probe = self.c.udp_probe_snapshot(self.cfg.run_id)
        if session_probe is None:
            return void("UDP sequence probe snapshot for the Session ID query became unavailable")
        try:
            udp_session_probe.parse_log(self.udp_probe_baseline)
            parsed_session_probe = udp_session_probe.parse_log(session_probe)
        except ValueError as exc:
            return void(f"UDP sequence probe Session ID evidence is malformed: {exc}")
        same, identity_detail = udp_session_probe.same_client_identity(self.udp_probe_baseline, session_probe)
        if not same:
            self.udp_probe_baseline = session_probe
            return void(f"UDP sequence probe sender identity changed before Session ID query: {identity_detail}")
        if not parsed_session_probe.sent or not parsed_session_probe.replies:
            return void("UDP sequence probe has no sent-and-answered baseline for the Session ID query")
        session_id, error = self.c.udp_probe_session_id(target_node, session_probe)
        if error:
            self.udp_probe_baseline = session_probe
            return void(f"UDP sequence probe pre-move Session ID query failed: {error}")
        if session_id is None:
            self.udp_probe_baseline = session_probe
            return void(f"UDP sequence probe flow was absent on synced standby node{target_node}")
        baseline = self.c.udp_probe_snapshot(self.cfg.run_id)
        if baseline is None:
            self.udp_probe_baseline = session_probe
            return void("UDP sequence probe pre-move snapshot became unavailable")
        try:
            parsed = udp_session_probe.parse_log(baseline)
        except ValueError as exc:
            return void(f"UDP sequence probe pre-move evidence is malformed: {exc}")
        same, identity_detail = udp_session_probe.same_client_identity(session_probe, baseline)
        if not same:
            self.udp_probe_baseline = baseline
            return void(f"UDP sequence probe sender identity changed during Session ID query: {identity_detail}")
        if not parsed.sent or not parsed.replies:
            return void("UDP sequence probe has no pre-move sent-and-answered baseline")
        self.udp_probe_baseline = baseline
        return {"status": "READY", "snapshot": baseline, "session_id_before": session_id}

    def udp_probe_window(self, pending: Dict, after_snapshot: Optional[str] = None) -> Dict:
        if pending.get("status") != "READY":
            return pending
        current = after_snapshot or self.c.udp_probe_snapshot(self.cfg.run_id)
        if current is None:
            return {"status": "VOID", "detail": "UDP sequence probe snapshot became unavailable",
                    "metrics": {}}
        session_id_after, error = self.c.udp_probe_session_id(pending["target_node"], current)
        self.udp_probe_baseline = current
        if error:
            return {"status": "VOID",
                    "detail": f"UDP sequence probe final-window Session ID query failed: {error}",
                    "metrics": {}}
        status, detail, metrics = udp_session_probe.classify_snapshots(
            pending["pre_move_snapshot"], pending["post_commit_snapshot"], current,
            pending["session_id_before"], session_id_after)
        return {"status": status, "detail": detail, "metrics": metrics}

    # -- one move -------------------------------------------------------

    def one_rg(self, rg: int, target: int, pre: Ownership,
               udp_probe_pre: Optional[Dict] = None) -> Tuple[RGMoveResult, float, Optional[Dict]]:
        cmd, untargeted = move_command(rg, target, self.cfg.issuer, self.cfg.form)
        t0 = self.now()
        self.move_commands_issued += 1
        rc, out = self.c.cli(self.cfg.issuer, cmd)
        t_ret = self.now()
        cls, first = classify_cli(rc, out, rg, untargeted)
        udp_probe = None
        post_commit_snapshot = None
        snapshot_at_landing = False
        if udp_probe_pre is not None:
            if udp_probe_pre.get("status") != "READY":
                udp_probe = udp_probe_pre
            elif cls == CLI_TRIGGERED:
                # A local resign confirms no commit: checkpoint at the
                # observed landing instead (below).
                snapshot_at_landing = True
            elif cls != CLI_OK:
                udp_probe = {"status": "VOID",
                             "detail": "UDP sequence checkpoint requires the directed CLI's transfer-committed confirmation",
                             "metrics": {}}
            else:
                # The directed CLI response confirms the transfer commit.
                # Snapshot immediately after that confirmation; packets sent
                # during command latency or before commit cannot prove survival.
                post_commit_snapshot = self.c.udp_probe_snapshot(self.cfg.run_id)
                if post_commit_snapshot is None:
                    udp_probe = {"status": "VOID",
                                 "detail": "UDP sequence probe post-commit checkpoint became unavailable",
                                 "metrics": {}}
        landed, dual, last, samples, dual_detail = None, False, pre.detail, 0, ""
        # Bound: the RG must have landed before the operator's next command,
        # which their loop issues `sleep S` after this one returns.
        deadline = t_ret + self.cfg.budget.converge_s
        while True:
            # The target first, then the old owner (#19041: views()).
            v0, v1 = self.views(first=target)
            own = rg_ownership(rg, v0, v1)
            if own.dual_active:
                dual = True
                samples += 1
                dual_detail = dual_detail or f"{own.detail}; node{target} read first"
            last = own.detail
            if own.owner == target:
                landed = self.now() - t0
                break
            if self.now() >= deadline:
                break
            self.sleep(self.cfg.poll_s)
        if snapshot_at_landing and landed is not None:
            post_commit_snapshot = self.c.udp_probe_snapshot(self.cfg.run_id)
            if post_commit_snapshot is None:
                udp_probe = {"status": "VOID",
                             "detail": "UDP sequence probe landing checkpoint became unavailable",
                             "metrics": {}}
        if udp_probe_pre is not None and udp_probe_pre.get("status") == "READY" and udp_probe is None:
            if landed is None:
                udp_probe = {"status": "VOID",
                             "detail": f"UDP probe could not reach node{target} after RG{rg} failed to land",
                             "metrics": {}}
            else:
                # Keep the pre-move Session ID, but query the promoted-node
                # identity at the end of the judged window, beside its final
                # probe snapshot, so later recreation cannot escape detection.
                udp_probe = {"status": "READY",
                             "pre_move_snapshot": udp_probe_pre["snapshot"],
                             "post_commit_snapshot": post_commit_snapshot,
                             "session_id_before": udp_probe_pre["session_id_before"],
                             "target_node": target}
        # self._owners (the next move's precondition) is refreshed by
        # watch_window at the END of the window, not here at landing.
        res = RGMoveResult(rg, target, pre.owner, pre.detail, cls, first, rc, round(t_ret - t0, 3),
                           None if landed is None else round(landed, 3), last, dual)
        res.dual_samples = samples
        res.dual_detail = dual_detail
        res.follow_expected = self.cfg.traffic and self.cfg.helper_check and bool(self.members.get(rg))
        return res, t_ret, udp_probe

    def watch_window(self, results: List[RGMoveResult], until: float, first: Optional[int] = None):
        """Keep sampling both views until the window ends (`until`, on the
        monotonic clock): a move that reverts, or goes dual-active, after
        landing is not a landed move. Reads are sequential, `first` (the
        move's target) first (#19041: views()). After landing no handoff is
        pending, so every dual-active sample is a real overlap or a second
        handoff, and either one FAILs. With several RGs moved to different
        targets, one order serves all of them; that is safe for the same
        reason. An RG that never landed already FAILs "did not land"."""
        while self.now() < until:
            v0, v1 = self.views(first=first)
            for r in results:
                own = rg_ownership(r.rg, v0, v1)
                if own.dual_active:
                    r.dual_active = True
                    r.dual_samples += 1
                    if not r.dual_detail:
                        r.dual_detail = f"{own.detail}; node{first} read first" if first is not None else own.detail
                if r.landed_s is not None and own.owner != r.target and not r.reverted:
                    r.reverted = own.detail
                self._owners[r.rg] = own
            self.sleep(self.cfg.poll_s)

    def member_counts(self, hv: Dict[int, Optional[Dict]], rg: int) -> Dict[int, Optional[int]]:
        out: Dict[int, Optional[int]] = {}
        for n in (0, 1):
            h = hv.get(n)
            out[n] = None if h is None else sum(int(h["if"].get(x, 0)) for x in self.members.get(rg, []))
        return out

    def neigh_nodes(self) -> Dict[str, Optional[int]]:
        out: Dict[str, Optional[int]] = {}
        if self.cfg.lan_vip4:
            mac = neigh_mac(self.c.neigh(self.cfg.lan_vip4))
            out["v4"] = self.macs.get(mac, (None, ""))[0] if mac else None
        if self.v6_router:
            mac = neigh_mac(self.c.neigh(*self.v6_router))
            out["v6"] = self.macs.get(mac, (None, ""))[0] if mac else None
        return out

    def _refresh_owners(self, rgs: List[int]) -> Dict[int, Optional[int]]:
        """Read and cache the current single-owner view for every tracked RG."""
        v0, v1 = self.views()
        self._owners = {rg: rg_ownership(rg, v0, v1) for rg in rgs}
        return {rg: own.owner for rg, own in self._owners.items()}

    def restore_node0(self, rgs: List[int]) -> str:
        """Matrix row D3: leave node0 primary. A local pull on node0 per RG not
        already there; reported, never folded into the moves' verdicts."""
        try:
            self._refresh_owners(rgs)
        except Exception as e:
            return f"WARNING: cannot inspect ownership before restore: {e}; restore by hand"
        moved = []
        for rg in rgs:
            if self._owners.get(rg) is not None and self._owners[rg].owner == 0:
                continue
            self.c.cli(0, f"request chassis cluster failover redundancy-group {rg} node 0")
            moved.append(rg)
        deadline = self.now() + 30
        while moved:
            v0, v1 = self.views()
            if all(rg_ownership(rg, v0, v1).owner == 0 for rg in rgs):
                return f"node0 primary for RG {rgs} (restored {moved})"
            if self.now() >= deadline:
                return f"WARNING: node0 not primary for every RG in {rgs} after 30s; restore by hand"
            self.sleep(1.0)
        return f"node0 already primary for RG {rgs}"

    def run(self) -> int:
        cfg = self.cfg
        self.move_commands_issued = 0
        why, info = self.preflight()
        self.log(f"preflight: {json.dumps(info, sort_keys=True, default=str)}")
        skew = info.get("node1_minus_node0_s")
        if skew is not None and abs(skew) >= 10:
            self.log(f"preflight WARNING: node1 is {skew:+.1f}s from node0 — fabric RPC auth tolerates <30s;"
                     " cross-node moves are expected to FAIL (this harness does not fix clocks)")
        if why:
            self.log(f"FATAL: preflight VOID: {why}")
            self._write({"preflight": info, "void": why, "moves": []})
            return 2
        rgs = info["rgs"]
        # The LAN RG: the one whose RETH members own the MAC the LAN host
        # currently resolves the LAN VIP to (only that RG's move can change it).
        self._lan_rg = None
        if cfg.traffic and cfg.lan_vip4:
            mac = neigh_mac(self.c.neigh(cfg.lan_vip4))
            node_if = self.macs.get(mac or "")
            if node_if:
                for rg, mem in self.members.items():
                    if node_if[1] in mem:
                        self._lan_rg = rg
        info["lan_rg"] = self._lan_rg
        why = None
        if cfg.traffic and cfg.lan_vip4 and self._lan_rg is None:
            why = (f"the LAN host's neighbour entry for {cfg.lan_vip4} does not resolve to a RETH member MAC "
                   "of either node, so the traffic-follow check cannot read it")
        if cfg.traffic and cfg.target6 and not why:
            # IPv6 leaves the LAN host via its RA default router (a RETH
            # link-local), not the global LAN VIP: check THAT neighbour.
            self.v6_router = self.c.lan_v6_router()
            info["lan_v6_router"] = self.v6_router
            mac = neigh_mac(self.c.neigh(*self.v6_router)) if self.v6_router else None
            if not self.v6_router:
                why = "the LAN host has no IPv6 default route, so the IPv6 traffic-follow check cannot read it"
            elif mac not in self.macs:
                why = (f"the LAN host's IPv6 default router {self.v6_router[0]} resolves to {mac or 'no MAC'}, "
                       "which is no RETH member MAC of either node")
        if why:
            self.log(f"FATAL: preflight VOID: {why}")
            self._write({"preflight": info, "void": why, "moves": []})
            return 2
        # First target per RG: away from its current owner. Alternate strictly
        # afterwards, like the operator's loop, whatever happened.
        targets = {rg: 1 - info["owners"][rg] for rg in rgs}
        initial_owners = dict(info["owners"])
        moves: List[MoveRecord] = []
        disabled = []
        if not cfg.traffic:
            disabled.append("traffic (SOAK_TRAFFIC=0): no traffic-follow, loss or stall evidence")
        if not cfg.helper_check:
            disabled.append("helper (SOAK_HELPER_CHECK=0): no ha_groups or RETH-member counter evidence")
        void_reason: Optional[str] = None

        try:
            if cfg.traffic:
                # This is lock-protected and before our generators start.
                # Reset only ESTABLISHED clients for families whose target
                # address is pinned on this mouse host; loss v6 is external.
                iperf_ports = []
                if cfg.iperf4_on_mouse_target:
                    iperf_ports.append(cfg.iperf_port)
                if cfg.target6 and cfg.iperf6_on_mouse_target:
                    iperf_ports.append(cfg.iperf6_port)
                bad = self.c.prepare_iperf(iperf_ports)
                if bad:
                    raise VoidRun(f"iperf socket preflight: {bad}")
                per_move = cfg.sleep_s + cfg.budget.converge_s + 4
                self.start_traffic(int(cfg.moves * per_move * len(rgs) + 60))
                self.sleep(cfg.warmup_s)
                bad = self.traffic_preflight()
                if bad:
                    raise VoidRun(f"traffic preflight: {bad}")
                bad = self.start_udp_probe()
                if bad:
                    self.log(f"UDP sequence probe unavailable; each move's UDP cell will be VOID: {bad}")
            for i in range(1, cfg.moves + 1):
                target = targets[rgs[0]]
                t_issue = self.wall()
                udp_probe_checks = []
                udp_probe_pending = None
                results: List[RGMoveResult] = []
                t_ret_last = self.now()
                for rg in rgs:
                    if cfg.traffic:
                        if udp_probe_pending is not None:
                            # Close this CLI's evidence before the next CLI can
                            # cause recovery and mask its post-move loss.
                            udp_probe_checks.append(self.udp_probe_window(udp_probe_pending))
                            udp_probe_pending = None
                        udp_probe_pre = self.udp_probe_before_move(targets[rg])
                    else:
                        udp_probe_pre = None
                    r, t_ret_last, udp_window = self.one_rg(
                        rg, targets[rg], self._owners[rg], udp_probe_pre)
                    results.append(r)
                    if cfg.traffic and udp_window is not None:
                        if udp_window.get("status") == "READY":
                            udp_probe_pending = udp_window
                        else:
                            udp_probe_checks.append(udp_window)
                h1 = self.helpers()
                for r in results:
                    if r.landed_s is not None and cfg.helper_check:
                        r.helper = {n: (None if h1[n] is None else h1[n]["ha"].get(r.rg)) for n in (0, 1)}
                # The operator's `sleep S` starts when the CLI returns. Watch
                # the views for the rest of it, then close the last UDP window.
                self.watch_window(results, t_ret_last + cfg.sleep_s, first=target)
                if cfg.traffic:
                    h2 = self.helpers()
                    neigh = self.neigh_nodes()
                    for r in results:
                        if r.landed_s is None:
                            continue
                        if r.follow_expected:
                            a, b = self.member_counts(h1, r.rg), self.member_counts(h2, r.rg)
                            r.member_delta = {n: (None if a[n] is None or b[n] is None else b[n] - a[n]) for n in (0, 1)}
                        if self._lan_rg is not None and r.rg == self._lan_rg:
                            r.neigh_node = neigh
                    if udp_probe_pending is not None:
                        udp_probe_checks.append(self.udp_probe_window(udp_probe_pending))
                    if udp_probe_checks:
                        status, detail, metrics = udp_session_probe.combine_classifications([
                            (check["status"], check["detail"], check.get("metrics", {}))
                            for check in udp_probe_checks
                        ])
                        udp_probe = {"status": status, "detail": detail, "metrics": metrics,
                                     "windows": udp_probe_checks}
                    else:
                        udp_probe = {"status": "VOID",
                                     "detail": "UDP sequence probe has no per-move windows",
                                     "metrics": {}}
                else:
                    udp_probe = None
                rec = MoveRecord(i, target, cfg.issuer, self.lan_time(t_issue), 0.0,
                                 results, udp_probe=udp_probe)
                moves.append(rec)
                if len(moves) > 1:
                    moves[-2].t_next_lan = rec.t_issue_lan
                c = results[-1]
                probe_status = (udp_probe or {}).get("status", "-")
                probe_detail = (udp_probe or {}).get("detail", "")
                dual_note = "".join(f" dual_samples={r.dual_samples}" for r in results if r.dual_samples)
                self.log(f"move {i:>4} -> node{target}: cli={','.join(r.cli_class for r in results)}"
                         f" landed={','.join('-' if r.landed_s is None else f'{r.landed_s:.2f}' for r in results)}"
                         f"{dual_note} udp={probe_status} {probe_detail} {c.cli_first[:120]}")
                for rg in rgs:
                    targets[rg] = 1 - targets[rg]
            if moves:
                moves[-1].t_next_lan = self.lan_time(self.wall())
        except VoidRun as e:
            void_reason = str(e)
            self.log(f"FATAL: {void_reason}")
        except (SystemExit, KeyboardInterrupt):
            # Terminated: the lock wrapper may have died from the same signal,
            # so no further RG move (the node0 restore) may run unlocked.
            self.terminated = True
            raise
        finally:
            if self.udp_probe_started:
                try:
                    self.c.udp_probe_stop(cfg.run_id)
                except Exception as e:
                    self.log(f"WARNING: could not stop UDP sequence probe: {e}")
                self.udp_probe_started = False
            if cfg.traffic:
                if not self.terminated:
                    self.sleep(1.0)
                self.stop_traffic()
            if cfg.restore and not self.terminated:
                def read_current_owners():
                    try:
                        return self._refresh_owners(rgs)
                    except Exception as e:
                        self.log(f"WARNING: could not read current RG owners before restore decision: {e}")
                        return {rg: None for rg in rgs}

                current_owners = read_current_owners()
                owner_changed = any(
                    current_owners.get(rg) is not None
                    and current_owners[rg] != initial_owners.get(rg)
                    for rg in rgs)
                unknown_rgs = [rg for rg in rgs if current_owners.get(rg) is None]
                if unknown_rgs:
                    self.log(f"WARNING: current owner unreadable for RG(s) {unknown_rgs}; retrying before restore decision")
                    self.sleep(0.2)
                    current_owners = read_current_owners()
                    # Merge evidence: an unknown retry must not erase a known
                    # owner change observed in the first read.
                    owner_changed = owner_changed or any(
                        current_owners.get(rg) is not None
                        and current_owners[rg] != initial_owners.get(rg)
                        for rg in rgs)
                    unknown_rgs = [rg for rg in rgs if current_owners.get(rg) is None]
                    if unknown_rgs:
                        self.log(f"WARNING: current owner remains unreadable for RG(s) {unknown_rgs}; "
                                 "unknown is not treated as an ownership change")
                if self.move_commands_issued or owner_changed:
                    info["restore"] = self.restore_node0(rgs)
                    self.log(f"restore: {info['restore']}")
        end_offs = {n: measure_offset(self.c.clock, self.c.fw[n], self.wall) for n in (0, 1)}
        if end_offs[0] and end_offs[1]:
            info["end_node1_minus_node0_s"] = round(end_offs[1][0] - end_offs[0][0], 2)
        if void_reason is not None:
            self._write({"preflight": info, "void": void_reason, "moves": [asdict(m) for m in moves]})
            return 2
        return self.finish(moves, info, disabled)

    def finish(self, moves: List[MoveRecord], info: Dict, disabled: List[str]) -> int:
        cfg = self.cfg
        if cfg.traffic:
            for fam, _, _, _ in self.families():
                replies = parse_ping(self._read(self._path("ping", fam)))
                intervals, _, _ = parse_iperf_stream(self._read(self._path("iperf", fam)))
                gaps = ping_gaps(replies)
                stalls, agg = stream_stalls(intervals, cfg.budget.low_bps)
                for m in moves:
                    m.traffic = m.traffic or {}
                    m.traffic[fam] = traffic_for_window(m.t_issue_lan, m.t_next_lan, gaps, replies, stalls, agg,
                                                        intervals, cfg.budget)
        if cfg.traffic:
            self.score_routed(moves, disabled)
        for m in moves:
            m.verdict, m.reasons = move_verdict(m, cfg.budget, cfg.traffic)
        summary = summarize(moves, cfg.traffic, disabled, cfg.strict_cost)
        self.log(format_table(moves, cfg.traffic))
        routed_table = format_routed_table(moves)
        if routed_table:
            self.log(routed_table)
        self.log("summary: " + json.dumps(summary, sort_keys=True))
        for d in disabled:
            self.log(f"NOTE: check disabled: {d} — the run exits 2, not 0")
        # The smoke-cells ledger adapter reads this pair: a correct move
        # (PASS or COST) passed; a FAIL failed. VOID moves are neither, and the
        # exit status (2) makes the row VOID.
        c = summary["counts"]
        # "<n> passed, <m> failed, <k> cost": the smoke-cells adapter scores
        # the pair and records the cost as cells_cost; ledger_compare compares
        # only the headline, so the master-relative COST rule (row H11) is
        # judged by hand from the recorded rows. Strict mode counts COST as
        # failed.
        cost_failed = c[COST] if cfg.strict_cost else 0
        self.log(f"rg-move-soak: {c[PASS] + c[COST] - cost_failed} passed, {c[FAIL] + cost_failed} failed, "
                 f"{c[COST]} cost ({c[VOID]} void)")
        self._write({"preflight": info, "config": asdict(cfg), "summary": summary,
                     "moves": [asdict(m) for m in moves]})
        return summary["exit"]

    def score_routed(self, moves: List[MoveRecord], disabled: List[str]):
        """#19050: attach each move's routed-probe facts (LAN clock) and its
        target's host-originated route lag (the target's clock)."""
        cfg = self.cfg
        for p in cfg.routed:
            void = self.routed_void.get(p.name)
            if void:
                disabled.append(f"routed probe {p.name} VOID: {void}")
            replies = parse_ping(self._read(self._path("route", p.name)))
            gaps = ping_gaps(replies)
            for m in moves:
                m.routed = m.routed or {}
                if void:
                    m.routed[p.name] = {"void": void, "target": p.target}
                    continue
                facts = routed_for_window(m.t_issue_lan, m.t_next_lan, gaps, replies, cfg.budget)
                facts.update(target=p.target, gap_fails=p.gap_fails, interval_s=p.interval_s)
                m.routed[p.name] = facts
        if not (cfg.host4_target and cfg.host4_anchor):
            return
        if self.host4_void:
            disabled.append(f"host4 probe VOID: {self.host4_void}")
            for m in moves:
                m.host4 = {"status": "VOID", "detail": self.host4_void}
            return
        if self.host4_leak:
            for m in moves:
                m.host4 = {"status": "LEAK", "detail": self.host4_leak}
            return
        anchor = {n: parse_host_ping(self._read(self._path("host", f"{n}-anchor"))) for n in (0, 1)}
        routed = {n: parse_host_ping(self._read(self._path("host", f"{n}-routed"))) for n in (0, 1)}
        for m in moves:
            t, o = m.target, 1 - m.target
            # LAN clock -> this host's clock -> each node's clock.
            st = self.node_offset[t] - self.lan_offset
            so = self.node_offset[o] - self.lan_offset
            m.host4 = host4_move(anchor[t], routed[t], m.t_issue_lan + st, m.t_next_lan + st,
                                 anchor[o], routed[o], m.t_issue_lan + so, m.t_next_lan + so)

    def _write(self, obj):
        if self.cfg.outdir:
            with open(os.path.join(self.cfg.outdir, "result.json"), "w") as f:
                json.dump(obj, f, indent=1, sort_keys=True, default=str)


def _env_float(name, default):
    v = os.environ.get(name, "")
    return float(v) if v else default



def iperf_target_managedness(target4: str, target6: str, mouse4: str, mouse6: str,
                             alias4: str, same_host: str) -> Tuple[bool, bool]:
    """Return which iperf family targets are addressed on the managed mouse host."""
    v4 = bool(target4 and (target4 == mouse4 or (alias4 and target4 == alias4)))
    mouse_v6_match = bool(target6 and mouse6 and target6 == mouse6)
    # An explicit no or unknown flag vetoes v6 reset. With no flag, only the
    # same-host default profiles whose v4 and v6 destinations both exactly
    # equal the mouse's primary addresses provide positive evidence.
    same_host_confirmed = same_host == "yes" or (
        not same_host and target4 and mouse4 and target4 == mouse4)
    v6 = bool(mouse_v6_match and same_host_confirmed)
    return v4, v6


def routed_probes_from_env(routed4: str, routed6: str, static6: str, v6: bool, env=None) -> List[RoutedProbe]:
    """#19050: the routed-destination probes for this run. SOAK_ROUTED=0
    turns them off; SOAK_ROUTED4/6 and SOAK_STATIC6 override the env-file
    targets. v4 (a lab host behind the default route) probes at 10 ms and
    FAILs a move on a gap like the connected ping; the v6 default probe is
    the public resolver, probed at 100 ms to stay clear of ICMP rate limits,
    and the non-default static's host is an external router, also at 100 ms:
    for both a gap is a COST (their paths leave the lab)."""
    env = os.environ if env is None else env
    if env.get("SOAK_ROUTED", "1") == "0":
        return []
    out: List[RoutedProbe] = []
    r4 = env.get("SOAK_ROUTED4", routed4)
    if r4:
        out.append(RoutedProbe("r4", r4, "v4", float(env.get("SOAK_ROUTED4_INTERVAL", "0.01")),
                               env.get("SOAK_ROUTED4_GAP_FAILS", "1") != "0"))
    if v6:
        r6 = env.get("SOAK_ROUTED6", routed6)
        if r6:
            out.append(RoutedProbe("r6", r6, "v6", float(env.get("SOAK_ROUTED6_INTERVAL", "0.1")), False))
        s6 = env.get("SOAK_STATIC6", static6)
        if s6:
            out.append(RoutedProbe("s6", s6, "v6", float(env.get("SOAK_STATIC6_INTERVAL", "0.1")), False))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fw0", required=True)
    ap.add_argument("--fw1", required=True)
    ap.add_argument("--lan", required=True)
    ap.add_argument("--target4", required=True)
    ap.add_argument("--target6", default="")
    ap.add_argument("--lan-vip4", default="")
    ap.add_argument("--mouse-target", required=True)
    ap.add_argument("--lan-vip6", default="", help="ignored: IPv6 follows the LAN host's RA default router")
    ap.add_argument("--outdir", required=True)
    # #19050: routed destinations (env file ROUTED_TARGET4/6, STATIC_TARGET6)
    # and the connected WAN gateway the host-originated probe anchors on.
    ap.add_argument("--routed4", default="")
    ap.add_argument("--routed6", default="")
    ap.add_argument("--static6", default="")
    ap.add_argument("--wan-gw4", default="")
    a = ap.parse_args(argv)
    sleep_s = _env_float("SOAK_SLEEP", 5.0)
    budget = Budget(
        converge_s=_env_float("SOAK_CONVERGE_S", sleep_s),
        max_gap_ms=_env_float("SOAK_MAX_GAP_MS", 1000.0),
        max_stall_ms=_env_float("SOAK_MAX_STALL_MS", 2000.0),
        tail_s=_env_float("SOAK_TAIL_S", 1.0),
        follow_min_pkts=int(_env_float("SOAK_FOLLOW_MIN_PKTS", 500)),
        max_cost_stall_ms=_env_float("SOAK_MAX_COST_STALL_MS", 10000.0),
        max_host4_lag_ms=_env_float("SOAK_MAX_HOST4_LAG_MS", 250.0),
        expect_transfer=os.environ.get("SOAK_EXPECT_TRANSFER", "0") == "1",
    )
    v6 = os.environ.get("SOAK_IPV6", "1") != "0"
    target6 = a.target6 if v6 else ""
    iperf4_on_mouse_target, iperf6_on_mouse_target = iperf_target_managedness(
        a.target4,
        target6,
        os.environ.get("MOUSE_TARGET_V4", ""),
        os.environ.get("MOUSE_TARGET_V6", ""),
        os.environ.get("TARGET_ALIAS_V4", ""),
        os.environ.get("IPERF_TARGET_V4_V6_SAME_HOST", ""),
    )
    cfg = Config(
        moves=int(os.environ.get("SOAK_MOVES", "20")),
        sleep_s=sleep_s,
        rgs=os.environ.get("SOAK_RG", "2"),
        issuer=int(os.environ.get("SOAK_FROM", "0")),
        budget=budget,
        traffic=os.environ.get("SOAK_TRAFFIC", "1") != "0",
        helper_check=os.environ.get("SOAK_HELPER_CHECK", "1") != "0",
        strict_cost=os.environ.get("SOAK_STRICT_COST", "0") == "1",
        restore=os.environ.get("SOAK_RESTORE", "1") != "0",
        target4=a.target4,
        target6=target6,
        iperf4_on_mouse_target=iperf4_on_mouse_target,
        iperf6_on_mouse_target=iperf6_on_mouse_target,
        lan_vip4=a.lan_vip4,
        iperf_port=int(os.environ.get("SOAK_IPERF_PORT", "5211")),
        iperf6_port=int(os.environ.get("SOAK_IPERF6_PORT", "5210")),
        iperf_streams=int(os.environ.get("SOAK_STREAMS", "8")),
        outdir=a.outdir,
        run_id=re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(a.outdir.rstrip("/"))),
        form=os.environ.get("SOAK_FORM", FORM_TARGETED),
        routed=routed_probes_from_env(a.routed4, a.routed6, a.static6, bool(target6)),
    )
    r4 = next((p.target for p in cfg.routed if p.name == "r4"), "")
    if r4 and os.environ.get("SOAK_HOST4", "1") != "0":
        cfg.host4_target = r4
        cfg.host4_anchor = os.environ.get("SOAK_HOST4_ANCHOR", a.wan_gw4)
    if cfg.issuer not in (0, 1):
        print("FATAL: SOAK_FROM must be 0 or 1", file=sys.stderr)
        return 2
    if cfg.form not in FORMS:
        print(f"FATAL: SOAK_FORM must be one of {', '.join(FORMS)}", file=sys.stderr)
        return 2
    os.makedirs(cfg.outdir, exist_ok=True)
    print(f"rg-move-soak: {cfg.moves} moves of RG {cfg.rgs} from node{cfg.issuer} every {cfg.sleep_s:g}s, form {cfg.form}; "
          f"converge<= {budget.converge_s:g}s gap<= {budget.max_gap_ms:g}ms stall<= {budget.max_stall_ms:g}ms; "
          f"traffic={'on' if cfg.traffic else 'off'} v6={'on' if cfg.target6 else 'off'}; out={cfg.outdir}")
    print("rg-move-soak: routed probes: "
          + (", ".join(f"{p.name}={p.target}@{p.interval_s:g}s{'' if p.gap_fails else ' (gap=COST)'}" for p in cfg.routed)
             or "none configured (#19050: set ROUTED_TARGET4/6 or STATIC_TARGET6 in the cluster env)")
          + (f"; host4 {cfg.host4_target} anchored on {cfg.host4_anchor}" if cfg.host4_anchor else ""))
    soak = Soak(cfg, IncusCluster({0: a.fw0, 1: a.fw1}, a.lan, a.mouse_target))

    def on_term(signum, frame):
        # Unwind through run()'s finally: stops the LAN-host generators and
        # skips the node0 restore (no RG move may run after a SIGTERM).
        soak.terminated = True
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, on_term)
    try:
        return soak.run()
    except SystemExit:
        soak.stop_traffic()
        print("FATAL: harness terminated by signal (generators stopped)")
        return 2
    except Exception as e:  # a harness fault is VOID, never a FAIL
        soak.stop_traffic()
        print(f"FATAL: harness error: {type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
