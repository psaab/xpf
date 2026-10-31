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
    seconds after the CLI returns, exactly like the loop above;
  * scores the CLI text;
  * polls BOTH nodes' own `show chassis cluster status` until the target is
    primary and the other node secondary/secondary-hold in both views, and the
    target's `Forwarding: rg-active=` line is active and the other's inactive;
  * records any sample where both nodes claim the RG (dual-active);
  * reads each helper's own `ha_groups[].active` once the views converged;
  * attributes ping loss / longest ping gap and the worst iperf3 per-stream
    stall to the move's window, all on the LAN host's clock.

It never touches a clock. The preflight measures inter-node skew and reports
it, because a skewed cluster is exactly what the operator's loop hit.

Verdicts (one per move):

  PASS  every check held.
  FAIL  a CLI error; "already primary" when the precondition held; any other
        unexpected CLI text; the move did not land within the bound; a
        dual-active sample; the helper disagrees with the status views; or
        traffic did not follow (ping gap / stream stall over budget, no
        traffic in the window's tail, a traffic generator that died).
  VOID  the precondition did not hold: before a move to node t, the RG was not
        cleanly owned by the other node. A failed move therefore costs ONE
        FAIL, and the next move (back to where the RG still is) is VOID, not a
        second FAIL — the user's "already primary" line was that cascade.

Exit status: 0 all PASS; 1 any FAIL; 2 no FAIL but a VOID (or the whole run
was void at preflight).

Pure functions (parsers, verdicts, summary) are covered hermetically by
rg_move_soak_test.py; `Soak` takes an injectable cluster and clock so the
orchestration itself is driven there by a fake cluster too.
"""

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

PASS, FAIL, VOID = "PASS", "FAIL", "VOID"

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
    # trailing DIVERGENCE text.
    forwarding: Optional[str] = None
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
            v.forwarding_extra = " ".join(extra).lstrip("- ").strip()
    return views


NON_OWNER_ROLES = ("secondary", "secondary-hold")


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
    f0, f1 = v0.forwarding, v1.forwarding
    detail = f"node0={r0 or 'missing'}/{f0 or 'missing'} node1={r1 or 'missing'}/{f1 or 'missing'}"
    extras = [e for e in (v0.forwarding_extra, v1.forwarding_extra) if e]
    if extras:
        detail += " (" + "; ".join(extras) + ")"
    dual = (r0 == "primary" and r1 == "primary") or (f0 == "active" and f1 == "active")
    if dual:
        return Ownership(None, True, detail)
    if extras:
        return Ownership(None, False, detail)
    if r0 == "primary" and r1 in NON_OWNER_ROLES and f0 == "active" and f1 == "inactive":
        return Ownership(0, False, detail)
    if r1 == "primary" and r0 in NON_OWNER_ROLES and f1 == "active" and f0 == "inactive":
        return Ownership(1, False, detail)
    return Ownership(None, False, detail)


# ---------------------------------------------------------------------------
# CLI result
# ---------------------------------------------------------------------------

CLI_OK, CLI_ALREADY, CLI_ERROR, CLI_OTHER = "ok", "already", "error", "other"

_CLI_OK_RE = re.compile(r"Manual failover completed for redundancy group (\d+) \(transfer committed\)")


def classify_cli(rc: int, out: str, rg: int) -> Tuple[str, str]:
    """Classify one `request chassis cluster failover ... node N` result.

    The CLI can print `error: ...` and still exit 0, so the TEXT decides, and
    a nonzero rc is an error whatever the text says.
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
    per.extend(open_runs.values())
    if agg_run is not None:
        agg.append(agg_run)
    return per, agg


# ---------------------------------------------------------------------------
# Per-move verdict
# ---------------------------------------------------------------------------


@dataclass
class Budget:
    converge_s: float = 5.0
    max_gap_ms: float = 1000.0
    max_stall_ms: float = 2000.0
    tail_s: float = 1.0
    low_bps: float = 1_000_000.0


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
    dual_active: bool
    helper: Optional[Dict[int, Optional[bool]]] = None  # node -> helper rg active


@dataclass
class MoveRecord:
    index: int
    target: int
    issuer: int
    t_issue_lan: float
    t_next_lan: float
    rgs: List[RGMoveResult]
    traffic: Optional[Dict] = None
    verdict: str = ""
    reasons: List[str] = field(default_factory=list)


def traffic_for_window(t0: float, t1: float, gaps: List[PingGap], replies: List[Tuple[float, int]],
                       stalls: List[StreamRun], agg: List[StreamRun], intervals,
                       budget: Budget) -> Dict:
    """The traffic facts for one move window [t0, t1) on the LAN clock."""
    win_gaps = [g for g in gaps if t0 <= g.start < t1]
    lost = sum(g.lost for g in win_gaps)
    max_gap = max((g.end - g.start for g in win_gaps), default=None)
    tail0 = max(t0, t1 - budget.tail_s)
    tail_replies = sum(1 for ts, _ in replies if tail0 <= ts < t1)
    win_stalls = [s for s in stalls if t0 <= s.start < t1]
    worst = max(win_stalls, key=lambda s: s.seconds, default=None)
    agg_zero = sum(s.seconds for s in agg if t0 <= s.start < t1)
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
        "agg_zero_ms": round(agg_zero * 1000.0, 1),
        "tail_gbps": None if tail_bps is None else round(tail_bps / 1e9, 2),
        "ping_covered": covered_ping,
        "iperf_covered": covered_iperf,
    }


def move_verdict(rec: MoveRecord, budget: Budget, traffic_enabled: bool) -> Tuple[str, List[str]]:
    """Score one move. VOID (precondition) dominates, then every FAIL reason.

    The precondition is the state observed at the end of the previous move's
    poll (or the preflight), so it costs no extra reads and is the same
    evidence the previous verdict was built from.
    """
    reasons: List[str] = []
    for r in rec.rgs:
        if r.pre_owner != 1 - r.target:
            where = "unowned/unreadable" if r.pre_owner is None else f"on node{r.pre_owner}"
            reasons.append(f"precondition: RG{r.rg} was {where} before a move to node{r.target} ({r.pre_detail})")
    if reasons:
        return VOID, reasons
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
            reasons.append(f"RG{r.rg} dual-active sample during the move")
        if r.landed_s is None:
            reasons.append(f"RG{r.rg} did not land on node{r.target} within {budget.converge_s:g}s of the CLI returning (last: {r.last_detail})")
        elif r.helper is not None:
            want = {r.target: True, other: False}
            bad = [f"node{n}={'unreadable' if r.helper.get(n) is None else r.helper.get(n)}"
                   for n in (0, 1) if r.helper.get(n) is not want[n]]
            if bad:
                reasons.append(f"RG{r.rg} helper ha_groups[].active disagrees with status (want node{r.target}=True): {' '.join(bad)}")
    if traffic_enabled:
        t = rec.traffic or {}
        if not t.get("ping_covered", False):
            reasons.append("ping did not cover the move window (ping died or never started)")
        if not t.get("iperf_covered", False):
            reasons.append("iperf3 did not cover the move window (streams died or the client exited)")
        gap = t.get("ping_max_gap_ms")
        if gap is not None and gap > budget.max_gap_ms:
            reasons.append(f"ping gap {gap:g} ms > {budget.max_gap_ms:g} ms ({t.get('ping_lost')} lost)")
        stall = t.get("worst_stall_ms") or 0.0
        if stall > budget.max_stall_ms:
            reasons.append(f"stream {t.get('worst_stall_stream')} stalled {stall:g} ms > {budget.max_stall_ms:g} ms")
        if t.get("ping_covered") and t.get("ping_tail_replies", 0) == 0:
            reasons.append(f"traffic did not follow: no ping replies in the last {budget.tail_s:g}s of the window")
        if t.get("iperf_covered") and (t.get("tail_gbps") or 0.0) * 1e9 < budget.low_bps:
            reasons.append(f"traffic did not follow: iperf3 aggregate under {budget.low_bps / 1e6:g} Mbit/s in the window tail")
    return (FAIL, reasons) if reasons else (PASS, [])


def summarize(moves: List[MoveRecord], traffic_enabled: bool) -> Dict:
    counts = {PASS: 0, FAIL: 0, VOID: 0}
    for m in moves:
        counts[m.verdict] = counts.get(m.verdict, 0) + 1
    by_dir = {}
    for m in moves:
        key = f"to node{m.target}"
        d = by_dir.setdefault(key, {PASS: 0, FAIL: 0, VOID: 0})
        d[m.verdict] += 1
    out = {"moves": len(moves), "counts": counts, "by_direction": by_dir}
    scored = [m for m in moves if m.verdict != VOID]
    landed = [r.landed_s for m in scored for r in m.rgs if r.landed_s is not None]
    clis = [r.cli_seconds for m in scored for r in m.rgs]
    if landed:
        out["landed_s"] = {"median": round(statistics.median(landed), 2), "max": round(max(landed), 2)}
    if clis:
        out["cli_s"] = {"median": round(statistics.median(clis), 2), "max": round(max(clis), 2)}
    if traffic_enabled and scored:
        def dist(key):
            vals = [m.traffic.get(key) for m in scored if m.traffic and m.traffic.get(key) is not None]
            if not vals:
                return None
            return {"median": statistics.median(vals), "p95": sorted(vals)[int(0.95 * (len(vals) - 1))], "max": max(vals)}
        out["ping_lost"] = dist("ping_lost")
        out["ping_max_gap_ms"] = dist("ping_max_gap_ms")
        out["worst_stall_ms"] = dist("worst_stall_ms")
    reasons: Dict[str, int] = {}
    for m in moves:
        for r in m.reasons:
            key = re.sub(r"\d+(\.\d+)?", "N", r.split(":")[0] if r.startswith("precondition") else r)[:110]
            reasons[key] = reasons.get(key, 0) + 1
    out["reason_classes"] = dict(sorted(reasons.items(), key=lambda kv: -kv[1]))
    out["exit"] = 1 if counts[FAIL] else (2 if counts[VOID] else 0)
    return out


def format_table(moves: List[MoveRecord], traffic_enabled: bool) -> str:
    hdr = f"{'#':>4} {'to':>3} {'rg':>4} {'cli':>7} {'cli_s':>6} {'land_s':>6}"
    if traffic_enabled:
        hdr += f" {'lost':>5} {'gap_ms':>7} {'stall_ms':>8} {'tail_G':>6}"
    hdr += "  verdict  reason"
    lines = [hdr]
    for m in moves:
        rg = ",".join(str(r.rg) for r in m.rgs)
        cli = ",".join(r.cli_class for r in m.rgs)
        cli_s = max((r.cli_seconds for r in m.rgs), default=0.0)
        land = [r.landed_s for r in m.rgs]
        land_s = "-" if any(x is None for x in land) else f"{max(land):.2f}"
        row = f"{m.index:>4} {m.target:>3} {rg:>4} {cli:>7} {cli_s:>6.2f} {land_s:>6}"
        if traffic_enabled:
            t = m.traffic or {}
            gap = t.get("ping_max_gap_ms")
            row += (f" {t.get('ping_lost', '-'):>5} {('-' if gap is None else f'{gap:.0f}'):>7}"
                    f" {t.get('worst_stall_ms', 0):>8.0f} {('-' if t.get('tail_gbps') is None else t['tail_gbps']):>6}")
        row += f"  {m.verdict:<7}  {m.reasons[0] if m.reasons else ''}"
        lines.append(row)
        for extra in m.reasons[1:]:
            lines.append(" " * 9 + "+ " + extra)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Live cluster access
# ---------------------------------------------------------------------------

HELPER_SNIPPET = r"""
import json, socket
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
st = r.get("status", r)
print(json.dumps({str(g.get("rg_id")): bool(g.get("active")) for g in st.get("ha_groups", [])}))
"""


class IncusCluster:
    """Talks to the live cluster through `incus exec` only."""

    def __init__(self, fw: Dict[int, str], lan: str, timeout: float = 30.0):
        self.fw = fw
        self.lan = lan
        self.timeout = timeout

    def _exec(self, ref: str, argv: List[str], timeout: Optional[float] = None) -> Tuple[int, str]:
        try:
            p = subprocess.run(["incus", "exec", ref, "--"] + argv, capture_output=True, text=True,
                               timeout=timeout or self.timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return 124, f"error: incus exec {ref} timed out"

    def cli(self, node: int, cmd: str) -> Tuple[int, str]:
        return self._exec(self.fw[node], ["cli", "-c", cmd])

    def status(self, node: int) -> str:
        return self._exec(self.fw[node], ["cli", "-c", "show chassis cluster status"])[1]

    def helper(self, node: int) -> Optional[Dict[int, bool]]:
        rc, out = self._exec(self.fw[node], ["python3", "-c", HELPER_SNIPPET], timeout=15)
        if rc != 0:
            return None
        try:
            return {int(k): v for k, v in json.loads(out.strip().splitlines()[-1]).items()}
        except (ValueError, IndexError):
            return None

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


@dataclass
class Config:
    moves: int = 20
    sleep_s: float = 5.0
    rgs: str = "2"
    issuer: int = 0
    budget: Budget = field(default_factory=Budget)
    traffic: bool = True
    helper_check: bool = True
    target4: str = ""
    iperf_port: int = 5211
    iperf_streams: int = 8
    poll_s: float = 0.2
    outdir: str = ""
    run_id: str = ""


class Soak:
    def __init__(self, cfg: Config, cluster, now_fn=time.time, sleep_fn=time.sleep, log=print):
        self.cfg = cfg
        self.c = cluster
        self.now = now_fn
        self.sleep = sleep_fn
        self.log = log
        self.lan_offset = 0.0  # LAN clock minus this host's clock

    # -- helpers --------------------------------------------------------

    def views(self) -> Tuple[Dict[int, RGView], Dict[int, RGView]]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f0, f1 = ex.submit(self.c.status, 0), ex.submit(self.c.status, 1)
            return parse_status(f0.result()), parse_status(f1.result())

    def resolve_rgs(self, v0: Dict[int, RGView]) -> List[int]:
        spec = self.cfg.rgs.strip().lower()
        if spec == "all":
            return sorted(v0)
        return [int(x) for x in re.split(r"[ ,]+", spec) if x]

    def lan_time(self, t_local: float) -> float:
        return t_local + self.lan_offset

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
            offs[name] = measure_offset(self.c.clock, ref, self.now)
        info["clock"] = {k: (None if v is None else {"offset_s": round(v[0], 3), "rtt_s": round(v[1], 3)})
                         for k, v in offs.items()}
        if offs["lan"] is None:
            return "cannot read the LAN host clock", info
        self.lan_offset = offs["lan"][0]
        if offs["node0"] and offs["node1"]:
            skew = offs["node1"][0] - offs["node0"][0]
            info["node1_minus_node0_s"] = round(skew, 2)
        info["chrony"] = {n: self.c.chrony(n) for n in (0, 1)}
        # #18585 builds print the heartbeat-measured peer offset; record it
        # beside the harness's own measurement (absent on older builds).
        info["peer_clock_line"] = {}
        for n in (0, 1):
            m = re.search(r"^Peer clock offset: .*$", self.c.status(n) or "", re.M)
            if m:
                info["peer_clock_line"][n] = m.group(0)
        self._owners = {rg: o for rg, o in owners.items()}
        return None, info

    # -- traffic --------------------------------------------------------

    def start_traffic(self, duration_s: int):
        rid, out = self.cfg.run_id, self.cfg.outdir
        t = shlex.quote(self.cfg.target4)
        stamp = ("import sys,time\n"
                 "for l in sys.stdin:\n"
                 "    sys.stdout.write('%.6f %s' % (time.time(), l)); sys.stdout.flush()\n")
        iperf = (f"sh -c 'echo $$ > /tmp/r-soak-{rid}.iperf.pid; exec iperf3 -c {t} -p {self.cfg.iperf_port}"
                 f" -P {self.cfg.iperf_streams} -t {duration_s} -i 0.1 --json-stream --forceflush'"
                 f" | python3 -u -c {shlex.quote(stamp)}")
        ping = (f"echo $$ > /tmp/r-soak-{rid}.ping.pid; exec ping -D -i 0.01 -W 1 -w {duration_s} {t}")
        self.ping_p, self.ping_f = self.c.popen_lan(ping, os.path.join(out, "ping.log"))
        self.iperf_p, self.iperf_f = self.c.popen_lan(iperf, os.path.join(out, "iperf.jsonl"))

    def stop_traffic(self):
        rid = self.cfg.run_id
        self.c.lan_sh(f"for p in /tmp/r-soak-{rid}.iperf.pid /tmp/r-soak-{rid}.ping.pid; do"
                      f" [ -f $p ] && kill -INT $(cat $p) 2>/dev/null; done; sleep 2;"
                      f" rm -f /tmp/r-soak-{rid}.iperf.pid /tmp/r-soak-{rid}.ping.pid")
        for p, f in ((self.ping_p, self.ping_f), (self.iperf_p, self.iperf_f)):
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
            f.close()

    # -- one move -------------------------------------------------------

    def one_rg(self, rg: int, target: int, pre: Ownership) -> RGMoveResult:
        cmd = f"request chassis cluster failover redundancy-group {rg} node {target}"
        t0 = self.now()
        rc, out = self.c.cli(self.cfg.issuer, cmd)
        t_ret = self.now()
        cls, first = classify_cli(rc, out, rg)
        landed, dual, last = None, False, pre.detail
        # Bound: the RG must have landed before the operator's next command,
        # which their loop issues `sleep S` after this one returns.
        deadline = t_ret + self.cfg.budget.converge_s
        while True:
            v0, v1 = self.views()
            own = rg_ownership(rg, v0, v1)
            last = own.detail
            dual = dual or own.dual_active
            if own.owner == target:
                landed = self.now() - t0
                break
            if self.now() >= deadline:
                break
            self.sleep(self.cfg.poll_s)
        self._owners[rg] = own
        res = RGMoveResult(rg, target, pre.owner, pre.detail, cls, first, rc, round(t_ret - t0, 3),
                           None if landed is None else round(landed, 3), last, dual)
        return res

    def run(self) -> int:
        cfg = self.cfg
        why, info = self.preflight()
        self.log(f"preflight: {json.dumps(info, sort_keys=True)}")
        skew = info.get("node1_minus_node0_s")
        if skew is not None and abs(skew) >= 10:
            self.log(f"preflight WARNING: node1 is {skew:+.1f}s from node0 — fabric RPC auth tolerates <30s;"
                     " cross-node moves are expected to FAIL (this harness does not fix clocks)")
        if why:
            self.log(f"VOID (preflight): {why}")
            self._write({"preflight": info, "void": why, "moves": []})
            return 2
        rgs = info["rgs"]
        # First target per RG: away from its current owner. Alternate strictly
        # afterwards, like the operator's loop, whatever happened.
        targets = {rg: 1 - info["owners"][rg] for rg in rgs}
        moves: List[MoveRecord] = []
        if cfg.traffic:
            per_move = cfg.sleep_s + cfg.budget.converge_s + 3
            self.start_traffic(int(cfg.moves * per_move * len(rgs) + 60))
            self.sleep(3.0)
        t_start = self.now()
        try:
            for i in range(1, cfg.moves + 1):
                target = targets[rgs[0]]
                t_issue = self.now()
                results = []
                for rg in rgs:
                    results.append(self.one_rg(rg, targets[rg], self._owners[rg]))
                if cfg.helper_check:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                        h = {n: ex.submit(self.c.helper, n) for n in (0, 1)}
                        hv = {n: f.result() for n, f in h.items()}
                    for r in results:
                        if r.landed_s is not None:
                            r.helper = {n: (None if hv[n] is None else hv[n].get(r.rg)) for n in (0, 1)}
                rec = MoveRecord(i, target, cfg.issuer, self.lan_time(t_issue), 0.0, results)
                moves.append(rec)
                if moves[:-1]:
                    moves[-2].t_next_lan = rec.t_issue_lan
                c = results[-1]
                self.log(f"move {i:>4} -> node{target}: cli={','.join(r.cli_class for r in results)}"
                         f" landed={','.join('-' if r.landed_s is None else f'{r.landed_s:.2f}' for r in results)}"
                         f" {c.cli_first[:120]}")
                for rg in rgs:
                    targets[rg] = 1 - targets[rg]
                # The operator's `sleep S` starts when the CLI returns; the
                # poll above ran inside that sleep.
                t_ret_last = t_issue + max(r.cli_seconds for r in results)
                remaining = t_ret_last + cfg.sleep_s - self.now()
                if remaining > 0:
                    self.sleep(remaining)
            if moves:
                moves[-1].t_next_lan = self.lan_time(self.now())
        finally:
            if cfg.traffic:
                self.sleep(1.0)
                self.stop_traffic()
        end_offs = {n: measure_offset(self.c.clock, self.c.fw[n], self.now) for n in (0, 1)}
        if end_offs[0] and end_offs[1]:
            info["end_node1_minus_node0_s"] = round(end_offs[1][0] - end_offs[0][0], 2)
        return self.finish(moves, info, t_start)

    def finish(self, moves: List[MoveRecord], info: Dict, t_start: float) -> int:
        cfg = self.cfg
        if cfg.traffic:
            with open(os.path.join(cfg.outdir, "ping.log")) as f:
                replies = parse_ping(f.read())
            with open(os.path.join(cfg.outdir, "iperf.jsonl")) as f:
                intervals, _, _ = parse_iperf_stream(f.read())
            gaps = ping_gaps(replies)
            stalls, agg = stream_stalls(intervals, cfg.budget.low_bps)
            for m in moves:
                m.traffic = traffic_for_window(m.t_issue_lan, m.t_next_lan, gaps, replies, stalls, agg,
                                               intervals, cfg.budget)
        for m in moves:
            m.verdict, m.reasons = move_verdict(m, cfg.budget, cfg.traffic)
        summary = summarize(moves, cfg.traffic)
        self.log(format_table(moves, cfg.traffic))
        self.log("summary: " + json.dumps(summary, sort_keys=True))
        self._write({"preflight": info, "config": asdict(cfg), "summary": summary,
                     "moves": [asdict(m) for m in moves]})
        return summary["exit"]

    def _write(self, obj):
        if self.cfg.outdir:
            with open(os.path.join(self.cfg.outdir, "result.json"), "w") as f:
                json.dump(obj, f, indent=1, sort_keys=True, default=str)


def _env_float(name, default):
    v = os.environ.get(name, "")
    return float(v) if v else default


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fw0", required=True)
    ap.add_argument("--fw1", required=True)
    ap.add_argument("--lan", required=True)
    ap.add_argument("--target4", required=True)
    ap.add_argument("--outdir", required=True)
    a = ap.parse_args(argv)
    sleep_s = _env_float("SOAK_SLEEP", 5.0)
    budget = Budget(
        converge_s=_env_float("SOAK_CONVERGE_S", sleep_s),
        max_gap_ms=_env_float("SOAK_MAX_GAP_MS", 1000.0),
        max_stall_ms=_env_float("SOAK_MAX_STALL_MS", 2000.0),
        tail_s=_env_float("SOAK_TAIL_S", 1.0),
    )
    cfg = Config(
        moves=int(os.environ.get("SOAK_MOVES", "20")),
        sleep_s=sleep_s,
        rgs=os.environ.get("SOAK_RG", "2"),
        issuer=int(os.environ.get("SOAK_FROM", "0")),
        budget=budget,
        traffic=os.environ.get("SOAK_TRAFFIC", "1") != "0",
        helper_check=os.environ.get("SOAK_HELPER_CHECK", "1") != "0",
        target4=a.target4,
        iperf_port=int(os.environ.get("SOAK_IPERF_PORT", "5211")),
        iperf_streams=int(os.environ.get("SOAK_STREAMS", "8")),
        outdir=a.outdir,
        run_id=re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(a.outdir.rstrip("/"))),
    )
    if cfg.issuer not in (0, 1):
        print("SOAK_FROM must be 0 or 1", file=sys.stderr)
        return 2
    os.makedirs(cfg.outdir, exist_ok=True)
    print(f"rg-move-soak: {cfg.moves} moves of RG {cfg.rgs} from node{cfg.issuer} every {cfg.sleep_s:g}s; "
          f"converge<= {budget.converge_s:g}s gap<= {budget.max_gap_ms:g}ms stall<= {budget.max_stall_ms:g}ms; "
          f"traffic={'on' if cfg.traffic else 'off'}; out={cfg.outdir}")
    cluster = IncusCluster({0: a.fw0, 1: a.fw1}, a.lan)
    return Soak(cfg, cluster).run()


if __name__ == "__main__":
    sys.exit(main())
