#!/usr/bin/env python3
"""Validate issue #1321 surplus borrow/give-back phase artifacts.

Input is a JSON artifact with four named phases:

{
  "root_cap_mbps": 25000,
  "borrower_guarantee_mbps": 10000,
  "peer_guarantee_mbps": 10000,
  "handback_samples": [
    {"t_sec": 1.0, "throughput_mbps": {"borrower": 16000, "peer": 4000}},
    {"t_sec": 3.2, "throughput_mbps": {"borrower": 9000, "peer": 9800}}
  ],
  "phases": [
    {"name": "borrow_alone", "throughput_mbps": {"borrower": 18000, "peer": 0}},
    {"name": "peer_demand", "throughput_mbps": {"borrower": 17000, "peer": 4000}},
    {"name": "peer_steady", "throughput_mbps": {"borrower": 9000, "peer": 9800},
     "cos_admission_drops": {"peer": 0}},
    {"name": "peer_idle_reclaim", "throughput_mbps": {"borrower": 17800, "peer": 0}}
  ]
}

The script deliberately validates reduced artifacts only. It does not run
traffic; shell harnesses can feed it summaries from iperf, dataplane status,
or Prometheus as those live runners evolve.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any, Optional, Tuple


REQUIRED_PHASES = ("borrow_alone", "peer_demand", "peer_steady", "peer_idle_reclaim")


def _finite_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    out = float(value)
    if not math.isfinite(out):
        raise ValueError(f"{field} must be finite")
    return out


def _nonnegative_number(value: Any, field: str) -> float:
    out = _finite_number(value, field)
    if out < 0:
        raise ValueError(f"{field} must be non-negative")
    return out


def _positive_number(value: Any, field: str) -> float:
    out = _nonnegative_number(value, field)
    if out <= 0:
        raise ValueError(f"{field} must be positive")
    return out


def _phase_map(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    phases = artifact.get("phases")
    if not isinstance(phases, list):
        raise ValueError("phases must be a list")
    out: dict[str, dict[str, Any]] = {}
    for index, phase in enumerate(phases):
        if not isinstance(phase, dict):
            raise ValueError(f"phases[{index}] must be an object")
        name = phase.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"phases[{index}].name must be a non-empty string")
        if name in out:
            raise ValueError(f"duplicate phase name: {name}")
        out[name] = phase
    missing = [name for name in REQUIRED_PHASES if name not in out]
    if missing:
        raise ValueError(f"missing required phase(s): {', '.join(missing)}")
    return out


def _throughput(phase: dict[str, Any], role: str) -> float:
    throughputs = phase.get("throughput_mbps")
    if not isinstance(throughputs, dict):
        raise ValueError(f"phase {phase.get('name')}: throughput_mbps must be an object")
    return _nonnegative_number(throughputs.get(role), f"phase {phase.get('name')}: throughput_mbps.{role}")


def _drops(phase: dict[str, Any], role: str) -> float:
    drops = phase.get("cos_admission_drops", {})
    if drops is None:
        return 0.0
    if not isinstance(drops, dict):
        raise ValueError(f"phase {phase.get('name')}: cos_admission_drops must be an object")
    return _nonnegative_number(drops.get(role, 0), f"phase {phase.get('name')}: cos_admission_drops.{role}")


def _handback_from_samples(
    artifact: dict[str, Any],
    *,
    peer_guarantee: float,
    min_peer_guarantee_ratio: float,
    borrow_alone_bps: float,
    max_borrower_demand_ratio: float,
) -> Tuple[Optional[float], Optional[str]]:
    samples = artifact.get("handback_samples")
    if samples is None:
        return None, "missing_handback_samples"
    if not isinstance(samples, list) or not samples:
        raise ValueError("handback_samples must be a non-empty list when present")

    threshold_peer = peer_guarantee * min_peer_guarantee_ratio
    threshold_borrower = borrow_alone_bps * max_borrower_demand_ratio
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError(f"handback_samples[{index}] must be an object")
        t_sec = _nonnegative_number(sample.get("t_sec"), f"handback_samples[{index}].t_sec")
        throughputs = sample.get("throughput_mbps")
        if not isinstance(throughputs, dict):
            raise ValueError(f"handback_samples[{index}].throughput_mbps must be an object")
        borrower = _nonnegative_number(
            throughputs.get("borrower"),
            f"handback_samples[{index}].throughput_mbps.borrower",
        )
        peer = _nonnegative_number(
            throughputs.get("peer"),
            f"handback_samples[{index}].throughput_mbps.peer",
        )
        if peer >= threshold_peer and borrower <= threshold_borrower:
            return t_sec, "handback_samples"
    return None, "handback_samples_no_match"


def validate(
    artifact: dict[str, Any],
    *,
    min_peer_guarantee_ratio: float,
    min_peer_demand_ratio: float,
    min_borrower_borrow_ratio: float,
    max_handback_sec: float,
    max_borrower_demand_ratio: float,
    min_reclaim_ratio: float,
    min_reclaim_alone_ratio: float,
    root_cap_tolerance_ratio: float,
    max_peer_steady_drops: float,
) -> dict[str, Any]:
    phases = _phase_map(artifact)
    root_cap = _nonnegative_number(artifact.get("root_cap_mbps"), "root_cap_mbps")
    borrower_guarantee = _positive_number(
        artifact.get("borrower_guarantee_mbps"),
        "borrower_guarantee_mbps",
    )
    peer_guarantee = _positive_number(artifact.get("peer_guarantee_mbps"), "peer_guarantee_mbps")

    borrow_alone = phases["borrow_alone"]
    peer_demand = phases["peer_demand"]
    peer_steady = phases["peer_steady"]
    reclaim = phases["peer_idle_reclaim"]

    borrow_alone_bps = _throughput(borrow_alone, "borrower")
    peer_demand_peer = _throughput(peer_demand, "peer")
    steady_borrower = _throughput(peer_steady, "borrower")
    steady_peer = _throughput(peer_steady, "peer")
    reclaim_borrower = _throughput(reclaim, "borrower")
    steady_peer_drops = _drops(peer_steady, "peer")
    handback, handback_source = _handback_from_samples(
        artifact,
        peer_guarantee=peer_guarantee,
        min_peer_guarantee_ratio=min_peer_guarantee_ratio,
        borrow_alone_bps=borrow_alone_bps,
        max_borrower_demand_ratio=max_borrower_demand_ratio,
    )
    if handback is None:
        handback = max_handback_sec + 1.0

    failures: list[str] = []
    if borrow_alone_bps < borrower_guarantee * min_borrower_borrow_ratio:
        failures.append(
            f"borrower alone throughput {borrow_alone_bps:.3f} Mbps does not prove surplus borrow: "
            f"below {min_borrower_borrow_ratio:.3f} * guarantee {borrower_guarantee:.3f} Mbps"
        )
    # `peer_demand` is a liveness/audit phase, not the guarantee-service
    # verdict. The real service gate is `peer_steady` plus the handback
    # timing evidence. Keep this default low enough that a legitimate
    # in-transition sample does not fail merely because handback has not
    # completed yet, while still rejecting decorative all-zero demand.
    if peer_demand_peer < peer_guarantee * min_peer_demand_ratio:
        failures.append(
            f"peer demand throughput {peer_demand_peer:.3f} Mbps below "
            f"{min_peer_demand_ratio:.3f} * guarantee {peer_guarantee:.3f} Mbps"
        )
    if steady_peer < peer_guarantee * min_peer_guarantee_ratio:
        failures.append(
            f"peer steady throughput {steady_peer:.3f} Mbps below "
            f"{min_peer_guarantee_ratio:.3f} * guarantee {peer_guarantee:.3f} Mbps"
        )
    if handback > max_handback_sec:
        failures.append(
            f"handback window {handback:.3f}s exceeds {max_handback_sec:.3f}s"
        )
    if handback_source == "handback_samples_no_match":
        failures.append(
            "handback_samples never show peer guarantee restored while borrower gave back surplus"
        )
    if handback_source == "missing_handback_samples":
        failures.append(
            "handback_samples are required; scalar handback evidence is not auditable"
        )
    if steady_borrower > borrow_alone_bps * max_borrower_demand_ratio:
        failures.append(
            f"borrower did not give back surplus: steady {steady_borrower:.3f} Mbps "
            f"> {max_borrower_demand_ratio:.3f} * alone {borrow_alone_bps:.3f} Mbps"
        )
    if reclaim_borrower < steady_borrower * min_reclaim_ratio:
        failures.append(
            f"borrower did not reclaim surplus: reclaim {reclaim_borrower:.3f} Mbps "
            f"< {min_reclaim_ratio:.3f} * steady {steady_borrower:.3f} Mbps"
        )
    if reclaim_borrower < borrow_alone_bps * min_reclaim_alone_ratio:
        failures.append(
            f"borrower reclaim {reclaim_borrower:.3f} Mbps is not near borrow-alone "
            f"{borrow_alone_bps:.3f} Mbps: below {min_reclaim_alone_ratio:.3f} * alone"
        )
    if steady_peer_drops > max_peer_steady_drops:
        failures.append(
            f"peer steady CoS admission drops {steady_peer_drops:.0f} exceed "
            f"{max_peer_steady_drops:.0f}"
        )

    cap_limit = root_cap * (1.0 + root_cap_tolerance_ratio)
    phase_totals: dict[str, float] = {}
    for name in REQUIRED_PHASES:
        total = _throughput(phases[name], "borrower") + _throughput(phases[name], "peer")
        phase_totals[name] = total
        if total > cap_limit:
            failures.append(
                f"phase {name} total {total:.3f} Mbps exceeds root cap "
                f"{root_cap:.3f} Mbps with tolerance {root_cap_tolerance_ratio:.3f}"
            )

    return {
        "verdict": "PASS" if not failures else "FAIL",
        "failure_reasons": failures,
        "thresholds": {
            "min_peer_guarantee_ratio": min_peer_guarantee_ratio,
            "min_peer_demand_ratio": min_peer_demand_ratio,
            "min_borrower_borrow_ratio": min_borrower_borrow_ratio,
            "max_handback_sec": max_handback_sec,
            "max_borrower_demand_ratio": max_borrower_demand_ratio,
            "min_reclaim_ratio": min_reclaim_ratio,
            "min_reclaim_alone_ratio": min_reclaim_alone_ratio,
            "root_cap_tolerance_ratio": root_cap_tolerance_ratio,
            "max_peer_steady_drops": max_peer_steady_drops,
        },
        "metrics": {
            "borrow_alone_borrower_mbps": borrow_alone_bps,
            "peer_demand_peer_mbps": peer_demand_peer,
            "peer_steady_borrower_mbps": steady_borrower,
            "peer_steady_peer_mbps": steady_peer,
            "peer_idle_reclaim_borrower_mbps": reclaim_borrower,
            "peer_steady_drops": steady_peer_drops,
            "handback_window_sec": handback,
            "handback_source": handback_source,
            "phase_total_mbps": phase_totals,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--min-peer-guarantee-ratio", type=float, default=0.95)
    parser.add_argument(
        "--min-peer-demand-ratio",
        type=float,
        default=0.01,
        help=(
            "minimum peer-demand phase throughput as a fraction of peer guarantee; "
            "this is a liveness proxy, while peer_steady/handback enforce service"
        ),
    )
    parser.add_argument("--min-borrower-borrow-ratio", type=float, default=1.05)
    parser.add_argument("--max-handback-sec", type=float, default=5.0)
    parser.add_argument("--max-borrower-demand-ratio", type=float, default=0.90)
    parser.add_argument("--min-reclaim-ratio", type=float, default=1.10)
    parser.add_argument("--min-reclaim-alone-ratio", type=float, default=0.90)
    parser.add_argument("--root-cap-tolerance-ratio", type=float, default=0.02)
    parser.add_argument("--max-peer-steady-drops", type=float, default=0.0)
    args = parser.parse_args()

    with open(args.input) as f:
        artifact = json.load(f)
    verdict = validate(
        artifact,
        min_peer_guarantee_ratio=args.min_peer_guarantee_ratio,
        min_peer_demand_ratio=args.min_peer_demand_ratio,
        min_borrower_borrow_ratio=args.min_borrower_borrow_ratio,
        max_handback_sec=args.max_handback_sec,
        max_borrower_demand_ratio=args.max_borrower_demand_ratio,
        min_reclaim_ratio=args.min_reclaim_ratio,
        min_reclaim_alone_ratio=args.min_reclaim_alone_ratio,
        root_cap_tolerance_ratio=args.root_cap_tolerance_ratio,
        max_peer_steady_drops=args.max_peer_steady_drops,
    )
    with open(args.out, "w") as f:
        json.dump(verdict, f, indent=2, sort_keys=True)
    return 0 if verdict["verdict"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as exc:
        print(f"fairness_surplus_giveback_validate: {exc}", file=sys.stderr)
        sys.exit(2)
