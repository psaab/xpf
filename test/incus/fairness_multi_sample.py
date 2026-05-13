#!/usr/bin/env python3
"""Run fairness-harness repeatedly and summarize per-run fairness contract."""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
from pathlib import Path
import statistics
import subprocess
import sys
from typing import Any


DEFAULT_SAMPLES = 5
DEFAULT_MAX_MEAN_GAP = 0.05
DEFAULT_MAX_RUN_GAP = 0.05
DEFAULT_MAX_MEAN_COV: float | None = None
DEFAULT_MAX_STDEV_COV: float | None = None
DEFAULT_MAX_RUN_COV: float | None = None
DEFAULT_PER_RUN_TIMEOUT_SEC = 600
POST_KILL_COMMUNICATE_TIMEOUT_SEC = 5
FAIRNESS_EVAL_VERDICT_KEYS = {
    "verdict",
    "observed_cov",
    "cstruct",
    "gap",
    "failure_reasons",
    "distribution_a_i",
    "n_active",
    "saturated",
    "a_i_sum_check_ok",
    "starved_flow_count",
}


class MultiSampleError(RuntimeError):
    pass


def parse_ratio(raw: str) -> float:
    raw = raw.strip()
    if raw.endswith("%"):
        value = float(raw[:-1]) / 100.0
    else:
        value = float(raw)
    if not math.isfinite(value):
        raise argparse.ArgumentTypeError(f"ratio is not finite: {raw!r}")
    if value < 0:
        raise argparse.ArgumentTypeError(f"ratio must be non-negative: {raw!r}")
    return value


def optional_ratio(raw: str) -> float | None:
    if raw.strip().lower() in {"none", "off", "disabled"}:
        return None
    return parse_ratio(raw)


def extract_json_objects(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    idx = 0
    while idx < len(text):
        start = text.find("{", idx)
        if start < 0:
            break
        try:
            obj, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            idx = start + 1
            continue
        if isinstance(obj, dict):
            objects.append(obj)
        idx = start + end
    return objects


def extract_verdict_objects(text: str) -> list[dict[str, Any]]:
    return [
        obj for obj in extract_json_objects(text)
        if FAIRNESS_EVAL_VERDICT_KEYS.issubset(obj)
    ]


def stream_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def numeric_field(verdict: dict[str, Any], key: str, *, allow_negative: bool = False) -> float:
    value = verdict.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MultiSampleError(f"verdict JSON missing numeric field {key!r}")
    number = float(value)
    if not math.isfinite(number):
        raise MultiSampleError(f"verdict JSON field {key!r} is not finite")
    if not allow_negative and number < 0:
        raise MultiSampleError(f"verdict JSON field {key!r} is negative")
    return number


def optional_numeric_field(verdict: dict[str, Any], key: str) -> float | None:
    if key not in verdict or verdict[key] is None:
        return None
    return numeric_field(verdict, key)


def integer_field(verdict: dict[str, Any], key: str) -> int:
    value = verdict.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise MultiSampleError(f"verdict JSON missing integer field {key!r}")
    if value < 0:
        raise MultiSampleError(f"verdict JSON field {key!r} is negative")
    return value


def sample_record(index: int, sample_dir: Path, exit_code: int, verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample": index,
        "sample_dir": str(sample_dir),
        "exit_code": exit_code,
        "verdict": verdict.get("verdict"),
        "observed_cov": numeric_field(verdict, "observed_cov"),
        "cstruct": numeric_field(verdict, "cstruct"),
        "gap": numeric_field(verdict, "gap", allow_negative=True),
        "aggregate_mbps": optional_numeric_field(verdict, "aggregate_mbps"),
        "starved_flow_count": integer_field(verdict, "starved_flow_count"),
        "failure_reasons": verdict.get("failure_reasons", []),
    }


def summarize(
    samples: list[dict[str, Any]],
    *,
    max_mean_gap: float,
    max_run_gap: float,
    max_mean_cov: float | None,
    max_stdev_cov: float | None,
    max_run_cov: float | None,
) -> dict[str, Any]:
    if not samples:
        raise MultiSampleError("no samples")

    observed_covs = [float(s["observed_cov"]) for s in samples]
    cstructs = [float(s["cstruct"]) for s in samples]
    gaps = [float(s["gap"]) for s in samples]

    mean_cov = statistics.mean(observed_covs)
    stdev_cov = statistics.stdev(observed_covs) if len(observed_covs) > 1 else 0.0
    max_cov = max(observed_covs)
    min_cov = min(observed_covs)

    mean_cstruct = statistics.mean(cstructs)
    stdev_cstruct = statistics.stdev(cstructs) if len(cstructs) > 1 else 0.0
    max_cstruct = max(cstructs)
    min_cstruct = min(cstructs)

    mean_gap = statistics.mean(gaps)
    stdev_gap = statistics.stdev(gaps) if len(gaps) > 1 else 0.0
    max_gap = max(gaps)
    min_gap = min(gaps)

    failure_reasons: list[str] = []
    failing_samples = [s["sample"] for s in samples if s.get("verdict") != "PASS"]
    if failing_samples:
        failure_reasons.append(f"sample verdicts failed: {failing_samples}")
    if mean_gap > max_mean_gap:
        failure_reasons.append(
            f"mean gap {mean_gap:.6f} exceeds threshold {max_mean_gap:.6f}"
        )
    if max_gap > max_run_gap:
        failure_reasons.append(
            f"max gap {max_gap:.6f} exceeds threshold {max_run_gap:.6f}"
        )
    if max_mean_cov is not None and mean_cov > max_mean_cov:
        failure_reasons.append(
            f"mean observed_cov {mean_cov:.6f} exceeds threshold {max_mean_cov:.6f}"
        )
    if max_stdev_cov is not None and stdev_cov > max_stdev_cov:
        failure_reasons.append(
            f"sample stdev observed_cov {stdev_cov:.6f} exceeds threshold {max_stdev_cov:.6f}"
        )
    if max_run_cov is not None and max_cov > max_run_cov:
        failure_reasons.append(
            f"max observed_cov {max_cov:.6f} exceeds threshold {max_run_cov:.6f}"
        )

    return {
        "verdict": "PASS" if not failure_reasons else "FAIL",
        "sample_count": len(samples),
        "thresholds": {
            "max_mean_gap": max_mean_gap,
            "max_run_gap": max_run_gap,
            "max_mean_cov": max_mean_cov,
            "max_sample_stdev_cov": max_stdev_cov,
            "max_run_cov": max_run_cov,
        },
        "observed_cov": {
            "mean": mean_cov,
            "sample_stdev": stdev_cov,
            "min": min_cov,
            "max": max_cov,
        },
        "cstruct": {
            "mean": mean_cstruct,
            "sample_stdev": stdev_cstruct,
            "min": min_cstruct,
            "max": max_cstruct,
        },
        "gap": {
            "mean": mean_gap,
            "sample_stdev": stdev_gap,
            "min": min_gap,
            "max": max_gap,
        },
        "samples": samples,
        "failure_reasons": failure_reasons,
    }


def _kill_process_group(pgid: int) -> None:
    """Send SIGTERM then SIGKILL to a process group to clean up all descendants.

    SIGTERM is sent first as a courtesy, then SIGKILL immediately follows.
    There is no grace-period delay between them because this function is only
    called on a CI timeout abort — the harness has already exceeded its time
    budget and we need it dead fast to avoid tying up ports for subsequent runs.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return


def run_samples(args: argparse.Namespace) -> dict[str, Any]:
    harness_args = list(args.harness_args)
    if harness_args and harness_args[0] == "--":
        harness_args = harness_args[1:]

    out_dir = args.out_dir
    if out_dir.exists():
        raise MultiSampleError(f"--out-dir already exists: {out_dir}")
    out_dir.mkdir(parents=True)

    samples: list[dict[str, Any]] = []
    width = len(str(args.samples))
    for index in range(1, args.samples + 1):
        sample_dir = out_dir / f"sample-{index:0{width}d}"
        sample_dir.mkdir()
        artifact_dir = sample_dir / "artifacts"
        artifact_dir.mkdir()

        env = os.environ.copy()
        env["ARTIFACT_DIR"] = str(artifact_dir)
        cmd = [str(args.harness), *harness_args]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        # Capture pgid immediately after Popen while proc.pid is guaranteed
        # alive. We cannot use proc.pid later because Python's communicate()
        # loop may internally reap the leader via waitpid(WNOHANG) before
        # TimeoutExpired fires (e.g. when the shell exits early but a child
        # keeps the pipe open). The pgid remains valid for os.killpg as long
        # as any group member is alive, which is exactly our target.
        pgid = os.getpgid(proc.pid)
        timed_out = False
        try:
            stdout_text, stderr_text = proc.communicate(timeout=args.per_run_timeout_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(pgid)
            try:
                stdout_text, stderr_text = proc.communicate(
                    timeout=POST_KILL_COMMUNICATE_TIMEOUT_SEC
                )
            except subprocess.TimeoutExpired as exc:
                _kill_process_group(pgid)
                stdout_text = stream_text(exc.stdout)
                stderr_text = stream_text(exc.stderr)
        exit_code = proc.returncode

        (sample_dir / "stdout.log").write_text(stdout_text, encoding="utf-8")
        (sample_dir / "stderr.log").write_text(stderr_text, encoding="utf-8")
        if timed_out:
            (sample_dir / "command.json").write_text(
                json.dumps(
                    {
                        "argv": cmd,
                        "exit_code": None,
                        "timeout_sec": args.per_run_timeout_sec,
                        "timed_out": True,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            raise MultiSampleError(
                f"sample {index} harness timed out after {args.per_run_timeout_sec}s; "
                f"see {sample_dir}"
            )
        (sample_dir / "command.json").write_text(
            json.dumps(
                {
                    "argv": cmd,
                    "exit_code": exit_code,
                    "timeout_sec": args.per_run_timeout_sec,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        if exit_code not in (0, 1):
            raise MultiSampleError(
                f"sample {index} harness exited {exit_code}; see {sample_dir}"
            )

        objects = extract_verdict_objects(stdout_text)
        if len(objects) != 1:
            raise MultiSampleError(
                f"sample {index} expected exactly one verdict JSON, found {len(objects)}; "
                f"mixed-CoS or missing-verdict output is not supported by this wrapper yet"
            )
        verdict = objects[0]
        (sample_dir / "verdict.json").write_text(
            json.dumps(verdict, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        samples.append(sample_record(index, sample_dir, exit_code, verdict))

    summary = summarize(
        samples,
        max_mean_gap=args.max_mean_gap,
        max_run_gap=args.max_run_gap,
        max_mean_cov=args.max_mean_cov,
        max_stdev_cov=args.max_stdev_cov,
        max_run_cov=args.max_run_cov,
    )
    summary["out_dir"] = str(out_dir)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    default_harness = Path(__file__).with_name("fairness-harness.sh")
    parser = argparse.ArgumentParser(
        description="Run fairness-harness N times and summarize Cstruct-aware fairness.",
    )
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--harness", type=Path, default=default_harness)
    parser.add_argument(
        "--max-mean-gap",
        type=parse_ratio,
        default=DEFAULT_MAX_MEAN_GAP,
        help="Maximum allowed mean observed_cov-cstruct gap across samples.",
    )
    parser.add_argument(
        "--max-run-gap",
        type=parse_ratio,
        default=DEFAULT_MAX_RUN_GAP,
        help="Maximum allowed observed_cov-cstruct gap in any sample.",
    )
    parser.add_argument(
        "--max-mean-cov",
        type=optional_ratio,
        default=DEFAULT_MAX_MEAN_COV,
        help="Optional absolute mean observed_cov gate; default disabled.",
    )
    parser.add_argument(
        "--max-stdev-cov",
        type=optional_ratio,
        default=DEFAULT_MAX_STDEV_COV,
        help="Optional absolute observed_cov sample-stdev gate; default disabled.",
    )
    parser.add_argument(
        "--max-run-cov",
        type=optional_ratio,
        default=DEFAULT_MAX_RUN_COV,
        help="Optional absolute per-run observed_cov gate; default disabled.",
    )
    parser.add_argument(
        "--per-run-timeout-sec",
        type=int,
        default=DEFAULT_PER_RUN_TIMEOUT_SEC,
        help="Hard timeout for each fairness-harness run.",
    )
    parser.add_argument(
        "harness_args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to fairness-harness.sh. Prefix with -- to separate.",
    )
    args = parser.parse_args(argv)
    if args.samples < 2:
        parser.error("--samples must be >= 2")
    if args.per_run_timeout_sec <= 0:
        parser.error("--per-run-timeout-sec must be > 0")
    if not args.harness.exists():
        parser.error(f"--harness does not exist: {args.harness}")
    if not os.access(args.harness, os.X_OK):
        parser.error(f"--harness is not executable: {args.harness}")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        summary = run_samples(args)
    except MultiSampleError as exc:
        print(f"fairness-multi-sample: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
