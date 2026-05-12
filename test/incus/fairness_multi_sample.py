#!/usr/bin/env python3
"""Run fairness-harness repeatedly and summarize per-run CoV variance."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
from typing import Any


DEFAULT_SAMPLES = 5
DEFAULT_MAX_MEAN_COV = 0.15
DEFAULT_MAX_STDEV_COV = 0.03
DEFAULT_MAX_RUN_COV = 0.25
DEFAULT_PER_RUN_TIMEOUT_SEC = 600


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
    return [obj for obj in extract_json_objects(text) if "verdict" in obj]


def numeric_field(verdict: dict[str, Any], key: str) -> float:
    value = verdict.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MultiSampleError(f"verdict JSON missing numeric field {key!r}")
    number = float(value)
    if not math.isfinite(number):
        raise MultiSampleError(f"verdict JSON field {key!r} is not finite")
    if number < 0:
        raise MultiSampleError(f"verdict JSON field {key!r} is negative")
    return number


def timeout_stream_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def sample_record(index: int, sample_dir: Path, exit_code: int, verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample": index,
        "sample_dir": str(sample_dir),
        "exit_code": exit_code,
        "verdict": verdict.get("verdict"),
        "observed_cov": numeric_field(verdict, "observed_cov"),
        "cstruct": verdict.get("cstruct"),
        "gap": verdict.get("gap"),
        "aggregate_mbps": verdict.get("aggregate_mbps"),
        "starved_flow_count": verdict.get("starved_flow_count"),
        "failure_reasons": verdict.get("failure_reasons", []),
    }


def summarize(
    samples: list[dict[str, Any]],
    *,
    max_mean_cov: float,
    max_stdev_cov: float,
    max_run_cov: float,
) -> dict[str, Any]:
    observed_covs = [float(s["observed_cov"]) for s in samples]
    mean_cov = statistics.fmean(observed_covs)
    stdev_cov = statistics.stdev(observed_covs) if len(observed_covs) > 1 else 0.0
    max_cov = max(observed_covs)
    min_cov = min(observed_covs)

    failure_reasons: list[str] = []
    failing_samples = [s["sample"] for s in samples if s.get("verdict") != "PASS"]
    if failing_samples:
        failure_reasons.append(f"sample verdicts failed: {failing_samples}")
    if mean_cov > max_mean_cov:
        failure_reasons.append(
            f"mean observed_cov {mean_cov:.6f} exceeds threshold {max_mean_cov:.6f}"
        )
    if stdev_cov > max_stdev_cov:
        failure_reasons.append(
            f"sample stdev observed_cov {stdev_cov:.6f} exceeds threshold {max_stdev_cov:.6f}"
        )
    if max_cov > max_run_cov:
        failure_reasons.append(
            f"max observed_cov {max_cov:.6f} exceeds threshold {max_run_cov:.6f}"
        )

    return {
        "verdict": "PASS" if not failure_reasons else "FAIL",
        "sample_count": len(samples),
        "thresholds": {
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
        "samples": samples,
        "failure_reasons": failure_reasons,
    }


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
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                check=False,
                timeout=args.per_run_timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            (sample_dir / "stdout.log").write_text(
                timeout_stream_text(exc.stdout),
                encoding="utf-8",
            )
            (sample_dir / "stderr.log").write_text(
                timeout_stream_text(exc.stderr),
                encoding="utf-8",
            )
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
            ) from exc

        (sample_dir / "stdout.log").write_text(proc.stdout, encoding="utf-8")
        (sample_dir / "stderr.log").write_text(proc.stderr, encoding="utf-8")
        (sample_dir / "command.json").write_text(
            json.dumps(
                {
                    "argv": cmd,
                    "exit_code": proc.returncode,
                    "timeout_sec": args.per_run_timeout_sec,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        if proc.returncode not in (0, 1):
            raise MultiSampleError(
                f"sample {index} harness exited {proc.returncode}; see {sample_dir}"
            )

        objects = extract_verdict_objects(proc.stdout)
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
        samples.append(sample_record(index, sample_dir, proc.returncode, verdict))

    summary = summarize(
        samples,
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
        description="Run fairness-harness N times and summarize observed CoV stability.",
    )
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--harness", type=Path, default=default_harness)
    parser.add_argument("--max-mean-cov", type=parse_ratio, default=DEFAULT_MAX_MEAN_COV)
    parser.add_argument("--max-stdev-cov", type=parse_ratio, default=DEFAULT_MAX_STDEV_COV)
    parser.add_argument("--max-run-cov", type=parse_ratio, default=DEFAULT_MAX_RUN_COV)
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
