#!/usr/bin/env python3
"""Validate the exact debug-leg registries against Cargo's live test census.

The live mode discovers every bin/test target from Cargo metadata, asks each
for both runnable and ignored libtest listings, and reconciles the resulting
(target-name, full-test-path) sets with the three checked-in registries.
Fixture mode is deliberately small and hermetic so the shell self-test can
exercise every fail-closed direction without compiling Cargo targets.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence

FAMILY_TOKENS = ("frame", "nat", "session", "checksum")
MAX_ARG_BYTES = 1 << 20
TARGET_KINDS = ("bin", "test")


class CensusError(RuntimeError):
    """A named fail-closed validator error."""


def key_text(key: tuple[str, str]) -> str:
    return f"{key[0]}\t{key[1]}"


def sample_keys(keys: Iterable[tuple[str, str]], limit: int = 12) -> str:
    values = sorted(key_text(key) for key in keys)
    if len(values) > limit:
        return ", ".join(values[:limit]) + f", ... ({len(values)} total)"
    return ", ".join(values) if values else "<none>"


def require_set_equal(label: str, actual: set[tuple[str, str]], expected: set[tuple[str, str]]) -> None:
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        raise CensusError(
            f"{label}: missing [{sample_keys(missing)}]; unexpected [{sample_keys(extra)}]"
        )


def parse_list_output(
    output: str, target: str, mode: str, allow_empty: bool = False
) -> set[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line_no, raw_line in enumerate(output.splitlines(), 1):
        line = raw_line.strip()
        if not line.endswith(": test"):
            continue
        path = line[: -len(": test")].strip()
        if not path:
            raise CensusError(f"{target} {mode}: empty test path at output line {line_no}")
        rows.append((target, path))
    if not rows:
        if mode == "--list":
            print(
                f"warning: {target} {mode}: no ': test' entries; treating target as empty",
                file=sys.stderr,
            )
            return set()
        if allow_empty:
            return set()
        raise CensusError(f"{target} {mode}: no ': test' entries; target/list parser or target is broken")
    parsed = set(rows)
    if len(parsed) != len(rows):
        duplicates = [key for key in rows if rows.count(key) > 1]
        raise CensusError(f"{target} {mode}: duplicate target/path entries [{sample_keys(set(duplicates))}]")
    return parsed


def cargo_command(cargo: str, toolchain: str, *args: str) -> list[str]:
    words = shlex.split(cargo)
    if not words:
        raise CensusError("cargo command is empty")
    return words + [f"+{toolchain}", *args]


def run_checked(command: Sequence[str], cwd: Path, label: str) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        tail = "\n".join(detail[-12:])
        raise CensusError(f"{label} failed (rc={result.returncode}):\n{tail}")
    return result.stdout


def discover_targets(metadata: Mapping[str, object], manifest: Path) -> list[tuple[str, str]]:
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise CensusError("cargo metadata has no packages array")
    manifest_resolved = manifest.resolve()
    package: Mapping[str, object] | None = None
    for candidate in packages:
        if not isinstance(candidate, dict):
            continue
        candidate_manifest = candidate.get("manifest_path")
        if isinstance(candidate_manifest, str) and Path(candidate_manifest).resolve() == manifest_resolved:
            package = candidate
            break
    if package is None:
        raise CensusError(f"cargo metadata has no package for {manifest}")
    raw_targets = package.get("targets")
    if not isinstance(raw_targets, list):
        raise CensusError("cargo metadata package has no targets array")
    targets: list[tuple[str, str]] = []
    for raw_target in raw_targets:
        if not isinstance(raw_target, dict):
            continue
        kinds = raw_target.get("kind")
        name = raw_target.get("name")
        if not isinstance(kinds, list) or not kinds or not isinstance(name, str):
            continue
        kind = kinds[0]
        if kind in TARGET_KINDS:
            targets.append((name, kind))
    names = [name for name, _kind in targets]
    if len(targets) != len(set(names)):
        duplicate_names = sorted(name for name in set(names) if names.count(name) > 1)
        raise CensusError(
            "target names are not unique across bin/test kinds; normalized two-column key is unsafe: "
            + ", ".join(duplicate_names)
        )
    if not targets:
        raise CensusError("cargo metadata discovered no bin/test targets")
    return sorted(targets)


def live_sets(root: Path, manifest: Path, cargo: str, toolchain: str) -> tuple[list[tuple[str, str]], set[tuple[str, str]], set[tuple[str, str]]]:
    metadata_text = run_checked(
        cargo_command(
            cargo,
            toolchain,
            "metadata",
            "--manifest-path",
            str(manifest),
            "--format-version",
            "1",
            "--no-deps",
        ),
        root,
        "cargo metadata",
    )
    try:
        metadata = json.loads(metadata_text)
    except json.JSONDecodeError as exc:
        raise CensusError(f"cargo metadata returned invalid JSON: {exc}") from exc
    targets = discover_targets(metadata, manifest)
    listed: set[tuple[str, str]] = set()
    ignored: set[tuple[str, str]] = set()
    for name, kind in targets:
        flag = "--bin" if kind == "bin" else "--test"
        for mode, extra in (("--list", ("--list",)), ("--list --ignored", ("--list", "--ignored"))):
            output = run_checked(
                cargo_command(
                    cargo,
                    toolchain,
                    "test",
                    "--manifest-path",
                    str(manifest),
                    flag,
                    name,
                    "--",
                    *extra,
                ),
                root,
                f"cargo {flag} {name} {mode}",
            )
            parsed = parse_list_output(output, name, mode, allow_empty=(mode == "--list --ignored"))
            if mode == "--list":
                listed |= parsed
            else:
                ignored |= parsed
    if not listed:
        raise CensusError("live census is empty: every target returned no runnable-or-ignored tests")
    return targets, listed, ignored


def fixture_sets(root: Path) -> tuple[list[tuple[str, str]], set[tuple[str, str]], set[tuple[str, str]]]:
    try:
        census = json.loads((root / "census.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CensusError(f"fixture census.json is unreadable: {exc}") from exc
    raw_targets = census.get("targets") if isinstance(census, dict) else None
    if not isinstance(raw_targets, list):
        raise CensusError("fixture census.json has no targets array")
    targets: list[tuple[str, str]] = []
    listed: set[tuple[str, str]] = set()
    ignored: set[tuple[str, str]] = set()
    for raw_target in raw_targets:
        if not isinstance(raw_target, dict):
            raise CensusError("fixture target is not an object")
        name = raw_target.get("name")
        kind = raw_target.get("kind")
        raw_listed = raw_target.get("listed")
        raw_ignored = raw_target.get("ignored")
        if not isinstance(name, str) or kind not in TARGET_KINDS:
            raise CensusError("fixture target needs string name and bin/test kind")
        if not isinstance(raw_listed, list) or not isinstance(raw_ignored, list):
            raise CensusError(f"fixture target {name} needs listed and ignored arrays")
        if any(not isinstance(path, str) for path in raw_listed):
            raise CensusError(f"fixture target {name} listed entries must be strings")
        if any(not isinstance(path, str) for path in raw_ignored):
            raise CensusError(f"fixture target {name} ignored entries must be strings")
        if name in {target_name for target_name, _kind in targets}:
            raise CensusError(f"fixture target name is duplicated: {name}")
        targets.append((name, kind))
        listed.update((name, path) for path in raw_listed)
        ignored.update((name, path) for path in raw_ignored)
    if not listed:
        raise CensusError("live census is empty: fixture has no listed tests")
    return sorted(targets), listed, ignored


def read_registry(path: Path, fields: int, label: str) -> tuple[set[tuple[str, str]], dict[tuple[str, str], str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CensusError(f"{label}: cannot read {path}: {exc}") from exc
    if not lines:
        raise CensusError(f"{label}: registry is empty: {path}")
    if lines != sorted(lines):
        raise CensusError(f"{label}: registry is unsorted: {path}")
    keys: set[tuple[str, str]] = set()
    reasons: dict[tuple[str, str], str] = {}
    for line_no, line in enumerate(lines, 1):
        parts = line.split("\t")
        if len(parts) != fields:
            raise CensusError(f"{label}: line {line_no} must have {fields} tab-separated columns")
        target, path_value = parts[0], parts[1]
        reason = parts[2].strip() if fields == 3 else ""
        if not target or not path_value:
            raise CensusError(f"{label}: line {line_no} has an empty target or test path")
        key = (target, path_value)
        if key in keys:
            raise CensusError(f"{label}: duplicate target/path entry {key_text(key)}")
        keys.add(key)
        reasons[key] = reason
        if fields == 3 and not reason:
            raise CensusError(f"{label}: line {line_no} has no reason for {key_text(key)}")
    return keys, reasons


def validate(root: Path, listed: set[tuple[str, str]], ignored: set[tuple[str, str]], targets: list[tuple[str, str]]) -> dict[str, int]:
    target_names = {name for name, _kind in targets}
    if ignored - listed:
        raise CensusError(f"ignored entries are absent from live listing: [{sample_keys(ignored - listed)}]")
    if not listed:
        raise CensusError("live census is empty: no target-qualified tests were listed")
    tests, _test_reasons = read_registry(root / "debug-leg.tests", 2, "debug-leg.tests")
    ignored_registry, ignored_reasons = read_registry(root / "debug-leg.ignored", 3, "debug-leg.ignored")
    excluded, excluded_reasons = read_registry(root / "debug-leg.excluded", 3, "debug-leg.excluded")
    for label, keys in (("debug-leg.tests", tests), ("debug-leg.ignored", ignored_registry), ("debug-leg.excluded", excluded)):
        unknown_targets = {key for key in keys if key[0] not in target_names}
        if unknown_targets:
            raise CensusError(f"{label}: unknown target names [{sample_keys(unknown_targets)}]")
    if any(not reason.startswith("MEASUREMENT:") for reason in ignored_reasons.values()):
        bad = [key for key, reason in ignored_reasons.items() if not reason.startswith("MEASUREMENT:")]
        raise CensusError(f"debug-leg.ignored: every reason must start with MEASUREMENT: [{sample_keys(bad)}]")
    if any(not reason for reason in excluded_reasons.values()):
        bad = [key for key, reason in excluded_reasons.items() if not reason]
        raise CensusError(f"debug-leg.excluded: every reason must be non-empty [{sample_keys(bad)}]")
    all_registry = tests | ignored_registry | excluded
    if len(all_registry) != len(tests) + len(ignored_registry) + len(excluded):
        raise CensusError("registries overlap: a target-qualified path appears in more than one registry")
    live = set(listed)
    runnable = live - ignored
    family = {key for key in live if any(token in key[1] for token in FAMILY_TOKENS)}
    family_ignored = family & ignored
    family_runnable = family & runnable
    if tests & ignored:
        raise CensusError(f"debug-leg.tests has missing/ignored entries: [{sample_keys(tests & ignored)}]")
    if excluded & ignored:
        raise CensusError(f"debug-leg.excluded has missing/ignored entries: [{sample_keys(excluded & ignored)}]")
    require_set_equal("ignored family equation X = F intersection I", family_ignored, ignored_registry)
    require_set_equal("family partition A union E = F intersection R", family_runnable, tests | excluded)
    if tests & excluded:
        raise CensusError(f"family partition A intersection E is non-empty: [{sample_keys(tests & excluded)}]")
    if tests - runnable:
        raise CensusError(f"debug-leg.tests has missing live entries: [{sample_keys(tests - runnable)}]")
    if excluded - runnable:
        raise CensusError(f"debug-leg.excluded has missing live entries: [{sample_keys(excluded - runnable)}]")
    raw_selected = {}
    for target, path_value in tests:
        raw_selected.setdefault(path_value, []).append(target)
    selected_collisions = {path_value: names for path_value, names in raw_selected.items() if len(names) > 1}
    if selected_collisions:
        detail = ", ".join(f"{path_value} ({','.join(sorted(names))})" for path_value, names in sorted(selected_collisions.items()))
        raise CensusError(f"selected target collision: raw paths appear in multiple targets: {detail}")
    raw_candidate = {}
    for target, path_value in family_runnable:
        raw_candidate.setdefault(path_value, []).append(target)
    candidate_collisions = {path_value: names for path_value, names in raw_candidate.items() if len(names) > 1}
    if candidate_collisions:
        detail = ", ".join(f"{path_value} ({','.join(sorted(names))})" for path_value, names in sorted(candidate_collisions.items()))
        raise CensusError(f"family candidate target collision: raw paths appear in multiple targets: {detail}")
    argv_bytes = sum(len(path_value.encode("utf-8")) + 1 for path_value in raw_candidate)
    if argv_bytes >= MAX_ARG_BYTES:
        raise CensusError(f"family candidate argv is {argv_bytes} bytes, at/above the 1 MiB bound")
    return {
        "targets": len(targets),
        "listed": len(live),
        "ignored": len(ignored),
        "family": len(family),
        "family_ignored": len(family_ignored),
        "family_runnable": len(family_runnable),
        "selected": len(tests),
        "excluded": len(excluded),
        "argv_bytes": argv_bytes,
    }


def run_self_test() -> None:
    parsed = parse_list_output("noise\nfoo::bar: test\n", "fixture", "--list")
    assert parsed == {("fixture", "foo::bar")}
    warning = io.StringIO()
    with contextlib.redirect_stderr(warning):
        empty = parse_list_output("noise\n", "fixture", "--list")
    assert empty == set()
    assert "warning:" in warning.getvalue()
    assert any(token in "afxdp::frame::tests::ok" for token in FAMILY_TOKENS)
    assert not any(token in "afxdp::control::tests::ok" for token in FAMILY_TOKENS)
    assert any(token in "afxdp::coordinator::tests::poll_timeout" for token in FAMILY_TOKENS)
    print("debug-leg census self-test: parser/classifier positive controls PASS")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, help="read census.json and registries from a hermetic fixture")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--manifest", type=Path, default=Path("userspace-dp/Cargo.toml"))
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("--toolchain", default=os.environ.get("XPF_RUST_TOOLCHAIN", ""))
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        try:
            run_self_test()
        except (AssertionError, CensusError) as exc:
            print(f"debug-leg census self-test: FAIL: {exc}", file=sys.stderr)
            return 1
        return 0
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    registry_root = args.fixture_root.resolve() if args.fixture_root else root / "userspace-dp"
    try:
        if args.fixture_root:
            targets, listed, ignored = fixture_sets(registry_root)
        else:
            if not args.toolchain:
                raise CensusError("--toolchain is required in live mode")
            targets, listed, ignored = live_sets(root, manifest.resolve(), args.cargo, args.toolchain)
        counts = validate(registry_root, listed, ignored, targets)
    except CensusError as exc:
        print(f"debug-leg census: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "debug-leg census: OK "
        f"{counts['targets']} targets; listed={counts['listed']}; ignored={counts['ignored']}; "
        f"F={counts['family']}; X={counts['family_ignored']}; "
        f"F∩R={counts['family_runnable']}; A={counts['selected']}; E={counts['excluded']}; "
        f"candidate_argv={counts['argv_bytes']} B"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
