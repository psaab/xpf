#!/usr/bin/env python3
"""Fail-closed census of kernel-mutating Go test sources in guarded packages."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PACKAGES = (
    "pkg/daemon",
    "pkg/dataplane",
    "pkg/dataplane/userspace",
    "pkg/flowexport",
    "pkg/lldp",
    "pkg/nftables",
    "pkg/ra",
    "pkg/routing",
    "pkg/snmp",
)
MARKERS = {
    "netlink": re.compile(
        r"\bnetlink\.(?:LinkAdd|LinkDel|LinkSet[A-Z]\w*|"
        r"Addr(?:Add|Del|Replace)|Route(?:Add|Del|Replace)|"
        r"Rule(?:Add|Del|Replace)|Neigh(?:Add|Del|Replace))\b"
    ),
    "nft": re.compile(
        r"\b(?:NewNetlinkInstaller|nftables\.New|gnft\.New)\s*\(|"
        r"(?:exec\.)?Command(?:Context)?\([^\n]*\"nft\"|"
        r"\.Install(?:HostInbound|Lo0|TransitBarrier|ArmedTransitFence)\s*\("
    ),
    "bpf": re.compile(
        r"\b(?:ebpf\.(?:NewMap|NewMapWithOptions|NewProgram|"
        r"LoadCollection|LoadAndAssign)|unix\.SYS_BPF|BPF_MAP_CREATE)\b"
    ),
}


def package_candidates(root: Path) -> tuple[dict[str, tuple[str, ...]], list[str]]:
    candidates: dict[str, tuple[str, ...]] = {}
    errors: list[str] = []
    for package in PACKAGES:
        directory = root / package
        if not directory.is_dir():
            errors.append(f"missing guarded package directory: {package}")
            continue
        sources = sorted(directory.glob("*_test.go"))
        if not sources:
            errors.append(f"no Go test sources in guarded package: {package}")
        mains = []
        guarded = False
        for source in sources:
            text = source.read_text(encoding="utf-8")
            if re.search(r"\bfunc\s+TestMain\s*\(", text):
                mains.append(source)
            if "testguard.ExitIfUnsafe()" in text:
                guarded = True
            classes = tuple(name for name, marker in MARKERS.items() if marker.search(text))
            if classes:
                candidates[source.relative_to(root).as_posix()] = classes
        if not mains or not guarded:
            errors.append(
                f"{package}: TestMain must call testguard.ExitIfUnsafe() before tests"
            )
    return candidates, errors


def expected_row(path: str, classes: tuple[str, ...]) -> tuple[str, str, str, str]:
    class_text = "+".join(classes)
    isolation = "private-net+mount"
    proof = "package-TestMain:testguard.ExitIfUnsafe;testguard-run"
    if "bpf" in classes:
        proof += ";vm-test-root-for-privileged-map-cells"
    return path, class_text, isolation, proof


def read_tsv(path: Path, columns: int) -> tuple[list[tuple[str, ...]], list[str]]:
    errors: list[str] = []
    rows: list[tuple[str, ...]] = []
    if not path.is_file():
        return rows, [f"missing registry/floors file: {path}"]
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        row = tuple(line.split("\t"))
        if len(row) != columns or any(not item for item in row):
            errors.append(f"{path}:{number}: expected {columns} nonempty TSV columns")
            continue
        rows.append(row)
    return rows, errors


def check(root: Path) -> tuple[list[str], dict[str, int], int]:
    errors: list[str] = []
    candidates, package_errors = package_candidates(root)
    errors.extend(package_errors)
    registry_path = root / "test/host-mutation-census.tsv"
    registry_rows, registry_errors = read_tsv(registry_path, 4)
    errors.extend(registry_errors)
    actual: dict[str, tuple[str, str, str]] = {}
    for path, class_text, isolation, proof in registry_rows:
        if path in actual:
            errors.append(f"duplicate registry path: {path}")
            continue
        actual[path] = (class_text, isolation, proof)

    expected = {path: expected_row(path, classes)[1:] for path, classes in candidates.items()}
    for path in sorted(expected.keys() - actual.keys()):
        errors.append(f"unregistered host-mutation test source: {path}")
    for path in sorted(actual.keys() - expected.keys()):
        errors.append(f"stale/non-mutating registry row: {path}")
    for path in sorted(expected.keys() & actual.keys()):
        if actual[path] != expected[path]:
            errors.append(
                f"{path}: registry metadata drift; expected {expected[path]!r}, got {actual[path]!r}"
            )

    counts: dict[str, int] = {}
    for classes in candidates.values():
        for name in classes:
            counts[name] = counts.get(name, 0) + 1
    floor_rows, floor_errors = read_tsv(root / "scripts/host-mutation-census.floors", 2)
    errors.extend(floor_errors)
    floors: dict[str, int] = {}
    for name, count_text in floor_rows:
        if name in floors:
            errors.append(f"duplicate class floor: {name}")
            continue
        if not count_text.isdecimal():
            errors.append(f"invalid class floor for {name}: {count_text!r}")
            continue
        floors[name] = int(count_text)
    for name in sorted(set(counts) | set(floors)):
        count, floor = counts.get(name, 0), floors.get(name)
        if floor is None:
            errors.append(f"missing floor for discovered mutation class {name}")
        elif count < floor:
            errors.append(f"{name} census below floor: found {count}, requires at least {floor}")
        elif name not in counts:
            errors.append(f"class floor has no corresponding source candidates: {name}")
    return errors, counts, len(candidates)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--list", action="store_true", help="print detected registry rows")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.list:
        candidates, package_errors = package_candidates(root)
        for path, classes in sorted(candidates.items()):
            print("\t".join(expected_row(path, classes)))
        for error in package_errors:
            print(f"ERROR\t{error}", file=sys.stderr)
        return 1 if package_errors else 0
    errors, counts, total = check(root)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "host-mutation census: "
        + ", ".join(f"{name}={counts[name]}" for name in sorted(counts))
        + f"; {total} registered Go test sources; package guards and bidirectional floors PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
