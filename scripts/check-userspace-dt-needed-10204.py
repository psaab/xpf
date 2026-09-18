#!/usr/bin/env python3
"""Verify #10204's static snapshot linkage and dynamic dependency boundary.

Usage:
    check-userspace-dt-needed-10204.py BINARY LINKER_MAP

The three libxpf*.a files are static archives and therefore must not appear in
DT_NEEDED. The linker map is the proof that they supplied the linked members;
DT_NEEDED is checked independently for accidental shared libelf/libz/libzstd
leakage through a transitive dependency.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SNAPSHOT_MEMBER_RE = {
    "libxpfelf.a": re.compile(r"\blibxpfelf\.a\([^)]*\)"),
    "libxpfz.a": re.compile(r"\blibxpfz\.a\([^)]*\)"),
    "libxpfzstd.a": re.compile(r"\blibxpfzstd\.a\([^)]*\)"),
}
BARE_ARCHIVE_RE = {
    "libelf.a": re.compile(r"\blibelf\.a\([^)]*\)"),
    "libz.a": re.compile(r"\blibz\.a\([^)]*\)"),
    "libzstd.a": re.compile(r"\blibzstd\.a\([^)]*\)"),
}
NEEDED_RE = re.compile(r"\(NEEDED\).*?Shared library: \[([^]]+)\]")
BARE_SHARED_RE = re.compile(r"^lib(?:elf|z|zstd)\.so(?:$|\.)")


def read_needed(binary: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["readelf", "-d", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("#10204: readelf is required to inspect DT_NEEDED") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"#10204: readelf -d failed for {binary}: {exc.stderr.strip()}"
        ) from exc
    return NEEDED_RE.findall(result.stdout)


def verify(binary: Path, linker_map: Path) -> None:
    if not binary.is_file():
        raise SystemExit(f"#10204: binary does not exist: {binary}")
    if not linker_map.is_file():
        raise SystemExit(f"#10204: linker map does not exist: {linker_map}")

    needed = read_needed(binary)
    leaked = [name for name in needed if BARE_SHARED_RE.match(name)]
    if leaked:
        raise SystemExit(
            "#10204: forbidden host shared dependencies in DT_NEEDED: "
            + ", ".join(leaked)
        )

    map_text = linker_map.read_text(encoding="utf-8", errors="replace")
    snapshot_counts = {
        archive: len(pattern.findall(map_text))
        for archive, pattern in SNAPSHOT_MEMBER_RE.items()
    }
    bare_counts = {
        archive: len(pattern.findall(map_text))
        for archive, pattern in BARE_ARCHIVE_RE.items()
    }
    missing = [archive for archive, count in snapshot_counts.items() if count == 0]
    if missing:
        raise SystemExit(
            "#10204: linker map has no members from required snapshot archive(s): "
            + ", ".join(missing)
        )
    leaked_archives = [archive for archive, count in bare_counts.items() if count]
    if leaked_archives:
        raise SystemExit(
            "#10204: linker map contains members from bare host archive(s): "
            + ", ".join(f"{archive} ({bare_counts[archive]})" for archive in leaked_archives)
        )

    print("#10204: DT_NEEDED and snapshot archive verification passed")
    print("  DT_NEEDED: " + ", ".join(needed))
    for archive, count in snapshot_counts.items():
        print(f"  {archive} members: {count}")
    for archive, count in bare_counts.items():
        print(f"  {archive} members: {count}")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} BINARY LINKER_MAP", file=sys.stderr)
        return 2
    verify(Path(argv[1]), Path(argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
