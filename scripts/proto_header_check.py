#!/usr/bin/env python3
"""Hermetic generated-proto-header check (#16195).

Compares the version stamps in the checked-in generated Go headers
against the versions recorded as constants in proto/README.md and
against the matching go.mod module versions. No network, no protoc,
no plugin execution: only file reads.

Stamps parsed:
  pkg/grpcapi/xpfv1/xpf.pb.go       protoc-gen-go vX, protoc vY
  pkg/grpcapi/xpfv1/xpf_grpc.pb.go  protoc-gen-go-grpc vA, protoc vY

Cross-checks:
  protoc-gen-go stamp  == go.mod google.golang.org/protobuf version
  protoc-gen-go-grpc stamp == the grpc module constant in proto/README.md
    (protoc-gen-go-grpc is released on its own sub-module version line;
    it is not the google.golang.org/grpc module version in go.mod, so
    README is its recorded-constant home -- see proto/README.md)
  protoc stamps agree with each other and with the README protoc constant
  README constants agree with their counterparts above

Exit 0 = all agree, 1 = mismatch/missing (red), 2 = usage/layout error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PB_GO = "pkg/grpcapi/xpfv1/xpf.pb.go"
GRPC_PB_GO = "pkg/grpcapi/xpfv1/xpf_grpc.pb.go"
README = "proto/README.md"
GOMOD = "go.mod"

# README constants, one per line, e.g.:
#   - `protoc` v3.21.12
#   - `protoc-gen-go` v1.36.11 (== google.golang.org/protobuf)
#   - `protoc-gen-go-grpc` v1.6.1
_README_RE = {
    "protoc": re.compile(r"^- `protoc` v(\S+)\s*$", re.M),
    "protoc-gen-go": re.compile(r"^- `protoc-gen-go` v(\S+)\s*$", re.M),
    "protoc-gen-go-grpc": re.compile(r"^- `protoc-gen-go-grpc` v(\S+)\s*$", re.M),
}

_PB_HEADER_RE = re.compile(
    r"protoc-gen-go v(\S+)\s*\n//\s*protoc\s+v(\S+)", re.M
)
_GRPC_HEADER_RE = re.compile(
    r"protoc-gen-go-grpc v(\S+)\s*\n//\s*-?\s*protoc\s+v(\S+)", re.M
)


def parse_pb_header(text: str) -> tuple[str, str] | None:
    m = _PB_HEADER_RE.search(text)
    return (m.group(1), m.group(2)) if m else None


def parse_grpc_header(text: str) -> tuple[str, str] | None:
    m = _GRPC_HEADER_RE.search(text)
    return (m.group(1), m.group(2)) if m else None


def parse_readme_constants(text: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for key, rx in _README_RE.items():
        m = rx.search(text)
        out[key] = m.group(1) if m else None
    return out


def parse_gomod_version(text: str, module: str) -> str | None:
    # Matches `require mod vX`, block entries (`\tmod vX`), and
    # single-line requires alike.
    m = re.search(
        rf"^\s*(?:require\s+)?{re.escape(module)} v(\S+)\s*$", text, re.M
    )
    return m.group(1) if m else None


def check(root: Path) -> list[str]:
    errors: list[str] = []

    def read(rel: str) -> str | None:
        p = root / rel
        if not p.is_file():
            errors.append(f"{rel}: missing")
            return None
        return p.read_text()

    pb_text = read(PB_GO)
    grpc_text = read(GRPC_PB_GO)
    readme_text = read(README)
    gomod_text = read(GOMOD)
    if None in (pb_text, grpc_text, readme_text, gomod_text):
        return errors
    assert pb_text and grpc_text and readme_text and gomod_text

    pb = parse_pb_header(pb_text)
    if pb is None:
        errors.append(f"{PB_GO}: no 'protoc-gen-go vX / protoc vY' stamp")
        gen_go = protoc_pb = None
    else:
        gen_go, protoc_pb = pb

    grpc_hdr = parse_grpc_header(grpc_text)
    if grpc_hdr is None:
        errors.append(
            f"{GRPC_PB_GO}: no 'protoc-gen-go-grpc vX / protoc vY' stamp"
        )
        gen_go_grpc = protoc_grpc = None
    else:
        gen_go_grpc, protoc_grpc = grpc_hdr

    consts = parse_readme_constants(readme_text)
    for key, val in consts.items():
        if val is None:
            errors.append(f"{README}: no recorded `- `{key}` v...` constant")

    protobuf_mod = parse_gomod_version(gomod_text, "google.golang.org/protobuf")
    if protobuf_mod is None:
        errors.append(f"{GOMOD}: google.golang.org/protobuf not found")

    def cmp(label: str, a: str | None, a_src: str, b: str | None, b_src: str) -> None:
        if a is None or b is None:
            return  # already reported as missing
        if a != b:
            errors.append(f"{label}: {a_src} is v{a} but {b_src} is v{b}")

    cmp("protoc-gen-go", gen_go, PB_GO, protobuf_mod, f"{GOMOD} protobuf")
    cmp("protoc-gen-go", gen_go, PB_GO, consts["protoc-gen-go"], README)
    cmp(
        "protoc-gen-go-grpc",
        gen_go_grpc,
        GRPC_PB_GO,
        consts["protoc-gen-go-grpc"],
        README,
    )
    cmp("protoc", protoc_pb, PB_GO, protoc_grpc, GRPC_PB_GO)
    cmp("protoc", protoc_pb, PB_GO, consts["protoc"], README)

    return errors


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[1]) if len(argv) == 2 else Path(__file__).resolve().parent.parent
    if not (root / GOMOD).is_file():
        print(f"proto_header_check: {root} is not the repo root (no go.mod)", file=sys.stderr)
        return 2
    errors = check(root)
    if errors:
        for e in errors:
            print(f"proto-header-check: FAIL: {e}", file=sys.stderr)
        print(
            "proto-header-check: regenerate with the pinned tools in "
            "proto/README.md (CI: make proto-regen-check) or fix the stamp",
            file=sys.stderr,
        )
        return 1
    print("proto-header-check: OK (headers == proto/README.md constants == go.mod)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
