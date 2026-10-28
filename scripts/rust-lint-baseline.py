#!/usr/bin/env python3
"""#17190 rustc warning ratchet.

Runs cargo check --release and cargo check --release --tests with
--message-format=json (pinned toolchain via Makefile), counts unique
(lint, file) pairs, and fails on any pair not in userspace-dp/lint-baseline.tsv
or any baseline count increase. Decreases are reported (baseline can be
regenerated with --write) but do not fail, so burn-down PRs stay green.
"""
import argparse, collections, json, subprocess, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "userspace-dp" / "lint-baseline.tsv"

def census(args):
    env = dict(os.environ)
    cargo = os.environ.get("CARGO", "cargo")
    cmd = [cargo, "check", "--release", "--manifest-path", "userspace-dp/Cargo.toml", "--message-format=json"] + args
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    if out.returncode != 0:
        sys.stderr.write(out.stderr[-4000:])
        raise SystemExit(f"cargo check {args} failed rc={out.returncode}")
    counts = collections.Counter()
    locs = {}
    for line in out.stdout.splitlines():
        try: d = json.loads(line)
        except Exception: continue
        if d.get("reason") != "compiler-message": continue
        m = d["message"]
        if m["level"] != "warning": continue
        code = (m.get("code") or {}).get("code", "no_code")
        for s in m.get("spans", []):
            if s.get("is_primary"):
                key = (code, s["file_name"])
                counts[key] += 1
                locs.setdefault(key, []).append(f"{s['file_name']}:{s['line_start']}: {m['message']}")
    return counts, locs

def load_baseline():
    base = {}
    if not BASELINE.exists(): return base
    for line in BASELINE.read_text().splitlines():
        if not line or line.startswith("#"): continue
        lint, file, count = line.split("\t")
        base[(lint, file)] = int(count)
    return base

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="regenerate baseline from current census")
    a = ap.parse_args()
    total = collections.Counter(); locs = {}
    for extra in ([], ["--tests"]):
        c, l = census(extra)
        total.update(c)
        for k, v in l.items(): locs.setdefault(k, []).extend(v)
    if a.write:
        lines = ["# #17190 rustc warning baseline: lint<TAB>file<TAB>count (unique primary spans, release+tests)"]
        for (lint, file), n in sorted(total.items()):
            lines.append(f"{lint}\t{file}\t{n}")
        BASELINE.write_text("\n".join(lines) + "\n")
        print(f"wrote {BASELINE} with {sum(total.values())} warnings in {len(total)} (lint,file) pairs")
        return 0
    base = load_baseline()
    failures = []
    for key, n in sorted(total.items()):
        if key not in base:
            failures.append(f"NEW warning {key[0]} in {key[1]} (x{n}): " + "; ".join(locs[key][:3]))
        elif n > base[key]:
            failures.append(f"INCREASE {key[0]} in {key[1]}: {base[key]} -> {n}: " + "; ".join(locs[key][:3]))
    decreased = [(k, base[k], total.get(k, 0)) for k in base if total.get(k, 0) < base[k]]
    for k, old, new in sorted(decreased):
        print(f"note: decreased {k[0]} {k[1]}: {old} -> {new} (run --write to ratchet down)")
    if failures:
        print("rust-lint-baseline FAILED:", file=sys.stderr)
        for f in failures: print("  " + f, file=sys.stderr)
        return 1
    print(f"rust-lint-baseline OK: {sum(total.values())} warnings, {len(total)} (lint,file) pairs, no new/increased")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
