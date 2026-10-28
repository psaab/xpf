#!/usr/bin/env python3
"""#17190 rustc warning ratchet.

Runs cargo check --release and cargo check --release --tests with
--message-format=json (pinned toolchain supplied by the Makefile via
RUSTUP_TOOLCHAIN), counts warnings per (profile, lint, file) — profile is
"release" or "tests" — and fails on any triple not in
userspace-dp/lint-baseline.tsv or any baseline count increase within that
profile. Keeping the profiles as separate keys stops release-profile
growth from being laundered by a test-profile cleanup in the summed
census. A census that comes back empty (or below MIN_CENSUS pairs) fails
closed: a broken toolchain invocation must not look like a clean tree.
Each profile must additionally be non-empty on its own: a combined-only
floor would let a fully-empty release or tests census pass (rc=0, no
warnings) whenever the other profile alone carried >= MIN_CENSUS pairs.
Decreases are reported (baseline can be regenerated with --write) but do
"""
import argparse, collections, json, subprocess, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "userspace-dp" / "lint-baseline.tsv"

# Floor for a believable census: the tree carries 246 (profile,lint,file)
# pairs; an empty or near-empty census means cargo/rustc output was not
# parsed (wrong toolchain, stale target dir) and must fail, not pass.
MIN_CENSUS_PAIRS = 50

PROFILES = (("release", []), ("tests", ["--tests"]))


def census(profile, args):
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
                key = (profile, code, s["file_name"])
                counts[key] += 1
                locs.setdefault(key, []).append(f"{s['file_name']}:{s['line_start']}: {m['message']}")
    return counts, locs


def load_baseline():
    base = {}
    if not BASELINE.exists(): return base
    for line in BASELINE.read_text().splitlines():
        if not line or line.startswith("#"): continue
        parts = line.split("\t")
        if len(parts) == 4:
            profile, lint, file, count = parts
            base[(profile, lint, file)] = int(count)
        elif len(parts) == 3:
            # Pre-fold summed format: reject rather than silently compare
            # summed counts against per-profile censuses.
            raise SystemExit(
                "lint-baseline.tsv uses the old 3-column summed format; "
                "regenerate with: python3 scripts/rust-lint-baseline.py --write"
            )
        else:
            raise SystemExit(f"malformed lint-baseline.tsv line: {line!r}")
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="regenerate baseline from current census")
    a = ap.parse_args()
    total = collections.Counter(); locs = {}
    for profile, extra in PROFILES:
        c, l = census(profile, extra)
        if not c:
            print(
                f"rust-lint-baseline FAILED: census for profile {profile!r} "
                "is empty (0 (profile,lint,file) pairs); refusing to pass "
                "on an empty/broken per-profile census",
                file=sys.stderr,
            )
            return 1
        total.update(c)
        for k, v in l.items(): locs.setdefault(k, []).extend(v)
    if len(total) < MIN_CENSUS_PAIRS:
        print(
            f"rust-lint-baseline FAILED: census has only {len(total)} "
            f"(profile,lint,file) pairs (< floor {MIN_CENSUS_PAIRS}); "
            "refusing to pass on an empty/broken census",
            file=sys.stderr,
        )
        return 1
    if a.write:
        lines = ["# #17190 rustc warning baseline: profile<TAB>lint<TAB>file<TAB>count (unique primary spans; release and tests censused separately)"]
        for (profile, lint, file), n in sorted(total.items()):
            lines.append(f"{profile}\t{lint}\t{file}\t{n}")
        BASELINE.write_text("\n".join(lines) + "\n")
        print(f"wrote {BASELINE} with {sum(total.values())} warnings in {len(total)} (profile,lint,file) pairs")
        return 0
    base = load_baseline()
    failures = []
    for key, n in sorted(total.items()):
        if key not in base:
            failures.append(f"NEW warning {key[1]} in {key[2]} [{key[0]}] (x{n}): " + "; ".join(locs[key][:3]))
        elif n > base[key]:
            failures.append(f"INCREASE {key[1]} in {key[2]} [{key[0]}]: {base[key]} -> {n}: " + "; ".join(locs[key][:3]))
    decreased = [(k, base[k], total.get(k, 0)) for k in base if total.get(k, 0) < base[k]]
    for k, old, new in sorted(decreased):
        print(f"note: decreased {k[1]} {k[2]} [{k[0]}]: {old} -> {new} (run --write to ratchet down)")
    if failures:
        print("rust-lint-baseline FAILED:", file=sys.stderr)
        for f in failures: print("  " + f, file=sys.stderr)
        return 1
    print(f"rust-lint-baseline OK: {sum(total.values())} warnings, {len(total)} (profile,lint,file) pairs, no new/increased")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
