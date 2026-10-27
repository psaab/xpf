"""#6988 code-motion verifier.

Reconstructs nat/source.rs from the split AS IT WAS AT THE SPLIT MERGE and
compares it byte-for-byte with the pre-split file at the merge's first
parent, allowing ONLY the visibility widenings enumerated below. Any other
difference — a reordered statement, a changed literal, a dropped
comment — fails.

Both inputs are pinned git refs (defaults below), NOT origin/master and NOT
the working tree, so this verifier is reproducible indefinitely: later edits
to nat/source/ cannot break it, and it makes NO claim about the current
tree. The original verifier read origin/master:source.rs and re-derived its
seams after every master merge (see the old SEAMS comment: #7858 inserted 99
lines at ~717 and shifted every seam below it); that is exactly the drift
that made it un-runnable once source.rs itself was deleted by the split.

Defaults: --split 22b9cb22d07be2c041efb7ef250083a6c53f9c6b (the #7860 merge,
2026-08-28), --base 63705b4421d0c5ec42c04d88e449aab86ced30ac (its first
parent, the last master with a monolithic source.rs, 3414 lines). The split
commit d85c20ffdf with its own parent 44a3356249 also verifies, with the
pre-shift seams in that commit's copy of this script.

Usage: python3 scripts/verify-nat-source-split-6988.py [--base REF] [--split REF]
       (one positional [base-ref] is also accepted, for compatibility)
"""
import argparse, subprocess, sys


def show(ref, path):
    return subprocess.run(['git', 'show', f'{ref}:{path}'],
                          capture_output=True, text=True, check=True).stdout.split('\n')


def parse_refs(argv):
    p = argparse.ArgumentParser(description='#6988 split verifier (pinned refs)')
    p.add_argument('--base', default=None, help='pre-split ref (default: split-merge first parent)')
    p.add_argument('--split', default=None, help='split-merge ref')
    p.add_argument('base_pos', nargs='?', default=None, help='[compat] positional base ref')
    a = p.parse_args(argv)
    split = a.split or '22b9cb22d07be2c041efb7ef250083a6c53f9c6b'
    base = a.base or a.base_pos or '63705b4421d0c5ec42c04d88e449aab86ced30ac'
    return base, split


BASE_REF, SPLIT_REF = parse_refs(sys.argv[1:])
BASE = show(BASE_REF, 'userspace-dp/src/nat/source.rs')

# Seam line ranges in the BASE (pre-split) source.rs at BASE_REF, derived by
# content: each span's first and last line was matched in the base file and
# the span length checked against the submodule body. They are properties of
# the pinned base only — they no longer shift, because the base no longer
# moves.
SEAMS = [('failure', 59, 215), ('expand', 1193, 1366), ('release', 1679, 1935),
         ('synced', 1937, 2451), ('nat64_ports', 2453, 2592), ('match_rules', 2594, 3340)]

# Two WIDENINGS (private -> pub(super)) and one RESPELLING. The respelling is
# not a visibility change at all: `pub(super)` inside `nat::source` meant
# `pub(in crate::nat)`, and one level deeper the same keyword would mean
# `pub(in crate::nat::source)` — narrower, and it broke
# nat/tests_aggregate_budget.rs with E0603 on the first build. The absolute
# form restores exactly what the pre-split file had.
ALLOWED = [('failure', '    fn for_rule(', '    pub(super) fn for_rule('),
           ('failure', 'fn source_nat_failure_reason_from_snapshot(',
                      'pub(super) fn source_nat_failure_reason_from_snapshot('),
           ('expand', 'pub(super) fn expand_pool_address(',
                     'pub(in crate::nat) fn expand_pool_address(')]


def submodule_body(name):
    lines = show(SPLIT_REF, f'userspace-dp/src/nat/source/{name}.rs')
    i = lines.index('use super::*;')          # header ends at the glob import
    body = lines[i + 2:]                        # skip the blank line after it
    while body and body[-1] == '':
        body.pop()  # trailing newline the writer added
    return body


# 1. Un-apply the allowed edits, so what remains must be IDENTICAL to base.
recon = {}
for name, a, b in SEAMS:
    body = '\n'.join(submodule_body(name))
    # Explanatory lines added by the split are tagged so stripping them is
    # deterministic rather than a prefix guess that can silently miss one.
    body = '\n'.join(l for l in body.split('\n') if '// #6988-note:' not in l)
    for f, old, new in ALLOWED:
        if f == name:
            assert body.count(new) == 1, f'{name}: expected exactly one {new!r}'
            body = body.replace(new, old)
    recon[name] = body.split('\n')

# 2. Rebuild the original line sequence.
mod_lines = show(SPLIT_REF, 'userspace-dp/src/nat/source/mod.rs')
# strip the inserted block (mod decls + re-exports + their comment banner)
start = next(i for i, l in enumerate(mod_lines) if l.startswith('// #6988: source.rs crossed'))
end = next(i for i, l in enumerate(mod_lines) if l.startswith('pub(crate) use match_rules::*;'))
residual = mod_lines[:start - 1] + mod_lines[end + 2:]

out = []
ri = 0
taken = set()
for n in range(1, len(BASE) + 1):
    hit = [s for s in SEAMS if s[1] == n]
    if hit:
        out.extend(recon[hit[0][0]]); taken.add(hit[0][0]); continue
    if any(a < n <= b for _, a, b in SEAMS):
        continue
    out.append(residual[ri]); ri += 1

assert len(taken) == len(SEAMS), f'missed submodules: {set(s[0] for s in SEAMS) - taken}'
if ri != len(residual):
    print(f'FAIL: {len(residual) - ri} residual mod.rs lines unaccounted for'); sys.exit(1)

if out == BASE:
    print(f'PASS: the split at {SPLIT_REF[:12]} reconstructs nat/source.rs EXACTLY ({len(BASE)} lines).')
    print(f'      (base {BASE_REF[:12]}; this checks the split merge only, not the current tree)')
    print(f'      Allowed edits, and nothing else: {len(ALLOWED)}')
    for f, old, new in ALLOWED:
        print(f'        {f}.rs: {old.strip()}  ->  {new.strip()}')
    sys.exit(0)

import difflib
print('FAIL: reconstruction differs from the pre-split file:')
for d in list(difflib.unified_diff(BASE, out, 'pre-split', 'reconstructed', lineterm='', n=1))[:60]:
    print(d)
sys.exit(1)
