# `scripts/mutate.sh`: refuse to mutate a target with uncommitted changes

Landed out of #9158, where an ad-hoc driver destroyed a fix mid-matrix. The rule
already existed in this repo as a comment at the top of `mutate.sh` — *"Commit
before running: a harness that rewrites files WILL eat uncommitted work"* — and
a comment cannot fire.

## The sharp reason, which is not the lost work

`mutate.sh` infers APPLIED from the file differing from HEAD:

```sh
applied=yes
git -C "$REPO" diff --quiet -- "$file" && applied=no
```

If the target was **already dirty before the cell ran**, that is true whether or
not the mutation text landed. So every cell reports `applied=yes`, **including
one that changed nothing** — and the check that exists to stop a no-op mutation
being scored as a green revert is exactly the check a dirty tree turns off. The
harness's own comment names that hazard ("a mutation that silently failed to
apply looks exactly like a green revert, and green is the answer the measurement
wanted"); a dirty target disables the defence against it.

Second reason: committing first makes an interrupted cell recoverable with one
`git checkout -- <file>`. A timeout kill or session death between apply and
restore otherwise leaves the MUTANT in the tree with the original only in
`$WORK` — the "dead lane's worktree carrying an applied mutant" shape already
recorded in this repo.

## What #9158 measured

An ad-hoc driver reverting with `git checkout --` (restores to HEAD, unlike
`mutate.sh`'s `cp`) destroyed a working-tree-only fix on its FIRST cell. Every
one of seven mutants then came back `VOID: not applied` against a pristine tree
— **including the control**, which is the tell. Without noticing that, the
reading is "my anchors are wrong", which is hours spent in the wrong place.

## Shape

`mutation_dirty_targets` (in `mutate-lib.sh`) takes `git status --porcelain`
OUTPUT rather than calling git, so `make test-mutate-lib` stays hermetic — no
repo, no compiler. `mutate.sh` collects the spec's file column, calls it, and
exits 2 with the offending paths named. `MUTATE_ALLOW_DIRTY=1` overrides for
someone who knows why.

Refusal rather than a warning: the failure it prevents is a whole matrix of
indistinguishable results, and a warning scrolls past.

## Self-test, both directions

`scripts/mutate-selftest.sh` drives the predicate from fixture text:

| Cell | Direction |
|---|---|
| clean set returns 0, prints nothing | must NOT fire |
| MODIFIED target returns 1 and NAMES the file | must fire |
| STAGED target returns 1 | must fire — `git diff --quiet` compares against HEAD, so staged defeats it too |
| a blank line is not dirty | must NOT fire — else every clean run is refused and the guard is useless |
| two dirty targets both reported | must fire completely |

The middle rows are the pair that matters: identical predicate, identical
caller, and the only difference is whether the target was dirty.

**Mutation-verified.** Replacing the predicate body with `return 0` (always
clean) reds 4 of the 7 cells; reverting restores green. A self-test that cannot
fail proves nothing.

**End-to-end, both directions**, against a real worktree: a dirty target exits
**2** and names it; a clean one prints `pre-flight ok - 1 target(s) clean at
HEAD` and proceeds; `MUTATE_ALLOW_DIRTY=1` exits 0. The lib predicate passing
does not prove `mutate.sh` calls it, so that leg is measured separately.

## Log

- **Timestamp**: 2026-09-09
- **Action**: added `mutation_dirty_targets` + the `mutate.sh` pre-flight gate +
  7 self-test cells; mutation-verified the guard and the wiring.
- **File(s)**: `scripts/mutate-lib.sh`, `scripts/mutate.sh`,
  `scripts/mutate-selftest.sh`, `docs/log/mutate-preflight.md`
