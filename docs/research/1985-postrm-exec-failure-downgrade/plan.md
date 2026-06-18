# Plan: postrm exec-failure must not trigger destructive downgrade teardown (#1985)

## 1. Problem

`debian/xpf.postrm` (case `upgrade`) decides whether the new package
PREDATES the #1964 hardened layout by EXECUTING a capability probe on the
newly-unpacked staged binary (`xpf.postrm:134-154`):

```sh
if [ -x "$STAGED/xpfd" ] && \
   "$STAGED/xpfd" seed-runtime --capability-check >/dev/null 2>&1; then
    : # downgrading to another hardened package — leave the layout.
elif [ -L "$CURRENT" ] || [ -e "$CURRENT" ]; then
    repoint_owned_sbin_to_staged   # sbin -> staged
    rm -f "$CURRENT"               # delete versions/current
    remove_runtime_dropin          # remove 10-xpf-version.conf + daemon-reload
fi
```

The `&&` short-circuits to FALSE whenever the staged `xpfd` fails to exec
for ANY reason — dynamic-link error during unpack, binary corruption,
libc/ABI conflict, arch mismatch — not only when it is genuinely a
pre-hardened binary missing the subcommand. The probe CONFLATES "new binary
lacks the layout" with "new binary cannot run." On exec failure during a
real UPGRADE the destructive `elif` runs and tears down the versioned
runtime.

## 2. Hypothesis

The downgrade decision must NOT depend on whether the staged binary can
exec. The dpkg-supplied version arguments distinguish upgrade from
downgrade deterministically without trusting the binary. Keying the
teardown on a version comparison (with the capability probe as a
confirmatory SECONDARY signal, never the sole gate) eliminates the false
downgrade. The sibling `xpf.preinst` already demonstrates the safe pattern
(version fallback + skip-don't-destroy on unrunnable binary,
`preinst:144-161`).

## 3. Goal / acceptance criteria

- A hardened→hardened UPGRADE where the staged `xpfd` is non-execable does
  NOT delete `versions/current`, does NOT repoint sbin to staged, does NOT
  remove the drop-in.
- A genuine downgrade to a pre-#1964 package STILL cleans up correctly
  (the existing behavior the code intends).
- On ambiguity (cannot determine direction), the SAFE default is "leave
  the hardened layout intact" — the verify-dataplane cut gate /
  refuse-before-STOP guard is the backstop.
- Regression test: non-execable staged xpfd on upgrade → layout survives.

## 4. Approach

### 4.1 Deterministic, EXEC-FREE downgrade detection

The defect is that the downgrade decision trusts the staged binary's EXEC.
The fix replaces exec with a deterministic exec-free signal. Codex
confirmed dpkg passes `$2` = the NEW (incoming) version to the OLD postrm
on `upgrade`; but the commit-count+SHA version scheme makes a hardcoded
floor unusable (§4.2). The RECOMMENDED signal (§4.2 option a) is the
NON-EXEC layout marker the newly-unpacked staged tree carries:

```sh
# The hardened package ships staged/.layout-version (or a sentinel file)
# via debian/rules. The newly-unpacked staged tree is on disk at old-postrm
# time. Read it WITHOUT executing anything.
STAGED_LAYOUT_MARKER="$STAGED/.layout-version"
if [ -f "$STAGED_LAYOUT_MARKER" ]; then
    : # new package is hardened (carries the layout marker) — NEVER tear
      # down (upgrade OR hardened->hardened downgrade). No exec, no version
      # parse.
elif [ -L "$CURRENT" ] || [ -e "$CURRENT" ]; then
    # new package PREDATES the layout (no marker) — genuine pre-#1964
    # downgrade.
    ... destructive cleanup ...
fi
```

The marker is a plain file read — no `dpkg --compare-versions`, no exec.
The capability probe is DROPPED entirely (it was the foot-gun); the marker
is the sole, exec-free gate.

(If review prefers the version-compare path (§4.2 option b) over the marker,
`dpkg --compare-versions` is always available in a maintainer script and
exec-free — but it requires anchoring a real floor via the build, which is
why the marker is recommended.)

### 4.2 Determining the floor version — UNANCHORED (Codex NEEDS-MAJOR, FOLDED)

**Codex found the floor cannot be a hand-picked changelog version.**
`debian/changelog:1` is `0.0.0`; the real package version is GENERATED at
build time from commit-count + SHA (`Makefile:337-340`, e.g.
`0.0.4123+gd58a067837c7`). PR #1972 (#1964 layout) has no stable
human-readable version to pin. A hardcoded `HARDENED_FLOOR = "0.9.0"` (as
an early test fixture used) is meaningless against that scheme and makes the
gate a no-op or wrong.

Options for review:
- **(a) Capability MARKER, not version compare.** Detect the hardened
  layout by a STATIC artifact the hardened package ships and a pre-hardened
  one does not — e.g. presence of the `seed-runtime` SUBCOMMAND is what the
  current code probes, but that requires EXEC. A non-exec marker: the
  hardened package ships a sentinel FILE (e.g.
  `/usr/local/share/xpf/.hardened-layout` or a versioned
  `staged/.layout-version` integer) that postrm reads WITHOUT exec. The
  downgrade decision becomes "does the NEWLY-UNPACKED staged tree carry the
  hardened-layout marker?" — file existence, no exec, no version parse.
  This is the cleanest deterministic signal and sidesteps the version
  scheme entirely.
- **(b) Anchor a real floor via the build.** Stamp `HARDENED_FLOOR` into
  the maintainer script at build time from the same version source
  (`Makefile`/`debian/rules`), so the compare is against a real version.
  More moving parts; ties postrm to the version-stamping pipeline.

**Recommended: (a) the non-exec layout marker.** It is deterministic,
exec-free (the whole point — the bug was trusting exec), and independent of
the commit-count version scheme. The marker is shipped by `debian/rules`
into the staged payload, so the NEWLY-UNPACKED staged tree present at
old-postrm time carries it iff the new package is hardened.

### 4.3 Edge: `$2` empty / unparsable

If `$2` is empty or `dpkg --compare-versions` errors (should not happen on
a normal upgrade), default to the SAFE branch (leave layout intact) and
log loudly — never fall through to teardown. Mirrors preinst's
"skip-don't-destroy" posture.

### 4.4 Upgrade-transition gap — the OLD (buggy) postrm runs during this fix's own rollout (AGY NEEDS-MAJOR, FOLDED)

**AGY plan review correctly flags:** dpkg runs the **OLD** package's
`postrm upgrade <new>` during an upgrade (Debian maintainer-script call
order). So upgrading FROM a currently-installed buggy version TO the fixed
version still executes the OLD buggy postrm. If the new staged `xpfd` can't
exec at that moment (e.g. an OS/libc bump in the same transaction), the OLD
postrm's exec-probe short-circuits and runs the destructive teardown — the
exact bug — during the very upgrade that ships the fix. The new postrm fix
does NOT protect this one transition.

**AGY's suggested fix — new preinst `sed`-patches
`/var/lib/dpkg/info/xpf.postrm` to neutralize the probe — is NOT adopted
as-written.** Rewriting dpkg's own on-disk control scripts from a
maintainer script is fragile and surprising: it depends on the exact text
of the installed old script, races dpkg's own bookkeeping, and leaves a
mutated control file dpkg did not author (a future `dpkg --verify` / debug
nightmare). It is a last-resort hack.

**Codex (NEEDS-MAJOR, FOLDED) corrected two errors in the v1 disposition:**

- The "cooperative marker" idea is UNENFORCEABLE for the buggy→fixed hop:
  the OLD buggy postrm runs during that upgrade and predates any marker
  logic, so it cannot read or honor a marker. A marker only helps
  fixed(N)→...→(N+2) hops, where the running postrm is already the fixed
  one — which by then doesn't NEED the marker (it already keys on the
  layout marker §4.1). So the cooperative-marker provides ZERO additional
  protection. DROPPED from the plan.
- The "postinst re-seed mitigates it" claim is FALSE: `debian/xpf.postinst`
  runs `seed-runtime` ONLY on first install (`postinst:40`, gated on
  `[ -z "$2" ]`); on UPGRADE (`$2` non-empty) it takes the else-branch that
  does NOT re-seed and only creates COMPLETELY-ABSENT links. So if the old
  postrm deleted `versions/current`, the upgrade's postinst does NOT restore
  it, and `pkg/upgrade/cutover.go:213-221` (refuse-before-STOP) can then
  REFUSE the next cut. The postinst is not a mitigation.

**Honest disposition (FOLDED):** the buggy→fixed transition is a genuine
one-time exposure inherent to fixing a maintainer script — the fix cannot
run before it is installed, and dpkg runs the OLD (buggy) postrm during the
upgrade that ships the fix. There is NO clean in-band fix for that single
hop short of rewriting dpkg's control files (AGY's sed-patch), which is
REJECTED as fragile. The plan therefore:

1. Ships the exec-free marker gate (§4.1) — protects all transitions ONCE
   the fixed package is installed.
2. Does NOT claim a cooperative-marker or postinst-reseed mitigation (both
   refuted above).
3. HONESTLY DOCUMENTS the one-time buggy→fixed exposure in the PR body +
   `docs/in-place-upgrade.md`: the exposure fires ONLY if the new staged
   xpfd is non-execable at OLD-postrm time AND `versions/current` exists.
   The realistic trigger is an OS/libc bump in the SAME apt transaction
   making the new binary temporarily unloadable. Operator guidance: stage
   xpf upgrades separately from OS/libc bumps (already the spirit of the
   "don't run xpfd upgrade during apt upgrade" guidance).
4. RECOVERY note: if the old postrm did tear down the layout, the operator
   re-runs `xpfd seed-runtime` (or reinstalls) to rebuild `versions/current`
   + the drop-in before the next cut. Document this recovery.

AGY's sed-patch of `/var/lib/dpkg/info/xpf.postrm` is a REJECTED
alternative (fragile control-file rewriting; depends on exact old-script
text; leaves a dpkg-unauthored mutated control file).

## 5. Alternatives rejected

- **Keep exec-probe as the gate, add a retry.** A retry of a corrupt
  binary still fails; doesn't fix the conflation. Rejected.
- **Probe a DIFFERENT staged binary.** Same exec-failure class. Rejected.
- **Make teardown reversible / journaled.** Over-engineering; the right
  fix is to not misclassify in the first place. Rejected.

## 6. Files touched

- `debian/xpf.postrm` (exec-free marker gate; DROP the exec probe)
- `debian/rules` (ship the layout marker `staged/.layout-version` into the
  staged payload)
- `test/debian/postrm-test.sh` (the existing maintainer-script test harness
  from #1964/#1967 — EXTEND it; Codex confirmed it exists and that its
  `$2=0.9.0` floor fixture is meaningless under the real version scheme, so
  the marker approach replaces it)
- `docs/in-place-upgrade.md` (downgrade-detection contract: exec-free
  marker, not exec-probe; the one-time buggy→fixed exposure + recovery)

## 7. Test strategy

Strong regression test reproducing the false downgrade:

- Set up a fake hardened layout: `versions/current -> <ver>`, sbin links
  through current, drop-in present.
- Place a NON-EXECABLE `$STAGED/xpfd` (e.g. a 0-byte file, or `chmod -x`,
  or a script that `exit 1`s — to simulate exec/link failure).
- Run `postrm upgrade <NEW_VER>` with `<NEW_VER>` >= the hardened floor.
- BEFORE fix: `versions/current` deleted, sbin repointed, drop-in removed
  → test FAILS (asserts they survive).
- AFTER fix: all three survive → test PASSES.
- Companion case: `postrm upgrade` with NO staged layout marker (a true
  pre-#1964 downgrade) → destructive cleanup STILL runs (downgrade path
  preserved).
- Marker present + non-execable staged xpfd → layout survives (the core
  fix: the gate no longer trusts exec).

Codex-required test matrix (the harness is `test/debian/postrm-test.sh`,
which EXISTS): marker-present-execable, marker-present-NON-execable (the
bug case → must survive), marker-ABSENT (genuine downgrade → tears down),
empty `$2`, reinstall (`$2`==same). Drop the meaningless `$2=0.9.0` floor
fixture Codex flagged at `postrm-test.sh:159-163`.

The harness execs the script against a tempdir layout — reuse it directly.

## 8. Invariants

- Downgrade detection depends on the dpkg VERSION argument, never on the
  staged binary's exec success.
- The destructive teardown runs ONLY for a genuine pre-#1964 downgrade.
- On any ambiguity, the hardened layout is preserved (fail-safe).

## 9. Risk

MEDIUM-LOW. The fix narrows a destructive branch (strictly safer). Main
risk is getting `HARDENED_FLOOR` and the `$2` semantics exactly right;
covered by the upgrade-vs-downgrade test pair. Must confirm dpkg's
postrm-on-upgrade `$2` is the NEW version (Debian Policy / dpkg maintainer
script call order) — to be verified in implementation and asserted in the
plan-review.

## 10. Rollout / validation

- Maintainer-script test (above).
- A real .deb upgrade rehearsal on a standalone VM: install hardened
  package, then upgrade to another hardened package while having corrupted
  the staged xpfd (e.g. truncate it post-unpack is hard to stage; instead
  use the script test as the authoritative proof and note the .deb
  rehearsal limitation in the PR body).
- `make test-deploy` standalone to confirm normal upgrade still works.

## 11. Disposition

engineer-now after plan review — the safe pattern already exists in
preinst; this is bounded. Key open item for review: confirm dpkg `$2`
semantics in postrm-upgrade and pick the floor version from changelog.

## Reviewer verdicts

- Claude SMR: PLAN READY pending `$2`-semantics confirmation in impl.
- AGY companion: PLAN NEEDS-MAJOR (r1) — the OLD (buggy) postrm runs during
  the buggy→fixed upgrade transition. AGY's sed-patch remedy REJECTED;
  folded a documented-exposure disposition.
- Codex companion: PLAN NEEDS-MAJOR (r1) — confirmed `$2`=new-version
  semantics, but found THREE holes: (1) `HARDENED_FLOOR` is UNANCHORED
  (versions are commit-count+SHA, `debian/changelog` is 0.0.0) → version
  compare is a no-op; (2) the cooperative-marker for buggy→fixed is
  UNENFORCEABLE (old postrm predates it); (3) the "postinst re-seed
  mitigation" does NOT exist on upgrade (`postinst:40` seeds only when
  `$2` empty). ALL FOLDED: pivoted to an EXEC-FREE LAYOUT MARKER (§4.1/4.2)
  instead of version-compare; dropped the cooperative-marker claim; replaced
  the false postinst-reseed mitigation with honest documentation + an
  operator recovery note. Re-verdict pending: the marker pivot resolves the
  floor-anchoring hole; the buggy→fixed one-hop exposure is documented as
  inherent. Expected PLAN YES on the marker approach after one more pass.
