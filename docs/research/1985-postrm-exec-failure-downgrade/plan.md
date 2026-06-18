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

### 4.1 dpkg version arguments

In the postrm `upgrade` case, dpkg passes the NEW version being installed
as `$2` (for old-postrm `upgrade <new-version>` in the downgrade/upgrade
call order). The script can compare `$2` against the #1964 hardened-layout
floor version using `dpkg --compare-versions`:

```sh
HARDENED_FLOOR="<first-version-with-#1964-layout>"   # static metadata
if dpkg --compare-versions "$2" ge "$HARDENED_FLOOR"; then
    : # new package is hardened-or-newer — NEVER tear down (it is an
      # upgrade or a hardened->hardened downgrade).
elif [ -L "$CURRENT" ] || [ -e "$CURRENT" ]; then
    # new package PREDATES the layout — genuine pre-hardened downgrade.
    ... destructive cleanup ...
fi
```

`dpkg --compare-versions` is always available in a maintainer script
(it's part of dpkg) and does not depend on the staged binary running.

**The capability probe is DEMOTED to a confirmatory check, not the gate.**
Options for review:
- (a) Drop the probe entirely; rely solely on the version compare.
- (b) Keep the probe as an ADDITIONAL "leave it" signal: tear down ONLY
  if BOTH the version is below the floor AND the probe fails — but never
  tear down merely because the probe failed. (Belt-and-suspenders, but the
  version compare alone is sufficient and simpler.)

Recommended: (a) — version compare is deterministic and the probe adds an
exec-failure foot-gun with no benefit once the version is authoritative.

### 4.2 Determining the floor version

`HARDENED_FLOOR` is a static constant in the script (the version in
`debian/changelog` where the #1964 versioned-runtime layout first shipped
— PR #1972). It is metadata, not derived at runtime. Document it inline
and cross-reference the changelog entry.

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

Safer options for review (pick one):

- **(a) Pre-seed the state the old postrm gates on.** The old destructive
  branch only fires when `[ -L "$CURRENT" ] || [ -e "$CURRENT" ]` is true
  AND the probe fails. The NEW preinst (runs BEFORE the old postrm) cannot
  make the probe pass without a runnable binary, and removing `current`
  pre-emptively would itself break rollback. So pre-seeding does not cleanly
  defuse it. Likely insufficient — document why.
- **(b) Accept the one-transition exposure, rely on the existing
  backstops.** The destructive teardown removes `current` + the drop-in +
  repoints sbin to staged. The new package's `postinst` (runs AFTER the old
  postrm) re-seeds the versioned runtime (`seed-runtime`) and rewrites the
  drop-in — IF the new xpfd can exec by then. If it cannot exec at postinst
  either, the daemon is broken regardless of this bug (a non-runnable new
  binary is a failed upgrade). So the NET new exposure from the old postrm
  is narrow: it only matters if the new binary is non-execable at OLD-postrm
  time but execable at postinst time. Quantify this window; it may be
  acceptable-with-documentation given postinst re-seeds.
- **(c) Targeted, idempotent preinst guard that does NOT rewrite dpkg
  scripts:** the new preinst writes a small marker
  (`/run/xpf/skip-postrm-teardown` or a `staged/.no-teardown`) that a
  COOPERATING old postrm would honor — but the OLD postrm predates the
  marker, so it can't honor it. Only works for FUTURE transitions, not the
  buggy→fixed one. So (c) protects buggy(N)→fixed→...→(N+2) but not the
  immediate hop. Document that the marker hardens future hops.

**Disposition:** the buggy→fixed transition is a genuine one-time exposure
inherent to fixing a maintainer script (the fix can't run before it's
installed). The plan should: (1) ship the postrm version-compare fix (4.1),
(2) add the cooperative marker (c) so all FUTURE transitions are protected,
and (3) HONESTLY DOCUMENT the one-time buggy→fixed exposure in the PR body
+ `docs/in-place-upgrade.md`, noting postinst re-seed (b) as the mitigation
and that the only unprotected case is "new binary non-execable at
old-postrm time but execable at postinst time." AGY's sed-patch (a-hack) is
listed as a REJECTED alternative with the fragility reasoning. Plan review
to confirm this disposition or escalate.

## 5. Alternatives rejected

- **Keep exec-probe as the gate, add a retry.** A retry of a corrupt
  binary still fails; doesn't fix the conflation. Rejected.
- **Probe a DIFFERENT staged binary.** Same exec-failure class. Rejected.
- **Make teardown reversible / journaled.** Over-engineering; the right
  fix is to not misclassify in the first place. Rejected.

## 6. Files touched

- `debian/xpf.postrm` (version-compare gate; demote/drop the exec probe)
- A test harness for the maintainer script (see §7) — likely a shell test
  under `test/` or a Go test that runs the script with a stub `$STAGED/xpfd`
  and asserts filesystem state. Check existing patterns: there may already
  be maintainer-script tests from #1964/#1967.
- `docs/in-place-upgrade.md` (document the downgrade-detection contract:
  version-compare, not exec-probe)

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
- Companion case: `postrm upgrade <OLD_VER>` with `<OLD_VER>` < floor →
  destructive cleanup STILL runs (downgrade path preserved).
- Edge: empty `$2` → layout survives + loud log.

Determine the existing maintainer-script test mechanism (the #1964/#1967
work added postrm/preinst hardening — check `test/` and
`pkg/upgrade/*_test.go` for a script-runner) and reuse it; if none exists,
a small `sh`-driven Go test that execs the script against a tempdir layout
is the minimal addition.

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
  the buggy→fixed upgrade transition, so this fix does not protect its own
  rollout. FOLDED in §4.4: AGY's exact remedy (preinst sed-patching
  `/var/lib/dpkg/info/xpf.postrm`) REJECTED as fragile control-file
  rewriting; instead ship the version-compare fix + a cooperative marker
  that protects all FUTURE transitions + honest documentation of the
  one-time buggy→fixed exposure (mitigated by postinst re-seed). Re-verdict
  pending Codex/arch confirmation of the disposition.
- Codex companion: _pending_
