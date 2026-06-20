# Research plan — #1997 + #2000: debian maintainer-script upgrade-safety

Branch: `research/1997-2000-upgrade-safety`
Base: `origin/master` @ `9979a89a0` (verified merge-base == origin/master).
Author: Claude (companion-free plan-drafting half of /research).
Status at draft time: **BOTH ISSUES ALREADY FIXED ON origin/master.** This plan
documents that finding, audits the merged fixes for residual gaps, and
recommends the honest disposition.

---

## 0. Headline finding (read this first)

Both #1997 and #2000 were fixed and **merged to `origin/master` earlier today
(2026-06-19)**:

| Issue | PR | Merge commit | Core fix commit | Merged |
|-------|----|--------------|-----------------|--------|
| #1997 | #2029 (`fix/1997-postrm-teardown-order`) | `f8af84ce0` | `600d6ca8f` (+ `80bc941de` Copilot hardening) | 2026-06-19 05:42Z |
| #2000 | #2031 (`fix/2000-postinst-sbin-via-current`) | `b7c1f804f` | `dc1d17cc1` (+ `53f805274` test hardening) | 2026-06-19 07:02Z |

The issues are still in state **OPEN** only because the merge commits referenced
`#1997` / `#2000` in prose but did **not** use a GitHub `Fixes #NNNN` closing
keyword, so they were not auto-closed.

I re-derived the fixes independently (read `postrm`/`postinst`/`preinst` + the Go
seed/flip), confirmed the merged code matches the correct fix, and ran both
regression suites green under `dash`. **No new production change is required.**
The remaining work is verification-and-close plus a short residual-gap audit
(Section 6) — none of which rises to a code change today.

Per-issue recommendation (full rationale in Section 9):
- **#1997 → PLAN-DEFER (verify-and-close).** Fix is correct, idempotent,
  crash-rerun-convergent, tested under sh+dash, documented. No re-engineering.
- **#2000 → PLAN-DEFER (verify-and-close).** Fix is correct, mirrors the
  seed/flip invariant, tested under sh+dash, documented. No re-engineering.

"PLAN-DEFER" here = "no engineering PR; verify the merged fix and close the
issue" — NOT "defer the work" (the work is done). If the reviewer disagrees that
verify-and-close is the right disposition for a merged-but-open issue, escalate
the residual nits in Section 6 to their own tracking issues rather than reopening
these.

---

## 1. Background — the in-place-upgrade layout contract

Source of truth: `docs/in-place-upgrade.md`, `debian/xpf.{preinst,postinst,postrm}`,
`pkg/upgrade/runtime/seed.go`, `pkg/upgrade/flip.go`.

The #1964 hardened versioned-runtime layout (built on the #1917 in-place-upgrade
state machine):

```
/usr/local/share/xpf/staged/<bin>        # dpkg payload (the only path dpkg writes)
/var/lib/xpf/versions/<ver>/<bin>        # immutable per-version runtime copies
/var/lib/xpf/versions/current -> <ver>   # symlink to the verified-live version
/usr/local/sbin/<bin> -> versions/current/<bin>   # live/operator links resolve THROUGH current
/etc/systemd/system/xpfd.service.d/10-xpf-version.conf  # unit drop-in pinning ExecStart to versions/<ver>/xpfd
/var/lib/xpf/staged-gen/<genid>/         # #1981 immutable staged generation (maintainer-managed, not a dpkg file)
```

`managedBins = {xpfd, cli, xpf-userspace-dp, xpf-day0-config}` (#1982 manifest
SSOT; the shell scripts keep a self-contained `BINS=` literal guarded by
`TestManagedBinaryDriftCanary`).

**Invariant the two issues share:** every live/operator sbin link, and the
on-disk teardown ordering, must keep the *verified-live* version
(`versions/current`) authoritative. #2000 is the **establish** side of that
invariant (postinst upgrade absent-link recovery), #1997 is the **teardown** side
(postrm downgrade order + idempotent rerun). Both are pure maintainer-script
shell; neither touches the Go cut state machine.

Maintainer-script phase order (Debian Policy §6.5/§6.6/§6.7), for crash-window
reasoning:
1. old-`prerm upgrade <new>`
2. new-`preinst upgrade <old>`  ← legacy-migration snapshot + lock gate
3. dpkg unpacks `staged/`
4. old-`postrm upgrade <new>`   ← **#1997 downgrade teardown lives here**
5. new-`postinst configure <old>`  ← **#2000 absent-link recovery + cut lives here**

(On a true downgrade the "new" package is the OLDER one; the #1997 teardown runs
in the OLD package's postrm i.e. the hardened package being removed, keyed on the
incoming pre-hardened version `$2`.)

---

## 2. Issue #1997 — postrm downgrade teardown order / idempotency

### 2.1 The original bug (pre-`600d6ca8f`)

The genuine pre-#1964 downgrade teardown in `debian/xpf.postrm` ran:

```sh
if incoming_predates_hardened_layout "$2" \
   && { [ -L "$CURRENT" ] || [ -e "$CURRENT" ]; }; then   # guard on current ALONE
    repoint_owned_sbin_to_staged   # 1.
    rm -f "$CURRENT"               # 2.  <-- destructive, deletes the guard artifact
    remove_runtime_dropin          # 3.  <-- guarded behind the now-deleted artifact
fi
```

Two coupled defects:
- **Destructive step before the dependent cleanup.** `rm current` ran *before*
  `remove_runtime_dropin`.
- **Re-entry gated on the artifact an earlier step deletes.** The whole block was
  guarded on `versions/current` presence.

### 2.2 Crash window (exact)

A SIGKILL/power-loss after `rm -f "$CURRENT"` (step 2) but before
`remove_runtime_dropin` (step 3) leaves:
- `versions/current` GONE,
- `10-xpf-version.conf` drop-in STILL PRESENT (orphan), pinning
  `ExecStart=/var/lib/xpf/versions/<ver>/xpfd` for a `<ver>` the downgraded
  (pre-hardened) package no longer manages.

dpkg reruns the failed postrm (`dpkg --configure -a`, or apt retry). The rerun
evaluates the guard `[ -L current ] || [ -e current ]` → **false** (current is
gone) → takes the else branch → **never removes the orphan drop-in**. On the next
boot systemd honors the stale drop-in and the unit's `ExecStart` references a
deleted binary path → broken unit.

Severity LOW: requires a kill in a sub-ms shell window during a pre-#1964
downgrade (already a rare operation). Recoverable by reinstall / manual rm.

### 2.3 The merged fix (`600d6ca8f` + Copilot `80bc941de`) — correct

Option **B** (idempotent re-run convergence), chosen over Option A (bare reorder)
because a bare reorder still leaves a one-instruction window:

```sh
if incoming_predates_hardened_layout "$2" \
   && { [ -L "$CURRENT" ] || [ -e "$CURRENT" ] \
        || [ -L "$DROPIN" ] || [ -e "$DROPIN" ]; }; then   # guard on current OR drop-in
    repoint_owned_sbin_to_staged   # 1. idempotent (atomic symlink; owned-only)
    remove_runtime_dropin          # 2. idempotent (rm -f drop-in + rmdir .d + boot-guarded reload)
    rm -f "$CURRENT"               # 3. destructive step LAST (idempotent rm -f)
fi
```

Why correct:
- **Order:** destructive `rm current` is now the LAST step, so the only operation
  that can flip the guard false runs after the drop-in is already gone →
  single-run orphan window shrinks to nothing.
- **Idempotent re-entry:** the guard now also fires on drop-in presence, so a
  rerun after a crash *between* steps 1→3 re-enters and converges. All three
  steps are idempotent (atomic owned-only symlink repoint, `rm -f`, `rmdir
  2>/dev/null`).
- **Dangling-symlink robustness (Copilot):** `[ -L "$DROPIN" ] || [ -e "$DROPIN"
  ]` — a bare `-e` is false for a dangling symlink, so a drop-in that is a broken
  symlink (e.g. the .d dir relocated) would slip past a `-e`-only guard. Both
  arms together = "present in any form". (`$CURRENT` already had both arms.)

### 2.4 Dependency-order safety (the "needs-research (small)" nit, answered)

I re-read all three maintainer scripts. **No teardown step depends on
`versions/current` being gone first:**
- `remove_runtime_dropin` operates only on `$DROPIN` + its `.service.d` dir +
  `daemon-reload`; it never reads `current`.
- `repoint_owned_sbin_to_staged` operates only on `$SBIN/*` (and `link_is_owned`
  matches a target string under `$STAGED` OR `$CURRENT`, so it still recognizes a
  link naming a now-deleted `current/<bin>` and repoints it to `staged/<bin>` —
  idempotent even after current is gone).
- `preinst`/`postinst` run in separate dpkg phases and assume nothing about
  postrm teardown order.

The reorder is therefore safe; the issue's "confirm no other step depends on
current being gone first" is satisfied.

---

## 3. Issue #2000 — postinst upgrade absent-link recovery target

### 3.1 The original bug (pre-`dc1d17cc1`)

The UPGRADE branch of `debian/xpf.postinst` recovered a COMPLETELY ABSENT sbin
link directly to staged:

```sh
for b in $BINS; do
    if [ ! -e "$SBIN/$b" ] && [ ! -L "$SBIN/$b" ]; then
        ln -sfnT "$STAGED/$b" "$SBIN/$b"      # direct to UNVERIFIED staged
    fi
done
```

The existing/dangling-link protection was already correct (the `! -e && ! -L`
guard means only a *completely absent* link is touched — an operator-repointed or
increment-B-staged dangling link is left alone). But the absent-link *recovery
action* targeted the pre-#1964 direct-staged layout.

### 3.2 Why it matters (mixed state before VERIFY/STOP/FLIP)

On a hardened host every other sbin link resolves through `versions/current` (the
verified-live version), while the recovered one resolves to the just-unpacked,
UNVERIFIED `staged/<bin>`. Concrete harms:
- recovered `cli` → operator runs the NEW cli against the OLD running daemon;
- recovered `xpf-userspace-dp` → a direct helper-launch path finds the staged
  helper before the cut verified it (bypasses the verify-dataplane gate);
- a future newly-added managed binary's first upgrade creates its link outside
  `versions/current` permanently.

### 3.3 The merged fix (`dc1d17cc1`) — correct

```sh
CURRENT_DIR=/var/lib/xpf/versions/current
for b in $BINS; do
    if [ ! -e "$SBIN/$b" ] && [ ! -L "$SBIN/$b" ]; then
        if [ -e "$CURRENT_DIR/$b" ]; then
            ln -sfnT "$CURRENT_DIR/$b" "$SBIN/$b"   # recover THROUGH versions/current
        else
            echo "...leaving absent until the verified cut establishes it..." >&2
        fi
    fi
done
```

Three-way matrix, all correct:
- `versions/current/<bin>` exists → recover THROUGH it (same target the seed
  `seed.go:169` and flip `flip.go:43` use, so the cut's flip is a no-op-shaped
  repoint of the same link). Verified-live, never unverified-staged.
- newly-introduced managed binary, no `current/<bin>` yet → LEAVE ABSENT (logged)
  until the verified cut populates `versions/<v>/` and flips. Early exposure of
  the unverified staged binary is exactly what this avoids.
- legacy/never-seeded host (no `versions/current` at all) → all absent links left
  for the preinst migration + the cut to establish, never direct to staged.

This restores the invariant: **the live sbin namespace only ever exposes the
verified-live version, never the just-unpacked staged version, until the verified
cut runs.**

---

## 4. Cross-issue coherence (why they are coupled)

Both issues are the same invariant from opposite ends of the lifecycle:

| | #2000 (establish) | #1997 (teardown) |
|---|---|---|
| Script | postinst `configure <old>` | postrm `upgrade <new>` (downgrade) |
| Direction | upgrade forward | downgrade to pre-hardened |
| Action | recover absent link → `versions/current` | repoint owned link → `staged`, then remove drop-in, then rm current |
| Invariant | live namespace = verified-live only | crash-safe convergent teardown; no orphan drop-in |
| Authority anchor | `versions/current` (forward) | drop-in + `versions/current` presence (reverse) |

The seed (`seed.go`) and flip (`flip.go`) Go code are the third corner: they both
point sbin through `versions/current`, and the #2000 fix aligns postinst with
that idiom while the #1997 fix keeps the teardown convergent. Reviewing them
together avoids a future change re-introducing a staged-direct link on one side
while the other still assumes `versions/current` authority.

---

## 5. Concrete maintainer-script state (what is on master NOW)

- `debian/xpf.postrm` lines 254-280: guard `incoming_predates_hardened_layout
  "$2" && { [ -L CURRENT ] || [ -e CURRENT ] || [ -L DROPIN ] || [ -e DROPIN ]
  }`; body order repoint → remove drop-in → `rm -f CURRENT` (LAST). #1997 fix
  present and complete.
- `debian/xpf.postinst` lines 105-121: `CURRENT_DIR` recovery through
  `versions/current/<bin>`, else leave absent + log. #2000 fix present and
  complete.
- `test/debian/postrm-test.sh`: `rerun_after_crash_removes_orphan_dropin`,
  `oldbug_leaves_orphan_proves_nontautology`,
  `rerun_removes_dangling_dropin_symlink` (+ pre-existing legacy/staged-gen
  scenarios). PASS under sh AND dash.
- `test/debian/postinst-test.sh`: `recovers_cli_through_current`,
  `recovers_helper_through_current`, `leaves_existing_and_dangling_links`,
  `new_managed_binary_stays_absent`, `legacy_no_current_leaves_absent`,
  `oldbug_repairs_to_staged_proves_nontautology`. PASS under sh AND dash.
- `pkg/upgrade/manifest/manifest_drift_test.go:231-232`: both fixtures added to
  `binsSites` drift canary.
- `docs/in-place-upgrade.md`: teardown-order text (lines 198-205, 230, 235-239)
  and the postinst absent-link-recovery bullet (lines 367-383) updated for both
  issues.

---

## 6. Residual-gap audit (hostile; none block close)

These are the genuinely-remaining nits I found while auditing the merged fixes.
None is a regression vs the bug each issue described; each is either documented
intended behavior or a strictly-narrower window than what was fixed. Listed so
the reviewer can decide whether any deserves its own tracking issue.

1. **#1997 residual window between steps 2→3.** A crash AFTER
   `remove_runtime_dropin` but BEFORE `rm current` leaves the drop-in gone and
   `current` present. The rerun guard fires (`current` present), re-enters,
   re-runs all three idempotent steps, and converges. NOT a defect — this is
   exactly the convergence the fix buys. Confirmed idempotent. No action.

2. **#1997 `remove|purge` path has no equivalent crash-window narrative.** The
   `remove`/`purge` case (postrm lines 206-220) runs `remove_owned_sbin_links` →
   `remove_runtime_dropin` → (purge only) `rm -rf VERSIONS STAGED_GEN`. A crash
   mid-`remove` is converged by dpkg's own postrm rerun (all steps idempotent),
   and on the next install the seed re-establishes the layout. No orphan-drop-in
   class here because the drop-in removal is unconditional (not guarded behind a
   to-be-deleted artifact). Lower-risk than the downgrade path; no fix needed,
   but a one-line doc note that the remove/purge teardown is unconditional (so
   immune to the #1997 class) would close the symmetry. Optional.

3. **#2000 newly-introduced binary can stay absent indefinitely on a clustered
   node.** If a new managed binary ships and the operator never runs `xpfd
   upgrade --rolling` (clustered nodes are stage-only), the link stays absent
   until the cut. This is documented-intended (never expose unverified staged),
   but the operator-facing symptom (a missing `/usr/local/sbin/<newbin>` between
   apt-install and the rolling cut) is not called out in operator docs. Optional
   doc note; not a code change.

4. **#2000 / #1997 both assume `versions/current` is a symlink to a sibling dir.**
   If `current` is corrupted to a regular file (matching the preinst
   non-symlink guard at `preinst:137-145`), the postinst `[ -e "$CURRENT_DIR/$b"
   ]` test follows into a non-dir and fails → link left absent (safe). The postrm
   `rm -f current` removes a regular file fine. Both degrade safe. No action.

5. **Float over the #1981 staged-gen interaction.** `staged-gen/` teardown in
   postrm (lines 281-291) is keyed on a SEPARATE higher floor and is orthogonal
   to the #1997 drop-in/current ordering — the two teardowns do not share state.
   Confirmed no interaction. No action.

---

## 7. Invariants (must hold; all currently satisfied)

- **I1 (live-namespace verified-only):** for every `b in BINS`, `/usr/local/sbin/b`
  is either absent OR resolves to `versions/current/b` (verified-live) OR is a
  foreign operator link — NEVER to `staged/b` on a hardened host during an
  upgrade. [#2000]
- **I2 (idempotent postrm teardown):** the downgrade teardown converges to {sbin
  → staged, no drop-in, no current} after ANY number of mid-teardown crashes +
  reruns. [#1997]
- **I3 (atomic link swap):** every sbin/current repoint uses temp-symlink +
  `mv -f` (`atomic_symlink`) OR `ln -sfnT` (replace-or-fail, never nest) — no
  unlink-then-create window where a respawn finds no path. [both]
- **I4 (no orphan drop-in):** after a completed downgrade teardown OR
  remove/purge, no `10-xpf-version.conf` survives pinning a deleted version path.
  [#1997]
- **I5 (seed/flip/postinst agreement):** the postinst absent-link recovery target
  equals the seed target equals the flip target (`versions/current/<bin>`), so
  the cut's flip is a no-op-shaped repoint. [#2000]
- **I6 (drift canary):** `BINS=` in all three scripts == `manifest.Names()`; both
  test fixtures are in `binsSites`. [both]

---

## 8. Risk table

| Risk | Likelihood | Impact | Mitigation / status |
|------|-----------|--------|---------------------|
| Merged fix is subtly wrong and I rubber-stamp it | low | high | Re-derived independently; ran both suites under dash; checked non-tautology proofs exist; cross-checked against seed.go/flip.go. |
| Closing the issue hides a real residual | low | med | Section 6 enumerates every residual; escalate to new issues, don't bury. |
| Reopening/re-engineering churns merged code | med | med | Recommend verify-and-close, NOT a new PR. |
| Drift canary not actually exercising fixtures | low | low | Confirmed `binsSites` lists both; `go test ./pkg/upgrade/...` green per PR. |
| Crash-window test is tautological | low | med | Both PRs ship an `oldbug_*_proves_nontautology` scenario that synthesizes the pre-fix script and asserts it FAILS; verified present + passing. |
| sh-vs-dash POSIX divergence in the guards | low | med | Both suites run under sh AND dash; `shellcheck 0.11.0` exit 0 no warnings per PR. |
| Future change re-introduces staged-direct link | med | med | I5 + drift canary + this cross-issue doc; consider a guard test asserting no `-> staged` link on a hardened host post-upgrade (Section 10). |

---

## 9. Recommendation + rationale (per issue)

### #1997 → PLAN-DEFER (verify-and-close)
The reorder + OR-guard + dangling-symlink robustness fix is correct, idempotent,
and crash-rerun-convergent; it is documented in `docs/in-place-upgrade.md` and
covered by a non-tautological dash-clean regression. The "confirm no other step
depends on current being gone first" research nit is answered (Section 2.4: none
does). No re-engineering — verify on master and close, optionally filing Section
6.2 as a doc nit.

### #2000 → PLAN-DEFER (verify-and-close)
The absent-link recovery now targets `versions/current` (matching seed/flip),
preserves the existing/dangling-link protection, leaves newly-introduced/legacy
links absent until the verified cut, and never exposes the unverified staged
binary. It is documented and covered by a non-tautological dash-clean regression
plus the drift canary. No re-engineering — verify on master and close, optionally
filing Section 6.3 as an operator-doc nit.

(If the reviewer rejects "verify-and-close" as a valid /research outcome for a
merged-but-open issue, the fallback is to treat Section 6's residuals as the
scope and convert this to two tiny doc-only PRs — but I assess that as
gold-plating; the substantive work shipped.)

---

## 10. Test plan (verification, not new development)

All of these are RE-RUN / VERIFY steps against `origin/master`; no new test code
is proposed (the merged PRs already ship the regression scenarios). If the
reviewer wants an *additional* belt-and-suspenders test, item T5 is the one worth
adding.

- **T1 (#1997 rerun convergence):** `dash test/debian/postrm-test.sh` — asserts
  `rerun_after_crash_removes_orphan_dropin` + `rerun_removes_dangling_dropin_symlink`
  pass and `oldbug_leaves_orphan_proves_nontautology` proves discrimination.
  (Verified green at draft time.)
- **T2 (#2000 recovery target):** `dash test/debian/postinst-test.sh` — asserts
  `recovers_cli_through_current` / `recovers_helper_through_current` resolve to
  `versions/current`, `new_managed_binary_stays_absent` +
  `legacy_no_current_leaves_absent` leave absent, and
  `oldbug_repairs_to_staged_proves_nontautology` discriminates. (Verified green.)
- **T3 (drift canary):** `go test ./pkg/upgrade/manifest/...` — `binsSites`
  includes both fixtures; force a `BINS=` drift in a scratch copy and confirm the
  canary fails (sanity that it is live).
- **T4 (lint):** `bash -n` + `shellcheck` on both maintainer scripts — exit 0.
- **T5 (NEW, optional belt-and-suspenders, the only thing worth adding):** a
  postinst scenario that starts from a fully-seeded hardened layout, deletes ONE
  sbin link AND asserts post-recovery that NO sbin link resolves to a path under
  `staged/` (a global I1 assertion, not per-binary). Guards against a future
  partial regression where one branch reverts to staged. Add to
  `postinst-test.sh` only if the reviewer wants it; not required to close #2000.

### How to exercise the actual crash windows / dpkg --configure rerun
The shell suites already reconstruct the exact post-crash on-disk state (sbin
repointed, current removed, drop-in present) and invoke the teardown again —
which is precisely what `dpkg --configure -a` does on a half-configured package.
For a full end-to-end (optional, NOT required to close): in the standalone
Ubuntu 26.04 test VM, `apt install` the hardened `.deb`, then simulate a
mid-teardown kill by manually reconstructing the orphan state and running
`dpkg --configure -a` / re-`apt install` the pre-hardened `.deb` and assert
`systemctl cat xpfd` shows no stale drop-in. The unit-level shell tests are the
authoritative gate; the VM run is confirmatory only.

---

## 11. Out of scope

- The #1981 staged-generation (`staged-gen/`) lifecycle, its floor, and its
  postrm teardown — orthogonal to the drop-in/current ordering (Section 6.5).
- The Go cut-over state machine (`pkg/upgrade/cutover.go`, `flip.go`,
  `runner.go`, `runtime/seed.go`) — the maintainer-script fixes align WITH it but
  do not change it. Touched only as read-references for the invariant.
- The #1985 exec-free downgrade detection and the `HARDENED_LAYOUT_FLOOR` /
  `STAGED_GEN_FLOOR` values — already shipped, unchanged by these issues.
- The #1965 host-wide upgrade lock + preinst gate, and the #1964 legacy-migration
  preinst snapshot — read for phase-order reasoning only.
- HA rolling-upgrade orchestration (`xpfd upgrade --rolling`), kernel A/B channel
  (#1930), signed distribution (#1924) — unrelated subsystems.
- Closing the GitHub issues / posting `Fixes #` — a process action for the
  parent, not a code change.

---

## 12. Open questions (for serial Codex + AGY review)

1. Is "verify-and-close" an acceptable /research disposition for a
   merged-but-open issue, or does the project want these reopened-as-fixed via a
   no-op confirming PR? (Affects whether Sections 6.2/6.3 become tiny doc PRs.)
2. #1997 Section 6.2: is the `remove|purge` teardown's lack of an explicit
   crash-window narrative worth a doc note, or is "unconditional drop-in removal
   ⇒ immune to the orphan class" self-evident enough to skip?
3. #2000 Section 6.3: should the operator docs call out that a NEWLY-INTRODUCED
   managed binary's `/usr/local/sbin/<bin>` is intentionally absent on a
   clustered node between `apt install` and `xpfd upgrade --rolling`? Could an
   operator script that hard-depends on the path being present break?
4. Is T5 (the global "no sbin link → staged on a hardened host" assertion) worth
   adding now as cheap future-regression insurance, or is it gold-plating given
   I1 is already covered per-binary?
5. Does any OTHER maintainer-script path (e.g. a future `prerm`, or the #1981
   `publish-generation` / cut paths) ever create an sbin link, such that the I1
   invariant needs enforcement beyond postinst+seed+flip? (I found none in
   postinst/postrm/preinst/seed.go/flip.go, but the cut runner was only
   read-referenced.)
6. Are the `HARDENED_LAYOUT_FLOOR`/`STAGED_GEN_FLOOR` historical fixed points
   genuinely immune to a future re-release with a lower commit count (e.g. a
   hotfix branch), or could a backport produce a `.deb` version that
   mis-classifies? (Out of scope for #1997/#2000 but adjacent in the same file.)
