# In-place upgrade mechanism (#1917)

The `pkg/upgrade` package implements the verified, atomic,
rollback-capable in-place upgrade cut-over for xpfd + the AF_XDP
dataplane helper. It is invoked as `xpfd upgrade [--rolling]` and from
the `.deb` postinst.

This doc is the module contract for `pkg/upgrade`, the `xpfd upgrade`
subcommand, the postinst HA-mode contract, and the dogfood deploy.

## Layout

```
/usr/local/share/xpf/staged/          dpkg-static staging (increment A) — apt's write target
/var/lib/xpf/versions/<ver>/          non-dpkg runtime version dirs (retain N=3); maintainer-script-managed, NEVER in dpkg's file list (#1964) — seeded at first install
/var/lib/xpf/versions/current -> <ver># bookkeeping pointer (the verified-live version)
/usr/local/sbin/{xpfd,cli,...} -> versions/current/<bin>   live + operator links (resolve THROUGH current, #1964)
/var/lib/xpf/upgrade.state            crash-safe state-machine journal
/etc/systemd/system/xpfd.service.d/10-xpf-version.conf     ExecStart pinned to the CONCRETE version
```

### Managed-binary manifest (single source of truth, #1982)

The set of binaries the upgrade treats as a version-locked unit —
`xpfd`, `cli`, `xpf-userspace-dp`, `xpf-day0-config` — is declared ONCE
in `pkg/upgrade/manifest`. The source list is the UNEXPORTED `managed`
slice (`pkg/upgrade/manifest/manifest.go`) — `[]manifest.Binary`
carrying `Name`, `StagedSrc`, and the `LockstepCut` class. It is
unexported so no importer can mutate or reorder the SSOT at runtime;
callers reach it only through the read-only accessors `manifest.All()`
(a fresh `[]Binary` copy with metadata), `manifest.Names()` (basenames
in SSOT order), and `manifest.LockstepNames()` (the
`LockstepCut == true` subset). Everything that touches the set derives
from it:

- the cut machine (`pkg/upgrade`, `managedBins = manifest.Names()`) —
  copy, flip, verify, GC; its pre-start completeness check
  (`versionDirComplete`) derives the lockstep subset
  (`xpfd`, `xpf-userspace-dp`) from `manifest.LockstepNames()`;
- the first-install seed (`pkg/upgrade/runtime`, same derivation);
- the maintainer scripts (`debian/xpf.{preinst,postinst,postrm}`) and
  `debian/rules` keep a self-contained `BINS="..."` literal / install
  set (no build-time mutation of tracked files — a sed-into-the-checkout
  step would dirty git and double-edit on re-run);
- the shell test fixtures under `test/debian/`.

A Go drift canary (`pkg/upgrade/manifest`'s
`TestManagedBinaryDriftCanary`) parses every shell site and FAILS the
suite if any list diverges from `manifest.Names()`, fail-closed (a site
that drops its `BINS=` literal trips the canary rather than passing
vacuously). To add a managed binary: add an entry to the `managed`
slice in `pkg/upgrade/manifest/manifest.go`, then update each shell
site to match — the canary tells you which ones.

## State machine (`pkg/upgrade`)

```
STAGED -> PREFLIGHT -> COPIED -> VERIFIED -> STOPPED -> FLIPPED -> STARTED -> COMMITTED
```

Each transition is journaled (temp+fsync+rename) so a crash is
recoverable and idempotent — re-running `xpfd upgrade` resumes from the
journal. The ONLY live-state mutations are STOP and FLIP-then-START;
PREFLIGHT / COPY / VERIFY are pure and abortable (a failure there leaves
the running daemon and config untouched).

**Superseded stale cut (a NEWER version was staged before the old cut
finished).** When the journaled target differs from the newly-staged
version, the live system is recovered to a consistent state BEFORE a fresh
cut starts, so the new cut's rollback target (`PreviousVersion`, read from
`current`) is always a verified-live version. For a stale **STOPPED**
journal the old cut already stopped the daemon but never flipped `current`,
so recovery restarts the still-current KNOWN-GOOD daemon. That restart is
**fail-closed** (#5846): if `StartUnit` FAILS, recovery ABORTS and returns
the error — it does NOT sweep partials, reset the journal, or begin a fresh
cut, because doing so would start a new cut whose rollback target is the
version that JUST FAILED TO RESTART while the control plane is DOWN
(possible unrecoverable state). The stale journal + partials are PRESERVED
so an operator or the next-boot re-run retries recovery; a fresh cut
proceeds only once the known-good daemon is confirmed restarted. This
mirrors the fail-closed-on-lifecycle-error posture of the rolling/kernel
drain paths (#5845).

- **PREFLIGHT** — check `/var` free ≥ staged size + config-DB snapshot
  size + margin; GC eligible versions if short; take the pre-upgrade
  config-DB snapshot (`.partial`+rename, never torn) for rollback.
  The config-DB dir is classified **fail-closed** (#5074): the stat is
  branched explicitly — `nil` ⇒ present (snapshot it), `os.IsNotExist`
  ⇒ the ONLY legitimate skip (genuinely no DB), and ANY OTHER stat error
  (EACCES/EIO/stale mount) ⇒ ABORT the (pure) preflight before any live
  mutation. A transient/permission error must NOT be misread as "DB
  absent": that would leave `DBSnapshotPath` empty (`AdvancedStateFloor`
  false) and let the binary cut proceed with no restorable pre-upgrade
  DB, so a later rollback could not restore the config. A `dirSize`
  failure while sizing a PRESENT DB (e.g. EIO on a subfile) is likewise
  surfaced, never silently sized as 0.

  **A RESUMED cut RE-TAKES this snapshot (#6556).** PREFLIGHT, COPY and
  VERIFY are pure — the daemon stays LIVE and accepting commits across
  all three — and the host-wide upgrade lock is NOT held across an
  interruption, so the operator has no signal that a cut is pending. A
  resume that reused the snapshot taken at the ORIGINAL preflight meant a
  later auto-rollback silently reverted every commit made in the
  interruption window. This is the same argument the VERIFY bullet below
  already makes for its own sibling case (#1967/#1981), with a crash in
  place of a verify failure.

  The re-snapshot is FLOORED at STOPPED, and that floor is load-bearing
  rather than cautious. From STOPPED the daemon is down, so no commit can
  have landed and there is nothing to re-capture; and re-snapshotting at
  FLIPPED would be actively WRONG — `versions/current` already points at
  the new binary, which may have started and migrated the DB envelope, so
  the "pre-upgrade" snapshot would capture POST-upgrade state and defeat
  rollback entirely. The exposed span is exactly
  `{PREFLIGHT, COPIED, VERIFIED}`.

  The snapshot writer (`snapshotConfigDB`, extracted from `preflight` so
  the resume path shares one implementation) also changed its ORDERING
  for this: the replacement is made durable in `.partial` FIRST and only
  then does the previous snapshot give way. The pre-#6556 code removed
  the live snapshot before copying, which is harmless on a first
  preflight (nothing to lose) and not harmless on a re-snapshot — a crash
  mid-copy would leave the journal naming a directory that no longer
  exists, so the rollback fails at restore time instead of falling back
  on the older snapshot. It re-classifies the DB directory rather than
  trusting the original preflight's verdict: a DB that is GONE by resume
  time clears `DBSnapshotPath`/`AdvancedStateFloor` **and removes the
  stale snapshot dir**, so a rollback cannot restore a config DB over a
  root the operator deliberately emptied.
- **COPY** — `staged/` → `.<ver>.partial/` + checksum + atomic rename to
  `versions/<ver>/`. A crash never leaves a half-populated version dir;
  stray `.partial` dirs are swept on re-run, and the sweep fsyncs the
  parent `versions/` dir so the unlink cannot be resurrected by a crash
  before the next parent fsync (#1967 C4). The version key (`<ver>`) comes
  from `staged/xpfd version` and is validated as a safe single path segment
  (no `/`, `..`, leading dot, whitespace, control/high bytes) — a corrupt
  binary or a benign `version`-format drift hard-fails the cut rather than
  keying `versions/` by garbage (#1967 C1; `BinaryVersion` never falls back
  to the raw output).
- **VERIFY** — `versions/<ver>/xpfd verify-dataplane` against the running
  kernel with throwaway socket/state/pin env paths. A REJECT aborts with
  the live dataplane untouched. On a verify failure the just-copied
  `versions/<ver>/` is removed and the journal is rewound below COPIED, so
  a same-version retry (operator drops a corrected binary into `staged/`)
  RE-copies and re-verifies rather than re-verifying the stale failing copy
  (#1967). Two guards: the cleanup NEVER deletes the active or rollback
  version dir (only when `<ver>` is neither `current` nor PreviousVersion),
  and the journal is rewound BELOW PREFLIGHT (with the stale DB-snapshot
  fields cleared and the snapshot removed) so the retry takes a FRESH
  config-DB snapshot and recopies — the daemon stays live across a verify
  failure, so a config change before the retry must not be captured by the
  pre-failure snapshot (a later rollback would otherwise lose it).
- **STOP → FLIP → START** — stop the old daemon (closes the
  respawn-mismatch race: no live process can re-resolve the flipped
  helper), flip `current` + the `/usr/local/sbin` links + the unit
  ExecStart drop-in, then start the new daemon. Before START a diagnostic
  check confirms `versions/<ver>/{xpfd,xpf-userspace-dp}` still exist
  (a concurrent GC/disk event in the FLIP→START window) — a missing binary
  fails fast with a clear cause and routes through the same START-failure
  auto-rollback (#1967 C3, diagnostic only; the outcome was already covered
  by the START-failure rollback).

### Respawn-mismatch closure (two structural guards)

1. **STOP-before-FLIP** — no live old xpfd exists to respawn a helper
   after the unit is stopped.
2. **Concrete-version ExecStart** — the FLIP templates the unit
   `ExecStart`/`ExecStartPre` to the literal `/var/lib/xpf/versions/<ver>/xpfd`
   path (NOT the `current` symlink — systemd does NOT symlink-resolve
   `argv[0]`). So `dir(os.Args[0])` is the matching-version dir and even
   a transient respawn resolves the matching-version `xpf-userspace-dp`,
   never the shared `/usr/local/sbin` link.

### Post-start helper-readiness gate (#5286)

After START, the cut consults `System.HelperHealthy(expectVersion,
StartHealthDeadline)` before it COMMITS (GC + clear the rollback journal on
the standalone path) or returns the node to HA election. This gate decides
whether the new version actually forwards.

The production `realSystem` accepts a helper-health probe injected via
`upgrade.NewSystemWithHelperHealth`; `cmd/xpfd` (`buildUpgradeSystem`) now
wires it. Before #5286 the construction site used the probe-less
`NewSystem`, so `HelperHealthy` degraded to a bare `systemctl is-active`
poll and IGNORED `expectVersion` — service PROCESS ACTIVITY was the only
witness. Because xpfd is `Type=simple`, systemd reports the unit active the
instant the process is up, so the cut could COMMIT while the userspace
helper was down / stale / crash-looping and NOT forwarding.

The wired probe (`upgrade.HelperHealthProbe`) fails CLOSED unless, within
`StartHealthDeadline`, it observes ALL of:

1. **process up** — `systemctl is-active <unit>` == active. Necessary but
   NOT sufficient (this alone was the pre-#5286 signal).
2. **armed + forwarding** — the userspace helper answers a one-shot
   control-socket `status` query (the existing
   `userspace.ProbeStatus`/`ProbeForwardingArmed` request — no new IPC)
   reporting `Enabled && ForwardingArmed`, the authoritative "forwarding is
   live" pair. A down/stale/crash-looping helper fails here.
3. **on the target version** — the armed helper's executable
   (`/proc/<pid>/exe`) resolves under `versions/<expectVersion>/`, so a
   stale previous-version helper still armed on the shared control socket is
   not mistaken for the freshly-cut dataplane. This leans on the
   concrete-version `ExecStart` invariant above: `dir(os.Args[0])` — and
   therefore the co-located `xpf-userspace-dp` — is the matching-version
   dir.

The control-socket path is resolved from the ACTIVE config (honoring an
operator `system dataplane control-socket` override) with a default
fallback, so the gate probes the socket the running helper actually listens
on. Per the #1373 eBPF retirement the userspace helper is the ONLY
forwarding path, so a healthy post-upgrade node MUST have an armed
forwarding helper — there is no legitimate no-helper case to exempt. A
not-healthy result flows into the existing rollback path below.

#### `StartHealthDeadline` is AUTHORITATIVE across every blocking op (#5808)

The gate must RETURN by `StartHealthDeadline` no matter which dependency
wedges — otherwise a hung `systemctl`/DBus or an unresponsive control
socket strands the post-flip cut PAST the point where an automatic
rollback (standalone) or an operator-driven fence (HA) is still timely.
Before #5808 the `systemctl is-active` precondition ran under an
unbounded `exec.Command`, so a wedged systemd could block the whole gate
indefinitely.

The probe now bounds **every** blocking call by one `context.WithTimeout`
of `StartHealthDeadline`:

- **is-active probe** runs under `exec.CommandContext`; a wedged
  `systemctl` is SIGKILLed at the deadline, not left blocking. This is the
  single shared primitive `upgrade.UnitActive(ctx, unit)` — the wired
  `HelperHealthProbe` precondition, the probe-less fallback poll, AND
  `cmd/xpfd`'s wiring all route through it (one timeout behavior, not two
  divergent `exec.Command` impls).
- **control-socket status query** is capped to `min(StatusTimeout,
  time-remaining-to-deadline)`, so a `StatusTimeout` larger than the
  deadline can never run the query past it.
- **poll wait** uses a context-aware timer (`select` on `ctx.Done()` vs
  the poll timer), so it never overshoots the deadline by a full poll
  interval.

#### Every poll loop in `pkg/upgrade` bounds its sleep by the deadline (#7424)

The overshoot above is a package-wide property, not a `HelperHealthProbe`
one. `kernel_drain.go`'s two drain loops have used the `sleepBounded`
helper since #5808; `rolling.go`'s `waitPredicate` was the last raw
`time.Sleep(PollInterval)` in the package and now uses it too, so the
helper takes the interval as a parameter rather than reading the
`drainPollInterval` constant.

The deadline check sits BEFORE the sleep, which is what made this a wrong
ANSWER and not merely a late one: a predicate that first became true
*after* the deadline was accepted as satisfied within it, and a genuine
timeout was reported up to one poll interval late.

Note for anyone adding a test here: every pre-existing fixture in this
package uses `PollInterval: 1ms`, so the overshoot is 1ms and invisible to
all of them. `rolling_bounded_sleep_7424_test.go` inverts the ratio — a
50ms deadline against a 5s interval — because that is the smallest shape
in which removing the bound changes an outcome.

The gate distinguishes a definitive *not-ready* (retry until the deadline)
from a deadline/cancellation: a deadline failure wraps the context cause,
so callers can `errors.Is(err, context.DeadlineExceeded)`. The most-recent
GENUINE readiness failure (e.g. "helper not forwarding") is retained as
the diagnostic `last:` cause — a deadline *symptom* (a killed probe, or the
status query having no remaining budget) does not mask it. Standalone
auto-rollback and HA fence (`SkipStartHealthRollback`) both trigger
PROMPTLY at the deadline instead of hanging.

### Rollback (binary + DB atomic)

Standalone auto-rollback (on an unhealthy post-start helper) and operator
rollback both restore the config DB BEFORE re-flipping the binary:

```
stop -> restore config-DB snapshot (PREFLIGHT) -> re-flip current/sbin/unit to previous -> start
```

This is mandatory because the N+1 daemon writes `active.json` in the
config compatibility envelope (see below); a bare binary re-flip to N
would boot an N daemon that fatal-rejects the N+1 envelope DB (a brick).
The HA path disables auto-rollback — HA rollback is operator-driven (an
auto re-flip mid-rolling un-coordinates the cluster).

## First-install seed + legacy migration + refuse-before-STOP (#1964)

The cut needs a real, immutable rollback target. Before #1964 the very
first `.deb` install seeded none: the first (or legacy-migration) upgrade
had `PreviousVersion==""` and `rollback()` hard-refused — but dpkg had
already overwritten the old binary in `staged/`, so there was no recovery
path. #1964 closes this with three composed mechanisms (A/B/C) and one
layout invariant.

**Layout invariant:** `versions/<ver>/` and the `current` symlink are
runtime state OWNED BY THE MAINTAINER SCRIPTS, never in dpkg's file list.
dpkg only ever writes `staged/`. `/usr/local/sbin/*` resolve THROUGH
`versions/current`. Consequence: dpkg can never clobber a versioned
rollback target on a later unpack, because it does not know those paths
exist.

- **A — first-install seed (`xpfd seed-runtime`, `pkg/upgrade/runtime`).**
  On first install (`$2` empty) the postinst runs `seed-runtime` AFTER
  unpack but BEFORE `#DEBHELPER#` starts the unit: copy `staged/*` →
  `versions/<v>/`, set `versions/current → <v>`, repoint sbin through
  `versions/current`. No cut/verify/stop. Idempotent + crash-safe (`.partial`
  + atomic rename; symlinks via temp+rename; a re-run converges). If
  seeding fails the postinst falls back to legacy direct-staged links (the
  next upgrade migrates) and never fails the install.
- **B — legacy-migration snapshot (`debian/xpf.preinst`, self-contained
  shell).** A host installed BEFORE this layout has sbin → `staged/` and no
  `versions/current`. On its next upgrade the preinst — running BEFORE
  unpack, so the new Go-seed-capable `xpfd` is not on disk yet — snapshots
  the OLD `staged/*` into `versions/<oldver>/`, sets `current`, and
  repoints sbin, all in the SAME `upgrade` case as the #1965 lock gate,
  AFTER that gate passes. Idempotency: no-op the copy when `current` exists;
  ALWAYS (idempotently) complete the sbin repoint (a crash after `current`
  but before sbin still completes on retry). Rename-collision retry: if
  `versions/<oldver>` already exists, skip copy+rename and jump to creating
  `current` (avoid ENOTEMPTY blocking apt). Atomic symlink repoint via
  `ln -sf … .tmp && mv -f` (NOT `ln -sfnT`, which unlinks-then-creates).
  `<oldver>` is `staged/xpfd version` (validated a safe path segment),
  falling back to a sanitized dpkg `$2` if the old binary won't exec; never
  fails the transaction. Writes NO upgrade journal.
- **C — refuse-before-STOP (unconditional pre-STOP invariant).** The cut
  NEVER calls `StopUnit` unless a **restorable** target exists OR it is an
  explicitly sanctioned no-rollback first cut
  (`Options.AllowNoRollbackFirstCut`). With A/B this is unreachable in the
  field (`current` always exists), so the refusal fires only on an
  unexpected loss of the rollback target — exactly when a blind STOP would
  brick the daemon. On a flip failure AFTER STOP (the unit is already down),
  `recoverFromFlipFailure` rolls back to the previous version, or — for a
  sanctioned first cut — restarts the first-install binary from
  `versions/current`; it always returns a non-nil error so a flip failure is
  never reported as success.

  **"Restorable" is stricter than `PreviousVersion != ""` (#6374).** A
  nonempty basename is NOT sufficient: `os.Readlink` succeeds on a *dangling*
  `current` (target dir missing after storage damage / an interrupted
  repair), and `filepath.Base` silently strips a pathful target, so a
  corrupt `current` used to yield a nonempty `PreviousVersion` that passed
  every guard — then the post-STOP rollback flip to the missing dir failed
  and left xpfd offline. The recorded rollback target now comes from
  `restorableCurrentTarget`, which returns `ver==""` unless `current` is a
  symlink naming a **bare in-tree segment** whose `versions/<ver>/`
  **directory exists** and holds the **complete managed lockstep set**
  (`manifest.LockstepNames`), where each lockstep binary is a **regular file
  carrying the executable bit** — the flip drop-in execs the literal
  `versions/<ver>/xpfd` path, so a lockstep entry that is a directory / FIFO
  / socket / symlink / non-executable-bit file cannot be exec'd by systemd
  and is rejected (`os.Lstat`, so a symlink is rejected outright rather than
  followed). Beyond that type+bit metadata, each lockstep binary's **content**
  is parsed as an **ELF image** (`elfHeaderParseable` → `debug/elf.Open`, a
  best-effort content gate, #6409): a regular exec-bit file whose content is
  arbitrary text (`chmod 0755`), an empty/truncated file, or a file with a
  corrupt header carries the exec bit yet `execve` would fail and strand the
  daemon after STOP — the ELF parse rejects those. The lockstep set is
  exclusively native compiled binaries (`xpfd`, `xpf-userspace-dp`), never a
  script, so an ELF header gate carries no false-reject risk for a legitimate
  non-ELF runtime. This remains a **heuristic, not a guarantee** (#6409):
  proving "systemd can exec this" without exec'ing it is undecidable
  statically, so a structurally valid ELF whose **machine is wrong for the
  running architecture** or whose **body is corrupt** still parses here and is
  left to systemd's arbitration at restart (surfaced by the existing
  start-failure / auto-rollback path, not a silent bad cutover). The common
  dangling/pathful/incomplete/wrong-type/non-executable-bit **and non-ELF /
  truncated / corrupt-header content** modes are rejected here. The same
  `validateRestorableVersion` predicate
  re-checks a *persisted* `PreviousVersion` on every resume before STOP (a
  pre-#6374 journal or a dir damaged/GC'd after INIT is caught), and gates
  the standalone `rollback()` **before** it stops the daemon or restores the
  config DB — so an unrestorable target surfaces a clear error instead of
  rolling the DB back and then stranding the control plane on a missing
  runtime. (The HA path sets `SkipStartHealthRollback`; its rollback is
  operator-driven and never enters `rollback()`.)

  **The sanction covers ONLY a genuinely-absent `current` (#6374).**
  `restorableCurrentTarget` returns a second value, `present`, that
  distinguishes a **genuinely absent** `current` (`os.IsNotExist` →
  `present=false`, a real first install) from a **present-but-unrestorable**
  one (`present=true`: not a symlink / pathful / dangling / non-directory /
  lockstep-incomplete / an indeterminate `EACCES`/`EIO` stat error).
  `AllowNoRollbackFirstCut` / `FirstCutSanctioned` may bypass the
  refuse-before-STOP guard **only when `!present`**. A present-but-corrupt
  `current` still had a rollback target and it is now broken — stopping the
  daemon would strand it, the exact #6374 hazard — so it **refuses regardless
  of the sanction**, both at INIT **and on every resume**. The resumed
  empty-previous branch does not trust the persisted/invocation sanction on
  its own: it **re-resolves `current` at resume time** and refuses if
  `current` is now present-but-unrestorable — defending against a poisoned
  pre-#6374 journal (an over-broad sanction persisted for a present-but-corrupt
  `current`) or a `current` that corrupted after a genuinely-sanctioned INIT.
  It keys on *present AND unrestorable* (`present && ver==""`), NOT merely
  *present*, so a legitimate first-cut resume whose flip already pointed
  `current` at the (restorable) target still proceeds. Symmetrically the
  pre-STOP revalidation of a *nonempty* recorded `PreviousVersion` refuses
  regardless of the sanction (a recorded-but-broken target is never a
  sanctionable first install); the sanction applies only to a recorded-*empty*
  target with a still-absent `current`. An indeterminate I/O error on the
  target fails **closed** (`present=true` → refuse), never silently treated as
  absent-and-sanctionable.

  `readCurrentVersion` itself is unchanged — it still returns the raw
  basename for the conservative "never delete a dir that might be live" GC /
  stale-dir-replace guards, which must protect a present-but-incomplete live
  dir rather than treat it as absent.

Version strings that key `versions/<ver>` — and, the strictest sink, the
`ExecStart` line in the `10-xpf-version.conf` unit drop-in — are validated by a
SINK-AWARE strict allowlist (`ValidateVersionSegment`, mirrored by the shell
`is_safe_segment` in `debian/xpf.preinst`): only `[A-Za-z0-9]` plus
`. _ + ~ - :` are accepted, so Debian/semver versions (`1:2.3.4-1`,
`1.0.0~beta1`, `1.0.0+build.7`) pass while `/`, `..`, leading dot, whitespace,
and control chars are rejected. It also rejects `%` and the other systemd
argv metacharacters (`$`, `"`, `'`, `\`, backtick): although harmless as a bare
filesystem path segment, `%` is a **systemd unit specifier** (`%i`, `%n`, …), so
a `%`-bearing version substituted into the pinned `ExecStart` would be expanded
by systemd and silently rewrite the executable path after the upgrade STOP
(#5713 M41). None of these is legal in a Debian/semver version, so the allowlist
fails closed rather than substituting them.

**Lifecycle (`debian/xpf.postrm`):** remove/purge remove sbin links that
resolve through `versions/current` (in addition to legacy direct-staged
links), only when owned, AND remove the runtime unit drop-in
`/etc/systemd/system/xpfd.service.d/10-xpf-version.conf` + rmdir the now-empty
`.service.d` dir + boot-guarded `daemon-reload` (#1967) — otherwise systemd is
left with a drop-in whose ExecStart pins a deleted `versions/<ver>/xpfd`. The
drop-in removal is safe on legacy/never-seeded hosts (absent file) and leaves a
non-empty `.service.d` (a foreign operator drop-in) intact. `versions/` is left
on `remove` (a reinstall reuses it) and removed on `purge` (it is copied
binaries, not operator config — Policy §6.8). A downgrade to a package
predating this layout repoints sbin back to `staged/` atomically, removes the
runtime unit drop-in + boot-guarded `daemon-reload` (shared helper), and
finally deletes `versions/current` — so the downgraded binaries actually take
effect. The destructive `versions/current` delete runs LAST (#1997): a kill
mid-teardown after `rm current` but before the drop-in removal used to leave an
orphan `10-xpf-version.conf` that a postrm RERUN skipped (the rerun saw
`current` gone and took the false branch), pinning an `ExecStart` for a layout
the downgraded package no longer manages. Removing the drop-in before the
`current` delete shrinks the single-run window to nothing, and the rerun
presence guard now also keys on the drop-in's presence so a rerun re-enters and
converges (all three teardown steps are idempotent).

### Downgrade detection is exec-free and version-keyed (#1985)

The postrm must decide whether the package being installed predates the #1964
hardened layout (and so the lingering `versions/current` + drop-in must be torn
down). It originally did this by EXECUTING the staged binary
(`"$STAGED/xpfd" seed-runtime --capability-check`) and treating any non-zero
exit as "pre-hardened, tear the layout down". That conflated two different
things: a binary that genuinely lacks the subcommand, and a binary that cannot
EXEC AT ALL (dynamic-link error during unpack, corruption, libc/ABI conflict,
architecture mismatch). On a genuine UPGRADE where the new staged `xpfd`
happened to be non-execable, the `&&` short-circuited to false and the
destructive branch ran — deleting `versions/current`, repointing sbin to
`staged/`, and removing the drop-in — breaking the daemon on next boot.

The decision is now keyed on the dpkg-supplied INCOMING version (`$2`), which
is exec-free and has no staleness hazard:

```sh
if incoming_predates_hardened_layout "$2" \
   && { [ -L "$CURRENT" ] || [ -e "$CURRENT" ] \
        || [ -L "$DROPIN" ] || [ -e "$DROPIN" ]; }; then
    repoint_owned_sbin_to_staged   # 1. owned sbin -> staged (idempotent)
    remove_runtime_dropin          # 2. drop-in + daemon-reload (idempotent)
    rm -f "$CURRENT"               # 3. delete current LAST (idempotent, #1997)
fi
# incoming_predates_hardened_layout: dpkg --compare-versions "$2" lt FLOOR
```

The `[ -L "$DROPIN" ] || [ -e "$DROPIN" ]` arm is the #1997 crash-rerun fix: it
lets a postrm RERUN re-enter the teardown to finish removing an orphaned drop-in
even after `versions/current` is already gone. Each artifact is probed with both
`-L` and `-e` so a dangling symlink (which `-e` alone reports as absent) still
trips the guard.

`HARDENED_LAYOUT_FLOOR` is `0.0.4104` — the `.deb` version
(`0.0.<commit-count>+g<sha>`, `Makefile` `DEB_VERSION`) of commit `ef9525e70`,
the first package whose postrm manages the versioned-runtime layout on
downgrade and whose `xpfd` answers `seed-runtime --capability-check` — i.e.
the first package classifiable as hardened by this teardown contract. (Earlier
#1964 commits added the postinst seed at count 4102 and the preinst migration
at 4103; the postrm downgrade handling this floor protects landed at 4104.)
Any incoming version `< 0.0.4104` predates the contract and is a genuine
pre-#1964 downgrade; `>= 0.0.4104` (upgrade OR hardened->hardened downgrade,
including the floor version `0.0.4104+g<sha>` which sorts above the bare
`0.0.4104` floor) leaves the layout alone. The floor is a HISTORICAL fixed
point (the contract already shipped), not a per-release value — it is
never bumped.

- The teardown runs ONLY when `$2` is a confirmed pre-#1964 version AND a
  hardened artifact is present — `versions/current` OR (for the #1997
  crash-rerun case) the runtime drop-in.
- An empty or unparsable `$2` (`dpkg --compare-versions` exits 2) leaves the
  layout intact — the safe default, never a teardown on ambiguity. This
  mirrors the sibling `preinst migrate_legacy_layout` posture
  (skip-don't-destroy). The verify-dataplane cut gate / refuse-before-STOP
  guard (`pkg/upgrade/cutover.go`) is the backstop for a hardened-but-
  unrunnable staged binary.

A presence-only file marker (a sentinel the hardened package ships) was
considered and REJECTED: dpkg removes a file present ONLY in the old package
AFTER the old-postrm runs (Debian Policy 6.6 unpack order), so a marker shipped
by the hardened package LINGERS on disk at old-postrm time during a genuine
pre-#1964 downgrade and would mis-signal "incoming is hardened", skipping the
teardown the downgrade needs. The version argument has no such staleness.

**One-time buggy->fixed exposure.** dpkg runs the OLD package's `postrm
upgrade <new>` during an upgrade. Upgrading FROM a pre-#1985 (exec-probe)
package therefore still runs that OLD buggy postrm; the version-floor gate
cannot protect its own rollout for that single hop — the fix cannot run
before it is installed. The exposure fires ONLY if, at OLD-postrm time, the
new staged `xpfd` is non-execable AND `versions/current` exists. The realistic
trigger is an OS/libc bump in the SAME apt transaction making the new binary
temporarily unloadable; stage xpf upgrades separately from OS/libc bumps.
**Recovery** if the old postrm did tear the layout down: re-run `xpfd
seed-runtime` (or reinstall the package) to rebuild `versions/current` + the
unit drop-in before the next cut.

## HA rolling upgrade (`xpfd upgrade --rolling`)

Cuts the LOCAL clustered node with a controlled drain so the cluster
keeps forwarding. Run on each node in turn (the deploy driver sequences
both); exactly one node is primary throughout.

The rolling path is selected ONLY by the `--rolling` flag. `xpfd upgrade`
now REJECTS any stray positional argument (#4869): `flag.Parse` stops at
the first non-flag token, so `xpfd upgrade rolling` (missing the two
dashes) would otherwise leave `--rolling` false and silently run the
uncoordinated STANDALONE cut on a clustered node — no drain, no
takeover. A mistyped or misplaced argument is a hard usage error, not a
wrong/default run.

**Sibling lifecycle verbs reject leftover operands too (#5322).** The same
`flag.Parse`-stops-at-the-first-operand hazard applied to every sibling
root-only lifecycle verb, which had no `NArg()` guard: `xpfd seed-runtime`,
`xpfd publish-generation`, `xpfd cleanup`, and the `xpfd upgrade kernel`
`promote`/`drain`/`rejoin` sub-verbs (`status` is guarded for consistency).
A typo like `xpfd publish-generation typo --staged-gen-dir /lab` used to keep
the PRODUCTION default staged-gen dir (the `--staged-gen-dir` intent silently
discarded) and still repoint/GC the live generation while reporting success;
`xpfd upgrade kernel promote g0-typo` still reordered `BootOrder`. Each verb
now REJECTS any unexpected operand before any privileged mutation (the
publish-generation guard runs BEFORE the host-wide lock is taken). Legitimate
arity is preserved: `arm` still takes exactly one operand (the target kernel
version); the no-operand verbs take none.

**Clustered-node standalone-cut invariant (#5284).** Arg parsing alone is
NOT enough: a VALID empty arg set (a plain `xpfd upgrade`) still selects
`Runner.Run` purely because `--rolling` was omitted, and the postinst
deferred-publish recovery hint and this doc's recovery snippets emit that
bare verb. `Runner.Run` therefore enforces the invariant at the FINAL
privileged boundary — BEFORE the host-wide upgrade lock and BEFORE any
journal read or `StopUnit`: if the cluster-identity marker
`/etc/xpf/node-id` is PRESENT and the cut was NOT invoked by the rolling
driver, the run is refused (`refuse-standalone-cut-on-clustered-node`)
with guidance to use `xpfd upgrade --rolling`. It fails CLOSED (never
auto-reroutes) and the unit is NOT stopped, so the daemon keeps
forwarding. Presence — not content — is the signal, matching the daemon's
own HA boot-class gate (`pkg/daemon` `hasNodeIDFile`). This catches ALL
callers of the standalone flow, not just the CLI arg path; the CLI also
rejects early (belt-and-suspenders) for the clearest message. The rolling
driver (`RunRolling`) legitimately performs the per-node cut AFTER its
drain, so it invokes the inner `Runner.Run` with an internal
`ClusterCoordinated` flag that bypasses this gate — the gate distinguishes
a BARE standalone cut from a rolling-driver-invoked local cut, so
coordinated rolling upgrades are never blocked. A standalone node (no
`/etc/xpf/node-id`) is entirely unaffected.

**Indeterminate-membership fail-closed contract (#5573).** The
presence test is a tri-state, not a boolean. `ClusterNodeIDPresent`
returns `(true,nil)` when the marker exists (clustered), `(false,nil)`
ONLY for `os.IsNotExist` / ENOENT (genuinely standalone → proceed), and
`(false,err)` for EVERY other `os.Stat` failure — EACCES, EIO, ESTALE,
LSM denial, mount fault. A non-ENOENT lookup error means HA membership
is UNKNOWN, and BOTH the CLI belt-and-suspenders check and the
`Runner.Run` privileged gate FAIL CLOSED on it
(`refuse-standalone-cut-indeterminate-cluster-membership`): they refuse
the uncoordinated cut and do NOT stop the unit, because assuming
standalone when the marker is unreadable would let the
STOP→FLIP→START flow blackhole a real HA node whose peer is not ready.
Before #5573 the predicate returned `err == nil` for every error, so an
unreadable marker on a clustered node collapsed to "standalone" and both
gates were bypassed — a fail-OPEN HA-safety hole. The fix is
error-classification only; failover timing and the VRRP/session-sync
state machines are untouched.

1. assert peer alive + session sync established + HA protocol compatible
   (`CurrentHAProtocolVersion`) + session-sync WIRE version compatible
   (`SessionSyncWireVersion`, #7990) — else ABORT to image-replace (Path C),
   never drop connections.

   Note the third and fourth are different questions. "Session sync
   established" means the sync LINK is up; the wire-version check means the
   peer can actually DECODE the frames this node sends. Before #7990 only the
   first was asked on this path, and since #7925 the two versions are separate
   counters — so a peer with a matching HA version could still be unable to
   decode a single session frame.
2. **peer-takeover-ready precheck BEFORE demoting** — demoting a node
   whose peer cannot take over strands VIPs.
3. `ForceSecondary()` to start the drain.
4. **strong drain predicate** — peer owns the RGs, local VRRP BACKUP with
   no VIPs, `rg_active` false, sync clean (NOT merely "weight 0 set" — an
   RG keeps forwarding while VRRP is still MASTER). On timeout: fail back
   (`ResetFailover`) and ABORT WITHOUT cutting. When the failback SUCCEEDS the
   node resumed forwarding — no harm. But `ForceSecondary` already DEMOTED the
   node, so a FAILED failback is NOT harmless: the abort surfaces BOTH failures
   (`errors.Join`) and warns the node may be **stranded demoted** (force-
   secondary not undone, peer takeover unproven → possible both-nodes-secondary
   outage) so an operator investigates — it must NOT keep claiming "still
   forwarding" (#5845, mirroring the kernel-roll drain path `kernel_drain.go`).
5. single-node cut (auto-rollback disabled).
6. wait for session sync to re-establish, bounded by `RejoinDeadline`
   (60s default). The cut just restarted xpfd, so the local gRPC socket
   refuses connections for the first few seconds — that `connection
   refused` is the EXPECTED transient, treated as "not ready yet" and
   re-polled until the deadline (NOT a hard abort on the first dial
   error). Only the deadline aborts, surfacing the last observed error;
   the node is then left secondary for the operator to inspect.
7. `ResetFailover()` to rejoin election, then a **per-RG rejoin confirm**
   before the driver advances to the peer. `ResetFailover` enumerates the
   configured RGs FAIL-CLOSED (no `{0,1,2}` guess — #5044) and resets each,
   but a reset that returned nil is not proof the RG actually left the drain.
   So `RejoinAndConfirm` additionally gates on `LocalRejoinComplete()`: every
   configured RG (enumerated from `show chassis cluster status`) must show a
   non-zero `Weight` in `show chassis cluster information` — `ForceSecondary`
   zeroes every RG's weight, so a configured RG still at weight 0 (or absent
   from the local view) reads as STILL DRAINED and the rejoin does not confirm
   (#5138). Without this, `PeerAlive` + `SyncEstablished` (both GLOBAL) would
   green-light the rejoin while some RG — e.g. RG≥3 the old guess dropped —
   stayed demoted, and the driver would drain the peer that still owned it,
   opening a no-primary window for that group. forward-verify is the natural
   post-promotion check (`make test-failover`) — a passive node structurally
   cannot forward, so it is never "verified while passive".

   **#6557**: until that issue, this paragraph described the intent and the
   code did not implement it. `runRollingWith` step 7 called a bare
   `cl.ResetFailover()` and returned nil; `RejoinAndConfirm` — declared on
   the `RollingCluster` interface in `rolling.go` itself — was wired only
   into `kernel_drain.go`. `fakeCluster` had carried the `rejoinIncomplete`
   / `rejoinErr` seams since #5138 and no rolling test ever set them, and
   `TestRolling_HappyPath` asserted only that `ResetFailover` was *called*,
   so nothing observed the difference between requesting a rejoin and
   confirming one. Step 7 now calls `RejoinAndConfirm(cl, RejoinDeadline)`,
   so the binary rolling cut and the LANE-1 kernel roll share ONE definition
   of "rejoined". On failure the node is left secondary and the error tells
   the driver explicitly not to advance to the peer.

### `--unit` and the cluster control endpoint (#1983)

`--unit <name>` (default `xpfd`) selects the systemd unit the
stop/start/flip actions target. The cluster control RPCs the rolling
driver uses — `PeerAlive` / `SyncEstablished` / `DrainComplete` /
`ForceSecondary` / `ResetFailover`, and the same RPCs in `xpfd upgrade
kernel drain`/`rejoin` — all dial a single hard-coded LOCAL endpoint,
`127.0.0.1:50051`. There is no unit→endpoint mapping yet, so a
non-default `--unit` would cut ONE daemon (systemd actions honor the
unit) while driving cluster failover against ANOTHER (the default daemon
on `127.0.0.1:50051`) — wrong-daemon control.

To keep that contract honest, `upgrade.NewCLICluster` — the single
construction chokepoint for all three callers — REJECTS any unit other
than the default (`xpfd`) with a clear error rather than silently
dialing the default endpoint. `--unit` takes the BARE unit name; the
systemd layer appends `.service` itself, so `--unit xpfd.service` is a
non-default spelling and is rejected. The rejection IS the whole
contract: an alternate unit's cluster control would have to dial that
unit's OWN gRPC endpoint, and there is no unit→endpoint mapping, so a
non-default `--unit` is refused rather than driving failover against the
wrong daemon. This is a CLI control-TARGET + validation change only; it
does not alter VRRP / session-sync / cluster RUNTIME behavior.

## Config compatibility envelope (D1, `pkg/configstore`)

`active.json` carries a magic header LINE
(`#xpf-config-envelope v=1 writer=.. ast=.. min-reader=.. rollback-fmt=..`)
prepended to the (possibly-encrypted) JSON body. The leading `#` makes a
pre-floor reader's `json.Unmarshal` ERROR (fail closed) instead of
empty-loading a wrapping object and silently wiping config. A too-new
`min-reader` is rejected. A present-but-unreadable DB is tagged
`ErrConfigDBUnreadable` and made FATAL at startup (daemon_run.go) — never
silently overwritten by a blind bootstrap. A pre-floor (no-envelope) DB
still reads, so upgrading TO the floor is non-destructive.

`mgmt-never-stranded`: on the appliance the day-0 + protected-set lifeline
covers a fail-closed boot; #1922 hardens the foreign/non-appliance host
case (NOT implemented here — see #1922).

## postinst HA-mode contract

- FIRST install (`$2` empty, any node type): the postinst runs `xpfd
  seed-runtime` (#1964 mechanism A) — seed the versioned runtime + sbin
  links, NO cut. The daemon comes up resolving `versions/current` with a
  real rollback target in place.
- STANDALONE node (no `/etc/xpf/node-id`), UPGRADE: the postinst invokes
  `xpfd upgrade` (verified single-node cut). `XPF_NO_POSTINST_CUT=1`
  suppresses it. The cut's refuse-before-STOP guard (#1964 mechanism C)
  keeps the daemon up if no rollback target exists (e.g. a host where
  seeding/migration was skipped) — the postinst logs the non-zero cut and
  leaves the old daemon running.
- CLUSTERED node (node-id present), UPGRADE: STAGE-ONLY. Cut ONLY via
  `xpfd upgrade --rolling`. Keyed on node-id ALONE so a degraded-HA node
  never falls through to an uncoordinated standalone cut.
- UPGRADE (any node type): the postinst NEVER repoints an existing or
  dangling sbin link (that would let the running daemon resolve a
  different-version helper, or steal an increment-B-staged dangling link
  and bypass its verify gate). It only RECOVERS a link that is COMPLETELY
  absent, and it recovers it THROUGH `versions/current/<bin>` — the same
  verified-live target the seed and the flip use — NOT direct to
  `staged/<bin>` (#2000). Recovering direct to staged would create a mixed
  state before the cut's VERIFY/STOP/FLIP: most tools resolve the verified
  live version while the recovered one resolves the just-unpacked,
  unverified staged version (a recovered `cli` would run against the old
  daemon; a recovered `xpf-userspace-dp` would expose the unverified staged
  helper). A NEWLY-INTRODUCED managed binary whose target does not yet
  exist under `versions/current` (its first upgrade), and any absent link
  on a legacy/never-seeded host with no `versions/current`, is LEFT ABSENT
  until the verified cut (or the preinst migration) populates
  `versions/<v>/` and flips — early exposure of an unverified staged binary
  is exactly what this avoids.

## Dogfood deploy

`XPF_DEPLOY_DEB=1 make cluster-deploy` builds the `.deb` (outside the
#1875 cluster lock), `apt install`s it (stage-only on the clustered
nodes), and drives `xpfd upgrade --rolling` secondary-first. The default
raw push+restart path (and `XPF_DEPLOY_FAST`) is unchanged for the dev
inner loop. The deb path is opt-in until validated live; it then becomes
the CI/smoke default.

## Host-wide upgrade lock (#1965)

Every MUTATING upgrade operation on a host takes one host-wide advisory
lock — `/run/xpf/upgrade.lock`, a non-blocking exclusive `flock(2)`
(`pkg/upgrade/lock`). It serializes the standalone binary cut
(`xpfd upgrade`), the rolling driver (`xpfd upgrade --rolling`), the
postinst auto-cut, and the mutating `xpfd upgrade kernel`
sub-verbs (`arm`/`promote`/`drain`/`rejoin`). Without it two mutators
silently corrupt the crash-safe journal: both load the same snapshot,
modify independent copies, and last-write-wins, losing the rollback
target. Read-only status (`xpfd upgrade kernel status`) stays lock-free.

- `/run` is tmpfs and reboot-clearing — exactly right: the lock guards
  CONCURRENT mutators, while crash recovery stays journal-driven (the
  durable journal lives under `/var/lib/xpf`). A reboot mid-upgrade
  leaves no stale lock; the resume reads the journal, not the lock.
  `mkdir -p /run/xpf` runs before every acquire (a fresh boot's tmpfs may
  lack the dir).
- Owner metadata (PID, subcommand, target, start time) is written into
  the lock file after the flock succeeds, so a busy acquirer's error
  NAMES the current owner.
- The lock is released on every exit path (normal/error/panic) via defer;
  the kernel also drops the flock on process exit, so a crashed holder
  never wedges the host.
- **Rolling re-entrancy:** `RunRolling` takes the lock at entry and holds
  it through rejoin (covering the peer-check + `ForceSecondary` + drain
  window, not just the inner cut). The inner `r.Run()` runs with
  `Options{LockAlreadyHeld: true}` so it does NOT re-flock the same file
  (a second flock on a fresh fd of the same path returns `EWOULDBLOCK`
  and would abort the rolling upgrade).
- **Lock ordering vs the `/tmp/xpf-cluster.lock` deploy lock (#1875):**
  the cluster/deploy lock is taken OUTSIDE, the host upgrade lock INSIDE.
  No deadlock — the two never nest in the opposite order.
- **dpkg-vs-operator staged-source race — CLOSED by immutable versioned
  staging (#1981 Option B).** The cut no longer reads the dpkg-owned
  `staged/` path directly. `debian/xpf.preinst` still `flock`-gates the
  package op (fail-loud if an operator cut already holds the lock), but
  that was only a partial backstop — the preinst fd dies at preinst exit
  so the lock is NOT held during dpkg's per-file unpack, and a cut
  landing inside the unpack window could read a half-unpacked `staged/`
  that mixes binaries from two dpkg generations. #1981 closes it by
  construction; see "Immutable versioned staging" below.

## Immutable versioned staging (#1981 Option B)

dpkg unpacks the managed binaries into `staged/` one file at a time, so
across an `apt upgrade` unpack window `staged/` holds a MIX of old and
new binaries. A cut that copied directly from `staged/` could publish a
`versions/<ver>` mixing two dpkg generations — a torn set whose
`verify-dataplane` gate (xpfd+shim only) cannot detect a mismatched
`xpf-userspace-dp` (a lockstep-cut dataplane binary). #1981 closes that
window for ALL FOUR managed binaries:

- **Publish after a complete unpack.** `postinst configure` (which runs
  AFTER a complete unpack while the dpkg frontend lock serializes apt
  transactions) runs `xpfd publish-generation`: it copies the staged set
  into an immutable `staged-gen/<genid>/` (via `.partial` + atomic rename
  + dir-fsync) and atomically repoints a `staged-gen/current-gen` symlink
  (temp-symlink + rename, never `ln -sf`). `<genid>` is a zero-padded
  nanosecond wall-clock timestamp (`time.Now().UnixNano()`) + random
  suffix, so a same-version reinstall gets a distinct generation. The
  timestamp is NOT strictly monotonic (an NTP step can move the wall
  clock backward), so it is treated only as a generation key + a stable
  GC ordering hint; correctness never depends on `genid` ordering — GC
  protects `current-gen` and journal-referenced generations explicitly,
  so a backward clock step at most affects which NON-protected, non-live
  generation is reaped first, never the active source.
- **The cut reads the PINNED generation, never live `staged/`.** `Run`
  resolves `current-gen` ONCE at INIT and records the genid in
  `Journal.SourceGeneration`; `copyStaged` copies from
  `staged-gen/<SourceGeneration>/` — the resolved DIRECTORY, never
  re-reading the symlink — so a concurrent publish that advances
  `current-gen` cannot redirect an in-flight cut. The source is a
  generation dpkg is NOT touching, so it is internally a single
  generation by construction.
- **No published generation ⇒ refuse pre-PREFLIGHT.** A fresh cut with
  `current-gen` absent refuses at INIT with NO journal written and NO DB
  snapshot taken (the daemon is untouched). It never reads a torn
  `staged/`.
- **`staged-gen/` is maintainer-script-managed runtime state** under
  `/var/lib/xpf` (a sibling of `versions/`), NEVER a dpkg payload file —
  so dpkg never writes or removes it on unpack. The postrm removes it on
  `purge` and on a downgrade to ANY package below the #1981
  staged-generation floor (`STAGED_GEN_FLOOR`, a SEPARATE, HIGHER floor
  than the #1964 layout floor — so a post-#1964-but-pre-#1981 downgrade
  still removes `staged-gen/` even though it keeps the #1964
  versioned-runtime layout intact). The downgraded package never learns
  about `staged-gen/`, so leaving it would leak permanently; the pre-B
  cut reads live `staged/` as its only source, so removing `staged-gen/`
  strips nothing it can use.
- **GC retention N=2** (current + 1 prior — a superseded generation is
  never read again, so keeping 3 is pure disk waste). GC orders valid
  generation dirs by `genid` NAME (the zero-padded timestamp prefix makes
  name order chronological and mtime-independent) and keeps the newest N
  PLUS, ADDITIVELY, the explicitly-resolved `current-gen` generation AND
  any genid an active/resumable journal references (the GC-vs-resume race
  — a journal-pinned OLD generation never evicts an in-window generation,
  and `current-gen` is never reaped even if it is not the newest by name
  or mtimes are perturbed). It ignores (never counts, never deletes) any
  directory whose name is not a valid `genid`, and sweeps `.partial`
  orphans. **Fail-closed protection (#4876):** the publish's GC runs ONLY
  when the journal protection set is known. A crashed cut leaves a durable
  journal pinning its source generation with the host lock released; if
  that journal is present but cannot be read (I/O error) or is malformed,
  the pinned generation is UNKNOWN, so publish-generation SKIPS the GC
  rather than run it with an empty protection set and reap the crashed
  cut's source (which would leave the resume unrecoverable). An absent
  journal means no crashed cut, so GC proceeds normally. **The SAME rule now covers
  the other half of the protection set (#6763):** `current-gen` is
  resolved explicitly, and that resolution can FAIL — a readlink error, a
  hand-edited symlink carrying path components that would escape the
  staged-gen root, a target that is not a valid `genid`, or a DANGLING
  `current-gen` whose directory is missing. The error used to be
  DISCARDED, so the live generation simply went unprotected and GC reaped
  it as soon as it fell outside the retention window — with the dangling
  case being the sharpest, since a corrupt layout is exactly when the live
  generation most needs protecting. GC now REFUSES and deletes nothing
  when `current-gen` cannot be resolved. The benign case stays benign:
  `ResolveCurrent` returns `("", nil)` when there is no `current-gen` link
  at all, so a never-published root still GCs normally — absence is
  determinate, failure is not. All three GC callers already treat a GC
  error as a warning, never fatal, so the refusal degrades to "GC
  skipped" and cannot block a publish, a seed or a cut.
- **Same-version replacement (B-P3b OPT1).** `versions/<ver>` carries a
  `.srcgen` stamp; the copy-skip is generation-aware. A same-version
  re-stage with NEW bytes (a new generation) RE-COPIES a stale, non-live
  `versions/<ver>` (reusing the proven guarded-delete), or REFUSES
  pre-PREFLIGHT if `versions/<ver>` is the live `current`/rollback target
  (cannot safely mutate a live version dir mid-cut). Recovery on a
  refusal: re-stage under a distinct version tag, or `dpkg-reconfigure
  xpf` to realign the generation.
- **Crash-safety.** A crash before the `staged-gen/<genid>` rename leaves
  a `.partial` (pre-swept on the next publish); a crash after the dir
  rename but before the `current-gen` repoint leaves a
  complete-but-unreferenced generation (the PRIOR `current-gen` stays
  valid; a re-publish is idempotent). An aborted/failed unpack publishes
  NO new generation, so the prior generation stays the cut source — there
  is NO permanent-wedge class.
- **Deferred-publish recovery.** If the publish defers because the
  host-wide upgrade lock is busy (another upgrade in progress), the
  postinst drops `/run/xpf/upgrade-deferred`, skips the cut, and the
  operator recovers with `xpfd publish-generation && xpfd upgrade`
  (`dpkg-reconfigure xpf` is equivalent). A bare `xpfd upgrade` alone
  would re-read the OLD `current-gen` and no-op, so the recovery MUST
  publish first. **On a CLUSTERED node** (`/etc/xpf/node-id` present) the
  cut verb is `xpfd upgrade --rolling`, NOT the bare `xpfd upgrade` — the
  standalone cut is refused there (#5284). The postinst deferred-publish
  hint is node-id-aware and prints the correct verb; the runtime gate in
  `Runner.Run` refuses the bare cut regardless of what the operator types.
- **Disk budget.** Each binary set is ~50-70 MB (dominated by `xpfd`
  embedding the kernel-verified shim + `xpf-userspace-dp`). Steady-state
  copies: `staged/` (1) + `staged-gen/` current+1 (2) + `versions/`
  current+N=3 (4) ≈ **7 copies ≈ 350-490 MB**. A constrained appliance
  `/var` MUST size for this; the publish's own GC + the `versions/` GC
  bound it.
- **One-time first-deploy bootstrap caveat (intrinsic).** #1981 only
  protects cuts performed by a B-aware `xpfd`. During the very upgrade
  that INSTALLS the first B-aware binary, the operator-visible
  `xpfd upgrade` is still the OLD (pre-B) binary, which reads live
  `staged/` — the fix cannot run before it is installed. That single hop
  is covered by the existing backstops (the #1965 preinst lock gate +
  the `verify-dataplane` gate against the copied xpfd + "do not run
  `xpfd upgrade` during `apt upgrade`"). From the first B-aware version
  onward the window is closed by construction. This is a documented,
  bounded, one-time exposure, NOT a residual hole in the steady-state
  guarantee.

## Peer-takeover-readiness is best-effort; DrainComplete is authoritative

The local control socket renders the LOCAL node's view, so the
pre-demotion `PeerTakeoverReady` check cannot directly read the PEER's
takeover-readiness — it requires the peer alive and no LOCAL takeover
blocker. The AUTHORITATIVE guard is `DrainComplete`, which AFTER demotion
confirms the peer ACTUALLY holds primary for EVERY RG; if it does not
within the deadline, the rolling driver fails back and ABORTS WITHOUT
cutting. A peer that cannot take over therefore never leads to a cut — at
worst the drain times out and the local node is restored to forwarding.

## Session-sync wire version on the in-place path (#7990)

The LANE-1 in-place rolling path had **no session-sync version check at all**
until #7990, and the gap was structural rather than an oversight: there was no
channel. `SessionSyncWireVersion` was advertised only in the image manifest
(`xpfd protocol-versions`) and consumed only by `GateMixedBaseSwap` — the
LANE-2 image-replace gate. The heartbeat carries `HAProtocolVersion` and nothing
about the sync wire, and the session-sync frame header has no on-wire version
field.

**Why that mattered more than it sounds.** Roll a pair across a
`SessionSyncWireVersion` change and heartbeat, election and failover all keep
working, because the HA protocol never moved. The cluster is UP and looks
healthy. What is broken is session synchronisation — invisible until a failover
needs it, and indistinguishable from a cluster that has simply not synced
anything yet. The operator discovers it by losing every established flow after a
rolling upgrade that reported success.

**The channel.** The version now rides `syncMsgPeerCapabilities` (id 29) as a
trailing `u16`, beside #6650's config-snapshot version and #7147's capability
flags, under the #2170 trailing-field discipline. It is on the same connection
whose compatibility is in question, so "peer reachable" and "peer version known"
share one lifecycle — the same three reasons #6650 chose this channel over the
heartbeat, which apply with more force here. **No version bump**, and here that
is forced rather than merely convenient: bumping `SessionSyncWireVersion` in
order to advertise `SessionSyncWireVersion` would make the mixed-base gate —
which compares it for exact equality — refuse session sync across precisely the
upgrade that first carries the field.

**The honest limitation.** A peer that advertises nothing predates #7990, and
the gate PERMITS that case. Refusing would fire on every roll from the previous
release and on no real skew. So this gate cannot protect the first roll that
carries it; it protects every roll after — which is every roll that could
actually move the constant. That is the same dual-accept shape #4107 (heartbeat
auth) and #4126 (VRRP checksum) used: accept both wire forms during the upgrade
window, enforce once both sides speak the new one.

`show chassis cluster status` now renders `Session-sync wire version` and
`Peer session-sync wire version` beside the HA protocol lines. The peer line
reads `unknown` rather than `0` for a peer that has not advertised: there is no
valid wire version 0, so printing a number would invite a reader — or a parser —
to compare it as one.

## Rolling protocol-bump limitation

`HAProtocolCompatible` compares the RUNNING local daemon's HA protocol
version against the peer's. It cannot see the STAGED version's protocol
before the cut. So if a release BUMPS `CurrentHAProtocolVersion`, the
first node's precheck passes (running N vs peer N), it cuts to N+1, and
then the SECOND node's precheck fails (running N vs peer N+1) and aborts —
leaving a mixed-version cluster. This is the "not rolling-upgradable"
outcome the plan flags (Path C image-replace), but it is detected on the
second node, not pre-emptively. Operators MUST treat a protocol bump as a
non-rolling release (image-replace both nodes). A pre-emptive guard would
require the staged binary to report its protocol version to the driver
before the first cut (future work).

## Pinned BPF-map type/shape migration (shim collection pins)

The retained AF_XDP shim pins several maps under `/sys/fs/bpf/xpf` via the
collection load (`PinByName`, `loader_userspace_shim.go`). These pins live on
bpffs and PERSIST across a daemon restart, so on an in-place upgrade the new
daemon inherits the OLD daemon's pins. cilium/ebpf's `PinByName` load runs a
compatibility check against each existing pin; if the new spec's type or shape
differs, it returns `ErrMapIncompatible` and the WHOLE shim collection load
aborts — a boot-brick on upgrade (#1917/#1960 class).

Two disciplines apply, split by whether the map holds recoverable state:

- **DATA maps** (sessions, conntrack, dnat) go through
  `loadOrCreatePinnedShimMapWith`, which deliberately **REFUSES** to reset an
  incompatible pin (#2360). A silent reset would drop live sessions, so an
  incompatible DATA-map pin is a loud failure requiring operator action
  (image-replace, not rolling).
- **DISPOSABLE maps** — degraded-path counters (`userspace_fallback_stats` /
  `degraded_path_counters`) that reset to zero on every reload — are reconciled
  by `reconcileDisposableCollectionPin` BEFORE the collection load: a stale
  pin whose shape no longer matches (e.g. #4113 changed this map from `Array`
  to `PerCpuArray`) is dropped so the load recreates it fresh. Losing the old
  counts on the one-time migration is acceptable; a missing or already-migrated
  pin is left untouched, so counters survive an ordinary restart.

When bumping a shim map's type/size, decide which bucket the map is in. A DATA
map bump is a non-rolling release; a disposable-counter bump is handled by the
reconcile above (extend it only for maps whose loss is truly safe).

## Honest limits

- **No true zero-gap standalone restart.** The helper is an `exec.Command`
  child held in xpfd memory; a fresh xpfd spawns a NEW helper and clears
  the XSKMAP. Standalone cut-over is a bounded, MEASURED multi-second gap
  (the ~3s NAPI bootstrap window is the floor). True zero-gap
  (decoupled-helper re-attach) is future M-mech-2. The HA path masks the
  gap with a single ~60ms VRRP failover per node.
- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.

## LANE-1 HA kernel roll (#1930 INC-2)

A kernel bump can't be cut over in place (the running kernel can't be
swapped while live), so the kernel channel uses a fixed A/B UEFI boot
slot pair. `xpfd upgrade kernel` arms the INACTIVE slot's selector at the
candidate kernel and reboots one-shot (`efibootmgr --bootnext`, which the
firmware clears on the next boot — the loop-safety floor). On the
candidate boot, `xpf-kernel-promote.service` runs the kernel-space
`verify-dataplane` gate plus a forward beacon; on success it promotes
(non-destructive `BootOrder` front), on failure it reverts (bounded by
`maxPromoteAttempts`, then `restoreKnownGood`). The journal at
`/var/lib/xpf/kernel-upgrade.state` makes the trial crash-safe and
idempotent across the reboot.

The forward beacon (Gate 4) is the ONLY gate that asserts packets actually
move — Gate 3's `verify-dataplane` is structural, proving the candidate
kernel's BPF verifier accepts the shim and nothing more. Gate 4 requires
all three of: `xpfd` active, the dataplane helper reporting
`enabled && forwarding-armed` over its control socket, and a ping to
`BeaconTarget` (default: the IPv4 default gateway) succeeding within the
deadline.

The helper condition was added in #6607. Before it, the second condition
was `systemctl is-active xpfd-userspace-dp` — a unit that exists nowhere
in the repository and never has: the helper is a CHILD PROCESS xpfd
spawns, not a systemd unit. That probe could never report active, and
OR'd with the `xpfd` probe it could contribute neither a pass nor a fail,
so the guard silently degenerated to "xpfd is active". That is the
pre-#5286 mistake exactly: a `Type=simple` xpfd reports active
immediately while its helper is down, stale or crash-looping and NOT
forwarding — and an AF_XDP shim / verifier / driver mismatch against a
new kernel is the single most likely cause of that state, which is the
whole reason Gate 4 exists. The fail direction was PERMISSIVE, so a bad
kernel was more likely to be promoted than rolled back.

The probe reuses the binary channel's primitives rather than inventing
IPC: `userspace.ProbeStatus` over the control socket, adapted through
`upgrade.HelperStatusFunc` and injected by `cmd/xpfd` so `pkg/upgrade`
need not import (and cannot cycle with) `pkg/dataplane/userspace`. A nil
probe means the caller has no dataplane to ask (a non-xpfd embedder or a
test) and falls back to the `xpfd`-liveness check alone — "no
information" is not "unhealthy", and failing closed on it would revert
every such caller's promotion.

### Beacon target eligibility (#7157)

Gate 4's ping only means something if it CAN fail. Three target classes make it
succeed regardless of dataplane health, and before #7157 the gate could not tell
them from a healthy probe. Each is now refused before the ping, with a named
reason that reaches the operator through `KernelRollOutcome.Reason`:

| refused class | why the ping is uninformative |
|---|---|
| egress `dev lo` (a LOCAL target) | the host stack answers without a packet leaving the box |
| egress a MANAGEMENT interface | a candidate kernel can keep the OOB path working while the dataplane cannot forward transit traffic |
| no route at all | nothing can leave, so nothing can be concluded |

The `lo` case is the one that was reachable and unconditional. Measured on
`loss:xpf-userspace-fw0`:

```
# ip route get 172.16.50.8          <- the box's OWN dataplane address
local 172.16.50.8 dev lo table local src 172.16.50.8
# ping -c 1 172.16.50.8
1 packets transmitted, 1 received, 0% packet loss, rtt 0.055 ms
```

55 microseconds, over `lo`, with the dataplane in any state. So
`XPF_KERNEL_BEACON_TARGET` set to the box's own dataplane address made Gate 4
pass for **every** candidate kernel — and this document's own guidance ("set it
to a dataplane-side target") is what leads an operator to type it. **Set it to an
OFF-BOX address reachable over a dataplane interface** — the far end of a
transit link, or the HA peer's dataplane address.

The management classifier is `config.IsManagementIfName`, the #7515 SSOT already
shared by the daemon's `vrf-mgmt` binder, the networkd `VRF=` emitter and the
ip-monitoring next-hop validator. It is injected by the caller for the same
reason `HelperStatus` is, and a `nil` classifier is "no information" rather than
"ineligible" — but both production constructors wire it, and tests bind that
rather than leaving it to a comment.

Note that on an xpf-managed box the management default route is NOT what the
fallback finds: `fxp*`/`fab*`/`em*` are enslaved to `vrf-mgmt` (table 999), so
`ip -4 route show default` reads the main table and returns a dataplane route.
The management refusal therefore guards an operator-set target and a posture
where that VRF isolation is absent, not the default-gateway fallback.

### Known limitation: the beacon cannot pass on an HA secondary (#7157)

On a RETH-based HA secondary, FRR blackholes the static default while the peer
holds the VIP. Measured on `loss:xpf-userspace-fw1`:

```
# ip -4 route show default
blackhole default proto static metric 20
# ip route get 1.1.1.1
RTNETLINK answers: Invalid argument
```

`defaultGateway()` finds no `via`, so Gate 4 fails closed and the promotion
reverts — on the node an HA operator upgrades FIRST. The direction is safe (a
revert, never a brick), but a gate that cannot pass is a wall rather than a gate.
The workaround today is to set `XPF_KERNEL_BEACON_TARGET` to an address the
drained secondary can still reach over a dataplane interface. Whether a drained
secondary should instead be allowed to promote on preconditions A+B alone is a
deliberate weakening of a security gate and is tracked on #7157, not decided
here.

### Still open on #7157: this is eligibility, not a transit witness

None of the above shows that a packet crossed ingress AF_XDP → filter/PBR → zone
policy → session/NAT → egress. The ping is still host-originated, so it does not
traverse the forwarding path a transit packet takes. What eligibility buys is
that a PASS is now capable of being a FAIL. The external tagged transit witness
— an isolated source, a configured ingress, an expected egress, an explicit
policy/NAT expectation, bound to the candidate boot identity, IPv4 and IPv6 —
remains open, and needs an observer outside the box that the unattended
boot-time gate does not have.

Related, and also still open: `KernelJournal.ArmNonce` is written on every arm
and **never compared anywhere** (assignment sites only; the sole reads are in a
test asserting two attempts differ). It is provenance, not an anti-stale
mechanism, so #7157's "reject a stale result from an earlier candidate boot"
case has no implementation behind it.

### Operator visibility (#6495)

During a roll the channel is legible from the CLI the operator already has,
not only from a root shell:

```
> show system kernel-upgrade
Kernel upgrade channel (LANE 1, A/B slots):
  Running kernel:  6.18.4-11-generic
  Armed:           yes — a candidate trial is IN FLIGHT
    Candidate:     6.19.0-1-generic
    Known-good:    6.18.4-11-generic
    Active slot:   xpf-A
    Candidate slot: xpf-B
    State:         ARMED
    BootNext:      Boot0004 (one-shot, cleared by the firmware on boot)
  Promotion marker: none
  Last roll:       none recorded

  Cluster: this node is HELD SECONDARY — kernel-candidate promotion gate ...
```

Three things it answers that previously needed a root shell or journald:

- **Is a candidate armed?** `ARMING` is reported as *not* armed and says why:
  it is prepared intent whose firmware one-shot was never read back (#5847), so
  the next boot is the **known-good** kernel. An operator told "armed" there
  would expect a trial that will not happen.
- **Is this node held secondary by the upgrade gate, and by *which* gate?**
  `show chassis cluster status` and `show chassis cluster information` now
  annotate the hold, so a node parked SECONDARY by the *expected gate* is no
  longer indistinguishable from one demoted by a monitor failure or a manual
  failover.

  There are **two** hold reasons, because the daemon sets the one
  `kernelUpgradeHold` flag for two materially different conditions whose
  remedies differ:

  | Reason | Condition | Operator action |
  |---|---|---|
  | `KernelUpgradeHoldCandidate` | a candidate is genuinely ARMED | wait — the durable promotion marker releases it |
  | `KernelUpgradeHoldUnreadableJournal` | the #5682 fail-closed hold: `IsArmed` returned an **error**, so whether anything is armed is UNKNOWN | repair `/var/lib/xpf` — no marker may ever be written |

  Rendering one string for both would be a **false statement** in the
  fail-closed case: "held until the promotion marker confirms the running
  kernel" asserts a candidate exists and that a marker will resolve it, and the
  daemon reached that branch precisely because it could not establish either.
  That is the same class of defect as the invisibility this section is about,
  one layer in. `Manager.KernelUpgradeHoldReason()` returns the active reason;
  `KernelUpgradeHeld()` remains the yes/no predicate the election uses, and is
  deliberately **not** what the status surfaces render.

  The reason also follows the **#5682 self-heal transition**: when a fail-closed
  hold's journal becomes readable and a candidate *is* armed,
  `reconcileKernelUpgradeHold` converts it in place to a candidate hold and
  re-sets the reason, so the status stops telling the operator to repair a
  filesystem that is now healthy.

  The annotation is node-scoped and sits **above** every `Redundancy group:`
  header so the rolling-deploy node parser (`deploy_rolling_secondary_node`,
  `test/incus/deploy-lib.sh`) cannot read it as a table row.
- **Did the last candidate promote or revert, and why?** `revert()` clears the
  journal by design (the next boot must be a clean ordinary boot) and the
  promotion marker is written only on PROMOTE, so a rejected candidate used to
  leave `promoted=none` / `armed=none`: correct, and indistinguishable from a
  box that never tried, with the reason surviving only in journald. A durable
  last-roll record at `/var/lib/xpf/kernel-last-roll` (version, known-good,
  outcome, reason, timestamp) now survives the clear.

The last-roll record is deliberately **not** cleared at arm time, unlike the
promotion marker. The marker is cleared on `Arm` because a stale "promoted"
from a prior same-version roll would false-satisfy the HA orchestrator's
post-reboot version check. This record answers no such check — it is history,
overwritten by the next roll's outcome, and clearing it on arm would destroy
the previous answer exactly when an operator re-arming after a failure wants
it. Both writes are best-effort: a failed history write never changes what the
channel does, and a revert that could not record itself is still a revert. It
is written at the TOP of `revert()`, before that function's two early exits (a
journal that cannot be persisted, and the attempt-cap give-up), because those
are the states an operator most needs explained.

`show system kernel-upgrade`, the console CLI, and the remote `cli` all render
through `upgrade.RenderChannelStatus`, and the read path
(`upgrade.ReadChannelStatus`) mutates nothing, so it is safe at operator
polling frequency against the same durable state the promotion gate depends on.

**The gate execs xpfd by EXPLICIT path, never `$PATH` (#6541).** The
promotion gate runs as root on the candidate boot and its exit status
decides promote-vs-rollback, so a `$PATH` entry ordered ahead of the real
location must not be able to author that decision — and even with no
attacker, a stale `xpfd` left in another directory would verify the wrong
build against the candidate kernel. Both hops resolve explicitly:

- *Outer hop* — `scripts/image/xpf-kernel-promote` runs the xpfd the
  **arming recorded** (below). It cross-checks that record against
  `xpfd.service` and refuses on disagreement; it never resolves a binary
  any other way.

  Nothing is `$PATH`-resolved and nothing is inferred from the
  filesystem. The unit also pins
  `Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin`: the gate does
  `$PATH`-resolve `systemctl`/`readlink`/`reboot` on purpose, and
  systemd's *default* `PATH` ranks the operator-writable
  `/usr/local/sbin` and `/usr/local/bin` first.
- *Inner hop* — `realKernelSystem.VerifyDataplane`
  (`resolveVerifyGateBin`, `pkg/upgrade/kernel_linux.go`) resolves
  `os.Executable()` and **nothing else**. The running process IS `xpfd
  upgrade kernel promote`, and on Linux `/proc/self/exe` resolves the
  sbin→`current`→`versions/<ver>/xpfd` chain down to the concrete
  versioned artifact — so this is the kernel's answer for the running
  process, not an inference. If it cannot be resolved and validated
  (absolute, existing, regular, executable), the inner hop **refuses**.

  **Authority order, stated for both hops together (#6620).** The outer
  hop is `/proc/<MainPID>/exe` → strictly-parsed `ExecStart` → loud
  refusal; the inner hop is `os.Executable()` → refusal. Neither has a
  filesystem fallback, and they refuse for the same reason: `--sbin-dir`
  and `--versions-dir` relocate *independently* and neither relocation
  removes what it left behind, so a leftover at a compiled-in default is
  byte-for-byte indistinguishable from a live install. That includes the
  both-roots-relocated shape, where the surviving default symlink still
  points at the surviving default runtime and the two candidates are ONE
  INODE — exactly like a healthy layout.

  The inner hop used to fall back to `<SbinDir>/xpfd` and then
  `<VersionsDir>/current/xpfd`, ranked in that order because `flip` step
  6b repoints the sbin entry on every cut. A better-ranked guess is still
  a guess: on a relocated box the surviving default sbin symlink resolves
  perfectly and names a *stale* runtime, so the ranking preferred the
  stale build with full confidence. Refusing is not a lesser outcome — a
  Gate-3 error routes to `revert()` (restore the known-good `BootOrder`,
  reboot to the known-good slot), which is a correct terminal outcome,
  strictly better than a promotion authorized by the wrong dataplane.

**The arming records which xpfd must verify the candidate (#6601).**
Six revisions tried to answer *which xpfd is live?* on the candidate boot
from ambient state — `$PATH`, then the compiled defaults, then inode
identity, then a unit name, then that unit's `LoadState` — and each one
closed a single stale-authority window and left another. The last broke
concretely: a **disabled** unit still reports `LoadState=loaded` with
`MainPID=0`, so a leftover default unit whose drop-in named an OLD
version satisfied the arm-time check, and on the candidate boot its stale
`ExecStart` was accepted and the stale binary authorized the promotion.

Every one of those signals is ambient, and ambient state is exactly what
an operator can change between arming and the candidate boot. So the gate
stopped selecting signals and the question was removed instead:
**`xpfd upgrade kernel arm` IS an xpfd**, so `os.Executable()` names the
live binary by construction rather than by inference, and it knows this at
the moment it arms. Arming records that path, and the boot gate reads it.
*Which xpfd is live?* (unanswerable later) becomes *which xpfd armed this
candidate?* (a recorded fact).

The record is written twice, from one resolved value, in
`recordPromoteBinary` (`pkg/upgrade/kernel_arm_record.go`):

- `KernelJournal.PromoteBinary`, for the Go half's Gate-2b cross-check
  (`VerifyPromoteBinaryMatchesRecord`) — a mismatch **reverts**, so an
  undesignated binary never authorizes a promotion;
- a one-line sidecar at `/var/lib/xpf/kernel-promote-binary`, beside the
  journal, for the boot gate. The duplication is deliberate: the gate is
  POSIX `sh` with no safe JSON parser, and the path it execs must never
  come out of a JSON value — the same *a value may legally contain the
  delimiter* class that the `ExecStart` parse below is about.

It **fails closed**. A preflight that cannot establish which binary is
arming refuses the arm: arming is retryable, an unverified candidate
kernel is not. The sidecar is cleared with the journal
(`clearKernelJournal`) so "nothing armed" and "no record" stay one
statement — a record surviving a cleared journal would refuse every later
ordinary boot. Cross-language drift canaries
(`TestPromoteScriptArmRecordPathMatchesGo`,
`TestPromoteScriptJournalMatchesGo`) keep the shell's hardcoded paths and
state token equal to Go's.

Because the record carries the authority, a host cut with
`xpfd upgrade cut --unit <name>` is now **supported** rather than refused
at arm time: `xpfd.service` simply resolves nothing to cross-check
against, and the gate runs.

**"Record absent" is itself an inference, and it is checked (#6601 r7).**
When the sidecar is missing the gate would otherwise declare *nothing to
promote* and exit — a positive claim made from the **absence** of a file.
That claim holds only because arming writes the record before the `ARMED`
transition and clears it with the journal, so no crash ordering can
produce the divergence. Losing **one** of the two files out of band can:

- a `/var/lib/xpf` restored from a backup taken before the arm, or
  restored only partially;
- a stray cleanup — a tmpfiles rule, an operator `rm`, a housekeeping
  sweep — that removes the sidecar and leaves the journal;
- a candidate armed by a build **predating** the sidecar and then
  upgraded through the #1917 binary channel before the candidate boot:
  the journal says `ARMED` and no record was ever written.

A candidate is then armed, the gate silently does not run, and the next
reboot reverts it — behind a line that reads like an ordinary boot.

Not promoting is the safe direction, so this is availability and honesty
rather than security. It is nonetheless the same laundering the
renamed-unit warning exists to prevent, so the quiet exit is conditional:
with no sidecar the gate consults the journal for **one bit** — is a
candidate `ARMED`? — and:

| journal | outcome |
|---|---|
| absent, or not at `ARMED` | quiet `nothing to promote` (naming both files) |
| `ARMED` | loud `ERROR … REFUSING to promote`, saying the gate **did NOT run** and the candidate is **UNVERIFIED**, naming both files |
| present but not a readable regular file | `WARNING`: cannot establish whether anything is armed — absence of evidence is not evidence of absence |

**`--journal` is not one of those cases**, and must not be cited as this
check's motivation. Go derives the sidecar from the journal's *directory*,
so `xpfd upgrade kernel arm --journal <elsewhere>` moves **both** files
together: the gate would find neither and take the quiet branch, not the
loud ARMED-without-record branch above. That is a different defect, and
it is closed at the other end.

**Arming refuses a non-default journal path (#6631).** The boot gate
cannot be told where to look, and this is worth stating as *unreachable*
rather than *awkward* — all three channels that could carry a path are
absent:

| channel | why it does not exist |
|---|---|
| argument | `xpf-kernel-promote.service` is `ExecStart=/usr/local/sbin/xpf-kernel-promote` with no operands, and the script parses no argv of its own — no `$1`, no `$@`, no `getopts`. An operator drop-in overriding `ExecStart` has nothing to pass *to*. |
| environment | neither promote unit mentions a journal in any form; the only `Environment=` is the pinned `PATH`. |
| the inner exec | the gate runs `"$XPFD" upgrade kernel promote` with **no** `--journal`, so the Go half reads the compiled-in default regardless of what armed the candidate. |

So a candidate armed elsewhere would boot, run **unverified**, never be
promoted, and revert on the next plain reboot — the safe direction, but
silent, which is exactly the benign-skip laundering this gate otherwise
works to eliminate. `KernelRunner.Arm` therefore refuses up front with
`ErrKernelJournalUnpromotable`, before the candidate version is even
validated and before any system call: arming is a preflight and is
retryable, a candidate kernel booting unverified is not. The refusal
names the path the gate reads, so it is actionable.

The sentinel is deliberately **not** `ErrKernelChannelUnavailable`: that
one means *use LANE 2 instead* and exits 2, which the kernel-roll
orchestrator proceeds past. A mistyped flag is exit 1 — fix the command.

**For the kernel channel, `--journal` is therefore accepted only on the
verbs that cannot strand a candidate** (`status` and the crash-recovery
verbs). It remains fully usable on the non-kernel `xpfd upgrade` verbs,
which journal to `/var/lib/xpf/upgrade.state` and have no boot-time gate
reading a fixed path. The scoping is pinned by
`TestArmJournalGuardIsScopedToTheKernelArmPath_6631`, which requires the
guard to have exactly one caller and for that caller to be `Arm`.

`ARMED` **specifically**, not `ARMING`: `ARMING` is prepared intent
recorded before the firmware one-shot is read back, which is exactly the
line `IsArmed` draws (#5847), and matching it would put a loud error on
every boot of a box whose arm was interrupted. The read is a boolean and
never a path — `journal_state` must not grow a `promote_binary`
extraction, and a test asserts it has not.

**Why the outer hop cross-checks against systemd instead of guessing.**
`--versions-dir` **and** `--sbin-dir` are both real operator options, and
the cut maintains whatever was configured. A gate that knows only the
compiled defaults therefore breaks on a supported layout: with
`--versions-dir=/opt/xpf/versions --sbin-dir=/usr/sbin`, `/usr/sbin/xpfd`
is perfectly intact and simply is not one of our hardcoded paths. Such a
gate would either **skip an armed promotion entirely** — the worst
outcome, because the candidate kernel then runs unverified with nothing
in the journal to say the gate never ran — or, with leftover artifacts at
the default paths, **exec a stale build** that can reject a healthy
candidate and trigger a needless revert/reboot.

Since the record became the authority the cost of a wrong answer *here*
inverted: these hops no longer select the binary, so believing a bad one
does not hand it the promote decision — it fabricates a **disagreement**
with the record and refuses a healthy promotion. The strictness below is
kept for that reason, and the tests assert it by arming a good record,
feeding a hop something it must not believe, and requiring the gate to
promote anyway.

**There is no inference fallback, by construction (#6601).** Earlier
revisions of this gate did consult `/usr/local/sbin/xpfd` and
`/var/lib/xpf/versions/current/xpfd` when systemd could not answer, first
as a ranked list and then as an "unambiguous set". Both are wrong, and
not because of a missing case — because the question they try to answer
(*which of these files is the live xpfd?*) is not answerable from the
filesystem once a root has been relocated. `--sbin-dir` and
`--versions-dir` move **independently**, and neither relocation removes
what it left behind, so every shape such a fallback could recognise has a
relocation that makes it the stale build:

| leftover shape | why it looks decisive | why it is not |
|---|---|---|
| two usable defaults, **different files** | one must be stale | nothing on the box says which |
| two usable defaults, **same inode** | looks like the healthy `flip` 6b layout (`<SbinDir>/xpfd` → `<VersionsDir>/current/xpfd`) | a box that relocated **both** roots leaves exactly that pair behind, symlink still pointing at its own stale runtime — bit-identical, and `-ef` cannot tell them apart |
| **exactly one** usable default | "the only candidate" | it is the surviving half of a partial relocation just as often as it is a live install |

So the gate has no filesystem-derived candidate at all, rather than a
cleverer test over one. A stale `xpfd` here is silent and expensive: it
verifies the **candidate kernel** against a dataplane build nobody chose,
and its exit 0 *authorizes* the promotion. Refusing costs nothing by
comparison — the armed candidate simply stays un-promoted.

**The `MainPID` hop binds the pid back to the unit.** A pid is a number,
and a number is not an identity. If `xpfd.service` exits and the kernel
recycles its pid onto an unrelated process, `/proc/<pid>/exe` names *that*
binary — and a basename check only requires the impostor to be called
`xpfd`. So before the answer is believed, and **after** the `readlink` so
that a recycle *during* the sequence is caught rather than raced past, the
gate requires both:

- membership in `xpfd.service`'s own control group — systemd reports it
  as the structured `ControlGroup` property, the kernel reports each
  process's in `/proc/<pid>/cgroup`, and the gate matches the **path
  field** exactly (or as the parent of a delegated subgroup), never as a
  substring, so a same-prefix sibling cannot stand in for the unit;
- `MainPID` re-read and still the same positive pid.

A pid that cannot be bound this way yields nothing, and `ExecStart` gets
its turn; if that yields nothing either, the record stands unopposed —
absence of a cross-check is not evidence against the authority.
Availability is never preserved by a guess.

The first `MainPID` read comes from a **discovery snapshot** taken once,
before anything is decided, and the re-read is the one query deliberately
not taken from it (its whole purpose is to observe a pid that moved since
the snapshot). See *the refusal carries the facts*, below.

`xpfd.service` answers this directly, in two forms. `MainPID` +
`/proc/<pid>/exe` is the **kernel's** answer for the binary the live
daemon is actually executing; `ExecStart` is the **declared** one, and it
is exactly what the cut writes — `flip` step 6c templates
`ExecStart=<VersionsDir>/<ver>/xpfd` into `10-xpf-version.conf` on every
cut, and the shipped base unit carries `ExecStart=/usr/local/sbin/xpfd`
before the first cut. So it names the live binary both pre- and post-cut.
`systemctl` itself is `$PATH`-resolved, which is correct — it is a
distribution-owned binary, unlike xpfd.

**Unambiguous or nothing.** Every discovery source obeys one rule: a
source that cannot prove *which* executable it is naming must yield
nothing and let the next one try. When these hops still *selected* the
binary a wrong answer was far worse than no answer — it suppressed every
remaining candidate and that binary's exit 0 *authorized* the promotion;
now it vetoes a healthy one. Two consequences worth stating (#6601):

- `MainPID` is a structured integer and `/proc/<pid>/exe` is a kernel
  symlink, so this hop parses **no rendered path text at all**. It is
  tried first for exactly that reason. It yields nothing for a
  `… (deleted)` readback (a binary replaced on disk cannot be
  re-executed) or for a basename that is not `xpfd`.
- `systemctl show -p ExecStart --value` renders
  `{ path=/x ; argv[]=/x … }` and substitutes the stored path **raw**
  (`path=%s`, no escaping) — while systemd *permits* an executable path
  containing a space or a `;`. Stopping at the first space/semicolon does
  not fail to resolve, it resolves to a **shorter, different** path. The
  parse therefore cuts at systemd's real field delimiter, the literal
  `" ; argv[]="`, and gives up unless that occurs exactly once. Multiple
  `ExecStart` entries render one per **line**; an operator-overridden
  `Type=oneshot` unit can have several and the first need not be xpfd, so
  more than one line yields nothing rather than "take the first".

**Admission test.** Whatever a source names must be an existing,
**regular**, executable file (`-f` *and* `-x`). `test -x` alone is true
for a searchable **directory**, and the inner hop's `validateGateBin`
rejects a non-regular target, so both hops apply the same test rather
than only claiming to; `-f` also rejects the `#2176` dangling symlink.

**Refusing loudly beats skipping quietly.** The gate logs an explicit
`ERROR: … REFUSING to promote` and takes the non-rebooting infra-error
path in every state where something may be armed and it cannot run:

- the record names a path that is not an executable regular file now —
  a relocation, a GC'd version dir, a `#2176` dangling symlink;
- the record is present but is not an absolute path — "absent" is a
  definitive statement and must not be reachable by mis-parsing a file
  that IS present;
- the unit **contradicts** the record — the r6 sequence itself, a stale
  leftover unit whose drop-in still names an older version. Neither side
  is provably right, so the gate refuses rather than picking one;
- the journal says `ARMED` and the record is absent (above).

Every one of these deliberately still exits 0: a non-zero exit would trip
`OnFailure=` and reboot the box over what may be a transient packaging
window, whereas an un-promoted candidate is already safe — the firmware
cleared `BootNext`, so the next plain reboot falls back to the known-good
slot.

**A refusal leaves a durable record (#6622).** `exit 0` keeps the unit
`active` and `systemctl status xpf-kernel-promote` reads SUCCESS, so
before this the journal line was the only signal — and journal rotation
takes it away. An operator who armed a candidate, rebooted and came back
later saw a box running the old kernel and a promote unit reporting
success, with nothing saying the gate had declined or why.

That mattered more after the refusal became a real outcome rather than a
theoretical one: this gate used to fall back to a compiled default and
would usually run *something*. **A state that is now reachable needs to
be observable.**

The gate therefore writes `/var/lib/xpf/kernel-promote-refusal`, beside
the journal and the arm record and sharing their lifetime — it is
removed with the journal and rewritten by the next arm, so a refusal can
never be read as a verdict on a candidate that is no longer in flight.
`show system kernel-upgrade`, the console CLI and the remote `cli` all
render it through `upgrade.RenderChannelStatus`, and the status RPC
reads it through `upgrade.ReadChannelStatus`.

- **The unit still exits 0 and still does not trip `OnFailure=`.** That
  was deliberately avoided as the fix, and a test asserts it rather than
  assuming it.
- **Written only where the gate never ran `xpfd` at all**: every
  `refuse()`, plus the indeterminate-journal `WARNING`. Including the
  second is what makes the record's *absence* meaningful — if only
  `refuse()` wrote one, "no record" could not distinguish a clean boot
  from a boot the gate skipped for the other reason. It is **not**
  written by the quiet `nothing to promote` branch (that is the ordinary
  boot, and a file rewritten every boot buries the signal it carries) nor
  by the post-exec `rc` paths (there the gate *did* run `xpfd`, and the
  Go half owns the journal, the promotion marker and the last-roll
  record for those — a second writer would be a second source).
- **It carries the resolution facts** — the `LoadState`, `MainPID`,
  `ControlGroup` and raw `ExecStart` from the discovery snapshot the
  decision was made on, plus the journal bit, the cause, the
  branch-specific advice, a timestamp and the boot id. The status
  surface renders the snapshot rather than re-querying systemd: a
  re-query days later would describe a different system.
- **The boot id earns its place** because an early-boot clock can be
  wrong — no RTC, no NTP yet — so the timestamp alone cannot answer *was
  this THIS boot?*.
- **It does not duplicate the candidate version**, and that is a design
  choice rather than a gap. The gate is POSIX `sh` and the journal is
  JSON, so it reads that file for **one bit and never for a value**. The
  candidate is joined in by `ReadChannelStatus`, which has already
  parsed the journal in Go — and it is still accurate, because a refusal
  never transitions the journal, so the record and the `ARMED` candidate
  it declined are read from one consistent state.
- **Best-effort, always.** Every step of the write is suppressed and the
  writer always returns success. This runs on a candidate boot whose
  whole problem may be that the filesystem is not what the gate expected,
  and a gate that changed its exit path because it could not write a
  *diagnostic* would convert an observability gap into an availability
  one. A test plants a directory where the record goes and asserts the
  exit path is unchanged.
- **One line per field, `key=value`.** POSIX `sh` writes it and Go reads
  it, so the same *a value may legally contain the delimiter* hazard as
  the `ExecStart` parse applies in reverse: a systemd rendering can
  legally contain newlines (multiple entries render one per line), and an
  unflattened value would forge extra fields. Values are flattened; Go
  splits on the **first** `=` so a value containing one survives; unknown
  keys are ignored so a newer gate can add fields. A record present but
  carrying no *recognised* field is an **error**, never a silent "no
  refusal" — the same rule `ReadArmRecord` applies, for the same reason:
  "absent" is acted on as a positive statement. The path is pinned
  against Go by `TestPromoteScriptRefusalRecordPathMatchesGo_6622`.

**The refusal message carries the facts too, not just the policy.** The
journal line remains the immediate signal, so it echoes what systemd
actually returned (`LoadState=[…] MainPID=[…]
ControlGroup=[…] ExecStart=[…]`) and branches its advice on which cause
fired — `systemctl` unreachable, unit not-found, or unit known — because
telling an operator to fix `ExecStart` when `systemctl` could not be
consulted at all, or to fix an `xpfd.service` this host deliberately does
not use, points at the wrong system.

Those facts must be the ones the **decision** was made on. The previous
revision suppressed each query's failure at the point of use
(`2>/dev/null || return 0`) and then *re-queried* to build this message,
so a query that failed during discovery and succeeded on the re-read was
reported as "the unit IS known to systemd" and the operator was told to
fix an `ExecStart` that had never been consulted. Every systemd answer is
now read once, up front, into a **discovery snapshot**, and both the hops
and the message consume it — so what is printed is what was decided on by
construction rather than by care. `unit_facts` and `set_cause_advice`
cannot query systemd at all, and a test asserts that.

**The cross-check unit is pinned.** The gate cross-checks against
`xpfd.service` *specifically*, and deliberately does not infer which unit
is the xpf one: scanning for a
`<something>.service.d/10-xpf-version.conf` would resolve a leftover from
a renamed or removed unit exactly as readily as the live one — the same
indistinguishable-leftover problem that removed the filesystem fallbacks
— and there is no authoritative record to read instead, since `flip`
writes its drop-in *under* `<unit>.service.d/` without recording the unit
name anywhere.

`xpfd upgrade cut --unit <name>` is a supported standalone selector, and
on such a host `flip` maintains `<name>.service` while `<SbinDir>/xpfd`
is still repointed by step 6b, so the gate queries a unit that does not
exist. Under the pre-record design the unit **was** the authority, so
that layout could not be verified at all and `xpfd upgrade kernel arm`
refused it up front (`CheckKernelPromotionUnit`). The record removes the
dependency — the arming knows which xpfd it is regardless of what the
unit is called — so **that arm-time refusal is gone with the authority it
protected**, and such a box now promotes normally, logging
`arm record (xpfd.service resolved nothing to cross-check against)`.

Drift still matters, for a different reason: a canary
(`TestPromoteScriptUnitMatchesDefaultUnit`) keeps the shell script's
pinned unit equal to `upgrade.DefaultUnit`, because a wrong unit either
silently retires the cross-check (one that never resolves can never
contradict a stale record) or contradicts a good record and refuses every
promotion.

`KernelConfig` carries neither directory, so the *inner* hop's two
fallbacks are the compiled defaults; by then the outer hop has already
exec'd the right binary, so `os.Executable` — which needs no configured
root — is that binary.

If no explicit path resolves, the gate returns an error rather than
falling back to `$PATH`; `verifyAndPromote` turns any Gate-3 error into
`revert()` — restore the known-good `BootOrder` and reboot to the
known-good slot. On an A/B kernel promote that is the safe direction.

A lint test (`TestNoBareOrRelativeXpfArtifactExec`) enumerates every
shell-out under `pkg/upgrade` from the AST — direct `exec.*`, calls
through the package's own exec wrappers, and calls through *methods* such
as `System.VerifyDataplane` — and fails on any xpf-artifact command name
that is not an ABSOLUTE path. Bare names resolve against `$PATH` and
relative ones against the process CWD, so both are rejected, matching
`validateGateBin`. Artifact names come from `pkg/upgrade/manifest` (the
SSOT). The check applies to command names that evaluate at compile time
(a literal, a string const, or a `+` chain of those); a run-time value
such as `exec.Command(filepath.Join(dir, bin), …)` is the correct pattern
and is deliberately not classified. System binaries (`systemctl`,
`apt-get`, `efibootmgr`, …) are out of scope — PATH resolution is correct
for those, since they are distribution-owned and move between `/bin`,
`/usr/bin`, `/sbin`, and `/usr/sbin` across distributions.

**Fail-closed on ambiguous boot/watchdog state (#4872).** The gate never
treats an unreadable observation as a definite safe state:

- *BootCurrent read error.* When `efibootmgr`/NVRAM can't report which
  slot the firmware booted, `Promote` no longer blindly runs
  `cleanupAlreadyOnKnownGood` (which PRUNES the candidate slot —
  `/lib/modules/<candidate>` + `/boot/*-<candidate>`). It first reads
  `RunningKernel`: if it equals the candidate we ARE on the candidate, so
  it runs the verification gate (`verifyAndPromote`) instead of deleting
  the kernel it is running; only a positively-identified non-candidate
  running kernel takes the prune path. If BOTH `BootCurrent` and
  `RunningKernel` are unreadable the state is indeterminate —
  `recoverIndeterminate` preserves the journal + candidate, does NO prune
  and NO reboot, and surfaces a non-revert error so the oneshot maps it to
  an infra exit (not the exit-3 reboot). The next boot re-runs the gate.
- *StrictWatchdog (D1) arm failure.* The preflight only checks the BAKED
  watchdog-persistence flag; `armCandidate` now also treats a real
  `ArmWatchdog` failure as fatal UNDER STRICT MODE — it aborts the arm
  (no `BootNext`, no reboot, journal stays INSTALLED) rather than
  rebooting into the candidate with no functioning watchdog. D2 keeps the
  best-effort log-and-continue. The `realKernelSystem` watchdog helpers no
  longer swallow I/O errors: `ArmWatchdog` surfaces a `WDIOC_SETTIMEOUT`
  failure (after still attempting the keepalive), and `DisarmWatchdog`
  propagates open/write/close failures (a genuinely-absent device is still
  a clean nil).
- *Two-phase arm + BootNext readback (#5847).* The arm used to persist the
  `ARMED` journal BEFORE `efibootmgr --bootnext`, on the theory that an
  `ARMED`-without-`BootNext` journal is harmless. It is NOT: a crash in
  that gap (or before the best-effort rollback ran) left a FALSE-ARMED
  journal — the firmware still boots the known-good default and no trial
  ever happens, yet `Arm` refused-forever (`>= ARMED`) and self-recovery
  suppressed expired-lease failback INDEFINITELY (the drained node never
  rejoined). Neither write order is atomic with the NVRAM mutation, so
  `ARMED` is now made AUTHORITATIVE via a positive readback:
  1. record `ARMING` (prepared intent, with a fresh per-attempt nonce)
     BEFORE any NVRAM mutation;
  2. `SetBootNext(inactiveID)`;
  3. positively read `GetBootNext()` back and require it equals the armed
     inactive-slot id — a firmware that silently dropped or partial-wrote
     the variable must NOT yield a verified-ARMED journal;
  4. only THEN durably transition `ARMING -> ARMED`, recording the
     confirmed `BootID` for boot-provenance.
  5. **and on ANY failure after step 2, clear the one-shot (#6758).**
     `SetBootNext` has already succeeded by then, so returning an error and
     leaving the journal at `ARMING` used to leave the FIRMWARE armed while
     every durable software gate said unarmed — the exact inverse of what
     `ARMING` asserts below. Steps 3 and 4 both fail this way, as does the
     `recordPromoteBinary` write between them, and that last one is the
     sharpest: the readback had already CONFIRMED the one-shot, so the
     candidate was genuinely queued while no xpfd was designated to verify
     it — an armed candidate with nothing to run the promotion gate, which
     #6601 added that record specifically to prevent. The undo is
     single-sourced (`disarmAfterArmFailure`) because four failure paths
     needing the identical cleanup is how one gets missed, and clearing an
     absent BootNext is not an error so it is safe even where the firmware
     dropped the variable itself. If the clear ITSELF fails the divergence
     is real and cannot be undone in-process, so the error says so and names
     `efibootmgr --delete-bootnext`; it is deliberately NOT escalated to a
     journal state, because `ARMED` asserts a verified one-shot WITH a
     recorded promote binary — precisely what may be missing on the
     `recordPromoteBinary` path — so claiming it would substitute a
     different false record for this one.

  `ARMING` sits BELOW `ARMED` in the journal order, so a journal stuck
  there (readback failed / never ran) lets `Arm` RE-ARM (the `>= ARMED`
  refusal does not fire; `armCandidate` is idempotent) and does not
  suppress self-recovery. Only the verified `ARMED` (readback confirmed)
  counts as a genuine trial. The per-attempt `ArmNonce` (unique across
  attempts even under a stuck clock) distinguishes a fresh arm from a
  stale/crashed journal.

In a cluster the roll is driven ONE NODE AT A TIME by the external
orchestrator (`scripts/deploy/xpf-deploy.py kernel-roll`): drain
secondary-first (`xpfd upgrade kernel drain`, which confirms the peer
holds every RG before returning), arm+reboot into the candidate, poll
until `status` reports `promoted=<ver>` AND `uname -r` matches, then
`rejoin` (which confirms sync re-established before touching the peer).
A reverted node boots the OLD kernel and reports `promoted!=<ver>` → the
driver STOPS and never touches the peer (never-both-down).

The reservation lease TTL is `--lease-ttl <seconds>` (default 1800). It
MUST be a strictly-positive integer: the lease deadline is rendered as
`expires_at = now + ttl` and the acquire guard is a strict `now <
expires`, so a non-positive TTL yields a lease that is already expired
the instant it is written — the cross-orchestrator mutex never holds and
two independent drivers could each take a node's flock in turn and drain
OPPOSITE nodes into a no-primary outage. The parser rejects `0`/negative
at argument time (exit 2) rather than silently clamping; size the TTL to
comfortably exceed the whole roll (`--boot-deadline` plus drain/rejoin
margins). The same `--lease-ttl` contract applies to `image-roll`
(#5470).

The lease is RENEWED-WHILE-OWNED and FENCED-BEFORE-MUTATE (#5816). The
one-shot lease of #5470/#5545 wrote `expires_at` ONCE and neither roll
path renewed it nor re-checked ownership before its later mutations, so a
positive TTL shorter than the real roll (boot/drain deadlines, an image
recreate, ordinary reboot/rejoin latency) let BOTH node leases EXPIRE
while a driver kept running — and a successor could then atomically
reclaim both expired leases and start its own roll against the same pair
(split-brain deploy). Two mechanisms close this, both keyed on the SAME
owner-identity token (`nodename:pid<pid>`) the acquire/reclaim already
use:

- **Renewal** (`_renew_lease`): re-writes `expires_at = node_now + ttl`
  iff the holder still matches, atomically (temp+rename) under the acquire
  flock; a lease another orchestrator reclaimed (holder differs / file
  gone) is reported LOST and left untouched — renewal never resurrects a
  lost lease. It is fired every reboot-poll tick (keep-alive). The rolled
  node is unreachable while it reboots (kernel-roll) or has a fresh
  lease-less disk after recreate (image-roll), so during the wait ONLY the
  still-up PEER's lease is renewed — that peer lease is the load-bearing
  reservation (a successor can never acquire BOTH node leases while we
  hold the peer's). A mid-reboot transport failure is NEVER misread as a
  loss (the #4905-A discipline).
- **Fence** (`_fence_before_mutate`): immediately before EACH pair-mutating
  action (drain, arm+reboot, image-recreate, rejoin) it renews-and-verifies
  ownership of every relevant lease and, unless it can prove we still own
  them, `die()`s fail-closed. The load-bearing invariant: an orchestrator
  that has lost (or cannot confirm) its lease MUST NOT mutate the pair. A
  fence answers the phase BOUNDARY, not the phase: it extends the leases to
  one fresh TTL and returns.
- **Keep-alive across the recreate hook (#6762).** The image-roll recreate
  is an ARBITRARY operator script doing destroy+launch+day-0 — an image
  pull, a cloud API wait, a bare-metal re-flash — with no bound on its
  duration, and it used to run with NOTHING renewing. A hook outliving the
  TTL let the still-up peer's lease expire, and that peer lease is the SOLE
  remaining reservation once the recreate wipes the node's own `/var/lib`;
  a successor could then acquire BOTH node leases and start a concurrent
  roll on a pair this driver was mid-recreate on. The fence before it names
  exactly this risk (#5545 flagged the recreate as "potentially outlasting
  a short TTL") — one extension was simply the wrong shape of answer. The
  hook now runs under `_run_with_lease_keepalive`, which polls it to
  completion and renews the peer lease every `max(5, ttl // 3)` seconds.
  Renewal polls in the FOREGROUND rather than from a background thread: the
  renewal path shells out through the same runner the main flow uses, and a
  second thread driving it concurrently would add a new concurrency surface
  to the one code path whose whole job is preventing two drivers touching
  one pair. A loss detected mid-hook does NOT kill the hook — interrupting
  a half-finished destroy+launch is worse than letting it finish — it is
  recorded, and the caller `die()`s fail-closed BEFORE rejoin, the same
  response the boot-poll loop already gives.
- **Unverified-primary detection during the boot poll (#6759).** The recreate
  wipes the node, which erases the drain applied before it — the drain lived on
  the disk that was replaced. The identity gate (#5075: live `xpf-version` ==
  the AUTHENTICATED manifest's, and `/etc/xpf/node-id` == the assigned cluster
  node-id) runs AFTERWARDS, so between bringup and gate-pass the node is
  un-drained with unvalidated identity. The boot poll now also reads the node's
  RG state and, if the recreated node is PRIMARY before the gate passes, fails
  closed with the leases HELD — the same stance the loop already takes for a
  version/node-id mismatch.

  **This DETECTS the exposure; it does not close it.** The election happens
  during the recreated node's own bringup (`daemon_run_bringup.go` runs
  `UpdateConfig`, which elects on the single-node path) long before any driver
  command lands. No hold that lives ON the node can help:
  `holdSecondaryIfKernelCandidateArmed` keys on the on-node kernel journal, and
  a clean ENOENT is folded to "never armed" with no hold. A reboot preserves
  that journal so ENOENT truly means "never armed"; a recreate destroys it, so
  ENOENT means "the evidence was wiped" — and nothing on the node can tell those
  apart. That is NOT a defect in `kernel_selfrecover.go`: the distinction is
  correct for the path it was written for and has no way to be right for this
  one.

  Scope: `election.go`'s fresh-boot guard already keeps a NON-preempt RG with a
  reachable peer at SECONDARY, so the exposure is `preempt`-configured RGs and
  boots where the peer is not visible at first election.

- **Daemon hold across the recreate (#7559)** — the window above, closed. The
  detector stays as the net for an unprotected roll; this is the guard.

  The framing that made #7559 look expensive was "closing it needs a signal
  that survives the disk wipe". It does not. The election is run by a DAEMON
  whose start the driver already controls end to end. If `xpfd` never starts
  until the identity gate has passed, there is no election to hold and nothing
  has to survive anything.

  What makes it work is that **the #5075 gate is evaluable with the daemon
  down**: `xpfd protocol-versions` is a pure binary invocation
  (`cmd/xpfd/main.go` `cmdProtocolVersions` prints compile-time constants and
  returns before any daemon/config/state path), and `/etc/xpf/node-id` is read
  with `cat`. So the driver can prove "the expected node on the expected build"
  BEFORE the node is able to claim a redundancy group.

  That property also makes this the only candidate design that covers the case
  #5075 was actually filed for. Every hold that lives inside `xpfd` — a peer
  veto carried in the heartbeat, a day-0-seeded on-node marker — is honoured
  only by an image that KNOWS about it, so a hook that relaunched the OLD image
  ignores it and elects anyway. Not starting the daemon works no matter which
  image the hook launched.

  Sequence, per node, inside the existing boot poll:

  1. the recreate hook is invoked with `XPF_ROLL_DAEMON_HOLD=1` plus
     `XPF_ROLL_EXPECT_VERSION` / `XPF_ROLL_EXPECT_NODE_ID` — the identity this
     roll expects the node it is about to create to have;
  2. the hook keeps `xpfd` from auto-starting on the guest's FIRST boot. Mask
     the unit before the guest boots — an `/etc/systemd/system/xpfd.service`
     symlink to `/dev/null` in the launched filesystem is enough, and for
     incus that is `incus create` + inject + `incus start` rather than
     `incus launch`. A hook that only `systemctl disable`s the unit is also
     recognised as a hold;
  3. each poll tick reads the node's daemon state BEFORE the identity gate.
     The order is load-bearing: a node that came back with `xpfd` already
     RUNNING was never protected, and that stays true on the very tick where
     the gate happens to pass. Deciding afterwards would record the fastest
     possible failure — a node that booted, elected and answered within one
     poll interval — as a protected roll;
  4. once the gate PASSES, and only then, the driver runs `systemctl unmask
     xpfd && systemctl enable --now xpfd` and waits (bounded, 180s) for the
     daemon to be READY before rejoining. A node that FAILS the gate never
     reaches that line — every failure path `die()`s with the never-both-down
     leases held — so a wrong-image / wrong-node-id recreate is left **inert**,
     not merely detected.

  **The transport must not depend on xpfd, so the hold is backend-gated.** The
  hold makes the node inert, and on the sealed appliance image that includes
  its MANAGEMENT ADDRESS: `scripts/image/bake.py` purges cloud-init and deletes
  every netplan / `interfaces.d` file, so xpfd's own bootstrap lifeline is the
  only thing that ever addresses `fxp0`. That is what makes a held node safe
  (no addresses, nothing to forward) and it is the same fact that decides which
  transport can still reach it:

  - `--backend incus` — `incus exec` reaches the guest through the baked
    incus-agent, not by IP. The hold is requested here.
  - `--backend ssh` — the driver reaches the node by IP. A held xpfd means no
    IP, so the boot poll would never see the node at all, time out, and leave
    it masked, addressless and console-only. That trades a transient integrity
    exposure for a persistent outage, so the hold is **not** requested; the
    roll is bit-identical to its pre-#7559 behaviour. `--require-daemon-hold`
    overrides — an operator whose platform addresses the node independently of
    xpfd is the only one who can know that, and asking for the guarantee is
    how they say so.

  **"Ready" is not "systemd active".** `xpfd.service` is `Type=simple`, so
  `enable --now` returns the instant the process forks, while the gRPC listener
  comes up only after config compile+commit, interface rename, the networkd
  apply, the AF_XDP load and the FRR reload. The very next step is
  `xpfd upgrade kernel rejoin`, and `RejoinAndConfirm`
  (`pkg/upgrade/kernel_drain.go`) calls `ResetFailover()` **outside** its retry
  loop — one un-retried gRPC dial with a 5s timeout. Waiting on `ActiveState`
  alone would therefore fail the roll on a cold daemon with an opaque transport
  error. The driver waits for BOTH the unit to be running AND
  `show chassis cluster status` to answer with a redundancy-group block, which
  is the same gRPC path the rejoin uses and proves the cluster manager is
  populated.

  **Three daemon states, not two.** `held` (masked or disabled, and not
  running), `running`, and `pending`/`unknown` — a unit that is enabled but not
  yet up is a guest still BOOTING, and an unreadable state is a transport blip.
  Neither is protection, and folding either into "held" would report an
  unprotected roll as protected. `systemctl is-active` alone cannot make this
  distinction: it exits non-zero for every inactive state, so a masked unit and
  an unreachable node look identical. The driver reads `systemctl show xpfd -p
  LoadState -p UnitFileState -p ActiveState` in one round trip instead, and
  decides `running` FIRST — a unit masked in the unit file but nevertheless up
  can elect.

  **Not enforced by default, deliberately.** Holding the daemon is an act of
  the operator-supplied hook; every hook written before this change leaves
  `xpfd` auto-starting, so making an unheld daemon fatal by default would break
  every existing roll for a window those rolls have always run with. The new
  environment variables are purely ADDITIVE — a pre-#7559 hook ignores them and
  behaves exactly as it did — which is precisely why the driver VERIFIES the
  hold rather than assuming it: an unheld daemon is reported loudly and the
  #6759 detector remains the net. `--require-daemon-hold` turns the report into
  a refusal, with a DISTINCT message for "came back running" versus "the daemon
  state was never readable" — two causes rendered as one indistinguishable
  refusal is the #6495 blindness again, with two causes instead of one.

  If the driver dies between the recreate and the release, the node is left
  with `xpfd` held and the peer still primary: **redundancy is degraded,
  availability is not**, and the failure names its own remedy (`systemctl
  unmask xpfd && systemctl enable --now xpfd`), reachable over the same
  agent transport the driver was using. That is the same residual the
  peer-authority design carried, without the new cluster state or wire field it
  needed. Nothing self-recovering is lost in that state either: the bounded
  local self-recovery wired at `daemon_run_bringup.go` gates on `LocalDrained()`
  and a RECREATED node is not drained — the recreate wiped the in-memory drain
  along with the disk — so it is a no-op on this path with or without the hold.

  Covered by `scripts/deploy/test_xpf_deploy_daemon_hold_7559.py` (RED on
  revert: move the release before the poll loop and a wrong-build recreate is
  started; delete it and a correct recreate is left inert and never rejoined).
  Because `die()` is a `SystemExit`, `kernel-roll`'s `finally` still runs
  after a fence-abort — and its own best-effort restore-forwarding rejoin
  IS a pair mutation. So the fence records the loss (a `lost_lease` flag,
  set on a confirmed loss OR an unconfirmable-after-retries lease — the same
  fail-closed stance) and the `finally` SKIPS that rejoin whenever the flag
  is set: an orchestrator that lost its lease must not un-drain a pair a
  successor now owns. A clean abort where the lease is still confidently
  held leaves the flag clear and the restore rejoin runs as before.

Because renewal keeps the TTL a rolling window that never elapses while the
driver is live, the `--lease-ttl` FLOOR was NOT raised: a short TTL is now
safe (it is renewed). Size it above a single un-interruptible mutation the
keep-alive cannot cover mid-call — chiefly the `image-roll` recreate hook,
which the fence renews to a fresh full TTL immediately before invoking; the
default 1800s comfortably exceeds a VM launch + day-0. This also sharpens
the crashed-roll self-recovery contract below: the lease now stays alive
ONLY while the orchestrator is live, so an EXPIRED lease is an unambiguous
crash signal — a slow-but-alive driver no longer looks crashed.

The poll decides "the node rebooted" from an AFFIRMATIVE signal only — a
CHANGED `boot_id` (`/proc/sys/kernel/random/boot_id`, recorded pre-arm) or the
candidate kernel actually running — never from an empty status read (#4905-A).
The node-exec wrapper returns a STRUCTURED result (exit code + stderr), so a
transient SSH/incus drop or control-socket contention is distinguished from a
real reboot: an un-ok read is retried, not misread as a completed revert.
Before this, ANY empty `uname -r` set `rebooted=True`, so one status blip made
a still-drained-and-running node (e.g. an `arm` that failed its UEFI/NVRAM
preflight WITHOUT rebooting) look like a finished revert; the `finally` then
skipped its rejoin and left the node DRAINED + ForceSecondary with both leases
released — a silent loss of redundancy. Rejoin is now decided from the
confirmed drain state: a drained node that never affirmatively rebooted is
rejoined — UNLESS the roll aborted because we lost the lease (see the Fence
`lost_lease` note above), in which case the pair belongs to a successor and
the finally must NOT un-drain it.

If `rejoin` cannot confirm within its deadline, `RejoinAndConfirm`
(`pkg/upgrade/kernel_drain.go`) now surfaces the last non-nil
`PeerAlive`/`SyncEstablished` transport error in the returned error —
naming which check failed — instead of printing only the alive/synced
booleans (#4717). So an operator whose rejoin stalls on a refused gRPC
dial (xpfd still restarting) sees the actual cause in the `xpfd upgrade
kernel rejoin` stderr rather than having to correlate syslog. This is
diagnostics only: the happy path is unchanged and a failed rejoin
already STOPPED the roll before touching the peer.

Three independent safety nets keep an UNVERIFIED candidate from ever
carrying traffic:

1. **Election hold (`kernelUpgradeHold`).** A candidate boot sets an
   unconditional SECONDARY hold in `pkg/cluster` election BEFORE
   `cluster.Start()` (the orchestrator's in-memory `ForceSecondary` drain
   is lost across the reboot, and `peerAlive` is still false at boot so a
   ForceSecondary call would be a no-op). Unlike `ManualFailover` this
   hold is NOT auto-cleared for an isolated node — a candidate with a
   broken dataplane stays secondary even if it can't see the peer. It is
   set BEFORE `cluster.UpdateConfig` (which itself runs the first
   election) — not merely before `Start()` — so a candidate can never win
   even the initial single-node election. `SetKernelUpgradeHold` also
   DEMOTES any already-primary group as defense in depth.

   **Fail-closed on an UNREADABLE journal (#5682 / codex-review-182 M24).**
   `holdSecondaryIfKernelCandidateArmed` reads the journal to decide
   whether this is a candidate boot. A genuine read/parse FAILURE (I/O
   error, corruption, malformed content) is a failure mode that itself
   correlates with a bad upgrade, so it now sets the hold FAIL-CLOSED
   rather than treating the unknown state as "not armed" and proceeding to
   a normal election (which would bypass the hold and the promote/rollback
   safety). A clean `ENOENT` is precisely distinguished (`loadKernelJournal`
   folds a missing file to `KernelStateInit` with a nil error) and STILL
   proceeds normally, so a node that simply never armed an upgrade is never
   bricked into a spurious hold. A fail-closed hold is not stranded: it is
   tracked distinctly (`Daemon.kernelUpgradeHoldFailClosed`) and
   `reconcileKernelUpgradeHold` self-heals it — a later reconcile tick
   re-reads the journal and RELEASES the hold once the read succeeds and
   the node is definitively NOT armed (a transient I/O blip with no upgrade
   pending), CONVERTS it to a normal armed hold if the read now shows a
   genuine armed candidate (the strict marker gate then governs), or keeps
   holding while the journal stays unreadable. The strict marker-only
   release below is preserved for a genuinely-armed hold so the revert
   window can never transiently promote an unverified candidate.

   The hold is released only when the candidate is affirmatively
   VERIFIED+PROMOTED:
   the promotion gate runs in a SEPARATE process
   (`xpf-kernel-promote.service`, `After=xpfd`) and writes a durable
   promotion marker for the running kernel, so the daemon reconciles the
   hold on a 5s cadence and releases it only once the marker NAMES THE
   RUNNING KERNEL. A bare "no longer armed" test would be unsafe on the
   revert path: `revert()` clears the journal and THEN reboots, so a
   not-armed test could release the hold while the broken candidate is
   still running (transient split-brain) — the marker test fails safe (a
   reverted node reboots to known-good, where the hold is never set).
   On a gate HANG/timeout the unit's `OnFailure=` triggers
   `xpf-kernel-promote-failed.service`, which reboots once to known-good
   (the firmware-cleared BootNext + un-reordered BootOrder land it there)
   so a hung verify never leaves the node held secondary forever. Both
   units ship in the `.deb` — `debian/rules` stages the promote unit AND
   its `OnFailure=` recovery unit (installed via `dh_installsystemd
   --no-enable --no-start`, since the recovery unit has no `[Install]`
   section), with a build-time parity assert that the `OnFailure=` target
   is actually staged. Before #4202 only the bake staged the recovery
   unit, so a deb-installed / foreign host had a dangling `OnFailure=`
   reference ("Unit not found") and a hung gate got no recovery reboot.
2. **Lease-suppressed self-recovery.** If the orchestrator CRASHES while a
   node is drained+rebooting, the node would sit passive forever. The
   bounded local self-recovery (`pkg/upgrade/KernelSelfRecovery`,
   30s safety-net loop) auto-rejoins ONLY on the unambiguous crashed-roll
   fingerprint: an EXPIRED roll lease naming this node
   (`/var/lib/xpf/kernel-roll.lease`), a drained local node, and a
   healthy primary peer, held continuously for the grace window. A
   manually drained node or a #1917 binary-rolling drain never wrote a
   kernel-roll lease (`leaseNone`) and is left alone. The lease must carry
   a real `expires_at` (#4872): a semantic-empty body (`{}`) or one that
   omits the deadline decodes to `NodeID=0` + the zero time and, on node
   0, would otherwise read as an already-expired lease naming us and
   spuriously self-recover during a maintenance drain — a missing deadline
   is now rejected as no-decision (`leaseNone`). The grace window also
   requires CONTINUOUS positive evidence: any observation error
   (`Armed`/`LocalDrained`/`PeerHealthyPrimary`, e.g. a transient
   management outage) RESETS `drainedSince`, so a run of errored ticks
   can't silently age the deadline and let the next positive tick rejoin
   immediately.
3. **Still-armed gate.** Self-recovery refuses to rejoin while the kernel
   journal is at the VERIFIED `ARMED` state even if the lease has expired
   — a legitimately long-hanging roll (one that outran its lease TTL) is
   still a trial in flight; the promote/revert oneshot owns the
   resolution, and the election hold keeps the node secondary meanwhile.
   This gate is driven by `IsArmed`, which reports true ONLY for the
   verified `ARMED` state — NOT the `ARMING` prepared-intent state (see
   the two-phase arm below). A journal stuck at `ARMING` is NOT a genuine
   trial, so self-recovery does NOT suppress on it and the drained node
   can rejoin (#5847).

### Persistence precondition

The kernel channel REQUIRES `/var/lib/xpf` to be PERSISTENT across
reboots. The candidate journal (`kernel-upgrade.state`) is the only
record that a boot is a candidate trial; if it were on tmpfs/volatile
storage it would vanish on the candidate reboot, the election hold would
not be set (the node would not know it is a candidate), and an unverified
candidate could become primary. The journaled state machine for the
#1917 binary roll has the same requirement. This is a platform invariant
of the appliance image (`docs/install-images.md`), not a tunable.

The arm-record sidecar (`kernel-promote-binary`) shares that requirement
and is written to the same directory for exactly that reason: it is what
tells the boot gate **which xpfd** must verify the candidate. The two are
written and cleared together, and the gate treats a divergence between
them as an error rather than as a skip (#6601 r7), so losing only one of
them is loud rather than silent — but losing either still costs the
candidate its promotion.

## Kernel / OS upgrade lanes (#1930)

A kernel or base-OS move picks a lane by how big the change is:

| Change | Lane | Mechanism |
|---|---|---|
| Same kernel SERIES, in-place (verified shim already passes) | LANE 1 | `xpfd upgrade kernel` A/B UEFI boot channel (above) |
| New kernel SERIES, or kernel arriving with a base bump | LANE 2 | image-replace (`xpf-deploy.py image-roll`) |
| Base-OS major version (Ubuntu N → N+1) | LANE 3 | image-replace ONLY (the new kernel rides inside the image) |

The decision rule is **series change ⇒ LANE 2**: the AF_XDP shim's
kernel verifier (#1864) has only been proven against the kernel baked
into the image, so a new series goes through the fully-tested image
substrate (`bake.py` builds it, `validate.py` boot-gates it) rather than
the in-place channel.

### LANE 2 — rolling image-replace (`xpf-deploy.py image-roll`)

There is **no in-place base-OS swap**. `image-roll` recreates each HA
node from a new baked image ONE AT A TIME (built on the existing per-node
`launch` + day-0 re-apply), so the peer keeps forwarding:

1. **Mixed-base gate (before the FIRST swap).** After node[0] is replaced
   it runs the NEW image while node[1] still runs the OLD one — a
   *mixed-base* cluster. Sessions survive that window only if the new
   image's HA + session-sync protocols are back-compatible with the
   still-running peer. The driver reads the new image's
   `xpf-<ver>.manifest` (the `ha-protocol-version` /
   `ha-protocol-min-compat` / `session-sync-protocol-version` fields the
   bake records from `xpfd protocol-versions`) and the running peer's live
   `xpfd protocol-versions`, and applies `upgrade.GateMixedBaseSwap`

   **Signed gate input (#5042).** The `xpf-<ver>.manifest` sidecar is
   included in the signed `xpf-<ver>.SHA256SUMS` set at bake time, and
   `image-roll` VERIFIES it against that signed manifest (`--sha256sums` /
   `--sig` / `--pubkey`, defaulting to the `.SHA256SUMS` sibling + its
   `.minisig` + the pinned image pubkey) and parses the checksum-bound bytes
   before the gate reads them. Before #5042 the sidecar was parsed raw, so
   tampering ONLY those protocol fields — while every signed image byte
   stayed untouched — could spoof a compatible-window / matching-session-sync
   decision and bypass the session-safety stop. Verification is fail-closed:
   a missing/unsigned/mismatched manifest STOPS the roll (there is no
   `--allow-session-drop`-style bypass of the signature — that flag relaxes
   only the compatibility verdict, never the authentication of the input).
   The same verified manifest's `validated` field is read too (#9325): an
   image whose manifest records `validated: false` (a `--skip-validate`
   bake) STOPS the roll unless `--allow-unvalidated` is passed, and a
   manifest from a bake that predates the field is rolled with a warning.
   (mirrored in the driver, unit-tested in Go): sessions survive **iff**
   the peer's HA protocol is within the new image's
   `[min-compat, version]` window AND the session-sync protocol matches
   exactly. It is **fail-closed** — any missing field, any out-of-window
   peer, any session-sync mismatch STOPS the roll with
   "re-image both nodes (sessions drop)". `--allow-session-drop` proceeds
   node-by-node anyway (sessions drop at the failover).
2. **drain** node[0] → peer (confirmed; the INC-2 `xpfd upgrade kernel
   drain` verb, never recreate an undrained primary).
3. **recreate** node[0] from the new image via the operator's
   `--recreate-hook` (backend-specific destroy+launch+day-0; the
   sequencing + never-both-down stays in the driver while the recreate
   mechanics stay environment-specific). The node boots the new base,
   factory-bootstraps its config DB from the day-0 text, verifies the
   dataplane.

   **Hook contract.** The hook is invoked as `<hook> <node>` with
   `XPF_ROLL_NODE`, `XPF_ROLL_BACKEND`, and — since #7559 —
   `XPF_ROLL_EXPECT_VERSION`, `XPF_ROLL_EXPECT_NODE_ID` and
   `XPF_ROLL_DAEMON_HOLD=1` in the environment. The last three are the
   identity this roll expects of the node the hook is about to create, and
   the request that `xpfd` be kept from auto-starting on its FIRST boot so
   the driver can prove that identity before the node can win an election
   (see the #7559 note above). They are purely additive: a hook written
   before #7559 ignores them and behaves exactly as it did, which is why
   the driver verifies the hold rather than assuming it.
4. **poll** until it is back **as the EXPECTED node on the EXPECTED
   build**, then **rejoin** + confirm sync BEFORE touching node[1]
   (never-both-down; the INC-2 `rejoin` verb). Repeat for node[1].

   **Identity + version gate (#5075).** "Back" is NOT merely "some xpfd
   answers `protocol-versions`". Before #5075 the poll accepted ANY
   responding xpfd (a non-empty `xpf-version`), so a `--recreate-hook`
   that relaunched the OLD image, a stale alias, or the WRONG node-id
   satisfied it — the driver rejoined the wrong/old node and rolled the
   peer onto unintended/mixed software, a **silent deploy-integrity
   failure**. The poll now requires the responding daemon to be BOTH:
   - the **expected build** — its live `xpf-version` EXACTLY equals the
     AUTHENTICATED manifest's `xpf-version` (the same signed
     `xpf-<ver>.manifest` bytes the mixed-base gate reads, so no extra
     trust input is introduced), AND
   - the **expected node** — its `/etc/xpf/node-id` (the marker xpfd
     itself keys HA identity on) equals the cluster node-id the deploy
     assigned this node (`--node0-id` / `--node1-id`).

   The existing retry/timeout is preserved (keep polling until the gate
   passes or `--boot-deadline` elapses), but a responding-but-wrong daemon
   is **fail-closed**: the roll ERRORS with the never-both-down leases
   HELD (the peer stays primary, the half-rolled pair is left for the
   operator to investigate) instead of silently proceeding. Covered by
   `scripts/deploy/test_xpf_deploy_image_roll_identity.py` (RED on revert:
   the old node / wrong node-id is accepted and the roll completes).

When draining node[1] (the SECOND node), its peer is the already-rolled
NEW image, so the drain's exact-equality HA precheck is relaxed with
`xpfd upgrade kernel drain --allow-mixed-ha` (the gate already validated
window-compat). node[1] is still on the OLD image at that point, so the
driver **feature-detects** `--allow-mixed-ha` on node[1]'s running binary
(`drain --help`) and only passes it when supported — an image rolled FROM
a pre-INC-3 release has no such flag and would otherwise abort on it. When
the flag is absent the driver falls back to the OLD binary's exact-equality
precheck, which is correct whenever old/new advertise the same HA version
(the only in-window case a same-version roll produces); a genuine
in-window protocol *difference* cannot be relaxed by an OLD binary, so the
operator must re-image both nodes together.

Scope note (Codex): `--allow-mixed-ha` relaxes ONLY the drain's
exact-equality *HA-protocol* precheck (`HAProtocolCompatible`). The drain's
`PeerTakeoverReady` / transfer-readiness check is still enforced, and on a
real HA mismatch the peer reports `Transfer ready: no`
(`daemon_ha_userspace.go`), which still aborts the drain. So neither
`--allow-mixed-ha` nor `--allow-session-drop` is a blanket "drain under any
HA skew" bypass — a genuinely HA-skewed peer is still refused at the
transfer-readiness gate. This is dormant in practice today because the HA /
session-sync protocol versions are pinned exact-version, so the only
in-window cases that reach the relaxed precheck advertise equal HA versions;
the scope matters for any future release that widens the HA compat window.

**Standalone** is a documented reboot/recreate gap (image swap + factory
boot + day-0 re-apply); there is no zero-gap standalone image replace.

### LANE 3 — base-OS major upgrade: image-replace only

**Default and ONLY supported path: image-replace (LANE 2).** A baked N+1
image carries the new kernel, glibc, systemd, FRR, strongSwan, kea, and
chrony as one `validate.py`-gated unit.

**State carries as TEXT config, not the encrypted DB.** The portable
artifact is `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` for HA identity),
re-applied via the day-0 drive; the freshly-imaged node factory-bootstraps
`.configdb` from the text on first boot. `master.key` is RE-GENERATED on
the new image, NOT carried — do not attempt to carry `.configdb`/
`master.key` across a fresh image (the new key cannot decrypt a carried
DB). (For an *in-place* #1917 upgrade the DB persists; image-replace
re-bootstraps from text — different paths.)

**In-place `do-release-upgrade` is UNSUPPORTED.** It modifies the entire
userspace in-place and irreversibly (no rollback if the new userspace
fails to forward); constrained with `apt-mark hold linux-*` it leaves the
release half-upgraded; it can leave N+1 userspace on the old N kernel
where the shim may not verify; and it cannot be CI-tested. Operators who
run it anyway do so at their own risk and should re-image afterward.
