# Plan of action — #1981: close the dpkg-unpack vs operator-cut staged-source race

- **Issue:** #1981 (HIGH, correctness / upgrade integrity)
- **Mode:** `/research` — converge a plan + recommend a mechanism; STOP at PLAN-READY. No code, no PR.
- **Revision:** r4 (r1→r2: recommendation FLIPPED D→**B**. r2→r3: B ratified by
  all three; tightened the B spec for eight r2 spec-findings. r3→r4: Codex and
  AGY r3 INDEPENDENTLY converged on ONE remaining hole — B-P3b's same-version
  `versions/<ver>` replacement protocol (a blind `.partial`→rename fails
  `ENOTEMPTY` and a destructive replace would mutate the live/rollback dir
  mid-cut, violating #1967). r4 adds the SAFE replacement protocol (OPT1
  refuse-or-guarded-replace [recommended, reuses the proven `cleanupFailedVerifyCopy`
  guard] / OPT2 generation-keyed `versions/<ver>-<genid>` dir). r1 findings §11;
  r2 §12; r3 §13.)
- **Base:** `origin/master` @ `b1ef3ed16` (includes merged #1982 manifest SSOT, #1984, #1985, #1983).
- **Research branch:** `research/1981-staged-generation-immutability`

---

## 1. Problem statement

`/usr/local/share/xpf/staged/` (`DefaultStagedDir`) is **not an immutable
source** during an operator-driven cut-over. The race:

1. `apt upgrade` begins. The **new** package's `preinst upgrade` runs BEFORE
   unpack (Debian Policy §6.5/§6.6). It only does a *point-in-time*
   `flock -n /run/xpf/upgrade.lock true` probe — the lock fd dies at preinst
   exit, so **the lock is NOT held during dpkg's unpack** (the preinst comment
   at `debian/xpf.preinst:14-22` says exactly this).
2. dpkg unpacks the payload. **dpkg replaces files one at a time**: for each
   managed binary it writes `staged/<bin>.dpkg-new` then `rename()`s it over
   `staged/<bin>`. Across the unpack interval the staged dir therefore holds a
   **mix**: e.g. `staged/xpfd` already NEW while `staged/xpf-userspace-dp` is
   still OLD.
3. An operator runs `xpfd upgrade` (acquires the now-free lock) and `copyStaged`
   (`pkg/upgrade/cutover.go:507-547`) does `copyTree(StagedDir, partial)` then
   atomic-renames to `versions/<TargetVersion>/`. If that copy lands entirely
   inside the unpack window it publishes a **single `versions/<ver>` dir that
   mixes old and new binaries** under one `TargetVersion`.

The existing integrity check **cannot catch this**:

- `copyTreeChecksum(partial)` (`cutover.go:526`) checksums the **copied bytes
  against their own freshly-generated sum** — proves the copy is internally
  intact, NOT that all managed binaries came from the **same dpkg unpack
  generation**.
- The kernel `verify-dataplane` gate (`cutover.go:551-573`) validates only the
  copied `xpfd` + embedded shim. It is a **partial** backstop: it never
  establishes that `cli`, `xpf-userspace-dp`, `xpf-day0-config` came from the
  same generation. A torn set whose `xpfd` happens to verify-pass (new `xpfd`
  paired with an ABI-incompatible old `xpf-userspace-dp`) sails through and
  flips a mismatched dataplane live. `xpf-userspace-dp` is a **lockstep-cut
  dataplane binary** (manifest `LockstepCut: true`), so this is the real, HIGH
  exposure.

Prior hardening narrowed but did not close this: #1965 host-wide lock (cannot
cover the unpack interval), #1967/#1974 cut robustness (crash-safety, not
generation consistency), #1982 manifest SSOT (composes, doesn't itself prove
consistency). `docs/in-place-upgrade.md:385-395` names it the "dpkg-vs-operator
staged-source race" as an accepted caveat. #1981 IS the issue to close it.

## 2. Goal / acceptance criteria

- An operator `xpfd upgrade` (and the postinst auto-cut, and `--rolling`) MUST
  NOT publish a `versions/<ver>` that mixes binaries from two dpkg unpack
  generations. The cut either reads a **whole, single-generation** source, or
  **fails loudly before any live mutation** (pure pre-STOP failure, daemon
  untouched).
- Crash-safe at **every** maintainer-script + cut step, and across dpkg's
  error-unwind (`abort-upgrade`/`abort-remove`/`abort-deconfigure`): kill at any
  line leaves a consistent, resumable state. **NEVER** a permanently-wedged
  "can't ever cut again" host, and NEVER a daemon-down-with-no-rollback host.
- Compose with the #1965 lock, the #1967 deferred-cut + verify-fail cleanup +
  DB-snapshot lifecycle, the #1982 manifest, and the #1964 first-install seed /
  legacy-migration — do not regress any of them.
- A regression test that **mutates one managed staged binary mid-copy**
  (simulating a half-unpack) MUST fail the cut, and the **pre-fix** path
  (self-generated target checksum only) must be shown to NOT catch it
  (counter-factual pin per engineering-style "Test strength").

## 3. Blast radius (files this design touches)

| File | Role | Expected change class (Option B) |
|---|---|---|
| `debian/xpf.postinst` | runs AFTER unpack, drives auto-cut | after a SUCCESSFUL unpack, publish `staged → staged-gen/<genid>/` (atomic) BEFORE the auto-cut |
| `pkg/upgrade/cutover.go` | the cut copy step | `copyStaged` reads from the latest published `staged-gen/<genid>/` instead of live `staged/`; the source-generation selection + presence check moves to INIT (pre-PREFLIGHT) |
| `pkg/upgrade/runner.go` | layout + GC | new `StagedGenDir` config; GC of `staged-gen/` mirrors the `versions/` GC |
| `pkg/upgrade/manifest/` | SSOT | (B needs no per-binary manifest for the gate; an optional genid-stamp helper if a straddle tripwire is wanted) |
| `pkg/upgrade/runtime/seed.go` | first-install seed | publish the first `staged-gen/<genid>/` from the seeded set (so a first manual cut has a source generation) |
| `debian/rules` | staging | NO change — dpkg still owns ONLY `staged/`; `staged-gen/` is maintainer-script-managed runtime state like `versions/` |
| `docs/in-place-upgrade.md` | operator/design doc | replace the "accepted caveat" §385-395 with the closed-race contract + recovery |
| tests | `pkg/upgrade/*_test.go` | mid-copy mutation regression + publish-atomicity + GC + first-install |

No hot-path code. No protocol-field/BPF-map change. Packaging + cut-path
correctness only.

## 4. The design space — FOUR mechanisms evaluated

All must defeat the same adversary: **a cut that reads a torn set while dpkg is
mid-unpack.** The decisive axis is *does the cut ever read the path dpkg is
actively rewriting, and how much maintainer-script lifecycle state must be
correct for the fix to hold.*

### Option A — Unpack+configure presence SENTINEL — REJECTED

A bare presence-file dropped by preinst, removed by postinst, that makes
`copyStaged` refuse while present. **FATAL:** an aborted unpack (the new
postinst never runs) strands the sentinel → **permanent host wedge** (every
future cut refuses forever). A presence file has no generation identity, so it
cannot self-clear on a fresh complete generation. Strictly worse than the bug it
fixes. Rejected.

### Option B — Immutable VERSIONED staging — **RECOMMENDED**

**Mechanism (full spec):**

1. dpkg still unpacks the managed binaries into the dpkg-owned `staged/`
   (unchanged; `debian/rules` untouched). dpkg owns ONLY `staged/`.
2. **`debian/xpf.postinst configure` (AFTER unpack, BEFORE the auto-cut):** the
   unpack for THIS transaction is now COMPLETE (Debian Policy §6.7: `postinst
   configure` runs after all files are unpacked and the dpkg frontend lock is
   held, serializing transactions). The postinst invokes the staged binary to
   **publish** the complete staged tree into an immutable, generation-keyed
   source dir: `staged-gen/<genid>/` via `.partial` + atomic rename + dir-fsync.
   `<genid>` is a fresh monotonic token (nanosecond-time + random suffix, so a
   reinstall of the SAME version still gets a distinct genid — AGY r1-#4). A
   `staged-gen/current-gen` symlink (atomic) names the latest complete
   generation, mirroring `versions/current`.
3. **`copyStaged` (`pkg/upgrade/cutover.go`)** copies from the genid the journal
   recorded at INIT (`staged-gen/<SourceGeneration>/`, the directory, NOT through
   the `current-gen` symlink — so a concurrent publish that re-points
   `current-gen` cannot redirect an in-flight cut), **NEVER from live `staged/`**.
   The source-generation is resolved ONCE at INIT (see §6 B-P3): if
   `staged-gen/current-gen` is absent the cut refuses pre-PREFLIGHT (no source
   generation — operator must let the package op finish / run `seed-runtime`).
   The copy is from a dir dpkg is NOT touching, so it is internally a single
   generation by construction. `copyTreeChecksum` stays as the intra-copy
   integrity check; no new before/after manifest gate is needed.
   **Same-version destination identity (Codex r2-#2 — required):** today
   `copyStaged` keys the destination by `TargetVersion` and SKIPS an existing
   `versions/<ver>` (`cutover.go:512`). A same-version reinstall publishes a NEW
   genid but the cut would skip the copy (dir exists) — never picking up the new
   bytes — or, worse, reuse a stale/pre-fix torn `versions/<ver>`. Fix: stamp the
   source genid into `versions/<ver>` (a `.srcgen` dotfile written atomically
   with the version dir) and make the copy-skip "skip ONLY if the existing
   `versions/<ver>` carries the SAME genid"; a different genid for the same
   version forces a fresh recopy (into `versions/<ver>.partial` → rename). This
   keeps the `versions/<ver>` key (the unit drop-in + rollback machinery depend
   on it) while making the skip generation-aware.
4. **`pkg/upgrade/runtime/seed.go` (first install)** publishes the first
   `staged-gen/<genid>/` (+ `current-gen`) from the seeded set, so a first
   manual `xpfd upgrade` has a source generation even though the postinst
   first-install path does not run the auto-cut. The publish is idempotent and
   runs on every seed invocation (incl. the already-seeded resume path) — and on
   the seed-FAILURE fallback (direct-staged links) the postinst still publishes a
   `staged-gen/<genid>` from the (complete, just-unpacked) staged tree so a later
   cut is not sourceless (Codex r1-#4, AGY r1-#3). If even the publish fails
   (ENOSPC on a brand-new host with no prior generation), the cut later refuses
   safely (no source) — it never reads torn `staged/`; see B-P7.
5. **GC:** `staged-gen/` GC mirrors the `versions/` GC shape (`flip.go:306`) but
   with a SMALLER retention — **retain the current generation + 1 prior (N=2),
   NOT N=3** (AGY r2-#2). Unlike `versions/` (which backs binary+DB rollback to
   N prior versions), `staged-gen/` is only ever a *cut source*: once superseded
   by a newer `current-gen` an older generation is never read again, so keeping
   3 is pure disk waste. GC protects `current-gen` AND any genid referenced by an
   active/resumable journal (`SourceGeneration` — AGY r2-#3 / Codex r2-#3), and
   sweeps `.partial` orphans. The publish command pre-sweeps stale `.partial`
   dirs BEFORE copying (AGY r2-#1b) so a crashed prior publish cannot accumulate
   half-copies that exhaust `/var`.

**Why B is the robust choice (the r1 reviewer convergence):**
- **No preinst sentinel, no lifecycle coupling.** B writes nothing in preinst
  and nothing on dpkg's error-unwind. A failed/aborted unpack simply never
  publishes a new `staged-gen/<genid>`; the PRIOR generation stays valid and the
  cut keeps reading the last-good source. There is **no permanent-wedge window**
  — the class of failure that sinks A, and that D must actively fight with
  abort-* handlers + self-healing (Codex r1-#1/#2, AGY r1-#1-CRIT, SMR r1-MAJOR1).
- **The cut never reads the path dpkg rewrites.** The torn-read window is closed
  by construction, for ALL FOUR managed binaries, not just the verify-gated
  xpfd+shim.
- **No #1967 regression.** The source-generation presence check is at INIT
  (pre-PREFLIGHT), so a refusal writes no journal and takes no DB snapshot —
  unlike D's `copyStaged`-placed refusal that would strand a `.dbsnap` at
  StatePreflight (Codex r1-#3).
- **Composes cleanly.** #1965 lock unchanged; #1982 manifest unchanged (B does
  not need per-binary checksums for the gate, though it MAY keep a genid stamp);
  #1964 seed/legacy-migration gains one publish step.

**Costs (honest):**
- **Extra disk (AGY r2-#2, corrected for retention=2):** the binary set is
  dominated by `xpfd` (embeds the kernel-verified shim) + `xpf-userspace-dp`;
  budget ~50-70 MB per set. Steady-state copies on disk:
  `staged/` (1) + `staged-gen/` current+1 (2) + `versions/` current+N=3 (4) =
  **~7 copies ≈ 350-490 MB** (AGY's worst case was 9 copies assuming
  `staged-gen` also retained N=3 — r3 cuts `staged-gen` retention to N=2, saving
  two copies). On a 1-2 GB `/var` this is still a real footprint a constrained
  appliance MUST size for. The publish's own free-space check (B-P7) and the
  `staged-gen` GC bound it. **State the concrete budget + the `/var` floor in the
  engineer PR.**
- **One new publish step + one new GC surface.** Both reuse the existing
  `.partial`+rename + atomic-symlink + `versions/` GC machinery — low novelty.
- **Transient 3 copies during a cut:** `staged`, `staged-gen/<genid>`,
  `versions/<ver>.partial`. The PUBLISH (in postinst, not the cut) does its OWN
  free-space check + GC before copying (B-P7); the cut's PREFLIGHT
  (`cutover.go:439`) sizes only the `versions/<ver>` copy from the (already
  on-disk) `staged-gen` source.

**Bootstrap caveat — the FIRST B-aware deploy (Codex r2-#1, honest scope):**
B only protects cuts performed by a **B-aware** `xpfd`. During the very upgrade
that *installs* the first B-aware binary, the operator-visible `xpfd upgrade` is
still the **OLD** (pre-B) binary, which reads live `staged/` (the fix cannot run
before it is installed — the same one-hop bootstrap limitation #1964's
first-install seed already documents). Mitigation is the EXISTING backstops for
that single hop: the #1965 preinst lock gate (fail-loud if an operator cut is
already running) + the verify-dataplane gate against the copied xpfd + the
operator guidance "do not run `xpfd upgrade` during `apt upgrade`." From the
first B-aware version onward the window is closed by construction. This is a
documented, bounded, one-time exposure — NOT a residual hole in B's
steady-state guarantee. State it plainly in `docs/in-place-upgrade.md`.

### Option C — bare SOURCE generation manifest — REJECTED

`staged/.generation` (genid + per-binary sha256) verified before+after copy,
SHIPPED as a dpkg payload file. **FATAL:** dpkg replaces `.generation` in the
same per-file rename storm; a cut wholly inside the unpack window reads the same
**stale-but-valid** genid before AND after, and the stale checksums match the
not-yet-replaced binaries → **false pass** on a torn set. Bare C only catches a
copy that *straddles* a genid change, not one wholly inside one (stale)
generation. Rejected.

### Option D — HYBRID (preinst invalidates → postinst publishes valid manifest → cut verifies) — REJECTED in favor of B; corrected spec retained as the fallback

C's manifest driven by A's lifecycle: preinst writes `staged/.generation =
"unpacking"` (sentinel VALUE, not a presence file); postinst writes a valid
genid+per-binary-sha256 manifest after unpack; `copyStaged` reads it before and
after and refuses on absent/`"unpacking"`/checksum-mismatch.

D is *correct in principle* and dissolves A's permanent-wedge (the sentinel is a
manifest value the next successful postinst overwrites) and C's stale-pass (the
preinst invalidation means a cut inside the window reads `"unpacking"`). But the
r1 review surfaced that **D keeps fighting the maintainer-script lifecycle**, and
making it sound requires ALL of the following — every one a place to get it
wrong:

- **D-fix-1 (ordering):** the `.generation := "unpacking"` write must come AFTER
  the preinst `flock` contended-cut gate (NOT first, as r1-P1 said) — else a
  contended abort strands `"unpacking"` over an intact tree and false-refuses the
  lock-holding operator cut (Codex r1-#1, SMR r1-MAJOR1).
- **D-fix-2 (abort-unwind):** dpkg error-unwind runs `new-postrm abort-upgrade`
  then `old-postinst abort-upgrade` (Debian Policy §6.5/§6.6). The OLD package's
  abort path must rewrite a valid manifest — but on the FIRST deploy of this fix
  the OLD package has no such logic, so D ALSO needs a **self-healing** cut: on
  seeing `"unpacking"` with dpkg NOT currently unpacking, recompute the manifest
  from the (quiesced) staged tree. Detecting "dpkg not unpacking" has no clean
  signal (probing dpkg's frontend lock is itself racy). This is real added
  complexity (AGY r1-#1-CRIT, Codex r1-#2).
- **D-fix-3 (#1967):** the refusal must move out of `copyStaged` (post-PREFLIGHT)
  to INIT, or rewind the journal + sweep the `.dbsnap`, to avoid the stale-snapshot
  regression (Codex r1-#3).
- **D-fix-4 (first-install):** seed must write the manifest incl. the
  seed-failure fallback (Codex r1-#4, AGY r1-#3); `preinst install` must also
  cover the legacy-migration unpack window (AGY r1-#2).
- **D-fix-5 (copyTree):** decide whether `.generation` is copied into
  `versions/<ver>` (copyTree copies all dotfiles today) (Codex r1-#5).

Every one of D-fix-1..5 is a correctness-load-bearing maintainer-script edit. B
needs NONE of them. **D is retained as the documented fallback** if, at engineer
time, B's extra disk copy is judged unaffordable on the appliance `/var`; in
that case implement D with ALL of D-fix-1..5.

## 5. Multiple Path Options — recommendation

| | A (presence sentinel) | **B (immutable versioned staging)** | C (bare manifest) | D (hybrid manifest+lifecycle) |
|---|---|---|---|---|
| Closes unpack-window torn read (all 4 binaries) | partial | **yes, by construction** | no | yes (if D-fix-1..5 all correct) |
| Permanent-wedge risk | **yes** | **no** | no | no (needs abort-* + self-heal) |
| Reads the path dpkg rewrites | n/a | **never** | yes | yes (the marker) |
| Maintainer-script lifecycle coupling | high | **none (postinst publish only)** | low | **high** (preinst+postinst+abort-*) |
| #1967 DB-snapshot/journal regression risk | n/a | **none (check at INIT)** | n/a | yes unless moved to INIT |
| Extra disk | no | **yes (1 copy/gen, GC-bounded)** | no | no |
| New crash-safety surface | low | **low (1 atomic publish + GC)** | low | medium-high |
| Composes w/ #1965/#1967/#1982/#1964 | n/a | **yes** | n/a | yes (with care) |

**Recommendation: Option B (Immutable Versioned Staging).** It closes the
torn-read *by construction* — the cut reads a generation dpkg is not touching —
for all four managed binaries, with **zero preinst state, zero error-unwind
handling, and no permanent-wedge window**. Its only cost is one GC-bounded extra
copy of the binary set per generation, an explicit and well-understood disk
trade an appliance can size for, in exchange for removing the entire
maintainer-script-lifecycle hazard surface that Option D must keep fighting (all
three r1 reviewers independently reached this conclusion). **D is the documented
fallback** (with the corrected D-fix-1..5 spec in §4) if the disk budget is
unacceptable. A and C are rejected for the fatal flaws above.

## 6. Ordering & crash-safety invariants (Option B contract for `/engineer`)

- **B-P1 (publish after a complete unpack, before the auto-cut):** the
  `staged → staged-gen/<genid>` publish runs in `postinst configure` (AFTER
  unpack completes, while dpkg's frontend lock serializes apt transactions),
  BEFORE the standalone auto-cut and the clustered stage-only branch. Place it
  UNCONDITIONALLY within `configure` for `$2` non-empty (so clustered
  stage-only, XPF_NO_POSTINST_CUT, deferred-TOCTOU, and standalone-cut all see a
  fresh generation), and via the seed for `$2` empty (first install).
- **B-P2 (atomic publish + atomic current-gen):**
  `staged-gen/<genid>.partial` → fsync → atomic rename → fsync `staged-gen/`;
  then repoint `current-gen` via **temp-symlink + rename** (`symlink(<genid>,
  current-gen.tmp); rename(current-gen.tmp, current-gen)` — NOT `ln -sf`, which
  unlink-then-creates and leaves a window where `current-gen` is absent; reuse
  the preinst's existing `atomic_symlink` shape — AGY r2-#1a). A crash before the
  dir rename leaves a `.partial` (pre-swept by the next publish, B-P below); a
  crash after the dir rename but before the `current-gen` rename leaves a
  complete-but-unreferenced genid (prior `current-gen` still valid; next publish
  re-publishes idempotently). NEVER a torn published generation, NEVER an absent
  `current-gen`.
- **B-P2b (publish is serialized + best-effort + gated, AGY r2-#1b/#4, Codex
  r2-#5):** the publish command (a) acquires the host-wide upgrade lock
  `/run/xpf/upgrade.lock` so it is mutually exclusive with an operator cut and
  its GC cannot delete a generation a cut is reading; (b) PRE-SWEEPS stale
  `staged-gen/*.partial` BEFORE copying so a crashed prior publish cannot
  accumulate half-copies that exhaust `/var`; (c) is BEST-EFFORT for the postinst
  (a publish failure does NOT `set -e`-abort `configure` — a non-zero postinst
  half-configures dpkg, worse than a deferred cut), but logs LOUDLY and the
  postinst MUST NOT then run the auto-cut (a failed publish ⇒ skip the cut; the
  prior generation stays the cut source). The lock acquire is non-fatal too: if
  the lock is busy (an operator cut is running) the postinst defers the publish +
  drops `/run/xpf/upgrade-deferred` (same shape as the #1965 postinst contention
  branch) — the operator re-runs after the cut completes. **Deferred-publish
  recovery (SMR r3-NIT1):** a deferred publish leaves the NEW binaries staged but
  unpublished, so a bare `xpfd upgrade` re-run would read the OLD `current-gen`
  and no-op ("already committed"). The recovery verb must therefore PUBLISH first:
  either `xpfd upgrade` itself runs the publish when it observes the staged tree
  is newer than `current-gen` / the `upgrade-deferred` marker is set (it already
  holds the lock at that point), OR recovery is documented as `dpkg-reconfigure
  xpf` (re-runs the postinst publish). Pick one at engineer time; do not leave the
  recovery as a bare `xpfd upgrade`.
- **B-P3 (cut resolves the source genid at INIT; copies the dir, not the
  symlink):** `Run()` resolves `staged-gen/current-gen` at INIT (pre-PREFLIGHT)
  and records the resolved genid in a NEW `Journal.SourceGeneration` field
  (Codex r2-#4 — the journal must grow this field). Absent → refuse with no
  journal written and no DB snapshot taken (Codex r1-#3 closed by construction).
  `copyStaged` copies from `staged-gen/<SourceGeneration>/` (the resolved
  directory, never re-reading `current-gen` and never copying THROUGH the
  symlink) so a concurrent publish cannot redirect an in-flight cut. The
  journaled `TargetVersion` is read from that generation's `xpfd`; a resume keys
  the SAME genid.
- **B-P3b (same-version destination identity + SAFE replacement protocol, Codex
  r2-#2 + Codex/AGY r3):** stamp `SourceGeneration` into `versions/<ver>/.srcgen`
  (written atomically inside the version dir, so GC removes it with the dir — NOT
  a sibling dotfile) and change the `copyStaged` skip from "skip if
  `versions/<ver>` exists" to "skip ONLY if it exists AND its `.srcgen` == this
  cut's `SourceGeneration`." The IDENTITY stamp alone is necessary but NOT
  sufficient: a same-version-but-different-genid cut must REPLACE an existing
  `versions/<ver>`, and that dir may be the LIVE `current` target and/or the
  rollback target, and `rename(.partial, versions/<ver>)` fails `ENOTEMPTY` over
  a non-empty dir while a destructive RemoveAll+recopy during the pure COPY phase
  would (a) violate the #1967 "never mutate a live version dir mid-cut" invariant
  and (b) race the running daemon's helper-spawn path (`dir(os.Args[0])` pins to
  `versions/<ver>/xpfd`, `flip.go:30`). Two sound resolutions — **pick at
  engineer time:**
  - **B-P3b-OPT1 (minimal — refuse-or-guarded-replace):** if the existing
    `versions/<ver>` is the live `current` OR the rollback (`PreviousVersion`)
    target, REFUSE the same-version-different-genid cut pre-PREFLIGHT with a clear
    error ("re-stage under a distinct version; cannot safely replace a live/
    rollback version dir"). Otherwise (a stale, non-live `versions/<ver>` — e.g.
    a pre-fix torn copy or an abandoned older attempt) it is safe to RemoveAll +
    recopy, reusing EXACTLY the existing guarded-delete logic in
    `cleanupFailedVerifyCopy` (`cutover.go:605`), which already proves a version
    dir is neither `current` nor previous before deleting it. This adds no new
    layout and preserves every existing invariant; the refused case is the
    pathological dev/re-stage one.
  - **B-P3b-OPT2 (clean structural — generation-keyed dir, AGY r3):** key the
    destination by `versions/<ver>-<genid>/`. The `.partial`→rename then always
    targets a fresh non-existent path (atomic, no `ENOTEMPTY`, the live/rollback
    dir is never touched during COPY); `current` + the unit-drop-in ExecStart +
    rollback keying resolve to `<ver>-<genid>` at FLIP (daemon already stopped).
    Stronger but ripples into the `current` symlink, the drop-in path, rollback
    keying, and GC (all version-keyed today) — a larger, but fully sound, change.

  **Recommendation: OPT1** (minimal, reuses the proven guarded-delete, refuses
  only the pathological same-version-different-bytes case) unless `/engineer`
  finds same-version-different-genid is a routine production path, in which case
  OPT2's gen-keyed layout is the clean answer. Either fully closes the hole; the
  plan does not leave it as an unsafe blind rename.
- **B-P4 (durable, ONE Go implementation):** publish + `current-gen` + `.srcgen`
  writes are `fsatomic` DurableState (survive power loss). The shell postinst
  delegates the publish to the staged Go binary (a dedicated `xpfd
  publish-generation` verb is cleanest; or fold into `seed-runtime`) so there is
  ONE durable-copy implementation, unit-tested, not hand-rolled shell — mirrors
  the #1964 seed split (durable logic in Go, postinst just invokes it).
- **B-P5 (genid identity):** `<genid>` = monotonic (nanosecond time) + random
  suffix so a same-version reinstall yields a distinct generation and GC mtime
  ordering is stable (AGY r1-#4).
- **B-P6 (staged-gen NOT a dpkg payload file; purge + downgrade cleanup):**
  `staged-gen/` is maintainer-script-managed runtime state under `/var/lib/xpf/`
  (NOT under the dpkg-owned `staged/`), like `versions/`. dpkg never writes or
  removes it on unpack (it only touches its own recorded payload files; a
  never-recorded runtime dir is immune to unpack-replace AND to the "files
  removed from the new package" cleanup — corroborated by the postrm's own
  documented "presence-only file marker" trap, `debian/xpf.postrm:36-42`). The
  postrm MUST (AGY r2-#5): (a) on `purge`, `rm -rf staged-gen/` alongside
  `$VERSIONS` (else an orphan dir survives purge — a Policy violation); (b) on a
  DOWNGRADE to a pre-B package (incoming `$2` predates the B floor — reuse the
  #1985 `dpkg --compare-versions` version-keyed detection already in the postrm),
  `rm -rf staged-gen/` so the obsolete dir does not leak permanently (the old
  postrm never learns about it).
- **B-P7 (publish does its OWN free-space check; ENOSPC fail-safe):** the
  publish command (NOT the cut's PREFLIGHT) checks free `/var` against the set
  size + margin and runs its `staged-gen` GC BEFORE copying. On ENOSPC: on an
  UPGRADE the prior `staged-gen/<g>` stays valid (cut keeps reading it — but see
  the SMR no-silent-stale note: the postinst must surface "no new generation
  published" loudly so the operator does not believe a same-version no-op cut was
  the upgrade); on a FIRST install with no prior generation the publish simply
  fails and a later cut refuses safely (no source) — it NEVER reads torn
  `staged/`. The cut's existing PREFLIGHT (`cutover.go:439`) sizes only the
  `versions/<ver>.partial` copy from the on-disk `staged-gen` source.

## 7. Test strategy

1. **Torn-source regression (the §2 acceptance pin), counter-factual:**
   - **B path:** publish `staged-gen/<g1>` from a clean set, then mutate live
     `staged/` to a torn mix, then drive a cut — assert it reads `<g1>` (clean)
     and the torn `staged/` is NEVER read (the cut output equals the published
     generation, not the torn live tree).
   - **Counter-factual:** point the PRE-FIX `copyStaged` at live `staged/` with
     the torn mix and show it publishes a torn `versions/<ver>` that the
     self-checksum passes — recreating the failure mode (engineering-style "Test
     strength").
2. **No-source refusal:** `staged-gen/current-gen` absent → cut refuses at INIT,
   NO journal written, NO `.dbsnap` taken, daemon untouched (pins Codex r1-#3).
3. **Publish atomicity / crash-resume:** kill between `.partial` and rename
   (orphan swept); kill between rename and `current-gen` (prior gen still valid,
   re-publish idempotent); assert no torn published generation ever observable.
4. **abort-unwind:** simulate a failed unpack (postinst does not publish) →
   assert the PRIOR `staged-gen/<g0>` stays valid and a cut from it succeeds (the
   permanent-wedge class is structurally absent — this is the test that would
   FAIL under Options A/D-without-fixes).
5. **First-install + seed-failure fallback:** seed publishes `<genid>`; a manual
   cut from a first-install host succeeds; the seed-failure (direct-staged)
   fallback still publishes a generation so a later cut is not sourceless.
6. **GC:** `staged-gen/` retains current+1 (N=2), protects `current-gen` AND any
   genid referenced by an active/resumable journal (`SourceGeneration`), sweeps
   `.partial` + abandoned genids; reuses the `versions/` GC test shape.
7. **GC-vs-resume race (AGY r2-#3 / Codex r2-#3):** journal a cut at
   `StateCopied` with genid `g0`; publish a newer generation that would GC `g0`;
   assert GC PROTECTS `g0` (journal-referenced) so the resume copy still finds
   its source.
8. **Same-version reinstall (Codex r2-#2):** publish `g1` for version V, cut to
   `versions/V` (stamps `.srcgen=g1`); publish `g2` (still version V, new bytes);
   assert the next cut RE-COPIES (`.srcgen` differs) instead of skipping the
   stale `versions/V`. Counter-factual: with the version-only skip, the cut
   wrongly skips and ships stale bytes.
9. **Publish lock + best-effort (B-P2b):** publish defers (drops the
   `upgrade-deferred` marker, does NOT cut) when the upgrade lock is busy; a
   publish copy failure does NOT fail `configure` and does NOT run the auto-cut.
10. **Clustered stage-only:** a clustered-node postinst publishes a generation
    (no cut) and a later `xpfd upgrade --rolling` cuts from it.
11. **postrm purge + downgrade (B-P6):** `purge` removes `staged-gen/`; a
    downgrade to a pre-B `$2` removes `staged-gen/` (version-keyed detection),
    leaving no leak.

**Deploy validation (engineering-style §8):** packaging/cut-path change, no
dataplane code. Lane: the `.deb` dogfood in `cluster-setup.sh`. Assert clean
build→install→standalone-cut on the standalone VM; `cluster-deploy` (stage-only)
+ `xpfd upgrade --rolling` cuts both nodes; `make test-failover` still passes
(the cut path feeds the rolling driver's inner `Run`). No CoS/failover
regression expected.

## 8. Alternatives rejected (summary)

- **A (presence sentinel):** permanent-wedge on aborted unpack. Rejected.
- **C (payload-shipped manifest):** stale-manifest false-pass inside the unpack
  window. Rejected.
- **D (hybrid):** correct but requires D-fix-1..5 (preinst ordering, abort-*
  unwind handling + self-heal, #1967 INIT-move, first-install/seed, copyTree
  decision) — a high maintainer-script-lifecycle hazard surface that B removes
  entirely. Retained as the documented fallback if B's disk cost is
  unaffordable.
- **Do nothing / keep the caveat:** verify gate is a PARTIAL backstop (xpfd+shim
  only); a torn xpfd(new)+xpf-userspace-dp(old) lockstep pair whose xpfd
  verify-passes flips a mismatched dataplane live. HIGH, real exposure. PLAN-KILL
  only justified if reviewers judge the operator caveat acceptable AND the
  four-binary gap negligible — this plan argues it is not.

## 9. Sequencing / dependencies

- Builds on #1982 (manifest SSOT): `manifest.Names()` enumerates the set to
  publish; no per-binary checksum manifest needed for B's gate (the published dir
  IS the integrity boundary). If a genid stamp is wanted, the constant lives in
  the manifest package + drift canary.
- No conflict with #1983/#1984/#1985 (merged). Independent of the #1930 kernel
  channel.

## 10. Open questions for the user / architecture review

- **O1 (PRIMARY — B vs D):** recommend **B** (ratified by all three reviewers).
  Confirm the appliance `/var` can budget steady-state ~7 copies of the binary
  set (≈350-490 MB at ~50-70 MB/set: staged + staged-gen current+1 + versions
  current+N=3). If `/var` cannot, fall back to **D** with the full D-fix-1..5
  spec in §4. This is the one decision that flips the mechanism.
- **O2 (genid representation):** time+random suffix (B-P5). Confirm or pick.
- **O3 (publish entry point):** new `xpfd publish-generation` subcommand vs
  folding the publish into `seed-runtime`. A dedicated verb is cleaner for the
  upgrade postinst path. Decide at engineer time.
- **O4 (first-deploy bootstrap caveat):** acknowledge that the FIRST B-aware
  upgrade is still cut by the OLD binary reading live `staged/` (Codex r2-#1) —
  a bounded one-time exposure covered by the existing #1965 lock + verify gate +
  operator guidance, closed by construction from the first B-aware version on.
  Confirm this caveat is acceptable (it is intrinsic — the fix cannot run before
  it is installed).

## 11. r1 → r2 changelog (how each r1 finding was folded)

- **Codex r1-#1 / SMR r1-MAJOR1 (P1 ordering):** mooted by B (no preinst write).
  Captured as D-fix-1 for the fallback.
- **Codex r1-#2 / AGY r1-#1-CRIT (abort-unwind wedge):** mooted by B (no
  error-unwind handling; aborted unpack leaves the prior generation valid).
  Captured as D-fix-2 for the fallback.
- **Codex r1-#3 (#1967 stale snapshot on post-PREFLIGHT refusal):** B resolves
  the source at INIT (B-P3) so a no-source refusal writes no journal / takes no
  snapshot. Captured as D-fix-3 for the fallback.
- **Codex r1-#4 / AGY r1-#3 / SMR r1-MAJOR2.2 (seed manifest + fallback):** B's
  seed publishes a generation incl. the seed-failure fallback (§4.B.4, B-P1).
- **AGY r1-#2 (first-install / preinst install window):** B has no preinst write,
  and the cut reads only published generations, so a partially-unpacked live
  `staged/` during a first install/legacy migration is never a cut source.
- **Codex r1-#5 (`.generation` copied into version dirs):** mooted by B (no
  `.generation` marker). For D-fallback, D-fix-5 decides it.
- **Codex r1-#6 / AGY r1-#4 / SMR r1-MINOR2 (B's rejection not earned):** ACTED
  ON — recommendation flipped to B; genid monotonicity folded as B-P5.
- **SMR r1-MINOR1 (genid decorative):** B drops the per-binary manifest gate
  entirely; genid is only a generation key + GC stamp.

## 12. r2 → r3 changelog (mechanism B ratified; spec tightened)

All three r2 reviewers accepted Option B as the right mechanism (Codex
verbatim: "I still think B is the right direction over D"). r3 folds the eight
convergent r2 spec-findings — none changes the mechanism:

- **Codex r2-#1 (first-deploy bootstrap):** §4.B "Bootstrap caveat" + O4 — the
  first B-aware upgrade is still old-binary-cut against live `staged/`; bounded,
  one-time, covered by existing backstops, closed by construction thereafter.
- **Codex r2-#2 (same-version destination identity):** B-P3b — `.srcgen` stamp +
  genid-aware copy-skip; test §7.8.
- **Codex r2-#3 / AGY r2-#3 (GC-vs-resume race):** B-P3 adds
  `Journal.SourceGeneration`; B-P3/§4.B.5 GC protects journal-referenced genids;
  test §7.7.
- **Codex r2-#4 (journal must grow a field):** B-P3 — new
  `Journal.SourceGeneration`.
- **Codex r2-#5 / AGY r2-#2 (disk honesty + publish free-space):** §4.B costs
  corrected to ~7 copies; staged-gen retention cut to N=2; B-P7 gives the publish
  its OWN free-space check + GC; ENOSPC fail-safe spelled out.
- **AGY r2-#1a (non-atomic current-gen symlink):** B-P2 — temp-symlink+rename.
- **AGY r2-#1b (partial leak):** B-P2b — pre-sweep `.partial` before copy.
- **AGY r2-#4 / SMR r2-MINOR1 (publish/cut concurrency):** B-P2b — publish takes
  the upgrade lock; defers (drops `upgrade-deferred`) when busy; test §7.9.
- **AGY r2-#5 (postrm purge + downgrade leak):** B-P6 — purge `rm -rf
  staged-gen/`; version-keyed downgrade cleanup; test §7.11.
- **SMR r2-MINOR2 (no silent stale cut on publish failure):** B-P2b + B-P7 —
  publish failure logs loudly + skips the auto-cut; the "no new generation
  published" condition is surfaced so an operator never mistakes a same-version
  no-op for the upgrade.

## 13. r3 → r4 changelog (single remaining hole closed)

Codex r3 and AGY r3 INDEPENDENTLY converged on ONE remaining correctness hole
(both accepted every other r3 item as resolved at plan level; both explicitly
called it "not new scope"):

- **Codex r3 / AGY r3 (same-version `versions/<ver>` replacement protocol):**
  r3's B-P3b `.srcgen` identity stamp detects a same-version-different-genid cut
  but did not define HOW the existing `versions/<ver>` is safely replaced. A
  blind `.partial`→rename fails `ENOTEMPTY`; a destructive RemoveAll+recopy
  during the pure COPY phase would mutate the live `current`/rollback dir and
  race the running daemon's helper-spawn (`dir(os.Args[0])`), violating #1967.
  r4 B-P3b adds the SAFE replacement protocol with two sound resolutions —
  **OPT1** (refuse a same-version-different-genid cut when the dir is
  live/rollback; otherwise reuse the proven guarded-delete in
  `cleanupFailedVerifyCopy`; recommended, minimal) / **OPT2** (generation-keyed
  `versions/<ver>-<genid>` dir so the rename always targets a fresh path; clean
  structural fix, larger surface). Either fully closes the hole.
- **SMR r3-NIT1 / AGY r3-NIT (deferred-publish recovery verb):** folded into
  B-P2b (the recovery must PUBLISH-then-cut, not bare `xpfd upgrade`; pick `xpfd
  upgrade`-auto-publishes vs `dpkg-reconfigure xpf` at engineer time).
