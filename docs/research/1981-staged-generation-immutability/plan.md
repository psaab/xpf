# Plan of action — #1981: close the dpkg-unpack vs operator-cut staged-source race

- **Issue:** #1981 (HIGH, correctness / upgrade integrity)
- **Mode:** `/research` — converge a plan + recommend a mechanism; STOP at PLAN-READY. No code, no PR.
- **Revision:** r2 (r1 → r2: recommendation FLIPPED from Option D to **Option B**
  after all three reviewers independently argued D keeps fighting the dpkg
  maintainer-script lifecycle while B sidesteps the entire wedge class. r1
  findings folded throughout — see §11.)
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
3. **`copyStaged` (`pkg/upgrade/cutover.go`)** copies from
   `staged-gen/<current-gen>/`, **NEVER from live `staged/`**. The
   source-generation is resolved ONCE at INIT (see §6 ordering): if
   `staged-gen/current-gen` is absent the cut refuses pre-PREFLIGHT (no source
   generation yet — operator must let the package op finish / run
   `seed-runtime`). The copy is from a dir dpkg is NOT touching, so it is
   internally a single generation by construction. `copyTreeChecksum` stays as
   the intra-copy integrity check; no new before/after manifest gate is needed.
4. **`pkg/upgrade/runtime/seed.go` (first install)** publishes the first
   `staged-gen/<genid>/` (+ `current-gen`) from the seeded set, so a first
   manual `xpfd upgrade` has a source generation even though the postinst
   first-install path does not run the auto-cut. The publish is idempotent and
   runs on every seed invocation (incl. the already-seeded resume path) — and on
   the seed-FAILURE fallback (direct-staged links) the postinst still publishes a
   `staged-gen/<genid>` from the (complete, just-unpacked) staged tree so a later
   cut is not sourceless (Codex r1-#4, AGY r1-#3).
5. **GC:** `staged-gen/` GC mirrors the `versions/` GC (`flip.go:306`): retain
   N=3 newest, protect `current-gen`, sweep `.partial` orphans + abandoned
   genids. One extra retained copy of the binary set per generation, bounded by
   N=3 + the protected current.

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
- **Extra disk:** one published copy of the binary set per retained generation.
  The set is dominated by `xpfd` (embeds the kernel-verified shim) +
  `xpf-userspace-dp`; budget ~50-70 MB per generation, ×(N=3 + current) worst
  case under `/var`. A constrained appliance must size `/var` for it; the
  PREFLIGHT free-space check (`preflight`, `cutover.go:439`) and the
  `staged-gen` GC bound it. **State the concrete budget in the engineer PR.**
- **One new publish step + one new GC surface.** Both reuse existing
  `.partial`+rename + the `versions/` GC shape — low novelty.
- **Transient 3 copies during a cut:** `staged`, `staged-gen/<genid>`,
  `versions/<ver>.partial`. PREFLIGHT must account for `staged-gen` in its
  free-space need (it already sums `staged` + dbsnap + margin; add the publish).

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

- **B-P1 (publish after a complete unpack):** the `staged → staged-gen/<genid>`
  publish runs in `postinst configure` (AFTER unpack completes, while dpkg's
  frontend lock serializes transactions), BEFORE the standalone auto-cut and the
  clustered stage-only branch. Place it UNCONDITIONALLY within `configure` for
  `$2` non-empty (so clustered stage-only, XPF_NO_POSTINST_CUT, deferred-TOCTOU,
  and standalone-cut all see a fresh generation), and via the seed for `$2`
  empty (first install).
- **B-P2 (atomic publish):** `staged-gen/<genid>.partial` → fsync → atomic
  rename → fsync `staged-gen/`; then atomically repoint `staged-gen/current-gen
  -> <genid>`. A crash before the rename leaves a `.partial` (GC-swept); a crash
  after the rename but before `current-gen` leaves a complete-but-unreferenced
  genid (the prior `current-gen` is still valid; the next postinst re-publishes
  idempotently). NEVER a torn published generation.
- **B-P3 (cut reads current-gen, resolved at INIT):** `Run()` resolves the
  source generation from `staged-gen/current-gen` at INIT (pre-PREFLIGHT). Absent
  → refuse with no journal written and no DB snapshot taken (Codex r1-#3 closed
  by construction). The journaled `TargetVersion` is read from the published
  generation's `xpfd`, and the genid is recorded in the journal so a resume keys
  the SAME generation.
- **B-P4 (durable):** publish + `current-gen` writes are `fsatomic` DurableState
  (survive power loss). The shell postinst delegates the publish to the staged Go
  binary (`xpfd publish-generation` / fold into `seed-runtime`) so there is ONE
  durable-copy implementation, unit-tested, not hand-rolled shell — mirrors the
  #1964 seed split (durable logic in Go, postinst just invokes it).
- **B-P5 (genid identity):** `<genid>` = monotonic (nanosecond time) + random
  suffix so a same-version reinstall yields a distinct generation and GC mtime
  ordering is stable (AGY r1-#4).
- **B-P6 (staged-gen is NOT a dpkg payload file):** `staged-gen/` is
  maintainer-script-managed runtime state under `/var/lib/xpf/` (NOT under the
  dpkg-owned `staged/`), like `versions/`. dpkg never writes or removes it on
  unpack; the postrm removes it on `purge` (mirror the `versions/` purge handling
  in `debian/xpf.postrm`). Confirmed against dpkg semantics: dpkg only touches
  its own recorded payload files; a never-recorded runtime dir is immune to
  unpack-replace AND to the "files removed from the new package" cleanup
  (independently corroborated by the postrm's own documented "presence-only file
  marker" trap, `debian/xpf.postrm:36-42`).
- **B-P7 (PREFLIGHT free-space):** PREFLIGHT must include the `staged-gen`
  publish in its free-space need (it already sums staged + dbsnap + margin); the
  publish happens in postinst (not in the cut), so the cut's PREFLIGHT only sizes
  the `versions/<ver>` copy — but the postinst publish itself should fail loudly
  (not silently) on ENOSPC and leave the prior generation valid.

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
6. **GC:** `staged-gen/` retains N=3, protects `current-gen`, sweeps `.partial`
   and abandoned genids; mirrors and reuses the `versions/` GC test shape.
7. **Clustered stage-only:** a clustered-node postinst publishes a generation
   (no cut) and a later `xpfd upgrade --rolling` cuts from it.

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

- **O1 (PRIMARY — B vs D):** recommend **B**. Confirm the appliance `/var` can
  budget one GC-bounded extra copy of the binary set per retained generation
  (~50-70 MB × up to N=3+current). If NOT, fall back to **D** with the full
  D-fix-1..5 spec in §4. This is the one decision that flips the mechanism.
- **O2 (genid representation):** time+random suffix (B-P5). Confirm or pick.
- **O3 (publish entry point):** new `xpfd publish-generation` subcommand vs
  folding the publish into `seed-runtime`. Either is fine; a dedicated verb is
  cleaner for the upgrade postinst path. Decide at engineer time.

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
