# Plan of action — #1981: close the dpkg-unpack vs operator-cut staged-source race

- **Issue:** #1981 (HIGH, correctness / upgrade integrity)
- **Mode:** `/research` — converge a plan + recommend a mechanism; STOP at PLAN-READY. No code, no PR.
- **Revision:** r1
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
  against their own freshly-generated sum** — it proves the copy is internally
  intact, NOT that all managed binaries came from the **same dpkg unpack
  generation**.
- The kernel `verify-dataplane` gate (`cutover.go:551-573`) validates only the
  copied `xpfd` + embedded shim. It is a **partial** backstop: it never
  establishes that `cli`, `xpf-userspace-dp`, `xpf-day0-config` came from the
  same generation. A torn set whose `xpfd` happens to verify-pass (e.g. the new
  `xpfd` paired with an old `xpf-userspace-dp` that is ABI-incompatible) sails
  through and flips a mismatched dataplane live.

Prior hardening narrowed but did not close this:
- #1965 host-wide lock — serializes *operator* cuts against each other and the
  postinst cut, but cannot cover the unpack interval (preinst fd dies).
- #1967/#1974 cut-over robustness — crash-safety + verify-fail cleanup, not
  source-generation consistency.
- #1982 manifest SSOT — gives a single managed-binary list; composes with this
  fix but does not itself prove generation consistency.

`docs/in-place-upgrade.md:385-395` names this the **"dpkg-vs-operator
staged-source race"** as an accepted caveat with no tracking issue to close it.
#1981 IS that tracking issue.

## 2. Goal / acceptance criteria

- An operator `xpfd upgrade` (and the postinst auto-cut, and `--rolling`) MUST
  NOT publish a `versions/<ver>` that mixes binaries from two dpkg unpack
  generations. The cut either copies a **whole, single-generation** staged
  tree, or it **fails loudly before any live mutation** (pure pre-STOP failure,
  daemon untouched).
- Crash-safe at **every** maintainer-script + cut step (kill at any line leaves
  a consistent, resumable state; never a permanently-wedged "can't ever cut"
  host and never a daemon-down-with-no-rollback host).
- Compose with the #1965 lock, the #1967 deferred-cut, the #1982 manifest, and
  the #1964 first-install seed / legacy-migration — do not regress any of them.
- A regression test that **mutates one managed staged binary mid-`copyStaged`**
  (simulating a half-unpack) MUST fail the cut **before** the fix's mechanism
  passes, and the **pre-fix** code path (self-generated target checksum only)
  must be shown to NOT catch it (counter-factual pin per engineering-style
  "Test strength").

## 3. Blast radius (files this design touches)

| File | Role | Expected change class |
|---|---|---|
| `debian/xpf.preinst` | runs BEFORE unpack | invalidate the source-generation marker to a sentinel value |
| `debian/xpf.postinst` | runs AFTER unpack, drives the auto-cut | write the VALID generation manifest **before** the auto-cut reads staged |
| `pkg/upgrade/cutover.go` (`copyStaged`) | the cut copy step | verify the source-generation marker BEFORE and AFTER copy |
| `pkg/upgrade/manifest/` | SSOT | a marker-name constant + (maybe) a manifest writer/reader helper shared by Go + shell-parity canary |
| `pkg/upgrade/runtime/seed.go` | first-install seed | write a valid generation manifest for the seeded set (so a first cut composes) |
| `docs/in-place-upgrade.md` | operator/design doc | replace the "accepted caveat" §385-395 with the closed-race contract |
| tests | `pkg/upgrade/*_test.go`, manifest drift canary | the mid-copy mutation regression + shell-parity for the new marker |

No hot-path (packet/poll) code. No protocol-field/BPF-map change. This is a
packaging + cut-path correctness fix.

## 4. The design space — THREE candidate mechanisms

All three must defeat the same adversary: **a `copyStaged` that runs entirely
inside dpkg's unpack window, reading a torn set.** The decisive question for
each is *who writes the integrity signal, and is that write atomic relative to
dpkg's per-file `rename()` storm.*

### Option A — Unpack+configure SENTINEL (a marker held for the whole unpack)

A marker that exists for the WHOLE dpkg unpack+configure interval and makes
operator `xpfd upgrade` FAIL before reading staged.

- **Mechanics that would work:** preinst (before unpack) drops a sentinel;
  postinst (after unpack+configure) removes it; `copyStaged` refuses while the
  sentinel is present.
- **FATAL flaw — the preinst fd cannot span the unpack boundary.** This is the
  *exact* existing hole. A `flock`-style fd-held sentinel dies at preinst exit.
  A *file* sentinel dropped by preinst and removed by postinst DOES span the
  interval — but only if it is crash-safe AND cannot be left dangling. Two
  sub-failures:
  - If the package operation **aborts mid-unpack** (disk full, SIGKILL of
    dpkg), the new postinst never runs, so the sentinel is **never removed** →
    the host is **permanently wedged**: every future `xpfd upgrade` refuses
    forever. (apt's `abort-upgrade`/error-unwind runs the OLD scripts, which do
    not know about the new sentinel.)
  - A bare presence-sentinel cannot distinguish "unpack in progress NOW" from
    "a crashed unpack last week." It has no generation identity, so it cannot
    *self-clear* on a fresh, complete generation.
- **Verdict:** REJECT as a standalone mechanism. A pure presence-sentinel trades
  the torn-set risk for a permanent-wedge risk — strictly worse for an
  appliance. Its only sound form is "a sentinel *value* that is overwritten by a
  valid generation manifest after unpack" — which is Option D below.

### Option B — Immutable VERSIONED staging (unpack into a per-version immutable dir)

Unpack into a versioned immutable staging dir and atomically publish a complete
generation manifest only after ALL managed files are present.

- **Mechanics:** dpkg still writes `staged/` (it must — that is the
  dpkg-owned path in `debian/rules`). After unpack, the postinst atomically
  *publishes* a snapshot of `staged/` into an immutable, generation-keyed
  source dir (e.g. `staged-gen/<genid>/`) via `.partial` + rename. `copyStaged`
  copies from the **published immutable generation**, never from the live
  `staged/`.
- **Strengths:** the cut never reads the path dpkg is actively rewriting. The
  published dir is immutable once renamed (a later unpack publishes a NEW genid
  dir; the old one is untouched). Composes cleanly with versions/ GC.
- **Costs / open questions:**
  - **A second full copy of the binary set** on every package install (staged →
    staged-gen/<genid>), THEN the cut copies again (staged-gen → versions/<ver>).
    Three copies of ~the binary set on disk transiently (staged, staged-gen,
    versions/<ver>). Disk cost on a constrained appliance.
  - **Crash mid-publish:** a `.partial` + rename makes the publish atomic, but
    the postinst must be idempotent and GC abandoned `staged-gen/*.partial`.
  - **Who publishes, and when, relative to the postinst auto-cut?** The publish
    MUST complete before the standalone postinst auto-cut reads it — same
    ordering constraint as Option D, plus the extra copy.
  - **It does not by itself prove the published snapshot is a single
    generation** — if the postinst publishes *while a second apt transaction is
    mid-unpack* (pathological, but apt's dpkg lock normally serializes
    transactions), the snapshot could still be torn. So B still needs a
    generation-identity check; it just relocates WHERE the cut reads from.
- **Verdict:** the *most robust* read-isolation, but the extra full copy + the
  GC of a second versioned tree is real complexity and disk cost for a
  marginal gain over D (which already makes the cut refuse a torn read). Keep
  as the fallback if D's atomicity cannot be made sound.

### Option C — SOURCE generation manifest (verify a genid before AND after copy)

A stable generation-id / checksummed SOURCE manifest that `copyStaged` verifies
BEFORE and AFTER copying.

- **Mechanics (bare C):** maintain `staged/.generation` (a genid +
  per-binary-checksum manifest). `copyStaged` reads the genid before the copy
  and again after, and the per-binary checksums against the copied bytes; a
  mismatch (either the genid changed under it, or a binary's checksum differs
  from the manifest) aborts the cut pre-STOP.
- **FATAL flaw of BARE C (the #1981 prior-research AGY finding, ratified
  here):** *who writes `staged/.generation` atomically relative to dpkg's file
  replacement?* If the manifest is shipped as a dpkg file in the payload, dpkg
  replaces it at some point in the SAME per-file `rename()` storm. A cut whose
  copy lands **entirely within unpack, BEFORE dpkg has replaced `.generation`**,
  reads the same stale genid before AND after, and the **stale manifest's
  checksums match whichever binaries dpkg has not yet replaced** — but the cut
  has no way to know which binaries dpkg already replaced. The before==after
  genid check passes on a torn set. Bare C does not close the window; it only
  catches a copy that *straddles* a genid change, not one wholly inside a single
  (stale) generation's window.
- **The fix that rescues C → Option D.** The manifest must be invalidated by the
  preinst (before unpack) to a sentinel value and rewritten as VALID by the
  postinst (after unpack) — NOT shipped as a dpkg-replaced payload file. Then a
  cut inside the unpack window reads the **sentinel** (not a stale-but-valid
  genid) and refuses.
- **Verdict:** bare C is unsound. Its correct form is Option D.

### Option D — HYBRID (preinst invalidates → postinst publishes a valid manifest → cut verifies) — RECOMMENDED

This is C's manifest **driven by A's lifecycle**, with the sentinel being a
*manifest value* (not a separate presence file), which dissolves both A's
permanent-wedge failure and C's stale-manifest failure.

**Mechanism:**

1. **`debian/xpf.preinst` (BEFORE unpack):** write `staged/.generation` =
   `"unpacking"` (an invalid-by-construction sentinel value, durably:
   write-temp+fsync+rename, then fsync the staged dir). This marks the staged
   tree as MID-REPLACE for the entire unpack interval.
2. **dpkg unpacks** the managed binaries (per-file rename storm). `.generation`
   is NOT a dpkg payload file — it is maintainer-script-managed runtime state
   (like `versions/`), so dpkg never touches it during unpack. It stays
   `"unpacking"` for the whole interval.
3. **`debian/xpf.postinst` (AFTER unpack, BEFORE the auto-cut — ORDERING IS
   LOAD-BEARING):** compute a fresh genid + per-managed-binary sha256 over the
   now-complete staged tree and write a VALID `staged/.generation` manifest
   (durably). This MUST happen before the postinst's own standalone auto-cut
   (`postinst:140-185`) invokes `xpfd upgrade`, or the auto-cut would read
   `"unpacking"` and the **first standalone in-place deploy would be
   permanently deferred** (the Codex finding folded in the prior research).
4. **`copyStaged` (`pkg/upgrade/cutover.go`):**
   - read `staged/.generation` BEFORE copy; if absent or `== "unpacking"`,
     **refuse the cut pre-STOP** (a half-unpack is in progress — the correct
     fail-safe is to wedge THIS cut, not the host: the package operation will
     finish and rewrite a valid manifest, after which a re-run proceeds).
   - copy `staged/` → `.partial`, computing per-file sha256.
   - read `staged/.generation` AGAIN after copy; if it changed (a new unpack
     started under us) OR is now `"unpacking"`, refuse.
   - verify each managed binary's copied-bytes sha256 equals the manifest's
     entry; any mismatch refuses. (This is the generation-consistency proof the
     self-checksum lacks.)
5. **`pkg/upgrade/runtime/seed.go` (first install):** after seeding
   `versions/<v>/`, write a valid `staged/.generation` for the freshly-staged
   set so a subsequent operator cut from a first-install host composes (the
   postinst seed path does not run the upgrade auto-cut, but a later manual
   `xpfd upgrade` from staged must see a valid manifest).

**Why D dissolves A's permanent-wedge and C's stale-manifest:**
- vs A: the sentinel is a *value of a manifest that is always overwritten by the
  next successful postinst*, so a fresh complete generation self-clears it. A
  crashed unpack leaves `"unpacking"`, which wedges only the CUT (correct: there
  is genuinely no consistent source) until the operator re-runs/repairs the
  package op — not the host forever. **Recovery is `apt install --reinstall xpf`
  (re-runs postinst → valid manifest) or `xpfd seed-runtime` if the staged tree
  is itself intact** — must be documented.
- vs C: the manifest is preinst-invalidated, so a cut inside the unpack window
  reads `"unpacking"` (refuses) instead of a stale-but-valid genid (false pass).

**Crash matrix (the kill-at-every-step proof the plan must carry):**

| Kill point | `.generation` state | Cut behavior | Host state |
|---|---|---|---|
| before preinst write | absent (or prior valid) | absent→refuse; prior-valid→**see note** | daemon up |
| preinst wrote `"unpacking"`, dpkg crash mid-unpack | `"unpacking"` | refuse (torn source) | daemon up; recover via reinstall |
| unpack done, postinst crash BEFORE manifest write | `"unpacking"` | refuse | daemon up; recover via reinstall |
| postinst wrote valid manifest, crash before auto-cut | valid | proceeds (complete generation) | daemon up; operator runs `xpfd upgrade` |
| mid-copyStaged, concurrent new unpack flips to `"unpacking"` | `"unpacking"` on after-read | refuse (after-check) | daemon up |

**NOTE (open sub-question O1 — see §10):** the "prior valid manifest" row. If a
NEW package op begins, the preinst's FIRST action is to overwrite `.generation`
with `"unpacking"`. If the preinst is killed BEFORE that write, the manifest
still holds the PREVIOUS generation's valid genid+checksums — which match the
OLD on-disk binaries (dpkg has not unpacked yet). A cut here copies a consistent
OLD generation and passes. That is **correct** (the old set is internally
consistent), so this is safe — but the plan asserts it explicitly so a reviewer
can confirm the preinst write is the FIRST mutating action (ordering invariant
P1 below).

## 5. Multiple Path Options — explicit recommendation

| | A (bare sentinel) | B (immutable versioned staging) | C (bare source manifest) | **D (hybrid)** |
|---|---|---|---|---|
| Closes unpack-window torn read | partial | yes | **no** | **yes** |
| Permanent-wedge risk | **yes** | no | no | no (cut-only, recoverable) |
| Stale-manifest false-pass | n/a | no | **yes** | no |
| Extra full disk copy | no | **yes (a 2nd versioned tree)** | no | no |
| Generation-consistency proof for ALL 4 binaries | no | needs C anyway | yes (if sound) | **yes** |
| New crash-safety surface | low | medium (publish + GC) | low | low-medium |
| Composes w/ #1965/#1967/#1982/#1964 | n/a | yes (+ GC) | yes | **yes** |

**Recommendation: Option D (Hybrid).** It is the *minimal sound* mechanism: it
adds one maintainer-script-managed dotfile (`staged/.generation`), a preinst
invalidation, a postinst publish (ordered before the auto-cut), and a
before/after manifest+checksum gate in `copyStaged`. It closes the torn-read for
ALL four managed binaries (not just the verify-gated `xpfd`+shim), it cannot
permanently wedge the host, and it reuses the existing fsatomic + manifest SSOT
machinery. Option B is *more isolated* but pays a second full copy of the binary
set on every install plus a second GC surface — disk and complexity an appliance
should not spend when D already guarantees the cut never publishes a torn set.
**B is the documented fallback** if, in implementation, the postinst manifest
write cannot be made atomic relative to a (pathological) concurrent apt
transaction; in that case publishing into an immutable genid dir and cutting
from THERE removes the live-`staged/` read entirely. Bare A and bare C are
rejected for the fatal flaws above.

## 6. Ordering & crash-safety invariants (the contract /engineer must hold)

- **P1 (preinst write is first):** the `staged/.generation := "unpacking"` write
  is the FIRST mutating action of the preinst `upgrade` case, BEFORE the lock
  probe's side effects and BEFORE `migrate_legacy_layout`. (So a kill before it
  leaves a valid OLD manifest = safe; a kill after it leaves `"unpacking"` =
  refuse, also safe.) Re-confirm against the actual preinst flow at engineer
  time — the lock probe must still run (it is the fail-loud contended-cut gate),
  and the contended-cut gate must still abort BEFORE the package op proceeds.
- **P2 (postinst manifest BEFORE auto-cut):** the valid-manifest write in
  `configure` MUST precede BOTH the standalone auto-cut branch AND be written on
  the clustered-node stage-only branch (so a later `xpfd upgrade --rolling` sees
  a valid manifest). It must also be written on the first-install (`$2` empty)
  seed branch (via the seed, §4.5).
- **P3 (durable writes):** `.generation` writes use `fsatomic`-class durability
  (temp+fsync+rename+dir-fsync) — it is DurableState (must survive power loss so
  a post-reboot cut reads the right marker). The shell preinst write must mirror
  this (write `.generation.tmp`, fsync, `mv -f`, sync the dir) — shell parity
  with the Go writer, enforced by the manifest drift canary extended to the
  marker.
- **P4 (cut refuses, never wedges host):** an absent/`"unpacking"`/mismatched
  manifest is a **pure pre-STOP refusal** — the daemon is never stopped, live
  state untouched, the error tells the operator how to recover (re-run after the
  package op completes, or `apt install --reinstall`).
- **P5 (genid identity):** the genid must change on every distinct unpack so a
  before/after straddle is detectable. A monotonically-fresh value
  (e.g. a random token or `unpack-time + pid`) written by the postinst is enough;
  the per-binary checksums are the actual consistency proof, the genid is the
  cheap straddle tripwire.
- **P6 (manifest is NOT a dpkg payload file):** `.generation` lives under the
  dpkg-owned `staged/` dir but is maintainer-script-managed (never listed in the
  package payload / `debian/rules install`), exactly like `versions/` is
  maintainer-script-managed. Confirm dpkg does not remove it on the new
  package's unpack (it won't — dpkg only touches its own payload files;
  conffile/obsolete logic does not apply to a file it never recorded).

## 7. Test strategy

1. **Mid-copy mutation regression (the §2 acceptance pin), counter-factual:**
   - Seed `staged/` with a valid generation manifest. Drive `copyStaged`; inject
     a mutation of ONE managed binary's bytes (via a `copyTree` seam or a hooked
     filesystem) DURING the copy, leaving `.generation` stale. Assert the
     after-copy per-binary checksum mismatch makes `copyStaged` return an error
     and NOT publish `versions/<ver>`.
   - **Counter-factual half:** run the SAME mutation against the PRE-FIX path
     (self-generated target checksum only) and prove it does NOT error (it
     checksums the torn copy against itself). This is the engineering-style
     "recreate the failure mode" pin.
2. **Unpacking-sentinel refusal:** set `.generation = "unpacking"`; assert
   `copyStaged` refuses pre-STOP and the daemon is never stopped (state stays
   pure). Set it absent; assert refuse.
3. **Happy path:** valid manifest, untouched staged → cut proceeds, publishes
   `versions/<ver>`, journal advances normally.
4. **postinst ordering (P2):** a Go-level or shell-level test that the valid
   manifest exists at the moment the auto-cut would read it (so the first
   standalone deploy is not deferred). The prior research's Codex finding is the
   regression this guards.
5. **Shell-parity canary:** extend `manifest_drift_test.go` (or a sibling) to
   assert the preinst/postinst `.generation` writer matches the Go marker
   constant + sentinel value, so the two never drift.
6. **Crash-resume:** journal-resume tests already exist; add one that a resume
   after a refusal (no journal written, per §refuse-at-init) re-reads
   `.generation` and proceeds once it is valid.

**Deploy validation (per engineering-style §8):** this is a packaging/cut-path
change with no dataplane code; the relevant lane is the `.deb` dogfood in
`cluster-setup.sh` (it installs the package) — assert a clean
build→install→standalone-cut on the standalone VM, and that `cluster-deploy`
(stage-only on clustered nodes) followed by `xpfd upgrade --rolling` still cuts
both nodes. No CoS / failover regression is expected, but `make test-failover`
must still pass since the cut path touches the rolling driver's inner `Run`.

## 8. Alternatives rejected (summary)

- **Bare Option A (presence sentinel):** permanent-wedge on crashed unpack;
  rejected.
- **Bare Option C (payload-shipped manifest):** stale-manifest false-pass inside
  the unpack window; rejected.
- **Do nothing / keep the caveat:** the verify gate is a PARTIAL backstop
  (xpfd+shim only). A torn `xpfd`(new)+`xpf-userspace-dp`(old) set whose xpfd
  verify-passes flips a mismatched dataplane live. HIGH severity, real exposure
  on any host where an operator races `apt upgrade`. PLAN-KILL is only justified
  if reviewers judge the operator-guidance caveat ("don't run `xpfd upgrade`
  during `apt upgrade`") acceptable AND the four-binary consistency gap
  negligible — this plan argues it is not, given xpf-userspace-dp is a
  lockstep-cut dataplane binary.

## 9. Sequencing / dependencies

- Builds on #1982 (manifest SSOT): the per-binary checksum loop and the shell
  marker constant should be sourced from `pkg/upgrade/manifest` so they cannot
  drift. The marker-name + sentinel-value constant belongs in the manifest
  package; the drift canary extends to cover it.
- No conflict with #1983/#1984/#1985 (merged). Independent of the kernel channel
  (#1930) work.

## 10. Open questions for the user / architecture review

- **O1 (confirmed safe in §4 NOTE):** the "preinst killed before the
  `"unpacking"` write" window leaves a valid OLD manifest and a cut copies a
  consistent OLD generation — safe. Invariant P1 makes the `.generation` write
  the first preinst action so this window is as small as possible. Ratify.
- **O2 (D vs B final lock):** recommend D. Confirm the user accepts D's
  "wedge-the-cut-not-the-host" semantics on a crashed unpack (recovery =
  reinstall) rather than B's extra-copy read-isolation. If the user prefers
  zero chance of ever reading the live `staged/` during a cut, choose B (at the
  disk/GC cost).
- **O3:** genid representation (random token vs unpack-time+pid). Either works
  for the straddle tripwire; per-binary checksums are the real proof. Pick the
  simplest at engineer time.
