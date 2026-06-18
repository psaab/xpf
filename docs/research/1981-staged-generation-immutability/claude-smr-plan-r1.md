# Claude SMR — hostile plan review r1 (#1981)

**Plan:** `docs/research/1981-staged-generation-immutability/plan.md` r1
**Verdict:** **PLAN-NEEDS-MAJOR** (one real ordering bug in the recommended
mechanism; the architecture itself — Option D — is sound and correctly preferred
over A/B/C).

I reviewed against the actual maintainer-script flow, not the prose summary.

## MAJOR-1 — P1 is WRONG: the `"unpacking"` write must come AFTER the contended-cut lock gate, not before it

The plan's invariant P1 says: *"the `staged/.generation := "unpacking"` write is
the FIRST mutating action of the preinst `upgrade` case, BEFORE the lock probe's
side effects and BEFORE `migrate_legacy_layout`."*

That ordering introduces a NEW false-refusal bug. The preinst `upgrade` case
(`debian/xpf.preinst:208-224`) opens with the contended-cut gate:

```sh
if ! flock -n "$LOCK" true; then
    echo "xpf: another in-place upgrade is in progress ..." >&2
    exit 1          # apt aborts BEFORE unpack — staged/ left UNTOUCHED
fi
```

If P1 writes `.generation="unpacking"` *before* this gate, then on a **contended
abort** (a concurrent operator `xpfd upgrade` holds the lock), the preinst
`exit 1`s — apt aborts, **no unpack happens, no postinst runs to rewrite the
manifest**. The marker is now stranded at `"unpacking"` over a **perfectly
intact, single-generation** staged tree.

The currently-running operator cut that holds the lock — the one this gate was
protecting — will, on its `copyStaged` before-read (or after-read), read
`"unpacking"` and **refuse a cut against a staged tree that was never torn**.
That is a self-inflicted false refusal, and worse, it's triggered by the very
contention the lock gate exists to handle gracefully. The marker would also
linger `"unpacking"` after the contended apt fully aborts, wedging the NEXT
operator cut too, until a successful package op rewrites it.

**Correct ordering:** the `.generation := "unpacking"` write must happen ONLY
once this preinst has committed to letting an unpack proceed — i.e. AFTER the
`flock -n` contended-cut gate passes (and it is fine to place it before or after
`migrate_legacy_layout`, since both run only on the non-contended path). Then a
contended abort leaves the marker at its prior VALID value, the lock-holding cut
reads a valid manifest, and proceeds correctly.

Rewrite P1 to: *"the `.generation := "unpacking"` write is the first mutating
action AFTER the contended-cut `flock` gate passes."* The §4 NOTE/O1 reasoning
("preinst killed before the write leaves a valid OLD manifest = safe") still
holds and in fact gets STRONGER with this correction: the only kill window that
strands `"unpacking"` is now genuinely "an unpack was about to / did proceed,"
which is exactly when a refuse is correct.

This is MAJOR because the plan currently prescribes the wrong invariant; an
`/engineer` that implements P1 verbatim ships the regression.

## MAJOR-2 — the postinst valid-manifest write must be on EVERY non-aborted configure path AND must itself be crash-safe-idempotent, not just "before the auto-cut"

P2 says write the valid manifest "before the auto-cut." That is necessary but
the plan under-specifies two things the crash matrix depends on:

1. **The clustered-node stage-only branch** (`postinst:117-119`) returns without
   cutting. The plan's §6 P2 does say to write the manifest there too — good —
   but the §4 crash matrix and §4.3 description only walk the standalone branch.
   Make explicit that the manifest write is **unconditional within `configure`
   for `$2` non-empty**, placed BEFORE the `if [ -f /etc/xpf/node-id ]` branch
   so all of {clustered stage-only, XPF_NO_POSTINST_CUT, deferred-TOCTOU,
   standalone cut} observe a valid manifest. Otherwise a clustered node stages
   without a manifest and the later `xpfd upgrade --rolling` refuses.

2. **First-install ($2 empty) path:** the plan routes the manifest write through
   the seed (§4.5). Confirm the seed writes the manifest EVEN ON the seed's
   "already seeded / resume" idempotent path (the seed early-returns when
   `versions/<ver>` exists — `seed.go:124-130`). If the manifest write is gated
   behind the copy step, a re-run that skips the copy also skips the manifest,
   and a first cut from a re-seeded host refuses. The manifest write must be
   idempotent and run on every seed invocation regardless of copy-skip.

Not fatal, but the plan must name these two placements or the implementation
will reproduce exactly the "first standalone deploy permanently deferred" class
of bug the prior research already caught once.

## MINOR-1 — genid is decorative given per-binary checksums; say so or drop it

§4.4 + P5 keep a genid as a "straddle tripwire" in addition to per-binary
sha256s. The per-binary checksum after-read already detects any torn or
mid-flight set (a binary dpkg replaced under the copy mismatches the
pre-unpack manifest). The genid only adds value for the narrow case where TWO
full unpacks complete during one copy AND the second produces byte-identical
binaries with a different identity — which the checksums would pass anyway
(byte-identical = not torn). The genid is cheap and harmless, but the plan
overstates it as load-bearing. Recommend: keep it ONLY as the `"unpacking"`
sentinel carrier (its real job) and the manifest's freshness stamp; do not
imply the before/after genid comparison is a correctness primitive independent
of the checksums. The checksums are the proof; the sentinel value is the gate.

## MINOR-2 — B's rejection is now adequately earned, but state the disk number

The prior research comment flagged "Option B's rejection is not fully earned."
The r1 §4 B analysis is much stronger (extra full copy, second GC surface, still
needs a generation check anyway). To fully earn it, put a concrete disk figure:
the managed set is 4 binaries dominated by `xpfd` (embeds the shim) +
`xpf-userspace-dp`; B holds THREE transient copies (staged, staged-gen/<genid>,
versions/<ver>) vs D's TWO (staged, versions/<ver>). On a constrained appliance
`/var` that is a real margin. With that number stated, B-reject is earned.

## What is RIGHT (and why this is NEEDS-MAJOR, not KILL)

- The dpkg model in §1 is correct: per-file `.dpkg-new`+rename during unpack →
  genuine torn window; preinst fd dies at preinst exit (the code comment agrees).
- P6 (manifest is maintainer-script-managed, NOT a dpkg payload file) is the
  right call and is independently corroborated by the postrm's own documented
  "presence-only file marker" trap (`debian/xpf.postrm:36-42`): dpkg removes a
  file that exists ONLY in the old package after old-postrm runs. A
  never-recorded dotfile is immune to that, and to obsolete-file cleanup.
- D correctly dominates A (no permanent-wedge: the sentinel is a manifest VALUE
  self-cleared by the next successful postinst, not a presence file an aborted
  unpack strands forever) and C (preinst-invalidation defeats the stale-but-valid
  manifest false-pass). The recommendation is the right one.
- The verify-dataplane "partial backstop" framing is accurate — it is xpfd+shim
  only, so a torn xpfd(new)+xpf-userspace-dp(old) lockstep pair is exactly the
  exposure, and D closes it for all four managed binaries.

Fix MAJOR-1 (the P1 ordering), tighten P2 with the two explicit placements
(MAJOR-2), fold the two minors, and this is PLAN-READY.
