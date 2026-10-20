# #15742 follow-up — hardening the empty-policy snapshot class

Branch `fix/harden-empty-policy-snapshot` (Refs #15742; new issue to be
filed by Main). The defect: commit 670274c712 dropped `Policies: policies`
from the full snapshot builder literal while `Summary.PolicyCount` still
reported the compiled rule count. The helper installed `policies=[]` and
default-denied all transit; nobody noticed until live probes. The field
itself was restored by PR #15921. This change makes the CLASS fail loudly
and immediately at every layer, each independently sufficient:

## Layers

1. **Builder invariant** (`pkg/dataplane/userspace/builder.go`,
   `snapshot_policy_invariant.go`): after the full build,
   `validateSnapshotPolicyInvariant` compares the published set against
   `expectedPolicyCount(cfg)` — the effective POST-QUARANTINE ground
   truth (lower the rules, apply the exact quarantine scrub, count
   survivors). A config whose every rule is legitimately quarantined
   expects ZERO and passes (`TestBuildSnapshotDropsDanglingGlobalMatchZone`);
   non-quarantined rules vanishing between lowering and publication
   still errors the compile (fail closed, prior snapshot kept).
   Structured `slog.Error` with `expected_policy_count`, `policy_count`,
   `policies_len`, `first_zone_pair`, `generation`. (First revision
   compared against the RAW authored count and false-fired on
   fully-quarantined configs — fixed per triple review.)

2. **Send-site gate** (`requestApplySnapshotPreparedLocked`, the single
   `apply_snapshot` send site): `Manager.validateSnapshotForSend`
   refuses when `len(Policies)` disagrees with EITHER the snapshot's
   self-declared `Summary.PolicyCount` OR the manager's
   `expectedPolicyCount` stamp (Manager field, init -1, stamped in
   `Manager.Compile` from every full build before its own send).
   Zeroing BOTH transmitted fields (0 == 0) therefore still refuses
   whenever the last full Compile expected policies; a stamped 0
   (fully-quarantined / policy-free Compile) legitimately sends 0/0.
   Refusal is `errSnapshotPolicyMismatch` — known-unsent class like
   `errRGProviderNotWired`: no generation burn, no retry debt.

3. **Helper (Rust)** (`userspace-dp/src/server/handlers/snapshot.rs`): on
   `apply_snapshot`, after the version gate and before the monotonicity /
   content-identity gates, TWO arms refuse the whole apply (prior
   snapshot/policies/status retained, sticky
   `snapshot_policy_mismatch_total` incremented, `ERROR` logged):
   (a) `summary.policy_count != policies.len()`; (b) an empty policy
   install over a non-empty installed set, regardless of counts —
   there is **no explicit full-clear signal on the wire**, and adding
   one needs a protocol bump (follow-up below), so silently emptying
   enforcement mid-stream is never accepted from a partial publish;
   a legitimate empty FIRST apply (nothing installed) still succeeds.
   Round-2 update: the deliberate clear-all path now exists via the
   additive authorized-clear marker (see Residual gaps) — a marked
   full-Compile clear installs empty at the helper; only unmarked
   empty publishes refuse. The refusal stays loud (ERROR + counter +
   metric), never silent.

4. **Observability**:
   - Go: `slog.Error` on builder and send-site refusals (counts +
     first zone pair, above).
   - Rust: `ERROR:` eprintln on refusal; `ProcessStatus` gains
     `snapshot_policy_mismatch_total` and `last_snapshot_policy_count`
     (additive, `serde(default)`; Go `ProcessStatus` mirrors both).
   - Prometheus (`pkg/api`): `xpf_userspace_snapshot_policy_mismatch_total`
     (counter) and `xpf_userspace_last_snapshot_policy_count` (gauge),
     emitted unconditionally from the existing userspace status collect.
   - Status display (`pkg/dataplane/userspace/format`): `Last snapshot
     policies: N` beside `Last snapshot generation`, plus a mismatch line
     when the counter is nonzero. No new endpoint invented.

## Tests

- Go (`snapshot_policy_invariant_test.go`):
  - `TestBuilderInvariantRejectsDroppedPoliciesField` — dropped-field
    shape and count drift both fail the builder invariant; policy-free
    config still builds. Verified RED by deleting the
    `Policies: policies` line: `buildSnapshot` itself returns
    `errSnapshotPolicyMismatch`.
  - `TestBuilderFullyQuarantinedConfigPasses` — a config whose only
    policies are quarantine-scrubbed builds 0/0 cleanly and
    `expectedPolicyCount` returns 0 (the review regression; production
    twin `TestBuildSnapshotDropsDanglingGlobalMatchZone` also passes).
  - `TestSendSiteRefusesPolicyCountMismatch` — refuses before any
    control request (0 sends), generation unchanged, known-unsent.
  - `TestSendSiteRefusesBothZeroedPartialPublish` — Policies AND
    PolicyCount both zeroed still refuse against a non-zero stamped
    expectation; stamped 0 legitimately sends 0/0.
  - `TestFullBuilderPopulatesEverySnapshotField` — field-coverage census
    (exemptions each carry a reason) catches the NEXT dropped field.
- Rust (`server/tests.rs`):
  `apply_snapshot_policy_count_mismatch_is_refused_and_counted` (2-vs-0
  shape) and `apply_snapshot_both_zeroed_over_installed_is_refused`
  (0/0 over a non-empty installed set refuses; legitimate empty first
  apply succeeds).

## Residual gaps

- **Authorized clear (round-2 fold, #15937)**: closed WITHOUT a
  protocol bump via the additive `clear_policies` marker (option (c),
  the smallest authorized-clear path). Only `Manager.Compile` sets it,
  on a full build; the send site spends (zeroes) it after the send;
  `stripSingleUseCommitMetadata` strips it from every partial clone;
  `syncSnapshotLocked` re-marks only when helper status proves the
  cleared set already landed (idempotent landing-confirmation, not a
  fresh authorization). The Rust gate accepts a marked empty install
  over a non-empty installed set; unmarked both-zeroed publishes still
  refuse at both layers. Old helpers ignore the field (additive,
  `serde(default)`); old Go sends false. A mixed-version old-helper
  fleet predating the installed-set gate has no gate to authorize —
  no worse than before this hardening. The stamp now commits ONLY
  after a successful apply (a refused Compile leaves the prior stamp,
  so retained-count partials still publish — stamp-poisoning fix).
- The send-site stamped expectation is per-Manager-process: a daemon
  restart before any full Compile leaves expected=-1, where only the
  self-consistency arm + the helper's installed-set gate apply.
- The census's representative config has no NAT/screen/filter/CoS/
  tunnel content; those fields are exempted with reasons rather than
  populated.
- Helper counter resets on helper restart (process-lifetime counter,
  consistent with the other `*_total` status counters).

## Fold corrections (triple review, bb7c5f5273 + this fold)

- Builder comment at the invariant call site corrected: the ground
  truth is post-quarantine (`expectedPolicyCount`), not the Summary
  resync alone; a raw authored count would false-fire on the supported
  fully-quarantined posture.
- Census extended into the nested `Summary` struct (SchedulerCount /
  HAEnabled exempted with reasons; HostName/DataplaneType now seeded in
  the fixture; PolicyCount/ZoneCount/InterfaceCount/identity asserted
  consistent). Deleting the nested `PolicyCount: len(policies),` line
  was mutation-verified to turn the Go hardening set red.
- Validation counts corrected: Rust `server::tests::apply_snapshot` is
  22 listed / 22 passing at this head (20 at the first reviewed head;
  the first revision's "21/21" was wrong). `pkg/api` shows exactly the
  pre-existing failure set, byte-identical base vs head (the earlier
  "19 failures" figure is withdrawn — an artifact of counting
  subtests/output).
- Traceability: this work is driven by #15937; commits and PR now
  carry `Refs #15937` alongside `Refs #15742`.


## Round-3 fold (Codex3)

Full builds bypass the send-site stamp arm via an unexported `fullBuild` provenance bit (builder-set, Compile-affirmed, stripped on every partial clone alongside the clear marker); the stamp enforces only on partial publishers and re-commits after a successful full apply. Clear-attempt timeouts converge via the Compile retry re-marking from the build itself. See commit message.

## Round-4 fold (Codex4+Opus4)

Stamp now follows HELPER-PROVEN state, not Compile's outer error:
- `Compile` commits `expectedPolicyCount` on nil OR
  `PublishedSnapshotTailError` (the snapshot IS enforced at that
  point) via `commitExpectedPolicyCountFromLandedSnapshot`.
- `syncSnapshotLocked` reconciles the stamp from helper status
  (`LastSnapshotPolicyCount` at generation >= retained, only once
  this Manager has published) in the status catch-up, and commits
  from the accepted snapshot on the deferred-publish success path
  when it carried a full build.
- Clear re-marking is provenance-based, not landed-only: a retained
  snapshot that IS the Compile's full build with an empty policy set
  re-marks in BOTH landing states (landed = idempotent confirmation;
  not-landed = restoring its own attempt's authorization), while a
  provenance-less empty retained snapshot never mints a mark.
Regressions: `TestTailErrorStampFollowsAcceptedBuild`,
`TestLostResponseLandedStampFollowsStatus` (+stale-status negative),
`TestSyncRetryRemarksUnlandedClear` (real `syncSnapshotLocked` drive:
unlanded clear retries marked, stamp commits 0, provenance-less
retained refuses at the gate).
