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
   `snapshot_policy_invariant.go`): after the full build (post zone
   quarantine, which legitimately scrubs rules and resyncs the count),
   `validateSnapshotPolicyInvariant` errors the compile when
   `len(Policies) != Summary.PolicyCount`, or when the compiled config
   carries >=1 security policy rule (zone-pair + global) but the snapshot
   carries none. Compile error = prior snapshot kept (fail closed), never
   published. Structured `slog.Error` with `policy_count`, `policies_len`,
   `first_zone_pair`, `generation`.

2. **Send-site gate** (`requestApplySnapshotPreparedLocked`, the single
   `apply_snapshot` send site): `validateSnapshotForSend` refuses any
   snapshot whose `Summary.PolicyCount != len(Policies)` with
   `errSnapshotPolicyMismatch` — same known-unsent refusal class as
   `errRGProviderNotWired` (registered in `isKnownUnsentFailure`): no
   generation burn, no retry debt. Catches every future builder path,
   including partial-republish clones and hand-built publishers.

3. **Helper (Rust)** (`userspace-dp/src/server/handlers/snapshot.rs`): on
   `apply_snapshot`, after the version gate and before the monotonicity /
   content-identity gates, `summary.policy_count != policies.len()`
   increments the dedicated sticky counter
   `snapshot_policy_mismatch_total` (owned by `ServerState`, projected
   into `ProcessStatus` by `refresh_status`), logs
   `ERROR: apply_snapshot refused (snapshot policy mismatch) ...` and
   refuses the WHOLE apply — prior snapshot, policies, status generations
   all retained (never install-empty-then-deny). The wire already carries
   `summary.policy_count` (Go `SnapshotSummary.PolicyCount` / Rust
   `SnapshotSummary.policy_count`), so **no protocol bump was needed**;
   the empty-when-prior-nonempty special case is subsumed by the count
   check.

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
    `errSnapshotPolicyMismatch` (also turns the pre-existing
    `TestSnapshotCarriesPolicies15742` red through the builder, not just
    its own assertions).
  - `TestSendSiteRefusesPolicyCountMismatch` — the send site refuses
    before any control request (recorder sees 0 sends), generation
    unchanged, error is known-unsent, outcome-unknown not marked; a
    consistent snapshot still sends.
  - `TestFullBuilderPopulatesEverySnapshotField` — field-coverage census:
    every exported `ConfigSnapshot` field must be non-zero from the full
    builder for a representative config (zones/interfaces/policies/global
    policy), except an explicit exemption list where each entry carries a
    reason. Catches the NEXT dropped literal field; a new struct field
    fails until populated or consciously exempted.
- Rust (`server/tests.rs`):
  `apply_snapshot_policy_count_mismatch_is_refused_and_counted` — seeds a
  1-policy snapshot, then applies the dropped-field shape
  (policy_count=2, policies=[]): refused with the mismatch error,
  counter 0->1 in both ServerState and status, generation/policy count/
  installed snapshot unchanged.

## Residual gaps

- The census's representative config has no NAT/screen/filter/CoS/tunnel
  content; those fields are exempted with reasons rather than populated.
  Extending the fixture would tighten it, at the cost of a much heavier
  config fixture.
- The Rust gate trusts `summary.policy_count` as delivered; a producer
  that zeroed BOTH the count and the policies would pass all three
  layers — but that requires two coordinated field drops, and the Go
  builder's ground-truth arm (compiled rule count) covers it on the full
  Compile path.
- Helper counter resets on helper restart (process-lifetime counter,
  consistent with the other `*_total` status counters).
