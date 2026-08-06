# Codex — hostile plan review r3 (#4626 L01)

Task `task-mshr3ghb-16q62y`. Reviewed `plan.md` @ `cc6c8c3e5` (v3, Path D recommended). The branch advanced to `65c87b7e0` (v3.1, carrier resolution) during the review; Codex notes this itself and its verdict does not rest on the later revision. The v3.1 change was confined to the carrier section, and Codex reached the same carrier conclusion independently — plus a further finding (the BPF-mirror sweep/bulk can overwrite the event-derived value) that v3.1 did not have. Verbatim final output below.

```
[2026-08-06T17:09:50.170Z] Final output
Path D’s carrier is salvageable; its clearing semantics are not. The proposed bit cannot distinguish an old policy ID from a different policy that inherits the same numeric ID after activation. Fixing that requires an admission fence or stable per-session policy/config identity—a materially different design. For this narrow payoff, document the limitation and close L01.

I reviewed the exact `cc6c8c3e5` plan blob; the branch advanced during review, but that later revision is not the basis of this verdict.

## 1. Carrier

`SessionValue.LogFlags` is the best carrier, but only if the Rust BPF publisher becomes an authoritative projection.

The hardcoded zero in [publish_conntrack.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:227) is historical filler from the original display-mirror implementation. Today:

- Locally owned userspace sessions always have `LogFlags=0` in their BPF mirror.
- Rust session-init/close logging works because it reads `SessionMetadata.log_session_*` directly, not that mirror.
- The parallel helper-event path carries named booleans to Go, which folds them into `SessionValue.LogFlags`, sends them cross-chassis, and unfolds them into `SessionSyncRequest` for the peer helper.
- Incremental sweep and reconnect bulk serialize the BPF mirror. Because each resend gets a newer generation, its zero `LogFlags` can overwrite a correct event-derived value on the peer. This is probably also a latent session-init/close reliability defect.

Therefore Path D needs both projections:

1. `SessionMetadata` → binary event/JSON fallback → Go `LogFlags`.
2. `SessionMetadata` → V4/V6 `publish_conntrack.log_flags` → BPF mirror → sweep/bulk.

The refresh path lookup-modify-writes the existing row and preserves `LogFlags`, so initial publication is the missing piece.

Carrier alternatives are worse:

| Carrier | Result |
|---|---|
| Free `LogFlags` bit | Viable; no BPF-size or cross-chassis frame growth |
| `SessionValue.Flags` bit 9+ | Not carried: HA encodes only the low byte at [sync_protocol.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_protocol.go:116). Requires a new trailing wire field |
| Go-only dedicated field | Invisible to the BPF rows used by render, clear, sweep, and bulk |
| Dedicated on-map field | Requires C/Go/Rust ABI changes plus a new cross-chassis field |

Thus the narrow “zero growth on the existing BPF and cluster session layouts” claim survives only with `LogFlags`. The broader “wire layout unchanged” claim does not: structured protobuf APIs and durable RT_FLOW/binary outputs still need additive schema or record changes.

## 2. Independent plane inventory

The implementation has at least ten distinct boundaries, not six:

1. Rust attribution origin and every `SessionMetadata` constructor, clone, reverse, shared, and promotion path.
2. Helper→Go binary SESSION_OPEN codec. Its flags byte is a separate namespace; only bits 6–7 are free.
3. JSON/RPC `SessionDeltaInfo`, retained fallback queues, and Rust/Go DTO manifests.
4. Go V4/V6 delta conversion into canonical `SessionValue.LogFlags`.
5. V4/V6 pinned BPF publication and the budgeted re-resolution refresh.
6. Cross-chassis V4/V6 codec, including incremental, sweep, bulk, reconnect, and stored replicas.
7. Go→Rust `SessionSyncRequest` and import into peer `SessionMetadata`.
8. Session consumers: clear, local REST/gRPC/CLI rendering, protobuf/REST schemas, and `include_peer` fanout.
9. RT_FLOW producers and codecs: policy deny, host-inbound non-policy deny, session create, and session close are separate builders/layouts.
10. Both Go RT_FLOW decoders, `EventRecord`, name resolution, syslog, retained event buffer, SSE, gRPC events, and the custom binary log.
11. If the retained legacy eBPF event producer is in scope, it is another producer; otherwise the plan must explicitly state that its ambiguity remains.

Conversely, `pkg/policymatch` is not a Path D plane. It already has `Matched` plus an authoritative `PolicyName`, and only emits `policy_id` on a positive match. The r2 `policymatch:1516` finding contradicted B′’s “zero is never assigned” invariant; carrying it into D was an inaccurate fold.

## 3. Mixed-version claim

I found no production consumer that changes behavior merely because an unknown `LogFlags` bit is set:

- Cluster decode accepts the full byte without mask validation.
- BPF conversions preserve it.
- Go→Rust code tests known bits individually.
- Reconciliation compares keys, not whole `SessionValue` bytes.
- Generation dedup does not compare `LogFlags`.
- Frame authentication covers raw bytes generically.
- Existing wire/BPF roundtrip tests preserve the complete byte.

So there is no strict-decoder, equality, checksum, or dedup incompatibility.

But “no mixed-version window” is still too absolute. There is a safe degradation window:

- Old-produced `(0,false)` remains unattributed on new code.
- Old code ignores new `(0,true)` semantically.
- An old node’s Go→Rust projection cannot express the new boolean; helper promotion/republication can consequently strip it.
- The first-policy benefit is therefore lost while an old producer or consumer participates.

That is not false attribution or unsafe over-clear by itself; it is today’s under-attribution/under-clear. The honest claim is “no unsafe mixed-version window, but feature precision degrades during rollout.”

## 4. Conditional render arm

Compute:

```text
effective = policy_id != 0 || attributed_bit
```

Then the correct logic is:

```text
ReservedPolicyName(id, effective):
    if id == DefaultPolicySentinelID:
        return default-policy, true
    if id == 0 && !effective:
        return unattributed, true
    return "", false

SessionPolicyName(localNames, id, effective):
    if ReservedPolicyName(...) matched:
        return reserved name
    return localNames[id]

PeerSessionPolicyName(peerName, id, effective):
    if ReservedPolicyName(...) matched:
        return reserved name
    return peerName
```

For `(0,true)`, local rendering reaches `localNames[0]`; peer rendering trusts the peer-provided name. It must never resolve peer ID 0 against the local map because IDs are node-local. See the existing load-bearing ordering in [policy_display.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/policy_display.go:79).

Wrong-but-plausible forms include:

- Keeping zero unconditionally reserved: first-policy under-attribution remains.
- Using the raw bit rather than `id != 0 || bit`: old-peer nonzero sessions stop resolving/clearing.
- Trusting a nonempty peer name before the zero guard: restores #6851.
- Resolving peer `(0,true)` through the local map: mixed-config misattribution.
- Making the default sentinel conditional on the bit.
- Looking up `map[0]` before rejecting `(0,false)`.

The plan’s “all three signatures remain preserved” assertion is impossible without adding tuple-aware replacements and migrating every caller.

## 5. Clear path

Both invalidators produce only sets of old numeric IDs. They do not see the discriminator. The shared V4/V6 scan in [daemon_policy_invalidate.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_policy_invalidate.go:285) is the only place that can test it.

That core is reached from:

- Normal commit and commit-confirmed apply.
- Incoming peer-config apply.
- Commit-confirmed rollback.
- Both deleted-policy and changed-policy invalidators.
- Default-policy invalidation.

Availability by row type:

- V4 and V6 callbacks both receive `SessionValue.LogFlags`.
- Peer-synced rows retain the incoming byte because `SetClusterSyncedSessionV4/V6` writes the full value to BPF.
- Locally owned userspace rows lack it until both Rust publishers are fixed.
- Refresh preserves the byte, but can change `PolicyID`.
- Peer-synced/unbound rows keep their frozen ID.

The fatal problem is that the predicate is still keyed on a positional ID:

```text
C1: [A, B]  => A=0, B=1
C2: [B]     => B=0
```

The commit activates C2 before invalidation runs in [daemon_apply_commit.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_apply_commit.go:245). A packet worker can then install a fresh C2 B session as `(0,true)` before or during the scan. The old-A deletion set contains `0`, so:

```text
effective_attributed && ids[0]
```

clears the new B session as though it were old A. `applySem` serializes applies, not dataplane admission.

The BPF row contains neither configuration epoch nor stable admitting-policy identity, so no refinement of the proposed bit predicate can distinguish them. The same race affects a freshly admitted session under a modified ID-0 policy: policy-rematch can unnecessarily clear a session already evaluated under the new rule.

HA adds another manifestation: session deletes use an asynchronous queue, whereas config sync writes directly. Config can overtake deletes; an equal/newer-epoch reused-ID row is admitted because `configEpochStale` rejects only strictly older epochs, then the receiver’s old-ID sweep clears it and can send the false delete back in active/active operation.

The refresh assumption is also false. Refresh runs in roughly 100 ms slices and targets a full-table cycle within about ten seconds, not “after ~1s”; it is not synchronized with Go invalidation. A deleted policy row can be re-resolved to `DefaultPolicySentinelID` before the scan and escape the old-ID target entirely. See [bpf_map/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/afxdp/bpf_map/mod.rs:375).

A correct design needs one of:

- A fail-closed admission/quiescence fence spanning new-policy activation through invalidation; or
- Stable admitting-rule/snapshot identity carried in every local, peer, and BPF row—or a lifecycle-correct sidecar—and clearing by that identity.

Either replaces the central Path D mechanism.

## 6. Default policy

`DefaultPolicySentinelID == 0xFFFFFFFF` is nonzero, so `effective_attributed` is always true regardless of the raw bit. That is correct: the ID is meaningful and represents an implicit policy decision.

Consequences:

- Its `ReservedPolicyName` arm remains unconditional.
- The existing direct sentinel clear remains exact.
- Public REST/gRPC should expose computed `effective_attributed`, not the raw carrier bit; otherwise an old default-policy row would incorrectly say its ID is meaningless.
- There is no `defaultPolicyRuntimeIDs` function—the current implementation directly passes a singleton sentinel set.
- The plan’s “L14 remains deferred/unblocked” statement is stale against this tree: default-policy clearing already uses the shared invalidator.
- Under D, zero is not a “reserved exact value.” `(0,false)` and `(0,true)` deliberately have different meanings. Only `0xFFFFFFFF` remains an unconditional reserved value.

## 7. Is D worth it?

No, not in this issue’s current scope.

Even after repairing the carrier, the work touches more than ten semantic/codec/output boundaries and makes a security-sensitive render guard conditional. More importantly, it still cannot reliably deliver the principal payoff—precise first-policy delete/rematch—without a new activation synchronization or stable-identity design.

The JSON/RPC fallback’s missing policy ID/counter/timeout remains an independent defect worth fixing. If product requirements later make exact session invalidation mandatory, that deserves a new plan based on stable admission identity or an atomic apply/invalidate transaction.

Given the narrow remaining benefit and the unavailable reservation alternative, documenting the limitation is the better engineering choice.

## 8. Test plan

`(N,false)` does detect removal of the `!= 0` arm in a clear test if the target set is exactly `{N}`. It does not uniquely bind it:

- `(DefaultPolicySentinelID,false)` also depends on the nonzero arm in the generic clear predicate.
- The mixed-version old-peer/nonzero test repeats the same behavior.
- Existing ordinary-policy clear fixtures generally default `LogFlags` to zero.
- A render test for nonzero N may simply perform the ordinary map lookup and never exercise the shared predicate.

So the mutation is not masked—it should still fail—but the “only distinguishing mutation” and “one distinct RED” claims are false. Add a direct predicate unit test plus an isolated clear fixture.

The missing distinguishing tests include:

- V4/V6 Rust BPF publication.
- Binary event and JSON fallback independently.
- Event-derived install followed by incremental sweep and reconnect bulk.
- V4/V6 cluster codec and Go→Rust import.
- Bit retention through refresh.
- Policy deny, session create, and session close RT_FLOW encoders separately.
- Both Go RT_FLOW decoders and each durable/structured sink.
- Peer protobuf propagation and sanitizer.
- Same-node and active/active C1→C2 reused-ID races.

Mutating a Rust field out of a struct will cause a compile failure, contrary to the plan’s assertion-failure-only rule. Mutations should retain the field and omit one assignment or serialization hop.

## 9. Fold accuracy and falsified assertions

Accurate folds:

- B′’s four kill arguments are represented faithfully.
- The two true peer-ingress doors are correctly distinguished from local helper egress.
- The five numeric namespaces are correctly classified.
- `RuntimePolicyIndex` should be deleted on miss, not shifted.
- gRPC `policy_id` must remain `optional`.
- R2’s HIGH rating applied specifically to B′, and v3 correctly rates B′ HIGH.

Incorrect or internally inconsistent folds:

- The `pkg/policymatch:1516` finding was incorrectly made a D discriminator plane.
- “No signature moves” is false.
- “No `.proto` change or regen” conflicts with the promised additive `SessionEntry` and `EventEntry` fields in [xpf.proto](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/proto/xpf/v1/xpf.proto:392).
- The heartbeat-capability trailer text remains in §6 despite B′ being rejected.
- “Both reserved values keep exact meanings” and §10’s “zero is reserved, so exact” are false under D.
- “Nothing externally visible changes” conflicts with the new structured discriminator and durable-record changes.
- Archived RT_FLOW records do not carry the claimed stable `rule_id` string; the current RT_FLOW field is numeric.
- The “~1s refresh” claim is false.
- The original source inventory still repeats stale r1 misclassifications such as the unpublished flow-cache seed and generic fabric/filler event sites.
- Path D’s MED risk rating is no longer supportable once the activation/clear race and actual plane count are included; this is HIGH forwarding-correctness risk.

PLAN-KILL
```
