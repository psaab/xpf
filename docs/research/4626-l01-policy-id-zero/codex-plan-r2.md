# Codex — hostile plan review r2 (#4626 L01)

Task `task-mshq5qd0-x3ar4z`. Reviewed `plan.md` @ `12ea93354` (v2, Path B′ recommended). Verbatim final output below.

```
[2026-08-06T16:43:10.855Z] Final output
Path B′ is not salvageable as a minor revision. Its translation is undefined for real shipped sentinel values, its “exact inverse” fails during ordinary config propagation, and its capability is not bound to the TCP session stream it controls. I recommend rewriting the plan around Path D. Kill B′, not the issue.

### 1. Egress downgrade is neither total nor an exact behavioral inverse

The unconditional `policy_id - 1` in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/docs/research/4626-l01-policy-id-zero/plan.md:463) mishandles three important values:

| B′ local value | Blind downgrade | Old peer’s actual interpretation |
|---|---:|---|
| `0`, unattributed | `0xFFFFFFFF` | `default-policy` — false attribution and eligible for default-policy clearing |
| `1`, first configured policy | `0` | `unattributed`, because the old resolver checks reserved zero before its populated map |
| `0xFFFFFFFF`, default-policy | `0xFFFFFFFE` | unknown numeric policy; default-policy invalidation misses it |

`DefaultPolicySentinelID` is not theoretical: default-permit sessions carry it, and default-policy invalidation targets it exactly ([types.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/types.go:530), [daemon_policy_invalidate.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_policy_invalidate.go:207)). Ingress “rewrite every old ID to zero” likewise destroys this sentinel.

Even with synchronized configs, `1 → 0` does not restore first-policy behavior. The old build renders zero as `unattributed` before map lookup and skips zero in both invalidators ([policy_display.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/policy_display.go:79), [daemon_policy_invalidate.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_policy_invalidate.go:72)). It is an arithmetic inverse, not a behavioral inverse for the exact policy this issue concerns.

The minimum typed mapping would have to preserve both reserved values and subtract only a proven configured ID. The plan does not define that proof.

Config skew then breaks even the ordinary-ID case. Example:

- C1 is `[A,B,C]`; old-space IDs are `0,1,2`.
- The new node commits C2 `[A,C]`; B′ IDs are `1,2`.
- Before the old peer applies C2, new `C=2` is downgraded to `1`.
- The old C1 peer interprets `1` as `B`.
- When it applies C2, its deletion sweep for old `B=1` can clear the newly synced `C` session.

The generation machinery does not close this window:

- Local apply completes before the config is pushed ([daemon_apply_commit.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_apply_commit.go:245)).
- `QueueConfig` allocates the new generation only afterward ([sync_conn_config.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn_config.go:230)).
- The receiver merely queues config for asynchronous application ([sync_conn_read.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn_read.go:298)).
- `configEpochStale` rejects only `epoch < max(applied, applying)`, so an equal or sender-newer session is admitted before or during apply ([sync_conn_gen.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn_gen.go:410)).

Sending zero avoids confident misnaming and over-clear, but is not strictly better: every configured-policy session becomes unattributed and exempt from deletion/rematch, potentially retaining stale forwarding. It is the safer degradation, not a Pareto improvement. Accurate downgrade needs proof that the peer applied the exact config—an acknowledgement/barrier the old peer does not provide.

### 2. The ingress-door inventory is wrong

There are exactly two production cross-chassis admission arms:

1. `syncMsgSessionV4 → decodeSessionV4Payload → installClusterSyncedV4` ([sync_conn_read.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn_read.go:98)).

2. The equivalent V6 arm ([sync_conn_read.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn_read.go:124)).

Incremental pushes, sweeps, bulk sync, and both fabrics all converge on those arms. Normalisation belongs after decode and before `installClusterSyncedV4/V6`, with the sender’s space bound to that connection.

The cited [daemon_ha_userspace_convert.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_ha_userspace_convert.go:385) path is not peer ingress. It converts local helper deltas—binary event-stream or JSON/RPC drain/export—into outbound cluster sessions. Treating it as ingress risks normalising local new-space IDs.

After actual peer admission, the ID fans out through `PutClusterSyncedV4/V6` into the BPF mirror and Go→Rust `SessionSyncRequest.PolicyID` ([manager_ha.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/manager_ha.go:1653)). Normalising once before storage is load-bearing because later ring callbacks, sweeps, and bulks may relay that stored value.

Egress is broader than “both encoders”: queue-time incremental encoding, ring-event requeue, sweep, and direct bulk writes all need connection-consistent handling. Current queues contain pre-encoded bytes, and `sendLoop` retries the same bytes after reconnect ([sync_conn_write.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn_write.go:268)). A frame encoded for a space-0 process can therefore reach its replacement space-1 process.

### 3. Heartbeat extension passes old-reader compatibility, but fails as a capability protocol

What checked out: an old parser reads its known version fields and ignores additional body bytes. The tail-located HMAC authenticates opaque extra bytes, so a carefully designed extension can remain old-reader compatible.

What does not check out:

- Immediately after the current HA version sits the optional `"XPFA"` authentication trailer ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/heartbeat.go:76)). A naïve new parser reading “one more byte” sees `'X'` (`0x58`) from an authenticated old peer, not an absent capability. `UnmarshalHeartbeat` runs before auth-tail recognition ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/heartbeat.go:890)).

- The current body reserve accounts for exactly length byte plus HA version ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/heartbeat.go:239)). The new byte must be included in size accounting.

- “No heartbeat observed yet” cannot mean legacy space 0. Session sync can connect and immediately bulk-prime before the first 100 ms heartbeat tick. New↔new startup could therefore collapse valid space-1 IDs to zero before capability discovery.

- The capability is node-global UDP state controlling independently established TCP connections. It has no ordering or incarnation binding to queued frames, a peer restart, or a fabric replacement.

The extension therefore needs explicit framing or auth-tail-aware parsing, tri-state `unknown/space0/space1`, and connection lifecycle rules. A sync-connection negotiation is materially cleaner.

Q3′’s suggested validation is impossible. A space-1 peer legitimately sends zero for unattributed sessions, so rejecting zero would reject valid state. Old and new nonzero domains overlap, so a bare ID cannot prove which numbering function produced it. The receiver can validate capability encoding and connection lifecycle; it cannot validate truthful space use from the scalar. Advertise-only is insufficient as an admission invariant.

### 4. The 21-site classification is incomplete, and `RuntimePolicyIndex` should not shift

The actual disposition is:

- 1 runtime SSOT that must shift: [policies.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/policies.go:64).

- 2 legacy-compiler `PolicyRule.RuleID` producers that must shift or be explicitly decoupled: [compiler.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/compiler.go:924) and its global twin. These keys populate production `CompileResult.PolicyNames`, which userspace session/log/API renderers still consume. Leaving them space 0 makes new ID 1 resolve to the old second-policy name.

- 1 display fallback that should be deleted, not shifted: [policies_ids.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/policies_ids.go:123).

- 15 raw counter-handle sites that must not shift: [metrics.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/api/metrics.go:1220), REST/CLI/gRPC policy renderers, and [policycounters.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/policycounters.go:239). This is the fifth class omitted by the plan’s claimed four.

- 2 physical BPF map keys that must not shift: [maps_policy.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/maps_policy.go:45) and its scheduler-update twin.

`RuntimePolicyIDs` suppresses walker errors and returns a partial map. Shifting its fallback manufactures a plausible real ID for a policy that was never assigned one; it can also collide with another missing entry. The correct fix is to surface absence/error, not fabricate `ordinal+1`.

The same problem exists in `pkg/policymatch`: `matchedResult` directly indexes the partial map, so a miss becomes `Matched=true, PolicyID=0` ([policymatch.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/policymatch/policymatch.go:1516)). That contradicts B′’s zero-never-assigned invariant.

Finally, the upper-bound rejection must use checked/wider arithmetic. Checking only an already-wrapped `uint32` result does not establish the universal property claimed by §7.

### 5. Additional +1 costs are understated

Several checks produced concrete additions:

- Prometheus does not expose numeric policy ID as a label. `xpf_policy_hits_total` labels are zone pair plus rule name ([metrics_descriptors_policy.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/api/metrics_descriptors_policy.go:5)). Its numeric input is an internal raw counter handle. Correct B′ causes no label churn; shifting that handle silently reads the wrong counter.

- `policyRuleIDForCounter(DefaultPolicySentinelID)` must remain before divmod and unchanged ([policycounters.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/policycounters.go:75)). Counter-handle zero remains valid for the first policy, so “zero defaults fail safe” is only a runtime/session-ID invariant, not codebase-wide.

- #3623’s rationale becomes stale in source, generated documentation, and two regression suites—not just the REST test named by the plan. See [xpf.proto](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/proto/xpf/v1/xpf.proto:327) and [server_policy_id_zero_3623_test.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/grpcapi/server_policy_id_zero_3623_test.go:13). Keep `optional`: MatchPolicies still uses presence to distinguish matched from unmatched, and it is now an established compatibility contract. The comments and generated bindings still need regeneration even though the wire shape does not change.

- The public shift includes policy inventory, MatchPolicies, zone summaries, REST/SSE events, and CLI diagnostics—not merely sessions, Index and RT_FLOW. `pkg/policymatch` is missing from the proposed affected-package test list.

Checks that did pass: I found no fourth durable numeric-ID store. `PolicyIDsByStableKey` compares old/new IDs from the same shifted function correctly; local Rust sessions re-resolve through stable `rule_id`; policy counters persist by stable name. Peer-synced sessions remain unbound and preserve their frozen scalar across config reload, however, which reinforces that B′ cannot assume semantic equality merely because config eventually converges.

### 6. SessionDeltaInfo should land first, but “manufactured zero is harmless” is overstated

Field-first sequencing is sound. Go already has and consumes `SessionDeltaInfo.PolicyID`; Rust alone omits it and its constructor ([protocol_ha.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/protocol_ha.go:162), [binding.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/protocol/binding.rs:1147)). Before renumbering, the added field carries current space-0 semantics. There is no wrong-meaning deployment window.

It is independently worthwhile and should precede either B′ or D. For actual fallback parity it should carry `policy_counter_idx` and application timeout too; Go already expects all three.

But it does not make B′ safe:

- Legitimate unattributed zero still exists and blind subtraction underflows it.

- The default-policy sentinel still exists and blind subtraction corrupts it.

- Even after a corrected preserve-zero translation, a manufactured zero remains an attribution, invalidation, counting and timeout quality loss. It is fail-safe, not harmless.

### 7. The test plan is not yet mutation-sensitive

Per-arm fixtures are necessary, but they only bind a helper’s branches. They do not prove every V4/V6, incremental/bulk, local/peer, queue/retry call site invokes the helper with connection-current state.

Required distinguishing mutations include:

- `+1 → +2`, not only removing `+1`.

- Leaving `CompileResult.PolicyNames` in space 0.

- Erroneously shifting one counter handle or one physical BPF key.

- Bypassing each V4/V6 ingress and egress call site.

- Values `0`, first-policy `1`, ordinary policy, unknown ID and `0xFFFFFFFF`.

- Unsigned old heartbeat, signed old heartbeat, truncated/invalid extension, no-heartbeat-yet, capability transition and reconnect with a queued frame.

- C1/C2 skew before apply, during apply, failed apply, and active/active non-authority direction.

- Orphan helper event stream and pinned-map flush.

The mixed-build leg is necessary, not theatre in principle. As written, a steady identical-config failover is theatre for the decisive claim. It must pin the exact old artifact, force config skew or rapid reorder/delete, exercise first/ordinary/unattributed/default-policy sessions, reverse config authority as well as node placement, and cross heartbeat/TCP reconnect ordering.

### 8. Behavioral risk is HIGH

MED is not honest. B′ changes every public runtime ID, translates every peer-synced session, couples asynchronous UDP state to TCP session admission, and can falsely name or clear an unrelated policy’s session. Missed sentinel handling also breaks default-policy invalidation. This is broad compatibility behavior with forwarding consequences, not a localized display change.

### 9. Path D is the better recommendation

The plan’s deciding argument against D contradicts its corrected predicate:

```text
effective_attributed = policy_id != 0 || attributed_bit
```

A forgotten field defaults to `(0,false)`, which is safely unattributed. A nonzero ID from an old peer remains attributed. Only first-policy zero needs the bit. Therefore the demonstrated `SessionDeltaInfo` omission does not discriminate B′ from D; it underclaims safely under both.

D preserves every existing numeric join key, needs no mixed-space translation or capability, and degrades across old/new peers exactly as today for first-policy zero. Its six-plane plumbing and scalar-only off-box ambiguity are real costs. Structured APIs should expose the discriminator explicitly, and RT_FLOW must carry it. Those costs are still preferable to a permanent bidirectional translation protocol whose correctness depends on config timing.

The author over-corrected toward literal reservation.

### 10. Kill B′, not the issue

The remaining defects are narrow, but real: first-policy deletion/rematch exclusion, durable attribution underclaim, and the standalone fallback metadata gap. Path D addresses them without numeric churn or a cross-channel compatibility layer.

If literal scalar reservation is non-negotiable and Path D is rejected, then PLAN-KILL/document-the-limitation is preferable to B′. Because D remains a credible lower-risk solution, my overall verdict is major redesign rather than killing the issue outright.

PLAN-NEEDS-MAJOR
```
