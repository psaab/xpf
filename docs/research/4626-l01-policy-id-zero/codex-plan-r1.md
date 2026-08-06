# Codex — hostile plan review r1 (#4626 L01)

Task `task-mshoutve-upydpx`. Reviewed `docs/research/4626-l01-policy-id-zero/plan.md` @ `f78ac55c7` (base `b8b39a16a`). Verbatim final output below.

```
[2026-08-06T16:13:16.524Z] Final output
Recommendation rejected. Path C cannot safely reach its promised end state, and the main technical argument against literal `+1` numbering is based on conflated ID namespaces.

The requested plan blob at `f78ac55c7` is identical to the current worktree’s plan blob. Current HEAD only adds review documents; the production tree remains based on `b8b39a16a`. The worktree is clean and no code was changed.

## Claim-by-claim findings

1. **Restart isolation: FALSE as stated.**

   Direct control-socket adoption does not exist. A new manager unlinks the pathname and spawns its own helper; an orphan remains bound to an unreachable Unix-socket inode. See [process.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/process.go:18) and [lifecycle.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/server/lifecycle.rs:154). An old helper exiting later can also unlink the new helper’s pathname, because cleanup is not ownership-checked, but that causes availability loss rather than adoption.

   The broader conclusion—“no old-stamped local state crosses an xpfd restart”—is false. The event socket is separate:

   - The new daemon starts its listener before spawning the replacement helper.
   - An orphan retries that socket indefinitely.
   - Go accepts an event-stream client without checking PID or helper incarnation at [eventstream.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/eventstream.go:436).
   - Unacknowledged frames can replay. After a failed correctness-critical delta, the orphan can re-export its owned-forward session population through the delta-loss recovery path.

   This does not populate the replacement helper’s local table directly, but the new xpfd can receive old-helper rows and forward them to the HA peer. Pinned BPF session maps are an additional restart-surviving numeric-ID store.

2. **HA version admission: VERIFIED.**

   No session-sync admission path rejects a connection because `CurrentHAProtocolVersion` differs. The sync header has no version field, admission only limits connection setup, and after the auth handshake frames proceed directly through `receiveLoop`: [sync.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync.go:21), [sync_admission.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_admission.go:58), [sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_conn.go:88).

   `sync_auth.go` does contain a separate `syncAuthVersion`, but it is not the HA/session-wire version, and the receiver does not validate that version byte. HA mismatch affects readiness and image-replacement gates, not live frame admission. Therefore a simple HA version bump does not make renumbering safe.

3. **Packed `+1` arithmetic: PRINCIPAL CLAIM FALSE.**

   The 256-slot reachability claim is correct: `walkPolicyRuleSlots` accepts an exact fill because it rejects only `ruleIndex+span > 256`, so indices 0–255 are reachable at [policies.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/policies.go:73).

   But `policyRuleIDForCounter` does not decode runtime `policy_id`. Its documentation explicitly says it decodes a different, raw slice-index counter handle at [policycounters.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/policycounters.go:43). No production caller passes a runtime ID to that divmod.

   A runtime `+1` therefore gives disjoint ranges:

   - Set `n`: `[n*256+1, (n+1)*256]`
   - Set `n+1`: `[(n+1)*256+1, (n+2)*256]`

   There is no collision and no need to reduce capacity to 255. If runtime decoding were later needed, it would decode `id-1`.

   I found only one production divmod decoder, not two. There are 15 raw counter-handle encoder occurrences, plus six multiply/add sites in other namespaces: runtime allocation, runtime-display fallback, legacy compiler IDs, and physical BPF map keys. The plan conflates those namespaces and incorrectly treats all of them as one encoding that must move together.

4. **Persistence: BROAD CLAIM FALSE.**

   `pkg/configstore` has no numeric policy-ID reference, and the helper state file does not restore a session table. Those narrow statements are correct.

   However:

   - The helper state file serializes its `ConfigSnapshot`, whose policy records contain `policy_id`, via [persistence.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/server/helpers/persistence.rs:25). It is observability persistence, not restored runtime state.
   - `sessions` and `sessions_v6` are deliberately pinned to survive daemon restarts at [loader_userspace_shim.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/loader_userspace_shim.go:72), and their values contain `PolicyID`.
   - Initial cleanup has a conditional preservation branch at [maps_sync.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/maps_sync.go:577).

   A renumbering design therefore needs an explicit flush, translation, or lifetime proof for pinned rows. “Only RT_FLOW persists IDs” is factually wrong.

5. **Path C mixed-version safety: CORE SAFE, SURFACE CLAIMS FALSE.**

   While both zero guards remain, new-node ← old-peer behavior is substantially today’s behavior. Old-node ← new-peer also does not resolve `0xFFFFFFFE` to a configured policy and ordinarily cannot sweep it.

   But an old build does not uniformly “render empty”:

   - CLI: `4294967294/4294967294`, via numeric fallback in [cli_show_flow.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cli/cli_show_flow.go:348).
   - REST: numeric `policy_id`, with `policy_name` omitted.
   - gRPC: numeric ID with empty `PolicyName`.
   - RT_FLOW: decimal `"4294967294"` as the policy name, via [ringbuf.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/logging/ringbuf.go:272), not empty.
   - Direct `include_peer` fanout may preserve the new peer’s supplied `unattributed` name.

   This is safe from confident configured-policy misattribution, but it is not a strict UX improvement over today’s `unattributed`.

   Also, `0xFFFFFFFE` is not structurally unreachable. The current arithmetic produces it at policy-set `0x00FFFFFF`, rule index 254. There is no policy-set-count or reserved-ID guard in the walker. Practical config size makes collision implausible, but “can never collide” requires a production rejection, not merely a unit assertion.

6. **Two-release removal: DAY-ONE REASONING RIGHT; RETIREMENT MECHANISM BROKEN.**

   Under Path C as drafted, the zero exclusion cannot be removed on day one because an old peer can still send ambiguous zero. That part is correct.

   The proposed N/N+1 mechanism is not:

   - Release N adds no protocol version or capability, so N is indistinguishable from every pre-N version.
   - `MinCompatHAProtocolVersion` is real image metadata, but it is not runtime sync admission.
   - Raising `CurrentHAProtocolVersion` also changes `SessionSyncWireVersion`, whose image gate requires exact equality; it does not create the claimed rolling boundary.
   - Manual or otherwise ungated deployments can still connect excluded versions.
   - An orphan local helper bypasses peer-version reasoning entirely.
   - The JSON fallback described below continues manufacturing zero even in a homogeneous new/new cluster.

   The plan also misses a second ID-zero exclusion in `changedPolicyRuntimeIDs` at [daemon_policy_invalidate.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_policy_invalidate.go:443). Removing only lines 72–77 leaves first-policy rematch invalidation broken.

   If N+1 never arrives, release N is mostly migration churn and an automation-visible numeric sentinel change without delivering precise clearing or attribution. That kills the recommended sequence, not the whole issue.

7. **Path D wire facts: VERIFIED; COMPATIBILITY PREDICATE WRONG.**

   `LogFlags` is a `u8`; bits 0–1 and 6–7 are used, with bits 2–5 free at [types.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/types.go:947). The complete byte is carried cross-chassis at [sync_protocol.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/cluster/sync_protocol.go:170) and decoded at line 455. Cross-chassis wire growth is indeed zero.

   But `attributed && ids[PolicyID]` breaks rolling compatibility: an old peer leaves the bit clear for every legitimate policy, including all nonzero IDs. The compatible rule is:

   ```text
   effective_attributed = policy_id != 0 || attributed_bit
   ```

   The bit should disambiguate zero only.

   D still needs substantial plumbing: Rust metadata, same-host event flags, JSON fallback, Go→Rust import, BPF publication—currently `log_flags` is hardcoded zero—and the separate RT_FLOW codec. It is not “one cheap bit,” but unlike C it can deliver day-one precision once corrected. The recommendation must be reopened.

8. **`DuplicatePolicyId` rationale: STALE.**

   The external `apply_snapshot` entry rejects a non-current protocol version before integrity preflight at [snapshot.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/server/handlers/snapshot.rs:25). Other production parser calls consume the already-accepted stored snapshot. The check near line 446 is only the separate `bump_fib` handler, not another integrity-preflight ingress.

   Thus an older peer cannot legitimately reach `DuplicatePolicyId` with an old snapshot. A hand-built current-v4 snapshot can omit the field through serde defaulting, but that violates the current private contract; it is not a compatibility requirement.

   Removing the exception is independent validator cleanup and can remain a separate change. The stale older-peer rationale should be removed and the follow-up explicitly tracked; it should not depend on Path C’s fictional N+1 boundary.

9. **Stamping inventory: MATERIALLY WRONG AND INCOMPLETE.**

   The live non-policy sources that actually matter are:

   - Missing-neighbor seed: [neighbor_dispatch.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/afxdp/neighbor_dispatch.rs:606).
   - Firewall-self-originated tunnel: [tunnel.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/afxdp/tunnel.rs:595).
   - Host-inbound no-match arm at [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1892). Only `NoMatch` changes; an explicit `junos-host` permit can legitimately have real ID zero.
   - Host-inbound admission-deny RT_FLOW at `event_emit.rs:262`.

   Misclassified entries:

   - `flow_cache.rs:631` explicitly says the seed is never published; it is not a separate non-policy session install.
   - `event_emit.rs:306`, `:362`, and `:498` are filler fields. The codec substitutes `screen_id` or `filter_id`, so changing them has no policy-ID wire effect.
   - There is no separate non-policy fabric constructor. Fabric-transit sessions are policy-admitted and stamp `policy_result.policy_id`; companions inherit that ID.
   - `worker/loop_body/mod.rs:1815` and `ha/session_import.rs:421` are indeed test-only fixtures.

   The fatal omission is the production JSON/RPC HA fallback:

   - Go expects `PolicyID`, `PolicyCounterIdx`, and `AppTimeout` in [protocol_ha.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/dataplane/userspace/protocol_ha.go:118).
   - Rust’s fallback `SessionDeltaInfo` contains none of them at [binding.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/protocol/binding.rs:1147).
   - Its constructor omits `delta.metadata.policy_id` at [session_delta.rs](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/userspace-dp/src/afxdp/session_delta.rs:200).
   - The production fallback loop drains this queue every 100 ms while disconnected and every five seconds even while connected at [daemon_ha_userspace_stream.go](/home/ps/git/bpfrx/.claude/worktrees/4626-research-l01/pkg/daemon/daemon_ha_userspace_stream.go:254).
   - Conversion consequently stamps zero into the cluster session value. A later reconciliation copy receives a fresh install generation and can overwrite an earlier correct binary-stream copy on the peer.

   Therefore even a homogeneous Path-C fleet continues creating zero-stamped synced sessions. Once the zero render/sweep guards are removed, arbitrary policy sessions can be mislabeled as the first policy and swept with it. This directly invalidates Path C’s N+1 state and its “no local protocol/fixture change” assertion.

10. **Recommendation and issue scope: REJECT THE SUBSTITUTION.**

   Path C solves only “two meanings no longer share the same value in newly stamped data.” It does not deliver the requested structural invariant that zero is invalid as a real configured policy.

   Literal reservation has concrete value that Path C lacks:

   - Zero-initialized or omitted metadata naturally remains unattributed.
   - A missed transport field fails toward “unknown” instead of becoming the first policy.
   - Validators can reject real policy ID zero.
   - Consumers inspecting the scalar alone need no knowledge of a second high sentinel.

   The existing JSON fallback omission is direct evidence for that value: under Path C, every forgotten/defaulted zero becomes confidently attributable after guard removal.

   A corrected literal uniform `+1` design retains all 256 slots; its real costs are mixed-version translation, numeric continuity, orphan-helper fencing, and pinned-row handling—not divmod corruption. A corrected attributed-bit design is also viable. Path C could remain a candidate only after adding an actual capability/admission invariant, fallback coverage, both zero guards, helper-incarnation handling, and honest old-surface/API behavior. At that point its claimed simplicity has largely disappeared.

This is not PLAN-KILL: the ambiguity is real, literal reservation has demonstrated defensive value, and viable redesigns exist. It does require a new architecture pass rather than edits around the current recommendation.

PLAN-NEEDS-MAJOR
```
