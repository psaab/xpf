# Codex hostile plan review — #6751 (round 41)

# PLAN-NEEDS-REVISION

I reviewed the exact committed v15.29 blob at `d34e8faf1`. Plan line numbers below refer to that blob; a later uncommitted AGY edit in the worktree was excluded.

1. **BLOCKER — The capability/framing fold remains normatively contradictory, and the ordered send is not bound to a lossless pre-publication path.**

   The new rules are present at `docs/research/6751-nopat-admission/plan.md:696-731`: authority is captured per BulkStart, non-capable windows are disposition-only, capability precedes data, and first capability knowledge forces a fresh prime.

   However, retained normative sections still require the incompatible design:

   - `plan.md:1354-1380` assigns capability transport to a dedicated 5–10s periodic ticker alone.
   - `plan.md:2774-2783` again inventories the capability frame as ticker-driven.
   - `plan.md:3474-3477` calls the dedicated periodic ticker the fixed transport.
   - `plan.md:2283-2289`, `2366-2368`, and `2400-2407` still make every completed BulkEnd definitive and allow P1 confirmation/admission decisions.
   - `plan.md:3189-3191` and `3313-3321` repeat unconditional definitive/P1 behavior in validation.

   The bootstrap/loss question is therefore not closed. Today the connection is published and its reader started before the immediate cold prime (`pkg/cluster/sync_conn.go:130-194`, `244-274`). The global writer can then select that connection (`pkg/cluster/sync_conn_write.go:268-300`), while `queueMessage` is explicitly lossy before TCP (`pkg/cluster/sync_conn_write.go:36-49`). Checked direct writes exist (`pkg/cluster/sync_protocol.go:49-82`; BulkStart uses one at `pkg/cluster/sync_bulk.go:81-90`), but v15.29 never normatively says capability uses that class before publication, or defines an equivalent emission gate.

   If capability is a successful direct write before publication, TCP ordering closes selective in-transit loss. If it remains ticker/queue-driven or follows publication, a drop/overtaking window remains.

   Disposition-before-ACK itself is implementable: `plan.md:289-310` requires serialized disposition/import before ACK, matching `pkg/cluster/sync_conn_read.go:98-147` and `241-247`. Thus genuine rows may complete disposition before ACK while alias-proof debt remains. The retained definitive/P1 clauses nevertheless still authorize the forbidden confirmation, purge, and clear.

2. **BLOCKER — The degraded interval and connected-only readiness terminal still conflict.**

   `plan.md:663-665` still specifies `quiet_interval = 2.5 × keepalive_timeout`, illustrated as 7.5s. That contradicts the later actual-detector derivation at `plan.md:749-774`.

   Code uses a 10s read deadline (`pkg/cluster/sync.go:88-91`) and closes an ACK-capable peer after two missed periods (`pkg/cluster/sync_conn_read.go:27-46`), making the practical bound roughly 20s plus write/scheduling jitter. Legacy peers that never ACK remain deliberately unbounded because miss enforcement is gated by `peerHeartbeatAckEver` (`pkg/cluster/sync_conn_read.go:33-36`; `pkg/cluster/sync_test.go:4655-4745`).

   Retained text also still calls the readiness timeout a bounded release terminal at `plan.md:735-738`, `2136-2145`, and `3015-3016`. The actual 5s readiness timer requires a connected peer (`pkg/daemon/daemon_ha_sync.go:40-47`); disconnect clears state and stops it (`pkg/daemon/daemon_ha_sync.go:109-130`). The required no-release-without-reconnect behavior is pinned by `pkg/daemon/session_sync_readiness_test.go:33-53`.

   Therefore the blob still offers implementors two incompatible terminals: an unsafe 7.5s/5s path and the new fence-owned, disconnected-eligible path.

3. **BLOCKER — Fence-cycle expiry has no complete serialized lifecycle or precedence over the 5s timer.**

   The plan labels its lifecycle inventory complete but omits fence-cycle expiry at `plan.md:1605-1622` and `1689-1696`. The readiness callback protection at `plan.md:1649-1668` checks arming generation and connectedness, but not fence state/generation.

   This leaves the disagreement asked about unresolved. Disconnect notification is asynchronous (`pkg/cluster/sync_conn.go:569-570`), so a connected-only readiness callback can race fence engagement before disconnected state is committed. Conversely, an old fence timer can fire after a higher-generation abort/re-arm described at `plan.md:2233-2235`. No normative precedence prevents either stale terminal from releasing the newer cycle.

   Fence engagement must atomically invalidate/gate readiness release, and fence expiry must be a generation-bound lifecycle event with cancellation, commit ordering, and explicit precedence.

   It also should not literally reuse all effects of the existing bulk-received callback: that path sets `syncBulkPrimed=true` (`pkg/daemon/daemon_ha_sync.go:90-100`) and records `bulk-sync-complete` (`pkg/vrrp/manager.go:380-405`). A degraded terminal needs a distinct committed release effect that does not falsely claim bulk completion or discharge either debt.

4. **BLOCKER — The named private-RG outer gate is not code-real.**

   The plan relies on a private-RG readiness gate at `plan.md:770-774` and pins it at `3000-3004`. Production code does not currently enforce one:

   - `pkg/daemon/daemon_ha_vip.go:40-55` bases no-RETH takeover on VIP readiness, without consulting sync readiness.
   - `pkg/daemon/daemon_ha_vip.go:100-105` routes both no-RETH VRRP and private-RG election through that path.
   - `pkg/daemon/vip_readiness_test.go:345-386` proves takeover readiness can succeed while `cluster.IsSyncReady()` is false.
   - `pkg/cluster/sync_state.go:13-27` defines the readiness state, but there is no production takeover consumer.

   The plan must explicitly reintroduce and wire the private-RG sync gate—including its disconnected bound—or stop claiming it as an outer bound.

Verified folds:

- The two distinct debts are correctly stated at `plan.md:499-510`; delivery ends at matching BulkEnd-ACK, while alias-proof ends only with a capable definitive snapshot or row close. The fresh capable prime is present at `727-731`. Finding 1 prevents whole-blob composition from being sound.
- The retained-C0 regression pin is present at `plan.md:2997-3008`, although `3015-3016` contradicts it.
- Classic RETH’s independent 30s hold is code-real (`pkg/daemon/daemon_run_bringup.go:226-233`; `pkg/vrrp/manager.go:351-376`) and remains an effective outer bound.
- I found no new kill shot against the option-(a) core. The blockers are in the capability/alias and terminal/hold machinery, not the settled core fork.
