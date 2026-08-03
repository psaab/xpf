# Codex hostile plan review — #6751 plan v1 (round 1)


codex
# Verdict: PLAN-NEEDS-REVISION

The underlying vulnerability is real and reserve-or-PAT is salvageable. The proposed architecture does not yet guarantee unique translated tuples across allocator domains, forwarding generations, HA replicas, or rolling upgrades.

1. **BLOCKER — The registry is not global across all owners of a translated address.**

   Interface mode would get a new allocator, while source pools and NAT64 retain separate allocators. If interface address `E` is also present in a pool, both domains can independently allocate `(E, P)`, recreating the vulnerability.

   The existing #5144 validation describes exactly this failure:

   > “two DISTINCT owners whose expanded members intersect can each hand out the same … tuple, and the reverse (1:N) NAT index cannot tell”

   See [compiler_validate_strict_nat.go:2525](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2525>) and [compiler_validate_strict_nat.go:2556](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2556>). That validator enumerates source-pool and NAT64 owners only—not interface addresses—at [compiler_validate_strict_nat.go:2576](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2576>).

   HA reservation is also ambiguous because `NatDecision` has no rule/mode provenance. It scans pools containing `rewrite_src` and stops at the first successful reservation at [nat/source.rs:895](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:895>) and [nat/source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>). Release similarly stops after the first matching pool at [nat/source.rs:814](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:814>).

   Required revision: either unify interface, pool, and NAT64 ownership by translated address, add authoritative allocator provenance, or extend strict configuration rejection to interface/pool overlap.

2. **BLOCKER — “Node-global” is not generation-global, and remove/re-add loses live reservations.**

   Workers hold independent `Arc<ForwardingState>` generations at [runtime_view.rs:93](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/types/runtime_view.rs:93>), while every rebuild begins with a fresh `ForwardingState::default()` at [forwarding_build/mod.rs:200](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding_build/mod.rs:200>).

   Copying existing allocator Arcs is insufficient with lazy creation:

   1. The new state copies a map without address `E`.
   2. An old-generation worker lazily creates allocator A for `E`.
   3. A new-generation worker creates allocator B.
   4. Both can reserve the same port.

   The plan explicitly says a removed address drops its allocator at [plan.md:352](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:352>). Sessions are not synchronously purged when forwarding state rotates; reaping later uses the current state at [loop_body/mod.rs:1615](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1615>). Remove→re-add can therefore create an empty allocator while old sessions still own tuples, followed by ABA-style release corruption.

   The registry map itself must be shared across overlapping generations, and address state must remain tombstoned until every holder is gone—or sessions must retain an allocator lease directly.

3. **BLOCKER — The scalar holder-refcount design does not model real session-entry lifecycles.**

   `handle_upsert_synced` installs/replaces the entry first and reserves afterward at [upsert_synced.rs:64](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64>). Repeated sync refreshes replace existing entries at [session/install.rs:295](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:295>), so blind `holders += 1` leaks on every replay or refresh.

   The origin distinction is also unsuitable: `SyncImport`, `SharedMaterialize`, and `WorkerLocalImport` all satisfy `is_peer_synced()` at [session/entry.rs:242](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:242>). Sibling replication uses `WorkerLocalImport`, so a local-versus-peer boolean cannot identify holder ownership.

   Actual install paths bypass `handle_upsert_synced`:

   - `WorkerCommand::UpsertLocal` installs directly at [session_glue/mod.rs:778](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:778>).
   - Shared-map materialization installs directly at [session_glue/mod.rs:1122](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1122>).

   Both entries can later reap and decrement despite never acquiring a holder.

   Promotion and demotion are count-neutral origin changes, not destruction. Promotion mutates an existing entry at [promote.rs:99](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99>), while demotion assigns `SessionOrigin::SyncImport` in place at [session/install.rs:568](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:568>). The cited [promote.rs:194](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:194>) is a translated-session purge, not ordinary promotion.

   Required revision: define an acquisition identity/lease per concrete worker table entry and distinguish insert, same-tuple refresh, different-tuple replacement, materialization, and destruction.

4. **BLOCKER — Synced reservation conflicts are not fail-closed.**

   `handle_upsert_synced` commits the session before calling the reservation helper at [upsert_synced.rs:64](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64>). Existing pool reservation silently falls through when `reserve_flow` fails at [nat/source.rs:945](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:945>).

   Therefore the plan’s “skip gracefully on drift” invariant at [plan.md:346](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:346>) can leave an imported, live, unreserved session whose tuple conflicts locally. That contradicts the promised fail-closed property.

   Reservation must be transactional with installation, or the conflicting entry must be rejected/quarantined and removed.

5. **MAJOR — Probe purity misses the tuple-unknown synthetic caller.**

   Gating minting only on `!non_first_fragment` protects the fragment probe at [nat_exception.rs:94](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/nat_exception.rs:94>). Normal packet paths derive that flag from parsing, so a real first fragment should not carry it.

   However, the address-only wrapper invokes the matcher with `protocol=None`, zero ports, and `non_first_fragment=false` at [nat/source.rs:1098](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1098>). The matcher interprets `None` as `tuple_unknown` at [nat/source.rs:1186](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1186>). The proposed interface branch would mint a phantom address-only reservation for this synthetic query.

   Minting must require both `!non_first_fragment` and `!tuple_unknown`.

   Production tuple-matcher callers are the forwarding path at [forwarding/nat.rs:104](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding/nat.rs:104>) and the wrapper at [nat/source.rs:1109](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1109>); the coordinator status caller is test-only. No additional production caller was found. Changing arguments does not alter the #1377 textual “exactly two decision sites” guard at [snat_contract_doc_guard.rs:53](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/tests/snat_contract_doc_guard.rs:53>).

6. **MAJOR — The proposed allocator semantics and capacity are much broader than “PAT only corrupted flows.”**

   `AddressOccupancy` owns only address+numeric-port bits at [allocator.rs:504](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:504>). Protocol and remote endpoint are not part of occupancy. Consequently one allocator per address will PAT:

   - Same source port to different servers.
   - TCP and UDP sharing the same numeric port.
   - Every source port or ICMP identifier below 1024.

   Those flows have distinct external five-tuples and are not currently ambiguous. This contradicts the risk claim at [plan.md:370](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:370>).

   `PortAllocator::new(1, 1024, 65535)` also creates a 64,512-flow cap at [allocator.rs:771](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:771>) and [allocator.rs:2333](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:2333>). Portless tokens consume `live_by_flow` capacity too at [allocator.rs:1747](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1747>). `reserve_flow` at [allocator.rs:1654](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1654>) does not enforce the normal allocation cap, so standby behavior also needs an explicit policy.

   Allocator reuse is mechanically feasible: `reserve()` is exact CAS ownership at [allocator.rs:672](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:672>). A new helper can eliminate reserve→claim TOCTOU only if it continuously holds the `live` mutex through idempotence check, capacity check, exact reserve, fallback claim, and insert. Existing `allocate_translation` is not that exact precedent—it deliberately claims without the global mutex at [allocator.rs:999](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:999>).

7. **MAJOR — The Junos parity claim is unsupported.**

   In-repo evidence says only that `port-overloading off` disables source-port reuse across destinations at [types_security.go:627](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/types_security.go:627>) and [compiler_nat_source.go:253](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_nat_source.go:253>). It does not prove Junos always changes the port or preserves the first available source port.

   Preserve-first plus PAT-on-conflict is a defensible xpf compatibility semantic; always-PAT is unnecessary for correctness. But the proposed strict address-wide bitmap behaves like the `port-overloading off` posture across different destinations even though that knob is merely advisory. The plan must present this as an intentional semantic choice and obtain approval for its capacity implications—not claim literal Junos parity.

8. **MAJOR — Mixed-version HA remains vulnerable in the omitted direction.**

   The plan considers old-active/new-standby but omits new-active/old-standby. An old standby can import a new active’s PAT decision because `rewrite_src_port` already travels through HA, but its reservation helper skips non-pool rules at [nat/source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>). After failover, it can admit an old interface-mode flow onto the synced tuple.

   Protocol compatibility permits this skew when `SessionSyncProtocol` matches at [imageversions.go:162](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/upgrade/imageversions.go:162>). The plan needs a capability/version gate, failover restriction, or an explicitly accepted insecure rolling-upgrade window.

   The generic PAT carriage itself is already present: HA conversion carries `NATSrcPort` at [daemon_ha_userspace_convert.go:357](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:357>), flow-cache descriptors copy `rewrite_src_port` at [flow_cache.rs:586](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/flow_cache.rs:586>), and RT_FLOW records carry it at [rt_flow.rs:82](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/rt_flow.rs:82>). No new port wire field is required, but targeted interface-mode failover/cache tests are.

   Helper restart/rehydration of this newly authoritative in-memory registry is also absent from the test plan.

9. **MAJOR — The proposed observable counter contradicts “Rust-only/no API change.”**

   Existing global displacement telemetry needs a Rust status field at [protocol/control.rs:343](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs:343>) and a Go mirror at [protocol_status.go:287](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_status.go:287>). A “polled” `interface_snat_pat_collisions_total` cannot become operator-visible without equivalent status/metrics plumbing.

   PAT’d sessions are already visible through `rewrite_src_port`, including show-session publication at [publish_conntrack.rs:197](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/bpf_map/publish_conntrack.rs:197>) and Go rendering at [server_sessions.go:1724](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/grpcapi/server_sessions.go:1724>). What is missing is registry occupancy, holders, exhaustion, and preserve-first ownership visibility.

10. **MINOR — The release inventory is nine production calls, not seven.**

   The sites are reap at [loop_body/mod.rs:1625](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1625>); five rollbacks at [poll_descriptor/mod.rs:2313](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2313>), [2374](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2374>), [2472](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2472>), [2634](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2634>), and [4902](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4902>); synced delete at [delete_synced.rs:38](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:38>); translated-sync purge at [promote.rs:194](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:194>); and terminal teardown at [session_glue/mod.rs:563](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:563>).

   Each currently has forwarding-state access, so threading registry access is feasible. Interface-mode release genuinely no-ops today; the source says:

   > “interface-mode / static SNAT … owns no pool `live_by_flow` entry”

   at [nat/source.rs:795](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:795>).

   A dormant RST deletion path at [session_glue/mod.rs:908](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:908>) lacks forwarding access and release. It is currently unreachable because `should_teardown_tcp_rst` returns false at [session_glue/mod.rs:893](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:893>), but the plan should explicitly exclude it from the invariant.

11. **MINOR — Address-only is the correct registry key under the current global session namespace.**

   Egress interface addresses are selected from the interface primary address at [forwarding/nat.rs:99](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding/nat.rs:99>). `SessionKey` contains no ifindex, zone, or routing instance at [session/key.rs:9](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs:9>).

   Therefore `(address, VRF)` would be unsafe: two VRF-specific allocators could emit the same globally indexed reverse tuple. Address-only is conservatively correct. It does not solve identical pre-NAT tuples in overlapping VRFs because `SourceNatFlowKey` also lacks routing context at [nat/source.rs:144](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:144>); that remains #2387.

12. **MINOR — The core bug is confirmed, but the RST claim is stronger than the cited evidence.**

   Interface mode returns only `rewrite_src` and performs no allocation at [nat/source.rs:1226](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1226>). Reply validation compares only recomputed tuple keys at [session/key.rs:19](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs:19>), and lookup returns the first validating bucket member at [session/lookup.rs:222](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs:222>). The pinned tests prove first-installed selection at [session/tests.rs:4560](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/tests.rs:4560>) and [session/tests.rs:4602](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/tests.rs:4602>).

   Shared publication is single-valued and displaces the previous entry at [shared_ops.rs:897](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:897>). Flow-cache ifindex fields do not rescue the first reply: they only cache whichever session the global slow lookup selected.

   Thus deterministic cross-session reply misdelivery/data exposure is established. The cited tests do not independently prove the exact packet-level “RST tears down both sessions” lifecycle; that should be phrased as wrong-session reset/state damage unless an end-to-end RST test is added.

Option (a) should proceed only after redesigning allocator-domain ownership, generation lifetime, per-entry holder leases, sync-conflict handling, and mixed-version behavior.
tokens used
357,926
# Verdict: PLAN-NEEDS-REVISION

The underlying vulnerability is real and reserve-or-PAT is salvageable. The proposed architecture does not yet guarantee unique translated tuples across allocator domains, forwarding generations, HA replicas, or rolling upgrades.

1. **BLOCKER — The registry is not global across all owners of a translated address.**

   Interface mode would get a new allocator, while source pools and NAT64 retain separate allocators. If interface address `E` is also present in a pool, both domains can independently allocate `(E, P)`, recreating the vulnerability.

   The existing #5144 validation describes exactly this failure:

   > “two DISTINCT owners whose expanded members intersect can each hand out the same … tuple, and the reverse (1:N) NAT index cannot tell”

   See [compiler_validate_strict_nat.go:2525](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2525>) and [compiler_validate_strict_nat.go:2556](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2556>). That validator enumerates source-pool and NAT64 owners only—not interface addresses—at [compiler_validate_strict_nat.go:2576](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2576>).

   HA reservation is also ambiguous because `NatDecision` has no rule/mode provenance. It scans pools containing `rewrite_src` and stops at the first successful reservation at [nat/source.rs:895](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:895>) and [nat/source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>). Release similarly stops after the first matching pool at [nat/source.rs:814](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:814>).

   Required revision: either unify interface, pool, and NAT64 ownership by translated address, add authoritative allocator provenance, or extend strict configuration rejection to interface/pool overlap.

2. **BLOCKER — “Node-global” is not generation-global, and remove/re-add loses live reservations.**

   Workers hold independent `Arc<ForwardingState>` generations at [runtime_view.rs:93](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/types/runtime_view.rs:93>), while every rebuild begins with a fresh `ForwardingState::default()` at [forwarding_build/mod.rs:200](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding_build/mod.rs:200>).

   Copying existing allocator Arcs is insufficient with lazy creation:

   1. The new state copies a map without address `E`.
   2. An old-generation worker lazily creates allocator A for `E`.
   3. A new-generation worker creates allocator B.
   4. Both can reserve the same port.

   The plan explicitly says a removed address drops its allocator at [plan.md:352](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:352>). Sessions are not synchronously purged when forwarding state rotates; reaping later uses the current state at [loop_body/mod.rs:1615](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1615>). Remove→re-add can therefore create an empty allocator while old sessions still own tuples, followed by ABA-style release corruption.

   The registry map itself must be shared across overlapping generations, and address state must remain tombstoned until every holder is gone—or sessions must retain an allocator lease directly.

3. **BLOCKER — The scalar holder-refcount design does not model real session-entry lifecycles.**

   `handle_upsert_synced` installs/replaces the entry first and reserves afterward at [upsert_synced.rs:64](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64>). Repeated sync refreshes replace existing entries at [session/install.rs:295](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:295>), so blind `holders += 1` leaks on every replay or refresh.

   The origin distinction is also unsuitable: `SyncImport`, `SharedMaterialize`, and `WorkerLocalImport` all satisfy `is_peer_synced()` at [session/entry.rs:242](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:242>). Sibling replication uses `WorkerLocalImport`, so a local-versus-peer boolean cannot identify holder ownership.

   Actual install paths bypass `handle_upsert_synced`:

   - `WorkerCommand::UpsertLocal` installs directly at [session_glue/mod.rs:778](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:778>).
   - Shared-map materialization installs directly at [session_glue/mod.rs:1122](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1122>).

   Both entries can later reap and decrement despite never acquiring a holder.

   Promotion and demotion are count-neutral origin changes, not destruction. Promotion mutates an existing entry at [promote.rs:99](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99>), while demotion assigns `SessionOrigin::SyncImport` in place at [session/install.rs:568](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:568>). The cited [promote.rs:194](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:194>) is a translated-session purge, not ordinary promotion.

   Required revision: define an acquisition identity/lease per concrete worker table entry and distinguish insert, same-tuple refresh, different-tuple replacement, materialization, and destruction.

4. **BLOCKER — Synced reservation conflicts are not fail-closed.**

   `handle_upsert_synced` commits the session before calling the reservation helper at [upsert_synced.rs:64](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64>). Existing pool reservation silently falls through when `reserve_flow` fails at [nat/source.rs:945](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:945>).

   Therefore the plan’s “skip gracefully on drift” invariant at [plan.md:346](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:346>) can leave an imported, live, unreserved session whose tuple conflicts locally. That contradicts the promised fail-closed property.

   Reservation must be transactional with installation, or the conflicting entry must be rejected/quarantined and removed.

5. **MAJOR — Probe purity misses the tuple-unknown synthetic caller.**

   Gating minting only on `!non_first_fragment` protects the fragment probe at [nat_exception.rs:94](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/nat_exception.rs:94>). Normal packet paths derive that flag from parsing, so a real first fragment should not carry it.

   However, the address-only wrapper invokes the matcher with `protocol=None`, zero ports, and `non_first_fragment=false` at [nat/source.rs:1098](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1098>). The matcher interprets `None` as `tuple_unknown` at [nat/source.rs:1186](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1186>). The proposed interface branch would mint a phantom address-only reservation for this synthetic query.

   Minting must require both `!non_first_fragment` and `!tuple_unknown`.

   Production tuple-matcher callers are the forwarding path at [forwarding/nat.rs:104](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding/nat.rs:104>) and the wrapper at [nat/source.rs:1109](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1109>); the coordinator status caller is test-only. No additional production caller was found. Changing arguments does not alter the #1377 textual “exactly two decision sites” guard at [snat_contract_doc_guard.rs:53](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/tests/snat_contract_doc_guard.rs:53>).

6. **MAJOR — The proposed allocator semantics and capacity are much broader than “PAT only corrupted flows.”**

   `AddressOccupancy` owns only address+numeric-port bits at [allocator.rs:504](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:504>). Protocol and remote endpoint are not part of occupancy. Consequently one allocator per address will PAT:

   - Same source port to different servers.
   - TCP and UDP sharing the same numeric port.
   - Every source port or ICMP identifier below 1024.

   Those flows have distinct external five-tuples and are not currently ambiguous. This contradicts the risk claim at [plan.md:370](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:370>).

   `PortAllocator::new(1, 1024, 65535)` also creates a 64,512-flow cap at [allocator.rs:771](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:771>) and [allocator.rs:2333](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:2333>). Portless tokens consume `live_by_flow` capacity too at [allocator.rs:1747](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1747>). `reserve_flow` at [allocator.rs:1654](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1654>) does not enforce the normal allocation cap, so standby behavior also needs an explicit policy.

   Allocator reuse is mechanically feasible: `reserve()` is exact CAS ownership at [allocator.rs:672](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:672>). A new helper can eliminate reserve→claim TOCTOU only if it continuously holds the `live` mutex through idempotence check, capacity check, exact reserve, fallback claim, and insert. Existing `allocate_translation` is not that exact precedent—it deliberately claims without the global mutex at [allocator.rs:999](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:999>).

7. **MAJOR — The Junos parity claim is unsupported.**

   In-repo evidence says only that `port-overloading off` disables source-port reuse across destinations at [types_security.go:627](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/types_security.go:627>) and [compiler_nat_source.go:253](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_nat_source.go:253>). It does not prove Junos always changes the port or preserves the first available source port.

   Preserve-first plus PAT-on-conflict is a defensible xpf compatibility semantic; always-PAT is unnecessary for correctness. But the proposed strict address-wide bitmap behaves like the `port-overloading off` posture across different destinations even though that knob is merely advisory. The plan must present this as an intentional semantic choice and obtain approval for its capacity implications—not claim literal Junos parity.

8. **MAJOR — Mixed-version HA remains vulnerable in the omitted direction.**

   The plan considers old-active/new-standby but omits new-active/old-standby. An old standby can import a new active’s PAT decision because `rewrite_src_port` already travels through HA, but its reservation helper skips non-pool rules at [nat/source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>). After failover, it can admit an old interface-mode flow onto the synced tuple.

   Protocol compatibility permits this skew when `SessionSyncProtocol` matches at [imageversions.go:162](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/upgrade/imageversions.go:162>). The plan needs a capability/version gate, failover restriction, or an explicitly accepted insecure rolling-upgrade window.

   The generic PAT carriage itself is already present: HA conversion carries `NATSrcPort` at [daemon_ha_userspace_convert.go:357](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:357>), flow-cache descriptors copy `rewrite_src_port` at [flow_cache.rs:586](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/flow_cache.rs:586>), and RT_FLOW records carry it at [rt_flow.rs:82](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/rt_flow.rs:82>). No new port wire field is required, but targeted interface-mode failover/cache tests are.

   Helper restart/rehydration of this newly authoritative in-memory registry is also absent from the test plan.

9. **MAJOR — The proposed observable counter contradicts “Rust-only/no API change.”**

   Existing global displacement telemetry needs a Rust status field at [protocol/control.rs:343](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs:343>) and a Go mirror at [protocol_status.go:287](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_status.go:287>). A “polled” `interface_snat_pat_collisions_total` cannot become operator-visible without equivalent status/metrics plumbing.

   PAT’d sessions are already visible through `rewrite_src_port`, including show-session publication at [publish_conntrack.rs:197](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/bpf_map/publish_conntrack.rs:197>) and Go rendering at [server_sessions.go:1724](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/grpcapi/server_sessions.go:1724>). What is missing is registry occupancy, holders, exhaustion, and preserve-first ownership visibility.

10. **MINOR — The release inventory is nine production calls, not seven.**

   The sites are reap at [loop_body/mod.rs:1625](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1625>); five rollbacks at [poll_descriptor/mod.rs:2313](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2313>), [2374](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2374>), [2472](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2472>), [2634](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2634>), and [4902](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4902>); synced delete at [delete_synced.rs:38](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:38>); translated-sync purge at [promote.rs:194](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:194>); and terminal teardown at [session_glue/mod.rs:563](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:563>).

   Each currently has forwarding-state access, so threading registry access is feasible. Interface-mode release genuinely no-ops today; the source says:

   > “interface-mode / static SNAT … owns no pool `live_by_flow` entry”

   at [nat/source.rs:795](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:795>).

   A dormant RST deletion path at [session_glue/mod.rs:908](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:908>) lacks forwarding access and release. It is currently unreachable because `should_teardown_tcp_rst` returns false at [session_glue/mod.rs:893](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:893>), but the plan should explicitly exclude it from the invariant.

11. **MINOR — Address-only is the correct registry key under the current global session namespace.**

   Egress interface addresses are selected from the interface primary address at [forwarding/nat.rs:99](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding/nat.rs:99>). `SessionKey` contains no ifindex, zone, or routing instance at [session/key.rs:9](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs:9>).

   Therefore `(address, VRF)` would be unsafe: two VRF-specific allocators could emit the same globally indexed reverse tuple. Address-only is conservatively correct. It does not solve identical pre-NAT tuples in overlapping VRFs because `SourceNatFlowKey` also lacks routing context at [nat/source.rs:144](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:144>); that remains #2387.

12. **MINOR — The core bug is confirmed, but the RST claim is stronger than the cited evidence.**

   Interface mode returns only `rewrite_src` and performs no allocation at [nat/source.rs:1226](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1226>). Reply validation compares only recomputed tuple keys at [session/key.rs:19](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs:19>), and lookup returns the first validating bucket member at [session/lookup.rs:222](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs:222>). The pinned tests prove first-installed selection at [session/tests.rs:4560](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/tests.rs:4560>) and [session/tests.rs:4602](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/tests.rs:4602>).

   Shared publication is single-valued and displaces the previous entry at [shared_ops.rs:897](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:897>). Flow-cache ifindex fields do not rescue the first reply: they only cache whichever session the global slow lookup selected.

   Thus deterministic cross-session reply misdelivery/data exposure is established. The cited tests do not independently prove the exact packet-level “RST tears down both sessions” lifecycle; that should be phrased as wrong-session reset/state damage unless an end-to-end RST test is added.

Option (a) should proceed only after redesigning allocator-domain ownership, generation lifetime, per-entry holder leases, sync-conflict handling, and mixed-version behavior.
