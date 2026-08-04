# Codex hostile plan review — #6751 (round 30)

# PLAN-NEEDS-REVISION

Reviewed the frozen `d421d5d2e` v15.17 blob. The worktree’s plan file acquired an uncommitted later revision during review; that revision was excluded. Plan line references below are therefore `plan.md@d421d5d2e`.

1. **BLOCKER — Close ordering remains producer-incomplete and non-convergent.**

   The exact expiry→replacement→delayed-flush trace is real: expiry reaps at [loop_body/mod.rs:958](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:958), the replacement installs at [poll_descriptor/mod.rs:2449](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2449), and the delayed close reaches key-based cleanup at [session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs:406). An incarnation guard around all cleanup would fix that same-worker interleave.

   But `plan.md:1148-1158` misses a fourth producer: tunnel-remap purge constructs Close deltas at [tunnel_purge.rs:45](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/tunnel_purge.rs:45), applies an unconditional generation-zero delete at [session_import.rs:245](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:245), then publishes at [tunnel_purge.rs:80](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/tunnel_purge.rs:80).

   Retry exhaustion also has no convergence bound. Close removes the sender generation record at [sync_conn_gen.go:179](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:179); #2442 re-emits only Opens for surviving authoritative sessions at [loop_body/mod.rs:1196](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1196). It cannot remove a stale mirror row for closed K. A later bulk reads that row and mints a newer Open at [sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95), resurrecting K above the tombstone. The syscall retry terminates, but the correctness window is unbounded.

   The shard-local premise is also unproved: each worker owns a separate `SessionTable` at [setup.rs:138](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/setup.rs:138); no node-global incarnation comparison enforces the claimed affinity invariant.

2. **BLOCKER — Carry-forward fixes the stated Open gap but introduces unbounded state and retains poisoned aliases.**

   The original trace does converge under `plan.md:1178-1188`: a logged-only mirror failure at [publish_conntrack.rs:141](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:141), followed by delta install, BulkStart map replacement at [sync_conn_read.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:183), and absence reconciliation at [session_store.go:627](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:627). A greater tombstone makes a closed carried key inert.

   However, a timeout-admitted alias is itself delta-installed (`plan.md:1560-1566`) and therefore carried. The active derives explicit aliases only on the incremental path at [daemon_ha_userspace_stream.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370); its authoritative BPF-backed bulk normally contains canonical B but not explicit alias A. The next BulkStart seeds A, the bulk records B, and reconcile retains both. No new alias frame arrives to re-confirm/purge A.

   Cardinality is also unbounded: unique Open/Close churn grows the “since last completed BulkEnd” set indefinitely. Clearing it at BulkStart instead loses D1 across `BulkStart2 → abort → BulkStart3`; current abort/disconnect state is cleared at [sync_conn.go:554](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:554). A numeric cap, retain-until-success lifecycle, and authoritative overflow recovery are required.

3. **BLOCKER — The owner/occupancy split is correct in prose but not representable by the specified APIs.**

   `plan.md:316-322` still passes only `flow` into both allocator calls. The shipped address-only allocator derives destination occupancy directly from `flow.dst_ip/dst_port` at [allocator.rs:1727](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1727) and [allocator.rs:1740](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1740). If `flow` becomes the original-destination owner, `VIP:80` and `VIP:81` do not collide at effective `backend:8080`.

   The proposed record key `(owner, TranslatedTuple)` at `plan.md:364-377` also omits effective destination because `TranslatedTuple` contains only source IP and port at [allocator.rs:108](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:108). A backend-only DNAT change leaves `(owner,E:port)` unchanged, so distinct old/new occupancy records cannot coexist during staged replacement.

   Finally, the same `SourceNatFlowKey` serves interface and unchanged pool allocators at [source.rs:807](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:807), [source.rs:880](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:880), and [source.rs:1191](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1191). Making it original breaks pool effective-destination occupancy/release; leaving it effective breaks interface idempotence. Existing rollback also retains the effective key at [poll_descriptor/mod.rs:2201](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2201) and [poll_descriptor/mod.rs:2313](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2313). NAT64’s three sites remain internally consistent; the source/interface/pool key split is missing.

4. **BLOCKER — Worker-holder and standby allocator lifecycle are incomplete.**

   The port-less branch at `plan.md:316-320` omits both W and effective destination. The current method accepts only `(flow, translated_ip)` at [allocator.rs:1727](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1727), so GRE/ESP/address-only flows cannot acquire `{Worker(W)}` as required by `plan.md:471-473`. Static registration has the same missing API. The `+1 arg` signature inventory at `plan.md:1854-1859` contradicts the registry + W + effective-destination requirements.

   More critically, only local admission calls `allocator_for` (`plan.md:312`), while synchronized reserve is lookup-only and returns `NotThisDomain` when no allocator exists (`plan.md:263-265,336-340`). A fresh passive standby therefore imports peer interface-SNAT rows without any reservation. After failover, its first local mint creates an empty allocator and can preserve an already-live identity.

   The narrow fallible-allocator fold is closed—`allocator_for` returns `Option` and the shown local caller fails closed—but import/static creation and cap-failure semantics remain blocking.

5. **BLOCKER — Static cross-domain arbitration omits supported mapped-port static NAT.**

   v15.17 covers only whole-address static mappings at `plan.md:1669-1686,1733-1743`. Production mapped-port static rewrites the external source port at [static_nat.rs:746](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/static_nat.rs:746) and returns before interface admission at [nat_exception.rs:57](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs:57).

   Thus static `A:8080 → E:80 → C:443` and interface `H:80 → E:80 → C:443` form the same reverse identity. Static-first does not force the interface flow to PAT; interface-first does not make static fail closed. The tests at `plan.md:2124-2126` are also reversed relative to the normative directions at `plan.md:1739-1742`.

   Static-holder provenance across config removal, pool/NAT64 enablement, drain quarantine, and the uniform mint quarantine is unspecified. Whole-address registration alone cannot close either collision direction.

6. **BLOCKER — Alias index and purge discipline still have three correctness failures.**

   The `>4096` ordinary-SNAT bulk case is closed: the bulk index scales with `bulkRecv` and can ACK.

   The remaining failures are:

   - Bulk confirmation requires equal nonzero `RTFlowSessionID` at `plan.md:1513-1533`, but BulkSync reads the BPF-backed store at [session_store.go:118](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:118). That ID is absent from the BPF ABI at [bpf_session_value.go:75](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/bpf_session_value.go:75), lifts as zero at [bpf_session_value.go:204](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/bpf_session_value.go:204), and is encoded as zero by [sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95). A promoted legacy standby carrying base+alias rows cannot confirm the pair; BulkEnd admits the alias.

   - Incremental overflow deliberately timeout-admits excess entries at `plan.md:1546-1549`. After 4096 ordinary bases consume the only RTID-bearing index, a real alias cannot confirm and is installed as canonical, recreating the synthesized-companion misdelivery without wire loss.

   - Confirmation purge at `plan.md:1550-1558` is key-only. If timeout-admitted alias A is replaced by genuine direct row D at the same K, later confirmation of A deletes current D through [session_store.go:537](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:537). Map replacement is likewise key-based `UpdateAny` at [maps_session.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/maps_session.go:69). This is outside the documented delete-suppression residual and requires exact-publication compare-and-delete.

7. **NIT — Debt pre-dispatch attribution needs an explicit assertion.**

   Item 6 is otherwise closed: `plan.md:1265-1268` says a barrier failure aborts before starting, while the epoch→debtGen pair is recorded only at dispatch at `plan.md:1307-1315`; therefore no pair should exist for a pre-start abort. Add a test/assertion pinning that ordering.

| Round-29 fold | Adjudication |
|---|---|
| 1. Close incarnation/completeness | Open — finding 1 |
| 2. Carry-forward | Partial; original gap fixed, blockers remain — finding 2 |
| 3. Owner/occupancy split | Open — finding 3 |
| 4. Static cross-domain | Open — finding 5 |
| 5. Index lifecycle | Partial; bulk sizing fixed, alias failures remain — finding 6 |
| 6. Debt attribution | Closed with NIT 7 |
| 7. Worker-ID threading | Open — finding 4 |
| 8. Fallible allocator | Narrow fold closed; HA lifecycle open — finding 4 |
| 9. Producer enumeration | Closed; sweep included and journal preserves generation |
| 10. Sweep bound | Closed; reset/wake makes the sweep-cycle bound honest |
| 11. Projection | Closed; the exclude-list is conservative against the import surface |

Option (a) remains the selected design; these findings do not relitigate the fork. They show that v15.17 does not yet implement its own ownership and alias invariants. No files were modified.
