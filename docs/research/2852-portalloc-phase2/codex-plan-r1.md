# Codex hostile plan review — #2852 Phase-2 evaluation — r1 (verbatim)

Model: gpt-5.5 --effort high (default gpt-5.6-sol infra-failed; retried, see reviewer-ids.md).
Task: b5mnvhfhh (foreground-persisted). Registry evicted the job id post-run;
output recovered from the persisted stdout file.

```
[codex] Starting Codex task thread.
[codex] Thread ready (019f4858-b1fe-7de3-870d-543a61e46158).
[codex] Turn started (019f4858-b6b8-7361-9cb4-87eab0ba9d3b).
[codex] Assistant message captured: I’ll read the plan and the referenced dataplane paths directly from the specified worktree, t...
[codex] Running command: /bin/bash -lc 'rg -n "publish_shared_session|replicate_session_upsert|Mutex|live_by_flow|Addr...
[codex] Command completed: /bin/bash -lc 'rg -n "publish_shared_session|replicate_session_upsert|Mutex|live_by_flow|Addr... (exit 0)
[codex] Running command: /bin/bash -lc "sed -n '1,260p' docs/research/2852-portalloc-phase2/plan.md"
[codex] Command completed: /bin/bash -lc "sed -n '1,260p' docs/research/2852-portalloc-phase2/plan.md" (exit 0)
[codex] Running command: /bin/bash -lc 'pwd && git rev-parse HEAD && git status --short --branch'
[codex] Command completed: /bin/bash -lc 'pwd && git rev-parse HEAD && git status --short --branch' (exit 0)
[codex] Assistant message captured: The plan is making two different claims about “every new flow”: one transit install path at ~...
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '3000,3188p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '3000,3188p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/session_glue/mod.rs | sed -n '720,770p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/session_glue/mod.rs | sed -n '720,770p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '1,110p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '1,110p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/allocator.rs | sed -n '380,430p;600,620p;870,945p;...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/allocator.rs | sed -n '380,430p;600,620p;870,945p;... (exit 0)
[codex] Assistant message captured: So far, the 3136/3157 calls are unconditional after `forward_installed`, but not before: they...
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '120,260p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '120,260p'" (exit 0)
[codex] Running command: /bin/bash -lc "rg -n \"fn publish_shared_session|struct WorkerContext|peer_worker_commands|sh...
[codex] Command failed: /bin/bash -lc "rg -n \"fn publish_shared_session|struct WorkerContext|peer_worker_commands|sh... (exit 2)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '760,820p;1360,1...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '760,820p;1360,1... (exit 0)
[codex] Assistant message captured: I found one important crack in the plan wording: missing-neighbor seed publishes to the share...
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '882,945p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '882,945p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2928,2978p;3310...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2928,2978p;3310... (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/screen/mod.rs | sed -n '880,1045p;1410,1480p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/screen/mod.rs | sed -n '880,1045p;1410,1480p'" (exit 0)
[codex] Running command: /bin/bash -lc 'rg -n "MissingNeighborSeed|replicated|replicate_session_upsert|UpsertSynced|pe...
[codex] Command completed: /bin/bash -lc 'rg -n "MissingNeighborSeed|replicated|replicate_session_upsert|UpsertSynced|pe... (exit 0)
[codex] Assistant message captured: The shared publish path is definitely lock-based: it takes the base shared session mutex, the...
[codex] Running command: /bin/bash -lc "rg -n \"struct SharedSessionOwnerRgIndexes|type SharedSessionOwnerRgIndexes|fn...
[codex] Command completed: /bin/bash -lc "rg -n \"struct SharedSessionOwnerRgIndexes|type SharedSessionOwnerRgIndexes|fn... (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '760,885p;945,990p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/shared_ops.rs | sed -n '760,885p;945,990p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/session/install.rs | sed -n '1,80p' && nl -ba userspac...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/session/install.rs | sed -n '1,80p' && nl -ba userspac... (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba docs/research/2852-portalloc/microbench-results.md | sed -n '120,160p'"
[codex] Command completed: /bin/bash -lc "nl -ba docs/research/2852-portalloc/microbench-results.md | sed -n '120,160p'" (exit 0)
[codex] Assistant message captured: One more nuance: the older merged microbench says Phase 2 was “indicated” in the isolated all...
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/types/mod.rs | sed -n '36,75p' && nl -ba userspa...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/types/mod.rs | sed -n '36,75p' && nl -ba userspa... (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/allocator.rs | sed -n '1,45p;1110,1235p;1360,1450p...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/allocator.rs | sed -n '1,45p;1110,1235p;1360,1450p... (exit 0)
[codex] Running command: /bin/bash -lc "sed -n '260,460p' docs/research/2852-portalloc-phase2/plan.md"
[codex] Command completed: /bin/bash -lc "sed -n '260,460p' docs/research/2852-portalloc-phase2/plan.md" (exit 0)
[codex] Running command: /bin/bash -lc "rg -n \"fn rollback_flow|rollback_flow|release_flow\\(\" userspace-dp/src/nat/...
[codex] Command completed: /bin/bash -lc "rg -n \"fn rollback_flow|rollback_flow|release_flow\\(\" userspace-dp/src/nat/... (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/allocator.rs | sed -n '1235,1365p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/allocator.rs | sed -n '1235,1365p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '260,330p;720,840p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '260,330p;720,840p'" (exit 0)
[codex] Assistant message captured: Option A’s own deadlock warning is legitimate, but I’m not convinced by its cap argument as w...
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '840,960p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '840,960p'" (exit 0)
[codex] Running command: /bin/bash -lc 'rg -n "source_nat_decision_for_flow|match_source_nat|allocate_translation|pers...
[codex] Command completed: /bin/bash -lc 'rg -n "source_nat_decision_for_flow|match_source_nat|allocate_translation|pers... (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/session_glue/mod.rs | sed -n '320,390p;440,485p;...
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/afxdp/session_glue/mod.rs | sed -n '320,390p;440,485p;... (exit 0)
[codex] Assistant message captured: For HA reservation, Option A’s “same 5-tuple shard” claim checks out only if every reserve, r...
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '1120,1350p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '1120,1350p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '960,1015p;1015,1065p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '960,1015p;1015,1065p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/screen/mod.rs | sed -n '1045,1110p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/screen/mod.rs | sed -n '1045,1110p'" (exit 0)
[codex] Running command: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '1064,1118p'"
[codex] Command completed: /bin/bash -lc "nl -ba userspace-dp/src/nat/source.rs | sed -n '1064,1118p'" (exit 0)
[codex] Assistant message captured: I have enough code evidence for the core verdict. I’m pulling the plan’s own line numbers now...
[codex] Running command: /bin/bash -lc "nl -ba docs/research/2852-portalloc-phase2/plan.md | sed -n '1,120p;120,230p;2...
[codex] Command completed: /bin/bash -lc "nl -ba docs/research/2852-portalloc-phase2/plan.md | sed -n '1,120p;120,230p;2... (exit 0)
[codex] Running command: /bin/bash -lc 'git cat-file -e origin/master''^{commit} && git rev-parse origin/master || true'
[codex] Command completed: /bin/bash -lc 'git cat-file -e origin/master''^{commit} && git rev-parse origin/master || true' (exit 0)
[codex] Running command: /bin/bash -lc 'git merge-base --is-ancestor b4f2ddb2f HEAD; echo $? && git log --oneline --de...
[codex] Command completed: /bin/bash -lc 'git merge-base --is-ancestor b4f2ddb2f HEAD; echo $? && git log --oneline --de... (exit 0)
[codex] Assistant message captured: **Hostile Review** A. **Whack-a-mole argument: mostly correct, but overstated.** For the main...
[codex] Turn completed.
**Hostile Review**

A. **Whack-a-mole argument: mostly correct, but overstated.**

For the main committed tracked transit forward-flow install, `publish_shared_session` and `replicate_session_upsert` are synchronous and not HA-gated at the call site. After `forward_installed`, the code always calls `publish_shared_session(...)` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3136` and `replicate_session_upsert(...)` at `:3157`.

Those are real cross-worker locks:

- `publish_shared_session` locks `shared_sessions`, and for forward entries also `shared_nat_sessions` and `shared_forward_wire_sessions`, plus owner-RG index mutexes: `userspace-dp/src/afxdp/shared_ops.rs:882-943`, `userspace-dp/src/afxdp/types/mod.rs:42-46`, `shared_ops.rs:1085-1104`.
- `replicate_session_upsert` loops every peer queue and locks each `Arc<Mutex<VecDeque<WorkerCommand>>>`: `userspace-dp/src/afxdp/session_glue/mod.rs:731-740`.

They are not batched or deferred. Reverse installs also publish/replicate at `poll_descriptor/mod.rs:3452-3460`, and reverse repair does the same at `shared_ops.rs:870-877`.

But the plan’s “EVERY new flow” wording is too broad. `track_in_userspace` excludes LocalDelivery and DNS fastpath at `poll_descriptor/mod.rs:2943-2945`; admission refusal exits before publish at `:2968-2978`; MissingNeighborSeed publishes at `:5135-5141` but deliberately does not replicate, confirmed by `shared_ops.rs:51-52`. This does not collapse the kill argument, but the plan must scope it to committed tracked forward/reverse transit installs, not literally every new-flow path.

B. **Exact-cap regression: real for Option A as written, not inherent to sharding.**

Phase 1’s exact cap is real: the current allocator checks `live_by_flow.len()` under the single `live` mutex and only inserts while holding that mutex: `userspace-dp/src/nat/allocator.rs:912-931`. The file-level invariant also says this is exact and avoids the microbench’s in-flight overshoot model: `allocator.rs:24-31`.

Option A as written regresses that by using `fetch_add` reserve/rollback: `docs/research/2852-portalloc-phase2/plan.md:366-368`. The merged microbench did show the narrow-pool false-exhaustion failure for that style: `docs/research/2852-portalloc/microbench-results.md:143-154`.

But the plan overclaims that a sharded design cannot cheaply keep an exact cap. A bounded `compare_exchange` reservation counter, taken while holding the chosen flow shard after the reuse check and immediately before insert, can enforce `count <= cap` without the fetch-add overshoot. It still adds accounting complexity across `release_flow`, `rollback_flow`, stale `reserve_flow` replacement, deterministic paths, and HA imports, but it is not impossible or obviously expensive. Static per-shard sub-caps are bad under skew; summing all shard lengths per allocation is exact but defeats the point.

C. **Close #2852: yes, but do not pretend the residual is impossible to matter.**

The original issue headline is substantially fixed. Port ownership is now the atomic bitmap/CAS path (`allocator.rs:406-418`, claim used before the mutex at `:896`), while the residual mutex is the map critical section at `:912-943`. Release-side GC no longer holds the allocator mutex across a full sweep: `allocator.rs:1224-1231`, `:1556-1577`.

A CGNAT or legitimate connection-storm workload could still make the NAT map mutex material. The problem is that no full dataplane connection-rate measurement proves it dominates after publish/replication. In the current 6-worker shape, sharding NAT alone is an isolated allocator optimization sitting behind other synchronous per-new-session locks.

SYN flood is not a good Phase-2 justification. Initial SYN flood handling runs before session/NAT allocation: `poll_descriptor/mod.rs:789-817`, with cookie challenge generated in `screen/mod.rs:903-1034`. Session-miss ACK cookie validation also runs before NAT/session creation continues: `poll_descriptor/mod.rs:1377-1405`, `screen/mod.rs:1419-1479`.

D. **Option A is not plan-ready.**

The no-double-allocation invariant is plausible because the occupancy bit remains the ownership token. `reserve_flow` also uses the bit CAS before inserting the live record: `allocator.rs:1474-1504`.

But Option A is not deadlock-free as specified. The plan first says it “sidesteps” F5 (`plan.md:293-298`), then admits the release-path ABBA hazard (`:380-390`). The hazard is real: current release/rollback reads the live record to discover `persistent_key`, then mutates lease state under the same mutex: `allocator.rs:1186-1210`, `:1242-1274`. Splitting those into `flow_shard` and `leases` creates `flow_shard -> leases` unless the design mandates `leases -> flow_shard` everywhere or re-derives the persistent key before locking.

Also, Option A must explicitly cover deterministic v4/v6 and NAT64 wrapper paths, not just ordinary non-persistent SNAT. Deterministic allocation currently takes the same `live` mutex at `allocator.rs:1325` and `:1405`; NAT64 uses the same allocator through `source.rs:871-886` and reserve wrapper `source.rs:960-970`.

VERDICT: PLAN-KILL/CLOSE. Close #2852 as substantially resolved, do not adopt Option A; fix the plan’s overbroad “EVERY new flow” wording and replace the “sharding cannot preserve exact cap” claim with the narrower, correct claim that Option A’s current fetch-add design regresses F4.
```
