===RESULT===
`gh issue view 1870` was attempted, but the sandbox blocked GitHub network access: `socket: operation not permitted`.

**Findings**
1. **Critical:** Path A does not fix the plan’s claimed HA bulk-export residue. Local-tunnel entries are `SyncImport` ([tunnel.rs:191](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/tunnel.rs:191), [shared_ops.rs:664](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/shared_ops.rs:664)); `SyncImport` is `is_peer_synced()` ([entry.rs:75](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/entry.rs:75)); owner-RG export skips peer-synced origins ([session_glue/mod.rs:427](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs:427), [session_glue/mod.rs:439](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs:439)). So installing these entries into `SessionTable` still will not bulk-export them. The plan must either de-scope HA bulk export or redesign origin/export semantics.

2. **Medium:** Observability docs are stale under Path A. The Prometheus descriptor explicitly says `session_create_drops` covers “UpsertLocal replicas” ([metrics_descriptors.go:553](/home/ps/git/bpfrx/.claude/worktrees/1870-research/pkg/api/metrics_descriptors.go:553)), and the session README says the same ([README.md:94](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/README.md:94)). If Path A makes `UpsertLocal` uncapped, the plan’s “no Go-side” claim is wrong.

3. **Medium:** Test plan misses the failing HA assertion that would catch finding 1. Existing export tests prove only local `ForwardFlow` exports ([session_glue/tests.rs:2083](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/tests.rs:2083)) and demoted/peer-synced entries do not ([session_glue/tests.rs:2962](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/tests.rs:2962)). Add an `UpsertLocal(SyncImport)` export pin and decide the expected behavior explicitly.

4. **Low:** Add a producer/fan-out pin, not only a single rigged worker queue. The defect is per-worker: producer pushes the pair to every worker queue ([tunnel.rs:322](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/tunnel.rs:322)), and each worker applies against its own `SessionTable` ([session_glue/mod.rs:459](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs:459)). A two-worker cap/below-cap test would pin the divergence class directly.

**Checks**
I did not find a missed below-cap table-install divergence: both paths remove, allocate epoch, write the same fields, index, and push the wheel ([session/mod.rs:774](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs:774), [session/mod.rs:860](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs:860)). `allow_replace_local=true` is correct for preserving current `UpsertLocal` replacement semantics: current install has no local-clobber guard, and local-tunnel production already requires HA-enforced `ForwardCandidate` ([tunnel.rs:159](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/tunnel.rs:159)).

`create_drops` is genuinely shipped for today’s at-cap `UpsertLocal`: the apply arm calls capped install ([session_glue/mod.rs:556](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs:556)), cap refusal increments it ([session/mod.rs:758](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs:758)), and worker/status export carries it ([loop_body/mod.rs:198](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:198), [helpers.rs:148](/home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/server/helpers.rs:148)).

Close-as-fixed is not the better verdict: #1871 fixed visibility, not the shared-map/worker-table disagreement. Path A is still plausible for that narrower defect, but the current plan overclaims HA bulk-export repair.

PLAN-NEEDS-CHANGES

Codex session ID: 019eb8a6-245e-7c73-9273-edd6b562ab1c
Resume in Codex: codex resume 019eb8a6-245e-7c73-9273-edd6b562ab1c
