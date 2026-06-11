I will start by listing the contents of the target directory to verify the presence of the plan and the previous review file.
I will read the previous review report `agy-plan-r2.md` and the updated plan `plan.md` to understand the v3 revisions, the test cases, and the design claims. I will also search for `tunnel.rs` to locate the source code we need to verify.
I will view the previous review report `agy-plan-r2.md` to verify the findings from round 2.
I will find the exact path of `tunnel.rs` and search for the TX path logic around lines 72-101.
I will list the top-level directory contents of the worktree to understand its structure.
I will search for `allow_unseeded_tunnel_local` in the `userspace-dp` directory to find `tunnel.rs`.
I will search for `build_local_origin_tunnel_tx` in `userspace-dp` to locate the tunnel transaction logic.
I will view the `userspace-dp/src/afxdp/tunnel.rs` file around lines 70 to 120 to verify the local-origin tunnel TX path.
I will search for the location of `poll_descriptor` in the repository.
I will search for `poll_descriptor` files inside our specific worktree to avoid other worktree references.
I will view the `userspace-dp/src/afxdp/poll_descriptor/mod.rs` file to verify the RX resolution claims.
I will view `userspace-dp/src/afxdp/poll_descriptor/mod.rs` around lines 240-275 to find the `resolve_flow_session_decision` call.
I will search for the definition of `resolve_flow_session_decision` to see how it resolves hits from the shared maps.
I will search for `resolve_flow_session_decision` inside `session_glue/mod.rs` to find the exact line range where it is defined.
I will run the search again with `MatchPerLine` set to true to retrieve line numbers.
I will view `userspace-dp/src/afxdp/session_glue/mod.rs` starting from line 878.
I will view the test plan section in the plan to read the specification for test 4b.
I will view `userspace-dp/src/session/mod.rs` around lines 748 to 780 to verify the behavior of the old capped install path.
I will view `userspace-dp/src/session/mod.rs` around lines 834 to 885 to verify the behavior of `upsert_synced_with_origin`.
I will view `userspace-dp/src/afxdp/session_glue/promote.rs` to verify how `should_keep_synced_hit_transient` and `is_translated_forward_session_key` are defined and how they interact with `NatDecision::default()`.
I will search for `struct NatDecision` to verify its fields.
I will view `userspace-dp/src/nat/mod.rs` around line 48 to inspect the fields of `NatDecision`.
I will view lines 780 to 815 of `userspace-dp/src/session/mod.rs` to see the delta push logic in the capped install path.
I will search for `UpsertLocal` in `userspace-dp/src/afxdp/tunnel.rs` to see how it is created and if the origin is always peer-synced.
I will view `userspace-dp/src/afxdp/tunnel.rs` around lines 280 to 340.
I will view lines 140 to 240 of `userspace-dp/src/afxdp/tunnel.rs` to verify that `session_entry` and `reverse_session_entry` are created with a peer-synced origin.
I will search for `is_peer_synced` in `entry.rs` to verify the origin classifications.
I will view `userspace-dp/src/session/entry.rs` around line 78 to see the origin classifications.
I will view lines 40 to 69 of `userspace-dp/src/session/entry.rs` to see the complete set of `SessionOrigin` enum variants.
I will search for `is_transient_local_seed` in `userspace-dp/src/session/entry.rs`.
I will view lines 96 to 120 of `userspace-dp/src/session/entry.rs`.
I have completed the Round 3 confirmation review of the implementation plan [docs/research/1870-local-tunnel-pair/plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/docs/research/1870-local-tunnel-pair/plan.md). 

### 1. Revision-Header Fold & Section Verification

*   **TX Path / RX Resolution Claim Verification:**
    *   Spot-checked [userspace-dp/src/afxdp/tunnel.rs:72-101](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/tunnel.rs#L72-L101): Confirmed that local-origin packets read from the `tun` device build a TX request and enqueue directly to TX via the coordinator, completely bypassing the worker-side RX resolution.
    *   Spot-checked [userspace-dp/src/afxdp/poll_descriptor/mod.rs:121,257](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L121) and [userspace-dp/src/afxdp/session_glue/mod.rs:878-970](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L878-L970): Inbound reply packets decapped by the worker RX loop traverse `resolve_flow_session_decision` where hits in the shared scope are reactively materialized via `materialize_shared_session_hit`.
    *   Verified that `should_keep_synced_hit_transient` evaluates to `false` for default `NatDecision` sessions (which carry no rewrite addresses, as defined in [userspace-dp/src/nat/mod.rs:48-52](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/nat/mod.rs#L48-L52)), proving the RX self-healing path for the reverse entry is infallible and will not be blocked.
*   **At-Cap same-key replacement (Test 4b):**
    *   Verified that `install_with_protocol_with_origin` performs the cap check first ([userspace-dp/src/session/mod.rs:758](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L758)), blocking stale key replacement at capacity.
    *   Verified that `upsert_synced_with_origin` does not have capacity checks and calls `remove_entry(&key)` ([userspace-dp/src/session/mod.rs:860](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L860)) before inserting the new entry. Thus, if a same-key entry exists at capacity, the total table length `len()` decreases by 1 and then returns to `cap` on insertion, maintaining `len() == cap` exactly without growth. Test 4b pins this behavior correctly.

### 2. Remaining Findings

None. The v3 revisions correctly fold all previous findings.

### 3. Verdict

PLAN-READY
