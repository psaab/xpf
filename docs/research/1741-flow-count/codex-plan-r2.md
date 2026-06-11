Codex Task started in the background as task-mq91ul6e-5ylq0v. Check /codex:status task-mq91ul6e-5ylq0v for progress.
CODEX_TASK_ID=task-mq91ul6e-5ylq0v
**Findings**

- LOW: `agy-impl-reference.patch` is not literally compile-ready as stored if reused verbatim. It changes `count_active_flows(&self)` to `&mut self`, but [flow_cache_tests.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache_tests.rs:1642) still has `let cache = FlowCache::new();`. Trivial Phase 2 fix: make that binding mutable. Not a design blocker because the v2 plan already requires test-helper agreement.

**Verdict: PLAN-READY**

I found no verified counterexample to Path A or the v2 mechanism narrative.

Verified against code:

- FIN/RST exclusion is real: [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache.rs:216) requires `tcp_flags & 0x17 == 0x10`, so FIN/RST miss fast path. Slow-path cache population ignores TCP flags via `should_cache` at [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache.rs:221), creates entries with `last_used_epoch: 0` at [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache.rs:373), and same-key insert replaces at [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache.rs:689).

- Final client ACK restamp is plausible and matches code. The fast-path gate is before slow path at [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/poll_descriptor/mod.rs:209), `stage_flow_cache_hit` looks up `&flow.forward_key` at [flow_cache_hit.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:94), and lookup writes `entry.last_used_epoch = now` at [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache.rs:664). I did not verify iperf3 with tcpdump here, but for client-active TCP close the final ACK has ACK set and FIN/SYN/RST clear, so it is eligible.

- RST teardown is production-dead: [session_glue/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/session_glue/mod.rs:621) unconditionally returns `false`; the only push to `scratch_rst_teardowns` is behind that predicate at [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1905). The lifecycle invalidation at [worker/lifecycle.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/worker/lifecycle.rs:227) is therefore unreachable unless that predicate changes.

- No tick-without-scan production path found. Hot and idle paths both call `publish_binding_debug_state` at [debug_state.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/umem/debug_state.rs:44) and [debug_state.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/umem/debug_state.rs:53); publish does `tick_advance_epoch()` then immediately `active_flow_debug_entries(...)` at [debug_state.rs](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/umem/debug_state.rs:230).

- The repro patch applies cleanly with `git apply --check`. I could not apply/run `cargo test --release issue_1741_clean_close_choreography_still_ghosts` in this read-only sandbox, but the test’s epoch math does produce 10 wrap resurrections on current code.

- The 3-of-6 scrape attribution is properly hedged in v2: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/docs/research/1741-flow-count/plan.md:121) says mechanism/shape are proven, but specific per-scrape attribution is plausible, not demonstrated.

No PLAN-KILL basis found.

Codex session ID: 019eb520-5393-7d63-9f6c-a75672a62fb3
Resume in Codex: codex resume 019eb520-5393-7d63-9f6c-a75672a62fb3
