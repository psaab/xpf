PLAN-READY

I could not produce a tunnel-marked transit delivery trace that depends on kernel slow-path reinjection.

Key evidence:

- Successful tunnel transit is userspace encapsulation: [frame/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/frame/mod.rs:264) dispatches nonzero `tunnel_endpoint_id` to WG or GRE encapsulation, and [gre.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/gre.rs:299) builds the native GRE outer frame.
- WG worker cold path does not deliver: [frame/wg.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/frame/wg.rs:98) calls `try_encap`; [frame/wg.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/frame/wg.rs:100) handles `NoSession`, requests handshake, then returns `None`.
- The supposed kernel shuttle also does not deliver pre-handshake: [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/wg_control.rs:581) calls the same `try_encap`; [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/wg_control.rs:592) handles `NoSession` by arming handshake and dropping.
- The chokepoint placement is correct: [slow_path.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156) handles `local_tunnel_deliveries` first and returns; [slow_path.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:198) then proceeds toward generic `slow_path.enqueue`.
- The current slow-path doors are fallback/exception paths, not required delivery paths: e.g. FabricRedirect fallback at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs:225), build-failure fallback at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs:575), and non-forward reinjection at [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2763).

No new telemetry hole found. `record_slow_path_accept` only increments counters in [umem/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/umem/mod.rs:921). Go/Rust consumers aggregate or print those counters, e.g. [statusfmt.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/statusfmt.go:273) and [monitor.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/monitoriface/monitor.go:452). I found no control path requiring slow-path accepts for tunnel-marked frames.

Implementability is clear. The Go builder already imports `pkg/config` and currently assigns positional ids at [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/tunnels.go:92). Rust has both apply surfaces needed for R-D: full reconcile assigns `new_forwarding` at [snapshot.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:60), runtime refresh assigns at [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/mod.rs:1014), and existing delete machinery is available via [runtime.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/runtime.rs:246) and [delete_synced.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:9).

No files modified by me. The worktree currently shows a pre-existing/concurrent `plan.md` doc diff and untracked `claude-smr-plan-r4.md`; I did not touch them.

Codex session ID: 019eb91f-ddfa-74b0-bc48-9751a110cd39
Resume in Codex: codex resume 019eb91f-ddfa-74b0-bc48-9751a110cd39
