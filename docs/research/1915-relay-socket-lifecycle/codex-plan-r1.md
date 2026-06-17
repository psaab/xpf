EXIT=0
- **Nit but real: the daemon line evidence is wrong.** The plan says DHCP relay wiring is at `daemon_run.go:640-641` at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1915-research-relay-socket-lifecycle/docs/research/1915-relay-socket-lifecycle/plan.md:77). In this checkout, 640-641 are unrelated session-sync comments; relay wiring is actually [daemon_run.go:875-878](/home/ps/git/bpfrx/.claude/worktrees/1915-research-relay-socket-lifecycle/pkg/daemon/daemon_run.go:875). Fix the evidence.

What is not a blocker: `serverConn` does not need `REUSEPORT` because it binds `giaddr:0`; it does need cancel close, and the plan has that. Double-close of `*net.UDPConn` is safe if errors are ignored. A1 itself is the right mechanism for pre-bind `SO_REUSEADDR`/`SO_REUSEPORT`/`SO_BINDTODEVICE`.

The plan needs another revision before implementation.
