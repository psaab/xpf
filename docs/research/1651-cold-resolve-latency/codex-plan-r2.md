**Verdict: PLAN-NEEDS-REVISION**

Confirmed resolved:
- Codex-r1 MEDIUM is resolved: §2 now correctly says warmer covers route next-hops **and fabric peers**, and code confirms `snapshot.fabrics` enqueue at `userspace-dp/src/afxdp/coordinator/mod.rs:733`.
- Codex-r1 LOW is resolved: §2 now includes representative `QUEUE`, `REDRIVE`, and `DROP_TIMEOUT` raw lines.

AGY adjudication:
- CAP_NET_RAW: I concur. For this shipped root appliance deployment, it is not a Path-C showstopper. The risk is real for a cap-dropped future model, but not for the current xpfd/xpf-userspace-dp deployment.
- Dead-host queue starvation: I agree the hazard is real and B3 should be the recommended shippable deliverable.
- Dynamic-neighbor leak and missing `SO_RCVBUF`: I concur these are real cache-correctness issues, but correctly spun out of #1651 latency scope.

Remaining blocker:
- [plan.md:46](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:46) still says the recommendation is Path C plus optional **B1**, while [plan.md:395](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:395) says Path C paired with **B3**. The decision matrix repeats the stale disposition at [plan.md:481](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:481) and [plan.md:486](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:486).
- [plan.md:433](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:433) validation covers Path C/B1/A but omits B3, despite B3 being the recommended code deliverable.

Fix is small: propagate “Path C for live-resolve latency + B3 negative-cache as the recommended shippable code change; B1 optional polish” into §0, §8, and §11.

Codex session ID: 019e7453-2dd6-7281-a4af-26a1b13db7af
Resume in Codex: codex resume 019e7453-2dd6-7281-a4af-26a1b13db7af
