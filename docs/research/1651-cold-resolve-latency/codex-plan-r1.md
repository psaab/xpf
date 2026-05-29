Verified checkout: `research/1651-cold-resolve-latency` at `d135f65e`, with `origin/master` at `a107e7489`.

**Verdict: PLAN-NEEDS-REVISION**

The core conclusion survives: I do not have a verified counterexample that kills Path C, and I do not see evidence that Path A should be built now. But the plan still has one material accuracy issue around warmer scope, plus one evidence-packaging gap that matters for a twice-reopened issue.

**Findings**

**MEDIUM — Warmer scope is misstated; routed cells remain non-load-bearing.**  
[plan.md](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:147) says the warmer warms “route next-hops only.” That is false. Code also warms fabric peers:

> `for fabric in &snapshot.fabrics { enqueue(fabric.parent_ifindex, fabric.peer_addr); }`

at [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/coordinator/mod.rs:733).

This does not break the on-link-host conclusion if the tested host is not a fabric peer, and the plan says `GATEM1651 QUEUE` fired per on-link connect. But the plan should say “route next-hops and fabric peers,” then explicitly state the on-link target was neither. The routed cells are correctly caveated later as warmer-eligible at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:194), so they should stay corroborating only.

**LOW — Add representative raw QUEUE/REDRIVE/DROP_TIMEOUT snippets.**  
The methodology is basically sound because `lookup_neighbor_entry` checks static/Go-pushed neighbors first, then dynamic neighbors:

> `state.neighbors.get(...)` before `dynamic_neighbors.get(...)`

at [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/forwarding/mod.rs:1529).

So if Go-push or stale `dynamic_neighbors` had made the path warm before forwarding, `MissingNeighbor` would not have fired. The plan’s `QUEUE` claim is therefore load-bearing. For this issue history, include 2-3 raw lines showing on-link `QUEUE next_hop=<host>`, matching `REDRIVE`, and dead-host `DROP_TIMEOUT held_us≈800740 attempts=3`.

**Answers To Required Points**

1. Measurement: sound for on-link live hosts; routed cells may be warm because gateways are warmer-eligible. Go-push/stale dynamic cache is ruled out only for trials where `QUEUE` fired.

2. On-link-host cell: yes, genuinely cold if the target is not a fabric peer. Code sets connected-route `next_hop` to the destination host at [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/forwarding/mod.rs:1220) and [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/forwarding/mod.rs:1231); warmer iterates route `next_hop`s, not connected-route destinations, at [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/coordinator/mod.rs:713).

3. Path C vs B3: Path C is right for live cold-resolve. B3 is not demanded by the live-target evidence, but if the operator’s “slow” cases are unreachable/repeated dead hosts, disposition should switch to B3. The plan already says that at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/docs/research/1651-cold-resolve-latency/plan.md:333).

4. Path A conditional-KILL: justified. Current code already probes immediately on first miss at [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2413), retries at 10/60/260 ms at [neighbor_dispatch.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/neighbor_dispatch.rs:33), and only times out unresolved packets after the computed 800 ms fast timeout at [forwarding_build/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/forwarding_build/mod.rs:401). I found no verified topology in this evidence where active XSK-TX resolution clearly wins; fresh Gate-M’ on a failing topology is the right gate.

Codex session ID: 019e744d-d8ab-7323-979b-e4d6d10b4360
Resume in Codex: codex resume 019e744d-d8ab-7323-979b-e4d6d10b4360
