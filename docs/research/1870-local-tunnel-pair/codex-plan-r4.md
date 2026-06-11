===RESULT===
**Findings**

1. **Low:** r3-2 is mostly folded, but two body shorthands still say “no worker-RX consumer” too absolutely: [plan.md:201](/home/ps/git/bpfrx/.claude/worktrees/1870-research/docs/research/1870-local-tunnel-pair/plan.md:201) and [plan.md:300](/home/ps/git/bpfrx/.claude/worktrees/1870-research/docs/research/1870-local-tunnel-pair/plan.md:300). §2.3’s precise statement is correct: worker RX has exact-key lookup, normal local-origin traffic never reaches it, and default NAT has no forward-wire alias. These later lines should say “no normal local-origin worker-RX consumer/path” or refer back to §2.3.

Confirmed: r3-1’s full-pair self-heal wording is narrowed correctly, and §5 test 1 now correctly uses exact forward-key lookup and forbids `find_forward_wire_match`.

PLAN-NEEDS-CHANGES

Codex session ID: 019eb8bc-bffd-7590-ba84-c5dd36e9310f
Resume in Codex: codex resume 019eb8bc-bffd-7590-ba84-c5dd36e9310f
