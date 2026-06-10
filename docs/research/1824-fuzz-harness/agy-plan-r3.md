# AGY adversarial plan review — #1824 r3 (final)

Job: adversarial-review-mq8f4t3l-0dz8k8. Plan reviewed: v3 @ 6d3db69b5851.
AGY explicitly confronted and CONFIRMED the D3 counterexample sites it missed in r2. Verbatim (tool-narration stripped):

PLAN-READY

- **Finding 1**: Confirm: [frame/mod.rs:840-841](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/mod.rs#L840-L841) (`apply_nat_port_rewrite(packet, 40, ...)`) and [checksum.rs:490](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/checksum.rs#L490)/[checksum.rs:517](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/checksum.rs#L517) (`40usize.checked_add(delta)`) hardcode the L4/checksum offset to 40. This diverges from [rewrite/ipv6.rs:35-41](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/rewrite/ipv6.rs#L35-L41) which parses actual extension headers, confirming D3.
- **Finding 2**: Confirm: [frame/mod.rs:403/413](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/mod.rs#L403) via [frame/mod.rs:581](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/mod.rs#L581) and [rewrite/mod.rs:56](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/rewrite/mod.rs#L56) write the Ethernet header in `rewrite_prepare_eth*` before TTL or port checks. Decline assertions must be corrected to bytes-from-L3-onward as folded in P-N3b.
- **Finding 3**: Confirm: [rewrite/mod.rs:52-54](file:///home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz/userspace-dp/src/afxdp/frame/rewrite/mod.rs#L52-L54) declines `nat64`/`nptv6` before prep, leaving the frame fully untouched (unlike the post-prep TTL/port checks), which is correctly captured in P-N3b(c).

Q1: Yes, v3 completely folds both findings, and no remaining valid-input divergences can be constructed inside the v3-restricted domain.
Q2: Nothing else is blocking, the plan is fully convergent.
