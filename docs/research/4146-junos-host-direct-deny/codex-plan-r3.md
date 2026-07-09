# Codex hostile plan-review r3 (on plan r5) — verbatim final output

Final output
Read-only result: four prior defects are closed; one remains open.

1. **STILL-OPEN — effective tier composition.** Rust evaluates exact → `from_any_index` → global ([policy.rs:2978](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/policy.rs:2978), [policy.rs:3014](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/policy.rs:3014), [policy.rs:3050](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/policy.rs:3050)). Although r5 acknowledges that order, its operative builder assembles only exact + global ([plan.md:214](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:214)). Thus a representable from-any deny is omitted, while `from-any permit any; global deny any` incorrectly renders the global drop.

2. **RESOLVED — global-any ingress scope.** Every global-any term is rendered per concrete zone using only that zone’s non-lifeline `iifname`s, never unscoped ([plan.md:237](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:237)); Rust likewise bypasses unzoned ingress at `from_id == 0`.

3. **RESOLVED — fine permit cannot re-admit.** Rust requires coarse admission first ([mod.rs:138](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:138)). r5 emits no fine `accept`; permits only subtract from later drops, so every surviving packet still faces the coarse gate ([plan.md:224](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:224)).

4. **RESOLVED — ND/PMTUD.** Rust coarse-admits these packets ([host_inbound.rs:484](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/forwarding/host_inbound.rs:484)) and then runs fine policy. r5 correctly places fine drops before the ND/PMTUD accepts ([plan.md:366](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:366)).

5. **RESOLVED — `tcp-rst`.** Plain denied TCP generates an RST when the ingress zone has `TCPRst` ([reject_reply.rs:102](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:102)); r5 makes the entire affected program unrepresentable, avoiding silent-drop divergence ([plan.md:335](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:335)).

The chain’s fine-eligibility domain also needs correction: placing every fine drop before coarse rules converts the existing `ident-reset` TCP/113 RST into a silent drop ([daemon_nft.go:688](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_nft.go:688)), while Rust’s pre-fine IPsec stage bypasses fine policy for coarse-admitted IKE and ESP-in-UDP/NAT-T ([poll_stages.rs:875](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_stages.rs:875)). Neither counterexample uses deferred reject or source-restricted permit.

The single required revision is to define the effective program as the complete fine-eligible decision function: exact → from-any → applicable global under one gate, with pre-fine terminal/exempt classes preserved ahead of DROP or made unrepresentable. Until then, the DENY slice can over-deny, under-deny, change an RST into a drop, and black-hole IPsec.

PLAN-REVISE

