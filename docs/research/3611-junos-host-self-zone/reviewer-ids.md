# #3611 research — reviewer task-ID ledger

Three plan reviewers (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer; it joins the quad at `/engineer` time on the code PR.

| Reviewer | Round | Task/Job ID | Verdict | Notes |
|----------|-------|-------------|---------|-------|
| Claude SMR | r1 | in-conversation (this session) | PLAN-DEFER (Piece B buildable) | `claude-smr-plan-r1.md`; hostile, failed KILL attempt |
| Codex | r1 | agent afe078619db1839c9 | PLAN-DEFER + BLOCKER | existing `xpf_dp_rst` output chain / priority invariant; exact-gate-or-KILL; oifname lab gate; M03 split PASS |
| AGY | r1 | adversarial-review-mr1vqaze-dg80s0 | Piece A KILL/doc-only; Piece B READY | `agy-plan-r1.md`; ALG gate rejects ~90% configs; oifname VRF-unsound |

Converged r2 disposition: PLAN-DEFER (split) — Piece A (from-zone junos-host,
host-originated) document-only/not-recommended; Piece B (to-zone junos-host
GLOBAL, host-inbound) buildable, split into its own issue. See plan.md §12.
</content>
