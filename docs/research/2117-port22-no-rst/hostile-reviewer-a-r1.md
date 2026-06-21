# Hostile plan reviewer A (independent Claude) — r1 — #2117

VERDICT: **PLAN-KILL CORRECT** (with one minor traceability NEEDS-REVISION note
that does not affect the kill)

Findings (independently verified against source):

1. `dscp-filter` IS bound as an input filter on the untrust ingress (ge-0/0/1).
   `test/incus/xpf-test.conf:20-26`.
2. `term block-ssh` matches TCP/22 and acts `discard`; port 22 is the ONLY TCP
   dport discarded. `xpf-test.conf:404-413`; matcher `filter/engine/matching.rs:
   30-61`, `PortMatcher::Single(22)` `filter/mod.rs:121`; first-match-wins
   `filter/engine/eval.rs:205-225`; 8080 only in DNAT (conf:341/348).
3. `FilterAction::Discard` is a silent drop. `filter/mod.rs:31-41`.
4. Input filter runs BEFORE the policy reject path and short-circuits on
   non-Accept. `poll_descriptor/mod.rs:659-677`; reject sites at mod.rs:1759 and
   mod.rs:2417; helper returns raw FilterAction (`poll_descriptor/filter.rs:
   84-124`) so Discard and Reject both recycle+continue.
5. `build_reject_rst_frame` is port-AGNOSTIC and the unit test
   `reject_tcp_with_egress_enqueues_rst` (`reject_reply.rs:168-205`, dst_port=22
   at L89) asserts the RST IS enqueued — the code literally proves a :22 SYN
   reaching the reject path produces a RST.
6. No port-22/SSH special-casing in the dataplane (only name-normalization
   tables `filter/compiler.rs:447`, `policy.rs:1169`).
7. host-inbound `system-services { ssh }` does NOT divert transit :22
   (local-delivery is disposition-driven; dst is the trust-HOST, transit; and
   the filter discards :22 before resolution).
8. NEEDS-REVISION (minor, non-kill-breaking): `docs/smoke/security-matrix-
   2026-06-20.md` is UNTRACKED (not on origin/master); plan §6.2 "amend the
   smoke doc" targets a non-version-controlled file — the closure note needs a
   durable target.

Summary: the kill is correct; every code-level assertion holds against
independently-read source. The only revision warranted is bookkeeping (durable
target for the closure note).
