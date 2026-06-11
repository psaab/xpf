# Claude SMR plan review — #1852 r3 (hostile, self-correcting r2)

My r2 PLAN-READY was PREMATURE. I deferred the helper caller-audit to
"confirm in implementation" instead of doing it — the exact soft-pass
anti-pattern `feedback_triple_review_includes_claude_smr` warns about.
Codex r2 and AGY r2 did the audit and found two real gaps. v3 fixes both;
this r3 verifies the fixes against code.

## Verdict: PLAN-READY (Path A, v3)

### Re-verification of the two r2 gaps

- **Defect-2 helper trap (AGY critical, Codex MED).** Confirmed real:
  `packet_rel_l4_offset_and_protocol` is read by `gre.rs:149`
  (`try_native_gre_decap_from_frame` — forwards the fragmented inner
  packet) and `tunnel.rs:256` (`local_origin_packet_meta`). Returning
  `None` on a fragment there would drop legitimately-forwardable
  fragmented IPv6-in-GRE and local-origin fragments. v3 correctly
  ABANDONS the helper change and gates `clamp_tcp_mss` directly (both
  families), leaving the shared helper untouched. This is the right
  scoping: the clamp is the only MUTATING consumer; the readers keep their
  offset. Correct.

- **SNAT allocator leak (Codex MED-HIGH).** Confirmed real:
  `source_nat_decision_for_flow` (`poll_descriptor/mod.rs:1146`) allocates
  and assigns `decision.nat` (`:1156`) BEFORE any rewrite leaf, so a
  leaf-only gate cannot stop the per-fragment pool-port allocation. v3
  adds the pre-allocation gate (S11) and a documented policy (Q6: drop
  dynamic-pool-SNAT non-first fragments). Correct — and it cleanly
  separates address-only NAT (static/interface, IP-rewrite-all works)
  from port-translating dynamic SNAT (cannot map without reassembly →
  drop).

### Residual checks

- The Q6 "drop dynamic-pool-SNAT non-first fragments" policy is the only
  defensible answer without reassembly, and it does not regress today
  (today those fragments are corrupted + leak; dropping is strictly
  better). It needs the user's sign-off as a behavior choice, which is
  exactly what an Open Question is for — not a blocker.
- v3's static/interface-NAT IP-rewrite-all path is unchanged from v2 and
  was confirmed checksum-correct by both reviewers in r1/r2.
- The descriptor fall-back, threaded predicate, segmentation admission
  gate, embedded-v4 guard, and S5/A′ corrections are all carried forward
  intact.
- Signature-propagation caution (r2): `apply_nat_*` gains a
  `non_first_fragment` param → update the #1842 prop-harness callers in
  the same commit. Implementation note, not a plan defect.

## Bottom line

v3 is the minimal correct fix and now covers the pre-allocation leak and
preserves GRE/tunnel fragment forwarding. PLAN-READY from the SMR seat.
Convergence pending Codex r3 + AGY r3 confirming the v3 fold. Q6 is a
behavior decision for the user (drop dynamic-SNAT non-first fragments).
