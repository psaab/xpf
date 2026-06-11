# Claude SMR plan review — #1852 r2 (hostile)

Reviewing plan v2 after the round-1 fold (Codex + AGY + my r1). Posture:
still hostile — checking that the fold is faithful and that v2 didn't
introduce a new wrong claim.

## Verdict: PLAN-READY (Path A)

The v2 revision faithfully folds every round-1 finding and the corrections
are code-grounded. Re-verification of each:

- **Port-write retraction (§4b)** — correct. `nat/source.rs:478-498`
  allocates and emits `rewrite_src_port: Some(...)` on the cold path,
  gated only by an IP/zone match (`source.rs:151`), no session lookup.
  `nat/destination.rs:120-121` wildcard DNAT emits `rewrite_dst_port:
  Some(...)`. My r1 narrowing was wrong; v2 is right and the SNAT
  port-leak escalation (§5) is the correct operational headline.
- **Shim partial-drop (§4a)** — correct and appropriately scoped: it
  narrows (≈31% TCP + short frags drop at `lib.rs:1396-1400` /
  `read_bytes`) without eliminating large-payload fragments. Honest.
- **S10 segmentation (§3/§7)** — correct: `meta.protocol` for a non-first
  TCP fragment is `PROTO_TCP`, the admission gate is fragment-blind, so
  the explicit no-segment gate is needed. Good.
- **Defect-2 helper trap (§4e/§7)** — correct and important: the naive
  swap to `packet_rel_l4_offset_and_protocol` would re-introduce the
  corruption because that helper walks past header 44 without an offset
  check (`inspect.rs:184-188`). v2's fragment-aware-helper fix is the
  right shape and matches the #1853 `parse_embedded_v6_l4` precedent
  exactly. The added caller-audit (GRE inner, `parse_tcp_reply_source`)
  is the correct diligence — `None` is the right answer for all of them.
- **F1 threaded predicate** — folded (orchestrator computes once, threads
  `non_first_fragment: bool`). Removes the double-walk. Good.
- **F2 descriptor fall-back** — folded with the confirmed call site
  (`flow_cache_hit.rs:264-280` `.or_else(rewrite_forwarded_frame_in_place)`).
  Parity preserved by construction.
- **F3 S5** — re-graded LOW with the correct no-cross-fragment-state
  rationale (shim is stateless per-packet, `lib.rs:646`).
- **F4 / A′** — corrected: parse_ipv4 does not read frag_off today; `0x40`
  is a free meta_flags bit. A′ is a real reserve.
- **S9 nit** — folded (own guard, not parse-path inheritance; line range
  fixed to 7-119).

## One residual caution (not blocking)

The `apply_nat_ipv4`/`apply_nat_ipv6` signature change adds a parameter to
functions the #1842 prop harness calls directly (`prop_tests/rewrite.rs`
`apply_nat_family`). The implementation must update those test callers in
the same commit as the signature change (the trio plan hit the identical
issue — AGY r1 finding 3 there). The plan's §9 already extends the harness;
just flag the signature-propagation explicitly at /engineer time. Not a
plan defect.

## Bottom line

v2 is internally consistent, code-grounded, and the path is the minimal
correct fix. Path A with the threaded predicate, descriptor fall-back,
segmentation gate, fragment-aware inspect helper, and the embedded-v4
guard. PLAN-READY from the SMR seat. Convergence depends on Codex r2 and
AGY r2 confirming the fold.
