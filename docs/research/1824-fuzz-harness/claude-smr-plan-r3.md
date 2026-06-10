# Claude SMR hostile plan review — #1824 r3 (final)

Reviewer: Claude (in-conversation SMR). Plan: v3 @ 6d3db69b5851 → v3.1.

## Verdict: PLAN-READY

## Self-correction first (required)
My r2 claim "I attempted to construct a divergence outside the excluded
byte set … and cannot" was WRONG. Codex r2 constructed one (v6 ext-headers ×
port NAT), and on verification I found the blast radius is larger than its
finding: the generic v6 NAT path's checksum adjusters also hardcode the L4
offset (`40usize.checked_add(delta)`, frame/checksum.rs:490 and 516–517),
so even address-only NAT on ext-header v6 packets writes a "checksum"
update into extension-header bytes. Root cause of my miss: I checked that
both paths use the same byte-write helpers (true) but did not check that
both paths compute the same OFFSETS to hand those helpers (false for v6 +
ext headers). Same lesson class as `feedback_verify_whole_function_body`:
the equivalence burden is the whole data flow, not the leaf writes.

## r3 verification of v3
- D3 fold: §10-D D3 quotes verified once more against source
  (frame/mod.rs:840–841; frame/checksum.rs:490/516–517;
  rewrite/ipv6.rs:35–41; rewrite_apply_v6's unused-for-NAT `rel_l4` at
  frame/mod.rs:550–555). Generator restriction (ext-header-free v6 for all
  NAT-applying properties incl. P-T4, since the splitter calls
  `apply_nat_ipv6`) is the correct research-scope treatment; fixing D3 in
  production first would couple a test-only PR to a NAT-path change and is
  properly left to the filed issue.
- P-N3b fold: prep-before-validation confirmed (frame/mod.rs:403/413 via
  :581 and rewrite/mod.rs:56); the nat64/nptv6 early decline at
  rewrite/mod.rs:51–53 is correctly the one fully-untouched case.
- Codex r3 nit accepted and fixed in v3.1: D3's `checksum.rs` citations
  disambiguated to `frame/checksum.rs` (the sibling `afxdp/checksum.rs`
  holds `compute_l4_csum_delta`).
- Codex r3 Q2 adoption: P-N3 comparisons run over the
  `InPlaceRewriteResult`-delimited output slices (offset/len), not whole
  areas, via the shared byte-mask helper in `prop_tests/oracle.rs`.

## Convergence
- Codex r3: PLAN-READY ("cannot construct a valid-input divergence inside
  the restricted domain"; no blocking findings).
- AGY r3: PLAN-READY (confirmed the D3 sites it missed in r2; "no remaining
  valid-input divergences"; "fully convergent").
- Claude SMR r3: PLAN-READY.

Recommendation stands: Option A (in-tree proptest), surfaces S1/S2/S4, S3
dropped, D1/D2/D3 filed as issues at implementation time, with D3 the
highest-value single output of this research.
