# Claude SMR hostile plan review — #1824 r1

Reviewer: Claude (in-conversation SMR, hostile pass). Plan: plan.md v1 @ cf0cc3f725e7.

## Verdict: PLAN-NEEDS-REVISION (2 substantive defects, 3 minors). Architecture (Option A proptest in-tree) is sound; two properties are mis-specified and would false-fail or under-assert as written.

## Findings

### F1 (HIGH, property soundness) — P-N1 "byte-for-byte incl. checksums" is unsound at the one's-complement zero boundary
One's-complement checksums have two representations of zero (0x0000 /
0xFFFF). The code deliberately maps results: rewrite/ipv4.rs:113–118 maps a
computed 0x0000 UDP checksum to 0xFFFF; rewrite/ipv6.rs:96 maps 0→0xFFFF for
ALL v6 protocols; the generic adjust path has its own keep-zero/never-zero
handling (frame/mod.rs apply_nat_ipv4 UDP `keep_zero`). A forward rewrite
whose intermediate checksum lands on the boundary produces 0xFFFF where the
original packet held the other representation; the inverse rewrite then
cannot restore the original byte. `apply_nat(apply_nat(pkt,D),inv(D)) == pkt`
byte-for-byte is therefore false on a measure-nonzero input set — proptest
WILL find it and shrink to a non-bug. Required fix: split P-N1 into
(a) tuple fields (addrs+ports) byte-identical to original, payload identical,
TTL untouched by apply_nat; (b) checksums *valid* per the P-N2 full-recompute
oracle after each hop — never byte-compared across the round trip.

### F2 (MED, property mis-specification) — P-I5 conflates two paths that source `protocol` differently
Meta-led fast path (inspect.rs:329–334) builds the key with `meta.protocol`;
the v4 frame-led path takes `protocol = frame[l3+9]` (inspect.rs:614) and
puts THAT in the key. The "meta independence" property only holds when the
generator forces `meta.protocol == frame[l3+9]`. Plan must state this
generator constraint explicitly AND add the complementary divergence case as
a pinned example (inconsistent meta.protocol → which wins is path-dependent;
that is current intended behavior per the arbitration comment, so pin it,
don't paper over it).

### F3 (MIN) — P-W1 "generated via small per-field strategies" understates the cost
ConfigSnapshot is a wide struct (zones/interfaces/routes/neighbors/NAT
rules/filters/tunnels). Hand-rolled strategies for the full shape are
~150 LOC, not ~80, or the property silently degenerates to fixture-mutation
(fine, but say which). Given §11-Q4 already invites dropping S3, the plan
should pre-commit: full-shape strategies are NOT the deliverable; mutate the
two existing fixtures field-wise or drop S3.

### F4 (MIN) — §5.4 budget arithmetic unstated for shrink worst case
max_shrink_iters: 4096 on P-N3 (two mmaps + dual rewrite per iter) means a
single failure can cost ~minutes before reporting. Acceptable (only on
failure), but the plan should say failure-path time is unbounded-ish and
that's fine; reviewers shouldn't have to derive it.

### F5 (MIN) — §6 claims "Docs: frame/README.md gains a property-tests section" — also update §1663/§1669 cross-refs
The issue comment at convergence should explicitly mark which #1669 §12
bullets this plan does NOT deliver (session-table property; cargo-fuzz) so
the umbrella's residue stays honest.

## What I verified (not just read)
- bin-only crate: no src/lib.rs; benches comment confirms internals
  unreachable → cargo-fuzz blockage claim is real, not rhetorical.
- state_writer.rs:1–192 end-to-end: persister only; encode at
  server/helpers.rs:784–806; no Rust decoder of state.json (grep) — §4.2
  premise correction is correct.
- P-N3 harness feasibility: frame/tests.rs:597/1452 already constructs
  SessionDecision + calls rewrite_forwarded_frame_in_place on
  MmapArea::new(...); compute_l4_csum_delta is pub(super) in afxdp →
  reachable from frame child module. Differential test is buildable with
  zero visibility changes.
- UDP-0 divergence flagged in plan §11-Q2 is real: v4 descriptor path skips
  when old==0 (rewrite/ipv4.rs:110 comment) and generic path keep_zero
  matches, but v6 0→0xFFFF mapping interacts with F1.
