# Claude SMR hostile plan review — #1824 r2

Reviewer: Claude (in-conversation SMR). Plan: v2.1 @ 86e6b1a5e9f1.

## Verdict: PLAN-READY (one substantive finding, found and fixed during this pass — folded as v2.1; no remaining blockers I can construct a counterexample for).

## F1 (HIGH, found this round, fixed in v2.1) — v2's P-N3 still byte-compared the v4 IP-header checksum; that comparison is unsound by the same RFC 1624 ambiguity as the L4 case
Verified against source: descriptor path folds `!old_csum +
rd.ip_csum_delta + 0xFEFF` in a single pass (rewrite/ipv4.rs:79–91);
generic path chains three `checksum16_adjust` calls with intermediate
`checksum16_finish` refolds (checksum.rs:291–312, each `adjust` re-folds via
checksum16_finish). End-around-carry addition preserves the sum mod 0xFFFF,
but when the total ≡ 0 (mod 0xFFFF) the surfaced 16-bit representative can
be 0x0000 in one evaluation order and 0xFFFF in the other, so the
complemented stored bytes can legally differ between paths on ~2⁻¹⁶ of
valid inputs. Random testing at 128 cases would almost never hit it — but
shrinking toward minimal/extremal values makes the boundary MORE likely over
the harness's lifetime, which is the worst failure mode: a years-later flaky
red that looks like a NAT bug. v2.1 excludes ALL checksum fields from
byte-equality and validity-oracles them instead. I attempted to construct a
divergence outside the excluded byte set (addresses/ports/TTL/payload/other
header bytes) and cannot: both paths write identical values to those fields
by construction (same `write_ipv4_*`/`write_l4_*` byte-write helpers,
byte_writes.rs, called with the same rd/nat values; TTL decrement identical).

## Checks on the v2 fold of Codex/AGY r1 (hostile re-verification, not re-crediting)
- S3 drop: re-confirmed `ConfigSnapshot` derive list at protocol/snapshot.rs:182
  has no PartialEq; drop is forced, tombstone text accurate.
- P-N1 undo: nat/mod.rs:70–77 re-read — `reverse()` maps
  `rewrite_src ← rewrite_dst.map(|_| original_dst)`; using it as a
  same-packet inverse would swap-corrupt. v2 text now defines the harness
  undo field-by-field. Correct.
- P-N3b decline examples: frame/mod.rs:495 confirms the generic path also
  declines TTL≤1 — v1's "generic is only writer" claim is gone. Correct.
- flow_cache gates: should_cache at flow_cache.rs:221–226 excludes
  nat64/nptv6/non-TCP-UDP — the descriptor decline test's "never built in
  production" note is accurate.
- arb_v6_ext_chain: inspect.rs:50 loop bound `for _ in 0..6` — the >6-chain
  case pins the documented post-loop `Some(offset)` return (line 80), which
  is itself a slightly surprising behavior (returns an offset pointing at an
  unconsumed extension header). Worth one explicit example documenting that
  consequence; covered by the strategy spec as written.

## Residual risks I accept
- P-N3's byte-equality-except-checksums could still calcify a future
  intentional divergence (e.g. a deliberate descriptor-path optimization
  that reorders writes). Acceptable: the property compares *results*, not
  write order, and any intentional semantic divergence SHOULD be a loud
  test-visible event.
- The ≤10s budget is a target, not a measurement; §5.4 contains the
  halving rule if it misses. Fine for a plan.

PLAN-READY. Awaiting Codex r2 + AGY r2 on v2.1 for convergence.
