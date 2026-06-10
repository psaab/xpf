# Claude SMR hostile plan review — round 2

Target: plan.md v2 (`91f993f6f886`). Scope: re-verify the v2 folds only
(§5.5 rule, §5.6 split, §5.7 icmp_embed, §11 resolutions), hostile worked
traces per `feedback_race_window_worked_trace`.

## Verdict

**PLAN-READY** (all three defects), conditional on round-2 Codex/AGY
concurrence on Q8/Q9.

## Worked traces on the §5.5 no-op-port rule (all corners)

| Input (v6) | Generic (post-fix) | Descriptor (post-fix) | Parity |
|---|---|---|---|
| UDP stored 0, identity port | rule fires → 0xFFFF | ≡0 delta → computed 0 → canonicalize → 0xFFFF | ✓ |
| UDP stored 0, old≠new port | adjust from 0 → result; computed-0 canonicalized INSIDE `adjust_l4_checksum_port` → rule sees nonzero, no-op | delta applied + canonicalize | ✓ (rule cannot double-fire) |
| UDP stored 0, identity port + addr NAT | addr adjusters run FIRST (apply order: addresses then ports, mod.rs:789-841) → stored becomes nonzero → rule no-op | combined delta | ✓ |
| UDP stored valid C, identity port | untouched C | C → C (unique-representative fold, C≠0 so no canonicalization) | ✓ |
| TCP stored 0 (valid), identity port | untouched 0x0000 (rule UDP-gated) | ≡0 delta → 0 → #1839 predicate TCP → keeps 0x0000 | ✓ |
| ICMPv6 | port rewrite early-returns (non-TCP/UDP) | flow cache never caches ICMP | n/a |
| truncated (len < l4+4) | whole `apply_nat_port_rewrite` returns `Some(())` before the rule | descriptor bounds-guards skip | outside valid domain, unchanged |

No corner found where the rule fires wrongly or fails to fire. The rule's
guard "stored still literal 0x0000 after the port blocks" is sound because
the (post-#1840) adjuster canonicalizes its own computed zeros — the only
way to exit the blocks with literal 0 and a `Some` port field is the
identity short-circuit.

## §5.7 icmp_embed spec checks

- Outer offsets: builder's `pkt` is the L3-relative slice
  (`out[out_eth_len..]`); `v6_rel_l4_offset(pkt, meta.l3_offset,
  meta.l4_offset, ..)` computes `meta_rel = l4 − l3` — same frame-relative
  scalars / L3-relative slice shape as every §5.2 site. ✓
- `v6_rel_l4_offset` ignores `meta.protocol` (the outer proto is ICMPv6,
  not TCP/UDP) — correct, the helper is offset-only. ✓
- Embedded walk truncation: `packet_rel_l4_offset_and_protocol` is
  `.get()?`-bounded; the existing `embedded_ip_start + 48` floor remains a
  necessary-but-not-sufficient guard — acceptable, failure mode is `None`
  (skip reversal), today's behavior for short quotes. ✓
- Descriptor path never serves ICMP errors (flow cache gates TCP/UDP), so
  "no parity twin" in §5.7 is accurate. ✓

## Residual nits (non-blocking)

- §5.2 dead-trio row still carries the "or thread offset if tests
  reference" hedge while Q3 is resolved DELETE — harmless, implementation
  detail.
- §5.5 rule snippet uses pseudo-helpers (`stored_l4_checksum`,
  `write_l4_checksum`) — fine for a plan; the implementation will inline
  the two-byte read/write as the surrounding code does.

## Disposition

PLAN-READY from SMR. Awaiting Codex/AGY round-2 on Q8 (rule shape) and Q9
(icmp_embed spec).
