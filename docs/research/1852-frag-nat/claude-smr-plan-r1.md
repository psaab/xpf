# Claude SMR plan review — #1852 r1 (hostile)

Reviewing `docs/research/1852-frag-nat/plan.md` v1 as domain SMR
(dataplane / packet rewrite), CPU-arch/hot-path, and SW-design.
Posture: hostile. Looking for the plan to be wrong, not to confirm it.

## Verdict: PLAN-NEEDS-REVISION

The reachability analysis is the strongest part and I believe it is
correct: address-only NAT (static 1:1, interface NAT) is genuinely
port-blind (`nat/static_nat.rs:54-58` / `:70-74` set `rewrite_dst` /
`rewrite_src` with ports defaulted `None`), and `apply_nat_ipv4`'s IP-only
branch (`frame/mod.rs:752-755`) unconditionally calls
`adjust_l4_checksum_ipv4_dst(packet, ihl, …)` which writes 2 bytes at
`ihl+16`/`ihl+6` — payload on a non-first fragment. The "rewrite IP on all
fragments, skip L4 on non-first, checksum-correct because the L4 csum
lives only in fragment 1" reasoning is sound. But four issues must be
folded before PLAN-READY.

### F1 (must-fix) — the predicate's cost is double-counted AND the v4
path conflates `ihl`-relative offset with fragment status.

The plan proposes computing `ipv4_is_non_first_fragment` /
`ipv6_is_non_first_fragment` independently inside `apply_nat_*` AND inside
`enforce_expected_ports*`. For the generic orchestrators
(`rewrite_apply_v4`/`v6`, `build_forwarded_frame_into_*`) both leaves run
on the same packet → the v6 ext-walk runs twice. The plan hand-waves "or
thread it once from the orchestrator" — pick one. Recommendation: compute
the predicate ONCE in each orchestrator (5 sites) and thread a
`non_first_fragment: bool` into `apply_nat_*` / `enforce_expected_ports*`
/ `restore_l4_tuple_from_meta`. This also makes the descriptor path's
decision (`None` fall-back) consistent with the leaves and is the only way
to keep the hot path honest. The plan must commit to the
threaded-parameter shape, not leave it open.

### F2 (must-fix) — descriptor fast-path "return None" fall-back interacts
with the flow-cache that PRODUCED the descriptor.

The descriptor path (`apply_rewrite_descriptor`) is reached only for
flow-cached entries (ACK-only TCP + UDP per `rewrite/mod.rs:43-45`). The
plan says "return None → caller falls back to generic." Verify the caller
(`poll_descriptor.rs` ~:746) actually has a generic fall-back for a
descriptor that returns `None`, and that the fall-back re-derives the NAT
decision rather than dropping the packet. If the caller treats descriptor
`None` as "drop/short-packet," then fragments through a flow-cached NAT
session get dropped, not IP-rewritten — silently changing behavior and
contradicting §6. The plan asserts the fall-back exists; it must QUOTE the
call site proving it re-runs the generic rewrite (not drop). I did not
verify this in the worktree; the plan author must.

### F3 (should-fix) — S5 (ICMP ident) reachability is overstated as
LOW-MED without tracing whether `restore_l4_tuple_from_meta` even runs for
a non-first ICMP fragment.

`restore_l4_tuple_from_meta` (`frame/mod.rs:1114-1124`) only writes for
`PROTO_ICMP | PROTO_ICMPV6`. For a non-first ICMP fragment, the shim's
`parse_l4` ICMP arm (`lib.rs:1419`) reads `bytes[4],bytes[5]` as the
"ident" from payload and sets `meta.flow_src_port` = garbage. Then
`restore_l4_tuple_from_meta` writes that garbage-derived `meta.flow_src_port`
at `rel_l4+4` only if it differs from the current bytes. So the corruption
is real but writes garbage→garbage in many cases. The severity table
should either downgrade S5 to LOW or justify LOW-MED with the concrete
trace (NAT'd ICMP echo where meta.flow_src_port carries the first
fragment's echo id — but does it? the shim parses each fragment
independently, so the non-first fragment's meta carries ITS OWN payload
bytes, not fragment 1's id). I suspect S5 is LOW, and the "writes the echo
id from first frag" claim in §4 is WRONG — the shim has no cross-fragment
state. Fix the §4 wording.

### F4 (should-fix) — Path A′ wire-protocol claim needs the free-bit check.

§7 Path A′ says "a free `meta_flags` bit must exist." That is a
precondition, not a detail — if `meta_flags` is full, A′ is not viable
without a struct-size bump (which the trio plan's parity tests + the
C/Go struct-alignment rules make expensive). Since the plan recommends A
and holds A′ "in reserve," confirm at least one free `meta_flags` bit
exists so the reserve is real; otherwise drop A′ to "would require a meta
struct change" and stop implying it's a cheap fallback.

## Nits

- §3a S9: `build_nat_reversed_icmp_error_v4` "inherits the guard via the
  parse path" — but the builder (`icmp_embed/builders.rs:60-108`) reads
  `emb_l4_offset = emb_ip_offset + emb_ihl` directly, NOT via
  `parse_embedded_v4`. So S9 needs its OWN guard, not inheritance. Fix the
  plan's claim or the fix won't cover S9.
- §9 P-FRAG-2 asserts "descriptor path returns None (falls back)" — this
  is only testable if F2's fall-back is confirmed; otherwise the test pins
  a drop. Order F2 before writing that test.
- The plan correctly notes the NAT-domain generator emits fragment headers
  only at offset 0 (`strategies.rs:220`). Good — that's the exact gap the
  new generator closes.

## What's right (so I'm not just negative)

- Reachability narrowing (port writes self-gate via garbage-port session
  miss) is correct and well-argued — this is the kind of honest scoping
  that prevents over-engineering.
- Choosing IP-only-rewrite over drop (Path B) is the correct semantics:
  dropping all fragments breaks MORE than today's partial corruption, and
  the L4-checksum-in-fragment-1 argument makes IP-only provably correct.
- Folding defect 2 (ext-aware clamp) is cheap and right; a non-first
  fragment never carries a SYN so no fragment logic is needed there.
- PLAN-KILL invitation Q5 is genuine: MED severity on uncommon
  (fragmented + static NAT) traffic is a legitimate "maybe Path C" call.

Resolve F1 (commit to threaded predicate), F2 (quote the descriptor
fall-back call site), F3 (fix the §4 cross-fragment-state error +
re-grade S5), F4 (confirm a free meta_flags bit or downgrade A′), and the
S9 nit, and this is PLAN-READY at Path A.
