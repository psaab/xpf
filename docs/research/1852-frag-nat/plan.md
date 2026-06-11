# #1852 — Non-first-fragment port-NAT exposure + MSS-clamp v6 ext-header gap: plan of action

## 1. Status

**PLAN-DRAFT v1** — awaiting 3-way hostile review (Codex + AGY + Claude
SMR). Two pre-existing, family-symmetric defects collected from the
#1838/#1839/#1840 trio plan (`docs/research/1838-nat-v6-trio/plan.md`
§7.9, §10, §5.7 note 3 — now merged as #1853 on master `36dc00953`).
PLAN-KILL or partial (fix one, defer the other) is a legitimate outcome.

All file/line references are to master `5b3f9501e` (worktree
`.claude/worktrees/1852-research`).

## 2. Issue framing

Two divergences that the trio PR (#1853) deliberately left untouched:

1. **Non-first-fragment L4 rewrite (both families, all rewrite paths)** —
   a non-first fragment has no L4 header at the post-IP-header offset.
   Every NAT/rewrite path that writes ports or adjusts an L4 checksum at
   that offset interprets *payload* bytes as the L4 header. The trio PR
   added a fragment-offset guard ONLY to the embedded ICMPv6 walk
   (`parse_embedded_v6_l4`, shipped #1853); the forwarding-path rewrite
   sites and the embedded ICMPv4 walk were explicitly deferred here.

2. **MSS-clamp v6 extension-header gap (safe bail, feature gap)** —
   `clamp_tcp_mss` derives the v6 L4 offset as the fixed pair
   `(40, packet[6])`; when `packet[6]` is an extension-header type the
   protocol check (`protocol != PROTO_TCP`) fails and the clamp silently
   no-ops. No corruption — but `tcp-mss` clamping is not applied to
   ext-headered v6 SYNs.

## 3. Blast-radius inventory (per-site, file:line @ `5b3f9501e`)

### 3a. Defect 1 — L4-offset interpretation sites in the rewrite path

The XDP shim (`userspace-xdp/src/lib.rs`) parses every packet and writes
`UserspaceDpMeta`. It does **not** check the fragment-offset bits:

- `parse_ipv4` (lib.rs:1100-1142) reads `protocol = iph[9]` then calls
  `parse_l4` at `l3 + ihl` regardless of `frag_off`. For a non-first
  fragment, `parse_l4` (lib.rs:1388) reads payload bytes as ports /
  TCP-data-offset → `meta.flow_src_port` / `flow_dst_port` = garbage,
  `meta.l4_offset = l3 + ihl`.
- `parse_ipv6` (lib.rs:1144-1219) walks `NEXTHDR_FRAGMENT` (44) at
  lib.rs:1185 advancing 8 bytes **without** reading the offset bits, then
  `parse_l4` at the post-fragment offset → same garbage ports,
  `meta.l4_offset` points past the fragment header.

So the metadata handed to userspace already mis-describes a non-first
fragment as a normal L4 packet. Every downstream rewrite leaf then trusts
`rel_l4`:

| # | Site | file:line | What it writes at the L4 offset |
|---|------|-----------|---------------------------------|
| S1 | `apply_nat_ipv4` (IP-only NAT branch) | `frame/mod.rs:751/755/767/776` | `adjust_l4_checksum_ipv4_*` reads+writes 2 bytes at `ihl+16` (TCP) / `ihl+6` (UDP) for the address-change delta |
| S2 | `apply_nat_ipv6` (IP-only NAT branch) | `frame/mod.rs:833/846/872/879` | `adjust_l4_checksum_ipv6_*` at `rel_l4+16/+6/+2` |
| S3 | `apply_nat_port_rewrite` | `frame/mod.rs:913-973` | writes ports at `rel_l4`/`rel_l4+2` and adjusts the port-delta checksum (only when `nat.rewrite_*_port = Some`) |
| S4 | `enforce_expected_ports` / `_at` | `frame/mod.rs:1020/1066` | writes `expected_ports` at `rel_l4` + adjusts checksum (only when `expected_ports = Some` and current != expected) |
| S5 | `restore_l4_tuple_from_meta` (ICMP) | `frame/mod.rs:1108-1127` | writes `meta.flow_src_port` (echo id) at `rel_l4+4` |
| S6 | descriptor fast path v4 | `rewrite/ipv4.rs:62-121` | inline port writes + precomputed L4-csum delta at `l4+16/+6` |
| S7 | descriptor fast path v6 | `rewrite/ipv6.rs:63-108` | inline port writes + precomputed L4-csum delta |
| S8 | `parse_embedded_v4` | `icmp_embed/parse.rs:36-81` | reads ports at `ihl` (no frag-offset check) — the v4 twin of the #1853 v6 fix |
| S9 | `build_nat_reversed_icmp_error_v4` | `icmp_embed/builders.rs:60-108` | embedded un-NAT at `emb_ip_offset + emb_ihl` (no frag check on the QUOTED v4 packet) |

Orchestrators that call S1-S7 (each is a distinct entry that would need a
gate if gating at the orchestrator level rather than the leaf):

- `rewrite_apply_v4` / `rewrite_apply_v6` (generic in-place, mod.rs:504/560)
- `build_forwarded_frame_into_ipv4` / `_ipv6` (copy builder, build/ipv4.rs / ipv6.rs)
- `apply_rewrite_descriptor_ipv4` / `_ipv6` (descriptor fast path)
- `extract_l3_packet_with_nat` (slow_path.rs:278)
- tcp segmentation v4/v6 (`frame/tcp_segmentation.rs`, `tx/tcp_segmentation.rs`)

The forwarding/NAT pipeline has **zero** fragment awareness today
(`grep is_fragment userspace-dp/src/afxdp` → only `event_emit.rs`). Only
the **screen** layer reads frag bits (`screen/extract.rs:50-55,99-109`)
and only acts on them for the optional teardrop / icmp-fragment / syn-frag
checks — it does not unconditionally drop non-first fragments.

### 3b. Defect 2 — MSS clamp

- `clamp_tcp_mss` (`frame/tcp.rs:192-271`), v6 arm at tcp.rs:209-214 uses
  the fixed `(40, packet[6])`. Single function; both build arms reach it
  via `clamp_tcp_mss_frame` (`build/ipv4.rs:78`, `build/ipv6.rs:60`),
  gated by `tunnel_tcp_mss > 0`. No other production caller
  (`grep clamp_tcp_mss`). The `#1853` `v6_rel_l4_offset` helper is NOT
  used here — the clamp keeps its own fixed-40 derivation, so the gap
  remains in exactly this one function.

## 4. Reachability analysis (the honest narrowing)

The filed issue says "the REAL exposure may be narrower than filed." It
is — but a real, reachable corruption survives the narrowing.

**Port-write sites (S3, S6/S7 port writes, S4) are mostly self-gating.**
A non-first fragment carries garbage ports (payload bytes). The
session/flow lookup that produces a port-rewriting `NatDecision`
(`nat.rewrite_*_port = Some`) or `expected_ports = Some` keys on those
garbage ports → the session lookup **misses** → no port-NAT decision is
produced → S3/S6/S7 port writes and S4 enforcement never fire. Crafting
payload bytes that collide with a live port-NAT session only corrupts the
attacker's own flow. **LOW / effectively unreachable** for S3, S4 (port
arm), S6/S7 (port arm).

**Address-only NAT (S1, S2 IP-NAT branch) IS reachable and corrupts.**
Static 1:1 NAT (`nat/static_nat.rs:49-75`) and interface NAT produce
**port-blind** decisions keyed purely on IP (`match_dnat` / `match_snat`
set `rewrite_dst`/`rewrite_src`, ports `None`). The XDP shim redirects a
non-first fragment to a static-NAT'd / interface-NAT'd IP to userspace
(`USERSPACE_INTERFACE_NAT_V4/V6` and `USERSPACE_LOCAL_V4/V6` are keyed on
dst IP, port-blind; static external IPs register for local delivery via
`StaticNatTable::external_ips`). In userspace the IP-only NAT decision
flows to `apply_nat_ipv4`/`_ipv6`, which:

  1. rewrites the IP address (CORRECT — every fragment carries the IP
     header and must be rewritten consistently), then
  2. calls `adjust_l4_checksum_ipv4_dst` / `_ipv6_*` at the L4 offset to
     fold the address-change delta into "the L4 checksum" — but on a
     non-first fragment those 2 bytes are **payload**, so 2 payload bytes
     are mutated.

The L4 checksum lives only in the FIRST fragment. The first fragment is
NAT'd correctly (real L4 header present, delta folded in). Each non-first
fragment gets its IP rewritten (correct) **plus 2 corrupted payload
bytes** (wrong). On reassembly the receiver's L4 checksum (covering the
whole datagram, carried in fragment 1) no longer matches the
payload-corrupted reassembly → **silent drop of fragmented, statically
NAT'd TCP/UDP flows.** Reachable with `static nat` (or interface NAT) +
any fragmented flow ≥ 2 fragments. **MED.**

**ICMP ident restore (S5) is reachable, lower impact.** Fragmented ICMP
echo (large ping) through NAT: a non-first ICMP fragment gets
`meta.flow_src_port` (the echo id from the metadata) written at
`rel_l4+4` → 2 payload bytes corrupted, same reassembly-drop class.
ICMP-error embedded restore (S8/S9) requires the QUOTED packet inside an
ICMP error to itself be a non-first fragment, which then mostly produces
a session-lookup miss (garbage embedded ports) — **LOW**, but it is the
exact v4 twin of the bug #1853 judged worth fixing on v6, so closing it
restores family symmetry cheaply.

**Defect 2 is not corruption.** An ext-headered v6 SYN whose clamp is
skipped simply keeps its original MSS — a feature gap, **LOW**. (A
non-first fragment never carries a SYN, so the fragment question does not
add to defect 2.)

## 5. Severity — honest framing

| Defect / site | Reachable? | Impact | Severity |
|---------------|-----------|--------|----------|
| S1/S2 address-NAT L4-csum adjust on non-first frag (static/interface NAT) | YES | 2 payload bytes/frag corrupted → reassembly checksum mismatch → silent drop of fragmented NAT'd flows | **MED** |
| S5 ICMP ident restore on non-first ICMP frag | YES | payload corruption on fragmented ICMP echo through NAT | **LOW-MED** |
| S3/S4/S6/S7 port writes on non-first frag | Effectively no (session/expected-ports lookup misses on garbage ports) | self-inflicted only | **LOW** |
| S8/S9 embedded v4 non-first-fragment parse | YES (narrow) | session-lookup miss / no false match in practice; family asymmetry vs #1853 | **LOW** |
| Defect 2 — MSS clamp v6 ext gap | YES | clamp silently skipped; no corruption | **LOW** |

No defect is a security-critical RCE/escape; the headline is a
**correctness** bug: static/interface NAT silently breaks fragmented
flows. This was masked because (a) fragmentation is uncommon on the
loss-cluster smoke path (MSS-clamped, MTU-clean), and (b) the trio prop
harness pins *current* behavior, so it is not a regression.

## 6. Design — the correct rewrite semantics for fragments

Without datapath reassembly (the dataplane has none — confirmed no
reassembly code), the correct, minimal, flow-preserving behavior is:

- **First / atomic fragment** (offset == 0): full L4 rewrite as today
  (real L4 header present; port writes + checksum deltas are correct).
- **Non-first fragment** (offset != 0): rewrite the **IP address only**
  (consistent across all fragments — required for reassembly), and
  **skip every L4-offset byte operation** (port writes, IP-change L4
  checksum adjust, port enforcement, ICMP ident restore, MSS clamp). The
  address-change delta is folded into the L4 checksum exactly once, on
  the first fragment, which is correct for the whole datagram.

This keeps statically-NAT'd fragmented flows working (today they break),
adds no drop, and needs no reassembly state.

The discriminator is a single per-packet predicate:

- **v4**: `(frag_off & 0x1FFF) != 0` where `frag_off =
  u16::from_be_bytes([ip[6], ip[7]])` (IP-header-relative, trivial).
- **v6**: walk the ext chain for a fragment header (44); non-first iff
  present AND `(frag_off_field & 0xFFF8) != 0`. The shim's meta-led
  `rel_l4` shortcut hides this (the shim already advances past the
  fragment header, so `meta_rel >= 48`), so v6 detection requires either
  an explicit walk or a meta flag (see §7 path options).

## 7. Path options

### Path A — leaf-level family-gated fragment guard (RECOMMENDED)

Gate the shared leaf functions; all five orchestrators inherit the fix at
one point each.

- New private helpers in `frame/inspect.rs` (read-only, no mutation):
  `ipv4_is_non_first_fragment(packet: &[u8]) -> bool` and
  `ipv6_is_non_first_fragment(packet: &[u8]) -> bool` (bounded ext walk,
  reuses the §6 logic; mirrors `screen/extract.rs` semantics).
- `apply_nat_ipv4`/`apply_nat_ipv6`: after the IP-address rewrite branch,
  compute the predicate once; when non-first fragment, **return `Some(())`
  before the L4-checksum-adjust call and before `apply_nat_port_rewrite`**
  — but keep the IP byte writes. (Restructure so the IP writes happen,
  then `if !non_first { adjust_csum…; }`, then
  `if !non_first { apply_nat_port_rewrite… }`.)
- `enforce_expected_ports` / `_at`: early `return Some(false)` when the
  frame is a non-first fragment (no enforcement, no checksum touch).
- `restore_l4_tuple_from_meta`: early `return Some(false)` for non-first
  fragments (ICMP arm).
- Descriptor fast path (`rewrite/ipv4.rs`, `rewrite/ipv6.rs`): these do
  inline writes and do NOT call the leaves, so add the predicate there —
  when non-first fragment, perform the IP byte writes + the v4 IP-header
  checksum (delta is IP-only) + TTL, and **skip** the port writes and the
  `rd.l4_csum_delta` block. NOTE: `rd.l4_csum_delta` and `ip_csum_delta`
  are precomputed by the Go/decision layer assuming a normal L4 header;
  for the descriptor path the cleanest guard is: on a non-first fragment,
  **return `None`** so the caller falls back to the generic path
  (`rewrite_apply_*`), which then applies the leaf-level gate. This avoids
  re-deriving the precomputed deltas and keeps the fast path
  byte-for-byte equal to the generic path on the shared domain (preserves
  the #1838 P-N3 parity invariant).
- `parse_embedded_v4` (S8): add the IPv4 fragment-offset check, mirroring
  #1853's `parse_embedded_v6_l4` — return `None` for a quoted non-first
  fragment (no L4 header to read). `build_nat_reversed_icmp_error_v4` (S9)
  inherits the guard via the parse path / adds a symmetric check.
- **Defect 2**: change `clamp_tcp_mss`'s v6 arm to derive the offset via
  the shared `packet_rel_l4_offset_and_protocol` (ext-aware) instead of
  `(40, packet[6])`. A non-first fragment is naturally excluded (no SYN /
  no TCP header after the walk → the SYN-flag check no-ops). Closes the
  feature gap with no fragment-specific code.

Pros: one gate per leaf covers all five orchestrators; IP NAT of
fragmented flows starts working; preserves descriptor↔generic parity by
falling back (no delta re-derivation); contained entirely to
`userspace-dp` (matches the issue scope). Cons: per-packet v6 ext-walk
for NAT'd v6 packets in `apply_nat_ipv6` / `enforce_expected_ports`
(bounded 6 iterations; only on the NAT/enforcement path, not every
packet); the predicate is computed up to twice per packet (apply_nat +
enforce) — acceptable, or thread it once from the orchestrator.

### Path A′ — meta-flag from the shim (perf-optimal variant of A)

Have `parse_ipv4`/`parse_ipv6` in `userspace-xdp/src/lib.rs` set a
`UserspaceDpMeta.meta_flags` non-first-fragment bit during parse (it
already reads the v4 `frag_off` field and walks the v6 fragment header).
Userspace then checks one bit — zero extra parsing on any path. This is
arguably "the admission-layer answer" the trio plan asked for (the shim
IS the admission layer). Cons: wire-protocol extension — touches the shim
+ the meta struct (`protocol.rs`/`protocol.go` BOTH sides per
`feedback_wire_protocol_both_sides`) + a free `meta_flags` bit must
exist. Broader blast radius than the issue scope; defer unless the v6
ext-walk cost in Path A is shown to matter.

### Path B — fragment-aware offset helpers that DROP

Make `v6_rel_l4_offset` and the v4 IHL derivation return `None` (drop the
fragment) for non-first fragments at the rewrite entry. Simpler code, but
**changes drop accounting**: today fragmented NAT'd flows partly work
(first frag) / partly corrupt; under B they would be dropped entirely.
For static NAT, dropping all fragments breaks the flow MORE than the
status quo for the first fragment, and contradicts the "rewrite IP on all
fragments" correctness in §6. Also collides with `apply_nat_*`'s
documented skip-vs-fail contract (Some=skip, None=caller drops — invariant
#4 of the trio plan). REJECT as the primary, but viable as an explicit
operator policy (drop fragments through NAT) if §6's IP-only-rewrite is
deemed too clever.

### Path C — partial / document

Fix only the reachable MED corruption (S1/S2 address-NAT L4-csum adjust
gate) + the cheap family-symmetry restore (S8/S9 embedded v4) + the MSS
ext-aware fix (defect 2), and **document** S3/S4/S5/S6/S7 as
known-narrow-residual in `frame/README.md`. Smaller diff, leaves the
ICMP-ident (S5) corruption and the descriptor-path edge unfixed. Viable
if review judges A too broad for the realized risk.

## 8. Recommended path

**Path A** (leaf-level gate + descriptor-path fallback-to-generic +
embedded-v4 parse guard + ext-aware MSS clamp), with **Path A′ held in
reserve** if the v6 ext-walk cost is shown to regress the NAT path. Path A
is the smallest change that (a) stops the reachable MED payload
corruption, (b) makes statically-NAT'd fragmented flows actually work
rather than just "not corrupt," (c) restores v4/v6 embedded symmetry, and
(d) closes defect 2 — all within the issue's `userspace-dp/src/afxdp/`
scope, with the descriptor↔generic parity invariant preserved by
fall-back rather than delta re-derivation.

## 9. Test plan

1. **Extend the #1842 prop harness** (`frame/prop_tests/`): the NAT domain
   currently emits `ExtHdr::Fragment` only with offset 0 (first/atomic —
   `strategies.rs:220` encodes the frag header's offset bytes as 0). Add a
   non-first-fragment generator (offset bits != 0) to `arb_packet_with_nat`
   and assert:
   - P-FRAG-1: address-only NAT on a non-first fragment rewrites the IP
     bytes and leaves every byte at/after the (fictitious) L4 offset
     **identical** to input (no payload corruption);
   - P-FRAG-2: descriptor path returns `None` (falls back) on a non-first
     fragment, and the generic path's output is the IP-only rewrite;
   - P-FRAG-3: first/atomic fragment (offset 0) behavior is byte-identical
     to today (regression guard);
   - keep the existing P-N3 descriptor-vs-generic parity (the fallback
     keeps them equal on the shared non-fragment domain).
2. **Deterministic unit tests**:
   - `ipv4_is_non_first_fragment` / `ipv6_is_non_first_fragment` truth
     table (offset 0 MF=0/1, offset>0, no-frag-header, truncated chain);
   - static-DNAT on a 2-fragment TCP flow: fragment 1 fully NAT'd
     (IP+checksum), fragment 2 IP-only, payload byte-identical;
   - ICMP echo non-first fragment: `restore_l4_tuple_from_meta` no-ops;
   - `parse_embedded_v4` returns `None` for a quoted non-first fragment;
     first/atomic quoted fragment still parses (mirror the #1853 v6 tests
     at `icmp_embed/parse.rs:262-298`);
   - `clamp_tcp_mss` on an ext-headered v6 SYN now finds + clamps the MSS;
     a non-first fragment / non-SYN still no-ops.
3. **Suites/gates**: `cargo build --release` clean; full `cargo test
   --release` with awk-aggregated pass/fail over all `test result` lines;
   `go test ./...`; the known-flaky ledger (inplace_*, worker_queue
   concurrent_recovery, tx_latency_hist, wg reconcile_peers) must pass
   standalone before attribution. Smoke v4+v6 iperf3 on the loss userspace
   cluster + per-class CoS (parent runs serialized smoke; fragmented
   traffic is not iperf3-able — the prop harness is the functional
   evidence). `make test-failover` if any cluster/forwarding-shared code
   is touched (it is not expected to be).
4. **Never `cargo fmt`** the focused change (per the #1769 reflow gotcha).

## 10. Hidden invariants to preserve

1. **Descriptor↔generic parity (#1838 P-N3, empty mask)** — Path A keeps
   it by making the descriptor path FALL BACK (`None`) on non-first
   fragments rather than re-deriving the precomputed deltas; the generic
   path's IP-only rewrite is then the single source of truth.
2. **Skip-vs-fail contract (trio invariant #4)** — `apply_nat_*` keeps
   returning `Some(())` (skip the L4 work), never `None`, on non-first
   fragments. `None` stays reserved for genuine truncation/short-packet.
3. **v4 byte-identity / first-fragment byte-identity** — the gate only
   changes non-first-fragment output; offset-0 and non-fragmented packets
   are bit-identical (P-FRAG-3).
4. **Hot-path discipline** — predicate is a bounded read (v4: 2 bytes;
   v6: ≤6-iteration walk), only on the NAT/enforce path; no allocation, no
   `dyn`, helpers `#[inline]`. If review flags the v6 walk cost, escalate
   to Path A′.
5. **#1853 embedded-v6 fragment guard** — unchanged; the v4 guard mirrors
   it for symmetry (`embedded_reply_key`/`parse_embedded_v6_l4` semantics).
6. **MSS clamp**: `clamp_tcp_mss` must stay byte-identical for v4 and for
   non-ext v6 (offset 40); only ext-headered v6 changes (gap → clamped).

## 11. Open questions / PLAN-KILL invitation

- **Q1** — Is the §6 "rewrite IP on all fragments, skip L4 on non-first"
  semantics the right firewall behavior, or should NAT'd fragments be
  **dropped** (Path B) to match a "no reassembly ⇒ no fragment NAT"
  stance? Junos SRX default is flow-based reassembly; we have none.
  IP-only-rewrite keeps flows alive and is checksum-correct — but is it
  the behavior operators expect? **This is the kill-or-pick decision.**
- **Q2** — Is the descriptor-path **fall-back-to-generic** (return `None`)
  acceptable, or must the descriptor path handle fragments inline?
  Fall-back is rare (fragments are uncommon) and preserves parity for
  free; inline handling re-opens the delta-derivation divergence #1838
  just closed.
- **Q3** — Path A (contained, per-packet v6 walk) vs Path A′ (meta flag,
  wire-protocol change, zero walk)? Default A; A′ only if walk cost bites.
- **Q4** — Scope: fix both defects in one PR (they share `frame/` and the
  fragment predicate), or split defect 2 (MSS, trivial, independent) into
  its own commit/PR? Lean: one PR, two logical commits.
- **Q5 (PLAN-KILL)** — Given S3/S4/S6/S7 are effectively unreachable and
  the realized corruption (S1/S2/S5) requires fragmented traffic through
  static/interface NAT (uncommon on MSS-clamped paths), is the MED
  severity high enough to justify Path A's breadth, or should this be
  **Path C (partial)** or **closed as documented-known-limitation**?
  Reviewers may PLAN-KILL to C or to doc-only.

## Appendix — reviewer task IDs

See `docs/research/1852-frag-nat/reviewer-ids.md`.
