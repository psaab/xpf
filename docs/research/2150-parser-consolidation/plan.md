# #2150 — Userspace Ethernet/IPv6 parser consolidation

Plan status: **PLAN-READY** (refactor, with one latent-correctness sub-fix)
Base commit: `ef8dbb266` (master; includes #2178/#2148, #2188/#2155, #2189/#2146)
Branch: `research/2150-parser-consolidation`

---

## 1. Problem statement (as filed) vs. what the code actually does

The issue (codex-review-017, verified vs `12becabc4`) asserts a **runtime
correctness asymmetry**:

> Provider-tagged (0x88a8) ARP/NDP and NDP behind valid IPv6 extension
> headers can fail neighbor learning while the forwarding path accepts the
> same L2/L3 shape → avoidable neighbor misses / blackhole.

After tracing every parse site and the upstream XDP shim steering, the
"learning disagrees with forwarding on the same wire packet" claim **does
not hold as a live data-path defect** in the current architecture, because
**ARP frames and NDP Neighbor-Advertisement frames never reach the userspace
learning path at all** (see §3, the steering proof). The shim XDP_PASSes
them to the kernel.

What IS real and worth fixing:

1. **Parser fragmentation** — there are **five** distinct Ethernet-L2 offset
   parsers and **three** distinct IPv6 extension-header walkers in
   `userspace-dp`, each with subtly different VLAN/0x88a8 and ext-header
   semantics (§2). They genuinely disagree with one another on a single
   0x88a8-tagged frame and on a 0x88a8 double tag. This is a latent
   maintenance hazard and a real internal-consistency bug — the kind that
   becomes a live blackhole the instant any future change routes a
   provider-tagged or NDP-control frame through a path that uses the "wrong"
   parser.

2. **Two genuinely-wrong L2 parsers** that would mis-handle a single
   0x88a8 tag if they were ever fed one:
   - `afxdp/parser.rs::parse_eth_offsets` — treats 0x88a8 as the *inner*
     ethertype (only matches 0x8100). A single-0x88a8 ARP/NDP frame parses
     as L3-at-14 with ethertype 0x88a8 → classified `NotArp` / non-IPv6 →
     learning skipped.
   - `nat64.rs::frame_l3_offset` — matches only 0x8100; a 0x88a8 frame is
     treated as **untagged** (l3 = 14), which is wrong (the real L3 is at
     18). This would corrupt a NAT64 translation of a 0x88a8-tagged frame.

3. **`parse_ndp_neighbor_advert` has no IPv6 ext-header walk** — it reads
   the base `next_header` and assumes ICMPv6 at `l3_start + 40`. An NA
   behind a hop-by-hop / dest-options header would be missed. Real code
   defect; unreachable in practice (NA is XDP_PASSed, §3) but it is the
   exact bug the *forwarding-side* walkers (#2148/#2189) were written to
   avoid, so leaving it asymmetric is a correctness smell.

**Disposition recommendation:** treat #2150 as a **consolidation refactor
that folds in two latent-correctness sub-fixes** (the 0x88a8 L2 mishandling
in `parse_eth_offsets` + `nat64::frame_l3_offset`, and the NDP ext-header
walk). It is NOT a PLAN-KILL — the disagreement is real *between parsers*,
just not currently observable as a live blackhole because the affected
frames don't reach the affected code. The refactor removes the trap before
a future steering change springs it, and unifies five+three parsers down to
two canonical ones.

---

## 2. Inventory of every parse site (the SSOT problem)

### 2.1 Ethernet-L2 / VLAN offset parsers (FIVE distinct)

| # | Location | 0x8100 | 0x88a8 (single) | QinQ double | Output |
|---|----------|--------|-----------------|-------------|--------|
| L2-a | `afxdp/parser.rs:35 parse_eth_offsets` | tag (l3=18) | **inner ethertype (l3=14, BUG)** | n/a | (l3, ethertype) |
| L2-b | `afxdp/frame/inspect.rs:15 frame_l3_offset` | tag (l3=18) | tag (l3=18) | not unwound | l3 only |
| L2-c | `afxdp/cos/ecn.rs:56 ethernet_l3` | tag (l3=18) | tag (l3=18) | **reject (None)** | EthernetL3{family, l3} |
| L2-d | `nat64.rs:629 frame_l3_offset` | tag (l3=18) | **untagged (l3=14, BUG)** | n/a | l3 only |
| L2-e | `afxdp/icmp.rs:93 ingress_reply_l2` | tag (vid read @14) | tag (vid read @14) | not unwound | (src,dst,vlan_id) — VID only, not l3 |

Notes:
- **L2-a is the learning-path parser** (`classify_arp`,
  `parse_ndp_neighbor_advert`). It is the only one that gets 0x88a8 *wrong
  in the unsafe direction* (skips a valid frame).
- **L2-d (`nat64`)** is the only one that mis-offsets 0x88a8 into the IP
  body (l3=14 on a tagged frame) — actively corrupting.
- L2-b/L2-c/L2-e treat 0x88a8 as a single tag (l3=18), matching the shim.
- **No userspace parser unwinds a QinQ DOUBLE tag** (0x88a8 outer +
  0x8100 inner → real L3 at 22). The shim doesn't either (see §3) — it
  drops the frame before userspace. So double-tag transit is currently
  unsupported end-to-end; that is a *feature gap*, not a regression, and is
  out of scope for "make the parsers agree" unless we decide to add it.

Forwarding/screen don't actually *call* L2-a/L2-b for transit: they consume
`meta.l3_offset` (computed by the shim, §3) with `14|18` as the trusted fast
path and `frame_l3_offset` (L2-b) only as a fallback. So for transit the
**shim's L2 parser is the de-facto authority**, and L2-b/c agree with it.

### 2.2 IPv6 extension-header walkers (THREE distinct, all in userspace-dp)

| # | Location | Bound | Frag-aware | Fail mode | Used by |
|---|----------|-------|-----------|-----------|---------|
| V6-a | `frame/inspect.rs:31 frame_l4_offset` / `:86 packet_rel_l4_offset` / `:145 packet_rel_l4_offset_and_protocol` (#2148) | 6 | offset returned, frag not flagged | `None` on truncation | forwarding, GRE inner, session-flow parse |
| V6-b | `screen/extract.rs:66` (#2189) | 8 | yes (sets is_first_fragment) | **`Err` = fail-closed (drop)** | screen / IDS |
| V6-c | `icmp_embed/parse.rs:108 parse_embedded_v6_l4` (#1838) | 6 | yes (None on non-first frag) | `None` | embedded ICMPv6 error quoted-packet |

All three share the same `0|43|60` / `51` / `44` / `59` arm structure but
differ in: iteration bound (6 vs 8), fragment semantics, and fail
disposition (None vs Err vs drop). The **NDP-learning path (V6-MISSING)**
has *no* walker — `parse_ndp_neighbor_advert` (parser.rs:138-145) reads
`l3_start + 6` and assumes ICMPv6 at `l3_start + 40`.

### 2.3 Out-of-scope walkers (NOT userspace-dp)

- **`pkg/vrrp` (Go) `walkIPv6ExtHeaders`** (#2188/#2155, `instance.go:776`,
  `manager.go:656`) — a *Go* AF_PACKET VRRP receive path, different
  language and different socket. **Do NOT pull into the Rust
  consolidation.** Document it as a parallel implementation; no shared
  code is possible across the Go/Rust boundary without a much larger
  effort. The plan keeps it separate.
- **The XDP shim `parse_l2` / `parse_ipv4` / `parse_ipv6`**
  (`userspace-xdp/src/lib.rs:1083+`) — runs in the kernel BPF VM under the
  verifier. It is the L2/L3 authority for `meta.l3_offset`. It CANNOT
  share code with the userspace `std`-using parsers (no `std`, verifier
  constraints, `aya`/no_std). It is the right place to *add* QinQ-double
  support if we ever want it, but that is a separate issue.

---

## 3. Steering proof — why the "live blackhole" does not occur today

Trace of `userspace-xdp/src/lib.rs::try_xdp_userspace` (the normal path) and
the degraded path, for the three frame classes in the issue:

1. **ARP (ethertype 0x0806)** — `parse_l2` returns `eth_proto = 0x0806`
   (untagged) or, for a single-VLAN ARP, advances one tag then returns
   0x0806. The dispatch `match eth_proto { ETH_P_IP | ETH_P_IPV6 ... _ =>
   pass_non_ip_l2_direct() }` (lib.rs:373-377) hits the `_` arm →
   **`XDP_PASS` to the kernel** (lib.rs:941-946, comment: "Non-IP local L2
   frames such as ARP and LLDP must go directly to the kernel stack").
   → ARP NEVER lands in the XSK → `classify_arp` in
   `poll_stages.rs:78` can never see an ARP frame from the shim.

2. **NDP Neighbor Advertisement (IPv6, ICMPv6 type 136)** — parses as
   `ETH_P_IPV6`, but on BOTH the normal and degraded paths the shim
   diverts ICMPv6 types 133-137 to the kernel:
   - normal: `if parsed.protocol == PROTO_ICMPV6 && icmp_type 133..=137 {
     return pass_local_control(...) }` (lib.rs:537-539)
   - degraded: `is_degraded_local_or_control` returns true for the same
     range (lib.rs:964-965).
   → NA NEVER reaches the XSK → `parse_ndp_neighbor_advert` in
   `poll_stages.rs:100` can never see an NA frame from the shim.

3. **QinQ double tag (0x88a8 outer + 0x8100 inner)** — `parse_l2` advances
   exactly ONE tag (lib.rs:1091-1099, single `if`, no loop), leaving
   `eth_proto = 0x8100` (the inner TPID). Dispatch `_` arm → `XDP_PASS`.
   → double-tagged IP transit NEVER reaches userspace at all.

4. **Single 0x88a8 tag on an IP frame** — `parse_l2` advances one tag,
   inner ethertype = 0x0800/0x86dd → steered to userspace with
   `meta.l3_offset = 18`. Forwarding/screen trust `meta` (18) and parse
   correctly. The learning parsers (L2-a/L2-d) would mis-handle it, but
   the only frames steered to userspace here are *IP transit/local*, not
   ARP/NDP-control — so the mis-handling L2-a/L2-d still never run on a
   0x88a8 frame in the learning role.

**Conclusion:** the `poll_binding_process_descriptor` pipeline (fed solely
by the XSK rx ring, `poll_descriptor/mod.rs:172`) is the only consumer of
L2-a/V6-MISSING, and the frame classes that would expose their bugs are
XDP_PASSed upstream. The disagreement is real *between the parsers as
written*; it is NOT a currently-observable blackhole.

This is exactly the kind of finding that justifies a research-first
disposition: the issue's *mechanism* is wrong (no live asymmetry) but its
*conclusion* (consolidate the parsers; the learning parsers are buggy on
0x88a8 and ext-headers) is correct and worth doing before the steering ever
changes (e.g. if a future change steers NDP to userspace for HA neighbor
sync, or adds QinQ-double transit, the latent bug becomes live instantly).

---

## 4. The concrete disagreement (constructed packets)

Even though these frames don't reach the affected code today, the parsers
**provably disagree** on them — this is the consolidation's justification.

### 4.1 Single 0x88a8-tagged ARP reply
Wire: `dst(6) src(6) | 88a8 | TCI(2) | 0806(ARP) | arp-body(28)`

- `parse_eth_offsets` (L2-a): outer = 0x88a8 ≠ 0x8100 → returns
  `(14, 0x88a8)`. ethertype 0x88a8 ≠ ARP → `classify_arp` = **NotArp** →
  neighbor NOT learned.
- `frame_l3_offset` (L2-b) / `ethernet_l3` (L2-c): 0x88a8 → l3 = 18 →
  inner = 0x0806 → would parse as ARP-at-18 (L2-c rejects non-IP inner,
  but agrees the tag IS a tag).
- **DISAGREEMENT: L2-a says "untagged, ethertype 88a8"; L2-b/c say
  "single tag, l3 at 18".** A canary that asserts
  `parse_eth_offsets(f).0 == frame_l3_offset(f)` FAILS on this frame.

### 4.2 NDP NA behind a hop-by-hop header
Wire: `... 86dd | ipv6-base(40, next=0/HBH) | HBH(8, next=58) |
icmpv6-NA(24) | TLLA-opt(8)`

- `parse_ndp_neighbor_advert` (V6-MISSING): reads `next_header` =
  `raw[l3+6]` = 0 (HBH) ≠ 58 → **returns None** → MAC NOT learned.
- `frame_l4_offset` (V6-a) / `screen extract` (V6-b): walk HBH → land on
  ICMPv6 at l3+48 → parse correctly.
- **DISAGREEMENT: learning misses the NA; forwarding/screen find the
  ICMPv6.** A canary that asserts the learning L4 offset equals
  `packet_rel_l4_offset_and_protocol(&frame[l3..], AF_INET6)` FAILS.

### 4.3 Single 0x88a8 IPv4 frame through NAT64
- `nat64::frame_l3_offset` (L2-d): 0x88a8 ≠ 0x8100 → l3 = **14** (treats
  as untagged) → reads IP header starting *inside the VLAN tag* → garbage
  translation.
- shim `meta.l3_offset` = 18. **DISAGREEMENT of 4 bytes.**

---

## 5. Design — the canonical parsers

### 5.1 ONE canonical Ethernet-L2 parser

New module `afxdp/frame/parse/l2.rs` (the issue suggests an
`afxdp/frame/parse/` tree; we adopt that path but scope the move
pragmatically — see §6 options).

```rust
/// Parsed L2 result: L3 offset, terminal (innermost) ethertype, and the
/// VLAN tag stack actually present.
pub(in crate::afxdp) struct L2 {
    pub l3_offset: usize,
    pub ethertype: u16,
    pub outer_vlan: Option<VlanTag>,   // 802.1Q or 802.1ad
    pub inner_vlan: Option<VlanTag>,   // QinQ inner 802.1Q
}
pub(in crate::afxdp) struct VlanTag { pub tpid: u16, pub vid: u16, pub pcp: u8 }

pub(in crate::afxdp) fn parse_l2(frame: &[u8]) -> Option<L2>;
```

Behavior:
- untagged → l3 = 14
- single 0x8100 **or 0x88a8** → l3 = 18 (one tag), terminal ethertype =
  inner; record `outer_vlan`.
- QinQ (0x88a8/0x8100 outer whose inner ethertype is 0x8100/0x88a8) →
  l3 = 22, terminal ethertype = innermost; record outer + inner.
  This is the ONE place we ADD double-tag unwinding (it costs one more
  bounded 4-byte hop). Whether to actually admit double-tagged transit is
  a downstream policy question (the shim still drops it; see §8 risk) — but
  the *parser* should handle the shape so the userspace parsers stop
  disagreeing with reality.
- bounds-checked at every hop; returns `None` on truncation (never panics,
  never reads past `frame.len()`).

All five L2-a..L2-e collapse onto thin adapters over `parse_l2`:
- `classify_arp` / `parse_ndp_neighbor_advert` use `L2{l3_offset,
  ethertype}`.
- `frame_l3_offset` becomes `parse_l2(frame).map(|l| l.l3_offset)`.
- `ecn::ethernet_l3` becomes `parse_l2` + ethertype→family match (it can
  keep rejecting unknown inner if desired, but now QinQ resolves instead of
  rejecting).
- `nat64::frame_l3_offset` → `parse_l2(...).l3_offset` (fixes the 0x88a8
  l3=14 corruption).
- `icmp::ingress_reply_l2` → keep its `(src,dst)` MAC read but take
  `vlan_id` from `parse_l2`'s outer tag.

### 5.2 ONE canonical IPv6 extension-header walker

Reuse the **existing** `packet_rel_l4_offset_and_protocol` (#2148, V6-a) as
the base engine, but make it the SSOT by lifting it into
`afxdp/frame/parse/ipv6.rs` and giving it a fragment-aware variant so the
three current walkers become callers, not copies:

```rust
/// Walk the IPv6 ext-header chain over an L3-relative slice. Returns the
/// L4 offset, terminal protocol, and fragment disposition.
pub(in crate::afxdp) struct Ipv6Walk {
    pub l4_offset: usize,
    pub protocol: u8,
    pub is_fragment: bool,
    pub is_first_fragment: bool,
}
pub(in crate::afxdp) enum WalkError { Truncated }   // for fail-closed callers
pub(in crate::afxdp) fn walk_ipv6_ext(packet: &[u8]) -> Result<Ipv6Walk, WalkError>;
```

- V6-a callers (forwarding/GRE) keep their `Option`/None semantics via a
  thin `.ok()` adapter; their bound stays **6** (see §8 decision post-SMR:
  preserve per-caller bounds via a parameter; do NOT standardize in this
  refactor).
- V6-b (screen) maps `WalkError::Truncated → ScreenParseError::
  TruncatedIpv6ExtChain` to preserve the #2146/#2189 fail-closed contract
  EXACTLY.
- V6-c (icmp_embed) keeps its "non-first fragment → None" by checking
  `is_fragment && !is_first_fragment` on the result.
- **`parse_ndp_neighbor_advert` gains the walk** — it calls
  `walk_ipv6_ext(&frame[l3..])`, and only treats the frame as an NA when
  `protocol == 58` at the walked L4 offset. This is the latent-correctness
  sub-fix.

### 5.3 What stays separate (documented, not merged)

- `pkg/vrrp` Go `walkIPv6ExtHeaders` — different language; keep separate,
  cross-reference in `pkg/vrrp/README.md` and the new parse module doc.
- XDP shim `parse_l2`/`parse_ipv6` — kernel/no_std/verifier; keep separate.
  Add a doc note that the shim is the authority for `meta.l3_offset` and
  that the userspace canonical parser must agree with it on every shape the
  shim steers (untagged / single-tag). If we add QinQ-double to the
  userspace parser, the shim still drops double-tags, so there is no
  divergence in *reachable* frames — but document the gap so a future
  shim change knows to update both.

---

## 6. Options (the surface)

### Option A — Minimal fix-the-disagreement (NO new module tree)
Scope: fix L2-a (`parse_eth_offsets` to handle 0x88a8 as a single tag) and
L2-d (`nat64::frame_l3_offset`), add the ext-header walk to
`parse_ndp_neighbor_advert` by calling the existing
`packet_rel_l4_offset_and_protocol`. Add the two canaries.
- Pros: ~40 LOC, no churn, lands fast, removes the two real bugs and the
  ext-header gap, zero behavioral change to forwarding/screen.
- Cons: still 5 L2 parsers + 3 V6 walkers; the SSOT problem persists; the
  next 0x88a8/ext-header edge can drift again.
- Hot-path: only `nat64` and the (unreachable) learning path change; no
  forwarding/screen hot-path delta.

### Option B — Full unification (the issue's `afxdp/frame/parse/` tree)
Scope: §5.1 + §5.2 — one `parse_l2`, one `walk_ipv6_ext`, all
five L2 + three V6 callers become adapters; add QinQ-double unwinding to the
parser; add the canaries; move `arp.rs`/`ndp.rs` under `parse/`.
- Pros: true SSOT; QinQ-double shape handled uniformly; future-proof; the
  canary makes drift a compile/test failure.
- Cons: larger diff (~400-600 LOC moved/adapted across 8 files); risk of
  perturbing the #2146/#2189 fail-closed screen contract and the #2148/#1838
  fragment semantics; must re-validate every adapter byte-for-byte; hot-path
  touched (forwarding `frame_l4_offset`, screen extract) so a smoke is
  mandatory.
- Hot-path: forwarding + screen now go through the unified walker. MUST be
  `#[inline]`, allocation-free, bounded — verified by codegen inspection
  (no `Vec`, no `String`, no heap) and a line-rate smoke.

### Option C — Hybrid (RECOMMENDED)
Two PRs:
- **PR-1 (correctness, small):** Option A. Fixes the two real L2 bugs +
  the NDP ext-header gap + adds the two canaries that assert L2-a ==
  L2-b and learning-walk == forwarding-walk over a generated corpus of L2
  shapes (untagged / 0x8100 / 0x88a8 / QinQ) and ext-header chains. This
  alone closes #2150's correctness intent and is independently mergeable
  and low-risk.
- **PR-2 (refactor, larger):** Option B unification, gated on PR-1's
  canaries already being green (so the refactor is provably behavior-
  preserving — the canary fails the instant an adapter diverges). Includes
  the QinQ-double parser support and the module move.

Rationale: PR-1 delivers the safety value immediately at low risk; PR-2
delivers the maintainability value with the canary as a correctness
ratchet. If PR-2 review surfaces unacceptable hot-path or contract risk,
PR-1 still stands and #2150's correctness intent is satisfied.

**Recommendation: Option C.** If the engineer prefers a single PR, do
Option B but land the canaries FIRST in the same PR before the adapter
swap, and keep each adapter swap a separate commit so review can verify
behavior-preservation per-call-site.

---

## 7. Test / validation plan

Unit (Rust, `cargo test -p userspace-dp`):
1. **L2 canary**: for every shape in {untagged, 0x8100/vid100,
   0x88a8/vid100, QinQ 0x88a8+0x8100} × {IPv4, IPv6, ARP}, assert
   `parse_l2(f).l3_offset` equals the shim's offset (14/18/22) AND that all
   surviving adapters (`frame_l3_offset`, `ecn::ethernet_l3`,
   `nat64::frame_l3_offset`, `parse_eth_offsets`) agree.
2. **NDP ext-header**: NA behind HBH / dest-opt / routing header is parsed
   (target IP + TLLA MAC) — the new sub-fix. NA behind a *truncated* ext
   chain returns None (no panic, no OOB).
3. **0x88a8 ARP**: `classify_arp` on a single-0x88a8 ARP reply now returns
   `Reply` (was `NotArp`).
4. **nat64 0x88a8**: translation of a 0x88a8 IPv4 frame reads the IP header
   at offset 18 (was 14).
5. **Screen fail-closed preserved (#2146/#2189)**: re-run the existing
   `screen/tests.rs` truncated-ext-chain / syn-frag-bypass tests against
   the unified walker — they MUST still drop (Err). This is the
   highest-risk regression surface.
6. **Embedded ICMPv6 (#1838) preserved**: re-run icmp_embed tests; quoted
   non-first fragment still returns None.
7. **Frame prop tests**: existing `frame/prop_tests` (which already
   generate 0x8100/0x88a8 via `arb_vlan_tag`) must still pass.

Integration / smoke (loss userspace cluster, MANDATORY if PR-2 / Option B
lands — hot-path):
- `make cluster-deploy` + `./test/incus/apply-cos-config.sh` (deploy wipes
  CoS).
- Sustained iperf3 v4 + v6 through `172.16.80.200` / `2001:559:8585:80::200`
  for ≥15s each direction (per `feedback_verify_forwarding_with_sustained_iperf`)
  — confirm line rate, no stalls, `show security flow statistics` advancing.
- `make test-failover` (touches forwarding/neighbor; must be 14/0).
- Single-0x88a8 VLAN sub-interface forwarding sanity if a 0x88a8 transit
  path can be constructed in the cluster (the cluster uses 0x8100 VLAN 50/80
  today — a 0x88a8 path may not be constructible; if not, the unit canary is
  the authority and the smoke covers the no-regression on 0x8100).

NOT required: VRRP/cluster `walkIPv6ExtHeaders` (Go, untouched).

---

## 8. Risks & decisions

| Risk | Mitigation |
|------|-----------|
| Perturbing the #2146/#2189 screen fail-closed contract | Screen adapter maps `WalkError::Truncated → ScreenParseError::TruncatedIpv6ExtChain` 1:1; re-run the exact existing screen tests; per-call-site commit so review can diff behavior. |
| Walker iteration-bound change (6 vs 8) altering drop behavior | DECISION (post-SMR F3): **preserve each caller's existing bound** as a parameter to `walk_ipv6_ext` (forwarding/GRE = 6, screen = 8, embed = 6) so the unification is provably byte-identical. A frame with 7-8 ext headers that the 6-bound forwarding walker terminated early (returning `Some(offset)` mid-chain, NOT real L4) must keep that exact behavior — changing it would alter session keying / NAT for adversarial frames. Standardizing all callers to 8 is a SEPARATE follow-up issue, gated on its own test. The PR-1 canary MUST include 7- and 8-header IPv6 chains to pin this. |
| QinQ DOUBLE-tag parser support adds surface for a shape the shim drops | DECISION (post-SMR F4): the HARD requirement is **single-0x88a8 agreement** (or uniform rejection) across all parsers. Double-tag unwinding in the userspace parser is OPTIONAL (no reachable effect — shim drops double-tags). If added, the canary asserts all parsers either agree on the double-tag l3 OR uniformly reject it (uniform rejection is valid agreement). Do NOT claim double-tag transit support. |
| Adding QinQ-double parsing to userspace while shim still drops it | No reachable divergence (shim drops double-tags before userspace). Document the gap; do NOT claim double-tag transit support. If double-tag transit is desired, file a separate issue covering BOTH shim `parse_l2` and userspace. |
| Hot-path allocation/regression from unification | All canonical fns `#[inline]`, return `usize`/POD structs, no `Vec`/`String`; verify via `cargo asm`/`nm` zero-heap and a line-rate smoke (Option B only). |
| Frag semantics drift (#1838 / #2146) | The unified `Ipv6Walk` returns explicit `is_fragment`/`is_first_fragment`; each caller re-derives its prior predicate from those fields; covered by tests 5+6. |
| Over-scoping (pulling in VRRP Go walker / shim) | Explicitly out of scope, documented in §2.3 + §5.3. |

---

## 9. Documentation updates (part of the change)

- New `docs/research/2150-parser-consolidation/plan.md` (this file) +
  `claude-smr-plan-r1.md`.
- `userspace-dp/src/afxdp/frame/parse/README.md` (or a module doc comment)
  describing the canonical L2 + IPv6 parsers, the adapter list, and the
  **cross-reference to the two parallel implementations that intentionally
  stay separate** (shim `parse_l2`, Go `pkg/vrrp walkIPv6ExtHeaders`).
- Update `userspace-dp/src/afxdp/parser.rs` doc comment to point at the
  canonical parser and note the 0x88a8 + ext-header fix.
- Note in `pkg/vrrp/README.md` that the Rust dataplane has its own
  canonical walker (so future readers don't try to share across the
  boundary).

## 10. Files touched (estimate)

PR-1 (Option A): `afxdp/parser.rs`, `nat64.rs`, `afxdp/parser_tests.rs`
(+ canary), `nat64_tests.rs`. ~5 files, ~80 LOC net.

PR-2 (Option B): new `afxdp/frame/parse/{mod,l2,ipv6,arp,ndp}.rs`;
adapters in `afxdp/frame/inspect.rs`, `afxdp/cos/ecn.rs`, `nat64.rs`,
`afxdp/icmp.rs`, `screen/extract.rs`, `afxdp/icmp_embed/parse.rs`,
`afxdp/parser.rs`; doc files. ~12-14 files.

## 11. Recommendation summary

- **Disposition: PLAN-READY — refactor + 2 latent-correctness sub-fixes.
  NOT PLAN-KILL.**
- **The issue's live-blackhole mechanism is refuted** (ARP and NDP-NA are
  XDP_PASSed by the shim and never reach the userspace learning path; QinQ
  double-tags are dropped at the shim). Document this so the verdict is on
  record.
- **The issue's conclusion is correct**: the userspace parsers genuinely
  disagree on 0x88a8 and ext-headers, two of them (`parse_eth_offsets`,
  `nat64::frame_l3_offset`) are outright wrong on a single 0x88a8 tag, and
  `parse_ndp_neighbor_advert` lacks the ext-header walk its forwarding
  counterparts have. Fixing them removes a latent trap before a steering
  change springs it.
- **Recommended path: Option C (hybrid)** — PR-1 small correctness fix +
  canaries (independently valuable, low risk); PR-2 full unification gated
  on PR-1's canaries.
- **Reuse, don't duplicate**: base the canonical IPv6 walker on the
  existing #2148 `packet_rel_l4_offset_and_protocol`; map the screen
  adapter onto the #2189 fail-closed contract; keep the #2188 Go VRRP
  walker and the XDP shim parser explicitly separate.
- **Mandatory gate for the hot-path PR-2**: sustained iperf3 v4+v6 smoke +
  `make test-failover` on the loss userspace cluster; the screen
  fail-closed and embedded-fragment tests are the highest regression risk.
