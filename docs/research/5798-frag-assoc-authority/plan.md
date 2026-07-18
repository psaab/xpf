# Plan: authority-keyed, ingress-domain-scoped shared fragment association
## Coupled root+beneficiary — #5798 (root, HIGH/security) + #5689 (beneficiary) + PR #6095 (reference base)

- **Status:** PLAN-READY (recommended Path A + protocol-in-key + observability counter)
- **Research branch:** `research/5798-frag-assoc-authority` (docs only)
- **Baseline studied:** `origin/master` @ `340df9c8f`; reference implementation
  PR #6095 head `9e13d448533ce095b117db206d3446ed6904cd26`
  (`fix/5689-nat-frag-assoc`).
- **Contract:** `/research` — stops at PLAN-READY. No production source touched.
  No PR. Manual approval via `/engineer 5798` proceeds; #6095 is the base to
  harden, not re-implement.
- **Hostile reviews:** Claude SMR (complete — see `claude-smr-plan-r1.md`;
  caught + folded finding SMR-1). Codex + AGY both infra-blocked this session
  (Codex model/CLI version mismatch; AGY headless permission auto-deny) —
  retries documented in the SMR appendix; proceeded on Claude SMR.

---

## 1. Problem statement

The dataplane authorizes a **non-first IP fragment** by looking up a shared
fragment-association cache keyed on `(addr_family, src, dst, ident)` and, on a
hit, **returns the first fragment's committed `SessionDecision` directly** —
short-circuiting the flowless L3 enforcement arm (interface input filter, PBR
`then routing-instance`, zone security policy).

Because the key carries **no ingress identity** (no ingress ifindex, no zone,
no VRF/routing-instance, no IP protocol, no fabric-origin), a non-first
fragment that shares `(family, src, dst, ident)` with a first fragment from a
**different ingress security domain** aliases onto that domain's decision and
is forwarded under an authority it never earned.

Two coupled issues:

- **#5798 (root, OPEN, HIGH, `bug`+`security`)** — the NAT64 fragment
  association hit is not ingress-domain scoped; a NAT64 non-first fragment
  bypasses input-filter / PBR / zone-policy enforcement.
- **#5689 + PR #6095 (beneficiary, now DRAFT)** — cured the ordinary
  same-family NAT/NPTv6 non-first-fragment confidentiality leak (untranslated
  forward of the internal source / pre-DNAT destination) by **reusing the same
  unscoped NAT64 cache**. An independent hostile review found this **broadens
  #5798's bypass from NAT64-only to all SNAT/DNAT/static-NAT/NPTv6** — a path
  that previously always traversed full enforcement with its real L3 identity.

The two are one design problem: a **shared, authority-keyed,
ingress-domain-scoped** fragment association for both NAT64 and ordinary NAT.

---

## 2. Root cause / mechanism (mechanically verified)

### 2.1 The shared cache and its key (reference base, PR #6095 head)

`userspace-dp/src/nat64.rs`:

- `Nat64FragKey` (~L356–364): `addr_family: u8`, `src: IpAddr`, `dst: IpAddr`,
  `ident: u32`. **No protocol, no ingress identity.**
- `Nat64FragEntry` (~L367–382) adds `generation: u64` — the #5624 config-gen
  guard (a lookup under a different current generation evicts + misses).
- `Nat64FragAssoc` (~L385–438): `shards: Arc<Vec<Mutex<Vec<Nat64FragEntry>>>>`;
  `NAT64_FRAG_SHARDS * NAT64_FRAG_CAP_PER_SHARD (64)` = **1024** entries;
  `NAT64_FRAG_TTL_NS` = **2 s**. `install` (~L465) is first-fragment gated with
  expired-before-live prune (#5447); `lookup` (~L529) prunes expired, refreshes
  LRU, enforces the generation guard.
- Key builders `nat64_first_fragment_key` (~L617) /
  `nat64_nonfirst_fragment_key` (~L629) both funnel through
  `nat64_fragment_fields(packet, addr_family)` (~L575). **They take only
  `(packet, addr_family)` — they never see `meta`, so no ingress dimension can
  enter the key today.**

### 2.2 The pre-enforcement short-circuit

`userspace-dp/src/afxdp/poll_descriptor/mod.rs`, in
`poll_binding_process_descriptor`, the flowless arm is shaped:

```rust
} else if let Some(hit) = packet_frame.get(meta.l3_offset as usize..).and_then(|l3| {
        nat64_consult_forward_fragment_assoc(forwarding, l3, af, now_ns)   // #2562 NAT64
            .or_else(|| nat_consult_forward_fragment_assoc(forwarding, l3, af, now_ns)) // #6095 ordinary
    })
{
    hit                                   // <-- cached decision wins, verbatim
} else {
    // FLOWLESS ENFORCEMENT (the miss branch ONLY):
    //   (1) evaluate_non_pbr_input_filter(...)        interface input filter
    //   (2) ingress_route_table_override(...)         PBR `then routing-instance`
    //   (3) flowless_base_resolution(...) + zone policy
    // Comment on the arm: "Without this a `deny-all` zone pair fails OPEN for
    // fragments (it resolves a route and forwards)."
}
```

On a **hit**, `decision = hit` and control falls to the shared post-decision
forward/TX path. The three enforcement gates live **only** in the `else`
(miss) branch. Therefore a hit **bypasses all three** — exactly the #5798
defect. Install is at the ordinary session-commit site (diff wiring ~L3254);
consult at ~L3746.

### 2.3 Why the key aliases across domains

`nat64_consult_forward_fragment_assoc` is v6-only and filters to `nat.nat64`
decisions; `nat_consult_forward_fragment_assoc` handles v4+v6 and filters to
same-family address rewrites. Both derive the key from `(family, src, dst,
ident)` only. A non-first fragment from domain B with the same tuple/ident as a
domain-A first fragment computes the **same key**, hits domain A's entry, and
inherits A's permit + egress + NAT — never running B's input filter, PBR, or
zone policy. Fragment-ID is a 16-bit (v4) / 32-bit (v6) datagram label, **not
an authorization token**; it is guessable / spoofable / collidable across
VRFs with duplicate address space.

---

## 3. The decisive enabling finding — authority is already on `meta`

The central design question ("can the ingress authority even be derived on the
**non-first-fragment consult** path?") is answered **YES, with zero extra
resolution**. The XDP shim stamps the full ingress identity onto every packet's
`UserspaceDpMeta` (`userspace-dp/src/afxdp/types/mod.rs` ~L100–130, `#[repr(C)]`
size 96):

| Field | Meaning | Authority role |
|-------|---------|----------------|
| `ingress_ifindex: u32` | shim-stamped ingress interface | **primary authority** |
| `ingress_vlan_id: u16` + `ingress_vlan_present: u8` | logical unit / 802.1Q | logical-interface disambiguation |
| `ingress_zone: u16` | shim-stamped ingress zone | derived authority (see §7) |
| `routing_table: u32` | ingress routing table / VRF | derived authority |
| `protocol: u8` | IP protocol | protocol-collision fix (mandatory) |
| `addr_family: u8` | AF_INET / AF_INET6 | already in key |
| `config_generation: u64`, `fib_generation: u32` | live stamps | already used by build_generation guard |

Additionally, two **Rust-resolved effective-ingress bindings** are already in
scope at **both** the install site (~L3254) and the consult site (~L3746):

- `ingress_zone_override: Option<u16>` — the effective ingress zone **after**
  GRE-decap / fabric normalization (what the enforcement arm actually uses:
  `evaluate_non_pbr_input_filter(..., ingress_zone_override, ...)`).
- `packet_fabric_ingress: bool` — fabric-origin bit (used at `!packet_fabric_ingress`
  immediately above the consult arm).

**Consequence:** every dimension #5798's required-fix #2 lists
(family / protocol / effective ingress ifindex / effective zone / routing
instance / fabric origin) is available at consult time **without** resolving a
route, a zone, or a session. Path A (authority in the key) needs **no new
resolution machinery** — it threads existing `meta` + two in-scope bindings
into the key builder. This removes the primary PLAN-KILL condition.

### 3.1 Precedent: the flow cache is already ingress-scoped

`userspace-dp/src/afxdp/flow_cache.rs`: `FlowCacheEntry` carries
`ingress_ifindex: i32` (~L182) and a `FlowCacheStamp`
(`config_generation`/`fib_generation`); `FlowCacheLookup::for_packet`
(~L168) stamps `ingress_ifindex` + generations and a hit is rejected on
ifindex or generation mismatch. **The dataplane already treats "ingress
ifindex + generation" as part of a cached forwarding decision's identity for
the flow cache.** The fragment association is the one cached-decision path that
does *not* — this plan brings it to parity.

---

## 4. Blast radius / scope

- **Pre-#6095 (master):** bypass is **NAT64-only** (v6→v4 forward fragments).
  `nat64_consult_forward_fragment_assoc` is the only association consulted
  before the flowless arm.
- **With #6095 (draft):** bypass **broadens to all ordinary same-family NAT** —
  interface/pool/static SNAT, DNAT, static NAT, NPTv6, v4 **and** v6, forward
  direction. This is the regression the hold blocks.
- **Reachability:** the shared `Arc`-backed cross-worker cache makes a
  domain-A decision globally visible to a fragment landing on any worker/queue
  on any interface. Reachable with a coordinated/spoofing sender, mirrored
  traffic, interface migration, or duplicate address space across VRFs, within
  the 2 s TTL.
- **Files the fix touches (estimate):** `nat64.rs` (key struct + builder
  signature), `afxdp/poll_descriptor/mod.rs` (thread `meta`/overrides into the
  two install + two consult call sites), a counter (BatchCounters plumbing +
  `format/status*.go` row), `tests_fragment.rs` + `nat64.rs` tests, and
  `userspace-dp/src/FEATURES.md` + `docs/`. Path A is a **narrow, structural**
  change on top of #6095; Path C adds a module-tree reorg.

---

## 5. Constraints & invariants (must all hold)

1. **Fail-closed.** Loss/absence/mismatch of an association must **drop** a
   NAT-relevant fragment or fall through to full enforcement — never inherit a
   foreign domain's permit, and never (re)introduce the #5689 untranslated
   leak on a wrong-domain path.
2. **No L4 reads on a non-first fragment.** Payload bytes are never interpreted
   as ports (#2344). The key uses only IP-declared fields.
3. **Single SSOT key builder.** Install and lookup keys must be byte-identical,
   derived through one helper after GRE/fabric ingress normalization (#5798
   fix #3).
4. **Effective ingress, not raw underlay.** The authority must be the *same*
   effective-ingress notion the enforcement arm uses (`ingress_zone_override` /
   `packet_fabric_ingress`), so a GRE-decapped or fabric-ingress fragment is
   scoped to the domain enforcement would place it in — not the physical port.
5. **Bounded, cross-worker, first-install/non-first-lookup-only.** Preserve the
   1024-entry cap, 2 s TTL, expired-before-live prune (#5447), and
   generation guard (#5624). Non-first fragments must remain lookup-only so a
   tail-fragment flood cannot grow state.
6. **NAT64 + ordinary share one key type.** The fix must close #5798 (NAT64
   root) and #6095's broadened ordinary bypass **together** (see §9).
7. **Protocol in the key.** A TCP first fragment and a UDP non-first fragment
   with the same `(family, src, dst, ident)` must not alias (protocol
   collision — #5798 fix #2, #5689 constraint 1).
8. **Per-packet input filter runs on a HIT too (#5798 fix #4).** An
   authority-validated hit may inherit the first fragment's *stateful
   zone-policy permit + NAT translation + egress route*, but it **must not
   bypass per-packet interface input-filter semantics**: a `from is-fragment
   then discard`, address, or protocol term on the ingress interface must still
   apply to the non-first fragment. Today the input filter / screen live **only
   in the miss `else` branch** (poll_descriptor ~L3826+), so a hit skips them —
   the authority key alone does **not** close this. See §6 (recommended design)
   and finding SMR-1.

---

## 6. Multiple Path Options

### Path A — Authority **in the key** (RECOMMENDED)

Append the effective ingress authority + protocol to the association key:

```
FragKey = (addr_family, ip_protocol, effective_ingress_ifindex,
           ingress_vlan_id, effective_ingress_zone /*=zone_override|meta.ingress_zone*/,
           fabric_ingress_bit, src, dst, ident)
```

A cross-domain non-first fragment computes a **different key → clean MISS →
falls through to the full flowless enforcement arm** with its real L3 identity
(input filter, PBR, zone policy re-run). A same-domain non-first fragment (same
effective ingress) hits and legitimately inherits the first fragment's decision
— *including* its PBR-steered routing-table, which is correct reassembly
consistency because it provably came from the same ingress domain.

- **Correctness / fail-closed:** **Fail-closed by construction.** There is no
  window in which a foreign decision is read and then rejected; the wrong entry
  is simply *never found*. This is a **structural** guarantee, the strongest
  kind — a future refactor cannot silently drop a "compare" check and reopen
  the bypass (there is no check to drop).
- **Re-routing false-miss risk:** a fragment that legitimately arrives on a
  *different* firewall ingress interface than its first fragment misses. In all
  realistic topologies the fragments of one datagram from one source share the
  same L3 next-hop to the firewall and land on the same ingress logical
  interface; asymmetric per-fragment ingress-interface arrival at a *single*
  firewall is pathological. When it does happen, the miss **falls through to
  full enforcement** (safe) and degrades to pre-#5689 flowless behavior — an
  availability nit, never a security hole.
- **Blast radius:** smallest. Add fields to `Nat64FragKey`; change
  `nat64_fragment_fields`/`nat64_first_fragment_key`/`nat64_nonfirst_fragment_key`
  to take the authority (thread `meta` + `ingress_zone_override` +
  `packet_fabric_ingress`); thread those into the 2 install + 2 consult call
  sites (all already have them in scope). No new resolution, no new module, no
  new lookup path.
- **Composition with #6095:** direct. #6095's install/consult wiring and
  mutual-exclusion (`nat64` flag) are unchanged; only the key gains dimensions.
- **Downside:** a cross-domain alias attempt is **indistinguishable from a
  benign absent-first-fragment miss** (both are "no entry"), so #5798 fix #5's
  "distinct cross-domain counter" is not naturally satisfiable from the key
  path alone. Mitigation: an **observability-only** best-effort coarse probe
  (§6, Recommendation) that never affects forwarding.

### Path B — Authority **in the value, re-validated on consult**

Keep a coarse key `(family, src, dst, ident)`; store the first fragment's
authority tuple in the value; on a key hit, **compare** the non-first
fragment's live ingress authority; mismatch → fail-closed MISS + a dedicated
`frag_domain_mismatch` counter.

- **Correctness / fail-closed:** correct *if the compare is always run and
  always correct*. It is **check-then-reject**, not structural: the wrong
  decision is fetched and then discarded. A future edit that reorders or drops
  the compare silently reopens the full #5798 bypass. Weaker security posture.
- **Re-routing false-miss risk:** identical to Path A (a real domain change
  still misses) — no availability advantage.
- **Distinguishes wrong-domain vs absent:** **yes** — this is its one real
  advantage; it satisfies #5798 fix #5 literally with a first-class counter.
- **Blast radius:** larger — a `FragmentAuthorityStamp` in the value, an
  authority resolver invoked at consult (before enforcement), and a compare.
  A coarse key also lets an attacker force shard collisions more cheaply (many
  domains → same `(src,dst,ident)` → one shard).
- **Composition with #6095:** moderate — value grows, consult gains a compare.

### Path C — Modular shared `fragment_assoc/` component (the #5798 fix #1 destination)

Extract a real module tree (`fragment_assoc/{mod,key,cache,tests}.rs`)
unifying NAT64 + ordinary NAT behind the authority key + protocol, with the
sharded fixed-slot cache (replacing the NAT64 `Mutex<Vec>` linear scan) and the
full regression matrix. This is what #5798 required-fix #1 and the #5689
architecture proposal (its 11-section comment) ultimately call for.

- **Correctness / fail-closed:** same guarantee as whichever key model it
  embeds (recommend it embed Path A's key).
- **Blast radius:** **largest** — a new module tree, migration of the NAT64
  cache off `Nat64FragAssoc`, touching #5146/#5447/#5624/#5798 adjacent owners.
  High review cost; higher regression surface while #5798 is an *open HIGH*.
- **Composition with #6095:** replaces #6095's "reuse the NAT64 cache"
  mechanic wholesale — a re-architecture, not a hardening of the reference
  branch. Slower to land the security fix.
- **Value:** the correct long-term home; the miss-classifier (§8 below) and the
  fixed-slot cache belong here. Stage it **after** the security key lands.

---

## 6. Recommended approach — **Path A⁺ now, Path C staged as follow-up**

The recommended fix is **Path A plus a consult reorder** (call it **Path A⁺**):
the authority key closes the *cross-domain permit inheritance*, and the reorder
closes the *per-packet input-filter bypass* that the authority key does **not**
cover (constraint 8 / #5798 fix #4). Both are required; neither alone is
sufficient.

**Element 1 — Path A (authority in the key)** layered on PR #6095 as the
load-bearing domain-scoping fix, because:

1. It is **fail-closed by construction** — the strongest guarantee, and the one
   a security boundary should prefer over check-then-reject (Path B).
2. Every authority dimension is **already on `meta`** + two in-scope bindings,
   so it needs **no new resolution** at consult time — the simplest change that
   is also the safest.
3. It **composes directly** with #6095 (key gains fields; install/consult
   wiring and mutual exclusion unchanged) — it *hardens* the reference branch
   exactly as the maintainer's coupling comment directs.
4. It closes **both** #5798 (NAT64 root) and #6095's broadened ordinary bypass
   in one edit, because both consults derive keys from the same builder (§9).

**Element 2 — consult reorder (per-packet input filter on hit).** Restructure
the flowless arm so the per-packet **non-PBR interface input filter** (and
screen/IPsec) evaluates the non-first fragment's own L3 identity
(`is_fragment=true`, `l4_present=false`) **before** any inherited decision is
applied — on **both** hit and miss. Concretely: hoist the
`evaluate_non_pbr_input_filter` gate (currently only in the miss `else` branch,
~L3826+) to run ahead of the `consult → hit` branch, or run it inside the hit
branch before returning. A hit that clears its own input filter then inherits
the first fragment's *stateful zone-policy permit + NAT translation + egress
route*; a hit whose non-first fragment is caught by a `from is-fragment`/
address/protocol discard term is dropped (silent — no L4 to reject from). This
is exactly what #5798 fix #4 mandates and what the #5689 architecture proposal
(section 5, non-first step 2) specifies. **Without this element the fix is
incomplete** — an `is-fragment then discard` input-filter term would still be
bypassed for a same-domain hit.

**Authority dimension = effective logical ingress interface** (`ingress_ifindex`
+ `ingress_vlan_id`), reconciled with the enforcement's effective-ingress view
(`ingress_zone_override` / `packet_fabric_ingress`), **plus IP protocol**. The
key MUST derive from **exactly** the ingress inputs the enforcement arm uses, so
that "same key ⟺ same enforcement domain" holds by construction (§7).

**For the #5798 fix #5 "distinct counter":** add an **observability-only**
best-effort probe. On a full-authority-key MISS for a *NAT-relevant* non-first
fragment, do one coarse `(family, src, dst, ident)` shard scan **purely to bump
a `frag_domain_mismatch` counter** if a live entry exists under a *different*
authority — then still take the fail-closed path. This surfaces the security
signal (cross-domain aliasing attempts are visible on `show ... status`)
**without** letting the coarse probe influence any forwarding decision, so
Path A's structural guarantee is preserved. If the maintainer prefers, this
probe can be omitted entirely and cross-domain fragments counted under the
existing enforcement-path drop counters — the forwarding behavior is identical
either way.

**Stage Path C** (modular `fragment_assoc/`) as a **separate follow-up** issue:
the module reorg, the fixed-slot sharded cache, and the optional miss-classifier
(§8). It is the right destination but a large refactor that should not gate an
open HIGH security fix.

---

## 7. Which ingress dimension is the correct authority?

The authority must be the finest binding that **determines** all three
enforcement gates the hit bypasses. Analysis:

- **Interface input filter is bound per logical interface** (not per zone).
  Two interfaces in the same zone can carry *different* input filters.
- **Zone** is a deterministic function of the (effective) ingress interface.
- **Base routing-instance / VRF** is a function of the ingress interface.
- **PBR `then routing-instance`** is an *outcome* of matching the interface's
  input filter — itself a function of the ingress interface (plus, on the first
  fragment only, L4).

Therefore:

- **Keying on ZONE alone is insufficient** — two interfaces in one zone with
  different input filters would alias, letting a fragment on interface B
  inherit interface A's *input-filter* permit. That is still an input-filter
  bypass.
- **Keying on VRF/routing-instance alone is insufficient** — even coarser
  (many zones/interfaces per RI).
- **Keying on the effective logical ingress interface (ifindex + VLAN/unit) is
  correct** — it is the finest binding, and it *implies* zone + base-RI +
  input-filter selection. Same effective ingress ⟹ same input filter, zone, and
  base RI ⟹ inheriting the first fragment's full decision (including any
  L4-driven PBR steer it legitimately resolved) is correct reassembly, not a
  bypass.

**Reconciling with GRE/fabric:** `meta.ingress_ifindex` is the physical
underlay for a GRE-decapped or fabric-ingress packet; the *effective* ingress
domain used by enforcement is `ingress_zone_override` / `packet_fabric_ingress`.
The authority key must therefore include the effective-ingress view, not the
raw ifindex alone — i.e. key on `(ingress_ifindex, ingress_vlan_id,
effective_zone = ingress_zone_override.unwrap_or(meta.ingress_zone),
fabric_ingress_bit)`. Including the (redundant-but-cheap) effective zone and the
fabric bit is belt-and-suspenders against the case where two packets share an
ifindex but land in different effective zones (native vs GRE-decapped-into-a-
different-zone). All are in scope at both sites.

**Mirror the enforcement's ingress inputs exactly (RETH/bond caveat).** The
guarantee "same key ⟺ same enforcement domain" holds **only** if the key
derives from the *same* ingress inputs the enforcement arm consumes. The
enforcement uses `meta.ingress_ifindex` + `ingress_zone_override` +
`packet_fabric_ingress`; the key must use the same triple. If
`meta.ingress_ifindex` is a **bond/RETH physical member** rather than the
logical reth/unit ifindex, fragments of one datagram hashed across members
would false-miss — but they would fail **closed** (miss → the same enforcement
that the member's identity drives), so the guarantee is preserved and only
availability suffers. `/engineer` MUST confirm whether `meta.ingress_ifindex`
is the effective logical ingress (reth/unit) or a member, and, if a member, key
on the logical ifindex the enforcement resolves — to avoid the false-miss. This
is a verification item, not a blocker: the fail-closed direction is safe either
way.

**Protocol-in-key sub-fix (mandatory, independent of A/B/C):** add
`meta.protocol` to the key. Without it, a TCP first fragment and a UDP
non-first fragment sharing `(family, src, dst, ident)` alias — a protocol
collision that both #5798 (fix #2) and #5689 (constraint 1) call out. This is a
one-field addition and should land with the authority key.

---

## 8. Note on the miss-classifier (deliberately OUT of scope for Path A)

The #5689 architecture comment (section 6) proposes a `FragmentNatImpactIndex`
that **drops** an *association-miss* fragment when any NAT/NPT rule *could*
translate it — closing the residual #5689 untranslated-leak on a genuine miss
(reorder/expiry/eviction/failover). That is a **separate axis** from the #5798
authority bypass:

- **#5798 (this plan):** a *hit* must be domain-scoped. Path A fixes it.
- **#5689 residual (miss-leak):** a *miss* on a NAT-relevant fragment must not
  forward untranslated. That is the miss-classifier's job.

Path A's fail-closed-fall-through means a cross-domain fragment now MISSES and
runs full enforcement under its real identity — which, for its *real* domain,
may itself be a NAT-relevant flowless fragment with no association (the exact
pre-existing #5689 miss case #6095 already documents as a fail-closed
limitation). The miss-classifier is the principled fix for that residual and
belongs to **Path C / a #5689 follow-up**, not the #5798 security fix. Bundling
it would balloon the change and delay closing an open HIGH. Recommendation:
land Path A for #5798; track the miss-classifier under Path C / #5689's own
increment. This keeps the security fix minimal and reviewable.

---

## 9. Must NAT64 and ordinary NAT land together? — YES for the key, staged for the module

- **The authority-key fix is inherently unified.** Both consults —
  `nat64_consult_forward_fragment_assoc` (NAT64) and
  `nat_consult_forward_fragment_assoc` (ordinary) — derive their keys from the
  **same** `Nat64FragKey` via the **same** builder. Adding authority + protocol
  to that struct + builder fixes **both** paths in one edit. You cannot scope it
  to only ordinary NAT (that leaves #5798's NAT64 root open) or only NAT64
  (that leaves #6095's broadened ordinary bypass open). **So the key change must
  land once, for both.**
- **The module reorg (Path C) is separable.** Moving the cache into
  `fragment_assoc/` and migrating NAT64 off `Nat64FragAssoc` is a follow-up that
  does not gate the security fix.

Net: one PR hardens #6095 with the authority key + protocol + counter + tests
(closes #5798, unblocks #6095/#5689); a second, later PR does the modular
unification + optional miss-classifier.

---

## 10. Implementation plan (for the eventual `/engineer 5798`, on `fix/5689-nat-frag-assoc`)

1. **`nat64.rs` — extend the key (SSOT):**
   - Add to `Nat64FragKey`: `protocol: u8`, `ingress_ifindex: u32`,
     `ingress_vlan_id: u16`, `ingress_zone: u16`, `fabric_ingress: bool`
     (pack the bool into a flags byte for `#[derive(Eq)]` friendliness).
   - Change `nat64_fragment_fields` / `nat64_first_fragment_key` /
     `nat64_nonfirst_fragment_key` to accept an `IngressAuthority` struct (or
     the raw dims) alongside `(packet, addr_family)`. Include the new fields in
     `nat64_frag_shard_index` FNV mix. This is the one SSOT builder (#5798 fix #3).
2. **`poll_descriptor/mod.rs` — thread authority into all four call sites:**
   - Build `IngressAuthority { ifindex: meta.ingress_ifindex, vlan:
     meta.ingress_vlan_id, zone: ingress_zone_override.unwrap_or(meta.ingress_zone),
     fabric: packet_fabric_ingress, protocol: meta.protocol }` once per packet.
   - Pass it to `nat64_first_fragment_key` at the NAT64 install (cold path) and
     `nat_install_forward_fragment_assoc` (~L3254); to the two consults (~L3746).
3. **`poll_descriptor/mod.rs` — consult reorder (constraint 8 / #5798 fix #4):**
   - Hoist the per-packet non-PBR interface input filter
     (`evaluate_non_pbr_input_filter`, currently only in the miss `else` branch
     ~L3826+) so it evaluates the non-first fragment BEFORE the `consult → hit`
     branch applies an inherited decision — or run it inside the hit branch
     before returning `hit`. Preserve screen/IPsec ordering. A hit that clears
     its own input filter inherits the stateful permit + NAT + route; a hit
     caught by an `is-fragment`/address/protocol discard term drops (silent). Do
     **not** hoist the PBR/zone-policy resolution (those are the stateful
     verdict the hit legitimately inherits, per #5798 fix #4) — only the
     per-packet input filter + screen.
4. **Observability-only counter (optional, per §6):** add
   `frag_domain_mismatch` via the established `BatchCounters::record_*` →
   `BindingLiveState` → wire `BindingStatus` → `format/status*.go` row pattern
   (mirror `nat64_frag_dropped`). Bump it only from the best-effort coarse probe;
   never let the probe change forwarding.
5. **Docs:** update `userspace-dp/src/FEATURES.md` (the `nat64.rs` frag rows),
   `docs/fabric-cross-chassis-fwd.md` if it references the assoc, and add/adjust
   a short note in the module doc; log in `_Log.md`.
6. **No BPF ABI / control-wire change.** `meta` already carries every field; the
   key is a Rust-internal struct. Associations remain non-HA-synced.

---

## 11. Test plan / regression matrix (fail-on-revert oriented)

**Key/authority separation (new):**
- Same `(family, src, dst, ident)` from **different ingress ifindex** →
  distinct keys → MISS → full enforcement (assert a `deny-all` domain B drops;
  assert domain B `permit` re-runs and does NOT inherit A's NAT).
- Same `(family, src, dst, ident)`, different **VLAN/unit**, different
  **effective zone (zone_override)**, **fabric vs native ingress**,
  **GRE-decapped vs native** → MISS each.
- Same authority, **different worker** → HIT + translate (cross-worker preserved).
- **Protocol collision:** TCP first + UDP non-first, same tuple/ident → no alias.

**Ordinary-NAT matrix (harden #6095's single test):**
- v4 + v6; interface/pool/static **SNAT**, **DNAT**, static NAT, **NPTv6**
  inbound/outbound, composed src+dst; first-fragment install + non-first hit →
  address-only rewrite; non-first payload/ID/offset/MF byte-identical; **no
  session inserted** for the non-first fragment.

**Input-filter-on-hit (constraint 8 / #5798 fix #4) — the second load-bearing gate:**
- Ingress interface has `filter input { term t { from is-fragment; then
  discard; } }`. A **same-domain** non-first fragment that HITS a valid
  association must still be **dropped** by the is-fragment discard term (the hit
  must NOT bypass it). RED-on-revert: remove the consult reorder → the fragment
  forwards (translated) despite the discard term → test FAILS.
- Same interface, `from source-address <blocked> then discard`: a hit whose
  non-first fragment matches the address term drops; a hit that does not match
  inherits + translates.

**Fail-closed / lifecycle:**
- Cross-domain non-first with no same-domain first → MISS → enforcement drop
  (assert the `frag_domain_mismatch` counter increments **iff** the probe is
  enabled; otherwise the enforcement drop counter).
- TTL expiry, capacity eviction, **config-generation change** (#5624), HA
  failover → miss, never inherited permit.
- Assert install only after a committed forward decision (post session commit),
  no allocator/pool mutation by a non-first fragment.

**RED-on-revert gates (parent must verify firsthand):**
- Neutralize the authority in the key (revert to `(family, src, dst, ident)`) →
  the cross-domain-MISS test goes GREEN-should-be-RED, i.e. the domain-B-deny
  test FAILS (fragment inherits A's permit). This is the load-bearing #5798
  assertion.
- Neutralize protocol-in-key → the protocol-collision test fails.
- Neutralize the consult reorder (input filter back to miss-only) → the
  is-fragment-discard-on-hit test FAILS (fragment forwards despite the term).
- #6095's existing `flowless_non_first_fragment_inherits_ordinary_snat_translation_5689`
  stays GREEN (same-domain hit with no blocking input filter still translates).

**Smoke (post-merge, loss userspace cluster):** v4 + v6 fragmented flows across
a real NAT + a deny-all zone pair; assert same-domain fragments reassemble
translated and cross-interface-spoofed fragments are dropped/enforced. (Not a
`/research` deliverable; noted for `/engineer`.)

---

## 12. Risks & mitigations

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Legit re-routed fragment on a different ingress interface misses (Path A) | Low (availability) | Fails closed to full enforcement; realistic topologies co-locate a datagram's fragments on one ingress; degrades to pre-#5689 flowless behavior |
| `meta.ingress_zone` vs `ingress_zone_override` divergence | Med | Key uses `ingress_zone_override.unwrap_or(meta.ingress_zone)` — the same effective-ingress the enforcement arm uses |
| Observability probe reintroduces coarse-key collision cost / attack surface | Low | Probe is best-effort, off the forwarding decision, and optional; can be dropped entirely |
| Shard-index change (new key fields) perturbs distribution | Low | FNV mix already streams arbitrary bytes; add fields to the mix; cap/prune unchanged |
| Miss-classifier deferral leaves a residual #5689 untranslated-leak on a genuine miss | Med | Pre-existing #6095-documented limitation; tracked to Path C / #5689 follow-up, not regressed by Path A |
| Reverse-direction (reply) association still unimplemented | Low | Forward-only today (both NAT64 and #6095); reverse is a deferred increment; authority key applies identically when it lands |

---

## 13. Open questions for the maintainer

1. **Counter:** ship the observability-only `frag_domain_mismatch` probe, or
   count cross-domain fragments under the existing enforcement drop counters
   (simpler, no coarse probe)? (Recommendation: ship the probe — the security
   signal is cheap and valuable; it never touches forwarding.)
2. **Staging:** confirm Path A (security key) as PR #6095's hardening now, with
   Path C (modular `fragment_assoc/` + miss-classifier) as a tracked follow-up
   issue — vs doing the full Path C in one shot (larger, slower, higher risk on
   an open HIGH).

---

## Appendix — grounded citations (PR #6095 head `9e13d448`)

- `userspace-dp/src/nat64.rs`: `Nat64FragKey` ~L356; `Nat64FragEntry.generation`
  ~L378; `Nat64FragAssoc` / caps / TTL ~L347–438; `install` ~L465; `lookup`
  ~L529; `nat64_fragment_fields` ~L575; `nat64_first_fragment_key` ~L617;
  `nat64_nonfirst_fragment_key` ~L629.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs`:
  `nat_install_forward_fragment_assoc` / `nat_consult_forward_fragment_assoc`
  (new #6095 helpers, after `nat64_consult_forward_fragment_assoc` ~L140);
  ordinary install wiring ~L3254; consult `.or_else()` chain ~L3746; flowless
  enforcement arm (input filter / PBR / zone policy; "deny-all zone pair fails
  OPEN for fragments") in the `else` branch ~L3826+.
- `userspace-dp/src/afxdp/types/mod.rs`: `UserspaceDpMeta` ~L100–130
  (`ingress_ifindex`, `ingress_vlan_id`, `ingress_zone`, `routing_table`,
  `protocol`, `config_generation`, `fib_generation`).
- `userspace-dp/src/afxdp/flow_cache.rs`: `FlowCacheEntry.ingress_ifindex`
  ~L182; `FlowCacheLookup::for_packet` ~L168 (ingress-scoping precedent).
