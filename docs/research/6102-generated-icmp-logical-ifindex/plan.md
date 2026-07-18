# #6102 — Generated ICMP Time-Exceeded / Packet-Too-Big paths key
# egress + CoS-classify on the PHYSICAL bind ifindex instead of the
# LOGICAL unit ifindex

- **Status:** PLAN-READY (research only — no production code touched)
- **Branch:** `research/6102-generated-icmp-logical-ifindex` off
  `origin/master` @ `1e43937f5`
- **Type:** correctness / behavioral gap (silent drop + wrong-unit
  classification on VLAN sub-interfaces), fail-closed §6.2 adjacency
- **Recommendation:** single `/engineer` PR — a mechanical mirror of the
  shipped reject-path (#3976) / SYN-cookie (#3035) precedent at 5 sites +
  test rebuild + doc/comment correction. **No design fork needed** (see §10).

---

## 1. Summary

Two locally-generated ICMP error paths — Time Exceeded / Hop-Limit
Exceeded (TE) and egress-MTU Fragmentation-Needed / Packet-Too-Big (PTB)
— feed the **PHYSICAL** AF_XDP socket-bind ifindex (`ingress_ident.ifindex`)
to (a) the `forwarding.egress` feasibility lookup, (b) the ICMP reply
**builders**, and (c) the `classify_generated_reply` output-filter / CoS
classifier. All three of those maps are keyed by the **LOGICAL unit
ifindex**, not the physical bind port.

The sibling reject path (#3976) and SYN-cookie path (#3035) already
resolve the logical unit once — `resolve_ingress_logical_ifindex(
forwarding, ingress_ifindex, meta.ingress_vlan_id)` — and feed **that**
to the build + classify, while keeping the physical ifindex for the XSK
transmit device. TE and PTB were never converted; their inline comments
even *claim* they pass "the LOGICAL egress ifindex," which is false
(#6046 established `ingress_ident.ifindex` is physical).

**Impact:** on a VLAN sub-interface with no untagged parent unit, the
`forwarding.egress` lookup returns `None`, the builder `?`-returns `None`,
and the generated ICMP is **silently dropped** — breaking traceroute and
PMTUD through the DUT. On a VLAN sub-interface that *does* have an
untagged parent unit, the reply is sourced from the parent's address and
classified with the parent's CoS / DSCP-rewrite / output-filter — a
fail-closed §6.2 output-filter-boundary granularity gap.

This is the behavioral half of #6046 (which was doc-only) and closes the
exact gap the reject path (#3618/#3976) and cookie path (#3035) already
closed for their generators.

---

## 2. Background — the two-ifindex model (firsthand)

### 2.1 `ingress_ident.ifindex` is PHYSICAL

`BindingIdentity.ifindex` is the fixed per-binding AF_XDP socket-bind
port, set once at bringup — NOT a per-packet logical unit index. This was
established firsthand by #6046 (see the issue body) and is consistent with
the deliberately-PHYSICAL #5856 per-zone rate-limit bucket that keys on
`ingress_ident.ifindex` (`userspace-dp/src/afxdp/icmp.rs:239-243`,
`tx/dispatch/mod.rs:287-291`).

### 2.2 `forwarding.egress` and `ingress_logical_ifindex` are LOGICAL-keyed

`userspace-dp/src/afxdp/forwarding_build/interfaces.rs`, `populate_egress`:

- `bind_ifindex = if iface.parent_ifindex > 0 { iface.parent_ifindex }
  else { iface.ifindex }` (`:273-277`) — for an **untagged** interface
  `bind_ifindex == iface.ifindex` (logical == physical); for a **VLAN
  sub-interface** `bind_ifindex` is the physical parent and `iface.ifindex`
  is the sub-if's own logical index (distinct).
- `state.ingress_logical_ifindex.insert((bind_ifindex, vlan_id),
  iface.ifindex)` (`:291-301`) — maps `(physical bind, vlan) → logical`.
  A sub-interface (`parent_ifindex > 0`) uses `insert` (authoritative);
  a parent (`parent_ifindex == 0`) uses `entry().or_insert` (keeps first).
- `state.egress.insert(iface.ifindex, EgressInterface { bind_ifindex,
  vlan_id, src_mac, primary_v4, primary_v6, redundancy_group, .. })`
  (`:326-338`) — **egress is keyed by the LOGICAL `iface.ifindex`**, and
  each entry carries the sub-if's own `src_mac`, `vlan_id`, primary
  addresses, and `redundancy_group`.

### 2.3 The resolver — the SSOT the fix reuses

`userspace-dp/src/afxdp/forwarding/mod.rs:882-891`:

```rust
pub(super) fn resolve_ingress_logical_ifindex(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<i32> {
    forwarding
        .ingress_logical_ifindex
        .get(&(ingress_ifindex, ingress_vlan_id))
        .copied()
}
```

`ingress_logical_ifindex: FastMap<(i32, u16), i32>`
(`userspace-dp/src/afxdp/types/forwarding.rs:207`).

`meta.ingress_vlan_id` is populated by the shim on every userspace-path
frame (`userspace-xdp/src/lib.rs:688`, `ingress_vlan_id: parsed.vlan_id`;
`0` when the frame is untagged, which correctly resolves the untagged
unit key `(physical, 0)`).

### 2.4 The shipped precedent — reject path (#3976) and cookie path (#3035)

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:272-278`:

```rust
let logical_ingress_ifindex =
    resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, meta.ingress_vlan_id)
        .unwrap_or(ingress_ifindex);
let bytes = if meta.protocol == PROTO_TCP {
    build_reject_rst_frame(packet_frame)
} else {
    build_reject_icmp_unreachable(packet_frame, meta, logical_ingress_ifindex, forwarding)
};
```

…and the same `logical_ingress_ifindex` feeds the classify at `:343`
(`classify_generated_reply(forwarding, logical_ingress_ifindex, &bytes,
now_ns)`), while the **physical** `ingress_ifindex` stays as the
`TxRequest.egress_ifindex` (XSK transmit device). The cookie path mirrors
this at `poll_descriptor/cookie_reply.rs:96-100,117`.

**Load-bearing corroboration:** the reject-path comment
(`reject_reply.rs:264-266`) asserts the TE builder
"*already passes `ingress_ident.ifindex` (the logical unit)*" — this is
the very misconception #6102 corrects. `ingress_ident.ifindex` is
physical; the TE builder was never converted.

---

## 3. Root cause — the 5 defect sites (firsthand)

### TE path — `userspace-dp/src/afxdp/icmp.rs`, `build_local_time_exceeded_request`

| # | Site | Current (physical) | Consequence |
|---|------|--------------------|-------------|
| T1 | `:189` | `let egress = forwarding.egress.get(&ingress_ident.ifindex)?;` | egress is logical-keyed → `None` on a VLAN sub-if with no untagged parent → `?` silently drops the TE. Also supplies `src_mac`/`tx_vlan_id`/`target_ifindex` — wrong unit when a parent entry exists. |
| T2 | `:197,200` | `build_local_time_exceeded_v4/v6(frame, meta, ingress_ident.ifindex, forwarding)` | builder internally does `forwarding.egress.get(&ingress_ifindex)?` (`icmp.rs:368`, v6 `:462`) → sources the ICMP from the wrong/absent unit's primary address + vlan. |
| T3 | `:268` | `classify_generated_reply(forwarding, ingress_ident.ifindex, &prebuilt_frame, now_ns)` | output filter / CoS keyed by logical unit → parent's (or first sub-if's) filter/CoS applied instead of this unit's. |

The `#3026` comment at `icmp.rs:258-266` **falsely** describes
`ingress_ident.ifindex` as "the LOGICAL egress ifindex … the unit ifindex
that keys `forwarding.egress`." It is physical.

### PTB path — `userspace-dp/src/afxdp/tx/dispatch/mod.rs`

| # | Site | Current (physical) | Consequence |
|---|------|--------------------|-------------|
| P1 | `:259-272` (`compute_forwarded_egress_ptb`) | `build_frag_needed_v4(source_frame, ptb_meta, ingress_ident.ifindex, ..)` / `build_packet_too_big_v6(.., ingress_ident.ifindex, ..)` | builder does the same logical-keyed egress lookup (`icmp_ptb.rs:381`, `:454`) → `None`/wrong-unit source address on a VLAN sub-if. |
| P2 | `:1311` (`enqueue_pending_forwards`) | `classify_generated_reply(forwarding, ingress_ident.ifindex, &ptb_bytes, now_ns)` | same output-filter / CoS granularity gap as T3. |

The `#2328` comment at `:1298-1309` describes classify on
`ingress_ident.ifindex` as "IS the egress" without the logical
resolution — same misconception.

---

## 4. Impact & severity

- **Silent drop (primary):** VLAN sub-interface with **no** untagged
  parent unit (the common case — e.g. `reth0.80` on `reth0`, which itself
  has no `unit 0` address): `forwarding.egress.get(physical)` → `None` →
  `?` → generated ICMP **never produced**. Traceroute across the DUT
  shows `* * *` for the hop; PMTUD blackholes (DF-set oversized frames are
  dropped as the original but the PTB signal never returns → path MTU
  never learned → TCP stalls on large segments). This is a real
  data-path outage for tagged uplinks.
- **Wrong-unit classification (secondary):** VLAN sub-interface **with**
  an untagged parent unit: reply sourced from the parent's primary
  address (wrong ICMP source), reflected untagged with the parent's
  `vlan_id` (0) instead of tagged, and classified with the parent's CoS
  forwarding-class / DSCP-rewrite / **output filter**. A per-unit
  `output firewall filter then discard` that should suppress the reply is
  bypassed — a fail-closed §6.2 output-filter-boundary violation (or the
  inverse: a parent filter wrongly drops a sub-if reply).
- **Scope:** only locally-**generated** ICMP errors on **tagged** ingress
  units. Untagged ports are unaffected (logical == physical → the fix is
  a literal no-op). Transit forwarding, RST reject, and SYN-cookie replies
  already resolve logical and are unaffected.

Severity: **high** for tagged-uplink deployments (traceroute/PMTUD are
operationally load-bearing), **medium** overall (untagged is the default).

---

## 5. Proposed design — mirror the reject-path pattern at 5 sites

Resolve the logical ingress unit **once per path** and feed it to the
egress lookup + builder + classify. Keep every transmit/XSK-device index
physical. Untagged ports: `resolve → None → unwrap_or(physical)` and
`logical == physical`, so the change is bit-identical there.

### 5.1 TE path (`icmp.rs`, `build_local_time_exceeded_request`)

Immediately before the feasibility lookup (currently `:189`), add:

```rust
// #6102: resolve the LOGICAL ingress unit ONCE. `forwarding.egress`,
// the reply builders, and `classify_generated_reply` are all keyed by the
// logical unit ifindex; `ingress_ident.ifindex` is the PHYSICAL bind port
// (#6046). Mirrors the reject (#3976) / cookie (#3035) precedent. The
// PHYSICAL `ingress_ident.ifindex` stays for the #5856 per-zone bucket and
// the XSK transmit (`target_ifindex`/`tx_ifindex`). Untagged: logical ==
// physical (no-op).
let logical_ingress = resolve_ingress_logical_ifindex(
    forwarding,
    ingress_ident.ifindex,
    meta.ingress_vlan_id,
)
.unwrap_or(ingress_ident.ifindex);
```

Then:
- **T1** `:189` → `let egress = forwarding.egress.get(&logical_ingress)?;`
  (feasibility on the correct unit; `egress.bind_ifindex` remains the
  physical parent, so `target_ifindex` at `:190-194` is still physical —
  the XSK transmit device is unchanged, and the `else` fallback stays
  `ingress_ident.ifindex`).
- **T2** `:197,200` → pass `logical_ingress` to
  `build_local_time_exceeded_v4/v6`.
- **T3** `:268` → `classify_generated_reply(forwarding, logical_ingress,
  &prebuilt_frame, now_ns)`.
- **UNCHANGED:** `:239-243` `ifindex_to_zone_id.get(&ingress_ident.ifindex)`
  (#5856 per-zone bucket — deliberately physical); `:279`/`:290`
  `target_ifindex`/`tx_ifindex` (physical XSK device); **`:289`
  `egress_ifindex: ingress_ident.ifindex`** (HA key — see §7).
- Rewrite the `#3026` comment block (`:258-266`) to describe the resolved
  logical unit, not "`ingress_ident.ifindex` … the LOGICAL egress ifindex."

### 5.2 PTB path (`tx/dispatch/mod.rs`)

The PTB **build** (`compute_forwarded_egress_ptb`) and **classify**
(`enqueue_pending_forwards`) are two different functions; resolve logical
independently at each (both have the ingress meta + `ingress_ident`).

- **P1** in `compute_forwarded_egress_ptb` (before `:258`): resolve
  `logical_ingress = resolve_ingress_logical_ifindex(forwarding,
  ingress_ident.ifindex, meta.ingress_vlan_id).unwrap_or(ingress_ident.ifindex)`
  and pass it to `build_frag_needed_v4` / `build_packet_too_big_v6`
  (`:262`,`:269`). **UNCHANGED:** `:287-291`
  `ifindex_to_zone_id.get(&ingress_ident.ifindex)` (#5856 bucket).
- **P2** in `enqueue_pending_forwards` (at `:1311`): resolve
  `logical_ingress = ...(request.meta.ingress_vlan_id)...` and pass it to
  `classify_generated_reply`. **UNCHANGED:** `:1333`
  `egress_ifindex: ingress_ident.ifindex` (physical XSK transmit device
  for the L2-reflected PTB).
- Rewrite the `#2328` comment (`:1298-1309`) accordingly.

### 5.3 Comment/doc SSOT correction (part of the same PR)

- `reject_reply.rs:264-266` — correct the "the Time Exceeded builder …
  already passes `ingress_ident.ifindex` (the logical unit)" claim.
- `userspace-dp/src/afxdp/README.md` (~`:680`, generation-sites list),
  `userspace-dp/src/afxdp/forwarding/README.md` (~`:388-400`, which lists
  #3026 among "every per-ingress map keyed by the logical unit resolves
  first" — currently inaccurate for the generated-ICMP build/classify),
  and `docs/generated-reply-rate-limit.md` (~`:61-75`, which asserts the
  reply build + output classify already key logical for TE/PTB) — update
  to reflect that TE/PTB now genuinely resolve logical for build+classify
  while the per-zone bucket stays physical.

**Net production diff:** two `let logical_ingress = …` bindings (one per
path) + three arg swaps on the TE path + two arg swaps on the PTB path +
comment corrections. No new functions, no signature changes, no control
flow changes.

---

## 6. Invariants to PRESERVE (call-outs — a wrong redirect regresses #5856/#5567)

1. **#5856 per-zone rate-limit bucket stays PHYSICAL.** Both
   `icmp.rs:239-243` and `tx/dispatch/mod.rs:287-291` resolve the zone via
   `ifindex_to_zone_id.get(&ingress_ident.ifindex)` on the **physical**
   bind ifindex — deliberately (VLAN sub-ifs on one port share that port's
   TE/PTB bucket; documented at `docs/generated-reply-rate-limit.md:61-75`).
   Do **NOT** redirect these to `logical_ingress`. Doing so would split one
   physical port's bucket per sub-if, changing the amplification-bound
   semantics #5856 chose (and diverging from the documented behavior).
2. **#5567 feasibility-before-consume ordering is unchanged.** The token is
   still consumed only after the build proves feasible. The fix only
   changes the ifindex *fed to* the build/egress-lookup; it does not move
   the token gate or the build. On a tagged sub-if the build now
   *succeeds* where it previously `None`-returned — which is the bug fix —
   but the ordering (build → feasibility → token) is intact.
3. **Transmit stays on the XSK PHYSICAL device.** TE `target_ifindex` /
   `tx_ifindex` (`egress.bind_ifindex`, physical) and PTB
   `egress_ifindex: ingress_ident.ifindex` (physical) are the XSK bind
   ports; they must not become logical (a logical index is not an XSK
   device and would break the enqueue/target-binding lookup).
4. **RFC-suppression gate (`can_generate_icmp_error_reply`, `ptb_reply_
   suppressed`) runs before any of this and is untouched.**

---

## 7. Security / HA-adjacency analysis

### 7.1 Fail-closed §6.2 output-filter boundary (the security-relevant half)

`classify_generated_reply` is the fail-closed output-filter/CoS boundary:
a terminal `discard`/`reject` output filter (or three-color policer) on
the reply's egress unit drops the reply, and a re-parse failure of our own
built bytes fails **closed** (drop + `generated_reply_classify_parse_
errors`). Today, on a VLAN sub-if, the classify runs on the physical
parent — so a per-unit output filter that *should* suppress the generated
ICMP is bypassed (leak), or a parent filter wrongly suppresses a sub-if
reply (over-drop). Feeding `logical_ingress` makes the boundary enforce
the **correct unit's** filter — strictly tightening the fail-closed
boundary. This mirrors exactly what #3035 did for the reject/cookie
generators.

### 7.2 HA egress key is NOT changed by this fix

The TE reply constructs a `ForwardingResolution` with
`egress_ifindex: ingress_ident.ifindex` (`icmp.rs:289`). `owner_rg_for_
resolution → owner_rg_for_flow(forwarding, resolution.egress_ifindex)`
(`forwarding/mod.rs:548,516-522`) resolves the HA redundancy group via
`egress.get(&egress_ifindex)`.

The fix **does not touch `:289`** — `resolution.egress_ifindex` stays
`ingress_ident.ifindex` (physical), so the value handed to
`owner_rg_for_flow` is byte-identical before and after. HA owner-RG
attribution for the generated TE reply is therefore **definitionally
unchanged**.

Two firsthand facts make this safe:

1. **The prebuilt TE/PTB reply is not HA-enforced on the dispatch path.**
   `enqueue_pending_forwards` handles the `PendingForwardFrame::Prebuilt`
   branch (`tx/dispatch/mod.rs:378`) and only special-cases
   `ForwardingDisposition::FabricRedirect` (`:386-387`); the TE reply is a
   `ForwardCandidate`, so it is enqueued for TX without an
   `enforce_ha_resolution` call. `resolution.egress_ifindex` is not read by
   owner-RG logic on this path.
2. **The PTB reply carries no `ForwardingResolution` at all** — it is
   emitted as a bare `TxRequest` (`:1327-1338`) with
   `egress_ifindex: ingress_ident.ifindex` (the XSK transmit device), so
   there is no HA owner-RG key to change.

**Out-of-scope observation (file a follow-up, do NOT fix here):** because
`owner_rg_for_flow` is logical-keyed and `:289` is physical, a *future*
code path that DID run `enforce_ha_resolution` on this resolution would
resolve `owner_rg = 0` for a tagged sub-if. Today that path does not exist,
and the pure-sub-if reply is dropped at the build stage anyway, so it is
latent, not live. Keeping `:289` physical preserves current behavior
exactly (the team's directive); converting it is a separate, HA-review-
gated change and must not ride this PR.

### 7.3 `meta.ingress_vlan_id` availability & correctness

- **TE:** `build_local_time_exceeded_request` takes `meta:
  UserspaceDpMeta` (`icmp.rs:164`); `meta.ingress_vlan_id` is in scope.
- **PTB build:** `compute_forwarded_egress_ptb` has `meta`/`ptb_meta`
  (`tx/dispatch/mod.rs`), `meta.ingress_vlan_id` in scope.
- **PTB classify:** `enqueue_pending_forwards` reads
  `request.meta.ingress_vlan_id` (already used at `:485`), same enclosing
  function as `:1311`.
- The shim sets `ingress_vlan_id = parsed.vlan_id` on every userspace-path
  frame (`userspace-xdp/src/lib.rs:688`); untagged → `0` → resolves the
  `(physical, 0)` untagged unit key → `unwrap_or(physical)` is only reached
  for a genuinely unmapped `(physical, vlan)` tuple (see §Hostile-review
  Q3), which fails closed exactly as today (physical-keyed drop).

---

## 8. Fail-on-revert test rebuild

### 8.1 Why the existing TE test is vacuous

`tests_icmp_te.rs:389`
(`build_local_time_exceeded_request_classifies_on_logical_egress_3026`)
sets `ingress_ident.ifindex = 12` (the **logical** unit) while
`meta.ingress_ifindex = 5` (`:400,418`). In production
`ingress_ident.ifindex` is **always** the physical bind port (#6046), so
this premise is unreachable: the test hands the code the logical value
directly, so the physical-keyed production code
(`egress.get(&ingress_ident.ifindex)` = `egress.get(12)`) accidentally
works and the test passes **regardless** of whether the caller resolves
logical. It proves nothing about caller-side resolution — it only
re-proves that `classify_generated_reply` honors its parameter (already
covered non-vacuously by `cos_classify_tests.rs:3423-3450+`, which is
fine — the defect is the CALLER, not `classify`).

### 8.2 Production-reachable replacement (TE)

Rewrite the test to the production shape:

- `ingress_ident.ifindex = 5` (**PHYSICAL** bind port).
- `meta.ingress_ifindex = 5`, `meta.ingress_vlan_id = 80`.
- `forwarding.ingress_logical_ifindex.insert((5, 80), 12)` (the map the
  daemon builds at `interfaces.rs:291-301`).
- `forwarding.egress.insert(12, EgressInterface { bind_ifindex: 5 (or 11),
  vlan_id: 80, primary_v4: Some(172.16.80.8), .. })` keyed on the LOGICAL
  unit 12, with the `then discard protocol icmp` output filter on unit 12
  (parent has none).
- Assert **both**: `request.is_none()` **and**
  `counters.time_exceeded_output_filter_drops == 1`.

**RED-on-revert coverage** (the double assertion catches every partial
revert):

| Revert | egress lookup | classify | Result |
|--------|--------------|----------|--------|
| Fix applied | `get(12)`=Some, build OK | `classify(12)` → filter fires | `None` + counter=1 ✅ |
| Revert classify only | `get(12)`=Some, build OK | `classify(5)` → no filter → admit | `Some` → `is_none()` FAILS RED |
| Revert egress-lookup only | `get(5)`=None → build `None` | (not reached) | `None` but counter=0 → counter assert FAILS RED |
| Full revert to physical | `get(5)`=None → build `None` | (not reached) | `None` but counter=0 → counter assert FAILS RED |

The counter assertion is essential: it distinguishes a *filter drop* (the
fix working) from a *build-fail drop* (a reverted egress lookup), so
`is_none()` alone cannot pass vacuously.

### 8.3 PTB analogue (new test)

Add a `ptb_classifies_on_logical_egress_6102` to
`tx/dispatch/tests/ptb.rs`, reusing `run_ptb_dispatch_with_forwarding`
(already parameterized on `ForwardingState`, `:86`):

- ingress binding physical (e.g. ifindex 11 as today), `req.meta.ingress_
  vlan_id = 80`.
- `forwarding.ingress_logical_ifindex.insert((11, 80), 12)`.
- `forwarding.egress.insert(12, .. output filter `then discard protocol
  icmp` on unit 12 ..)`; parent 11 unfiltered.
- Drive an oversized DF frame; assert the PTB is dropped by the unit-12
  filter with `counters.ptb_output_filter_drops == 1` (pre-fix: classify
  on physical 11 → no filter → PTB admitted → counter 0 → RED). Mirror the
  build-side coverage by also asserting the reply is sourced from the
  sub-if (or, minimally, that with no untagged parent the pre-fix path
  produced no PTB while the post-fix path does).

Both tests run in the standard `make test-rust` leg (`TMPDIR=/tmp` to
avoid the sun_path-108 socket-bind trap noted in project memory).

---

## 9. Validation plan

### 9.1 Unit (mandatory, gating)

`make test-rust` (needs cargo; `TMPDIR=/tmp`,
`CARGO_TARGET_DIR=/home/ps/.cache/xpf-cargo-6102r`). The two rebuilt
fail-on-revert tests are the primary gate; the full userspace-dp suite
must stay green (no HA/#5856/#5567 regression).

### 9.2 Loss-cluster smoke on a VLAN sub-interface (the decisive empirical proof)

`reth0.80` (VLAN 80 on `reth0`) on `loss:xpf-userspace-fw0/1` is a genuine
tagged sub-if — the exact topology that triggers the bug. Under the
cluster lock (`test/incus/with-cluster.sh`):

1. **Traceroute through the DUT** to the WAN target
   (`172.16.80.200` / `2001:559:8585:80::200`): before the fix the DUT hop
   shows `* * *` (TE dropped); after the fix the hop replies (Time
   Exceeded generated on the tagged unit). Run v4 **and** v6.
2. **PMTUD probe:** send a DF-set oversized frame (e.g. `ping -M do -s
   2000` v4 / oversized v6 toward a smaller-MTU next hop) whose forward
   egress MTU is exceeded; before the fix no Frag-Needed/PTB returns
   (blackhole); after the fix the PTB returns and path MTU is learned.
3. **CoS/output-filter granularity (optional but ideal):** apply a
   per-unit `output firewall filter then discard protocol icmp` on
   `reth0.80` and confirm the generated ICMP is suppressed on that unit
   while an untagged sibling still emits — proving classify keys the unit.

This VLAN-sub-if smoke is the **decisive** proof: the generated ICMP is
dropped before the fix and elicited after it. Untagged-path regression is
covered by the standard security-matrix / iperf3 smoke (logical ==
physical there, so behavior must be bit-identical).

### 9.3 Non-regression

`make test-failover` is **not** required (no cluster/VRRP/session-sync
code touched — the fix is confined to the generated-ICMP build/classify
inputs; the HA egress key is unchanged, §7.2). Standard sustained-iperf3
forwarding smoke (v4+v6, CoS on/off) confirms no fast-path regression.

---

## 10. Is this bounded enough to skip a design fork?

**Yes — single `/engineer` PR, no design fork.**

The design is fully determined by shipped precedent: the reject path
(#3976) and cookie path (#3035) already solved the identical problem with
`resolve_ingress_logical_ifindex(...).unwrap_or(physical)` feeding
build+classify while keeping the physical XSK transmit index. TE and PTB
are the two remaining generators that were never converted. The whole fix
is:

- 2 `let logical_ingress = …` resolutions (one per path),
- 3 TE arg swaps (egress lookup key, 2 builder args, classify arg) +
  2 PTB arg swaps (builder arg, classify arg),
- comment corrections + 3 doc touch-ups,
- 1 rebuilt TE test + 1 new PTB test (both fail-on-revert with the
  double `is_none()` + counter assertion).

There is no open design question: the invariants (§6) are explicit, the
HA key is untouched (§7.2), `meta.ingress_vlan_id` is proven available and
correct (§7.3), and the fail-on-revert tests are specified (§8). No
alternative implementation is competitive with "mirror the two sibling
paths." A design fork would only re-derive the reject-path pattern.

**One reviewer gate to honor:** the change touches the fail-closed §6.2
output-filter boundary, so the `/engineer` PR must carry the mandatory
independent hostile review even though the mechanical risk is low — the
security boundary (not the LOC count) sets the review bar.

---

## 11. Recommendation & rollout

- **Route:** one `/engineer` PR, `fix/6102-generated-icmp-logical-ifindex`.
- **Scope:** `icmp.rs` (TE, 3 sites + comment), `tx/dispatch/mod.rs` (PTB,
  2 sites + comment), `reject_reply.rs` comment correction,
  `tests_icmp_te.rs` (rebuild the vacuous test), `tx/dispatch/tests/ptb.rs`
  (new analogue), and the 3 docs in §5.3.
- **Merge gate:** `make test-rust` green + the two fail-on-revert tests +
  loss-cluster VLAN-sub-if traceroute/PMTUD smoke (v4+v6) + the mandatory
  independent hostile review of the §6.2 boundary change. No auto-merge.
- **Parent RED-on-revert:** the double-assertion tests (§8.2 table) are the
  parent-red proof; a revert must fail an **assertion** (admit + counter),
  not a build break.
- **Risk if wrong:** redirecting the #5856 bucket to logical would regress
  the documented per-zone amplification bound; §6 forbids it explicitly and
  the reviewer must confirm `ifindex_to_zone_id` stays physical.

---

### Appendix A — firsthand citations (origin/master @ 1e43937f5)

| Fact | File:line |
|------|-----------|
| `resolve_ingress_logical_ifindex` def | `userspace-dp/src/afxdp/forwarding/mod.rs:882-891` |
| `ingress_logical_ifindex: FastMap<(i32,u16),i32>` | `userspace-dp/src/afxdp/types/forwarding.rs:207` |
| egress logical-keyed insert | `forwarding_build/interfaces.rs:326-338` |
| `(bind,vlan)→logical` insert | `forwarding_build/interfaces.rs:291-301` |
| `bind_ifindex` = parent or self | `forwarding_build/interfaces.rs:273-277` |
| shim sets `ingress_vlan_id` | `userspace-xdp/src/lib.rs:688` |
| TE T1 egress lookup (physical) | `icmp.rs:189` |
| TE T2 builder args (physical) | `icmp.rs:197,200` |
| TE builder inner egress lookup | `icmp.rs:368` (v6 `:462`) |
| TE #5856 bucket (KEEP physical) | `icmp.rs:239-243` |
| TE T3 classify (physical) | `icmp.rs:268` |
| TE resolution egress_ifindex (KEEP) | `icmp.rs:289` |
| TE target/tx ifindex (physical) | `icmp.rs:279,290` |
| PTB P1 builder args (physical) | `tx/dispatch/mod.rs:259-272` |
| PTB #5856 bucket (KEEP physical) | `tx/dispatch/mod.rs:287-291` |
| PTB P2 classify (physical) | `tx/dispatch/mod.rs:1311` |
| PTB TxRequest egress_ifindex (physical XSK) | `tx/dispatch/mod.rs:1333` |
| Prebuilt dispatch only checks FabricRedirect | `tx/dispatch/mod.rs:378,386-387` |
| `owner_rg_for_flow` logical-keyed | `forwarding/mod.rs:516-522,548` |
| reject-path precedent (resolve once) | `poll_descriptor/reject_reply.rs:272-278,343` |
| reject-path false claim about TE builder | `poll_descriptor/reject_reply.rs:264-266` |
| cookie-path precedent | `poll_descriptor/cookie_reply.rs:96-100,117` |
| vacuous TE test | `tests_icmp_te.rs:389-494` |
| classify-level test (non-vacuous, keep) | `tx/cos_classify_tests.rs:3423+` |
| PTB test harness (parameterized) | `tx/dispatch/tests/ptb.rs:86` |
