# Hostile Claude self-review (SMR) — plan r1 for #6102

Reviewer stance: adversarial. Goal is to break the plan, not confirm it.
Every claim below is checked against `origin/master @ 1e43937f5`.

**Verdict: PLAN-READY.** The design is a faithful mirror of shipped
precedent (#3976/#3035); the 5 defect sites, the invariants, and the
fail-on-revert test rebuild are all correctly identified and firsthand-
cited. Three residual verification items (Q3/Q6/Q7 below) are flagged for
the `/engineer` pass — none block the plan, all are "confirm during
implementation," not "redesign."

---

## Q1. Does redirecting the egress-lookup (`icmp.rs:189`) to logical break the `None`-fallback for genuinely-unmapped ports?

**No.** Traced both directions:

- **Untagged port / untagged frame** (`vlan_id == 0`): `populate_egress`
  inserts `(bind_ifindex=iface.ifindex, 0) → iface.ifindex` for every
  interface (`interfaces.rs:291-301`), so `resolve(physical, 0)` returns
  `physical` and `egress.get(physical)` is the same entry as today. Bit-
  identical.
- **Genuinely-unmapped `(physical, vlan)`** (a tagged frame on a VLAN the
  config does not define): `resolve` returns `None` →
  `unwrap_or(ingress_ident.ifindex)` → `egress.get(physical)`. For a port
  with no untagged unit this is `None` → `?` → drop — **exactly today's
  behavior** (today also does `egress.get(physical) → None → drop`). The
  fix cannot turn a today-drop into a today-forward for an unmapped tuple,
  because the fallback re-uses today's key. So no fail-open is introduced.
- **The bug case** (mapped tagged sub-if, no untagged parent):
  `resolve(physical, 80) → 12`, `egress.get(12) → Some` → the reply is now
  *produced* where it was dropped. That is the intended fix, not a
  regression.

`target_ifindex` safety: after the lookup moves to logical,
`egress.bind_ifindex` is still the physical parent (`interfaces.rs:329`),
and `iface.ifindex > 0` is enforced at `interfaces.rs:270`, so
`bind_ifindex > 0` always holds → `target_ifindex` stays physical. The
`else { ingress_ident.ifindex }` fallback remains physical and safe. **No
finding.**

## Q2. Does keeping the #5856 bucket physical while moving classify to logical create an inconsistency?

**No inconsistency — but the asymmetry must be stated, and the plan does
(§6.1).** The two are orthogonal:

- The #5856 bucket bounds *amplification rate* and is deliberately keyed
  per **physical port** zone (`docs/generated-reply-rate-limit.md:61-75`),
  so sub-ifs on one port share it. This is coarser than the reject path's
  per-logical-unit bucket **by design** and is **pre-existing** — the fix
  does not touch it.
- The classify enforces per-**unit** output policy (filter/CoS/DSCP).
  Making it logical is strictly correct.

The only "asymmetry" is that TE/PTB will have a per-port bucket but a
per-unit classify, whereas reject has both per-unit. That asymmetry
already exists today (bucket is already physical); the fix does not widen
it. A hostile reader might argue "make the bucket logical too for
symmetry" — but that would **regress** #5856's documented amplification
bound (a low-TTL flood ingressing one sub-if could no longer be capped at
the port granularity the design chose) and diverge from
`generated-reply-rate-limit.md`. The plan correctly forbids it (§6.1).
**No finding** — but the reviewer of the eventual PR must confirm
`ifindex_to_zone_id.get(&ingress_ident.ifindex)` stays physical at all
four sites (`icmp.rs:239-243`, `tx/dispatch/mod.rs:287-291`).

## Q3. Is `meta.ingress_vlan_id` ALWAYS populated on the TE/PTB paths, or can it be 0/absent in a way that misroutes?

**Populated, but two edge inputs deserve an implementation-time check:**

- **Baseline:** the shim sets `ingress_vlan_id = parsed.vlan_id` on every
  userspace-path frame (`userspace-xdp/src/lib.rs:688`); untagged → 0 →
  resolves the `(physical, 0)` untagged unit. `ForwardPacketMeta` carries
  the field (`types/mod.rs:145`) and `From` preserves it both directions
  (`:203,:231`), so the PTB build (`request.meta.into()`) and PTB classify
  (`request.meta.ingress_vlan_id`, already read at `tx/dispatch/mod.rs:485`)
  resolve from the **same** ingress frame — no build/classify divergence.
- **⚠️ GRE-decap ingress:** `gre.rs:762` constructs a meta with
  `ingress_vlan_id: 0`. If a TE/PTB is generated for a GRE-decapsulated
  inner packet, `resolve(physical, 0)` keys the underlay's `(physical, 0)`
  unit. This is **no worse than today** (today keys `physical` directly),
  and `unwrap_or(physical)` preserves the current key if `(physical, 0)`
  is unmapped. **Verify** the engineer confirms GRE-decap TE still sources
  from a sane unit (likely fine — the reflection target is the underlay
  ingress, whose vlan is 0). Not a blocker: worst case is bit-identical to
  today.
- **⚠️ NAT64 / native-tunnel PTB:** `compute_forwarded_egress_ptb` runs
  for `is_nat64` / `uses_native_tunnel` frames. `request.meta.ingress_
  vlan_id` there is the **outer** ingress frame's vlan, and the PTB is
  L2-reflected back out the ingress — so the outer vlan is the correct
  reflection key. **Verify** during implementation that no inner/rewritten
  meta shadows `request.meta` before the classify. Again `unwrap_or`
  fails safe.

**Finding (LOW, non-blocking):** add a one-line assertion/comment in the
PR that tunnel/GRE/NAT64 TE-PTB inputs resolve via `unwrap_or(physical)` =
today's key, so these paths are provably ≥ current behavior. The two
fail-on-revert tests need not cover them (they are ≥-today by
construction), but a sentence in the PR body should note the reviewer
checked them.

## Q4. Does the fix change the HA egress key / owner-RG attribution?

**No — verified definitionally.** The fix does not modify `icmp.rs:289`
(`egress_ifindex: ingress_ident.ifindex`), so `owner_rg_for_flow(
resolution.egress_ifindex)` (`forwarding/mod.rs:548,516-522`) receives a
byte-identical input. Additionally:

- The prebuilt TE reply is enqueued by `enqueue_pending_forwards`, whose
  `Prebuilt` branch only special-cases `FabricRedirect`
  (`tx/dispatch/mod.rs:378,386-387`); a `ForwardCandidate` TE reply is not
  run through `enforce_ha_resolution`, so `egress_ifindex` is not consulted
  for owner-RG here.
- The PTB reply is a bare `TxRequest` with no `ForwardingResolution`
  (`:1327-1338`) — there is no HA key at all.

The plan's §7.2 out-of-scope note (that `:289` being physical is a
**latent** logical/physical mismatch for a hypothetical future HA-enforced
path, moot today because pure-sub-if replies drop at build) is correct and
correctly deferred. **No finding** — but I pushed on whether the plan
should *also* fix `:289` to logical: **no.** (a) It is not reached by
owner-RG today; (b) changing it risks `owner_rg = 0 → HAInactive → drop`
if any future path *does* enforce it, which is a HA-review-gated decision;
(c) the team directive is explicit: don't change the HA egress key. Keeping
it physical is the conservative, behavior-preserving choice.

## Q5. Is the existing test genuinely vacuous, and does the replacement actually fail RED on revert?

**Yes and yes.** `tests_icmp_te.rs:389` sets `ingress_ident.ifindex = 12`
(logical) with `meta.ingress_ifindex = 5` (physical) and an empty
`ingress_logical_ifindex` map — a production-unreachable premise (#6046:
`ingress_ident.ifindex` is always physical). The code under test uses
`ingress_ident.ifindex` directly, so handing it the logical value makes
the physical-keyed production code accidentally correct → passes
regardless of caller resolution. Confirmed vacuous.

The replacement (§8.2) with `ingress_ident.ifindex = 5` (physical),
`meta.ingress_vlan_id = 80`, `ingress_logical_ifindex[(5,80)] = 12`, filter
on logical 12, and the **double assertion** (`request.is_none()` **AND**
`time_exceeded_output_filter_drops == 1`) is robust. I re-derived the
revert matrix independently:

- Revert classify → build OK on 12, classify on 5 admits → `Some` →
  `is_none()` RED. ✅
- Revert egress-lookup → `get(5)=None` → build `None` → `is_none()` passes
  but counter=0 → counter assert RED. ✅
- Full revert → same as above, counter=0 RED. ✅

The counter assertion is load-bearing: without it, a reverted egress
lookup would pass `is_none()` vacuously (drop for the wrong reason). The
plan calls this out explicitly. **No finding.**

One nit: the replacement must set `meta.ingress_ifindex = 5` **and**
`ingress_ident.ifindex = 5` (both physical) so the resolve input is the
physical port; the plan says this. Also ensure `egress` is **not** keyed
under 5 (only under 12) so the pre-fix `get(5)` genuinely misses. The plan
implies this ("NO egress[5]") — make it explicit in the test.

## Q6. PTB build and classify resolve independently — can they pick different units?

**No, but confirm the meta identity in the PR.** Both read
`request.meta.ingress_vlan_id`: the build via
`compute_forwarded_egress_ptb(source_frame, request.meta, ...)`
(`tx/dispatch/mod.rs:719`) and the classify via
`request.meta.ingress_vlan_id` at `:1311`'s enclosing function
(`enqueue_pending_forwards`, same `request`). Same struct, same field →
same resolution. **Finding (LOW):** the engineer should resolve
`logical_ingress` from `request.meta.ingress_vlan_id` at **both** PTB sites
(not from any locally-narrowed `ptb_meta` copy that might diverge) to keep
the SSOT identical. Bit-identical today, but worth a one-liner.

## Q7. Does moving `icmp.rs:189` to logical change `src_mac` / `tx_vlan_id` in a surprising way?

**Yes — and that is the point, but flag the `tx_vlan_id` interaction.**
After the lookup is logical, `egress.src_mac`/`egress.vlan_id`
(`icmp.rs:294-295`) become the **sub-if's** values. For the reflected TE
there is a second vlan source: `ingress_reply_l2` (`icmp.rs:321-341`)
parses the inbound frame's full 802.1Q/802.1ad tag for the reflection.
**Verify** during implementation which one wins in the TX path (the
resolution's `tx_vlan_id` vs the reflected inbound tag) so the fix does
not double-tag or mis-tag. Most likely the reflected inbound tag is
authoritative for the L2 and `egress.vlan_id` feeds a different concern —
but this is the one place the TE path is *not* a literal mirror of the
reject path (reject builds a fresh frame; TE reflects), so it warrants an
explicit check + a smoke assertion that the generated TE on `reth0.80`
egresses **tagged with VID 80**. **Finding (MEDIUM for the PR, not for the
plan):** the §9.2 smoke must capture the generated ICMP on the wire and
confirm the VLAN tag, not just that "a reply came back."

## Q8. Scope / regression surface

The production diff is 2 resolutions + 5 arg swaps + comments. It touches
no control flow, no signatures, no HA/cluster code, no rate-limit ordering.
`make test-failover` is correctly deemed non-required (§9.3). The only
security-relevant surface is the fail-closed §6.2 output-filter boundary,
which the fix **tightens** (correct-unit enforcement). The plan's mandate
for an independent hostile review despite low mechanical risk (§10) is the
right call — the boundary, not the LOC, sets the bar. **No finding.**

---

## Consolidated findings for the `/engineer` pass

| # | Sev | Item |
|---|-----|------|
| F1 (Q7) | MED (PR) | Smoke must **capture the generated ICMP on the wire and assert VLAN VID 80** on `reth0.80` — confirm no double-/mis-tag from the `ingress_reply_l2` reflected tag vs `egress.vlan_id` interaction. This is the one non-literal-mirror spot. |
| F2 (Q3) | LOW | Note in the PR body that GRE-decap / NAT64 / native-tunnel TE-PTB inputs resolve via `unwrap_or(physical)` = today's key (≥ current behavior); reviewer confirms. |
| F3 (Q6) | LOW | Resolve `logical_ingress` from `request.meta.ingress_vlan_id` at both PTB sites (single SSOT), not a narrowed copy. |
| F4 (Q5) | LOW | In the rebuilt TE test, make it explicit that `egress` is keyed **only** under logical 12 (no `egress[5]`) so the pre-fix `get(5)` genuinely misses. |
| F5 (Q2) | INFO | Reviewer confirms `ifindex_to_zone_id` stays physical at all 4 #5856 sites. |

None of F1–F5 change the design or block PLAN-READY. F1 is a smoke-
assertion sharpening; F2–F5 are implementation-time confirmations. The
core recommendation stands: **single `/engineer` PR mirroring the reject/
cookie precedent.**

---

## Companion reviews (Codex / AGY)

Attempted per the research contract. Status recorded in
`companion-review-status.md` in this directory. If both are infra-blocked,
this SMR stands as a 1-of-3 hostile pass with the block documented — the
finding set above is the converged verdict.
