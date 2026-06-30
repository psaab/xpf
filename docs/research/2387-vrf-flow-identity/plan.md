# #2387 — VRF/routing-instance awareness in session/flow identity

**Status:** DRAFT v3 — incorporates all three r1 reviews (Claude SMR + AGY +
Codex; all three independently returned NEEDS-MAJOR-REVISION on the PBR
reachability escalation, and all three confirmed §4c/§4d/§7 accurate). Codex was
NOT infra-blocked this round — full 3-of-3.

**v3 changelog (from r1 reviews):**
- All three reviewers refuted the v1 "unreachable in a forwarding-correct config"
  claim — the collision IS reachable via PBR `then routing-instance` (per-VRF
  forwarding works without per-VRF default FIB). §3/§4b rewritten "latent in
  default mode, LIVE via PBR."
- **AGY Attack 4:** A.1 hard-reject breaks a *legitimate* overlapping-subnet PBR
  VRF design → softened to a commit **warning** by default (hard reject only if
  the product decision is "no overlapping subnets at all").
- **AGY Attack 5:** the v1/v2 "key widening must be last, after per-VRF FIB"
  ordering was wrong → split into **Track B-min** (P0+P2+P3, the minimal real fix
  using PBR as the forwarding mechanism) and **Track B-ext** (per-VRF default FIB
  — a separate enhancement, NOT a prerequisite).
- **Codex citation fixes:** corrected `CurrentHAProtocolVersion` location and
  added a path-shorthand note (`src/afxdp/` subtree).
- A.2 demoted (does not mitigate the conntrack-level breach); B-P0 tightened to a
  dense-interned u32 reusing the dead `routing_table` slot; leaked-flow corner
  resolved (domain-0 scope for B-min, dual-domain for B-ext).

**Branch:** `research/2387-vrf-flow-identity` (docs only — no production source).

**Verified against:** origin/master @ `13e3b269e` (campaign-8's prior comment was
written against `0160fbfb9`; this revision re-verifies every claim against current
master and corrects two of them — see §4).

---

## 1. Status

**CONVERGED v4 — PLAN-DEFER (research-converged), 3-of-3.** This is a `/research`
pass: it stops at PLAN-READY / PLAN-KILL / PLAN-DEFER and produces a converged
plan-of-action, no code PR. Convergence: Claude SMR r2 = PLAN-DEFER, AGY r2 =
PLAN-DEFER, Codex r2 = PLAN-DEFER after two §4c/§A.1 wording fixes (landed in v4;
`codex-plan-r2.md`). Codex was not infra-blocked in either round.

The headline recommendation is **PLAN-DEFER**: the bug is real and reachable
(LIVE under PBR `then routing-instance`, latent in default forwarding mode), but
the real fix (Track B-min) carries an HA wire change and a product-support
question. Ship the interim A.1 commit warning + A.3 docs now; schedule Track B-min
(domain id + key widening + HA wire bump) once the maintainer confirms
overlapping-subnet PBR VRF is supported. Track B-ext (per-VRF default FIB) is a
separate, independently deferrable enhancement. Awaiting manual `/engineer`
approval — no code until then.

## 2. Issue framing

#2387 says: the userspace-dp session/flow identity is the bare 5-tuple
(src ip, dst ip, src port, dst port, protocol) with no VRF / routing-instance
(or zone) discriminator, so two flows that live in different VRFs but share the
same 5-tuple collide in the conntrack map — causing wrong-flow forwarding, NAT,
or policy. The literal ask is "add VRF/routing-instance id (and/or zone) to the
SessionKey."

## 3. Honest scope / value framing

The bug **mechanism is real and confirmed** (§4). Its reachability is
**mode-dependent** (corrected in v2 after SMR r1):

- **Default forwarding mode (no PBR): latent.** For two flows to legitimately
  carry the *same* 5-tuple in two VRFs you need overlapping L3 address space, and
  the userspace forwarding layer is **not VRF-isolated** by default — the
  destination FIB lookup for a normal transit packet defaults to the global
  `inet.0`/`inet6.0` table, and local-delivery uses a single global address set.
  So an overlapping-subnet multi-VRF topology does not route correctly *in this
  mode* irrespective of the session key.
- **PBR mode (`then routing-instance` on the ingress interfaces): LIVE.** PBR is
  the dataplane's per-packet table override; with a PBR filter steering each
  ingress interface to its own per-VRF table, overlapping-address multi-VRF
  **does forward correctly** — and then the bare-5-tuple session key collides: a
  second flow with the same 5-tuple hits the first flow's conntrack session and
  inherits its egress / NAT / policy decision (wrong-VRF forwarding). See §4b for
  the verified ordering proof. This is a real, reachable (if niche)
  correctness/isolation breach — exactly #2387's multi-tenant scenario.

The session-key collision is the tip of a larger "VRF-aware forwarding +
conntrack isolation" feature. In default mode it is latent; in PBR mode it is a
live wrong-forwarding bug on the *second* colliding flow. Either way, the literal
"widen the key now" ask is the last and most expensive phase of that feature, not
a standalone fix.

The literal fix the issue asks for (widen the SessionKey) is, by itself:
- **the most expensive and riskiest phase** of that larger feature (hard HA wire
  break + version bump + C/Go/Rust/fixture lockstep + conntrack reverse-match
  correctness — §4, §5, §7), and
- **delivers zero realized isolation** until the forwarding layer is also made
  VRF-aware (a separate, larger body of work).

*If reviewers conclude the churn of the full feature is too large for what is a
niche (overlapping-address + PBR + simultaneous identical-5-tuple) config,
PLAN-KILL of the literal "widen the key now" ask is acceptable — but the
fail-closed guard (Track A.1) should ship regardless, because the bug is now
known to be reachable, not purely theoretical.* The recommended terminal state is
PLAN-DEFER: ship the cheap fail-closed guard + doc now; schedule the full feature
only if multi-tenant overlapping-subnet VRF isolation is a declared product goal.

## 4. Confirmed mechanism + what's already shipped (current master `13e3b269e`)

> **Path shorthand:** Rust dataplane citations below are relative to
> `userspace-dp/src/` and live under the `afxdp/` subtree unless the path already
> names another (e.g. `session/key.rs`, `nat/`). Full forms: `forwarding/mod.rs`
> = `userspace-dp/src/afxdp/forwarding/mod.rs`; `types/forwarding.rs` =
> `userspace-dp/src/afxdp/types/forwarding.rs`; `session_glue/mod.rs` =
> `userspace-dp/src/afxdp/session_glue/mod.rs`; `shared_ops.rs` =
> `userspace-dp/src/afxdp/shared_ops.rs`. (Codex r1 flagged the bare `src/types/`
> / `src/session/session_glue/` forms as non-existent — they are under
> `src/afxdp/`.)

### 4a. The key is the bare 5-tuple — confirmed

- `SessionKey` = `{ addr_family:u8, protocol:u8, src_ip:IpAddr, dst_ip:IpAddr,
  src_port:u16, dst_port:u16 }` — `userspace-dp/src/session/key.rs:9-17`. No
  zone / VRF / ifindex.
- Built at session-create from the L4 tuple + AF **only** —
  `parse_session_flow_from_meta` (`userspace-dp/src/afxdp/frame/inspect.rs:1513-1544`)
  and the frame/byte parsers (`inspect.rs:1220`, `:1451`, `:1546`). None read
  `meta.ingress_zone`, `meta.routing_table`, `meta.ingress_vlan_id`, or
  `meta.ingress_ifindex`.
- Every session map is keyed by `SessionKey` alone: the shared synced / NAT /
  forward-wire maps (`afxdp/coordinator/session_manager.rs:13-15`), the
  worker-local conntrack indexes `key_to_handle` / `nat_reverse_index` /
  `forward_wire_index` / `reverse_translated_index`
  (`session/mod.rs:453-457`), and the tunnel rate map (`afxdp/tunnel.rs:270`).
- Lookup uses `flow.forward_key` only — `lookup_session_across_scopes`
  (`afxdp/shared_ops.rs:563-599`) receives `ingress_ifindex` as a parameter but
  **does not** put it in the key; `SessionTable::lookup_with_origin`
  (`session/lookup.rs:28-43`) probes `key_to_handle.get(key)` then
  `reverse_translated_index`.
- The session entry stores `ingress_zone:u16` / `egress_zone:u16`
  (`session/entry.rs:25-26`) but these are read only for the per-zone half-open
  TCP override (`session/lookup.rs:51-55`), never for key matching. There is **no
  routing-table / VRF field** on `SessionMetadata` or `SessionEntry`.

**Conclusion:** two flows with identical 5-tuples on any two interfaces share one
conntrack entry. The flow cache (`FlowCacheEntry`) adds a partial discriminator —
its key is `(SessionKey, ingress_ifindex)` where `ingress_ifindex` is the **raw
physical** parent (`flow_cache.rs:149` lookup, `:424` insert), so two flows on
*different physical ports* don't collide there, but two VLAN sub-units on the
*same* physical parent still do. The conntrack table (no ifindex at all) is the
primary collision surface.

### 4b. The forwarding layer is NOT VRF-isolated — confirmed (this is why it's latent)

- Default FIB table is global: `DEFAULT_V4_TABLE="inet.0"` / `inet6.0`
  (`afxdp/forwarding/mod.rs:12-13`); a transit packet with no PBR override
  resolves there (`:1131-1133`, `:1174-1176`), and the established-session path
  passes `table=None` (`session_glue/mod.rs:148-153`).
- Local-delivery sets are global, single sets: `local_v4` / `local_v6`
  (`types/forwarding.rs:15-16`), tested at `forwarding/mod.rs:1134` / `:1177`,
  populated from every interface address into the one set
  (`forwarding_build/interfaces.rs:153`/`:169`).
- The **only** per-packet table override is PBR `then routing-instance`
  (`ingress_route_table_override`, `forwarding/mod.rs:1211`; sole production
  caller `poll_descriptor/mod.rs:1208-1216`). There is **no** automatic
  `ifindex → default-table` binding — an interface's native `routing_instance` is
  used only for connected-route table naming
  (`connected_route_tables`, `forwarding_build/interfaces.rs:126-127`/`:274-283`)
  and next-table recursion.

So in **default mode** two routing-instances both owning `10.0.0.10` already
collide at the global FIB and global `local_v4` layers; the overlapping config
never forwards correctly there, with or without a wider session key.

**But PBR makes per-VRF forwarding work — and that is where the collision goes
live (verified ordering proof):**

- Input `then routing-instance` is a valid, tested config
  (`pkg/config/firewall_ri_output_direction_3432_test.go:59-69`,
  `pkg/config/firewall_ri_conflict_3308_test.go:81-97`). With it,
  `ingress_route_table_override` returns the per-VRF table
  (`forwarding/mod.rs:1211`, builds `<ri>.inet.0`/`inet6.0` at `:1283-1288`), and
  the **session-miss** resolution honors it (`poll_descriptor/mod.rs:1208-1216`
  builds the override; `:1244-1248` passes it to
  `lookup_forwarding_resolution_in_table_with_dynamic`). Table-scoped
  forwarding+local-delivery under a supplied table is proven in
  `forwarding/tests.rs:2455-2546`. So overlapping-address multi-VRF *does* forward
  correctly under PBR.
- **The established-session fast path runs FIRST and ignores PBR:**
  `resolve_flow_session_decision` is called at `poll_descriptor/mod.rs:474` and
  short-circuits before the PBR override at `:1208` (comment at `:503`: it "never
  runs policy"). It looks up the conntrack session by the bare 5-tuple
  (`flow.forward_key`, `shared_ops.rs:563-599`).
- Therefore: flow 1 (VRF-A) creates a session caching egress-A; flow 2 (VRF-B),
  *same 5-tuple*, hits flow 1's session at line 474 and is handed flow 1's cached
  decision — its own PBR/route/policy is never evaluated → wrong-VRF forward +
  wrong NAT + wrong policy. The flow-cache `(SessionKey, physical_ifindex)`
  discriminator does not save it: flow 2 misses the flow cache (or collides if on
  the same parent VLAN) but still hits the ifindex-less conntrack table. **The
  conntrack table is the authoritative collision surface.**

### 4c. NEW since campaign-8 (#3096) — partial VRF awareness landed, but only in NAT *selection*

`#3096` (`ab9c6580e`, merged after `0160fbfb9`) added:
- `ifindex_to_routing_instance: FastMap<i32, String>` —
  `types/forwarding.rs:69`, built from `iface.routing_instance` at
  `forwarding_build/interfaces.rs:56-57`. **This is the P0 building block
  campaign-8 said "doesn't exist yet."** It now exists (as a name → not yet a
  compact id).
- `NatScopeCtx` (`nat/mod.rs:42`) resolved per-flow via `nat_scope_ctx_for_flow`
  (`forwarding/mod.rs:120-145`) from the ingress/egress ifindex, so NAT
  rule-*selection* is now routing-instance-scoped at **session create**.

**The coherence gap this introduces (new finding):** the NAT scope is checked
only when a session is *created* (`match_source_nat` path). On the established
fast path, `resolve_flow_session_decision` (`session_glue/mod.rs:1004-1044`)
returns the cached hit's decision via `lookup_session_across_scopes` using
`flow.forward_key` **without re-running the scope gate**. Because the session
cache is keyed by the bare 5-tuple, a second flow that collides on the 5-tuple
would inherit the first flow's NAT/policy/forwarding decision, *defeating
#3096's scoping for that flow*. The codebase is now partway into VRF-awareness
(NAT selection) while session identity is still VRF-blind — an internal
inconsistency. The gap is **latent in default mode** (§4b: the trigger does not
forward there) but **live under PBR** — NAT runs inside the same PBR-triggered
session-miss path (`forwarding/mod.rs:211-212` resolves the NAT scope, then
`session_glue/mod.rs:1037-1042` looks up `&flow.forward_key`), so flow 2's
established hit reuses flow 1's cached NAT decision without re-checking scope,
exactly as in §4b. A future per-VRF-FIB phase (B-ext) that makes default mode
forward would extend the live window to non-PBR configs too.

### 4d. CORRECTION to campaign-8's HA-wire claim (new finding)

Campaign-8 said a VRF-id "appended to the key payload is wire-compatible if
length-gated." **That is wrong.** On the cross-chassis byte wire
(`pkg/cluster/sync_protocol.go`), only the *value's trailing* fields are
length-gated/additive (decoder bails early-but-ok at each boundary,
`decodeSessionV4Payload:318/332/343/368`). The **key portion is fixed-layout
little-endian and NOT length-gated**, and the key is serialized *twice* (the
primary key, plus the embedded `reverse_key` inside the value at
`sync_protocol.go:136-145`). Widening `SessionKey` shifts the reverse-key block
and every value field after it, so it is a **hard wire break** requiring a
bump of `CurrentHAProtocolVersion` (`pkg/cluster/heartbeat.go:27-31`; the
`SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)` alias is at
`pkg/cluster/sync.go:36`) and the #1930 mixed-base ISSU gate — the upgrade path
already treats a mismatched HA protocol version as non-rolling-compatible
(`pkg/upgrade/cluster_cli.go:246-248`), so a key-wire bump forces a both-nodes
upgrade. Strictly more expensive than the "additive" estimate.

### 4e. `routing_table` meta field is dead (new finding)

`UserspaceDpMeta.routing_table:u32` (offset 24; `types/mod.rs:111`,
`userspace-xdp/src/lib.rs:132`) is hard-coded `0` at the shim ingress build
(`lib.rs:682`) and in the dp default init (`types/mod.rs:195`). The only code
that ever set it non-zero was C in the legacy BPF zone/filter programs deleted in
#1476. So it **cannot be repurposed as-is**; a routing-domain id must be computed
and plumbed fresh.

## 5. Concrete design

Two tracks. The decision between them is a **product-scope call** (see §11 Q1).

### Track A — proportionate hardening now (recommended default; cheap, fail-closed)

- **A.1 — commit-time WARNING (not a hard reject)** (`pkg/config` compiler).
  When a config assigns overlapping L3 address space (interface addresses or
  static routes) to two different routing-instances reachable via PBR `then
  routing-instance`, emit a **commit warning** naming both interfaces/instances:
  "overlapping L3 across routing-instances is forwarded via PBR but is NOT
  session-isolated (#2387) — colliding 5-tuples may cross-forward until the
  session identity is VRF-aware." **A warning, not a reject** — AGY r1 Attack 4
  correctly notes that overlapping-subnet PBR VRF is a *legitimate, working*
  multi-tenant design, so hard-rejecting it breaks a valid deployment to work
  around a fast-path bug. A hard reject is only appropriate if the maintainer's
  product decision is "we do not support overlapping subnets" at all (§11 Q1) —
  default to the warning. No wire/HA impact; pure config-layer. Pattern to
  mirror: the existing config-validation warnings (not the NPTv6 *reject* gate).
  This is the **interim safety net**; the real fix for the live breach is Track
  B-min.
- **A.2 — (de-prioritized) flow-cache logical-ifindex key.** Change
  `FlowCacheEntry` to key on the **logical** ingress ifindex (resolve
  `(parent, vlan) → logical` via `resolve_ingress_logical_ifindex`, already
  called at `flow_cache.rs:373` for the DSCP/L4 coherency check) instead of the
  raw physical `meta.ingress_ifindex` (`flow_cache.rs:149`, `:424`). **This does
  NOT mitigate #2387's core breach** — the conntrack table (no ifindex) is the
  authoritative collision surface (§4b), and the flow cache already carries the
  physical ifindex yet still doesn't prevent the cross-VRF hit. A.2 is a tidy-up
  that aligns the flow cache with the logical-ifindex SSOT used elsewhere
  (#2370/#3021) and stops same-parent-VLAN flow-cache reuse; rank it below A.1
  and A.3. No wire/HA change.
- **A.3 — documentation.** Record the single-forwarding-domain limitation in
  `userspace-dp/src/afxdp/forwarding/README.md` and the VRF docs, note that PBR
  is the only per-VRF forwarding path and that it is NOT session-isolated, and
  record the #3096 NAT-scope-vs-session-cache coherence contract.

### Track B-min — the minimal real fix for the LIVE PBR-mode bug (corrected ordering)

**AGY r1 Attack 5 correction:** v1/v2 said the key widening must come *last*,
after per-VRF default FIB (old B-P1), else it's a dead-end. That is **wrong**.
PBR `then routing-instance` is *already* the per-VRF forwarding mechanism on the
slow path (§4b), so widening the key + deriving a domain id alone fixes the
fast-path collision for PBR-based VRF deployments **without** needing per-VRF
default FIB. Per-VRF default FIB (now Track B-ext) is a *separate* enhancement
that makes *non-PBR* configs VRF-isolate — it is NOT a prerequisite for the key
fix. The minimal fix for the reachable bug is:

- **B-P0 — routing-domain id.** Derive a stable compact `routing_domain:u32`
  from the existing `ifindex_to_routing_instance` map by **interning the RI name
  to a dense u32** (domain 0 = default/unscoped) — never hash the RI name on the
  hot path. For PBR-steered flows the domain is the PBR-resolved
  routing-instance; for natively-assigned interfaces it is
  `ifindex_to_routing_instance[ingress_ifindex]`. Reuse the **dead
  `meta.routing_table` slot** (§4e) to carry it, so there is **no
  `UserspaceDpMeta` size change** (struct stays size-96 with its mirrored
  `offset_of!` asserts intact). SessionKey then grows by exactly 4 bytes.
- **B-P2 — symmetric discriminator in the key.** Add `routing_domain:u32` to
  `SessionKey`, `FlowCacheLookup`, and the reverse-key transforms
  (`reverse_wire_key` / `reverse_canonical_key`, `session/key.rs:84-138`). It
  **must be the routing-domain id, NOT zone or ingress-ifindex** — see §7.
  Leaked inter-VRF flows are scoped to domain-0 for B-min (the §7 hard gate).
- **B-P3 — HA wire (hard break).** Bump `CurrentHAProtocolVersion`, change the
  Go `sync_protocol.go` key encode/decode (primary + embedded reverse-key, V4 +
  V6), the Rust `SessionSyncRequest` (`protocol/control.rs:868-972`), the C
  conntrack mirror `session_key`/`session_key_v6`
  (`bpf/headers/xpf_conntrack.h:7`/`:68`), the Go mirror
  `dataplane.SessionKey`/`SessionKeyV6` (`pkg/dataplane/types.go:6`/`:87`), and
  regenerate the golden fixture `userspace-dp/tests/fixtures/protocol_wire_v1.json`.
  Gate mixed-version interop through the #1930 mixed-base ISSU path.

B-min (P0+P2+P3 + the leaked-flow scoping) is the smallest change that closes the
reachable #2387 breach. It is still non-trivial (the HA wire hard break + version
bump dominate the cost), but it is much smaller than the full per-VRF forwarding
feature.

### Track B-ext — per-VRF default forwarding (separate, deferred; NOT a prerequisite)

- **B-ext.1 — per-VRF forwarding without PBR.** Per-VRF `local_v{4,6}` sets and
  an ingress-VRF-scoped default FIB table, so an interface's native
  `routing_instance` selects the destination table for a normal packet *without*
  requiring a PBR filter. This makes §4b's default mode VRF-isolate too. It is an
  independent enhancement (a usability/parity improvement over "you must attach a
  PBR filter"), not needed for the B-min correctness fix.
- **B-ext.2 — leaked-flow full handling.** Replace B-min's domain-0 scoping of
  inter-VRF route-leaked flows with dual ingress+egress-domain storage and an
  egress-domain reverse-key transform (§7).
- **B-ext.3 — commit validation.** Flip A.1's warning to a "require overlap to
  live inside distinct routing-instances" model once isolation is real.

## 6. Public API preservation

Track A: no public Rust/Go API signature changes (A.1 is a new compiler check;
A.2 is internal to `flow_cache.rs`; A.3 is docs). Track B-min (B-P2/B-P3) changes
the `SessionKey` struct and the HA wire — by definition not preservable; that is
the cost the version bump exists to manage.

## 7. Hidden invariants the change must preserve

- **Conntrack reverse-match symmetry (the correctness trap).** The reply packet
  is matched via `reverse_wire_key` / `reverse_canonical_key`. The reply
  ingresses on the *egress* interface, so **ingress-zone and ingress-ifindex are
  asymmetric** across forward vs reply — putting either in the key breaks reply
  matching. The **routing-domain id is symmetric for intra-VRF flows** (forward
  and reply both stay in the VRF), so the reverse-key transform keeps the same
  domain and matching holds. **Residual asymmetry:** an **inter-VRF route-leaked
  flow** (next-table / rib-group) ingresses VRF-A, egresses VRF-B; its reply
  ingresses VRF-B, so the forward-stored domain differs from the reply's computed
  domain. **Resolution for B-min:** the config path that produces this is
  rib-group / `next-table` inter-VRF route leaking (`pkg/routing/`; recursion at
  `forwarding/mod.rs:1579-1604`). B-min **scopes leaked inter-VRF flows OUT** with
  a documented known-limitation (leaked flows keep domain-0 / unscoped identity,
  as today); Track B-ext.2 then stores both ingress and egress domain on the
  session and uses the egress domain in the reverse-key transform (mirroring NAT's
  reverse-key handling). Shipping the key widening without this scoping would
  silently regress leaked-flow conntrack, so the
  scoping decision is a hard gate, not prose. Campaign-8 did not flag this corner.
- **HA wire portability / mixed-version.** §4d: key widening is a hard break;
  ISSU during the upgrade window must not corrupt or silently drop sessions —
  hence the version bump + mixed-base gate + a version-aware decoder.
- **`UserspaceDpMeta` size/offset invariant.** The struct is size-96 with
  `offset_of!`/`const _` asserts mirrored in `types/mod.rs` and
  `userspace-xdp/src/lib.rs`; B-P0 plumbing must respect the mirror + asserts.
- **Allocation rules.** Domain-id derivation must be a per-packet *lookup* (an
  interned u32), never a per-packet `String` clone or hash of the RI name — the
  key is hashed per packet on the hot path.
- **#3096 NAT-scope coherence.** Any session-identity change must keep the
  invariant that a cached fast-path decision is only reused for a flow in the
  same scope it was admitted under.

## 8. Risk assessment

| Class | Track A | Track B |
|---|---|---|
| Behavioral regression | LOW — A.1 emits a commit WARNING (not a reject) on overlapping-L3-across-RI configs, INCLUDING PBR ones that currently forward; the config still commits, the operator is just told it is not session-isolated. (A hard reject is opt-in only, under the "no overlapping subnets" product posture — §11 Q1.) A.2 only changes which entry a same-parent VLAN flow caches under. | HIGH — touches conntrack identity, reply matching, per-VRF FIB; mis-set domain → flows fail to match (self-DoS) or cross-match. |
| HA mixed-version | NONE (no wire change). | HIGH — hard key-wire break (§4d); requires version bump + #1930 mixed-base ISSU gate + dual-format decoder for the upgrade window. |
| Wire / struct size | NONE. | MED — SessionKey +4 B (and the C/Go mirrors + golden fixture); `UserspaceDpMeta` already has the dead `routing_table` slot, so no meta size change if reused. |
| Performance (key hashed per packet) | NONE. | LOW-MED — +4 B in the key hash and per-entry map cost (~1-3%); domain-id derivation is one extra `FastMap` lookup at ingress. Must be measured (smoke + perf). |
| Architectural mismatch | LOW — A.1/A.3 are the honest contract; A.2 aligns flow-cache with the logical-ifindex SSOT already used elsewhere (#2370/#3021). | LOW-MED — corrected (AGY Attack 5): the key widening (B-min) is NOT a dead-end before per-VRF FIB, because PBR is already the per-VRF forwarding mechanism. Risk is reversed — B-min alone delivers PBR-mode isolation; B-ext (per-VRF default FIB) is the separable enhancement. The real mismatch risk is the HA wire hard break (managed by the version bump + ISSU gate). |

**PLAN-KILL acceptable if:** the churn of Track B outweighs the win for what is a
niche config (overlapping addresses + PBR + simultaneous identical 5-tuple —
§4b). Note the collision is **not** unreachable: it is live in PBR mode, only
latent in default mode. So PLAN-KILL rests solely on the cost/benefit prong, not
on unreachability. The proportionate immediate response is Track A.1 (commit
warning for the live breach) + A.3 (docs); the minimal real fix is **Track B-min**
(key widening + domain id + HA wire bump), scheduled if multi-tenant
overlapping-subnet VRF is a declared product goal. Track B-ext (per-VRF default
FIB) is independently deferrable.

## 9. Test plan

- **Track A.1 (RED-on-revert):** `pkg/config` unit test — two routing-instances
  with overlapping `10.0.0.10/24` on VLAN sub-units of one parent ⇒ commit
  succeeds with a **warning** naming both interfaces/instances. Reverting the
  guard (no warning emitted) makes the test go RED. (Under the opt-in hard-reject
  posture, a separate test asserts the commit is rejected.)
- **Track A.2:** `flow_cache` unit test — same physical parent, two VLAN units,
  identical 5-tuple ⇒ distinct flow-cache entries (RED if the key reverts to raw
  physical ifindex).
- **Track B-min (the issue's stated regression, RED-on-revert):** construct two
  flows — same parent ifindex, two VLAN sub-interfaces in different
  routing-instances each with a PBR `then routing-instance` filter steering to its
  own table (so each forwards), identical 5-tuples, differing policy/NAT — and
  assert **no** session or flow-cache reuse across the boundary, plus correct
  reply-direction match *within* each VRF, plus the inter-VRF route-leaked corner
  stays domain-0 (§7). Reverting the `routing_domain` field makes it RED (flow 2
  inherits flow 1's egress).
- **HA wire round-trip:** Go `sync_protocol.go` encode→decode of the widened key
  (V4 + V6, primary + reverse-key) round-trips; golden `protocol_wire_v1.json`
  regenerated and matched; a version-skew decode test proves graceful handling
  during ISSU.
- **HA live:** `make test-failover` on the loss userspace cluster (key crosses
  the cross-chassis wire) — required for any Track-B change touching session sync.
- **Perf neutrality:** smoke v4 + v6 + per-class CoS on the loss cluster; perf
  record to confirm the wider key + domain-id lookup is within noise.

## 10. Out of scope (explicitly)

- Per-VRF default FIB / per-VRF local-delivery sets (Track B-ext) — a separate
  multi-PR enhancement, NOT needed for the B-min correctness fix; #2388 already
  tracks the connected-route table-naming half.
- Zone-only flow isolation without overlapping addressing (not reachable; same
  src IP can't legitimately ingress on two zones without overlap or asymmetric
  routing).
- Repurposing `meta.routing_table` for anything other than the B-P0 domain id.
- Any change to the eBPF retirement posture (the C conntrack header is a
  parity/mirror artifact only).

## 11. Open questions for adversarial review

1. **Product scope (decides the response level):** Is overlapping-subnet
   multi-tenant VRF isolation (via PBR) something we support? The bug is now known
   reachable (live in PBR mode), so the choice is: (a) **support it** → schedule
   **Track B-min** (the real fix) + ship A.1 warning + A.3 docs as interim; or
   (b) **explicitly do not support it** → upgrade A.1 from a warning to a hard
   reject and document the non-support. Either way A.3 (docs) + A.1 (some guard)
   ship now. "Do nothing" is no longer defensible given reachability.
2. **[Largely answered by r1]** The §4c #3096 coherence gap is reachable via PBR
   (all three reviewers confirmed). Remaining sub-question: is there a
   *non-PBR* forwarding-correct trigger (e.g. asymmetric routing, ECMP across
   VRFs) that also reaches it? If so, B-ext (per-VRF default FIB) moves up too.
3. Is the routing-domain id truly the only symmetric discriminator, or is there a
   cheaper symmetric quantity already on both forward and reply packets? Refute
   or confirm that zone/ingress-ifindex are unusable (§7).
4. **[Answered by r1, confirm the scope call]** The inter-VRF route-leaked
   reverse-match corner (§7) has a config path today (rib-group / next-table). The
   plan scopes leaked flows to domain-0 in B-min and defers full dual-domain
   handling to B-ext.2. Do reviewers agree leaked flows can keep today's
   (domain-0) behavior in B-min, or must dual-domain be in the first cut?
5. Is the HA-wire hard-break assessment (§4d) correct that the key portion is not
   length-gated (all three r1 reviewers confirmed it is), or is there a
   forward-compatible encoding — e.g. a NEW session-sync message type carrying the
   domain as a trailing value field, with domain-0 implied for old peers — that
   downgrades B-P3 from "hard break" to "additive"? This is the single biggest
   lever on B-min's cost and deserves a deliberate design choice at /engineer time.
6. Is A.2 (flow-cache logical-ifindex key) safe to ship independently of A.1, or
   does changing the flow-cache key risk a first-packet-latency or
   cache-thrash regression on the untagged common case?
