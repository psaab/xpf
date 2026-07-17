# Plan of action — #5837: userspace XDP local-interface destination check bypasses DNAT/static-NAT

**Status:** DRAFT v5 — after Codex r4 (REVISE; architecture + verifier bounding accepted since r3) + Claude SMR r2–r4 (PLAN-READY). Pending round-5 review.
**Issue:** #5837 (bug, High, security, nat, audit)
**Research branch:** `research/5837-xdp-dnat-before-local`
**Base:** origin/master `7d2cd112fec4`
**Mode:** `/research` — stops at PLAN-READY / PLAN-KILL. No PR, no production code touched here.

**v5 changelog (Codex r4 — material correctness):**
- **Degraded-path bypass (new, important):** `is_degraded_local_or_control` (lib.rs:1037-1057)
  calls `is_local_destination`, so during helper degradation a configured interface-address
  DNAT tuple is re-classified local → passed to kernel = **#5837 recreated while degraded**.
  Fix: matching non-AH intent must be **dropped (fail-closed transit)** in every degraded /
  binding-missing / heartbeat-stale branch, not passed local (§5e). Adds verifier surface.
- **AH guard must precede the live-session lookup** (not just the miss arm), else an IPv6
  AH-to-self packet colliding with a translated session redirects before the guard (§5a).
- **Generation-safe deletion:** synchronous stale-delete under the server-state writer
  mutex, recomputed at apply; NO deferred cross-generation retry (§5d).
- Complete §5d≡§11 (adds NDP unicast, ingress-iface-absent, enumerated reduced-scope
  outcomes); IP-only PROTO_ANY DNAT → TCP+UDP expansion (ICMP dst-port=0 → dead key);
  per-family exact/wildcard capability **bitmask** produced by pkg/dataplane (no config↔ELF
  import cycle); named pin fields + extended ABI arm; numeric availability test.
- **§13 research-resolved vs implementation-execution boundary** added.

**Earlier:** v2 dedicated intent map (collision); v3 concrete ABI + loud diagnostics; v4
rollback-safe new-only txn + IPv6-AH guard + restart reconcile + mandatory pins.

---

## 1. Issue framing

On a non-GRE session miss the shim (`try_xdp_userspace`) returns a packet to the kernel as
kernel-local *before* consulting DNAT/static-NAT. `is_local_destination` (lib.rs:1363) only
exempts interface-mode SNAT. A port-forward / static 1:1 NAT mapping the **WAN interface's
own address** (legitimate Junos config) is inert on the first packet — delivered to the host
instead of translated + zone-policed. **High-severity security bypass.** Invariant: a
configured destination translation matching dst address + proto/port takes precedence over
kernel-local delivery; unmatched traffic to the same address still reaches local services.

## 2. Verifier go/no-go ladder (the crux)

Change is in the **`make generate`-gated shim** (1M-insn cap, #1864). **Tail-call is
forbidden** (retirement_boundary_canary_test.go:345-353; allowlist :127-129); `shimverify`
returns only binary PASS/REJECT. The intent classification must be placed in the healthy
miss arm **and** the degraded/early-return branches (§5e), so the verifier surface is larger
than "one probe" — this sharpens the crux. Ladder (implement time; artifact carries a
per-family capability bitmask, §5c, that the Go §5d diagnostics read):

1. Build **Phase-1 exact-both** (v4+v6 exact, incl. degraded-path drop) → `shimverify`.
2. PASS → ship exact-both. **Phase-2 wildcard = SEPARATE candidate**: PASS → ship wildcard;
   REJECT → **retain exact-both** (wildcard/static-1:1 forms → §5d warning).
3. Phase-1 exact-both REJECT → build **v4-exact-only** → `shimverify`.
4. v4-exact PASS → ship v4-only + LOUD §5d warning (all IPv6 forms un-enforced).
5. v4-exact REJECT → **instruction reclaim** (fold the existing `is_local`/`interface_nat`
   probes into one keyed pass) → re-verify; PASS → ship reclaimed scope.
6. Still REJECT → **PLAN-KILL** (interim: commit reject/warn only).

A candidate must PASS on **both** the 6.18 floor and current-image kernel (either REJECT =
candidate REJECT → next ladder step). Hard commit-reject as the *primary* fix is rejected
(parity); a warning alone doesn't fix the bypass.

## 3. Central finding

"Just add a `DNAT_TABLE` lookup" is **necessary but not sufficient**: the shim-visible
`dnat_table`/`dnat_table_v6` hold **only dynamic (flags=0) reverse-NAT**, not configured
forward DNAT (loader.go:407-441 setters are no-ops; configured DNAT lives in the helper's
in-memory tables, poll_descriptor:1511/1577; README:177). **Fix = (P) publish intent + (S)
shim probe before local classification, in all classification branches.**

## 4. Composes with

- Interface-SNAT exclusion (maps_sync.go:1670) — untouched.
- `dnat_table` reverse lifecycle (#2979): flags=0 `BPF_ANY` publish + delete-by-key
  (`checksum.rs:246-346`) — the collision that rules out map reuse (Option A).
- Verifier gate `shimverify` — local, not shim-wall-blocked; only smoke is.
- v6 wildcard precedent: `dnat_lookup_v6` exact-only (2nd HASH lookup blew the cap, lib.rs:882).

### 4a. Helper already applies DNAT before local resolution (fix sufficient, healthy path)

`poll_descriptor/mod.rs`: session miss → `pre_routing_dnat` (:1577) → dst rewritten in
`effective_resolution_target` (:1673) → `resolve_forwarding` (:3633) on the translated
target; policy on post-translation tuple (#2345). Steering to XSK is sufficient; **no helper
translation change** on the healthy path. (Degraded path is different — §5e.)

## 5. Concrete design (Option B — dedicated intent map)

### 5a. Shim probe (S) — with AH guard BEFORE the live-session lookup

`live_userspace_session_action` runs at lib.rs:584, before the miss arm. An IPv6 AH-to-self
packet whose inner tuple collides with a translated cleartext session would REDIRECT there
before any miss-arm guard. So the AH-local protection must run **before** the live-session
lookup (or the live-session path must decline local AH). Placement:

```rust
// dst_ne is NativeEndian (parsed.dst_v4 is BigEndian — matches USERSPACE_LOCAL_V4, NOT dnat).
let dst_ne = u32::from_ne_bytes([parsed.dst_addr[0..4]]);
// AH-local protection first: an AH-carrying packet whose (post-AH inner) dst is local must
// keep the is_local_destination XFRM shunt (§8.6) — decline intent AND the session-hit steer.
if parsed.ah_present && is_local_destination(&parsed) { return cpumap_or_pass(ctrl); }
// ... then the existing live-session lookup, then the miss arm:
if !parsed.ah_present && intent_matches(&parsed, dst_ne) {
    // fall through to XSK redirect
} else { /* is_icmp_to_interface_nat_local; is_local_destination → local */ }
```

`intent_matches` = one exact HASH probe/family (Phase 1). **ICMP:** `parse_l4` sets
`flow_dst_port = 0` for ICMP/ICMPv6 (lib.rs:1516), so ICMP intent is published `dst_port=0`
and hits exact (protocol byte disambiguates); identifier-agnostic; emitted only where an ICMP
translation is configured, preserving echo-reply handling for non-translated addresses.

### 5b. Intent semantics + restart reconcile

Intent is a **steer-superset**: port-0 (or address-wildcard) over-steers ALL ports for that
proto+ip; the helper re-checks the exact rule and locally-delivers non-matching packets (§4a)
— no policy bypass, an availability shift (§9/§10). **Restart:** pinned maps **persist**
across restart (loader_userspace_shim.go:63) — the map is NOT empty. On every bringup, the
helper enumerates the pinned intent maps (the actual current contents, incl. crash residue),
removes `current − desired` **before** inserting `desired − current` (so a stale-full map
doesn't fail the union preflight), and gates **binding readiness** (`maps_sync.go:673`, the
real shim steering gate) until the reconcile succeeds; any enumerate/insert/delete failure →
keep bindings non-READY, report, retry from scratch. Fresh-node fail-safe (absent intent →
is_local path → today's behavior, never a new bypass) still holds.

### 5c. Map + key ABI, mandatory plumbing, capability bitmask

New `dnat_intent_v4`/`dnat_intent_v6`, HASH, `BPF_F_NO_PREALLOC`, **fixed**
`max_entries = 8192`. Keys mirror `DnatKeyV4` `repr(C)`, all pads zeroed both sides:

```rust
#[repr(C)] struct IntentKeyV4 { protocol:u8, pad:[u8;3], dst_ip:u32(NE), dst_port:u16(host), pad2:u16 } // 12B
#[repr(C)] struct IntentKeyV6 { protocol:u8, pad:[u8;3], dst_ip:[u8;16], dst_port:u16(host), pad2:u16 } // 24B
```

Wiring (implement-time tasks):
- Shim declares both; add to canary `userspaceShimAllowedMapTypes` (:107) + PinByName
  `userspacePinnedShimMaps` (:502).
- Go: add `UserspaceMapPins.DnatIntentV4/DnatIntentV6` (protocol.go) + Rust `MapPins`
  fields (snapshot.rs); create/pin via `loadUserspaceShimSharedMaps` (:551, runs before
  shim load :97 — no lazy gap) + mirror in `userspaceShimSharedMapSpecs` (:604). **Extend
  the ABI arm**: `validateSharedMapExpectedABI` (:304) currently checks only type/key/value
  — add mandatory-presence + `max_entries==8192` + `BPF_F_NO_PREALLOC` for the intent maps.
- **Mandatory, fail-closed FDs:** helper opens via a non-optional open (NOT
  `open_optional_map`, which returns `Ok(None)` on empty pin, snapshot.rs:369) whenever the
  intent capability is active — a translating config never activates with absent intent FDs.
- **Capability bitmask (no import cycle):** package `dataplane` owns the embedded ELF
  (`userspace_xdp_rust.go`); `config` cannot read it (dataplane→config import edge,
  compiler.go:20). So `dataplane` computes a per-family bitmask
  `{v4_exact, v6_exact, v4_wildcard, v6_wildcard}` (+ an absent/legacy value for a shim with
  no intent maps) from the loaded artifact and PASSES it to the config compiler via a
  parameter/interface. The §5d diagnostics read that bitmask, so warnings always match the
  shipped candidate. Carrier: a shim-declared const map/section validated at load.
- **Cardinality preflight:** reject a config whose **`|current ∪ desired|` per-family**
  encoded-key count (after expansion) exceeds 8192.

### 5d. Publisher (P) — new-only, rollback-safe, generation-safe, loud

Reconcile intent in config apply from `destination_nat_rules` + `static_nat_rules`,
**only for rows that actually translate** (skip off/disabled/exemption/unparseable,
destination.rs:113). Key generation:
- port-scoped DNAT → exact `(proto, ip, port)`.
- port-scoped static NAT → exact `(proto, ip, port)` (representable, static_nat.rs:159);
  **TCP+UDP only** (ICMP dst-port=0 can't match a nonzero static port → dead key,
  static_nat.rs:572).
- port-less/range DNAT, port-less single-address static NAT → port-0 wildcard.
- **IP-only PROTO_ANY DNAT** (destination.rs:399) → TCP+UDP exact/port-0 expansion; the
  non-{TCP,UDP} residual is **loud-diagnosed** (the `u8` key can't hold 256).

**Transaction (rollback- AND generation-safe):**
1. `desired`, `new_only = desired − current`, `stale = current − desired`.
2. Preflight `|current ∪ desired|` per family ≤ 8192.
3. Insert **only `new_only`** with `UpdateNoExist` (loader.go:588) — never overwrite an
   active key. Any failure → delete only the `new_only` keys created this apply + abort the
   apply (fail-closed; unchanged active keys untouched). EEXIST races abort safely (control
   requests serialize under the server-state mutex, handlers/mod.rs:122).
4. Publication completes **before** the full-reconcile worker teardown
   (`coordinator/reconcile/mod.rs:297`, reconcile begins :193) and before the
   same-plan-refresh commit (`snapshot_refresh.rs:220/236`). `lifecycle.rs:310` is *init*.
5. **Generation-safe delete:** delete `stale` **synchronously under the writer mutex** in
   the same apply, recomputing `current − desired` at apply time. **No deferred
   cross-generation retry** (a delayed gen-B delete could remove a key gen-C re-desires — the
   value is presence-only, no generation tag). A delete failure keeps bindings non-READY +
   reports; the restart reconcile is the backstop.
6. **Deferred arming / disarmed refresh:** deferred activation runs through
   `set_forwarding_state`, which currently **discards** the reconcile error (forwarding.rs:32)
   — an intent-reconcile/restart-reconcile failure must instead revert arming and return
   `ok=false`. A disarmed same-plan refresh must reopen the mandatory intent pins (stop()
   clears FDs, coordinator/mod.rs:521) or defer publication to arm-time reconcile while
   classification stays disabled.

**§5d loud-diagnostic set (mandatory; ≡ §11).** Every form not dataplane-enforced on the
first packet raises an operator-visible commit-time warning naming the rule. Complete set:
static-NAT `protocol any` / IP-only PROTO_ANY DNAT non-{TCP,UDP} residual; DNAT/static
**address-prefix/LPM**; the **reduced-scope outcomes** — if Phase-2 rejects, ALL portless/
range DNAT + whole-address static-wildcard in BOTH families; if v4-only ships, ALL IPv6
forms; DNAT/static onto the firewall's own **ESP/AH/IKE/WG/non-native-GRE** control port;
**native-GRE outer** DNAT (sibling branch, lib.rs:646); **multicast / link-local / IPv4
limited-broadcast** (`should_fallback_early`, lib.rs:1340); **unicast NDP-shaped** ICMPv6
133-137 to a global interface address (early return, lib.rs:578); **IPv6-AH-to-self** address
(declined by §8.6); **ingress-iface-absent** interfaces (see §5e).

### 5e. Degraded / early-return coverage (the residual-bypass closure)

Every branch that currently treats `is_local_destination` as local and passes to the kernel
must be made **intent-aware and fail-closed**, or #5837 recurs during helper degradation:
- `is_degraded_local_or_control` (lib.rs:1037-1057) → `pass_local_control` on ctrl-disabled
  (lib.rs:1009), binding-missing/not-ready, heartbeat-missing/stale. A **matching non-AH
  intent tuple must be DROPPED via `drop_degraded_transit`** (fail-closed — the helper can't
  translate while degraded, so leaking the flow to the local host would reproduce the bypass).
- The `USERSPACE_INGRESS_IFACES` absent/zero early return (lib.rs:426) passes the packet
  before any probe. The plan must PROVE an active translating interface is always in the
  ingress set (it is a configured zone interface) or apply fail-closed intent classification
  there; either way, §5d warns for any interface that can't be covered.
- NDP (lib.rs:578) and `should_fallback_early` (lib.rs:1340) early returns: DNAT on those is
  nonsensical; out of scope with §5d warnings.

This additional placement is what pushes the verifier surface up and must be budgeted in the
§2 ladder (the degraded-path drop decision is part of Phase-1 exact-both).

## 6. Options

| Option | Mechanism | Port-aware | Verdict |
|---|---|---|---|
| **B (recommended)** | Dedicated `dnat_intent_v4/v6`, helper new-only reconcile; shim exact probe in all branches | Yes | **Primary** — disjoint lifecycle, no collision, safe rollout |
| A | Reuse `dnat_table` flags=1 | Yes | **Rejected** — dynamic publish/delete overwrite/erase colliding intent (checksum.rs:246-346) |
| A′ | Reuse `dnat_table` + sentinel key | Yes | Fallback-if-no-new-map; shares session capacity |
| C | Go address-exclusion | **No** | **Rejected** — not port-aware |
| D | Commit reject/warn | n/a | **Rejected as primary**; = the §5d diagnostic |

## 7. Public API / behavior preservation

- `is_local_destination`, `is_icmp_to_interface_nat_local`, `is_interface_nat_destination`,
  `dnat_lookup_v4/v6` unchanged; new `intent_matches` + `ParsedPacket.ah_present` field +
  check reorder + degraded-path intent drop.
- `dnat_table` MapSpec unchanged; new `dnat_intent_v4/v6` additive (safe rollout).
- Helper reverse lifecycle, interface-SNAT, GRE classify, ESP/WG/NDP short-circuits —
  unchanged except the degraded-path drop for matching intent.

## 8. Hidden invariants

1. Unmatched ports stay kernel-local.
2. Native-endian singular key contract (`from_ne_bytes`, host-order port, zeroed pads);
   cross-side key-bytes test.
3. Intent lifecycle disjoint from reverse-NAT.
4. New-only + generation-safe transaction: never overwrite/rollback/deferred-delete an active
   key; synchronous stale-delete under the writer mutex; union-capacity preflight.
5. Rule removal removes intent (non-LRU; restart reconcile backstop).
6. **Control-protocol precedence.** Shim short-circuits ESP / non-native GRE / local WG
   (lib.rs:539-548) — NOT AH/IKE. **IPv6 AH** is special: the shim walks THROUGH AH
   (lib.rs:1269), so the helper's `PROTO_AH` arm never fires for IPv6 AH, which relies on the
   `is_local_destination` shunt (forwarding/mod.rs:1288-1305). The §5a `ah_present` guard —
   placed **before** the live-session lookup — preserves it. Native-GRE outer uses the sibling
   branch (lib.rs:646). Multicast/link-local/broadcast/NDP pass local before the lookup. All
   out of scope with §5d warnings.
7. **Degraded fail-closed:** a matching non-AH intent tuple is dropped, never passed local,
   in every degraded/early-return branch (§5e).
8. Session-hit consistency: an AH-carrying IPv6 packet colliding with a translated session is
   declined by the §5a guard before the session-hit steer.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| eBPF verifier / 1M cap (**crux**) | **HIGH** | intent probe in miss arm + degraded branches + AH guard; tail-call forbidden; no headroom metric. Ladder §2. |
| Reconcile transaction | MED | new-only + generation-safe sync delete + union-capacity + restart reconcile + mandatory pins + deferred-arm error propagation. |
| Availability (over-steer → slow-path drop) | MED | port-0 over-steers ALL ports; non-SYN local delivery not session-cached (forwarding/mod.rs:1829) → repeated exposure; slow path drops when unavailable/rate-limited (slow_path.rs:283/301). Mitigate: exact intent for port-scoped rules; counted + bounded (§10). |
| IPv6-AH regression | MED (mitigated) | §5a guard before session-hit + miss. |
| Degraded-path residual bypass | MED (mitigated) | §5e fail-closed drop. |
| Behavioral regression | LOW–MED | reorder; unmatched ports + ICMP echo-reply preserved. |
| Static-NAT representability | MED | exact/port-0 subset + §5d loud diagnostics. |
| ABI bump (new maps) | LOW–MED | additive, safe rollout; mandatory-FD gating. |
| Rollout / smoke | MED (deferred) | end-to-end capture shim-wall-blocked; verifier + cargo tests are not. |

## 10. Test plan

- **Verifier:** `make generate`/`shimverify` PASS (exact-both incl. degraded-path drop first;
  wildcard separate); identical artifact PASSes 6.18 floor + current-image; deploy pre-flight.
- **Helper cargo:** new-only reconcile (v4-ok/v6-fail → roll back only new_only, apply
  aborted, active keys intact); union-capacity preflight; synchronous generation-safe delete
  (no cross-gen deletion of a re-desired key); restart reconcile rebuilds exactly from
  authoritative config before readiness; deferred-arm failure reverts arming (ok=false);
  only-translating rows emit intent; disjointness from `dnat_table`;
  `close_delta_deletes_dnat_table_entry_for_snat_flow` still green.
- **Shim (host-testable predicate/harness):** `ah_present` set for IPv6 AH; intent probe +
  degraded-path drop behavior — a shim-local predicate (not "helper cargo").
- **Go:** cross-side key-bytes assertion; cardinality preflight; §5d warning fires per residual
  form and matches the capability bitmask; ABI arm asserts presence + max_entries + flags.
- **RED acceptance (issue):** IPv4/IPv6 TCP/UDP DNAT on the interface address → first packet
  to XSK + fwd/rev translate; port-wildcard/static-1:1 (both families, v6 wildcard limitation
  noted); ICMP translated (port-0 exact) vs. ordinary ping local; unmatched SSH/BGP/IKE port
  local; **IPv6 AH-to-self stays kernel-local (XFRM), incl. the colliding-session-hit case**;
  **matching intent DROPPED (not local) while the helper is degraded**; zone policy on
  translated transit; generation-safe add/remove.
- **Availability (numeric):** using the clock-injectable limiter (slowpath_tests.rs:141),
  offer rate R (pps) / size S for duration T of unmatched traffic to an over-steered (port-0)
  address; assert admitted ≤ the JOINT packet-bucket AND byte-bucket ceiling (both full with
  1s capacity, slowpath.rs:86/108); count `slow_path_drops` WITHOUT summing
  `slow_path_rate_limited` (one rate-limited packet increments both, slow_path.rs:301);
  isolate unavailable/queue-full confounders; assert steady-state matched flows unaffected.
- **Smoke (DEFERRED — shim-wall):** end-to-end first-packet fwd+rev v4+v6 on `loss:` once the
  shim-ABI wall clears.

## 11. Out of scope (≡ §5d — each with a commit warning)

ESP/AH/IKE/WG/non-native-GRE own-control-port DNAT; IPv6-AH-to-self address; native-GRE outer
DNAT; static `protocol any` / IP-only PROTO_ANY non-{TCP,UDP} residual; DNAT/static
prefix/LPM; multicast/link-local/IPv4-limited-broadcast; unicast NDP-shaped ICMPv6 133-137;
reduced-scope outcomes (Phase-2 reject → all portless/range DNAT + whole-address static in
both families; v4-only ship → all IPv6 forms); ingress-iface-uncoverable interfaces; helper
translation math + interface-mode SNAT (unchanged).

## 12. Open questions for round-5 review (each invitable to PLAN-KILL)

1. **Verifier:** exact-both **plus the degraded-path drop + AH guard** affordable in one
   program (tail-call forbidden)? If REJECT → v4-exact-only + LOUD diagnostic, else PLAN-KILL.
2. **Degraded-path closure (§5e):** is fail-closed DROP the correct degraded behavior for a
   matching intent tuple, and is covering every early-return branch complete?
3. **AH ordering (§5a):** is the pre-session-hit `ah_present`+local decline the right fix?
4. **Generation-safe delete (§5d):** synchronous-under-mutex + no deferred cross-gen retry —
   does this close the reuse race?
5. **Capability bitmask (§5c):** dataplane-computes-passes-to-config (no import cycle) +
   per-family exact/wildcard bits — adequate to keep diagnostics matched to the artifact?
6. **Is PLAN-KILL warranted**, or is phased Option B the right call?

## 13. Research-resolved vs implementation-execution boundary

**Research-resolved (design decisions this plan owns):** map-reuse-vs-dedicated (B); the
collision, byte-order, ICMP, AH, degraded-path, generation-safety, and restart-persistence
correctness models; the verifier ladder + fail-safe + PLAN-KILL fork; the representable-subset
+ loud-diagnostic policy; the capability-bitmask dependency direction. These are the design
questions /research exists to answer, and they are answered.

**Implementation-execution (enumerated for `/engineer`, not authored here):** exact struct
field byte layouts / JSON tag strings; the capability-bitmask wire encoding + validator; the
precise `make generate`/`shimverify` runs on both kernels (the go/no-go gate is mechanical and
belongs to implementation, not the plan); exact test rates/thresholds beyond the joint-bucket
ceiling relationship. These are execution tasks the plan directs; a research doc that fully
authored them would be the implementation, not a plan.
