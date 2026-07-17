# Plan of action — #5837: userspace XDP local-interface destination check bypasses DNAT/static-NAT

**Status:** DRAFT v3 — revised after Codex r2 (REVISE, spec-depth) + Claude SMR r2 (PLAN-READY). Pending round-3 review.
**Issue:** #5837 (bug, High, security, nat, audit)
**Research branch:** `research/5837-xdp-dnat-before-local`
**Base:** origin/master `7d2cd112fec4`
**Mode:** `/research` — stops at PLAN-READY / PLAN-KILL. No PR, no production code touched here.

**v3 changelog (addresses Codex r2):** concrete key ABI (`repr(C)`, sizes, zeroing) +
map plumbing/capacity/canary-allowlist spec (§5c); fixed compile-time capacity + commit
cardinality preflight; publisher emits intent only for rules that actually translate;
atomic v4+v6 reconcile with rollback across **all** activation paths; startup fail-safe =
today's behavior (§5b); **loud operator-visible commit diagnostics for every
non-dataplane-enforced form** (§5d) so no residual bypass is silently marked fixed;
corrected ICMP port-0 contract; corrected shim short-circuit set (ESP/non-native-GRE/WG,
not AH/IKE); availability test reframed to bound slow-path drops; explicit v4-only↔PLAN-KILL
ladder (§2).

**v2 changelog:** switched from reuse-`dnat_table` (collision hazard) to a dedicated
zone-agnostic intent map; reframed verifier crux (tail-call forbidden, no headroom metric).

---

## 1. Issue framing

On a non-GRE **session miss**, the AF_XDP ingress shim (`userspace-xdp/src/lib.rs`,
`try_xdp_userspace`) returns a packet to the kernel (`cpumap_or_pass`) as
kernel-local *before* consulting configured DNAT/static-NAT. `is_local_destination`
(lib.rs:1363) only exempts interface-mode source-NAT. So a port-forward / static
one-to-one NAT mapping the **WAN interface's own address** (common, legitimate Junos
config) is inert on the first packet — delivered to the host instead of translated +
zone-policed. **High-severity security bypass.**

Invariant: *a configured destination translation matching destination address +
protocol/port must take precedence over kernel-local delivery; unmatched traffic to
the same interface address must still reach legitimate local services.*

## 2. Honest scope/value framing + the go/no-go ladder

Correctness/security fix. Win: DNAT/static-NAT on an interface address is enforced on
the first packet instead of bypassed. The change is in the **`make generate`-gated
shim**; the make-or-break is **verifier feasibility** (1M-insn cap, #1864), and the
escape hatches are narrow: **tail-call is forbidden** by the retirement canary
(`retirement_boundary_canary_test.go:345-353` bans `ProgramArray`/`.tail_call`/
`bpf_tail_call`; single XDP prog allowlisted :127-129), and `shimverify` returns only
binary PASS/REJECT (no processed-insn headroom). Decision ladder, run at implement time:

1. Build **Phase-1 exact-only, both families** → `shimverify`.
2. PASS → ship; Phase-2 wildcard is a **separate** built+verified candidate.
3. Full REJECT → build **v4-exact-only** → `shimverify`.
4. v4-exact PASS → ship v4-exact-only **with a LOUD commit-time diagnostic** (§5d) for
   the un-enforced v6 form.
5. v4-exact REJECT → attempt **instruction reclaim** (fold existing
   `is_local`/`interface_nat` probes) → re-verify.
6. Still REJECT → **PLAN-KILL** (or interim: commit-time reject/warn only).

A hard commit-reject as the *primary* fix is rejected: port-forward to an interface
address is legitimate config (parity), and a warning alone doesn't fix the bypass.

## 3. Central finding (verified by both reviewers)

The issue's "just add a `DNAT_TABLE` lookup" is **necessary but not sufficient**: in the
userspace-dp runtime the shim-visible `dnat_table`/`dnat_table_v6` hold **only dynamic
(flags=0) reverse-NAT** records, not configured forward DNAT.

- `pkg/dataplane/loader.go:407-441` — userspace-path `SetDNATEntry`/static setters/
  stale-delete hooks are **no-ops**. Configured DNAT/static-NAT is matched in the
  helper's in-memory `DnatTable`/`StaticNatTable` (`forwarding_build/mod.rs:309`,
  `poll_descriptor/mod.rs:1511/1577`).
- `userspace-dp/README.md:159-177` — "STATIC DNAT-config entries (flags=1) are never
  published." Non-LRU maps; stale historical flags=1 not structurally impossible across
  restarts — another reason not to overload `dnat_table`.

**The fix = (P) publish configured translation intent the shim can see + (S) a shim
probe before local classification.**

## 4. What's already shipped / must compose with

- **Interface-SNAT exclusion** (maps_sync.go:1670) — address-only, the wrong model for
  DNAT; untouched.
- **`dnat_table` reverse lifecycle** (#2979): flags=0 `BPF_ANY` publish
  (`checksum.rs:304-346`) + delete-by-key with no flags check (`checksum.rs:246-289`) —
  the collision that rules out map reuse.
- **Verifier gate** (#1864): `shimverify` real `BPF_PROG_LOAD` at `make generate` +
  deploy pre-flight. **Local, not shim-wall-blocked**; only end-to-end smoke is.
- **Retirement canary**: forbids tail-call/>1 XDP prog; map allowlist
  `userspaceShimAllowedMapTypes` (retirement_boundary_canary_test.go:107) — new maps
  must join it.
- **v6 wildcard precedent**: `dnat_lookup_v6` exact-only (a 2nd HASH lookup blew the cap
  in the v6 GRE classify, lib.rs:882-891).

### 4a. Helper already applies DNAT before local resolution (fix is *sufficient*)

`poll_descriptor/mod.rs`: session miss computes `pre_routing_dnat` (:1577-1601),
rewrites dst to the internal host in `effective_resolution_target` (:1673-1685), and
`resolve_forwarding` (:3633) runs on **that translated target**; policy on the
post-translation tuple (#2345). Once the shim steers the first packet to XSK, the helper
already does DNAT-before-local. **No helper translation change.**

## 5. Concrete design (Option B — dedicated intent map)

### 5a. Shim probe (S)

In `try_xdp_userspace`, non-GRE session-miss arm (lib.rs:632), **before**
`is_icmp_to_interface_nat_local`/`is_local_destination`:

```rust
// Native-endian dst — parsed.dst_v4 is BigEndian (matches BigEndian-published
// USERSPACE_LOCAL_V4); the intent map is NativeEndian (matches ipToUint32BE /
// the GRE-path dnat key). Rebuild from raw wire bytes.
let dst_ne = u32::from_ne_bytes([parsed.dst_addr[0], parsed.dst_addr[1],
                                 parsed.dst_addr[2], parsed.dst_addr[3]]);
if intent_matches(&parsed, dst_ne) {
    // fall through to XSK redirect — do NOT pass to kernel
} else {
    if is_icmp_to_interface_nat_local(&parsed) { return cpumap_or_pass; }
    if is_local_destination(&parsed) { return cpumap_or_pass; }
}
```

`intent_matches` = one exact HASH probe per family (Phase 1), keyed on
`(protocol, dst_ne, parsed.flow_dst_port)`. **ICMP:** `parse_l4` sets
`flow_dst_port = 0` for ICMP/ICMPv6 (lib.rs:1516), so an ICMP intent is published with
`dst_port = 0` and hits via an **exact** match (no wildcard probe needed). This is
identifier-agnostic (config has no runtime ICMP id), and ICMP intent is emitted only
where an ICMP-bearing translation is configured, so `is_icmp_to_interface_nat_local`
echo-reply handling for non-translated addresses is preserved.

### 5b. Intent semantics + startup fail-safe

Intent is a **steer-superset**, not an exact enforcement set: a port-0 (or
future address-wildcard) entry over-steers all ports for that proto+ip to XSK, where
the helper re-checks the exact rule (range, source scope, zone) and **locally-delivers
non-matching packets** via its LocalDelivery+reinject path (§4a) — no bypass, only an
availability shift (§9/§10). **Startup fail-safe:** an empty/not-yet-populated intent
map makes `intent_matches` return false → `is_local_destination` runs → **exactly
today's behavior** (the pre-fix status quo, not a *new* bypass). So the "gate
classification until intent is authoritative" requirement is satisfied structurally:
before the first authoritative snapshot lands, the fix is simply inactive, never
wrong-in-a-new-way.

### 5c. Map + key ABI, plumbing, capacity (the wiring spec)

New maps `dnat_intent_v4` / `dnat_intent_v6`, `BPF_MAP_TYPE_HASH`,
`BPF_F_NO_PREALLOC`, **fixed** `max_entries = 8192` (compile-time constant, mirroring
`USERSPACE_LOCAL_V4`; a BPF `MapSpec` capacity is fixed at load, NOT per-config). Keys
mirror the `DnatKeyV4` `repr(C)` discipline (explicit pad, zeroed):

```rust
#[repr(C)] struct IntentKeyV4 { protocol: u8, pad: [u8;3], dst_ip: u32, dst_port: u16, pad2: u16 } // 12B
#[repr(C)] struct IntentKeyV6 { protocol: u8, pad: [u8;3], dst_ip: [u8;16], dst_port: u16, pad2: u16 } // 24B
// value: u8 (presence-only). All pad bytes zeroed on both publish and probe.
```

Wiring checklist (each an implement-time task):
- Shim declares both maps `#[map(name=...)]`; add to `userspaceShimAllowedMapTypes`
  (canary) and the PinByName inventory (`userspacePinnedShimMaps`).
- Go creates/pins them (`loadUserspaceShimSharedMaps` + `hashMapSpec`) and mirrors the
  `MapSpec` in `userspaceShimSharedMapSpecs`, so `validateSharedMapExpectedABI` guards
  fresh-node ABI and `validateUserspaceShimLivePins` guards live drift.
  **Rollout is safe:** `validateUserspaceShimLivePins` skips a map with no live pin
  (`if !exists { continue }`), so the deploy that introduces these maps does NOT
  chicken-and-egg-reject against the old daemon.
- Helper opens the FDs (`coordinator/bpf_maps.rs` `dnat_intent_*_fd`, filled in
  `reconcile/bringup.rs` from `reconcile/snapshot.rs` `open_optional_map`), plumbed
  like the existing `dnat_table_fd`.
- Extend the `verify_userspace_shim` / #5307 ABI-checked inventory.
- **Commit-time cardinality preflight:** reject a config whose intent-entry count
  (after per-proto expansion) exceeds `max_entries`, with an actionable error.

### 5d. Publisher (P) — helper-owned, atomic, fail-closed, loud

The helper reconciles intent inside config apply, from `destination_nat_rules` +
`static_nat_rules`, emitting keys **only for rows that actually translate** — skip
`destination-nat off`, disabled, exemption, and unparseable rows
(`destination.rs:113`). Forms:
- port-scoped DNAT → exact `(proto, public_ip, port)`.
- port-less / range DNAT, single-address static NAT → port-0 wildcard
  `(proto, public_ip, 0)` (over-steer; helper re-checks).
- static NAT with **no protocol field** → per-proto expansion (TCP+UDP+ICMP) — noting
  this is an over-approximation of "all protocols" (§5d-diagnostic covers the residual).

**Atomic transaction across families:** build the full desired v4+v6 key set; insert
ALL; if any insert fails (incl. capacity), **roll back every inserted key and abort the
apply** (config not activated — fail-closed). Only then swap generation; then delete
stale keys (retry + metric on failure). Hook **every** activation path, not just
`snapshot_refresh.rs`: `server/lifecycle.rs:310`, `handlers/snapshot.rs:230`,
`coordinator/reconcile/mod.rs:167`. On bringup, rebuild the full desired set from the
authoritative snapshot before enabling (default `snapshot: None` → intent empty →
fail-safe per §5b).

**§5d-diagnostic (Codex r2 #4 — mandatory):** every translation form that the intent
map does **not** dataplane-enforce on the first packet MUST raise an operator-visible
**commit-time warning** naming the rule, so a residual limitation is never silently
"marked fixed." Covered forms: static-NAT `protocol any` beyond the TCP/UDP/ICMP
expansion; DNAT/static **address-prefix/LPM** rules (an exact-hash map can't hold a
prefix); the v6 (or wildcard) form if the verifier ladder ships a reduced scope (§2);
DNAT/static onto the firewall's own ESP/IKE/WG/non-native-GRE control port (§8.6). The
warning is generated by the config compiler (Go), which already walks these rules.

## 6. Multiple path options

| Option | Mechanism | Port-aware | Verifier | Verdict |
|---|---|---|---|---|
| **B (recommended)** | Dedicated `dnat_intent_v4/v6`, helper-reconciled; shim exact probe before local | Yes | +1 HASH/family exact; +wildcard as separate candidate | **Primary** — disjoint lifecycle, no collision, zone-agnostic key, safe rollout |
| A | Reuse `dnat_table` flags=1 | Yes | no new map | **Rejected**: flags in *value*, `.is_some()` steering, dynamic `BPF_ANY` publish + delete-by-key can overwrite/erase colliding intent (`checksum.rs:246-346`) |
| A′ | Reuse `dnat_table` with reserved `pad2`/`from_zone` sentinel | Yes | +distinct probe | Fallback-if-no-new-map: no collision, but shares session capacity + distinct lookup shape. Weaker than B |
| C | Go address-exclusion from `USERSPACE_LOCAL` | **No** | none | **Rejected**: not port-aware; whole address leaves the direct cpumap path |
| D | Commit reject/warn | n/a | none | **Rejected as primary**; valid only as interim guard / the §5d loud-diagnostic |

## 7. Public API / behavior preservation

- `is_local_destination`, `is_icmp_to_interface_nat_local`, `is_interface_nat_destination`,
  `dnat_lookup_v4/v6` unchanged; only check *order* changes + new `intent_matches`.
- `dnat_table`/`dnat_table_v6` MapSpec unchanged (not reused). New `dnat_intent_v4/v6`
  are **additive** ABI (safe rollout, §5c).
- Helper reverse lifecycle, interface-SNAT, GRE classify, ESP/WG/NDP short-circuits —
  unchanged.

## 8. Hidden invariants

1. Unmatched ports stay kernel-local (absent intent → unchanged local path).
2. Native-endian singular key contract (`from_ne_bytes`, host-order port, zeroed pads);
   cross-side key-bytes test.
3. Intent lifecycle disjoint from reverse-NAT (dedicated map).
4. Fail-closed atomic v4+v6 transaction (rollback on any insert failure, before swap).
5. Rule removal removes intent (non-LRU; stale-delete retry + metric).
6. **Control-protocol precedence.** The shim short-circuits **ESP, non-native GRE, and
   local WireGuard** *before* the ordinary lookup (lib.rs:539-548) — it does **not**
   early-return AH/IKE. AH/IKE (and ESP) are claimed by the **helper's** IPsec stage
   before its DNAT stage (`poll_descriptor/mod.rs:823` vs :1511). Either way,
   DNAT/static onto the firewall's own ESP/IKE/WG/GRE control port terminates locally by
   design and is **out of scope** with a §5d commit warning — documented, not silent.
   `should_fallback_early` (multicast/link-local, lib.rs:565) also passes to local before
   the lookup; DNAT on a multicast/link-local interface address is nonsensical → out of
   scope.
7. Session-hit/GRE consistency unchanged (helper creates the normal session).

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| eBPF verifier / 1M cap (**crux**) | **HIGH** | +HASH probes; tail-call forbidden, no headroom metric. Ladder §2: v4-exact-only / reclaim / PLAN-KILL. |
| Publication/reconcile correctness | MED | atomic v4+v6 rollback, all activation paths, restart rebuild, cardinality preflight. |
| Availability (over-steer → slow-path drop) | MED | over-steered first-packets ride the helper slow path, which **drops** when unavailable (`slow_path.rs:283`). Bounded to first-packets of configured DNAT ports; use exact (not address-wildcard) intent where config allows. |
| Behavioral regression (local delivery) | LOW–MED | reorder; unmatched ports + ICMP echo-reply preserved; startup fail-safe = status quo. |
| Byte-order/key drift | LOW | fixed + cross-side test. |
| Static-NAT representability | MED | per-proto/port-0 subset + §5d loud diagnostics for proto-any/prefix. |
| ABI bump (new maps) | LOW–MED | additive, safe rollout verified. |
| Rollout / smoke | MED (deferred) | end-to-end capture shim-wall-blocked; verifier + cargo tests are not. |

## 10. Test plan

- **Verifier (make-or-break):** `make generate`/`shimverify` PASS, Phase-1 exact-only
  first, Phase-2 wildcard separate. The **identical artifact** must PASS on both the
  **6.18 floor** and the current-image kernel; deploy pre-flight per target.
- **Helper cargo:** atomic reconcile (v4-ok/v6-fail → full rollback + apply aborted);
  only-translating-rows emit intent; restart rebuild; disjointness from `dnat_table`
  dynamic; `close_delta_deletes_dnat_table_entry_for_snat_flow` still green.
- **Go:** cross-side key-bytes assertion (publisher == shim probe); cardinality preflight
  rejects an over-cap config; §5d commit warning fires for each residual form;
  `buildLocalAddressEntries`/exclusion unchanged.
- **RED acceptance (issue):** IPv4/IPv6 TCP/UDP DNAT on the ingress interface address →
  first packet to XSK + fwd/rev translate; port-wildcard/static-1:1 (both families, v6
  wildcard limitation noted); ICMP/ICMPv6 translated (port-0 exact) vs. ordinary ping
  stays local; unmatched SSH/BGP/IKE port stays kernel-local; zone policy on translated
  transit; generation-safe add/remove.
- **Availability:** measure `slow_path_drops` delta under source-scoped over-steer with a
  loaded/rate-limited slow path — assert the drop exposure is **bounded and counted**
  (NOT zero-drop under exhaustion, which is impossible), and that steady-state matched
  flows are unaffected.
- **Smoke (DEFERRED — shim-wall):** end-to-end first-packet fwd+rev capture v4+v6 on
  `loss:` once the shim-ABI wall clears.

## 11. Out of scope (explicitly, each paired with a §5d commit warning)

- DNAT/static onto the firewall's own ESP/AH/IKE/WG/non-native-GRE control port.
- Static-NAT `protocol any` beyond TCP/UDP/ICMP expansion (shim key proto is `u8`; helper
  `PROTO_ANY=256`).
- DNAT/static **address-prefix/LPM** rules (exact-hash map can't hold a prefix;
  per-address expansion unbounded).
- IPv6 port-wildcard static-1:1 if the verifier can't afford the v6 wildcard probe.
- Multicast/link-local interface-address DNAT (`should_fallback_early`).
- Helper translation math, interface-mode SNAT — unchanged.

## 12. Open questions for round-3 review (each invitable to PLAN-KILL)

1. **Verifier:** Phase-1 exact-only affordable (GRE branch already carries exact v4+v6
   in the same program; tail-call forbidden)? If REJECT, is v4-exact-only + LOUD v6
   diagnostic an acceptable ship, or PLAN-KILL?
2. **Loud diagnostics:** does pairing every un-enforced form with a commit-time warning
   (§5d) adequately discharge "no silently-undocumented-as-fixed bypass surface," or must
   more forms be dataplane-enforced?
3. **Atomic reconcile:** insert-all-rollback-on-fail + all activation paths + startup
   fail-safe (§5b) — sufficient, or is a double-buffer needed for a mid-apply crash?
4. **Over-steer availability:** is the bounded slow-path-drop exposure for first-packets
   of configured DNAT ports acceptable, given it's counted and steady-state is unaffected?
5. **Static-NAT scope:** per-proto + port-0 subset + loud diagnostics — acceptable, or
   must proto-any/prefix be enforced?
6. **Is PLAN-KILL warranted**, or is phased Option B the right call?
