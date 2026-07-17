# Plan of action — #5837: userspace XDP local-interface destination check bypasses DNAT/static-NAT

**Status:** DRAFT v2 — revised after Codex + Claude SMR round-1 (both REVISE). Pending round-2 review.
**Issue:** #5837 (bug, High, security, nat, audit)
**Research branch:** `research/5837-xdp-dnat-before-local`
**Base:** origin/master `7d2cd112fec4`
**Mode:** `/research` — stops at PLAN-READY / PLAN-KILL. No PR, no production code touched here.

**v2 changelog:** recommended path switched from *reuse `dnat_table`* (Option A) to a
**dedicated zone-agnostic translation-intent map** (Option B) after Codex proved a
shared-key collision hazard in `dnat_table`. Verifier section reframed: tail-call is
**forbidden** by the retirement canary and `shimverify` gives no headroom metric, so the
escape hatches are exact-only / v4-only scope reduction / instruction reclaim / PLAN-KILL.
Added: complete key/byte-order contract, static-NAT representability limits, WG/ESP/IKE
precedence, error-propagating generation transaction. Confirmed the helper needs no
translation change (§4a).

---

## 1. Issue framing

On a non-GRE **session miss**, the AF_XDP ingress shim (`userspace-xdp/src/lib.rs`,
`try_xdp_userspace`) classifies a packet as **kernel-local** and returns it to the
kernel (`cpumap_or_pass`) *before* consulting any configured destination-NAT or
static-NAT. `is_local_destination` (lib.rs:1363) only exempts **interface-mode
source-NAT** addresses; it has no DNAT/static-NAT awareness. So a port-forward /
static one-to-one NAT that maps the **WAN interface's own address** (a common,
legitimate Junos config) never reaches the Rust dataplane on the first packet —
Linux accepts/rejects it as local traffic instead of translating + applying transit
zone policy, and if a local service binds that port the traffic is delivered to it.
**High-severity security bypass.**

Required invariant (from the issue): *for a session miss, a configured destination
translation matching destination address + protocol/port must take precedence over
generic kernel-local delivery; unmatched traffic to the same interface address must
still reach legitimate local control-plane services.*

## 2. Honest scope/value framing

Correctness/security fix, not performance. The win: a DNAT/static-NAT whose public
address is an interface address becomes **enforced on the first packet** instead of
silently bypassed. Blast radius of the *bug*: any deployment that port-forwards to
(or static-NATs) an interface address — mainstream firewall config.

The change lives in the **`make generate`-gated AF_XDP shim** (pinned toolchain +
real-kernel verifier, #1864). The make-or-break is **verifier feasibility**, and the
escape hatches are narrower than v1 assumed: **tail-call is forbidden** by the
retirement canary (`retirement_boundary_canary_test.go:340-350` bans `ProgramArray`
/`.tail_call`/`bpf_tail_call`, single XDP prog allowlisted), and `shimverify` returns
only binary PASS/REJECT (`cmd/shimverify/main.go` — no processed-insn metric). So the
verdict is genuinely uncertain until `make generate` runs, and the fallback is scope
reduction, not restructure.

*If the verifier rejects even the minimal (v4 exact-only) form and no acceptable
instruction-reclaim exists, PLAN-KILL — or ship v4-exact-only + a documented v6/wildcard
limitation — is an acceptable verdict.* A commit-time hard-reject is **not** a
substitute: port-forward to an interface address is legitimate Junos config
(parity), and a warning alone doesn't fix the bypass.

## 3. Central finding (verified by both reviewers)

The issue's "just add a `DNAT_TABLE` lookup — the helpers already exist" is
**necessary but not sufficient**: in the userspace-dp runtime the shim-visible
`dnat_table`/`dnat_table_v6` maps hold **only dynamic (flags=0) reverse-NAT**
records, not configured forward DNAT.

- `pkg/dataplane/loader.go:407-441` — the userspace path's `SetDNATEntry` /
  `SetDNATEntryV6` / static-NAT setters / stale-static delete hooks are **no-ops**
  (`return nil`). Configured DNAT/static-NAT is matched entirely inside the helper's
  in-memory `DnatTable`/`StaticNatTable` (`forwarding_build/mod.rs:309`, consulted at
  `poll_descriptor/mod.rs:1511/1577`).
- `userspace-dp/README.md:159-177` — the helper publishes dynamic flags=0 reverse
  records via `publish_dnat_table_entry`; "STATIC DNAT-config entries (flags=1) are
  never published or deleted by this path."
- Qualification (Codex): the pinned maps are non-LRU and the static cleanup hooks are
  no-ops, so *stale historical* flags=1 bytes are not structurally impossible across
  restarts — one more reason not to overload `dnat_table` (see §6).

**Therefore the fix requires a publication step that makes configured translation
intent visible to the shim, plus a shim lookup before local classification.**

## 4. What's already shipped / must compose with

- **Interface-SNAT exclusion** (`buildNATTranslatedLocalAddressExclusions`,
  maps_sync.go:1670) removes interface-mode SNAT addresses from `USERSPACE_LOCAL` and
  publishes them to `USERSPACE_INTERFACE_NAT` — address-only, the *wrong* model for
  DNAT (not port-aware). Must remain untouched.
- **`dnat_table` reverse-NAT lifecycle** (#2979): helper publishes flags=0 via
  `BPF_ANY` (`checksum.rs:304-346`) and deletes by key (`checksum.rs:246-289`) with
  **no flags/value check** — the collision hazard that rules out map reuse (§6).
- **Verifier gate** (#1864): `cmd/shimverify` real `BPF_PROG_LOAD` (CAP_BPF/root +
  pinned toolchain) runs at `make generate` and at deploy pre-flight
  (`xpfd verify-dataplane`). **Checkable locally at implement time — not
  shim-wall-blocked.** Only end-to-end cluster smoke is shim-wall-blocked.
- **Retirement canary** forbids tail-call and >1 XDP program (§2).
- **v6 wildcard precedent**: `dnat_lookup_v6` is exact-only because a 2nd HASH lookup
  blew the 1M cap in the v6 GRE classify (lib.rs:882-891). Any v6 wildcard inherits
  this; the issue's acceptance criteria already anticipate "the existing IPv6
  wildcard limitation."

### 4a. The helper already applies DNAT before local resolution (fix is *sufficient*)

Traced firsthand (`poll_descriptor/mod.rs`): on session miss the helper computes
`pre_routing_dnat` (DNAT + static-DNAT match, :1577-1601), rewrites the destination
to the internal host in `effective_resolution_target` (:1673-1685), and
`resolve_forwarding` (:3633) runs on **that translated target** — so LocalDelivery is
decided on the internal dst, not the interface address. Policy is evaluated on the
post-translation tuple (#2345, :1685+). **Conclusion:** once the shim steers the first
packet to XSK, the helper already does DNAT-before-local-resolution. The fix is
purely (P) publish intent + (S) shim classify; **no helper translation change.**

## 5. Concrete design (recommended: Option B — dedicated intent map)

Two pieces: **(P)** publish a config-driven, zone-agnostic translation-intent set the
shim can see; **(S)** shim probes it before local classification.

### P — dedicated `dnat_intent_v4` / `dnat_intent_v6` maps (helper-owned)

New `BPF_MAP_TYPE_HASH`, `BPF_F_NO_PREALLOC`, max_entries sized to config rule count
(small, bounded), **disjoint from the reverse-NAT `dnat_table` lifecycle** so dynamic
publish/delete can never touch intent. Key is a deliberately **minimal steer-superset**
— no `from_zone`, no source scope:

```
IntentKeyV4 { protocol: u8, dst_ip: u32 (native bytes), dst_port: u16 (host-order, 0 = wildcard) }
IntentKeyV6 { protocol: u8, dst_ip: [u8;16], dst_port: u16 (host-order, 0 = wildcard) }
Value: 1 byte, unused by the shim (steering is presence-only).
```

- **Owner = helper.** The helper holds the normalized rule tables
  (`nat/destination.rs`, `nat/static_nat.rs`) and reconciles intent inside the
  config-apply generation swap (`coordinator/snapshot_refresh.rs`). Go publication is
  rejected: Go compilation runs *before* the snapshot build/apply
  (`manager_compile.go`), so un-stubbing Go setters could mutate map state ahead of a
  *failed* apply. (Codex: "single writer" is aspirational either way — Go HA/session
  sync already writes dynamic `dnat_table` companions — but the *intent* map is a fresh,
  helper-only namespace.)
- **Populate from** `destination_nat_rules` + `static_nat_rules`, emitting:
  - exact `(proto, public_ip, port)` for port-scoped DNAT;
  - port-0 wildcard `(proto, public_ip, 0)` for port-less/range DNAT and single-address
    static NAT (helper re-checks the range/exact predicate on the XSK path).
- **Error-propagating generation transaction** (Codex #5): insert every new intent key
  FIRST; abort the apply on any insert failure (fail-closed, config not activated);
  swap generation; THEN delete stale keys with retry + metric on failure. A
  missing-new-intent-after-activation would be a translation-bypass window — forbidden;
  a stale-old-intent is over-steering only (helper re-checks). On bringup, clear stale
  intent before first classify (restart reconciliation).

### S — shim: probe intent before local delivery

In `try_xdp_userspace`, non-GRE session-miss arm (lib.rs:632), **before**
`is_icmp_to_interface_nat_local` / `is_local_destination`:

```rust
// Native-endian dst key MUST be rebuilt from raw bytes — parsed.dst_v4 is
// BigEndian (matches the BigEndian-published USERSPACE_LOCAL_V4), while the
// intent map is NativeEndian (matches ipToUint32BE / the GRE-path dnat key).
let dst_ne = u32::from_ne_bytes([parsed.dst_addr[0], parsed.dst_addr[1],
                                 parsed.dst_addr[2], parsed.dst_addr[3]]);
if intent_matches(&parsed, dst_ne) {
    // fall through to XSK redirect — do NOT pass to kernel
} else {
    if is_icmp_to_interface_nat_local(&parsed) { return cpumap_or_pass; }
    if is_local_destination(&parsed) { return cpumap_or_pass; }
}
```

`intent_matches` = one exact HASH probe per family (Phase 1). ICMP uses the identifier
(stored in `src_port`) as the port field, matching the publisher and the GRE path
convention (lib.rs:830-835) — and ICMP intent is emitted ONLY where an ICMP-bearing
translation is configured, so `is_icmp_to_interface_nat_local` echo-reply handling for
firewall-originated pings to non-translated addresses is preserved (SMR B2).

### Phasing (verifier budget — the crux)

- **Phase 1 (primary fix):** exact-match intent, both families, one HASH probe each.
  Covers TCP/UDP port-forward to an interface address — the headline bug.
- **Phase 2 (wildcard / static-1:1 / port-less):** add the port-0 wildcard probe.
  Because `shimverify` gives no headroom metric, Phase 2 is a **separately built +
  verified candidate**, not "measured in Phase 1." Precedent says v4 likely affords
  exact+wildcard, **v6 wildcard likely does not** (→ documented v6 limitation).
- **Fallback ladder if Phase-1 exact-only REJECTs** (tail-call forbidden, so):
  (a) scope to **v4-exact-only**, v6 documented-limitation; (b) reclaim instructions by
  folding the existing `is_local`/`interface_nat` probes; (c) if neither, **PLAN-KILL**
  (or interim commit-warning). This residual is why the verdict is verifier-gated.

## 6. Multiple path options

| Option | Mechanism | Port-aware | Verifier | Verdict |
|---|---|---|---|---|
| **B (recommended)** | Dedicated `dnat_intent_v4/v6` maps, helper-reconciled; shim exact probe before local | Yes | +1 HASH/family exact; +wildcard as separate candidate | **Primary** — disjoint lifecycle, no collision, clean zone-agnostic key |
| A | Reuse existing `dnat_table` with flags=1 forward intent | Yes | Same lookup cost, no new map | **Rejected**: `flags` is in the *value*, shim steers on `.is_some()`, dynamic `BPF_ANY` publish + delete-by-key (no flags check) can **overwrite/erase** a colliding intent entry → reopens bypass (`checksum.rs:246-346`); can't distinguish intent from reverse entries |
| A′ | Reuse `dnat_table`, but namespace intent via a reserved `from_zone`/`pad2` sentinel (e.g. `0xffff`) | Yes | +distinct-shape probe | **Alternative-if-no-new-map**: sentinel keeps intent keys disjoint from dynamic (from_zone=0) so no collision, but still **shares capacity** with sessions and adds a distinct lookup shape. Weaker than B |
| C | Go address-exclusion: strip DNAT public addr from `USERSPACE_LOCAL` | **No** | Zero shim change | **Rejected**: not port-aware; every port on the address becomes dependent on helper/slow-path availability (helper *can* LocalDelivery+reinject, but the whole address stops taking the direct cpumap path) — violates "unmatched port still takes kernel-local path" |
| D | Commit-time reject/warn | n/a | none | **Rejected as primary**: reject breaks legitimate Junos config; warn doesn't fix bypass. Valid only as interim guard |

## 7. Public API / behavior preservation

- `is_local_destination`, `is_icmp_to_interface_nat_local`,
  `is_interface_nat_destination`, `dnat_lookup_v4/v6` signatures unchanged; only the
  *order* of checks changes (intent first) + one new `intent_matches` helper.
- Existing `dnat_table`/`dnat_table_v6` MapSpec unchanged (**not reused for intent** →
  no reshaping of a pinned map). New `dnat_intent_v4/v6` are **additive** to the shim
  ABI inventory (`userspaceABICheckedPinnedMaps`) + Go `userspaceShimSharedMapSpecs` —
  a coordinated one-time bump, not a reshape (Codex: adding a name ≠ reshaping).
- Helper reverse-NAT lifecycle, interface-SNAT, GRE classify, ESP/WG/NDP
  short-circuits — unchanged.

## 8. Hidden invariants

1. **Unmatched ports stay kernel-local** — only configured tuples steer; else the
   unchanged local path runs.
2. **Byte-order/key contract is singular and native-endian** — intent map + shim probe
   both use `from_ne_bytes(raw dst)` + host-order port. Assert with a cross-side key
   test (Go builder == shim key bytes).
3. **Intent lifecycle disjoint from reverse-NAT** — dedicated map guarantees dynamic
   publish/delete can never touch intent (the A-rejection reason).
4. **Fail-closed generation transaction** — new intent inserted+verified before the
   generation swap; a failed insert aborts the apply.
5. **Rule removal removes intent** — else a stale key steals local delivery forever
   (non-LRU). Stale-delete has retry + metric.
6. **Control-protocol precedence** — ESP/AH/IKE/non-native-GRE/local-WG short-circuit
   *before* the ordinary lookup (lib.rs:539-548), and the helper also claims ESP/AH/IKE
   before its DNAT stage (poll_descriptor:823 vs 1511). The shim intent check sits in
   the ordinary session-miss branch, AFTER those short-circuits — consistent with the
   helper. DNAT/static-NAT onto the firewall's OWN interface address at an
   ESP/IKE/WG/GRE control port is **out of scope** (those terminate locally by design;
   §11). Documented, not a silent gap.
7. **Session-hit / GRE consistency** — packet 2 is found by
   `live_userspace_session_action` (helper created the normal session); GRE classify
   unchanged.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| eBPF verifier / 1M cap (**crux**) | **HIGH** | +HASH probes; tail-call forbidden, no headroom metric. Settled only at `make generate`. Fallback = v4-exact-only scope reduction / instruction reclaim / PLAN-KILL. |
| Publication/reconcile correctness | MED | New helper intent reconcile + fail-closed transaction + restart reconciliation. |
| Behavioral regression (local delivery) | LOW–MED | Reorder of checks; unmatched ports unchanged; ICMP echo-reply preserved. |
| Byte-order/key drift | LOW (was a v1 bug) | Fixed: native-endian rebuild; cross-side key test. |
| Static-NAT representability | MED | proto-any / ranges / prefixes need scoping (§11). |
| ABI bump (new maps) | MED | Additive, coordinated; shim-wall gates cluster smoke only. |
| Rollout / smoke | MED (deferred) | End-to-end capture shim-wall-blocked; verifier + cargo tests are not. |

## 10. Test plan

- **Verifier gate (make-or-break):** `make generate` → `shimverify` PASS on the pinned
  toolchain (root/CAP_BPF), Phase-1 exact-only first; Phase-2 wildcard = separate
  verified candidate. Also run against the **6.18 floor** kernel and the current image
  kernel (Codex: `shimverify` tests only the running kernel), plus deploy pre-flight
  per target. Local, not shim-wall-blocked.
- **Helper cargo tests:** intent reconcile add/remove; fail-closed insert-before-swap;
  disjointness from `dnat_table` dynamic entries; restart clears stale intent;
  `close_delta_deletes_dnat_table_entry_for_snat_flow` still green.
- **Go tests:** cross-side key-shape assertion (Go/publisher key bytes == shim probe
  key); `buildLocalAddressEntries`/exclusion unchanged.
- **RED acceptance tests (issue):** IPv4 & IPv6 TCP/UDP DNAT on the ingress interface
  address → first packet to XSK + forward/reverse translate; port-wildcard/static-1:1
  (both families, v6-wildcard limitation noted); ICMP/ICMPv6 translated vs. ordinary
  ping stays local; unmatched SSH/BGP/IKE port stays kernel-local; zone policy on the
  translated transit flow; generation-safe add/remove; **availability**: source-scoped
  over-steer + unmatched traffic still delivered when the helper slow-path is
  loaded/rate-limited (Codex #7).
- **Smoke (DEFERRED — shim-wall):** end-to-end first-packet forward+reverse capture
  v4+v6 on `loss:` once the shim-ABI wall clears. Documented deferral.

## 11. Out of scope (explicitly)

- **DNAT/static-NAT onto the firewall's own interface address at an ESP/AH/IKE/WG/
  non-native-GRE control port** — those protocols terminate locally before the ordinary
  lookup on both shim and helper (§8.6); port-forwarding the firewall's own tunnel
  control port is pathological.
- **Static-NAT with `protocol any` (helper `PROTO_ANY=256`)** beyond per-proto
  expansion — the shim key protocol is `u8`; intent is emitted per concrete proto
  (TCP/UDP/ICMP) or as a port-0 wildcard, not a single 256 sentinel.
- **Static-NAT of an address *block/prefix* onto interface addresses** — an exact-hash
  intent map can't hold a prefix and per-address expansion is unbounded; documented
  limitation.
- **IPv6 port-wildcard static-1:1 on an interface address** if the verifier can't afford
  the v6 wildcard probe (mirrors existing v6 GRE limit).
- Helper translation math, interface-mode SNAT handling — unchanged.
- Optional commit-time warning for static-NAT/port-wildcard on a management-carrying
  interface address — defensive follow-up, not required.

## 12. Open questions for round-2 review (each invitable to PLAN-KILL)

1. **Verifier headroom:** is Phase-1 exact-only (1 HASH/family) affordable given the
   GRE branch already carries an exact v4+v6 dnat lookup in the same program, and
   tail-call is forbidden? If REJECT, is v4-exact-only + v6-documented-limitation an
   acceptable ship, or PLAN-KILL?
2. **Dedicated map (B) vs sentinel-namespace (A′):** is the new-map ABI bump worth the
   clean disjoint lifecycle, or is the `from_zone`/`pad2` sentinel in `dnat_table`
   (no new map, shared capacity) the better tradeoff?
3. **Helper-owned reconcile fail-closed:** insert-before-swap + abort-apply-on-insert-
   failure — sufficient, or is a shadow/double-buffer needed to avoid a partial-intent
   window under a mid-apply crash?
4. **Static-NAT scope:** is emitting per-proto + port-0-wildcard intent (dropping
   proto-any and block-prefix) an acceptable representable subset, or must static-NAT
   parity be fuller?
5. **Control-protocol precedence:** is scoping out DNAT-on-own-ESP/IKE/WG/GRE-port
   correct, or is there a real config that needs it?
6. **Availability:** is moving source-scoped-nonmatch + unmatched traffic onto the
   helper slow-path (from direct cpumap) an acceptable robustness change?
7. **Is PLAN-KILL warranted** given the verifier risk + representability limits, or is
   the phased Option-B fix the right call?
