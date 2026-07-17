# Plan of action — #5837: userspace XDP local-interface destination check bypasses DNAT/static-NAT

**Status:** DRAFT v4 — revised after Codex r3 (REVISE, transaction-correctness) + Claude SMR r2/r3 (PLAN-READY). Pending round-4 review.
**Issue:** #5837 (bug, High, security, nat, audit)
**Research branch:** `research/5837-xdp-dnat-before-local`
**Base:** origin/master `7d2cd112fec4`
**Mode:** `/research` — stops at PLAN-READY / PLAN-KILL. No PR, no production code touched here.

**v4 changelog (addresses Codex r3 — architecture + verifier already accepted):**
rollback-safe **new-only** reconcile transaction (never delete active-generation keys) +
`|current ∪ desired|` per-family capacity preflight; intent maps **mandatory/fail-closed**
(not `open_optional_map`) when the shim capability is active, + Go/Rust snapshot pin-ABI +
fresh-node ABI arm; **restart reconcile** (pinned maps persist — the old "empty on start"
fail-safe was wrong); **IPv6-AH regression fix** (shim walks through AH → intent must
decline AH-carrying IPv6 so the `is_local_destination` XFRM shunt is preserved); complete
§5d loud-diagnostic set (adds IP-only any-proto DNAT, IPv6 AH, native-GRE outer DNAT,
multicast/link-local, IPv4 limited-broadcast); precise activation ordering (publish before
worker teardown + swap); availability test given finite workload + numeric bound + correct
all-ports/repeated-packet scope; port-scoped static NAT uses **exact** intent (not port-0
wildcard); disambiguated verifier ladder (Phase-2 reject retains Phase-1 exact-both).

**Earlier:** v2 switched from reuse-`dnat_table` (collision) to a dedicated zone-agnostic
intent map; v3 added concrete key ABI, wiring, and mandatory operator diagnostics.

---

## 1. Issue framing

On a non-GRE **session miss**, the shim (`userspace-xdp/src/lib.rs`, `try_xdp_userspace`)
returns a packet to the kernel as kernel-local *before* consulting configured DNAT/
static-NAT. `is_local_destination` (lib.rs:1363) only exempts interface-mode SNAT. So a
port-forward / static one-to-one NAT mapping the **WAN interface's own address** (common,
legitimate Junos config) is inert on the first packet — delivered to the host instead of
translated + zone-policed. **High-severity security bypass.**

Invariant: *a configured destination translation matching destination address +
protocol/port must take precedence over kernel-local delivery; unmatched traffic to the
same interface address must still reach legitimate local services.*

## 2. Honest scope + verifier go/no-go ladder

Correctness/security fix in the **`make generate`-gated shim**. The make-or-break is
**verifier feasibility** (1M-insn cap, #1864); escape hatches are narrow — **tail-call is
forbidden** by the retirement canary (retirement_boundary_canary_test.go:345-353;
allowlist :127-129) and `shimverify` returns only binary PASS/REJECT (no headroom metric).
Ladder, run at implement time (a single build artifact carries a **machine-readable
capability tag** — exact-both / v4-exact-only — that the Go §5d diagnostics read so
warnings match what shipped):

1. Build **Phase-1 exact-both families** → `shimverify`.
2. PASS → ship exact-both. **Phase-2 wildcard is a SEPARATE candidate**; if it REJECTs,
   **retain exact-both** (do NOT regress) — wildcard/static-1:1 forms get a §5d warning.
3. Phase-1 exact-both REJECT → build **v4-exact-only** → `shimverify`.
4. v4-exact PASS → ship v4-only **+ LOUD §5d warning** for the un-enforced v6 form.
5. v4-exact REJECT → **instruction reclaim** (fold the existing `is_local`/`interface_nat`
   probes into one keyed pass) → re-verify.
6. Still REJECT → **PLAN-KILL** (interim: commit reject/warn only).

The identical shipped artifact must PASS `shimverify` on **both** the 6.18 floor and the
current-image kernel; deploy pre-flight per target. A hard commit-reject as the *primary*
fix is rejected (parity); a warning alone doesn't fix the bypass.

## 3. Central finding (verified by both reviewers)

"Just add a `DNAT_TABLE` lookup" is **necessary but not sufficient**: the shim-visible
`dnat_table`/`dnat_table_v6` hold **only dynamic (flags=0) reverse-NAT** records, not
configured forward DNAT. `pkg/dataplane/loader.go:407-441` — userspace-path DNAT/static
setters are **no-ops**; configured DNAT is matched in the helper's in-memory
`DnatTable`/`StaticNatTable` (`poll_descriptor/mod.rs:1511/1577`). `userspace-dp/README.md:177`
— "STATIC DNAT-config entries (flags=1) are never published." **Fix = (P) publish intent
the shim can see + (S) a shim probe before local classification.**

## 4. Composes with

- Interface-SNAT exclusion (maps_sync.go:1670) — untouched.
- `dnat_table` reverse lifecycle (#2979): flags=0 `BPF_ANY` publish + delete-by-key, no
  flags check (`checksum.rs:246-346`) — the collision that rules out map reuse.
- Verifier gate (#1864) `shimverify` — local, not shim-wall-blocked; only smoke is.
- Retirement canary: no tail-call/>1 XDP prog; map allowlist `userspaceShimAllowedMapTypes`.
- v6 wildcard precedent: `dnat_lookup_v6` exact-only (2nd HASH lookup blew the cap in v6
  GRE classify, lib.rs:882-891).

### 4a. Helper already applies DNAT before local resolution (fix is *sufficient*)

`poll_descriptor/mod.rs`: session miss computes `pre_routing_dnat` (:1577), rewrites dst
to the internal host in `effective_resolution_target` (:1673), `resolve_forwarding`
(:3633) runs on that translated target; policy on the post-translation tuple (#2345). Once
the shim steers the first packet to XSK, the helper already does DNAT-before-local. **No
helper translation change.**

## 5. Concrete design (Option B — dedicated intent map)

### 5a. Shim probe (S)

In `try_xdp_userspace`, non-GRE session-miss arm (lib.rs:632), **before**
`is_icmp_to_interface_nat_local`/`is_local_destination`, and **guarded against AH** (§8.6):

```rust
let dst_ne = u32::from_ne_bytes([parsed.dst_addr[0], parsed.dst_addr[1],
                                 parsed.dst_addr[2], parsed.dst_addr[3]]); // NativeEndian, not parsed.dst_v4 (BE)
if !parsed.ah_present && intent_matches(&parsed, dst_ne) {
    // fall through to XSK redirect — do NOT pass to kernel
} else {
    if is_icmp_to_interface_nat_local(&parsed) { return cpumap_or_pass; }
    if is_local_destination(&parsed) { return cpumap_or_pass; }
}
```

`intent_matches` = one exact HASH probe/family (Phase 1), keyed on
`(protocol, dst_ne, parsed.flow_dst_port)`. **ICMP:** `parse_l4` sets `flow_dst_port = 0`
for ICMP/ICMPv6 (lib.rs:1516), so ICMP intent is published `dst_port = 0` and hits via an
**exact** match (protocol byte disambiguates from TCP/UDP port-0 keys); identifier-agnostic;
emitted only where an ICMP translation is configured, so echo-reply handling for
non-translated addresses is preserved.

### 5b. Intent semantics, AH guard, restart reconcile

Intent is a **steer-superset**: a port-0 (or address-wildcard) entry over-steers ALL ports
for that proto+ip to XSK, where the helper re-checks the exact rule (range/source/zone) and
**locally-delivers non-matching packets** (§4a) — no policy bypass, an *availability* shift
(§9/§10). **AH guard (Codex r3 #4):** the shim's IPv6 parser walks THROUGH AH (lib.rs:1269,
`NEXTHDR_AUTH`), so `parsed.protocol` becomes AH's inner next-header, and the helper's
IPv6-AH-to-self path *relies* on the `is_local_destination` XFRM shunt
(`forwarding/mod.rs:1288-1305`). So an `ah_present` parse signal MUST be added and the
intent check MUST decline AH-carrying packets, preserving the shunt. **Restart reconcile
(Codex r3 #3):** pinned maps **persist** across daemon restart (loader_userspace_shim.go:63)
— the intent map is NOT empty on restart. The prior "empty → status-quo" fail-safe holds
ONLY for a truly fresh node. On every bringup the helper MUST enumerate the pinned intent
maps and reconcile them **exactly** against the recompiled authoritative set BEFORE enabling
readiness/classification. (Fresh-node fail-safe still holds: absent intent → is_local path →
today's behavior, never a *new* bypass.)

### 5c. Map + key ABI, mandatory plumbing, capacity

New `dnat_intent_v4`/`dnat_intent_v6`, `BPF_MAP_TYPE_HASH`, `BPF_F_NO_PREALLOC`, **fixed**
`max_entries = 8192` (compile-time; a `MapSpec` capacity is fixed at load). Keys mirror
`DnatKeyV4` `repr(C)` discipline, all pads zeroed on publish AND probe:

```rust
#[repr(C)] struct IntentKeyV4 { protocol:u8, pad:[u8;3], dst_ip:u32(NE), dst_port:u16(host), pad2:u16 } // 12B
#[repr(C)] struct IntentKeyV6 { protocol:u8, pad:[u8;3], dst_ip:[u8;16], dst_port:u16(host), pad2:u16 } // 24B
// value u8 (presence-only).
```

Wiring (each an implement-time task):
- Shim declares both maps; add to `userspaceShimAllowedMapTypes` (canary :107) + PinByName
  inventory `userspacePinnedShimMaps` (:502).
- Go creates/pins + mirrors `MapSpec` in `userspaceShimSharedMapSpecs` (:604) so
  `validateSharedMapExpectedABI` guards fresh-node ABI and `validateUserspaceShimLivePins`
  guards live drift. **Rollout safe** (absent-pin skip, :410).
- **Mandatory, NOT optional (Codex r3 #2):** the helper opens the FDs via a
  *fail-closed* open (NOT `open_optional_map`, which returns `Ok(None)` on an empty pin,
  snapshot.rs:369) whenever the shim DNAT-intent capability is negotiated active — a
  translating config must never silently activate with absent intent FDs. Add the new pin
  paths to the Go (protocol.go) + Rust (snapshot.rs) snapshot ABI; add helper FD fields
  (`coordinator/bpf_maps.rs`, filled in `reconcile/bringup.rs`); extend the #5307 ABI-checked
  inventory.
- **Cardinality preflight** at commit: reject a config whose **`|current ∪ desired|`
  per-family** encoded-key count (after per-proto expansion) would exceed 8192 — feasibility
  depends on the union during the insert-before-delete window, not `|desired|` alone
  (Codex r3 #1).

### 5d. Publisher (P) — helper-owned, new-only, rollback-safe, loud

Reconcile intent inside config apply, from `destination_nat_rules` + `static_nat_rules`,
emitting keys **only for rows that actually translate** (skip `destination-nat off`,
disabled, exemption, unparseable — destination.rs:113). Forms:
- port-scoped DNAT → exact `(proto, public_ip, port)`.
- **port-scoped static NAT → exact** `(proto, public_ip, port)` (representable via
  `(external_ip, Some(port))`, static_nat.rs:159) — NOT port-0 (Codex r3 #6: reduces
  over-steer + verifier exposure).
- port-less/range DNAT, port-less single-address static NAT → port-0 wildcard `(proto,
  public_ip, 0)` (over-steer; helper re-checks).
- static NAT with **no protocol field** → per-proto expansion (TCP+UDP+ICMP); the residual
  (any non-{TCP,UDP,ICMP} protocol) is **loud-diagnosed**, not silently dropped.

**Rollback-safe transaction (Codex r3 #1, the key fix):**
1. Compute `desired` (v4+v6). `new_only = desired − current`; `stale = current − desired`.
2. Preflight `|current ∪ desired|` per family ≤ 8192.
3. Insert **only `new_only`** with `BPF_NOEXIST` (never overwrite an active key).
4. On ANY insert failure → delete **only the `new_only` keys inserted this apply** and
   **abort the apply** (fail-closed; unchanged active keys untouched).
5. Publication MUST complete **before** the full-reconcile worker teardown
   (`coordinator/reconcile/mod.rs:297`) and before the snapshot-refresh generation swap —
   using the real commit primitives (activation paths: `handlers/snapshot.rs:230`,
   `coordinator/reconcile` @ :193, `snapshot_refresh.rs`; `lifecycle.rs:310` is *init*).
6. After the swap, delete `stale` with retry + metric on failure.
7. Crash windows: before-swap crash may leave surplus `new_only` keys; after-swap-before-
   delete crash may leave `stale` keys — both are reconciled exactly by the mandatory
   **restart reconcile** (§5b) before readiness.

**§5d loud-diagnostic set (mandatory, complete — Codex r3 #5).** Every form NOT
dataplane-enforced on the first packet raises an operator-visible **commit-time warning**
naming the rule. Complete set (= §11): static-NAT `protocol any` / IP-only any-protocol
DNAT (`PROTO_ANY=256`, destination.rs:399 — the `u8` key can't hold it beyond the TCP/UDP/
ICMP expansion); DNAT/static **address-prefix/LPM** rules; the reduced-scope v6/wildcard
form if the ladder ships it (§2); DNAT/static onto the firewall's own **ESP/AH/IKE/WG/
non-native-GRE** control port; **native-GRE outer** DNAT (rides the sibling GRE branch,
lib.rs:646, not this lookup); **multicast/link-local/IPv4-limited-broadcast** interface-
address DNAT (`should_fallback_early`, lib.rs:1340); **IPv6-AH-to-self** address DNAT
(declined by the §8.6 guard).

## 6. Options

| Option | Mechanism | Port-aware | Verdict |
|---|---|---|---|
| **B (recommended)** | Dedicated `dnat_intent_v4/v6`, helper new-only reconcile; shim exact probe before local | Yes | **Primary** — disjoint lifecycle, no collision, safe rollout |
| A | Reuse `dnat_table` flags=1 | Yes | **Rejected** — flags in *value*, dynamic `BPF_ANY` publish + delete-by-key overwrite/erase colliding intent (`checksum.rs:246-346`) |
| A′ | Reuse `dnat_table` + reserved-sentinel key | Yes | Fallback-if-no-new-map; shares session capacity |
| C | Go address-exclusion | **No** | **Rejected** — not port-aware |
| D | Commit reject/warn | n/a | **Rejected as primary**; = the §5d loud diagnostic |

## 7. Public API / behavior preservation

- `is_local_destination`, `is_icmp_to_interface_nat_local`, `is_interface_nat_destination`,
  `dnat_lookup_v4/v6` unchanged; new `intent_matches` + `ah_present` parse field + check
  reorder.
- `dnat_table`/`dnat_table_v6` MapSpec unchanged. New `dnat_intent_v4/v6` additive (safe
  rollout).
- Helper reverse lifecycle, interface-SNAT, GRE classify, ESP/WG/NDP short-circuits —
  unchanged.

## 8. Hidden invariants

1. Unmatched ports stay kernel-local (absent intent → unchanged path).
2. Native-endian singular key contract (`from_ne_bytes`, host-order port, zeroed pads);
   cross-side key-bytes test.
3. Intent lifecycle disjoint from reverse-NAT (dedicated map).
4. New-only, fail-closed transaction: never overwrite/rollback-delete an active key;
   union-capacity preflight; publish before teardown/swap; restart reconcile.
5. Rule removal removes intent (non-LRU; stale-delete retry + metric + restart reconcile).
6. **Control-protocol precedence.** Shim short-circuits **ESP / non-native GRE / local WG**
   before the ordinary lookup (lib.rs:539-548) — NOT AH/IKE. AH/IKE/ESP are claimed by the
   helper's IPsec stage before its DNAT (poll_descriptor:823 vs :1511). **IPv6 AH is
   special**: the shim walks through AH so the helper's `PROTO_AH` arm never fires for IPv6
   AH, which relies on the `is_local_destination` shunt (forwarding/mod.rs:1288-1305) — the
   §8.6 `ah_present` guard preserves it. Native-GRE **outer** packets use the sibling GRE
   branch (lib.rs:646), not this lookup. `should_fallback_early` (multicast/link-local/
   limited-broadcast, lib.rs:1340) passes to local before the lookup. All of these are
   out-of-scope with §5d warnings.
7. Session-hit/GRE consistency unchanged.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| eBPF verifier / 1M cap (**crux**) | **HIGH** | tail-call forbidden, no headroom metric. Ladder §2: exact-both → v4-exact-only → reclaim → PLAN-KILL. |
| Reconcile transaction correctness | MED | new-only + rollback-safe + union-capacity + restart reconcile + mandatory pins. |
| Availability (over-steer → slow-path drop) | MED | port-0 intent over-steers **ALL** ports for that proto+ip; non-SYN local delivery is not session-cached (forwarding/mod.rs:1829), so repeated unmatched traffic stays exposed; the helper slow path **drops** when unavailable/rate-limited (`slow_path.rs:283`). Mitigate: exact intent for port-scoped rules; counted + bounded (§10). |
| IPv6-AH regression | MED (mitigated) | `ah_present` guard required (§8.6); without it, AH-to-self local delivery breaks. |
| Behavioral regression (local delivery) | LOW–MED | reorder; unmatched ports + ICMP echo-reply preserved. |
| Byte-order/key drift | LOW | fixed + cross-side test. |
| Static-NAT representability | MED | exact/port-0 subset + §5d loud diagnostics for proto-any/prefix. |
| ABI bump (new maps) | LOW–MED | additive, safe rollout; mandatory-FD gating. |
| Rollout / smoke | MED (deferred) | end-to-end capture shim-wall-blocked; verifier + cargo tests are not. |

## 10. Test plan

- **Verifier (make-or-break):** `make generate`/`shimverify` PASS, exact-both first,
  wildcard separate; identical artifact PASSes 6.18 floor + current-image; deploy pre-flight.
- **Helper cargo:** new-only reconcile (v4-ok/v6-fail → roll back only new_only, apply
  aborted, active keys intact); union-capacity preflight rejects over-cap; only-translating
  rows emit intent; **restart reconcile** rebuilds the pinned set exactly from authoritative
  config before readiness; `ah_present` declines AH-carrying IPv6; disjointness from
  `dnat_table`; `close_delta_deletes_dnat_table_entry_for_snat_flow` still green.
- **Go:** cross-side key-bytes assertion; cardinality preflight; §5d warning fires for each
  residual form and matches the shipped capability tag; ABI arms for the new maps.
- **RED acceptance (issue):** IPv4/IPv6 TCP/UDP DNAT on the ingress interface address →
  first packet to XSK + fwd/rev translate; port-wildcard/static-1:1 (both families, v6
  wildcard limitation noted); ICMP/ICMPv6 translated (port-0 exact) vs. ordinary ping stays
  local; unmatched SSH/BGP/IKE port stays kernel-local; **IPv6 AH-to-self stays kernel-local
  (XFRM)**; zone policy on translated transit; generation-safe add/remove.
- **Availability (finite, numeric):** offer a fixed rate R for duration T of unmatched
  traffic to an over-steered (port-0) address; assert `slow_path_drops` +
  `slow_path_rate_limited` stay within a defined budget derived from the token-bucket rate
  (slowpath.rs:77) and that **steady-state matched flows are unaffected** — NOT zero-drop
  under sustained overload (impossible, slow_path.rs:283).
- **Smoke (DEFERRED — shim-wall):** end-to-end first-packet fwd+rev capture v4+v6 on `loss:`
  once the shim-ABI wall clears.

## 11. Out of scope (each paired with a §5d commit warning — complete set)

- DNAT/static onto the firewall's own **ESP/AH/IKE/WG/non-native-GRE** control port.
- **IPv6 AH-to-self** address (declined by the §8.6 guard; XFRM local delivery preserved).
- **Native-GRE outer** address DNAT (sibling GRE branch).
- Static-NAT `protocol any` / IP-only any-protocol DNAT beyond TCP/UDP/ICMP expansion.
- DNAT/static **address-prefix/LPM** rules.
- **Multicast / link-local / IPv4 limited-broadcast** interface-address DNAT.
- IPv6 port-wildcard static-1:1 if the verifier can't afford the v6 wildcard probe.
- Helper translation math, interface-mode SNAT — unchanged.

## 12. Open questions for round-4 review (each invitable to PLAN-KILL)

1. **Verifier:** exact-both affordable (GRE branch already carries exact v4+v6; tail-call
   forbidden)? If REJECT → v4-exact-only + LOUD v6 diagnostic, else PLAN-KILL.
2. **Transaction:** new-only + `BPF_NOEXIST` + union-capacity + publish-before-teardown +
   restart reconcile — does this fully close the atomicity/capacity/persistence holes?
3. **IPv6-AH guard:** is an `ah_present` parse signal + decline the right fix, or is an
   explicit pre-intent IPv6-AH local return cleaner?
4. **Loud diagnostics:** is the complete §5d set + machine-readable capability tag adequate
   to discharge "no silently-undocumented-as-fixed bypass surface"?
5. **Availability:** is the counted, token-bucket-derived drop budget an acceptable
   acceptance criterion for the over-steer exposure?
6. **Is PLAN-KILL warranted**, or is phased Option B the right call?
