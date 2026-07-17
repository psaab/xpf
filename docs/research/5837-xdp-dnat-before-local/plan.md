# Plan of action — #5837: userspace XDP local-interface destination check bypasses DNAT/static-NAT

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Issue:** #5837 (bug, High, security, nat, audit)
**Research branch:** `research/5837-xdp-dnat-before-local`
**Base:** origin/master `7d2cd112fec4`
**Mode:** `/research` — stops at PLAN-READY / PLAN-KILL. No PR, no production code touched here.

---

## 1. Issue framing

On a non-GRE **session miss**, the AF_XDP ingress shim (`userspace-xdp/src/lib.rs`,
`try_xdp_userspace`) classifies a packet as **kernel-local** and returns it to the
kernel (`cpumap_or_pass`) *before* consulting any configured destination-NAT or
static-NAT. The local-destination test (`is_local_destination`, lib.rs:1363) only
exempts **interface-mode source-NAT** addresses; it has no awareness of DNAT /
static-NAT whose public/mapped address is also an interface address.

Consequence: a port-forward / static one-to-one NAT that maps the **WAN
interface's own address** (a common, legitimate Junos config) never reaches the
Rust dataplane on the first packet. Linux accepts or rejects it as local traffic
instead of applying the configured translation + transit zone policy. If a local
service happens to bind that port, the traffic is delivered to it — a
**High-severity security bypass** (the intended DNAT + policy path is inert).

Required invariant (verbatim from the issue): *for a session miss, a configured
destination translation matching destination address + protocol/port must take
precedence over generic kernel-local delivery; unmatched traffic to the same
interface address must still reach legitimate local control-plane services.*

## 2. Honest scope/value framing

This is a **correctness/security** fix, not a performance change. The "win" is:
a configured DNAT/static-NAT rule whose public address is an interface address
becomes **enforced on the first packet** for ordinary IPv4/IPv6 ingress, instead
of silently bypassed. Blast radius of the *bug*: any deployment that port-forwards
to (or static-NATs) an interface address — a mainstream firewall configuration.

Because the required change lives in the **`make generate`-gated AF_XDP shim**
(pinned toolchain + real-kernel verifier gate, #1864), the make-or-break question
is not "is the logic right" (it is straightforward) but "does the added hot-path
lookup fit the eBPF verifier's 1M processed-insn budget on the supported kernels."
The v6 GRE-inner classifier already had to **drop** its port-0 wildcard probe to
stay under that cap (lib.rs:882-901). That precedent is why this is `/research`.

*If reviewers conclude the verifier cost is prohibitive and no acceptable
restructure exists, PLAN-KILL (or a scoped exact-only-v4 subset) is an acceptable
verdict.* A commit-time reject is **not** an acceptable substitute (see §10/§11):
port-forwarding to an interface address is legitimate Junos config; hard-rejecting
it is a parity regression, and a warning alone does not fix the bypass.

## 3. Key finding that reshapes the issue's suggested fix

The issue's "Fix direction" suggests *"do a `DNAT_TABLE(_V6)` lookup — the helpers
already exist at lib.rs:860-901."* **That is necessary but not sufficient**, because
in the userspace-dp runtime the shim-visible `dnat_table` / `dnat_table_v6` maps do
**not** currently contain the configured forward DNAT/static-NAT rules:

- `userspace-dp/README.md:177` (authoritative): *"Compiler-managed STATIC
  DNAT-config entries (flags=1) are never published or deleted by this path."*
  The helper only publishes **dynamic (flags=0) reverse-NAT** records into
  `dnat_table` (`publish_dnat_table_entry`, #2979/#2406) for embedded-ICMP /
  SNAT-return steering.
- The Go compiler *does* build correctly-shaped static (flags=1) DNAT entries in
  `pkg/dataplane/compiler_nat.go:855-918` — **but** in the userspace path the
  `DataPlane` it writes through is `userspaceShimCompileDataplane`, whose
  `SetDNATEntry`/`SetDNATEntryV6` are **no-ops** (`return nil`,
  `pkg/dataplane/loader.go:407-408`). Configured DNAT/static-NAT matching happens
  entirely inside the helper's `nat/destination.rs` engine
  (`snapshot.destination_nat_rules` / `snapshot.static_nat_rules`), which the shim
  cannot see.

So a shim `dnat_lookup` before `is_local_destination` would find **nothing** for a
configured port-forward on the first packet. **The fix must include a publication
step that makes the configured translation intent visible to the shim.**

**Good news — the key/wildcard/byte-order contract already lines up.** The shim's
`dnat_lookup_v4/v6` (lib.rs:861-902) reads `DnatKeyV4{protocol, dst_ip (native),
dst_port (host-order numeric)}`; `compiler_nat.go` already builds exactly that
shape (`ipToUint32BE` native dst_ip, raw host-order `DstPort`, `DNATFlagStatic`),
and `maps_helpers.go:8-30` documents the shared contract. The publication code is
already correct; it is simply discarded by the no-op stub.

## 4. What's already shipped / partially batched (must compose with)

- **Non-interface-address DNAT already works.** When the DNAT public address is a
  routed-to-firewall IP that is *not* an interface address, `is_local_destination`
  returns false, the packet falls through to XSK, and the helper's `destination.rs`
  already translates + polices + creates the session correctly. **The defect is
  ONLY the ingress classification of DNAT-target tuples that coincide with an
  interface address.** The helper's translation path needs no change.
- **Interface-SNAT address exclusion** (`buildNATTranslatedLocalAddressExclusions`,
  maps_sync.go:1670) already removes interface-mode SNAT addresses from
  `USERSPACE_LOCAL` and publishes them to `USERSPACE_INTERFACE_NAT`. That is
  address-only and is the *wrong* model for DNAT (§6 Option C) because it is not
  port-aware. Our change must not disturb it.
- **`dnat_table` reverse-NAT lifecycle** (#2979): helper writes flags=0 dynamic
  entries and deletes them on session close (`flush_session_deltas`). Our static
  (flags=1) intent entries share the map but a **different flag class + different
  key tuples** (forward public tuple vs. reverse SNAT tuple), so the two lifecycles
  are disjoint. `ClearDNATStatic()` (maps_nat.go:37) already deletes *only* flags=1
  entries — the selective-clear primitive we need for reconcile exists.
- **`make generate` verifier gate** (#1864): `cmd/shimverify` runs a real
  `BPF_PROG_LOAD` (needs CAP_BPF/root + pinned toolchain) before the tracked `.o`
  is replaced. **This gate is checkable locally at implement time — it is NOT
  shim-wall-blocked.** Only end-to-end cluster smoke is shim-wall-blocked.
- **v6 wildcard precedent**: `dnat_lookup_v6` is exact-only *by design* — the
  second (port-0 wildcard) HASH lookup blew the 1M cap when added to the v6
  GRE-inner classify (lib.rs:882-891). Any v6 wildcard ambition inherits this
  constraint; the issue's acceptance criteria already anticipate "the existing
  IPv6 wildcard limitation."

## 5. Concrete design (recommended: Option A, helper-published intent)

Two independent pieces: **(P) publish intent** so the shim can see configured DNAT,
and **(S) shim classify** DNAT intent before local delivery.

### P — publish configured DNAT/static-NAT forward intent (flags=1) into `dnat_table`

Recommended owner: **the helper** (single writer of `dnat_table`, owns the reconcile
and thus generation-safety). On every config apply, the coordinator reconcile
(which already iterates `snapshot.destination_nat_rules` and
`snapshot.static_nat_rules`, coordinator/mod.rs:934) computes the set of forward
intent keys and reconciles them into `dnat_table`/`dnat_table_v6` with **flags=1**:

```
DnatKeyV4 { protocol, dst_ip: <public/mapped addr, native>, dst_port: <host-order, 0=wildcard> }
  -> DnatValueV4 { flags: STATIC (1), .. }   // value payload unused by the shim (it only tests is_some())
```

- **DNAT (port-scoped):** one exact entry per (proto, public_ip, public_port).
- **Static 1:1 / port-less DNAT:** one **port-0 wildcard** entry per
  (proto, public_ip) — this is the entry the shim's wildcard probe must find.
- **Reconcile = generation-safe:** publish NEW intent entries *before* removing
  stale ones (add-before-delete) so no first-packet window sees "no intent →
  local delivery" during a config transition. Deletion keys on flags=1 only, never
  touching the helper's flags=0 dynamic entries. `dnat_table` is
  `max_entries=MAX_SESSIONS`, `BPF_F_NO_PREALLOC`, non-LRU — static intent count is
  bounded by config rule count (tiny vs. session capacity), no eviction risk.
- **Source-scoped DNAT (#2394):** a DNAT rule with `match source-address` fires
  only for some sources. The intent map is keyed on dst-tuple only (no source), so
  it will steer *all* sources for that dst-tuple to XSK; the helper's
  `destination.rs` then applies the source constraint and, for a non-matching
  source, treats it as a normal transit/local flow. This is safe: over-steering to
  XSK never bypasses policy (the helper still decides). Document that the intent map
  is deliberately source-agnostic (steer-superset, enforce-exact-in-helper).

**Alternative owner (A-Go):** un-stub `userspaceShimCompileDataplane.SetDNATEntry`
to write flags=1 entries (the compiler machinery already builds them). Rejected as
primary because it makes Go a *second* writer of `dnat_table` alongside the helper,
splitting reconcile/generation ownership across the FFI boundary — the helper-owned
variant keeps one writer and one reconcile authority.

### S — shim: classify DNAT intent before local delivery

In `try_xdp_userspace`, non-GRE session-miss arm (lib.rs:632, the `_ =>` branch),
**before** `is_icmp_to_interface_nat_local` / `is_local_destination`:

```rust
// A configured destination translation for this exact tuple takes precedence
// over kernel-local delivery: steer to XSK so the helper applies DNAT + policy.
if dnat_intent_matches(&parsed) {
    // fall through to XSK redirect (do NOT pass to kernel)
} else {
    if is_icmp_to_interface_nat_local(&parsed) { return cpumap_or_pass; }
    if is_local_destination(&parsed) { return cpumap_or_pass; }
}
```

`dnat_intent_matches` reuses the existing `dnat_lookup_v4`/`dnat_lookup_v6`
helpers (already in the ELF/ABI — **no new map, no map-ABI bump**), keyed on
`parsed.protocol`, dst addr, and `parsed.flow_dst_port`. A match → skip local
delivery, fall through to the existing XSK redirect. A non-match → existing local
logic unchanged, so **unmatched ports on the same address still reach the kernel**
(the invariant). ICMP: an exact (proto=ICMP) intent match steers; otherwise the
existing `is_icmp_to_interface_nat_local` echo handling is preserved.

### Phasing to manage the verifier budget (the crux)

- **Phase 1 (primary security fix):** exact-match intent, both families. Covers
  TCP/UDP port-forward to an interface address — the headline bug. Add an
  **exact-only** variant of the lookup for the ordinary path (single HASH probe per
  family) to minimize added instructions.
- **Phase 2 (port-wildcard / static 1:1):** add the port-0 wildcard probe. Gate on
  verifier headroom measured in Phase 1. Precedent (§4) says v4 can likely afford
  exact+wildcard and **v6 wildcard may not** — if so, v6 static-1:1-on-interface
  ships as a documented limitation (mirrors the existing v6 GRE wildcard limit the
  issue already calls out), v6 exact DNAT still fixed.
- **Fallback if even Phase-1 exact-only exceeds the cap:** restructure — a tail-call
  to a small dedicated dnat-classify sub-program, or offset other lookups. This is
  the residual risk that makes the verdict genuinely uncertain until `make generate`
  runs. Since the GRE branch already performs an exact v4+v6 `dnat_lookup` within
  budget and the ordinary branch is a sibling, exact-only is *plausibly* affordable
  — but not guaranteed.

## 6. Multiple path options considered

| Option | Mechanism | Port-aware? | Verifier cost | Verdict |
|---|---|---|---|---|
| **A (recommended)** | Publish forward intent (flags=1) into existing `dnat_table`; shim `dnat_lookup` before `is_local_destination` | **Yes** | +1 HASH/family exact (Phase 1); +2 for v4 wildcard | **Primary** — reuses existing map + helpers + byte-order contract |
| B | New dedicated `dnat_intent_v4/v6` map, Go-populated; shim looks it up | Yes | Same lookup cost + **new map ⇒ ABI bump ⇒ shim-wall** + more map surface | Alternative; cleaner ownership but heavier rollout. Fold into A only if reusing `dnat_table` proves unworkable |
| C | Go address-exclusion: strip DNAT public addr from `USERSPACE_LOCAL` | **No** | Zero shim change | **Rejected**: not port-aware — kills local delivery for *other* ports (SSH:22 alongside DNAT:443); routes all address traffic through XSK, violating the acceptance criterion "unmatched port … still takes the kernel-local path"; degraded-mode local-return robustness concern |
| D | Commit-time reject/warn when DNAT public addr == interface addr | n/a | Zero dataplane change | **Rejected as primary**: reject breaks a legitimate/common Junos config (parity); warn-only doesn't fix the bypass. Viable only as an interim mitigation banner |

Option A vs B decision hinges on: A reuses the already-declared, already-ABI-checked
`dnat_table` and the already-correct `compiler_nat.go` key contract, adding **no new
map**; B is architecturally tidier (config-intent map separate from reverse-NAT
lifecycle) but forces a new-map ABI bump through the shim-wall and adds verifier
surface. Recommend A; keep B documented as the fallback if the dual-lifecycle sharing
of `dnat_table` raises a reviewer objection.

## 7. Public API / behavior preservation

- `is_local_destination`, `is_icmp_to_interface_nat_local`,
  `is_interface_nat_destination` signatures unchanged; only the *order* of checks in
  `try_xdp_userspace` changes (intent tested first).
- `dnat_lookup_v4`/`dnat_lookup_v6` signatures unchanged (reused).
- `dnat_table`/`dnat_table_v6` MapSpec (type/key/value/max_entries/flags) unchanged —
  **no ABI bump, `validateUserspaceShimSpec` #5307 check still passes.**
- Helper reverse-NAT (flags=0) publish/delete lifecycle unchanged; only a new
  flags=1 forward-intent reconcile is added, disjoint by flag + key tuple.
- Non-interface-address DNAT, interface-SNAT, GRE-inner classify, ESP/WG/NDP
  short-circuits — all unchanged.

## 8. Hidden invariants the change must preserve

1. **Unmatched ports stay kernel-local.** Only tuples with a configured translation
   are steered; everything else hits the unchanged `is_local_destination` path.
2. **Byte-order/key contract is singular.** Shim reads native dst_ip + host-order
   dst_port; publisher must write the identical shape. `compiler_nat.go` already
   does — any new helper-side publisher must match `maps_helpers.go` semantics
   exactly, and this must be asserted by a cross-side key test.
3. **Flag-class disjointness.** Static intent = flags=1, dynamic reverse = flags=0.
   Reconcile/delete of intent must key on flags=1 only; helper close-delta delete
   must remain flags=0 only. No cross-contamination, no leaks.
4. **Generation safety (add-before-delete).** A config apply must never open a window
   where a still-configured DNAT tuple has no intent entry (transient bypass). New
   before old.
5. **Rule removal removes intent.** A deleted DNAT/static-NAT rule must delete its
   intent entry or a stale entry keeps stealing local delivery forever (non-LRU map).
6. **Session-hit / GRE-inner consistency.** A session that was created via the new
   intent path must be found by `live_userspace_session_action` on packet 2 (it will
   — the helper creates the normal session); GRE-inner classify already does the
   dnat lookup, so its behavior is unchanged.
7. **Degraded-mode.** When ctrl disabled / binding missing, the degraded path
   (`is_degraded_local_or_control`) governs local delivery; intent classification
   only applies on the healthy path — acceptable (degraded mode already conservative).

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| eBPF verifier / 1M-insn cap (**crux**) | **HIGH** | Added hot-path HASH lookups; v6-wildcard precedent already hit the cap. Settled only by `make generate`+`shimverify`. Phasing + exact-only fallback + tail-call restructure mitigate. |
| Behavioral regression (local delivery) | LOW–MED | Reordering checks; unmatched ports unchanged. Risk is a mis-scoped intent entry stealing local delivery — covered by tests + generation-safety. |
| Publication/reconcile correctness | MED | New flags=1 reconcile across the map shared with dynamic entries; add-before-delete + flag-class discipline required. |
| Byte-order/key drift | LOW | Contract already aligned; assert with cross-side key test. |
| Architectural mismatch | LOW | Reuses existing map + helpers; no new ABI. Option B would raise this. |
| Rollout / smoke | MED (deferred) | End-to-end first-packet capture is shim-wall-blocked; verifier + helper cargo tests are not. |

## 10. Test plan

- **Verifier gate (make-or-break):** `make generate` → `build-userspace-xdp.sh` →
  `cmd/shimverify` PASS on the pinned toolchain (root/CAP_BPF). This is the primary
  gate and is runnable locally now — not shim-wall-blocked.
- **Helper unit tests (cargo):** intent-reconcile add/remove; flags=1 vs flags=0
  disjointness; `close_delta_deletes_dnat_table_entry_for_snat_flow` still green;
  key-SSOT byte-order test extended to the forward-intent key.
- **Go tests:** `buildLocalAddressEntries` / exclusion unchanged; if A-Go variant,
  compiler_nat publish path. Cross-side key-shape assertion (Go key == shim key).
- **RED acceptance tests (from the issue):** IPv4 & IPv6 TCP/UDP DNAT on the ingress
  interface address → first packet to XSK + forward/reverse translate; port-wildcard
  / static-1:1 (both families, v6-wildcard limitation noted); ICMP/ICMPv6 translated
  vs. ordinary ping remains local; unmatched SSH/BGP/IKE port stays kernel-local;
  zone policy evaluated on the translated transit flow; generation-safe add/remove.
- **Smoke (DEFERRED — shim-wall):** end-to-end first-packet forward+reverse capture
  for v4+v6 on `loss:` cluster once the shim-ABI wall clears. Documented deferral,
  not a merge blocker for the code+verifier+unit gates.

## 11. Out of scope (explicitly)

- IPv6 **port-wildcard** static-1:1 on an interface address if the verifier cannot
  afford the v6 wildcard probe (documented limitation, mirrors existing v6 GRE limit).
- Any change to the helper's actual DNAT/static translation math (already correct).
- Interface-mode SNAT handling (`USERSPACE_INTERFACE_NAT`) — unchanged.
- Commit-time warning for "static-NAT/port-wildcard on a management-carrying
  interface address" — optional defensive follow-up, not required for the fix.

## 12. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Verifier headroom:** Is exact-only intent (1 HASH/family) in the ordinary
   branch affordable given the GRE branch already carries an exact v4+v6 dnat lookup
   in the same program? If not, is a tail-call restructure acceptable, or is this a
   PLAN-KILL / scope-to-v4-exact-only?
2. **Publisher ownership:** helper-published intent (single writer, recommended) vs.
   Go-published (un-stub `SetDNATEntry`, reuse existing compiler code). Which better
   satisfies the "one canonical key/wildcard/byte-order contract" + generation-safety
   requirement?
3. **Reuse `dnat_table` vs. new intent map (A vs B):** is overloading `dnat_table`
   with flags=1 forward intent alongside flags=0 dynamic reverse acceptable, or does
   the shared lifecycle justify a dedicated map (and its ABI bump / shim-wall)?
4. **Source-scoped DNAT over-steering:** intent map is source-agnostic, so it steers
   all sources for a dst-tuple to XSK and lets the helper enforce the source
   constraint. Is "steer-superset, enforce-exact-in-helper" acceptable, or must the
   shim be source-aware (extra key width / verifier cost)?
5. **All-ports (static 1:1) on a management address:** correctly steals all local
   delivery per operator config (intended), but shadows local mgmt on that address.
   Acceptable-per-config, or do we need a commit-time guard?
6. **Generation-safety mechanism:** is add-before-delete on a non-LRU shared map
   sufficient, or is a generation/epoch fence needed to close the config-transition
   window?
7. **Is PLAN-KILL warranted?** Given the High/security severity and that
   commit-reject breaks parity, is any non-dataplane resolution defensible, or is the
   phased shim fix the only acceptable outcome?
