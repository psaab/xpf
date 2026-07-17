# Plan of action — #5837: userspace XDP local-interface destination check bypasses DNAT/static-NAT

**Status:** CONVERGED v7 — **PLAN-KILL (drive-by dataplane fix) + ship the Track-1 commit-WARNING; defer the full Option-B fix.** See §0. Codex r1–r6 (REVISE, high-signal, materially improved the design and surfaced deep unsolved fail-closed/HA/verifier surface) + Claude SMR r2–r6 (PLAN-READY r2–r6, self-corrected to concur with the PLAN-KILL-of-drive-by after Codex r6 disproved two v6 closures + surfaced the HA dimension). AGY infra-blocked every round (2-of-3 per the infra-block rule).

**v6 changelog (closes Codex r5's six design blockers):** strict transaction order
(insert-new → publish-generation → stale-delete-**after**-swap) + post-commit delete-failure
result (§5d); **`intent_authoritative` ctrl gate** so incomplete-reconcile state fails closed
independently of intent-map membership (§5b); ingress-interface coverage **proven** (zone
dataplane interfaces always in the ingress set; skipped = out-of-scope+warned, §5b/§5e);
disarmed-refresh **must publish-before-accept** (the defer branch rejected as unsafe, §5d);
instruction-reclaim **targets exact-both first** then v4-only (§2); **absent/malformed/legacy
capability ⇒ zero-enforcement ⇒ warn-every-rule**, threaded through every `CompileConfig*`
(§5c); ICMP port-0 is an exact key (not a Phase-2 casualty — don't over-warn, §5d); fixed the
`from_ne_bytes` pseudocode + `maps_sync.go:679-688` readiness cite.

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

## 0. CONVERGED VERDICT (v7) — PLAN-KILL of the drive-by dataplane fix; ship the commit-time WARNING; defer the full Option-B fix as a scoped, verifier-gated, HA-aware project

After six adversarial rounds (Codex + Claude SMR; AGY infra-blocked), the research converges
**not** on a clean drive-to-`/engineer`. The team-lead PLAN-READY test — *architectural
agreement AND verifier feasibility settled* — is met by **neither**:

1. **Verifier feasibility is unvalidated and the surface keeps GROWING.** The DNAT-before-local
   probe must live in the healthy miss arm, **every degraded / binding-missing / heartbeat-stale
   branch** (§5e — else #5837 recurs while the helper is degraded), and behind an **IPv6-AH
   guard** (§5a) — all inside the single `xdp_userspace_prog` under the **1M-insn cap** with
   **tail-call FORBIDDEN** (retirement canary) and **no `shimverify` headroom metric**. Each
   correctness layer added *more* hot-path surface against a fixed budget. The make-or-break is
   a real, unhedged gamble that can only be settled by a `make generate`/`shimverify` run — and
   the growing surface makes REJECT materially likely.
2. **The full fix's correctness surface is deep and NOT fully solved.** Codex r6 showed two of
   v6's "closures" were wrong and surfaced an unaddressed dimension:
   - **Incomplete-state fail-closed is NOT achieved.** The `intent_authoritative` bit only gates
     binding-READY; a *missing / failed-insert* intent key still falls to the non-READY path,
     which passes local = #5837 — the bit doesn't change what the degraded path does with a
     local-classified tuple. True fail-closed needs a heavier generation-tagged design (more
     verifier surface still).
   - **Ingress-interface coverage was proved wrong.** A packet can ingress an interface *other*
     than the one owning the destination address (DNAT is ingress-zone/interface/RI-scoped
     independently), and the physical **fabric parent IS in the ingress set** (an intentional HA
     path) — so the "always covered / fabric-skipped" claim is false.
   - **HA failover generation-safety is unaddressed (first-order for an HA firewall).** A
     stale-but-"authoritative" standby can remain takeover-eligible after a failed peer apply;
     takeover must be gated on exact equality of active-expected / helper-forwarding /
     intent-authoritative generations, which the current HA path does not check.
   - Plus: worker-visible-vs-internal publication ordering, the new-plan `defer_workers=true`
     acceptance path, and the boot/offline capability source/timing — each a real design decision.

These are **not nits**. Each is solvable, but every solution adds implementation surface AND
hot-path verifier cost, while the go/no-go verifier verdict stays unvalidated. Continuing to
iterate would be oscillation: the change is genuinely large, and each newly-exposed layer
yields another real hole.

**Converged recommendation (two tracks):**

- **TRACK 1 — SHIP NOW (pragmatic mitigation, PLAN-READY, tiny, zero verifier risk):** a
  **commit-time WARNING** in the Go config compiler when a DNAT/static-NAT public/mapped address
  equals a configured interface address — "this destination translation is inert on the first
  packet in the userspace dataplane (interface-address DNAT/static-NAT limitation, #5837); use a
  non-interface public address or expect first-packet local delivery." This is trivially feasible
  (the compiler already has `cfg.Warnings` and both the pool addresses and interface addresses,
  compiler.go), and it fixes the bug's **worst** property: today the bypass is **silent**. Making
  it **loud** is a real, immediate security-posture improvement and the honest first step. Spec: §0a.
- **TRACK 2 — DEFER (the full dataplane fix):** the Option-B design below (§5) is preserved as
  the canonical starting point IF the project chooses to invest in a large, verifier-gated,
  HA-aware implementation. It is NOT a drive-by. Before `/engineer`, the FIRST task is the
  `shimverify` gate on a Phase-1 exact-both candidate that ALSO carries the §5e degraded-path
  drop; a REJECT (materially likely) collapses this track to the Track-1 warning permanently.
  The full fix must additionally solve: real fail-closed incomplete-state (generation-tagged),
  per-rule ingress coverage + attach transition, HA-takeover generation-equality gating, and the
  capability boot-timing/source — see §0b.

**Terminal:** PLAN-KILL (drive-by dataplane fix) + Track-1 WARNING as the shippable outcome.
This matches the team-lead's explicitly-blessed "PLAN-KILL-with-a-pragmatic-fallback."

### §0a. Track-1 mitigation spec (the shippable part)

In the Go config compiler (`pkg/config/compiler.go`), after DNAT + static-NAT rule-set
compilation, for each rule whose translated **public/mapped destination address** (DNAT pool
address; static-NAT external address) equals a **configured interface address** (any family),
append a `cfg.Warnings` entry naming the rule-set/rule and the interface. Scope: warn (never a
hard error — the config is legal Junos and works for reply packets / existing sessions; only the
first-packet transit classification is affected). Covers both families. Test: a set-syntax config
with `destination-nat pool P address <WAN-iface-ip>` + a rule using P → exactly one warning;
a pool with a non-interface address → no warning; static-NAT external == iface addr → warning.
This is a self-contained `/engineer`-able change independent of the shim.

### §0b. What the deferred full fix (Track 2) must additionally solve (Codex r6)

1. Define "publish" as **worker-visible** state completion (not the internal `coord.forwarding`
   assignment), and delete stale intent only after that point.
2. Real fail-closed incomplete-state: a **generation-tagged** intent value so the shim can drop
   (not pass-local) a tuple whose configured generation isn't yet live — without a global bit
   that would downgrade an already-live generation mid-apply. Resolve ctrl-word ownership (Go
   reconstructs+overwrites the ctrl value; a helper-written bit is clobbered).
3. Per-rule ingress coverage: derive each rule's possible ingress interfaces from its
   zone/interface/RI scope (not address ownership); cover the attach-before-map-populate
   transition; preserve the intentional physical fabric-parent ingress path.
4. Cover every deferred/disarmed acceptance path, including new-plan `defer_workers=true`.
5. HA takeover gated on exact active-expected / helper-forwarding / intent-authoritative
   generation equality + local capability; a zero-capability legacy standby with applicable DNAT
   is takeover-ineligible or explicitly unsupported.
6. Capability source/timing: pre-load extraction from the embedded artifact OR
   compile-conservative-then-recompile; thread through **all** `CompileConfig*` call sites
   (store.go:343/481, check.go:39, upgrade.go:215, cli/grpc terse-interface shows, …).

*The design below (§1–§13) remains the Track-2 reference. Read §0 first: it is the converged
recommendation. §1–§13 are the full Option-B design and the six-round review history.*

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
   probes into one keyed pass), **targeting exact-both first** to preserve v6 coverage →
   re-verify. If reclaim+exact-both PASSes → ship exact-both; if reclaim only fits
   v4-exact-only → ship v4-only + LOUD §5d warning. The shipped candidate's capability
   bitmask (§5c) always reflects what actually passed.
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
let dst_ne = u32::from_ne_bytes([parsed.dst_addr[0], parsed.dst_addr[1],
                                 parsed.dst_addr[2], parsed.dst_addr[3]]);
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

### 5b. Intent semantics + authoritative-ready gate + restart reconcile

Intent is a **steer-superset**: port-0 (or address-wildcard) over-steers ALL ports for that
proto+ip; the helper re-checks the exact rule and locally-delivers non-matching packets (§4a)
— no policy bypass, an availability shift (§9/§10).

**Superset ordering invariant (closes the incomplete-state bypass, Codex r5).** The intent
map MUST always contain at least the **currently-active generation's** keys, so no live
DNAT-transit tuple is ever absent. This is guaranteed by the §5d order (insert-new →
publish-new-generation → delete-stale-*after*-swap) plus abort-on-insert-failure (a failed
apply leaves the prior complete generation live). The only state that violates the invariant
is a crash mid-apply — covered by the restart reconcile below.

**Authoritative-ready gate (fail-closed for incomplete state, Codex r5 blocker).** Because the
degraded/binding-not-ready/ctrl-disabled paths can only *drop a key that exists* — a MISSING
intent key would fall through to `is_local_destination` and pass local — membership alone
cannot fail closed during an incomplete reconcile. So add an explicit
`USERSPACE_CTRL.intent_authoritative` bit set true only after a successful full intent
reconcile for the live generation, and make **binding-READY additionally require it**. While
it is false (first-ever activation before the map is populated; mid-reconcile; post-crash
before restart reconcile), bindings are non-READY, so that generation's forwarding is not yet
active — the window is bounded to *before a generation is live*, never during active
forwarding of a generation whose intent is incomplete. During that window the shim uses the
pre-fix fail-safe (today's behavior) for local classification, which is the status quo, not a
new bypass. This is the shim-visible generation gate Codex asked for.

**Ingress-interface coverage (closed, Codex r5 blocker).** The `USERSPACE_INGRESS_IFACES`
early return (lib.rs:426) passes a packet before any probe, but `buildUserspaceIngressIfindexes`
(maps_sync.go:1502) includes every interface that has a security zone and is not
`userspaceSkipsIngressInterface` (which excludes mgmt/`fxp`/`em`/`fab`/`lo0`/tunnel/local-fabric,
maps_sync.go:~1512). A DNAT/static public address is on a configured **zone dataplane
interface**, which is therefore always in the ingress set → the probe runs. A DNAT configured
on a *skipped* interface's address (mgmt/tunnel/fabric/loopback) is non-transit, **out of scope
and §5d-warned**. So the fork is resolved: proven-covered for the in-scope case, warned for the
excluded case — no residual bypass.

**Restart:** pinned maps **persist** across restart (loader_userspace_shim.go:63) — the map is
NOT empty. On every bringup the helper enumerates the pinned intent maps (actual current
contents, incl. crash residue), removes `current − desired` **before** inserting
`desired − current` (so a stale-full map doesn't fail the union preflight), and holds
`intent_authoritative`=false (bindings non-READY, the real shim steering gate at
`maps_sync.go:679-688` / `userspaceBindingReady`) until the reconcile succeeds; any
enumerate/insert/delete failure → keep bindings non-READY, report, retry from scratch.

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
  `{v4_exact, v6_exact, v4_wildcard, v6_wildcard}` from the loaded artifact and PASSES it to
  the config compiler via a parameter/interface. The §5d diagnostics read that bitmask, so
  warnings always match the shipped candidate. Carrier: a shim-declared const map/section
  validated at load.
- **Absent/malformed/legacy capability semantics (Codex r5 blocker).** A shim with no intent
  maps (legacy/rollback), an unreadable carrier, or unknown/malformed bits ⇒ treated as
  **zero intent enforcement**, which MUST make the compiler **§5d-warn every applicable
  DNAT/static-NAT-on-interface-address rule** (fail-loud, never silently "fixed"). The
  capability parameter MUST thread through **every** compile entry point — strict, lenient,
  node-aware/HA, and offline (`config.CompileConfig*`, currently called with no capability
  input at `pkg/configstore/store.go:336` and `pkg/config/compiler.go:1925`) — so no compile
  surface emits an un-warned config against a reduced-capability shim.
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

**Transaction — strict order (rollback- AND generation-safe; Codex r5 blocker).** The order
is LITERAL and must not be relaxed: **insert-new → publish-new-forwarding-generation →
synchronous stale-delete AFTER the swap.** Deleting old-only intent *before* the new
generation is live would leave the old rule active in the helper while its first packet again
passes kernel-local — the §5b superset invariant forbids it.
1. `desired`, `new_only = desired − current`, `stale = current − desired`.
2. Preflight `|current ∪ desired|` per family ≤ 8192.
3. Insert **only `new_only`** with `UpdateNoExist` (loader.go:585) — never overwrite an
   active key. Any failure → delete only the `new_only` keys created this apply + **abort the
   apply** (fail-closed; the prior complete generation stays live). EEXIST races abort safely
   (control requests serialize under the server-state mutex, handlers/mod.rs:122).
4. **Publish the new forwarding generation** — full reconcile at
   `coord.forwarding = new_forwarding` (snapshot.rs:430, after teardown at
   `coordinator/reconcile/mod.rs:297`, reconcile begins :193); same-plan refresh commit at
   `snapshot_refresh.rs:236`. `lifecycle.rs:310` is *init*. Only now is the new intent+forwarding
   generation authoritative; set `intent_authoritative`=true (§5b) and mark bindings READY.
5. **Generation-safe delete AFTER the swap:** delete `stale` **synchronously under the writer
   mutex** in the same apply, recomputing `current − desired` at apply time. **No deferred
   cross-generation retry** (a delayed gen-B delete could remove a key gen-C re-desires — the
   value is presence-only, no generation tag). **Post-commit delete failure result:** the
   apply is reported as succeeded-with-warning (the new generation is already live and
   correct — surplus stale keys only over-steer, never bypass), the failure is metered, and
   the stale keys are reaped by the next apply's `stale` set or the restart reconcile.
6. **Deferred arming / disarmed refresh (Codex r5 — pick the safe branch).** Deferred
   activation runs through `set_forwarding_state`, which currently **discards** the reconcile
   error (forwarding.rs:32) — an intent-reconcile/restart-reconcile failure must instead
   revert arming and return `ok=false`. A disarmed same-plan refresh (updates forwarding
   without workers, snapshot.rs:208) MUST **reopen and publish the mandatory intent pins
   before accepting the refresh** — the "defer publication" alternative is rejected as unsafe
   (newly-accepted DNAT keys would be absent while the disarmed/ctrl-disabled path passes
   unmatched local to the kernel, lib.rs:1009). If the pins cannot be published, the refresh
   is rejected (`intent_authoritative` stays false → non-READY → no active forwarding).

**§5d loud-diagnostic set (mandatory; ≡ §11).** Every form not dataplane-enforced on the
first packet raises an operator-visible commit-time warning naming the rule. Complete set:
static-NAT `protocol any` / IP-only PROTO_ANY DNAT non-{TCP,UDP} residual; DNAT/static
**address-prefix/LPM**; the **reduced-scope outcomes** — if Phase-2 rejects, TCP/UDP
portless/range DNAT + whole-address static-wildcard in BOTH families (NOTE: ICMP/ICMPv6 use
`dst_port=0` which is an **exact Phase-1 key** (lib.rs:1516), so explicit ICMP translation
rules are covered by exact-both and are NOT Phase-2 casualties — do not over-warn them); if
v4-only ships, ALL IPv6 forms; DNAT/static onto the firewall's own **ESP/AH/IKE/WG/non-native-GRE** control port;
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
- The `USERSPACE_INGRESS_IFACES` absent/zero early return (lib.rs:426): **resolved in §5b**
  — an active translating interface (a zone dataplane interface) is always in the ingress set
  (`buildUserspaceIngressIfindexes`, maps_sync.go:1502), and a DNAT on a skipped interface's
  address (mgmt/tunnel/fabric/loopback, `userspaceSkipsIngressInterface`) is out of scope +
  §5d-warned. No residual bypass.
- NDP (lib.rs:578) and `should_fallback_early` (lib.rs:1340) early returns: DNAT on those is
  nonsensical; out of scope with §5d warnings.
- **Incomplete-state (missing key)** is closed by the §5b `intent_authoritative` gate: during
  an incomplete reconcile bindings are non-READY, so no generation whose intent map is
  incomplete is ever actively forwarding.

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
collision, byte-order, ICMP, AH-before-session-hit, degraded-path fail-closed drop,
generation-safety, restart-persistence, and **incomplete-state authoritative-ready gate**
correctness models; the **strict transaction order** (insert-new → publish-generation →
stale-delete-after-swap) + post-commit delete-failure result; the **disarmed-refresh
publish-before-accept** decision; the **ingress-interface coverage proof**; the verifier
ladder (incl. instruction-reclaim-targets-exact-both-first) + fail-safe + PLAN-KILL fork; the
representable-subset + loud-diagnostic policy; the **absent/malformed/legacy capability
semantics** (zero-enforcement ⇒ warn-every-rule) + propagation through every `CompileConfig*`
surface. These are the design questions /research exists to answer, and they are answered
(Codex r5 design blockers closed in v6).

**Implementation-execution (enumerated for `/engineer`, not authored here):** exact struct
field byte layouts / JSON tag strings / Rust `MapPins` identifiers; the capability-bitmask
wire encoding + validator; the injected-clock/rate seam the availability test needs at the
`SlowPathReinjector` level (slowpath.rs:313); the precise `make generate`/`shimverify` runs on
both kernels (the go/no-go gate is mechanical and belongs to implementation); exact test
rates/thresholds beyond the joint-bucket ceiling relationship. These are execution tasks the
plan directs; a research doc that fully authored them would be the implementation, not a plan.
