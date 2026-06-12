# #1884 — GRE tunnel anchors flap on every applyConfig: reconcile-in-place plan

## 1. Status

CONVERGED v9 (PLAN-READY ×3 at r9 — see §12) — r8 verdicts: Codex PLAN-NEEDS-REVISION (r7 closures
confirmed; ONE narrower counterexample in the BOTH-KNOBS overlap —
stanza-B-bind-failure + list-C retains a stale claim A while the
kernel is on C — folded as the OBSERVATION FALLBACK + stanza-wins
precedence `[r8]`); Claude SMR PLAN-READY (missed the overlap —
superseded); AGY r8 job DEGENERATE (succeeded-with-empty-result;
retried in r9 per the one-retry discipline). r7: stanza success-guard
+ MTU text sync `[r7]`. r6: master-observed list transfer `[r6]`.
r5: convergent clear-on-veto counterexample `[r5:*]`. Earlier: r4
`[r4:*]`, r3 `[r3:*]`, r2 `[r2:*]`, r1 `[r1:*]`.

## 2. Issue framing

`tunnelManager.Apply` (`pkg/routing/tunnel.go:94-310`) is destructive on
every invocation:

1. `clearLocked()` (tunnel.go:97) deletes EVERY tracked tunnel link and
   stops every keepalive, unconditionally.
2. The per-tunnel pre-loop delete (tunnel.go:113-121) `LinkDel`s any
   existing link with the desired name before re-adding it — even when
   the existing link is exactly the TUN anchor we are about to create.

`Apply` runs from `applyConfig` (`pkg/daemon/daemon_apply.go:259`) on
EVERY commit, every DHCP lease event (`daemon_dhcp.go:82`), and the
daemon run-loop config paths (`daemon_run.go:433,658`). Result, observed
live on the loss cluster during #1881 validation: `gr-0-0-0` ifindex
climbing 16 → 18 → 20 within minutes with zero tunnel config changes;
journal `removed existing tunnel link before apply name=gr-0-0-0
existing_type=tuntap`.

Consequences:
- The userspace helper's GRE local-origin reader fd dies on every
  recreate (fatal read errno). Pre-#1881 that thread never respawned —
  gr-X local-origin was permanently dead after the first post-boot
  applyConfig. With #1881/PR #1887 it becomes bounded tombstone→respawn
  churn per recreate — still churn, per commit.
- Link flap resets link state, drops kernel routes over the tunnel, and
  disturbs FRR (interface-down notices, route withdraw/re-add).
- Addresses are deleted with the link and re-added — a visible window
  with no tunnel address.

The WireGuard branch of the SAME function already solved exactly this in
#1432 (AGY Hazard B): `applyWireguardTunLocked` (tunnel.go:362-485)
reuses an existing wgN TUN in place, reconciles MTU and addresses
symmetrically, and is deliberately untracked so `clearLocked` cannot
delete it. GRE/IPIP anchors need the same reuse-in-place semantics.

## 3. Honest scope/value framing

This is a correctness/operational-stability fix, not a perf change. The
win: commit-time invariant "untouched tunnel ⇒ untouched netdev"
(matching the project's established networkd idempotency pattern —
`.link`/`.network` files are diffed and `networkctl reload` runs only
when files actually change). The cost: ~250 lines of reconcile logic
plus tests. Blast radius: `pkg/routing/tunnel.go` (the mechanism), plus
two small additive touches for the desired-MTU plumbing [r2: Codex F2]
— a `TunnelConfig.MTU` field (`pkg/config/types_routing.go`) and its
population in `collectAppliedTunnels` (`pkg/daemon/daemon_run.go`) —
and the `linkOps` test fake. No Rust-side change: the #1881/#1887 lane owns
the TUN-reader lifecycle; this fix simply makes Go-side recreates rare,
and on a legitimate recreate the contract is #1887's tombstone→respawn.

If reviewers conclude the fix shape is wrong or the churn is unjustified,
PLAN-KILL is an acceptable verdict.

## 4. What's already shipped / composes with this

- **#1432 S2a** — `applyWireguardTunLocked`: the proven reuse-in-place
  pattern this plan generalizes (TUN-type check, create-vs-reuse split,
  symmetric address reconciliation, VRF bind).
- **#1706** — `anchorReady` reuse path on LinkAdd-EEXIST
  (tunnel.go:135-149) + `fakeLinkOps` test harness
  (`pkg/routing/iface_reuse_test.go`), including the `hiddenUntil`
  transient-lookup race tests that MUST keep passing.
- **#1881 / PR #1887 (in flight, Rust side)** — live ForwardingState +
  three-pass GRE local-origin thread reconcile with tombstone→respawn on
  TUN death. Defines the cross-side contract for the rare legitimate
  recreate.
- **#1873** — stable content-derived tunnel-endpoint ids: a Go-side
  anchor recreate no longer scrambles dataplane endpoint identity.
- **AnchorOnly is the only production path**: `collectAppliedTunnels`
  (`pkg/daemon/daemon_run.go:83-119`) sets
  `AnchorOnly = EffectiveType(...) == TypeUserspace`, and the eBPF
  backend is hard-rejected (#1373 complete) — so every daemon-driven
  tunnel is a TUN anchor. The non-anchor kernel GRE/IPIP branch remains
  reachable only via the legacy standalone-CLI path
  (`pkg/cli/apply.go:83`, which never sets AnchorOnly).
- **MTU ownership** [r1: Codex F3 / AGY Q7; refined r2: Codex F2]:
  ongoing config-MTU reconcile is owned DOWNSTREAM of ApplyTunnels —
  `pkg/dataplane/compiler_iface.go:351,452,553` apply config-driven
  `LinkSetMTU` later in the same applyConfig run, BUT only through the
  ZONE interface path (compiler_iface.go:299,449): an UNZONED tunnel's
  configured MTU is never restored by that stage. The userspace
  snapshot reads the LIVE link MTU into tunnel endpoints
  (`pkg/dataplane/userspace/interfaces.go:368`, `tunnels.go:106`).
  Hence A.3 writes the configured MTU on create and reconciles it on
  every reuse when `tc.MTU > 0` (idempotent vs the compiler — same
  source value, both `!=`-guarded), and writes the 1500 default ONLY
  on adoption when no MTU is configured [r5: AGY Q2; r6 text sync].

## 5. Concrete design

### Path options considered

**Path A — full reconcile (recommended).** Diff desired vs actual per
tunnel: create missing, delete removed (set-diff, not clear-all),
reuse-in-place when compatible, recreate only on genuinely incompatible
kernel state. Detailed below.

**Path B — identity-hash skip.** Cache a per-tunnel config hash; skip
tunnels whose hash is unchanged; clear-and-recreate the changed ones.
Rejected:
- Still flaps the netdev on address-only or keepalive-only edits, where
  the kernel device needs no recreate at all.
- Fails the daemon-restart contract ("anchors adopted, not flapped"):
  after restart the hash cache is empty, so the first applyConfig
  recreates every anchor exactly like today.
- Repairs no drift (a manually deleted address stays missing until the
  config is edited).

**Path C — clear-and-recreate only when the tunnel SET changed.**
Cheapest diff, but any single tunnel edit still flaps ALL tunnels, and
the restart contract fails identically to B. Rejected.

**Rejected sub-option (v2): alias-based ownership marker.** Stamping
`IFLA_IFALIAS` on created anchors would give restart-stable ownership
detection, but costs a one-time upgrade flap of every pre-existing
anchor, a new linkOps method, and an operator-visible kernel marker —
all to solve only the rare foreign-TUN adoption, which flag checks +
MTU-reset-on-adopt (A.3) solve with less machinery.

**GRE attr mutability note (Path A research).** Kernel GRE/IPIP tunnel
parameters (local, remote, ttl, ikey/okey) ARE mutable in place via
`RTM_NEWLINK` change (`ip tunnel change` / `netlink.LinkModify`); the
interface name and the link TYPE (gre ↔ ip6gre ↔ ipip ↔ ip6tnl ↔ tuntap)
are not — type change requires delete+recreate, and a v4→v6 endpoint
move IS a type change (`Gretun.Type()` auto-selects "ip6gre",
netlink v1.3.1 link.go:1280-1285; ipip-over-v6 uses `Ip6tnl`). For TUN
anchors (the production path) there are NO tunnel attrs on the kernel
device at all — Source/Destination/Key live only in the dataplane
snapshot — so an anchor recreate is needed ONLY on link-type/flag
incompatibility. Given that, Path A deliberately does NOT use
`LinkModify` for the legacy non-anchor branch: attr changes there get
delete+recreate (a legitimate flap on a real tunnel re-point, legacy
path only). This keeps `linkOps` narrow and avoids shipping a
modify-path we cannot live-validate (the production cluster never runs
non-anchor tunnels).

### Path A mechanics

All changes inside `pkg/routing/tunnel.go`; `linkOps` gains
`LinkSetNoMaster(netlink.Link) error` (and the fake mirrors it).

**A.1 — set-diff removal replaces clear-all** [r1: SMR1-1 folded].
`Apply` no longer calls `clearLocked()`. The manager tracks
`t.ownedNames map[string]bool` — ALL non-WG tunnel names from the LAST
Apply's desired set, recorded unconditionally at entry (NOT the
per-tunnel success set `t.tunnels`, whose failure-`continue` paths can
leave a live link untracked under reuse semantics — e.g. a failed
`LinkDel` of a non-TUN collision, or legacy endpoint-validation
failure after a previous successful apply; the success-set diff would
then leak that link forever when the tunnel is removed from config).

```go
desired := make(map[string]bool, len(tunnels))
for _, tc := range tunnels {
    if tc.Mode != "wireguard" { desired[tc.Name] = true }
}
oldOwned := t.ownedNames // [r2: Codex F1] entry-time snapshot — the
                         // ADOPTION authority for A.3; never consult
                         // the rewritten set for adoption decisions.
next := make(map[string]bool, len(desired))
for k := range desired { next[k] = true }
for name := range oldOwned {
    if desired[name] { continue }
    t.stopKeepaliveLocked(name)  // new: cancel + drain + DELETE the
                                 // t.keepalives entry [r2: SMR2-2 —
                                 // a corpse left in the map makes
                                 // GetKeepaliveState lie and lets A.7
                                 // "retain" a cancelled runner]
    if link, err := t.ops.LinkByName(name); err == nil {
        if delErr := t.ops.LinkDel(link); delErr != nil {
            // [r2: Codex F5] retain ownership on failed delete so the
            // next Apply retries instead of orphaning the link.
            next[name] = true
            slog.Warn(...)
            continue
        }
    }
    delete(t.appliedAddrs, name) // only once gone/deleted
    delete(t.appliedRI, name)    // [r3] ditto; clearLocked clears both
}
t.ownedNames = next
t.tunnels = nil // rebuilt by the loop (GetStatus source, as today)
```

Restart bootstrap: empty `ownedNames` ⇒ deletes nothing ⇒ adoption.
Name-only ownership cannot detect an external same-name replacement
between applies — identical to today's clearLocked-by-name behavior
(Codex r2 Q4), documented, not a regression.
`Clear()`/`clearLocked()` keep delete-everything semantics (clearLocked
additionally clears `ownedNames`/`appliedAddrs`); note
`Manager.ClearTunnels` currently has ZERO callers (routing.go:148
wrapper only) and `stopAll()` (Close path) only stops keepalives, so
`Apply` was the only production user of clear-all (bounds old Q1;
ratified by Codex r1 OQ1 + AGY r1 Q1).

**A.2 — pre-loop delete (tunnel.go:113-121) is removed entirely.** Each
branch starts from `LinkByName` and decides reuse vs recreate itself.

**A.3 — anchor branch becomes reuse-first** [r1: Codex F4, SMR1-4, AGY
Q5/Q6, Codex F3 folded]:

Reuse compatibility check on an existing link, in order:
1. `*netlink.Tuntap` with `Mode == TUNTAP_MODE_TUN`;
2. `Flags & TUNTAP_NO_PI != 0` — the Rust side opens the device with
   `IFF_TUN | IFF_NO_PI` (`userspace-dp/src/slowpath.rs:17,355`); a
   foreign PI-enabled TUN would break attach where recreate heals it.
   Kernel readback reconstructs NO_PI/MULTI_QUEUE/persist via
   `IFLA_TUN_*` (netlink v1.3.1 parseTuntapData). `TUNTAP_ONE_QUEUE` is
   an obsolete no-op the kernel does not report — NOT compared;
3. `NonPersist == false` — a non-persistent TUN held alive only by a
   foreign fd would evaporate when that fd closes.

Any check fails ⇒ `LinkDel` + recreate (`replacing non-TUN tunnel
anchor` log, with reason). All pass ⇒ reuse:

```go
// [r2: Codex F1 / SMR2-1] adoption authority is the ENTRY-TIME
// ownership snapshot — A.1 has already rewritten t.ownedNames by the
// time the loop runs, which would mark every desired tunnel "owned"
// and make adoption unreachable (and, via the EEXIST path, would
// conversely fire the MTU write on an owned tunnel during a transient
// race). One flag, both reuse paths:
adopting := !oldOwned[tc.Name]

link, err := t.ops.LinkByName(tc.Name)
mustCreate := err != nil
if err == nil && !anchorReusable(link) { LinkDel; mustCreate = true }
if mustCreate {
    anchor := &netlink.Tuntap{ ... as today (tunnel.go:124-130) ... }
    if addErr := t.ops.LinkAdd(anchor); addErr != nil {
        // EEXIST / transient-lookup race (#1706): exactly ONE
        // re-lookup; reusable TUN ⇒ adopt the KERNEL-FETCHED link;
        // anything else ⇒ warn + continue (no unbounded retry).
        if existing, lkErr := t.ops.LinkByName(tc.Name); lkErr == nil && anchorReusable(existing) {
            link = existing
            reused = true
        } else { warn; continue }
    } else { closeTuntapFiles(anchor.Fds); link = anchor; created = true }
} else { reused = true; slog.Debug("tunnel anchor reused", ...) }

// [r1: Codex F3][r2: Codex F2] MTU-set-on-ADOPT, to the DESIRED value:
// when reusing a TUN this manager did NOT own at last apply (restart
// adoption, wireguard→gre same-name flip, foreign-but-compatible TUN),
// set MTU to the config-desired value — tc.MTU (new field, populated
// by collectAppliedTunnels from the interface/unit MTU config),
// defaulting to the TUN default 1500 when unconfigured. Setting the
// DESIRED value (not blanket 1500) closes the r2 hole: the compiler
// MTU stage runs through the ZONE interface path
// (compiler_iface.go:299,449), so an UNZONED tunnel's configured MTU
// would never be restored after a 1500 reset, and the userspace
// snapshot would publish 1500 (live-MTU reads at interfaces.go:368,
// tunnels.go:106). Owned reuse with tc.MTU == 0 never touches MTU
// [r6/r7 text sync — with tc.MTU > 0 the switch below reconciles on
// every reuse; idempotent vs the compiler, same source value, both
// !=-guarded]. Closes the WG→GRE leak (the
// snapshot must not inherit the WG-reduced ~1420) with NO transient
// bounce at all.
if created && tc.MTU > 0 {
    // [r4: AGY Q2] fresh create: the Tuntap LinkAdd does not carry an
    // MTU (and TUNSETIFF may ignore LinkAttrs.MTU — the #1432 Codex r4
    // precedent that added the explicit post-create LinkSetMTU on the
    // WG path, tunnel.go:402-410). Without this, a NEW unzoned tunnel
    // with a configured MTU would sit at the kernel default 1500
    // forever (compiler restore is zone-path-only). tc.MTU == 0 needs
    // no write — the kernel default IS 1500.
    t.ops.LinkSetMTU(link, tc.MTU)
}
if reused {
    switch {
    case tc.MTU > 0:
        // [r5: AGY Q2] reconcile to the configured MTU on EVERY
        // reuse, not just adoption: the compiler stage restores MTU
        // only for ZONED interfaces, so an MTU edit on an unzoned
        // owned tunnel was previously ignored. No fighting: the
        // compiler computes the same desired value from the same
        // config and both writers guard with `!=` (idempotent).
        if link.Attrs().MTU != tc.MTU { t.ops.LinkSetMTU(link, tc.MTU) }
    case adopting:
        // No configured MTU: only ADOPTION normalizes to the TUN
        // default (WG→GRE flip repair); owned reuse leaves an
        // unconfigured MTU alone.
        if link.Attrs().MTU != 1500 { t.ops.LinkSetMTU(link, 1500) }
    }
}
// shared tail: LinkSetUp, reconcileLinkAddrs, VRF bind/unbind
```

`tc.MTU` plumbing: `config.TunnelConfig` gains an `MTU int` field
(additive; zero = unconfigured) and `collectAppliedTunnels`
(daemon_run.go:83-119) copies the owning interface's `ifc.MTU` (or the
unit's `unit.MTU` when the tunnel is unit-level and unit MTU is set —
the compiler's unit-overrides-interface precedence,
compiler_iface.go:545-553) into each emitted TunnelConfig. The legacy
CLI path leaves it 0 ⇒ default 1500 on adopt, today's effective value.

This preserves the #1706 invariant (operate on the kernel-fetched link;
the `hiddenUntil`/`addExisting` race tests in iface_reuse_test.go:29,
114-152 keep passing — the EEXIST fallback is retained, not collapsed
away [r1: AGY critical 2]).

**A.4 — shared symmetric address reconciliation** [r1: Codex F2
folded]. Extract a helper
`reconcileLinkAddrsLocked(link, name string, addrs []string, applied map[string]bool)`:
- add configured-but-missing addresses;
- delete present-but-unconfigured NON-link-local addresses (drift
  repair, as the WG block does today);
- delete a present-but-unconfigured LINK-LOCAL address ONLY if it is in
  `applied` — the per-link record `t.appliedAddrs[name]` of addresses
  this manager itself configured (`applied == nil` is the WG sentinel:
  skip ALL link-local deletion, current WG semantics — guard is
  `applied != nil && applied[key]` to avoid the nil-map read [r2: AGY
  note]). Blanket-skipping link-local (the WG
  precedent, tunnel.go:452-453) would leak CONFIGURED fe80 addresses
  forever once removed from config (GRE unit tunnels DO configure fe80
  — compiler_interfaces.go:648 populates unit addresses; e.g.
  parser_cluster_test.go:1143 `fe80::8/64`), while deleting ALL stale
  link-local would tear down the kernel's autoconf fe80 (which the WG
  comment correctly protects). The applied-set split serves both.
- update `t.appliedAddrs[name]` to: addresses now ensured (successful
  or already-present adds of configured addresses) **∪ link-local
  addresses whose stale-delete FAILED** [r2: Codex F4] — dropping a
  failed-delete LL from `applied` would orphan it forever (still
  present in the kernel, never again deletable by the LL rule); keep it
  tracked until `AddrDel` succeeds or the address is observed absent.

WG branch: extraction reuses the helper but passes a nil applied-set
sentinel preserving its current blanket-LL-skip behavior byte-identical
(#1432 invariant); the WG configured-LL leak is real but pre-existing —
filed as a follow-up, not smuggled into this change.

Restart residual: `appliedAddrs` is not persisted; a configured fe80
removed from config WHILE the daemon was down survives adoption. Same
residual class as stale-anchor orphans (§10), documented.

**A.5 — VRF bind, and unbind ONLY what this manager bound** [r2: Codex
F3 folded — the v2 "exclusive ownership" invariant was FALSE]. All
branches keep `BindInterfaceToVRF` when `tc.RoutingInstance != ""`.
Unbind rule: the daemon's step 0a (`daemon_apply.go:216-231`) binds
`routing-instances <ri> interface` members — explicitly INCLUDING
tunnel names (`gr-0/0/0.0` → `gr-0-0-0` unit-strip in that loop) —
BEFORE ApplyTunnels runs, so a tunnel bound via the RI interface list
but carrying no `tunnel routing-instance` stanza would be bound at 0a
and then wrongly unbound by a blanket
`RoutingInstance=="" ∧ MasterIndex!=0 ⇒ LinkSetNoMaster`. (Today's
recreate also destroys the 0a binding — the tunnel ends every apply
unbound — but re-breaking it deliberately is not "preserving"
anything.) Instead the manager tracks `t.appliedRI map[string]string`
— the RI IT bound per tunnel — and calls `LinkSetNoMaster` only when
ALL of [r3: Codex blocker; r4: Codex + AGY convergent residual]:
- `appliedRI[name] != ""` (we bound it),
- `tc.RoutingInstance == ""` (stanza no longer wants it),
- `tc.RIListMember == ""` [r4: SAME-VRF veto] — the desired config
  does not list this tunnel in ANY `routing-instances <ri> interface`
  list. New additive `TunnelConfig.RIListMember` field, populated by
  `collectAppliedTunnels` by scanning `cfg.RoutingInstances[*]
  .Interfaces` with a SHARED normalization helper extracted from step
  0a's literal transform (`config.LinuxIfName` + `.0`-unit strip, skip
  `instance-type forwarding`, daemon_apply.go:218-237) and used by
  BOTH 0a and the scan so they can never diverge [r5: AGY/Codex Q1
  reconciliation]. LAST match wins, matching 0a's iteration order
  (last bind wins). Deliberately exact 0a parity, NOT
  `ResolveKernelIfName`: per-unit tunnels are named `uN`
  (compiler_interfaces.go:226-233) while 0a binds the literal `.N`
  form — so for unit>0 tunnels 0a's bind FAILS TODAY (pre-existing 0a
  bug: the `.N` device does not exist) and the veto correctly mirrors
  what 0a ACTUALLY binds (Codex r5 Q1). Fixing 0a's unit>0 naming is
  a follow-up issue (§10) and, via the shared helper, automatically
  carries the veto with it (AGY r5 F1 resolved structurally). Without
  this veto, a single commit moving the SAME VRF from tunnel-stanza
  to RI-list passes the identity check (the master genuinely IS the
  VRF we bound — 0a just re-bound the same device) and the unbind
  strips the fresh list-bind intent (r4 convergent counterexample).
  Veto over reordering: AGY's daemon_apply stage-reorder alternative
  is rejected — step 0a binds many non-tunnel members (and reordering
  would not fix the naming mismatch either, AGY r5 concurrence). The
  legacy CLI path leaves the field empty — no veto, today's
  semantics.
- **the link's CURRENT master is still the VRF we bound**: resolve
  `t.ops.LinkByName("vrf-" + appliedRI[name])` — the `vrf-` prefix is
  the daemon's VRF device naming (`BindInterfaceToVRF`, vrf.go:127;
  the bare RI name NEVER resolves and would have made unbind
  permanently unreachable [r4: AGY F1]) — and require its `Index` ==
  `link.Attrs().MasterIndex`. Index mismatch ⇒ master is not ours ⇒
  no unbind.

Claim rule — TRANSFER, never veto-clear [r5: convergent Codex r5 Q2 =
SMR5-1; r4 AGY F4]: `appliedRI[name]` tracks the config-DESIRED RI as
applied each round. Per-tunnel update:
- stanza nonempty ⇒ bind (as today) and `appliedRI[name] = stanza RI`
  **only when `BindInterfaceToVRF` SUCCEEDS**; on bind failure (vrf.go
  lookup or LinkSetMaster error — tunnel apply logs and continues,
  tunnel.go:183-188) fall through to the OBSERVATION FALLBACK below
  [r7: Codex — symmetric with the r6 transfer guard: commit 1 binds
  A, commit 2's stanza re-bind to B FAILS leaving the kernel on
  vrf-A, a blind claim=B would mismatch-clear at commit 3 and strand
  vrf-A; the claim must only ever name a master we bound successfully
  or observed];
- OBSERVATION FALLBACK (stanza bind failed, or stanza empty with a
  list member) [r8: Codex — overlap case]: if `RIListMember != ""`
  AND the link's current master is observed to be
  `vrf-<RIListMember>` ⇒ `appliedRI[name] = RIListMember`; otherwise
  RETAIN the previous nonempty claim. The stanza and list knobs can
  legally coexist (tunnel stanza RI compiles independently of RI
  interface lists — compiler_interfaces.go:189, compiler_routing.go:
  295; validation only warns on unknown RI interfaces, compiler.go:
  915). Without the fallback, commit 2 with stanza-B-bind-FAILURE
  plus list-C (0a bound C) retains a stale claim A while the kernel
  is on C; commit 3 removing both then mismatch-clears and strands C
  (Codex r8 counterexample). With it, the claim becomes C and the
  removal unbinds C. Both-present with stanza bind SUCCESS: stanza
  wins (bind overwrote 0a's list bind in apply order — today's
  effective precedence), claim = stanza RI;
- stanza empty ∧ `RIListMember != ""` ⇒ no bind, no unbind (the
  veto), and the claim is TRANSFERRED **only after observing the
  transfer target is real** [r6: Codex]: set
  `appliedRI[name] = RIListMember` only if the link's current
  `MasterIndex` equals the index of `vrf-<RIListMember>`; otherwise
  (0a's bind to the list RI FAILED — daemon_apply.go:229-236 logs and
  continues — or the VRF device is missing) RETAIN the previous
  nonempty claim. Without this guard, commit 1 stanza-binds A, commit
  2 lists B but 0a's bind fails (kernel still mastered to vrf-A),
  the blind transfer records B, and commit 3 (list removed) compares
  claim B to master A ⇒ mismatch ⇒ clears ⇒ vrf-A is stranded
  forever (Codex r6 counterexample). v5's clear-on-veto leaked a permanent
  stale master: commit 1 stanza-binds A, commit 2 moves A to the RI
  list (veto, claim cleared), commit 3 removes the list membership —
  0a has only a bind loop (daemon_apply.go:218-237, no unbind leg),
  the manager's claim is gone, and the tunnel stays slaved to vrf-A
  forever, where today's recreate would have freed it. With transfer,
  commit 3 unbinds via the normal path; a list-ONLY tunnel (never
  stanza-bound) likewise gains correct unbind-on-list-removal — and
  the master-observed transfer guard means a FAILED 0a bind (e.g. the
  unit>0 naming bug) never creates a claim at all [r6: supersedes the
  v6 "self-clears via mismatch" story];
- stanza empty ∧ list empty ∧ `appliedRI[name] != ""` ⇒ unbind, gated
  by the identity check. Clear the entry only on (a) successful
  `LinkSetNoMaster`, (b) identity mismatch (master not ours), or (c)
  VRF device NOT-FOUND (`isLinkNotFound`-class, vrf.go:144-163 — the
  kernel frees slaves when a master is deleted, so nothing of ours
  remains). On TRANSIENT errors — `LinkByName` non-not-found error,
  or `LinkSetNoMaster` failure — RETAIN the entry so the next Apply
  retries (matching the A.1/A.4 failure-retention discipline).

Lifecycle [r3: Codex + AGY hygiene]: A.1 removal-deletion and
`clearLocked` also `delete(t.appliedRI, name)` alongside
`appliedAddrs`. Net effect: tunnel-stanza RI removal unbinds
(recreate-parity where the master is still OUR bind and no list-bind
claims it); 0a-list bindings — different-VRF AND same-VRF same-apply
replacements — are never touched (strict improvement: they now
survive the apply). networkd never manages
tunnel masters (tunnels are `daemonOwned`, compiler_iface.go:1065-1081,
AGY r1 Q2). Restart residual: `appliedRI` is not persisted — an RI
removed while the daemon was down leaves the adopted anchor bound
until the operator intervenes (same restart-residual class as §10).
Pinned by unit tests: stanza-RI removed ⇒ unbind; 0a-style foreign
master + empty stanza ⇒ NOT unbound; RI present ⇒ bind.

**A.6 — non-anchor (legacy) branch: compare-then-decide** [r1: AGY Q4 /
Codex OQ4 normalization spec]. Build the desired link as today, then if
a link with the name exists, reuse iff ALL of:
- concrete type matches (`*netlink.Gretun` / `*netlink.Iptun` /
  `*netlink.Ip6tnl`) AND `Type()` string matches (catches v4↔v6 family
  flips — both `gre` and `ip6gre` deserialize to `*Gretun`,
  link_linux.go:2130-2133, with family-derived `Type()`);
- `net.IP.Equal(Local)` and `net.IP.Equal(Remote)` (kernel returns
  4-byte v4 slices; ParseIP yields 16-byte — never bytewise compare);
- TTL equal after defaulting config 0 → 64;
- `IKey`/`OKey` equal (Gretun; config 0 = unset both); `Proto` equal
  (Ip6tnl, == 4 for IPIP-over-v6);
- explicitly NOT compared: `PMtu`, `Tos`, flags, encapsulation limit —
  kernel-populated or mutated post-create (the `ip ... encaplimit none`
  exec, tunnel.go:259-269); comparing them would re-flap every ip6gre
  tunnel per commit, restoring the bug. IKey/OKey byte-order round-trip
  pinned by unit test on kernel-shaped fixtures.

Reuse ⇒ skip LinkAdd + skip encaplimit exec, run shared tail. Mismatch
⇒ `LinkDel` + `LinkAdd` (today's behavior, now only on a REAL change)
+ keepalive restart per A.7.

**A.7 — keepalive reconcile (LEGACY BRANCH ONLY)** [r1: SMR1-2, Codex
F1/F5, AGY critical 1 folded]. Scope: the anchor branch `continue`s at
tunnel.go:191 BEFORE the keepalive start at tunnel.go:304 — keepalives
exist ONLY on the legacy non-anchor branch today, and this plan
preserves that exactly (no probes are added to anchors).

- Identity = `(remote, interval, maxRetries)` with `maxRetries`
  NORMALIZED through the same `<=0 ⇒ 3` default `startKeepalive`
  applies (tunnel.go:533-535) BEFORE comparison — comparing raw config
  `0` against stored `3` would restart the runner every apply
  [r1: Codex F5].
- No runner, OR identity changed, OR the tunnel was (re)created this
  apply ⇒ (re)start via existing `startKeepalive` (which already
  stops+drains a predecessor, tunnel.go:528-531), AFTER the recreate
  completes. `Keepalive == 0` with a live runner ⇒ stop it. Removed
  tunnels ⇒ stopped in A.1.
- Identity unchanged on a reused tunnel ⇒ runner left alone, preserving
  probe state — **and the shared tail's `LinkSetUp` is SKIPPED when the
  retained runner's `state.Up == false`** (read under `state.mu`).
  Without this, Apply strands the link admin UP forever:
  `keepaliveLoop`'s down-transition is gated on `state.Up == true`
  (tunnel.go:587) — once Up=false, failing probes never re-issue
  `LinkSetDown` (Codex F1 + AGY critical 1 converged worked trace;
  today's clear-all masked it by resetting `state.Up = true` on every
  restart). Recovery still works: a succeeding probe takes the
  `!state.Up` branch (tunnel.go:574-582) and brings the link up.

**A.8 — daemon-restart adoption falls out.** After restart `ownedNames`
is empty; A.1 deletes nothing; A.3 finds the existing TUN anchor by
name, passes the reuse checks (it was created by this code: TUN, NO_PI,
persistent) and adopts it — with the one-time MTU set to the
config-desired value (tc.MTU, else 1500). Anchors survive daemon
restarts with stable ifindex.

### Log contract

- `tunnel anchor created` / `tunnel created` — only on real create.
- `replacing non-TUN tunnel anchor` / `tunnel replaced` (legacy attr
  change) — only on real recreate, with reason.
- `tunnel anchor reused` at Debug — per-commit, must not spam Info
  (Logging Rules).
- `removed existing tunnel link before apply` — deleted with the
  pre-loop delete.

## 6. Public API preservation

Unchanged: `Manager.ApplyTunnels`, `Manager.ClearTunnels`,
`Manager.GetTunnelStatus`, `Manager.GetKeepaliveState`,
`tunnelManager.Apply/Clear/stopAll/GetStatus/GetKeepaliveState`
signatures. `config.TunnelConfig` gains additive `MTU int` (zero =
unconfigured) [r2: Codex F2] and `RIListMember string` (the
routing-instance whose interface LIST names this tunnel, after 0a
normalization; empty = none) [r4] fields; existing constructors
unaffected, consumers verified additive-safe (r3). Internal-only: `linkOps` gains `LinkSetNoMaster`; `tunnelManager`
gains `ownedNames`, `appliedAddrs`, `appliedRI`; `keepaliveRunner`
gains normalized identity fields; `stopKeepaliveLocked` (cancel +
drain + map delete) + `reconcileLinkAddrsLocked` + `anchorReusable`
helpers added.

## 7. Hidden invariants the change must preserve

- **Operate on the kernel-fetched link** (#1706): every
  LinkSetUp/AddrAdd/AddrList/LinkSetMTU on a reused/adopted link uses
  the `LinkByName`-returned object (real ifindex), never a fresh
  ifindex-less struct. The `hiddenUntil` race tests pin this.
- **`closeTuntapFiles` only on freshly-created anchors** — kernel-
  fetched Tuntap has nil Fds; keep the call on the create path only.
- **Keepalive drain discipline (#848)**: every stop must
  `cancel(); <-done`; `stopAll` semantics unchanged for `Close()`.
- **Lock ordering**: everything stays under `t.mu`;
  `BindInterfaceToVRF` takes no lock (vrf.go) — unchanged. Reading
  `state.Up` takes `state.mu` nested under `t.mu` — same nesting
  GetStatus already uses (tunnel.go:719-731); keepaliveLoop takes
  `state.mu` without `t.mu`, no inversion.
- **WG branch behavior byte-identical** (A.4 extraction passes the
  blanket-LL-skip sentinel; #1432/#1736 invariants — untracked device,
  MTU reconcile, TUN-type check — untouched).
- **clearLocked semantics for explicit Clear()/shutdown unchanged**.
- **encaplimit exec** (ip6gre, tunnel.go:253-270) runs only when the
  device was actually (re)created.
- **MTU ownership**: with `tc.MTU > 0` the manager and the compiler
  write the SAME config-derived value (`!=`-guarded, idempotent, no
  fighting); with `tc.MTU == 0` the manager writes only the one-time
  adoption normalization to 1500 and never touches an owned reuse.
- **Cross-side contract (#1881/#1887)**: anchor delete remains the ONLY
  signal the Rust TUN reader gets; legitimate recreates still produce a
  clean delete→create sequence, never a mutate of an incompatible
  device into a TUN.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | The destructive apply accidentally guaranteed convergence (delete-all ⇒ no stale state). Reuse must explicitly reconcile addrs (A.4), VRF (A.5), keepalive/admin-state (A.7), MTU-on-adopt (A.3); a missed dimension = silent drift. Mitigated by the r1-driven folds + symmetric-reconcile tests + live validation. |
| Lifetime/locking | LOW | All under existing `t.mu`; keepalive drain pattern reused; `state.mu` nesting matches GetStatus precedent. |
| Performance | NONE→positive | Strictly fewer netlink ops per commit; no hot path. |
| Architectural mismatch | LOW | Generalizes the in-file #1432 WG pattern; matches the project-wide networkd reconcile-without-churn idiom. |

## 9. Test plan

Unit (extend `fakeLinkOps` — add LinkDel/LinkSetNoMaster/LinkSetMTU/
AddrDel recording + AddrList over recorded addrs + seedable
Tuntap flags/persist/MTU; new `pkg/routing/tunnel_reconcile_test.go`):
1. Same config applied twice → zero LinkDel/LinkAdd on second apply;
   LinkSetUp on the SEEDED (kernel-fetched) object; no MTU write.
2. Fresh manager + seeded compatible TUN (restart adoption) → reused,
   tracked; MTU 1400 seeded, no config MTU → LinkSetMTU(1500) exactly
   once; config MTU 9000 (unzoned-tunnel case) → LinkSetMTU(9000);
   second apply (now owned), tc.MTU==0, MTU re-seeded differently →
   NO MTU write; second apply (owned), tc.MTU==9000, MTU drifted →
   reconciled (row 6b rule) [r7: Codex text sync]; EEXIST-race reuse
   on an OWNED name, tc.MTU==0 → NO MTU write [r2: Codex F1].
3. Seeded dummy / PI-TUN (no NO_PI) / NonPersist TUN with anchor name →
   deleted + recreated.
4. Tunnel removed from config → deleted + keepalive stopped AND its
   `t.keepalives` entry removed (GetKeepaliveState returns nil) [r2:
   SMR2-2], others untouched; removal after a FAILED intermediate
   apply (ownedNames vs success-set) → still deleted; removal whose
   LinkDel FAILS → name retained in ownedNames and deletion retried
   on the next Apply [r2: Codex F5].
5. Address edit → AddrAdd new + AddrDel stale; configured fe80 removed
   → deleted (in appliedAddrs); foreign/kernel fe80 never deleted;
   fe80 stale-delete failure → stays in appliedAddrs and is retried
   [r2: Codex F4]; zero LinkDel.
6. Stanza-RI removed, master still ours, no RI-list membership →
   LinkSetNoMaster against `vrf-<ri>` (prefix pinned [r4: AGY F1]) +
   entry cleared; stanza→list move of the SAME VRF in one commit →
   NOT unbound (veto), claim TRANSFERRED to the list RI [r5:
   convergent]; stanza→list→list-removed across three commits →
   unbound at the third (the v5 clear-on-veto leak, pinned) [r5:
   Codex Q2 / SMR5-1]; list-ONLY bind then list removed → unbound via
   transferred claim; stanza-A → list-B with 0a bind FAILED (master
   still vrf-A) → claim RETAINED as A (guarded transfer), then list
   removed → A unbound [r6: Codex counterexample]; list-veto with 0a
   bind failed and NO prior claim → no claim created; stanza re-bind
   A→B where BindInterfaceToVRF FAILS (no list member) → claim
   retained as A, later stanza/list removal unbinds A [r7: Codex
   stanza-guard symmetry]; stanza-B-bind-FAILS + list-C with 0a bound
   C (overlap) → claim becomes C via observation fallback, removing
   both then unbinds C [r8: Codex counterexample]; stanza-B bind
   SUCCESS + list-C → claim B (stanza wins);
   stanza removed, master replaced same-apply by a DIFFERENT VRF →
   NOT unbound (identity mismatch), entry cleared [r3: Codex blocker];
   0a-style master with appliedRI empty → NOT unbound [r2: Codex F3];
   VRF device not-found → NOT unbound, entry cleared; TRANSIENT
   LinkByName/LinkSetNoMaster failure → entry RETAINED and unbind
   retried next apply [r4: AGY F4]; RI present → BindInterfaceToVRF;
   tunnel removed/cleared → appliedRI entry deleted.
6b. Created tunnel with config MTU (zoned or not) → explicit
   LinkSetMTU(tc.MTU) on create; created with tc.MTU==0 → no MTU
   write [r4: AGY Q2]; owned reuse with tc.MTU edited (unzoned) →
   reconciled [r5: AGY Q2]; owned reuse tc.MTU==0 with drifted MTU →
   NOT touched.
6c. RIListMember scan parity fixture: `gr-0/0/0.0` matches the base
   anchor; bare `gr-0/0/0` matches; `gr-0/0/0.1` does NOT match the
   `u1` device (exact 0a parity pinned against the shared helper);
   forwarding-type RI skipped; two RIs listing the same tunnel →
   LAST wins [r5: Q1].
7. Legacy: identical GRE attrs (kernel-shaped: 4-byte IPs, TTL 64,
   round-tripped keys) → reuse; changed Destination → delete+recreate;
   v4→v6 endpoints → recreate (Type() flip); Key set↔unset → recreate;
   PMtu/Tos/encaplimit differences alone → reuse (no flap).
8. Keepalive: unchanged params (incl. retry 0 vs default 3) → same
   runner survives, no restart; changed interval → restarted; runner
   state.Up==false + unrelated re-apply → LinkSetUp SKIPPED; recreate →
   restarted after recreate.
9. EEXIST race (`hiddenUntil`/`addExisting`) → adopts kernel-fetched
   link (existing iface_reuse_test.go cases keep passing, re-pointed).
10. WG branch: existing wireguard tests pass unchanged (byte-identical
    extraction).

Gates (unmasked, `echo $?`): `go build ./...`, `go vet ./...`,
`make test` (full Go suite). No Rust changes — no cargo gate.

Live (loss userspace cluster, via
`test/incus/with-cluster.sh "1884 validation" -- ...`; the #1887 agent
may hold the lock — WAIT; deploy wipes CoS — re-apply after):
- Record `ip -o link show gr-0-0-0` ifindex; commit an UNRELATED config
  change; ifindex unchanged, no `removed existing tunnel link` /
  link-down journal events, FRR quiet.
- Tunnel attr edit (anchor address change): ifindex unchanged, address
  updated in place.
- `systemctl restart xpfd`: anchor adopted (ifindex stable across
  restart), local-origin traffic resumes.

## 10. Out of scope (explicitly)

- Rust-side TUN reader lifecycle — owned by #1881/PR #1887.
- WG removed-tunnel teardown leak (#1432 AGY M1) — owned by S6 #1434.
- WG configured-link-local stale-address leak (same class as Codex r1
  F2 but on the WG branch, pre-existing) — file follow-up issue at
  /engineer time.
- WG VRF unbind-on-RI-removal — noted, default out.
- `LinkModify`-based in-place GRE re-point for the legacy branch.
- Stale anchors orphaned while the daemon was down (not in `ownedNames`,
  not in config) — leaked today, leaked after; ditto stale
  `appliedAddrs` link-local across restart. Separate issue if it bites.
- **Step-0a unit>0 tunnel naming bug** [r5: AGY F1]: 0a normalizes RI
  list entries to the literal `.N` form while per-unit tunnel devices
  are named `uN` (compiler_interfaces.go:226-233), so 0a's bind fails
  for unit>0 tunnels TODAY. Pre-existing; file follow-up issue at
  /engineer time. The shared normalization helper this plan extracts
  means the eventual fix automatically carries the RIListMember scan
  with it.
- `pkg/cli/apply.go` legacy path behavior beyond what A.6 changes.

## 11. Open questions for adversarial review (round 9 — final ratification)

Folded from r8 (Codex task-mqan0vrp-wpr5br): the claim-update rule is
now a single ordered procedure — (1) stanza nonempty: bind; success ⇒
claim = stanza RI; (2) on stanza-bind failure OR stanza empty: if
`RIListMember != ""` and the observed master IS `vrf-<RIListMember>`
⇒ claim = RIListMember; (3) otherwise retain the previous nonempty
claim; (4) config wants none ⇒ identity-gated unbind with the
established lapse/retention rules. Invariant: a claim is written only
from a successful bind or a direct observation; both-knobs overlap is
legal config and resolves stanza-wins on success, observation on
failure.

1. Is the ordered claim procedure now exhaustive over (stanza ∈
   {∅, bind-ok, bind-fail}) × (list ∈ {∅, 0a-ok, 0a-fail}) ×
   (prior claim ∈ {∅, stale, fresh}) — any cell that strands an
   owned master or unbinds a foreign one?
2. Any other defect or re-opened closure in the r8 fold?

Settled r2: LinkSetUp skip keyed on runner-down; appliedAddrs
best-effort + AddrDel-failure retention; A.6 field list; ownedNames
staleness today-parity. Settled r3 (Codex + AGY convergent evidence):
MTU precedence `unit.MTU > 0 ? unit.MTU : ifc.MTU` matches the
compiler (compiler_iface.go:449→549 ordering, inet6-min parse at
compiler_interfaces.go:537); TunnelConfig.MTU additive-safe (HA sync
is config-text — daemon_ha_sync.go:335 / cluster sync.go:172;
userspace snapshot maps explicit fields; configstore JSON additive;
String() explicit); ownedNames growth bounded (not-found path prunes);
upgrade-boot adoption write is convergence not churn; no r1 closure
re-opened.

(The r3-era questions that previously closed this section were
answered and superseded across r4-r8; see the per-round review docs.)

## 12. Convergence record

CONVERGED at round 9 on v9 @ b2163ce9509b: Codex
(task-mqangyjc-do7knl) PLAN-READY; AGY (adversarial-review-
mqan7eor-goab38) PLAN-READY with a full 27-cell claim-procedure sweep
(no cell strands an owned master or unbinds a foreign one); Claude SMR
(claude-smr-plan-r9.md) PLAN-READY with the matching induction
argument. Codex's only residual note was this section's stale r3 text
(non-blocking, fixed in this revision).
