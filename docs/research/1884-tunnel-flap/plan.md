# #1884 — GRE tunnel anchors flap on every applyConfig: reconcile-in-place plan

## 1. Status

DRAFT v2 — r1 verdicts: Codex PLAN-NEEDS-REVISION (5 findings), AGY
PLAN-NEEDS-REVISION (2 critical + Q-answers), Claude SMR
PLAN-NEEDS-REVISION (2 MAJOR; its Q3 answer was refuted by AGY/Codex
and retracted). All r1 findings folded below; revision markers `[r1:*]`.

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
when files actually change). The cost: ~200 lines of reconcile logic in
one file plus tests. Blast radius is `pkg/routing/tunnel.go` only (plus
the `linkOps` test fake). No Rust-side change: the #1881/#1887 lane owns
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
- **MTU ownership** [r1: Codex F3 / AGY Q7]: tunnel-anchor MTU is owned
  DOWNSTREAM of ApplyTunnels — `pkg/dataplane/compiler_iface.go:351,
  452,553` apply config-driven `LinkSetMTU` later in the same
  applyConfig run, and the userspace snapshot reads the LIVE link MTU
  into tunnel endpoints (`pkg/dataplane/userspace/interfaces.go:375`,
  `tunnels.go:113`). The reconcile must not fight that owner.

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
for name := range t.ownedNames {
    if desired[name] { continue }
    t.stopKeepaliveLocked(name)          // new: per-name stop+drain
    delete(t.appliedAddrs, name)
    if link, err := t.ops.LinkByName(name); err == nil {
        _ = t.ops.LinkDel(link)          // log per current clearLocked
    }
}
t.ownedNames = desired
t.tunnels = nil // rebuilt by the loop (GetStatus source, as today)
```

Restart bootstrap: empty `ownedNames` ⇒ deletes nothing ⇒ adoption.
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
            adopted = true
        } else { warn; continue }
    } else { closeTuntapFiles(anchor.Fds); link = anchor; created = true }
} else { adopted = (not in t.ownedNames); slog.Debug("tunnel anchor reused", ...) }

// [r1: Codex F3] MTU-reset-on-ADOPT: when reusing/adopting a TUN this
// manager did NOT own at last apply (restart adoption, wireguard→gre
// same-name flip, foreign-but-compatible TUN), reset MTU to the TUN
// default 1500 iff it differs. Owned reuse (name ∈ ownedNames at
// entry) NEVER touches MTU — config-driven MTU is owned downstream
// (compiler_iface LinkSetMTU, same applyConfig run, AFTER this), so a
// per-commit reset here would bounce MTU against that owner every
// commit. Adoption-reset bounces at most once per daemon lifetime and
// is corrected by the compiler stage milliseconds later, with no
// ifindex change. Closes the WG→GRE leak: the dataplane snapshot
// reads live MTU (interfaces.go:375, tunnels.go:113) and must not
// inherit the WG-reduced ~1420.
if adopted && link.Attrs().MTU != 1500 { t.ops.LinkSetMTU(link, 1500) }
// shared tail: LinkSetUp, reconcileLinkAddrs, VRF bind/unbind
```

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
  this manager itself configured. Blanket-skipping link-local (the WG
  precedent, tunnel.go:452-453) would leak CONFIGURED fe80 addresses
  forever once removed from config (GRE unit tunnels DO configure fe80
  — compiler_interfaces.go:648 populates unit addresses; e.g.
  parser_cluster_test.go:1143 `fe80::8/64`), while deleting ALL stale
  link-local would tear down the kernel's autoconf fe80 (which the WG
  comment correctly protects). The applied-set split serves both.
- update `t.appliedAddrs[name]` to the addresses now ensured.

WG branch: extraction reuses the helper but passes a nil applied-set
sentinel preserving its current blanket-LL-skip behavior byte-identical
(#1432 invariant); the WG configured-LL leak is real but pre-existing —
filed as a follow-up, not smuggled into this change.

Restart residual: `appliedAddrs` is not persisted; a configured fe80
removed from config WHILE the daemon was down survives adoption. Same
residual class as stale-anchor orphans (§10), documented.

**A.5 — VRF bind AND unbind** [r1: Codex OQ2 invariant stated]. All
branches keep `BindInterfaceToVRF` when `tc.RoutingInstance != ""`.
When `tc.RoutingInstance == ""` and the reused link reports
`MasterIndex != 0`, call `t.ops.LinkSetNoMaster(link)` — the recreate
this replaces implicitly cleared VRF membership. **Stated ownership
invariant**: a tunnel link's master is owned EXCLUSIVELY by
`TunnelConfig.RoutingInstance` — tunnel interfaces are `daemonOwned`
and excluded from networkd management
(compiler_iface.go:1065-1081, AGY r1 Q2 evidence), and the
routing-instance binds at daemon_apply.go:216 run BEFORE ApplyTunnels
and target non-tunnel member interfaces. Pinned by a unit test (RI
removed ⇒ LinkSetNoMaster; RI present ⇒ bind; no other master writer).

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
persistent) and adopts it — with the one-time MTU normalization to
1500. Anchors survive daemon restarts with stable ifindex.

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
signatures, `config.TunnelConfig`. Internal-only: `linkOps` gains
`LinkSetNoMaster`; `tunnelManager` gains `ownedNames`, `appliedAddrs`;
`keepaliveRunner` gains normalized identity fields;
`stopKeepaliveLocked` + `reconcileLinkAddrsLocked` + `anchorReusable`
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
- **MTU ownership**: owned-reuse never writes MTU (compiler_iface owns
  it); only adoption normalizes, once.
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
   tracked; MTU 1400 seeded → LinkSetMTU(1500) exactly once; second
   apply (now owned) with MTU re-seeded 1400 → NO MTU write.
3. Seeded dummy / PI-TUN (no NO_PI) / NonPersist TUN with anchor name →
   deleted + recreated.
4. Tunnel removed from config → deleted + keepalive stopped, others
   untouched; removal after a FAILED intermediate apply (ownedNames vs
   success-set: seed LinkDel failure on a collision) → still deleted.
5. Address edit → AddrAdd new + AddrDel stale; configured fe80 removed
   → deleted (in appliedAddrs); foreign/kernel fe80 never deleted;
   zero LinkDel.
6. RI removed → LinkSetNoMaster; RI present → BindInterfaceToVRF.
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
- `pkg/cli/apply.go` legacy path behavior beyond what A.6 changes.

## 11. Open questions for adversarial review (round 2)

1. A.3 MTU-reset-on-adopt: is `adopted ∧ MTU≠1500 ⇒ LinkSetMTU(1500)`
   the right ownership boundary, or does any path exist where the
   compiler stage does NOT follow in the same applyConfig run to
   restore a config-driven MTU (leaving the one-time 1500 reset live on
   an operator-MTU tunnel until the next commit)?
2. A.4 applied-set link-local rule: any hole where a CONFIGURED fe80 is
   absent from `appliedAddrs` at removal time other than the documented
   daemon-restart residual (e.g. AddrAdd transient failure on the apply
   that introduced it)? Is best-effort acceptable there?
3. A.7 skip-LinkSetUp-on-down-runner: does skipping LinkSetUp interact
   badly with a tunnel whose link someone ELSE downed (operator
   `ip link set down`) while the keepalive runner is up — i.e. should
   the skip be keyed strictly on runner-down, as proposed?
4. A.1 ownedNames: any caller sequence (Apply → Clear → Apply, CLI
   standalone path) where ownedNames goes stale relative to the kernel
   in a way that deletes a link the manager should not own?
5. A.6: any remaining kernel-normalization trap in Gretun/Iptun/Ip6tnl
   readback (e.g. EncapType/EncapFlags defaults, LinkAttrs.Flags) that
   makes the field-list comparison return false-"changed" and silently
   restore the per-commit flap?
6. Is the one-time adoption MTU bounce (1500 → compiler-restored value,
   same apply run) acceptable for FRR/dataplane consumers, or must
   adoption read the desired MTU from somewhere to avoid the bounce
   entirely?

If any answer exposes a structural flaw, PLAN-KILL remains an
acceptable verdict.
