# #1884 — GRE tunnel anchors flap on every applyConfig: reconcile-in-place plan

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

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
when files actually change). The cost: ~150 lines of reconcile logic in
one file plus tests. Blast radius is `pkg/routing/tunnel.go` only (plus
the `linkOps` test fake). No Rust-side change: the #1881/#1887 lane owns
the TUN-reader lifecycle; this fix simply makes Go-side recreates rare
(type-mismatch only), and on a legitimate recreate the contract is
#1887's tombstone→respawn.

If reviewers conclude the fix shape is wrong or the churn is unjustified,
PLAN-KILL is an acceptable verdict.

## 4. What's already shipped / composes with this

- **#1432 S2a** — `applyWireguardTunLocked`: the proven reuse-in-place
  pattern this plan generalizes (TUN-type check, create-vs-reuse split,
  symmetric address reconciliation skipping link-local, VRF bind).
- **#1706** — `anchorReady` reuse path on LinkAdd-EEXIST
  (tunnel.go:135-149) + `fakeLinkOps` test harness
  (`pkg/routing/iface_reuse_test.go`). Today that reuse path is dead in
  practice: the pre-loop delete removes the link before LinkAdd can hit
  EEXIST (it only fires when the pre-loop `LinkByName` transiently
  misses).
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

## 5. Concrete design

### Path options considered

**Path A — full reconcile (recommended).** Diff desired vs actual per
tunnel: create missing, delete removed (set-diff, not clear-all),
reuse-in-place when compatible, recreate only on genuinely
incompatible kernel state. Detailed below.

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

**GRE attr mutability note (Path A research).** Kernel GRE/IPIP tunnel
parameters (local, remote, ttl, ikey/okey) ARE mutable in place via
`RTM_NEWLINK` change (`ip tunnel change` / `netlink.LinkModify`); the
interface name and the link TYPE (gre ↔ ip6gre ↔ ipip ↔ ip6tnl ↔ tuntap)
are not — type change requires delete+recreate, and a v4→v6 endpoint
move IS a type change (`Gretun.Type()` auto-selects "ip6gre";
ipip-over-v6 uses `Ip6tnl`). For TUN anchors (the production path) there
are NO tunnel attrs on the kernel device at all — Source/Destination/Key
live only in the dataplane snapshot — so an anchor recreate is needed
ONLY on link-type mismatch. Given that, Path A deliberately does NOT use
`LinkModify` for the legacy non-anchor branch: attr changes there get
delete+recreate (a legitimate flap on a real tunnel re-point, legacy
path only). This keeps `linkOps` narrow and avoids shipping a
modify-path we cannot live-validate (the production cluster never runs
non-anchor tunnels).

### Path A mechanics

All changes inside `pkg/routing/tunnel.go`; `linkOps` gains one method.

**A.1 — set-diff removal replaces clear-all.** `Apply` no longer calls
`clearLocked()`. Instead:

```go
desired := make(map[string]bool, len(tunnels))
for _, tc := range tunnels {
    if tc.Mode != "wireguard" { desired[tc.Name] = true }
}
// Delete tracked tunnels that are no longer configured; stop their
// keepalives. (WG devices stay untracked/persistent per #1432 AGY M1.)
for _, name := range t.tunnels {
    if desired[name] { continue }
    t.stopKeepaliveLocked(name)          // new: per-name stop+drain
    if link, err := t.ops.LinkByName(name); err == nil {
        _ = t.ops.LinkDel(link)          // log per current clearLocked
    }
}
```

`t.tunnels` is reset before the loop and rebuilt during it as today
(apply-failure ⇒ untracked, unchanged). `Clear()` / `clearLocked()`
keep their delete-everything semantics — note `Manager.ClearTunnels`
currently has ZERO callers (grep: only the wrapper definition in
routing.go:148), and `stopAll()` (Close path) only stops keepalives. So
`Apply` is the only production path that exercised clear-all, which
bounds Q1.

**A.2 — pre-loop delete (tunnel.go:113-121) is removed entirely.** Each
branch now starts from `LinkByName` and decides reuse vs recreate
itself.

**A.3 — anchor branch becomes reuse-first** (mirrors
`applyWireguardTunLocked`, minus MTU):

```go
link, err := t.ops.LinkByName(tc.Name)
mustCreate := err != nil
if err == nil {
    tt, isTun := link.(*netlink.Tuntap)
    if !isTun || tt.Mode != netlink.TUNTAP_MODE_TUN {
        // dummy-anchor upgrade, leftover kernel gre device from a
        // dataplane-type transition, TAP collision, ...
        slog.Info("replacing non-TUN tunnel anchor", "name", tc.Name,
            "type", link.Type())
        if delErr := t.ops.LinkDel(link); delErr != nil { warn; continue }
        mustCreate = true
    }
}
if mustCreate {
    anchor := &netlink.Tuntap{ ... as today ... }
    if err := t.ops.LinkAdd(anchor); err != nil { warn; continue }
    closeTuntapFiles(anchor.Fds)
    link = anchor
    slog.Info("tunnel anchor created", ...)
} else {
    slog.Debug("tunnel anchor reused", "name", tc.Name)
}
// shared tail: LinkSetUp, reconcileLinkAddrs, VRF bind/unbind
```

The `goto anchorReady` EEXIST fallback collapses into this shape (the
LinkAdd-EEXIST race — link appears between LinkByName and LinkAdd — is
handled by one retry through the same lookup, preserving the #1706
"operate on the kernel-fetched link" invariant).

**A.4 — shared symmetric address reconciliation.** Extract the WG
address block (tunnel.go:436-476) into
`reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string)`:
add configured-but-missing, delete present-but-unconfigured, skip
kernel-managed link-local (fe80). Used by the WG branch (refactor, no
behavior change), the anchor branch, and the reused non-anchor branch.
This also fixes a latent anchor bug: today a reused anchor (EEXIST path)
only ever `AddrAdd`s — addresses removed from config persist.

**A.5 — VRF bind AND unbind.** All branches keep
`BindInterfaceToVRF` when `tc.RoutingInstance != ""`. New: when
`tc.RoutingInstance == ""` and the reused link has
`link.Attrs().MasterIndex != 0`, call `t.ops.LinkSetNoMaster(link)` —
today the recreate implicitly cleared VRF membership; reuse-in-place
must do it explicitly. `linkOps` gains `LinkSetNoMaster(netlink.Link)
error` (satisfied by `*netlink.Handle`; fake extended).
Caveat folded into the design: `MasterIndex != 0` cannot distinguish a
VRF master from any future non-VRF enslavement; for tunnel anchors the
daemon is the only writer, so unconditional unbind-on-empty-RI matches
the recreate semantics it replaces.

**A.6 — non-anchor (legacy) branch: compare-then-decide.** Build the
desired `netlink.Link` exactly as today, then if a link with the name
exists: same concrete type AND equal (local, remote, ttl, ikey, okey,
proto as applicable) → reuse in place (skip LinkAdd + skip encaplimit
exec; run shared tail). Any mismatch → `LinkDel` + `LinkAdd` (today's
behavior, now only on a REAL change). Comparison uses kernel-fetched
attrs (`*netlink.Gretun`/`*netlink.Iptun`/`*netlink.Ip6tnl`); IPs
compared with `net.IP.Equal` (kernel returns 16-byte forms). TTL
compares the defaulted value (config 0 → 64).

**A.7 — keepalive reconcile.** `keepaliveRunner` gains its config
identity `(remote string, interval, maxRetries int)`. In the apply loop:
no runner OR identity changed OR tunnel was (re)created → (re)start via
existing `startKeepalive` (which already stops+drains a predecessor);
identity unchanged on a reused tunnel → leave the running goroutine
alone (preserves `Failures`/`Up` probe state across commits). Tunnels
with `Keepalive == 0` that previously had a runner: stop it. Removed
tunnels: stopped in A.1 (new `stopKeepaliveLocked(name)` helper —
factored from `startKeepalive`'s stop+drain prologue).

**A.8 — daemon-restart adoption falls out.** After restart `t.tunnels`
is empty; A.1 deletes nothing; A.3 finds the existing TUN anchor by name
and reuses it. Anchors survive daemon restarts with stable ifindex.

### Log contract

- `tunnel anchor created` / `tunnel created` — only on real create.
- `replacing non-TUN tunnel anchor` / `tunnel replaced` (attr change,
  legacy branch) — only on real recreate, with reason.
- `tunnel anchor reused` at Debug — per-commit, must not spam Info
  (Logging Rules).
- `removed existing tunnel link before apply` — deleted with the
  pre-loop delete.

## 6. Public API preservation

Unchanged: `Manager.ApplyTunnels`, `Manager.ClearTunnels`,
`Manager.GetTunnelStatus`, `Manager.GetKeepaliveState`,
`tunnelManager.Apply/Clear/stopAll/GetStatus/GetKeepaliveState`
signatures, `config.TunnelConfig`. Internal-only: `linkOps` gains
`LinkSetNoMaster`; `keepaliveRunner` gains identity fields;
`stopKeepaliveLocked` + `reconcileLinkAddrsLocked` helpers added.

## 7. Hidden invariants the change must preserve

- **Operate on the kernel-fetched link** (#1706): every
  LinkSetUp/AddrAdd/AddrList on a reused link uses the
  `LinkByName`-returned object (real ifindex), never a fresh
  ifindex-less struct.
- **`closeTuntapFiles` only on freshly-created anchors** — kernel-
  fetched Tuntap has nil Fds (safe no-op today; keep the call only on
  the create path for clarity).
- **Keepalive drain discipline (#848)**: every stop must
  `cancel(); <-done` before the handle can be closed; `stopAll`
  semantics unchanged for `Close()`.
- **Lock ordering**: everything stays under `t.mu`;
  `BindInterfaceToVRF` takes no lock (vrf.go) — unchanged. No new
  cross-domain calls.
- **WG branch behavior byte-identical** (the A.4 extraction is
  refactor-only; #1432/#1736 invariants — untracked device, MTU
  reconcile, TUN-type check — untouched).
- **clearLocked semantics for explicit Clear()/shutdown unchanged** —
  only Apply's use of it is removed.
- **encaplimit exec** (ip6gre, tunnel.go:253-270) runs only when the
  device was actually (re)created — it is a per-create kernel attr, and
  the 15s-bounded exec must not run per-commit.
- **Cross-side contract (#1881/#1887)**: anchor delete remains the ONLY
  signal the Rust TUN reader gets; legitimate recreates (type mismatch)
  still produce a clean delete→create sequence, never a mutate of a
  non-TUN into a TUN.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | The destructive apply accidentally guaranteed convergence (delete-all ⇒ no stale state). Reuse paths must explicitly reconcile addrs (A.4), VRF (A.5), keepalives (A.7); a missed dimension = silent drift. Mitigated by symmetric-reconcile tests + live validation. |
| Lifetime/locking | LOW | All under existing `t.mu`; keepalive drain pattern reused as-is. |
| Performance | NONE→positive | Strictly fewer netlink ops per commit; no hot path. |
| Architectural mismatch | LOW | Generalizes the in-file #1432 WG pattern; matches the project-wide networkd reconcile-without-churn idiom. |

## 9. Test plan

Unit (extend `fakeLinkOps` — add LinkDel/LinkSetNoMaster/AddrDel
recording + AddrList over recorded addrs; new
`pkg/routing/tunnel_reconcile_test.go`):
1. Same config applied twice → zero LinkDel, zero LinkAdd on second
   apply; LinkSetUp on the SEEDED (kernel-fetched) object.
2. Fresh manager + seeded TUN anchor (restart adoption) → reused,
   tracked, no recreate.
3. Seeded dummy with anchor name → deleted + recreated as TUN.
4. Tunnel removed from config → its link deleted, keepalive stopped,
   others untouched.
5. Address edit on existing anchor → AddrAdd new + AddrDel stale,
   link-local preserved, zero LinkDel.
6. RoutingInstance removed → LinkSetNoMaster called; RI present →
   BindInterfaceToVRF called.
7. Legacy non-anchor: identical GRE attrs → reuse (no LinkDel); changed
   Destination → delete+recreate; v4→v6 source/dest → recreate (type
   change); Key set→unset → recreate.
8. Keepalive: unchanged params → same runner pointer survives apply;
   changed interval → restarted; Keepalive 0 → stopped.
9. Existing iface_reuse_test.go + wireguard tests pass unchanged.

Gates (unmasked, `echo $?`): `go build ./...`, `go vet ./...`,
`make test` (full Go suite). No Rust changes expected — no cargo gate.

Live (loss userspace cluster, via
`test/incus/with-cluster.sh "1884 validation" -- ...`; #1887's agent may
hold the lock — WAIT; deploy wipes CoS — re-apply after):
- Record `ip -o link show gr-0-0-0` ifindex; commit an UNRELATED config
  change; ifindex unchanged, no `removed existing tunnel link` /
  link-down journal events, FRR quiet.
- Tunnel attr edit (e.g. anchor address change): ifindex unchanged,
  address updated in place.
- `systemctl restart xpfd`: anchor adopted (ifindex stable across
  restart), local-origin traffic resumes.

## 10. Out of scope (explicitly)

- Rust-side TUN reader lifecycle — owned by #1881/PR #1887.
- WG removed-tunnel teardown leak (#1432 AGY M1) — owned by S6 #1434.
- WG VRF unbind-on-RI-removal (same gap as A.5 but on the WG branch) —
  noted; can ride along ONLY if reviewers ask, default out.
- `LinkModify`-based in-place GRE re-point for the legacy branch.
- Stale anchors orphaned while the daemon was down (not in `t.tunnels`,
  not in config) — leaked today, leaked after; separate issue if it
  bites.
- `pkg/cli/apply.go` legacy path behavior beyond what A.6 changes.

## 11. Open questions for adversarial review

1. Is removing `clearLocked()` from `Apply` safe for ALL callers —
   is any caller relying on Apply-as-full-reset (e.g. recovery flows
   that expect delete-all convergence)? PLAN-KILL if such a caller
   exists and cannot be migrated.
2. A.5 unbind: is `MasterIndex != 0 && RI == ""` → `LinkSetNoMaster`
   safe on all reused links, or can it fight another owner (networkd?)
   for tunnel anchors?
3. A.7 keeps probe state across commits — is preserving a DOWN
   keepalive state (link administratively down via keepaliveLoop) across
   an unrelated commit correct, given Apply also calls LinkSetUp on the
   reused link (resurrecting a keepalive-downed tunnel, as recreate does
   today)? Should LinkSetUp be skipped when the keepalive runner is
   retained and currently down?
4. A.6 attr comparison: are kernel-fetched Gretun fields (Ttl defaults,
   key normalization, 4-vs-16-byte IPs) reliably comparable, or does the
   comparison need normalization beyond `net.IP.Equal` + defaulted TTL?
   A false "changed" verdict silently restores today's flap.
5. Is the LinkAdd-EEXIST retry-once collapse of `goto anchorReady`
   actually equivalent to the #1706 semantics under the transient-lookup
   races its tests pin (`hiddenUntil` cases)?
6. Should the anchor reuse path verify TUN flags match what creation
   would set, or is Mode==TUN sufficient (WG precedent: Mode check
   only)? Verified: kernel-fetched Tuntap reconstructs Mode, NO_PI,
   MULTI_QUEUE and NonPersist via IFLA_TUN_* (netlink v1.3.1
   parseTuntapData); TUNTAP_ONE_QUEUE is an obsolete no-op flag
   (kernel ≥3.8) and is NOT reported back — so a flags comparison can
   only meaningfully check NO_PI/MULTI_QUEUE/persist.
7. Mode-flip `wireguard → gre` on the same name: the WG TUN is
   untracked, so A.1 does not delete it and A.3 reuses it — keeping the
   WG-reduced MTU (~1410-1425) on what is now a GRE anchor (a fresh
   anchor create would get the TUN default 1500). Flags/persist are
   identical, so the leftover is not detectable as "foreign". Should
   the anchor branch force MTU when reusing (risking clobbering an
   operator-set MTU, for which GRE TunnelConfig has no field), or is
   this rare flip acceptable as a documented residual?

If the answers expose a structural flaw (e.g. Q1 caller exists),
PLAN-KILL is an acceptable verdict.
