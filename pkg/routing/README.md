# pkg/routing

Manages static routes, GRE tunnels, VRFs, XFRM interfaces, and tunnel
keepalive probes via netlink. Tracks link state for monitored
interfaces and exposes per-tunnel up/down state via `KeepaliveState`
for weight-based failover.

This package owns netlink object lifecycles. FRR (`pkg/frr`) owns the
kernel route table; this package owns the *interfaces* routes hang off
of — and, since #7409, it also **reads** the kernel route table back for
the userspace dataplane FIB (see "Kernel-learned route import" below).

## Structure (#1698 domain split)

`Manager` (`routing.go`) is a thin **façade**: it owns the single
`*netlink.Handle` and delegates every public method to an unexported
per-domain manager. Each domain owns its own sub-state + its own lock
and depends on a narrow netlink-facing ops interface (`vrfOps`,
`routeLister`, `linkOps`, `ruleOps`) rather than the concrete handle,
which makes each domain unit-testable with a fake (see `rules_test.go`'s
`fakeRuleOps` and `routing_test.go`'s `fakeVRFOps`).

| File | Domain | Owns |
|------|--------|------|
| `routing.go` | `Manager` façade | sole `*netlink.Handle`, domain refs |
| `vrf.go` | `vrfManager` | VRF lifecycle + `BindInterfaceToVRF`; own `mu` + tracked set |
| `routes.go` | `routeReader` | kernel routing-table reads (`routeLister`) |
| `routeformat.go` | free fns | Junos `show route` formatters |
| `tunnel.go` | `tunnelManager` | GRE/IPIP + AnchorOnly TUN reconcile, VRF-claim, address, `Clear`/`GetStatus`; own `mu`. WireGuard and the keepalive runner are split into siblings below (#5661) |
| `tunnel_wireguard.go` | (part of `tunnelManager`) | WireGuard persistent-TUN lifecycle: `applyWireguardTunLocked`, inner-MTU cap (`wgTunMTUForEndpoint`, WG overhead consts), `errWGIncompatibleLinkRetained` sentinel, `closeTuntapFiles` |
| `tunnel_keepalive.go` | free fns | keepalive **prober** primitives (#1918): `tunnelProber`/`icmpProber`, `ProbeResult`, `UnsupportedKind`, ICMP-echo probe + errno classification |
| `tunnel_keepalive_runner.go` | (part of `tunnelManager`) | keepalive **runner** half (#5661): `KeepaliveState`/`keepaliveRunner`, `startKeepalive`/`stopAll`, `keepaliveLoop`/`keepaliveTick`, `GetKeepaliveState` |
| `xfrm.go` | `xfrmManager` | XFRM/IPsec interface lifecycle; own `mu` + tracked `name→if_id` set. `Apply` reconciles **differentially** against the tracked set (keep unchanged / create new / delete removed / recreate on `if_id` change) — it does NOT clear-all-then-rebuild, so an unrelated config commit leaves active xfrmi interfaces untouched (#2546). Refuses to create either of two distinct devices that derive the same `if_id` — fail-closed collision guard (#2909) |
| `rules.go` | `nextTableManager` / `ribGroupManager` / `pbrManager` | policy-routing ip-rule reconcilers (`ruleOps`, stateless) |
| `probe_pin.go` | `probePinManager` | RPM probe next-hop pin reconciler (#1827): fwmark rules in band 50-99 + pinned host routes in reserved tables 7000-7049 (`probePinOps`, stateless). `Apply` returns per-test install failures (keyed by TestKey) and rolls back the fwmark rule when the pinned route fails (best-effort — a failed rollback is swept by the next band clear; the pin reports failed either way); callers thread the failed map into `pkg/rpm` so affected tests hold state instead of probing unpinned (#1895) |
| `bond.go` | `bondManager` | bond (fabric/ae LAG) device lifecycle; own `mu` + tracked `name→bondSig` set. `Apply` reconciles **differentially** against the tracked set (keep unchanged / create new / delete removed / recreate on signature change) — it does NOT clear-all-then-rebuild, so an unrelated config commit no longer flaps the LAG (#5119, mirroring #2546) |
| `reth.go` | `rethManager` | stale `reth*` bond cleanup. `Clear` scans `LinkList` for `reth*` bond devices and deletes them; a per-bond `LinkDel` failure is aggregated with `errors.Join` and returned (NOT swallowed) so a stale reth bond left in the kernel fails the commit closed (#5704 / codex-review-182 M30, the reth analog of the #4901 xfrm/bond/tunnel `Clear` fix). Idempotent: an already-absent reth device is not returned by `LinkList`, so no `LinkDel` runs and no spurious error is produced; retry is implicit via the next reconcile's re-scan (no ownership map to retain) |
| `monitor.go` | `monitorManager` | interface-monitor HA signal; own `mu`. Link health via `linkAttrsUp` reads kernel **operstate** (`OperUp` → up; `OperUnknown` → admin-flag fallback; `OperDown`/lower-layer-down → down), **not** `IFF_UP` — admin-up-but-carrier-down (cable pulled) must report DOWN so HA fails over (#2070). Mirrors `pkg/vrrp.linkAttrsUp` and `pkg/cluster/monitor.go`. **A `LinkByName` failure is classified, not assumed absent (#8073):** `isLinkNotFound` means the interface belongs to the peer node and is dropped; any other error (ENOBUFS, EINTR, truncated netlink socket) carries the PREVIOUS pass's status forward with the current configured weight. These statuses feed `cluster.Manager.SetMonitorWeight`, so dropping one means that call never happens and the weight persists stale — a link that went down during the error would keep its last-known Up weight and the RG would not demote. The transient arm deliberately does not synthesize `Up=false`: demoting an RG on a netlink hiccup is worse than briefly stale state |

The tunnel domain depends on the VRF domain (`tunnelManager.vrfBinder`)
to bind tunnel interfaces to a routing-instance VRF;
`BindInterfaceToVRF` takes no lock, so there is no lock-ordering cycle.

### XFRM interface reconcile (#2546)

`xfrmManager.Apply` is called by `pkg/daemon` on **every** config commit
(not only IPsec changes) so xfrmi devices for deleted VPNs are torn
down. It therefore reconciles the desired xfrmi set (`name→if_id`
derived from each VPN's `bind-interface` via
`config.XFRMIfNameAndID`) against the tracked set instead of clearing
all and rebuilding:

- **keep** an interface untouched when it is still desired with the same
  `if_id` — no `LinkDel`/`LinkAdd`, so active tunnel traffic and routing
  bound to the interface survive an unrelated commit;
- **create** a newly-desired interface (also adopts a kernel link that
  outlived in-memory tracking, e.g. across a daemon restart);
- **delete** an interface whose VPN was removed;
- **recreate** (delete+create) an interface whose name is unchanged but
  whose desired `if_id` differs — `Ifid` is set at xfrmi creation and is
  not mutable in place.

A no-op commit (identical VPN set) issues zero `LinkDel` and zero
`LinkAdd`. `Clear()` (shutdown / full teardown) still deletes every
tracked interface.

**Fail-closed on genuine create/up/delete failure (#5310).** `Apply` used
to log every `LinkAdd` / find-after-create / `LinkSetUp` / `LinkDel`
failure and return `nil` **unconditionally**, so a route-based IPsec VPN
whose xfrmi could not be realized in the kernel (e.g. `LinkAdd` failed)
reported a **successful commit** while the interface — and the routes
bound to it — carried no traffic (fail-open false convergence). `Apply`
now accumulates the **genuine** netlink failures with `errors.Join` and
returns them (mirroring the #4823 bond create path and the #4901
`clearLocked` teardown path) so `pkg/daemon` fails the commit closed. The
tolerated idempotent conditions stay **non-errors**: an xfrmi that already
exists is adopted via the `LinkByName` path (re-tracked + brought up =
success, never a `LinkAdd`), and an already-gone delete returns `nil` from
`deleteLocked`. A created-but-not-brought-up xfrmi stays **tracked** (we
own the kernel link) so the next reconcile re-attempts the `LinkSetUp`; a
failed `LinkAdd` leaves it **untracked** for a clean retry. A
stale-`if_id` delete that fails skips the recreate this cycle (avoids an
`EEXIST` `LinkAdd`) and surfaces the error, matching the #5119 bond
changed-signature path.

**Only a genuine not-found may create or delete-gone (#5461 / #5495).**
Both the create/adopt lookup in `Apply` and the lookup in `deleteLocked`
used to treat **any** `LinkByName` error as "interface not present",
conflating a transient/lookup failure (`EBUSY`, `EINVAL`, timeout, netlink
transport) with genuine absence — the same class distinction the tunnel
path already draws (see the WireGuard/tunnel removal notes below and
`isLinkNotFound` in `vrf.go`).

- **#5461 (create path):** on a transient lookup error for an xfrmi that
  actually **exists**, `Apply` fell through to `LinkAdd` → `EEXIST` → a
  spurious fail-closed commit error, leaving the interface
  desired-but-untracked. `Apply` now only falls through to `LinkAdd` when
  the lookup error is a genuine not-found (`isLinkNotFound`); a transient
  error is **not** treated as absence — the entry is left tracked (retain
  ownership) and the real lookup error is surfaced so the commit fails
  closed on the genuine cause and the next reconcile retries.
- **#5495 (delete path):** `deleteLocked` took the "already gone" branch
  (drop tracking + return `nil`) on any `LinkByName` error, so a transient
  error silently **orphaned** a live kernel xfrmi (and stale
  routing/security state) while reporting convergence — a later `Apply`
  then had no removed-desired entry to drive cleanup. `deleteLocked` now
  drops tracking + reports gone **only** on a genuine not-found; a
  transient error retains the tracking entry and surfaces the error (this
  also covers the full-tunnel `Clear`/`clearLocked` path, which keeps the
  retained entry rather than nil-ing the map). The #4901 hardening only
  covered a failed `LinkDel` **after** a successful lookup; this closes the
  predating `LinkByName`-error branch.
- **#7529 (the same conflation in two SIBLING managers).** The xfrm manager
  was fixed above and the bond and tunnel managers were not, so the identical
  branch survived in two other places:
  - `bondManager.deleteLocked` dropped the name from `b.bonds` **and returned
    `nil`** on any lookup error. So xpf reported a successful delete for a bond
    still in the kernel, still enslaving its members, and no longer tracked —
    and nothing retries, because the reconcile diff keys off `b.bonds`.
  - `tunnelManager.Clear` took a bare `continue`, which leaves the name out of
    the `failed` set that `ownedNames` is rebuilt from. A live tunnel with
    stale addresses and XFRM `if_id` state became untracked, so no later
    `Apply` had a removed-desired entry to retry the delete.

  Both now release ownership **only** on `isLinkNotFound`; a transient error
  retains it and surfaces the real cause. Ownership is released **per name, on
  that name's own answer** — a `Clear` walking several owned names must release
  the genuinely-absent ones while retaining the transiently-failing one, so
  "retain everything if anything failed" is not the fix (it passes every
  single-name test and is wrong on the shape a real reconcile sees).

  Worth noting for the next sibling: the shape here is not a bug that recurred,
  it is one fix that was applied to one of three managers holding the same
  branch. When a predicate like `isLinkNotFound` is introduced, the question to
  ask is which OTHER call sites make the same conflation — grep for
  `LinkByName` with an error branch that assumes absence.

**Identity re-assertion on every post-create readback (#5523 C179-104 +
#6396).** `LinkAdd` and the `LinkByName` readback that follows it are two
syscalls. A device is adopted only after confirming the readback is the
INTENDED type — and, for xfrm and VRF, carrying the desired discriminator
too — never by name alone. The discriminator checked is per-manager: **xfrm
rejects type + `Ifid` + `ParentIndex==0`, VRF rejects type + table, and bond
rejects TYPE (`*netlink.Bond`) on ALL THREE of its create-path (#6396),
adopt-path (#6402), and KEEP-path (#6402) readbacks** (only a mode/MTU residual
remains — see the bond bullet). So a same-name foreign link (or, for xfrm/VRF, a
right-type link with the wrong discriminator) substituted by a concurrent
external actor in the add→readback window — or, for the bond adopt/KEEP paths, a
foreign link already wearing a fabric/RETH bond's name at steady state — is
rejected: it is not brought up or adopted, the name is reclaimed via
delete+recreate (or the commit fails closed on a create-path substitute), and no
foreign device is tracked as a satisfied device. This invariant now holds across
all three netlink-device managers:

- **xfrm** (`xfrm.go`) — the readback must be an `*netlink.Xfrmi` whose
  `Ifid` matches. Enforced on BOTH the adopt path (a kernel link outliving
  in-memory tracking; a non-xfrmi or stale-`if_id` link is delete+recreated,
  #5523 C179-104) and the post-create readback (#6396).
- **VRF** (`vrf.go` `createLinkedVRF`) — the readback must be an
  `*netlink.Vrf` whose `Table` matches (#6396). `added` stays true so the
  caller records ownership; the reconcile adopt path (`vrfTable` →
  recreate on table mismatch) reclaims a substitute on the next cycle.
- **bond** (`bond.go`) — ALL THREE readbacks that can bring a link up and track
  it as a satisfied bond must first re-assert `*netlink.Bond` — the **create
  path** (`createLocked` post-`LinkAdd`), the **adopt path** (`createLocked`
  steady-state reconcile branch), and the **KEEP path** (`Apply`'s
  tracked-and-unchanged fast path). `LinkByName` resolves the NAME, not the
  type, so any of the three, left ungated, would bring a same-name foreign link
  up and report convergence while NO bond carries the fabric/RETH members.
    - **create-path** gate (#6396) re-asserts the type after `LinkAdd`:
      `enslaveMembers` only surfaces a substitute via a real-netlink
      `LinkSetMaster` failure when a member is actually enslavable, so a bond
      whose configured members are all currently absent (the #4823 soft-error
      case) would otherwise adopt a foreign link; the explicit type check closes
      that hole for every member state.
    - **adopt-path** gate (#6402) re-asserts the type at the top of the
      steady-state reconcile branch (`if existing, err := LinkByName(name); err
      == nil`): a same-name foreign link already wearing a fabric/RETH bond's
      name — an external actor's device, or a leftover of a different type after
      a name collision — is reclaimed via `deleteLocked` + fall-through to the
      create path (mirroring the xfrm #5523 adopt gate and the
      `vrfTable`→recreate adopt path) rather than adopted. A `deleteLocked`
      failure leaves the foreign link present, so the recreate is skipped this
      cycle and the delete error is surfaced (commit fails closed, next reconcile
      retries the delete) — the #5119 / xfrm #5310 recreate discipline.
    - **KEEP-path** gate (#6402) re-asserts the type in `Apply`'s
      tracked-and-unchanged fast path (`if trackedSig == sig` → `LinkByName` →
      `LinkSetUp`). A tracked bond can be replaced by a same-name foreign link,
      and — because a failed `deleteLocked` retains tracking (#4901) — the
      adopt-gate delete-fail transition leaves `b.bonds[name]` still == desired
      sig with a foreign link present. Without the KEEP-path gate the next
      reconcile would bring that foreign link up and `continue`, never
      re-entering `createLocked`, never retrying the delete → false convergence
      forever. The gate falls a non-bond link through to the recreate path
      (which re-enters `createLocked`, whose adopt gate reclaims it or fails
      closed again), so `b.bonds[name]` is never presented as satisfied by a
      foreign link: `createLocked` is re-entered every reconcile until the delete
      succeeds.

  **Bond adopt/KEEP are HA-touching** (a fabric/RETH LAG reconcile change), so
  #6402 carries a loss-cluster `make test-failover` smoke; in the healthy case
  every gate is a pure pass-through (the link IS a `*netlink.Bond`), so
  steady-state reconcile of a real fabric bond is bit-identical and never
  flapped.

  The bond identity gate is now the TYPE assertion on all three readbacks. One
  narrower residual remains OPEN as further hardening (pre-existing — master
  never validated it; NOT a #6396/#6402 regression), a distinct concern from the
  type/identity-assertion readback family #6402 closed:
    1. **mode/MTU (all paths)** — the guards check the `*netlink.Bond` type
       only, then track the DESIRED `bondSig` (`sigWithMembers(sig, …)`), not the
       readback's observed mode/MTU. An `*netlink.Bond` with the wrong bond mode
       (802.3ad vs active-backup) or MTU passes and is tracked as satisfied.
  (xfrm and VRF adopt paths ARE fully gated — xfrm.go asserts type + `Ifid` +
  `ParentIndex==0`, and `vrfTable`→recreate asserts type + table. Bond now gates
  TYPE on create + adopt + KEEP; only the mode/MTU residual above remains.)

Without the check the name is tracked as satisfied while **no** device
carries the desired identity, silently blackholing the VPN / leaked routes
/ fabric LAG bound to it. (The tunnel/WireGuard manager reaches its reuse
path through a distinct anchor-reuse gate that already type-checks
`*netlink.Tuntap` — see the reuse notes below — so it is not part of this
readback family.)

### Bond (fabric/ae LAG) reconcile (#5119)

`bondManager.Apply` is called by `pkg/daemon` on **every** config commit
(not only when the bond/fabric config changes) so bonds for deleted
fabric interfaces are torn down. It therefore reconciles the desired bond
set (`name→bondSig` — mode, MTU, and the sorted resolved Linux member
set) against the tracked set instead of clearing all and rebuilding:

- **keep** a bond untouched when it is still desired with an identical
  `bondSig` **and its kernel device is still present** — no `LinkDel`/
  `LinkAdd`/`LinkSetMaster`, so an unrelated policy-only commit no longer
  flaps the LAG (`LinkDel`→`LinkAdd`→re-enslave→LACP re-converge, traffic
  loss on the bond). The keep verifies the kernel device via `LinkByName`
  before declaring convergence: a tracked, still-desired bond that has
  **vanished** from the kernel (deleted out from under the daemon — an
  operator `ip link del`, a driver reset, a transient kernel failure) is
  **not** kept but **recreated** through the create path, rather than
  reported as falsely converged and left down forever (#5703 /
  codex-review-182 M29);
- **create** a newly-desired bond (also adopts a kernel bond that
  outlived in-memory tracking, e.g. across a daemon restart). Both the
  create and adopt paths enumerate the bond's **actual** enslaved member
  set (`LinkList` by `MasterIndex`) and track the **realized** signature,
  never the full desired one: a fully-realized bond is tracked under the
  full desired sig and only brought up (no flap, #5259); a bond realized
  with a **partial** member set (a member absent at realization time — the
  #4823 soft error) is tracked under its realized (partial) sig — so a
  partial realization is never recorded as satisfied and does not become
  KEEP-forever (#5261). This is symmetric: a fresh-create with an absent
  member tracks the partial sig too, so it converges when the member
  appears rather than staying stuck (the fresh-create analogue of #5261);
- **complete in place** a still-desired bond whose realized member set is
  a strict **subset** of the desired set (same mode/MTU — just missing
  members, incl. a config member-**add**): the missing members are
  enslaved via the adopt branch with **no `LinkDel`/`LinkAdd`**, so a live
  (degraded) fabric/RETH bond is never flapped to grow it. Enslaving a
  slave into an existing bond is non-disruptive to the members already
  forwarding. This is the self-heal path for a partial realization once
  the absent member appears (#5261) — it replaces the earlier
  delete+recreate route, which flapped the bond on every commit;
- **recreate** (delete+create) a bond whose **identity** changed — a
  genuine change that is *not* a pure member addition (member removed, or
  mode/MTU changed); the mode and existing enslavement cannot be changed
  in place while members are attached;
- **delete** a bond whose fabric interface was removed.

A no-op commit (identical desired bond set) issues zero `LinkDel`, zero
`LinkAdd`, and zero `LinkSetMaster`, and a **partial** bond issues zero
`LinkDel`/`LinkAdd` on every reconcile (only an in-place `LinkSetMaster`
attempt of the still-missing members). This was the non-idempotent
anti-pattern #2546 fixed for XFRM but not bonds. `Clear()` (shutdown /
full teardown) still deletes every tracked bond.

**Teardown retains on delete failure (#4901).** The xfrm / bond / tunnel
teardown paths (`clearLocked`, reached via `Clear`) used to log a failed
netlink `LinkDel`, drop the object from tracking, and return `nil` — so a
transient / `EBUSY` / `EPERM` delete failure left the link in the kernel
while the manager forgot it owned it, orphaning the xfrmi / bond / tunnel
(stale addresses, enslaved members, XFRM `if_id` state) with no state left
to retry it. This mirrored neither the VRF nor the tunnel **Apply** removal
diff, both of which already retain ownership on a failed delete (`next[name]
= true`). `clearLocked` now returns the `errors.Join`'d delete errors and
**retains tracking** for objects whose `LinkDel` failed (`xfrmis` entry /
`bonds` name / `ownedNames` entry) so the next reconcile retries; only
successfully-removed (or already-gone) objects are dropped.

#### `if_id` collision guard (#2909)

The kernel keys the SA↔xfrmi binding on the XFRM `if_id`, so the `if_id`
**must be unique per distinct xfrmi device**. `config.XFRMIfNameAndID`
can derive a colliding id for two *distinct* `bind-interface` values: a
bare `st0` and an explicit `st0.0` both resolve to `if_id 1` (the unit
defaults to 0 when there is no `.N` suffix) under *different* device
names (`st0` vs `st0.0`). Programming both would either `EEXIST` or,
worse, silently route both VPNs' SAs through one device — leaking
traffic between VPNs that are supposed to be isolated.

`Apply` therefore detects when two distinct desired device names map to
the same `if_id` and **refuses to create either** colliding device
(fail-closed: no transit for the ambiguous pair beats a cross-VPN leak).
If one half of the colliding pair was already created by an earlier
commit, it is torn down on the commit that introduces the alias.
Non-colliding interfaces in the same commit are created normally. The
proper long-term fix is a commit-time rejection of an ambiguous
secure-tunnel `bind-interface` in the config compiler / `pkg/ipsec`
(separate lane, #2885); this routing guard is the last line of defense
so a config that slips through never programs colliding kernel state.

## Entry points

All public methods remain on `*Manager` with unchanged signatures and
delegate to the owning domain. Exported types:

- `Manager` — `routing.go` (façade).
- `VRFSpec` — `vrf.go`.
- `KeepaliveState` — `tunnel_keepalive_runner.go`. Per-tunnel probe status.
- `TunnelStatus` — `tunnel.go`.
- `RouteEntry`, `NextHop`, `TableRoutes` — `routes.go`. `RouteEntry.NextHops`
  lists every leg of a kernel ECMP route (see "Multipath / ECMP routes" below).
- `PBRRule` — `rules.go`.
- `InterfaceMonitorStatus` — `monitor.go`.
- `New() (*Manager, error)` — `routing.go`.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

`pkg/config` only.

## ip-rule priorities

- `50–99`: RPM probe next-hop pins (`fwmark <mark> lookup <table>`,
  #1827). Constants live in `pkg/config` (`ProbeRulePriorityBase`,
  `ProbeTableBase` 7000-7049, `ProbeFwmarkBase` 0x1000) because
  `pkg/config` commit validation, this package, and `pkg/rpm` all
  consume them. Cleared on daemon startup (`ClearProbePins`) so a
  crashed daemon never leaks pins.
- `100–199`: next-table inter-VRF leaking (static routes with
  `next-table` directive). `nextTableRulePriority` in `rules.go`.
  **The window is drawn down IPv4-FIRST, and that is enforced HERE
  (#6583).** `nextTableManager.Apply` advances one family-blind `prio` in
  slice order, so which leaks survive the `maxNextTableRules` cap used to
  be decided entirely by two `append` lines in
  `pkg/daemon/daemon_apply_routing.go` (v4 statics, then v6 statics) — a
  cross-package convention with nothing on either side binding it. The
  userspace FIB mirrors the same cap but draws it down in its own order
  (`pkg/dataplane/userspace/routes.go`: `addRoutes("inet.0", …)` then
  `addRoutes("inet6.0", …)`), so the two agreed only by coincidence.
  Swapping those appends would have installed 60 v6 + 40 v4 in the kernel
  against 60 v4 + 40 v6 in the FIB: 40 leaks in the kernel and not the
  FIB, 40 the reverse — a leak present only in the FIB resolves into the
  target VRF on the AF_XDP fast path while a slow-path packet for the same
  flow resolves in the main table (#6467's verdict split in a new shape).
  `nextTableFamilyOrdered` makes the agreement structural instead of
  conventional: no caller can get it wrong, and the guard cannot rot into
  a check of one caller while a second is added elsewhere. The partition
  is STABLE, so within a family the caller's relative order — which the
  FIB's per-family pass also preserves — is untouched; a correct grouping
  that shuffled inside the group would match on counts and still install
  a different SET.
- `31000–31999`: PBR (firewall-filter `routing-instance` action).
  `pbrRulePriority` in `rules.go`. **Kernel FBF support matrix (#3730):**
  `BuildPBRRules` mirrors only the term `from` predicates an `ip rule` can
  express — source/destination address + prefix-list, DSCP (any value
  0-63, #7796),
  `protocol` (`FRA_IP_PROTO`), `source-port` (`FRA_SPORT_RANGE`) and
  `destination-port` (`FRA_DPORT_RANGE`); multi-value protocol/port sets
  expand to one rule per value and a port range maps to a single `[lo,hi]`
  range. A term carrying any predicate an `ip rule` cannot represent —
  `source-port-except` / `destination-port-except`, `tcp-flags`,
  `icmp-type` / `icmp-code`, `is-fragment`, `flexible-match-range`, an
  unknown DSCP name, a non-empty address `except` set, an unknown protocol /
  unparseable port, or any unresolved `from` leaf — FAILS CLOSED:
  `buildPBRFromFilter` (via `pbrTermL4`) drops the whole term and records a
  degraded build error. Honoring the address/protocol/port half while
  silently dropping the rest would WIDEN the match and steer traffic the
  operator constrained away (the #3730 over-steer); dropping the term is
  the fail-safe under-steer (steered traffic falls back to the main table)
  and the userspace filter path still enforces the term exactly.

  **DSCP is carried in `FRA_DSCP`, not the legacy tos byte (#7796).** Until
  #7796 the DSCP was shifted into a TOS byte (`DSCP << 2`) and emitted as
  netlink's `Rule.Tos`. The kernel validates that byte against
  `IPTOS_TOS_MASK` (0x1E) and rejects anything outside it, so every DSCP
  from `cs1` (8) up returned EINVAL — and because `RuleAdd` errors are
  aggregated into the apply result, the WHOLE COMMIT failed. The only two
  values the kernel would have accepted, `cs0`/`be` (0), were dropped one
  layer up as an over-match, so there was no `from dscp` value for which a
  rule installed at all. `vishvananda/netlink` cannot express this selector
  (its `Rule` has only `Tos`, on the released v1.3.1 AND on upstream
  main/master), so `rule_dscp_linux.go` emits the attribute directly,
  mirroring the library's own request construction. DSCP 0 is now an exact
  selector: with `FRA_DSCP` the attribute's PRESENCE is the match, so a
  zero value means "DSCP 0" rather than "any DSCP", and the kernel renders
  such a rule as `dscp default`. An unparseable DSCP name is now reported
  as unknown instead of being silently folded into the DSCP-0 case.
  Because the failure lives in what the kernel ACCEPTS, the guard is an
  apply-leg test against a real netlink socket in a private netns
  (`rule_dscp_kernel_7796_test.go`); it SKIPs without CAP_NET_ADMIN, so
  `make test-rule-dscp-lib` runs it under `unshare -rn`. The
  degraded error is returned to the daemon (`daemon_apply.go` step 3d) and
  logged; the buildable rules are still installed.
  **Per-interface iif scoping (#5117).** Junos FBF is bound to a specific
  interface-unit input filter, so a `then routing-instance` term only steers
  traffic INGRESSING the interface the filter is attached to. Each kernel `ip
  rule` therefore carries an `IifName` (`FRA_IIFNAME`) resolved via
  `cfg.ResolveKernelIfName` — the canonical Junos-ref → Linux-name mapping, so a
  unit-0 collapse (`ge-0/0/0` → `ge-0-0-0`), an 802.1Q VLAN unit
  (`ge-0/0/0.50`) and a RETH member (`reth0` → local physical member) all
  resolve consistently. `collectAttachedInputFilters` preserves the ingress
  interface per attachment (it no longer dedups a filter down to a single global
  entry), and a filter attached to N interfaces expands to N rules — one per
  `(filter, interface)`, each with its own `IifName`. `pbrManager.Apply` refuses
  to install a rule with no ingress interface (fail closed, never a global rule).
  Before #5117 the mirror set no iif selector, so a slow-path (`XDP_PASS`) packet
  arriving on a DIFFERENT interface could match the global rule and be steered
  into the wrong VRF (cross-WAN / tenant route-leak) — the userspace fast path
  was always per-interface, so only the kernel fallback over-steered.
  **Contradictory deny terms are not steered (#4534).** A term that
  co-locates `then routing-instance <x>` with a terminating `then discard` /
  `then reject` is contradictory — it asks the dataplane to BOTH steer the
  packet into `<x>` AND drop it. The deny wins on BOTH forwarding paths: the
  userspace runtime returns `RouteOverride::Drop` (#4392,
  `ingress_route_table_override`) and `buildPBRFromFilter` SKIPS the steering
  `ip rule` (records a degraded error). Without the kernel skip the mirror
  `ip rule` would fail OPEN — steering slow-path / `XDP_PASS` traffic
  ingressing the attached interface (even with the #5117 iif selector) into
  the VRF that userspace drops.
  The strict commit gate (`validateFilterRoutingInstanceConflictStrict`,
  #3308) rejects such a term at commit, but is lenient on load / peer-sync
  (#1960 no-brick), so a persisted / peer-synced contradiction can still reach
  the builder — hence the runtime skip.
  **Userspace FIB snapshot skips this band (#4479).** The userspace
  route-snapshot builder (`buildRouteSnapshots`,
  `pkg/dataplane/userspace/routes.go`) mirrors kernel ip rules whose Dst maps
  to a routing-instance table into per-prefix `next-table` leaks so the
  userspace FIB can cross-reference VRF tables. A PBR rule's Dst also maps to a
  routing-instance table, but the rule carries selectors (`Src`, DSCP,
  protocol, `Sport`/`Dport`) the synthetic `NextTable` snapshot cannot express.
  Ingesting it would drop those selectors and widen the FBF steer into a
  dst-only VRF leak — the userspace twin of the #3730 over-steer. The builder
  therefore SKIPS any rule in `[PBRRulePriorityBase, +PBRRuleWindow)` and
  fails closed: the userspace FIB simply omits the leak while the kernel keeps
  applying the real, fully-qualified rule. `PBRRulePriorityBase` /
  `PBRRuleWindow` are the SSOT in `pkg/config`, shared by the install cap
  (`maxPBRRules`) here and the snapshot skip there so the two cannot drift.
  **The `maxPBRRules` cap is enforced DURING expansion, not after (#5683).**
  Each `routing-instance` term expands to a six-dimensional Cartesian product —
  DSCP × protocol × source-port × destination-port × source × destination.
  Before #5683 `buildPBRFromFilter` materialized the FULL product of every term
  into one slice and only `BuildPBRRules` then truncated to the cap, so a config
  whose dimensions multiply to millions of tuples exhausted memory/CPU DURING
  expansion — the cap did not protect against the blow-up it was meant to bound
  (a commit/apply/scrape DoS: `BuildPBRRules` runs on the apply path and on the
  `PBRBuildStats` Prometheus scrape). The builder now computes each term's
  product SIZE from the resolved dimension lengths (`pbrTermProduct`, O(dimensions)
  with a saturating multiply) BEFORE the nested loop and DROPS WHOLE any term
  that would push the running total past the remaining priority-window budget —
  the same fail-safe under-steer as an unrepresentable predicate, with a degraded
  error naming the offending filter/term and its product-vs-cap. The full
  product is never allocated. A config UNDER the cap expands byte-identically
  (the guard never fires); an over-cap term steers nothing in the kernel mirror
  (the userspace filter path still enforces it exactly), so the operator sees the
  degraded gauge/log and authors a tighter match.
- `33000–33099`: rib-group inter-VRF leaking (`from all lookup
  <table>`). `ribGroupManager.Apply` only installs a leak rule when an
  instance's `interface-routes` rib-group imports a rib that resolves to
  a real table *different* from the instance's own source table.
  `resolveRibTable` returns `(tableID, ok)`; an **unknown / undefined**
  import-rib (typo, non-existent instance, garbage — `ok == false`) is
  skipped with a warning and never sets `needsLeak`, so it cannot install
  a phantom `from all lookup <sourceTable>` rule — and nothing is ever
  installed into table 0 from an unresolved name (#2226). The family
  suffix is matched **exactly**: `resolveRibTable` (via
  `ribInstanceFromName`) resolves only `inet.0` / `inet6.0` (main table)
  and `<instance>.inet.0` / `<instance>.inet6.0` (an instance with a
  non-empty prefix). A malformed family token whose prefix happens to be
  a defined instance — `<instance>.inetX.0`, `.inetfoo.0`, `.inet60.0`,
  or trailing garbage like `.inet.0.x` — returns `ok == false` and is
  rejected, not silently mapped onto the instance table (#2253). The
  earlier loose `.inet` substring match accepted those. The matching
  commit-time gate `validateRibGroupImportRibReferencesStrict`
  (`pkg/config`) mirrors the same exact-suffix matcher and hard-rejects
  the dangling/malformed import-rib before apply; both sides MUST stay in
  lockstep so the commit gate and the runtime applier agree on what
  resolves. This runtime guard is the defense-in-depth backstop for the
  tolerant load / peer-sync path.
- main table at `32766`. The next-table range sits **before** main
  (lower priority value = higher priority). PBR sits before main as
  well; rib-group sits after.

### Routing-instance kernel table IDs (#3855)

A routing-instance's kernel routing table id (`VRFSpec.TableID`, what
`reconcileVRFs` binds a `vrf-<name>` device to) is a **stable
name-hash**, not a positional counter. `config.StableRoutingInstanceTableID`
(FNV-1a/64 of the instance NAME, folded into the reserved band
`[RoutingInstanceTableIDBase, RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan-1]`
= `[100000, 999999]`) computes it. This mirrors the #3075 `StableZoneID`
and #1873 `StableTunnelEndpointID` stable-identity pattern.

**Why:** the pre-#3855 compiler assigned `100, 101, 102…` by config
order, so deleting or reordering ONE routing-instance **renumbered every
survivor after it**. `reconcileVRFs` then saw an untouched survivor's
kernel VRF carry a now-stale table id, **deleted and recreated** the live
device (link down/up + route reprogram) — a forwarding outage on a VRF
the operator never touched, on **both HA nodes**. A name-derived id is
invariant under add/remove/reorder of siblings, so `reconcileVRFs` only
recreates on a *genuine* table change (a rename → new name → new id), not
on spurious positional churn.

The band sits above every other reserved kernel-table constant (the
kernel-reserved 253/254/255, the mgmt VRF table `999`, the RPM probe band
`ProbeTableBase` 7000-7049) so a stable routing-instance table can never
collide with any of them, and it stays `>= 100` by construction. The id
is a pure function of the NAME — both HA nodes and a cold-booting node
compute identical ids from identical config with zero synced state.

**Collision handling (#3719 pattern):** two names folding to the same
kernel table would MERGE two VRFs onto one table (a cross-VRF route
leak), so it is never allowed. The strict commit path
(`config.validateRoutingInstanceTableIDCollisionAST`) hard-**rejects** a
colliding pair; the lenient load / peer-sync path warns and
`compileRoutingInstances` **quarantines** the later-sorting instance
(`config.QuarantinedRoutingInstanceNames`) — its VRF is not created and
its routes/leaks are not programmed — preserving the #1960 no-brick
intent while guaranteeing no two VRFs ever share a table.

### clear()/Apply error contract (#2273, #3430, #3731, #5118)

Each reconciler's `Apply` is clear-then-re-add: `clear()` removes every
rule in the manager's own priority window, then `Apply` re-installs the
desired set. `clear()` walks `[AF_INET, AF_INET6]`, calling `RuleList`
(a per-family netlink dump) on each. The error handling is:

- **Per-family `RuleList` failures are best-effort but observable.** A
  family whose dump fails is skipped (its in-window rules are left in
  place that pass), but the failure is **aggregated and returned**
  (`errors.Join`, wrapped with the family) rather than swallowed. Every
  family whose dump succeeds is still cleaned. Before #2273 a transient
  `AF_INET` dump failure orphaned the IPv4 rules in the window for that
  pass and `clear()` returned `nil`, so the caller never learned — a
  brief, unobservable self-healing window (the rules are re-cleared on
  the next commit once the transient clears).
- **`Apply` logs-and-continues; it does NOT abort on a `clear()` error.**
  The clear error is captured, logged at WARN, and the desired rules are
  still re-added (forward progress on the common path is preserved,
  including the empty-config early returns). `Apply` then **returns the
  clear error** so `pkg/daemon` (`daemon_apply.go` steps 3b–3d) observes
  it. The daemon currently logs Apply errors at WARN and continues; the
  change makes the failure visible (and lets a future caller retry)
  without changing the daemon's apply sequencing.
- **Per-rule `RuleAdd` failures are aggregated and returned, never
  swallowed (#3430 for PBR, #3731 for next-table + rib-group).** Each
  reconciler collects every add failure with `errors.Join` while still
  attempting every remaining desired rule (forward progress), then returns
  the joined error alongside any clear error. Before #3731 the next-table
  and rib-group `Apply` paths only WARN-logged a `RuleAdd` failure and
  returned `clearErr` (i.e. `nil` on the common path): a transient netlink
  add error (EEXIST from stale kernel/udev state, ENOBUFS, a racing
  reconcile) *after* the up-front `clear()` had already removed the
  working leak rules left inter-VRF leaking silently DOWN while `Apply`
  reported success. A clean re-apply is unaffected: `clear()` removes the
  in-window rules before they are re-added, so an idempotent re-apply does
  not hit EEXIST — an already-cleared rule is re-added fresh and `Apply`
  returns `nil`.
- **Per-rule `RuleDel` failures in `clear()` are aggregated and returned,
  never swallowed — for ALL THREE reconcilers (#3430 H3 for PBR, #5118 for
  next-table + rib-group).** A stale route-leak rule that cannot be deleted
  is an active cross-VRF forwarding instruction that sits BEFORE the main
  table, so leaving it in place preserves inter-VRF reachability and can
  override a main-table route. Before #5118 the next-table and rib-group
  `clear()` only debug-logged a `RuleDel` failure, so `errors.Join(errs...)`
  returned `nil` and `Apply` reported SUCCESS while the stale leak rule
  survived until an unrelated future apply — a silent inter-VRF leak past a
  "successful" commit. All three `clear()` paths now `errors.Join` the
  `RuleDel` failure so it propagates through `Apply`. The ONE carve-out:
  an ENOENT / "no such rule" delete (the rule vanished between the
  `RuleList` dump and the delete, or an idempotent re-clear already removed
  it) is NOT a failure — deleting an already-absent rule reaches the
  desired end-state, so `isRuleAlreadyGone` filters it out and it is
  debug-logged only, keeping an idempotent re-clear from spuriously failing
  the apply.

### Route-display read error contract (#5125)

The read side (`routeReader` in `routes.go`) mirrors the write-side
`errors.Join`-per-family discipline above. `GetRoutes`, `GetRoutesForTable`,
and `GetAllTableRoutes` each dump `[FAMILY_V4, FAMILY_V6]` independently, and
`frr.GetRouteDetailJSON` runs `show ip route json` / `show ipv6 route json`
independently. Before #5125 a per-family netlink (or per-command vtysh/JSON)
failure was swallowed with `continue` and the function returned `nil` error,
so a failed inet6 dump alongside a successful inet4 dump rendered as an
authoritative "no inet6 routes" — indistinguishable from a genuinely empty
table during a transient backend hiccup.

- **Backend (this package + `pkg/frr`): join, don't swallow.** A per-family
  failure is `errors.Join`ed into the returned error, tagged with the family
  (`inet`/`inet6`) plus the table id / routing-instance name / failing vtysh
  command. The family that DID dump is still returned. So a **non-nil error
  alongside a non-empty slice means "partial result"** — the caller must
  render the partial and surface the error, not treat the error as fatal.
  `GetAllTableRoutes` likewise joins the main-table error and each
  per-instance error (previously it `continue`d and dropped the whole
  instance table) while still appending every table it could read.
- **Callers: render the partial, warn non-fatally — never bail.** Every
  `show route` render caller (`pkg/cli/cli_show_routing.go`,
  `pkg/grpcapi/server_show_routes_text.go`) now renders whatever entries were
  returned and emits an in-band `warning: partial route display (some address
  families unavailable): <err>` line instead of `return`ing the error and
  dropping the entire display. This is the load-bearing half of the fix: with
  the backend now returning a non-nil error on a partial, a caller that still
  did `if err != nil { return err }` would break the ENTIRE `show route` on a
  transient single-family hiccup — strictly worse than the old silent-swallow
  (which at least showed the inet4 partial). The structured
  `grpcapi.GetRoutes` RPC has no warning field, so it logs the error
  (`slog.Warn`) and returns the partial; a **total** failure (no entries at
  all) still returns a hard error. Fail-on-revert coverage:
  `routes_perfamily_5125_test.go` (backend), `pkg/frr/route_detail_perfamily_5125_test.go`
  (FRR backend), `pkg/grpcapi/server_show_routes_perfamily_5125_test.go`
  (caller renders partial + warns, RPC returns partial).

## Tunnel reconcile-in-place (#1884)

`tunnelManager.Apply` reconciles instead of clear-all +
delete-and-recreate: an untouched tunnel keeps its netdev (stable
ifindex — no FRR route churn, no userspace-dp TUN-reader death per
commit, see #1881/#1887), tunnels removed from config are deleted via a
set-diff against the previous DESIRED set (`ownedNames`, retained on a
failed delete OR a TRANSIENT `LinkByName` lookup error for retry — a
genuine not-found drops tracking; a transient error must not orphan a
live link with stale addresses, #1919 r2), and a device is recreated only
when the existing kernel link is genuinely incompatible:

- **Anchors** (production userspace path): reuse requires TUN mode +
  `NO_PI` (the Rust reader opens `IFF_TUN|IFF_NO_PI`) + persistent.
  MTU ownership: `tc.MTU > 0` (config) is reconciled on every reuse
  (the compiler MTU stage restores ZONED interfaces only); `tc.MTU ==
  0` is written exactly once when ADOPTING a device this manager did
  not own at the last apply (restart adoption; wireguard→gre same-name
  flip repair — the WG-reduced MTU must not leak into the userspace
  snapshot's live-MTU reads).
- **Legacy non-anchor** (standalone-CLI only): compare-then-decide on
  the config-driven attrs (type/family, endpoints, defaulted TTL,
  keys, ip6tnl proto); kernel-populated fields (PMtu, Tos, flags,
  encap-limit — mutated by the post-create `encaplimit none` exec) are
  deliberately NOT compared. Real changes delete+recreate; the
  encaplimit exec runs only on (re)create.
- **Addresses**: symmetric reconcile; stale LINK-LOCAL addresses are
  deleted only if recorded in `appliedAddrs` (a configured fe80 we
  applied), never the kernel's autoconf fe80; failed LL deletes stay
  tracked for retry. On an `AddrList` enumeration failure the reconcile
  deletes nothing AND preserves the prior applied LINK-LOCAL ownership
  (so a configured fe80 mid-removal is not silently re-classified as
  foreign and leaked on a later WG prune — #1919 r1 Codex MAJOR); the
  configured-address AddrAdd pass still runs (idempotent on EEXIST).
- **WireGuard removal address prune** (`wgConfigured`, #1919): WG `wgN`
  TUNs are persistent (#1432 S2a) — they are deliberately excluded from
  the `ownedNames` removal diff so the link is NEVER torn on reload
  (tearing it flaps the device + live peer). But that exclusion meant a
  WG tunnel REMOVED from config never had its addresses reconciled away
  (the per-tunnel apply loop only reconciles still-configured WG). `Apply`
  now keeps a WG-only `wgConfigured` set; a name that disappears from it
  has `pruneAppliedAddrsLocked` delete every present non-link-local
  address (manager owns the device's non-LL set, same as steady-state
  reconcile) plus configured/applied link-locals, while KEEPING the link.
  The helper returns `(failed, retry)`; the name is retained for retry
  when an `AddrDel` failed OR `AddrList` itself failed (cannot prove
  clean) — decoupled from `len(failed)` so an empty applied set with a
  transient list failure still retries (it does NOT reuse
  `reconcileLinkAddrsLocked`, whose return only records failed LL
  deletes). A transient `LinkByName` error (vs `isLinkNotFound`) also
  retains for retry; a genuine not-found drops tracking. The same removal
  pass also identity-gated-unbinds the WG TUN from its VRF (#5120,
  `unbindVRFClaimLocked`): the persistent `wgN` link is KEPT but is never
  left enslaved to the VRF it last claimed — a transient `LinkSetNoMaster`
  failure retains the `appliedRI` claim (and the `wgConfigured` entry) for
  retry, and a not-found device clears the claim (the binding died with the
  device). Residual deferred to #1434: removal while the daemon was DOWN is
  not pruned (only tracked-applied addresses/claims reconcile).
- **VRF claims** (`appliedRI`): written ONLY from a successful
  `BindInterfaceToVRF` or a direct observation that the link's master
  is `vrf-<RIListMember>` (a step-0a routing-instance interface-list
  bind) — never from intent. `TunnelConfig.RIListMember` (populated by
  `collectAppliedTunnels` with the exact step-0a name normalization)
  vetoes unbinding when the config list-binds the tunnel. Unbind on
  config-wants-none is identity-gated (`unbindVRFClaimLocked`): only when
  the current master IS the claimed RI's `vrf-` device; transient errors
  retain the claim for retry. WireGuard `wgN` TUNs now use this SAME claim
  machinery (#5120): `applyWireguardTunLocked` routes through
  `reconcileVRFClaimLocked` so removing the `routing-instance` stanza from
  a still-configured tunnel unbinds it, and the persistent-link removal
  prune (above) shares `unbindVRFClaimLocked` — closing the pre-#5120 gap
  where WG bound its VRF directly with no unbind branch and left `wgN`
  mastered to a stale VRF after an RI change or tunnel removal.
  - **The list bind now happens TWICE per apply (#6805), and it has to.**
    "0a owns list binds" is the contract this veto is written against —
    `reconcileVRFClaimLocked` case 2 only OBSERVES, it never binds — but step 0a
    runs BEFORE `applyInterfaceReconcile` creates the tunnel/xfrmi devices, so on
    a FIRST apply the owner ran before the thing it owns existed. 0a warned "not
    found", the observation found a link with no master and took no claim, and
    the tunnel came up **outside its VRF, in the default table**, on a commit
    that reported success — until some later apply happened to run 0a while the
    device existed. `Daemon.rebindRoutingInstanceMembers` re-drives the SAME loop
    at the post-networkd point where the devices are real (beside
    `rebindManagementVRFIfaces`). The veto is on UNBIND and is unchanged; the bug
    was the ordering, so the fix is a second pass rather than a bind moved into
    the tunnel manager. Both passes call ONE function
    (`Daemon.bindRoutingInstanceMembers`), because a second loop that drifted
    would leave this veto guarding a different set than the one being bound —
    and that divergence is always a bug, never a legitimate difference. The late
    pass stays best-effort at WARN like 0a: a routing-instance `interface` list
    can legitimately name an interface genuinely absent on this chassis, and
    failing the commit on that would reject configs correct for the fleet.
- **Keepalives** (BOTH the anchor and the legacy branch, #4071): runners
  are reconciled by normalized identity `(remote, source, interval,
  retry<=0→3)` and survive unrelated applies; `LinkSetUp` is SKIPPED
  when a retained runner holds the tunnel down (the down-transition in
  `keepaliveLoop` is gated on `state.Up`, so re-upping would strand
  the link admin UP). A change to the tunnel SOURCE restarts the runner
  (#1918 §5c): the source is the probe bind address. The prober is
  dataplane-agnostic (raw ICMP over the underlay FIB), so the production
  userspace-dp anchor path (`applyAnchorLocked`) starts the SAME engine as
  the legacy kernel-tunnel branch (`applyKernelTunnelLocked`) — a
  configured `keepalive` on a GRE anchor tunnel now probes the far end and
  LinkSetDowns the anchor TUN on peer death (the down oif withdraws its
  connected/overlay routes, driving OSPF/BGP/static-nexthop dependents to
  reconverge — the Junos gr-/st0 interface-down semantic). Before #4071
  the anchor path unconditionally stopped the runner, so a configured
  keepalive was accepted-but-inert on the only production dataplane.

**Fail-closed on genuine create/up/delete failure (#5355).** Like
`xfrmManager.Apply` before #5310, `tunnelManager.Apply` used to log every
per-tunnel `LinkAdd` / `LinkSetUp` / `LinkDel` failure and return `nil`
**unconditionally**, so a GRE/anchor/WireGuard tunnel that could not be
realized in the kernel reported a **successful commit** while the interface
was absent (or admin-DOWN, or a removed tunnel's device lingered) —
fail-open false convergence. `Apply` now accumulates the **genuine**
failures with `errors.Join` and returns them so the #5354
`applyInterfaceReconcile` tail-join fails the commit closed. The apply
helpers (`applyAnchorLocked` / `applyKernelTunnelLocked` /
`applyWireguardTunLocked`) and the shared `finishTunnelLocked` tail return
the create / replace-delete / bring-up error; the removal diff aggregates a
removed tunnel's `LinkDel` failure. The tolerated idempotent conditions
stay **non-errors**: a still-present compatible anchor is adopted in place
(reuse, not a `LinkAdd`), a delete of an already-gone tunnel is a no-op
(`isLinkNotFound`), and a **transient** `LinkByName` lookup only defers the
reconcile (retain + retry, no error — the device state is unknown, not
proven-broken). Config-parse issues (invalid endpoints) stay warn-only.
Address / MTU / VRF-claim reconcile failures are NOT folded into the
fail-closed signal — they retain+retry their own state (above) and are out
of scope, matching #5310's create/find/up/delete boundary.

## Keepalive liveness probing (`tunnel_keepalive.go`, #1918)

The keepalive performs a **real ICMP echo round-trip** — it is a
liveness check, not a route-existence check. (The pre-#1918 `probeICMP`
opened a socket and returned `true` without sending anything, so a dead
peer behind a valid route read up forever and the fail-safe
`LinkSetDown` was unreachable.)

- **Mechanism**: unprivileged datagram ICMP (`udp4`/`udp6` via
  `golang.org/x/net/icmp`), the same mechanism as the tested
  `pkg/cluster/monitor.go` precedent. Requires `net.ipv4.ping_group_range`
  to admit the daemon gid (or `CAP_NET_RAW`); when it does not, the probe
  is **ProbeUnsupported** and the link is HELD (never torn down — see
  hold-on-unknown).
- **Interval bound (#5705)**: the configured `keepalive <seconds>` is
  bounded to `0..32767` at commit-check (`pkg/config`
  `tunnelSchemaChildren`, `ValidateInteger(0, 32767)`; `0` = disabled)
  AND clamped at runtime by `clampKeepaliveIntervalSec` before every
  `time.Duration(sec) * time.Second` multiply (the `keepaliveLoop`
  ticker and `keepaliveProbeDeadline`). `time.Duration` is int64 ns, so
  an unbounded value overflowed the multiply, wrapped non-positive, and
  panicked `time.NewTicker` — a commit-reachable, self-inflicted xpfd
  crash. The runtime clamp is defense-in-depth for a value that reaches
  the dataplane un-gated (stale DB, a path bypassing `SchemaValidate`).
- **Reply match**: `Seq` + a per-probe random **Data-nonce** — NOT the
  ICMP ID. Datagram ("ping") sockets rewrite the outbound id to the
  socket source port, so id is advisory only.
- **Probe target / table**: the underlay `Destination`, routed in the
  GLOBAL/underlay FIB (no `SO_BINDTODEVICE` to an overlay VRF) — exactly
  where the tunnel's encapsulated packets resolve.
- **Source bind**: the probe binds the tunnel's local `Source` IP so the
  echo egresses from, and the reply returns to, the tunnel endpoint
  (multi-homed / policy-routed correctness). Empty source → wildcard.
- **Typed result** (`ProbeResult`): `ProbeAlive | ProbeDead |
  ProbeUnsupported`. The old `bool` erased "could not probe".
- **Hold-on-unknown** (Axis C): on `ProbeUnsupported` the loop does NOT
  change `Failures` and does NOT transition the link; it holds the prior
  `Up` and reports `KeepaliveUp == nil` with `KeepaliveInfo = "unknown
  (...)"`. Structural causes (missing `ping_group_range`/cap, bound
  source not local) hold indefinitely with a one-shot `slog.Warn`;
  transient causes (FD/memory exhaustion, unrecognized errno) hold but
  escalate to `slog.Error` after `MaxRetries` consecutive unknown ticks
  so a real peer death is never silently masked. Tearing the link down
  because the daemon cannot probe would be a self-inflicted outage.
- **Commit-after-success / lock scope** (Axis D): the tick classifies the
  probe and computes the transition INTENT under `state.mu`, releases the
  lock, performs the single `LinkSetUp`/`LinkSetDown` OUTSIDE the lock,
  and commits `state.Up` ONLY if the netlink op succeeded. A
  `LinkByName`/`LinkSet*` error leaves `Up` unchanged so the transition
  retries next tick (never a lost or half-applied transition), and a
  racing `GetStatus` never blocks behind a slow netlink op nor observes
  an uncommitted `Up`.
- **Recreate safety**: both `applyKernelTunnelLocked` and (since #4071)
  `applyAnchorLocked` cancel + DRAIN the existing keepalive runner BEFORE
  they delete/recreate the kernel link (drain-before-recreate), so no
  stale runner can issue a `LinkSet*` against a recreated link that reused
  the ifindex. A transient (non-not-found) lookup error is NOT treated as
  a recreate on either path — the EEXIST-adopt fallback keeps the link, so
  a live runner is retained rather than drained. A per-tunnel `linkGen`
  (`*atomic.Uint64`, read LOCK-FREE by the runner — it never takes
  `t.mu`) is the defense-in-depth backstop; the runner drops any
  transition whose captured generation no longer matches. The anchor
  branch also bumps `linkGen` whenever the `LinkAdd` ends `created` (#4076):
  its up-front `willRecreate` switch has no `default: return` (unlike the
  legacy branch), so a transient (non-not-found) lookup error that masks a
  device that had actually VANISHED — `LinkAdd` then SUCCEEDS — would
  otherwise leave the new device on a stale generation. The `created &&
  !willRecreate` bump gives every genuinely new device a fresh generation
  without double-bumping the already-drained classified-recreate path and
  without touching a plain reuse/adopt reconcile.

`Clear()`/`ClearTunnels` keep delete-everything semantics and reset the
reconcile state. Restart residuals (documented): anchors/addresses/RI
claims orphaned while the daemon was down are adopted as-is, not
retroactively diffed.

## Multipath / ECMP routes (#3944)

A kernel ECMP route (multiple equal-cost next-hops for one prefix,
installed by FRR or a `next-hop [ a b ]` static) carries its next-hops
in the netlink `RTA_MULTIPATH` list (`route.MultiPath`, a
`[]*netlink.NexthopInfo`), **not** in the single `route.Gw` — which is
nil for such a route. `routeToEntry` (`routes.go`) therefore checks
`route.MultiPath` first: when it is non-empty it populates
`RouteEntry.NextHops` with one `NextHop{Gateway, Interface, Weight}`
per leg (`multiPathNextHops`, resolving each leg's ifindex to a name and
recording `netlink.NexthopInfo.Hops + 1` as the weight), and back-fills
the single `NextHop`/`Interface` fields from the first leg so single-
field consumers show a real next-hop instead of a bare "direct". A
single-gateway, connected/direct, or discard route leaves `NextHops`
nil and is bit-identical to before.

For a no-gateway route `routeToEntry` labels the disposition from
`route.Type`: `RTN_BLACKHOLE` → `"discard"` (silent drop), `RTN_UNREACHABLE`
→ `"reject"` (drop + ICMP unreachable), else `"direct"` (directly-connected).
The `reject` mapping was added in #5410 to match the kernel FIB now that
#5298 installs a static `reject` route as `RTN_UNREACHABLE` via FRR; before
it, an installed reject route fell through to the `"direct"` else branch and
mis-rendered as directly-connected. The label set mirrors the `reject`/
`discard` conventions `formatTableJunos` and the gRPC/REST readers already
use for the config static-route view.

Rendering: `formatTableJunos` (`routeformat.go`, the canonical Junos
`show route` view used by both the local CLI and the gRPC text path)
emits one `>  to <gw> via <if>` line per leg when `NextHops` is
non-empty; the structured `GetRoutes` gRPC RPC emits one `RouteInfo`
per leg (same idiom as the REST static-route handler). Before #3944 an
ECMP route displayed as a single bare "direct"/empty next-hop, hiding
which paths a prefix load-balances over.

## Gotchas

- #848 / #1698: each interface domain (`tunnelManager`, `xfrmManager`,
  `bondManager`) now has its own lock instead of one shared `ifaceMu`.
  The split is safe because no operation crossed those domains under one
  lock; keepalives belong to the tunnel domain. Long-running reads
  (`GetTunnelStatus`) snapshot under the tunnel lock and iterate the
  copy lock-free.
- `vrfManager` holds its own lock for the entire netlink reconciliation;
  `ReconcileVRFs` isn't re-entrant.
- `Manager.Close()` is not safe to call concurrently with the public
  apply/read methods (single-threaded-shutdown contract; no daemon
  caller of `Close` today). It IS safe to call on a PARTIAL Manager
  (#5718 A7-b02-C01): the `*ForTest` constructors in `test_seams.go`
  wire only the domains their callers exercise, so `Close` nil-guards
  the tunnel domain exactly as it does `nlHandle` — an unguarded
  `m.tunnel.stopAll()` takes `t.mu` on a nil `*tunnelManager` and
  panics the caller that followed the documented `defer m.Close()`.
  Any new domain teardown added to `Close` needs the same guard.
  The guard must not degrade `Close` into a no-op on a wired Manager, so
  `close_partial_manager_5718_test.go` also drives a Manager with a live
  keepalive goroutine installed and observes both obligations discharged
  on real state (#5718 fold): the runner's `done` channel closes (proof
  the goroutine returned, not merely that `cancel` was called) and the
  handle release runs exactly once, AFTER the drain.
- **The handle release is indirected through `Manager.closeHandleFn`
  (#5718 fold r3).** `New()` binds it to the handle it just created — so
  a later reassignment of `m.nlHandle` cannot redirect `Close` away from
  the handle this Manager owns — and the partial `*ForTest`
  constructors leave it nil alongside `nlHandle`. The indirection exists
  so the #848 ORDERING contract is testable **without** a live netlink
  handle: a test that needs one SKIPS where netlink is unavailable, and
  a skipped test reports PASS, so it accepts every implementation there
  and a mutation cell scored against it is UNKNOWN, not GREEN. A guard
  that only fires on a box with netlink is not a guard for the merge
  gate. `TestCloseDrainsBeforeReleasingHandle_5718` is therefore the
  binding guard (injected release recorder, no netlink);
  `TestCloseReleasesLiveHandleAndKeepalives_5718` is supplementary and
  environment-gated, adding only that a real handle's sockets actually
  go away — `GetSocketReceiveBufferSize()` drops from one entry per live
  socket to none. A post-close `LinkList` is NOT an observable:
  `vishvananda/netlink` silently falls back to a package-level socket
  once `Handle.sockets` is nil.
- **Ordering is observed from inside the keepalive goroutine.** Final
  state is identical whether the drain or the release runs first, so the
  runner records whether the release had already fired at the moment it
  was cancelled. `stopAll` blocks on `<-runner.done`, which makes that
  read deterministic and race-free in both orders: drain-then-release
  gives `cancel -> read -> close(done) -> release`, release-then-drain
  gives `release -> cancel -> read`.
- Keepalive runner goroutines drain on the `done` channel before the
  netlink handle is closed. Closing the handle while a goroutine still
  holds it would be a use-after-close.
- Static routes go through `pkg/frr`, not this package. The "next-table"
  and "rib-group" leaking modes go through `ip rule` (here), not FRR.
- RPM probes that need VRF binding use `SO_BINDTODEVICE` on the VRF
  device, not on the destination interface.


## Kernel-learned route import (#7409)

**Refresh trigger (#7437).** The import is re-run whenever the routes-only
snapshot is republished. Until #7437 that happened on an operator commit or an
ip-monitoring actuation only, so a route the kernel learned in between stayed
absent from the helper FIB until the next push — a window bounded by "time to
the next commit", which on a quiet box with a flapping BGP peer is unbounded in
practice.

`pkg/daemon/daemon_route_listener.go` now subscribes to kernel route events and
drives that republish. It **marks only**: the actuation is coalesced through
`pkg/coalesce` (debounce 1 s, throttle 3 s, the `pkg/ipmon` precedent) because
every publish is a full snapshot replace over a control socket whose deadline
scales with payload size, and a per-event push under route churn would starve
session installs rather than merely add latency.

The listener's imported-table predicate calls `LearnedRouteTableIDs` — this
package's own function — rather than keeping a second copy of which tables are
imported, so the listener and the importer cannot disagree about which events
matter.

**The window is narrower, not closed.** A route learned at *t* reaches the
helper FIB some seconds later, and on a fresh boot the first push still bounds
it. The `NoRoute` disposition therefore **remains** slow-path eligible; #6664's
proposal to drop it is not made safe by #7437 alone.

`fibimport.go` reads the kernel FIB and hands the *learned* routes to the
userspace dataplane's snapshot builder
(`pkg/dataplane/userspace` `buildRouteSnapshots`).

### Why it exists

The helper FIB was built from config-derived sources only: config statics,
connected prefixes, the ip-rule leak mirror and the ip-monitoring overlay.
Nothing read the kernel. But FRR installs BGP/OSPF/IS-IS/RIP routes, and
DHCP leases on **non-management** interfaces contribute an AD-200 default plus
RFC 3442 classless routes, all into the kernel's main table. A transit packet
toward such a destination therefore either:

- resolved `NoRoute`, which is slow-path eligible, and was **reinjected to the
  kernel** — which forwarded it with no zone policy, no session, no NAT and no
  screen, and with no nftables `hook forward` chain behind it; or
- matched a *less-specific* config route (typically a static default) and was
  forwarded to **that** next-hop instead of the learned one — adjudicated, but
  down the wrong path.

### What is imported

`ImportLearnedRoutes(tableIDs)` dumps each named table per family with
`RouteListFiltered` and adopts a route only if **all** of:

| predicate | why |
|---|---|
| `Type == RTN_UNICAST` | the importer may only ever ADD a forwarding path — it can never publish a discard/blackhole/unreachable route and so can never turn forwarding into a drop. Also excludes the HA inactive-RG blackholes (`RTN_BLACKHOLE`, priority 4242) by construction |
| protocol in `learnedRouteProtocols` | keyed on the same RTPROT constants `rtProtoName` maps, including FRR's `RTPROT_ZSTATIC` (196). `RTPROT_REDIRECT` is deliberately excluded |
| has a next-hop gateway | a gateway-less route is directly connected and already reaches the FIB from the interface snapshot; requiring one also keeps clear of the Rust side's bare-gateway ifindex inference |
| every ECMP leg has a gateway | an ECMP set is imported **whole or not at all** — a half-imported set is the same defect class as an ECMP half-override |

A `nil` `Dst` is normalised to `0.0.0.0/0` / `::/0` — that is how a default
route can arrive, and it is the route the import most exists to capture.

The table set is **bounded** by `LearnedRouteTableIDs`: main plus each
configured routing instance. The management VRF (999) is hard-excluded — it is
not reachable from a packet reinjected on `xpf-usp0`, and importing it would
hand the transit fast path a route to the management gateway.

A netlink failure **fails the import closed** with no partial result, mirroring
the ip-rule enumeration's contract. This is the opposite of the display path's
partial-result behaviour in `routes.go`, deliberately: a missing `show route`
row misleads a human, a missing FIB entry misdirects a packet.

### Consumer-side rule

The snapshot builder applies the import as **gap-fill only** — an imported
route is discarded whenever the config-derived set already covers the same
`(table, family, prefix)`, compared on the *canonical* prefix. The operator's
route always wins, and every existing precedence contract keeps operating on
exactly the routes it did before.

### Known limitation

This **narrows** the divergence window; it does not close it. The snapshot is
republished on operator commit and on ip-monitoring actuation only — there is
no `RouteSubscribe` anywhere in this repo — so a route the kernel learns
between two pushes is still missing from the helper FIB until the next one.
For that reason `NoRoute` must **stay** slow-path eligible: dropping it instead
would black-hole every learned destination for the width of that window.
`xpf_userspace_binding_slow_path_no_route_packets_total` is the signal.

**What actually happened to that requirement (#7480, then #9054).** The
paragraph above states the requirement and the tree did not meet it. #7480 made
a `NoRoute` frame get adjudicated against the #3110 unzoned egress sentinel
before the slow-path chokepoint; no zone-pair or `junos-global` permit can match
that sentinel, so the DEFAULT action decides and a Junos-default deny box DROPS
the frame. For the narrow inter-publish window described above that was a
deliberate, bounded trade against the #6664 kernel-delegation bypass.

**The window is not always narrow.** This section does not mention the #8355
learned-route cap, and it is the unbounded-width version of exactly the
divergence described here: above ~65,000 kernel routes the daemon declines the
ENTIRE learned-route import, so every dynamically learned destination resolves
`NoRoute` until the table shrinks. Composed with #7480 that was a silent total
blackhole of the dynamic FIB — and #8355's operator log line said traffic still
forwarded through the kernel.

#9054 closes the composition rather than either half: `buildRouteSnapshots`
now reports whether the cap declined the import, the snapshot carries
`learned_route_import_capped` (snapshot protocol 10 — an older helper REFUSES
the snapshot rather than applying it and black-holing), and while the flag is
set the helper restores the slow-path delegation for `NoRoute` frames only.
#7480's adjudication is untouched for an uncapped snapshot.
