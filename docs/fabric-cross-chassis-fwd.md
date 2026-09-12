# Fabric Cross-Chassis Forwarding — Design & Bug Report

## Problem Statement

When fw0 reboots and preempts back to MASTER, a **2.1-second asymmetric routing
window** exists where fw0 is WAN MASTER but not yet LAN MASTER. During this gap:

1. WAN return traffic arrives at fw0 (it owns the WAN RETH VIP)
2. `bpf_fib_lookup` fails for LAN destinations (fw0 doesn't have the LAN route yet)
3. `META_FLAG_KERNEL_ROUTE` fallback hands post-NAT packets to the kernel
4. Kernel drops the packet (no route to the original LAN destination)
5. If a TCP RST traverses this path, BPF conntrack transitions the session to
   `SESS_STATE_CLOSED` — **permanently poisoning it**

**Timeline from fw0 logs (pre-fix):**
```
15:11:54.344 - vrrp: MASTER ge-0-0-1.50 group=101 (WAN)
15:11:56.485 - vrrp: MASTER ge-0-0-0 group=102 (LAN)   ← 2.1s gap
15:11:57.013 - SESSION_CLOSE src=172.16.50.6:1027 action=deny
```

## Solution — Three-Layer Fix

### Fix 1: BPF Fabric Cross-Chassis Redirect (Primary)

**Concept:** When `bpf_fib_lookup` returns `NO_NEIGH` or `NOT_FWDED` for an
existing session, redirect the **original (pre-NAT) packet** to the peer via the
fabric link instead of falling back to kernel routing.

**Why original (pre-NAT) packet?** At the xdp_zone stage, only meta fields have
been modified by dnat_table pre-routing — actual packet bytes are untouched.
Redirecting the raw packet lets the peer process it through its full pipeline
(dnat_table → session → FIB → NAT → forward) without double-NAT issues.

**Why this works on the peer:** Established sessions skip policy evaluation
(conntrack fast-path), so the zone mismatch (arriving on control zone fab0
instead of wan/lan) doesn't matter.

**Components:**

| File | Change |
|------|--------|
| `bpf/headers/xpf_maps.h` | `fabric_fwd_info` struct + `fabric_fwd` ARRAY map (1 entry) |
| `bpf/headers/xpf_helpers.h` | `try_fabric_redirect()` inline helper |
| `bpf/headers/xpf_common.h` | `GLOBAL_CTR_FABRIC_REDIRECT = 26` |
| `bpf/xdp/xdp_zone.c` | Call `try_fabric_redirect()` in NO_NEIGH + NOT_FWDED paths |
| `pkg/dataplane/types.go` | Go `FabricFwdInfo` struct matching C layout |
| `pkg/dataplane/maps.go` | `UpdateFabricFwd()` method on eBPF Manager |
| `pkg/dataplane/loader_ebpf.go` | Register `fabric_fwd` map from zoneObjs |
| `pkg/dataplane/dataplane.go` | `UpdateFabricFwd()` in DataPlane interface |
| `pkg/daemon/daemon.go` | `populateFabricFwd()` goroutine in `startClusterComms()` |

**Anti-loop protection:** `try_fabric_redirect()` checks
`ctx->ingress_ifindex == ff->ifindex` — packets arriving on the fabric interface
are never redirected back, preventing infinite loops.

**Map population:** `populateFabricFwd()` runs as a goroutine, resolving:
- Fabric interface ifindex + local MAC via `netlink.LinkByName()`
- Peer MAC from ARP table via `netlink.NeighList()` (retries up to 30x at 2s intervals)

**Event-driven refresh (`monitorFabricState`, #124):** a sibling goroutine
subscribes to netlink link + neighbor updates and calls `triggerFabricRefresh()`
when a fabric interface or the fabric peer's neighbor entry changes, so the
`fabric_fwd` map is re-resolved sub-second instead of waiting for the 30s
`populateFabricFwd` ticker. This monitor is resilient to netlink receive-buffer
overflow (ENOBUFS): a recoverable close of EITHER the link or neighbor update
channel resubscribes (via `runFabricStateSubscription`) after a 2s backoff and
re-syncs the fabric state, rather than dying permanently, and it closes BOTH
netlink sockets on every path so neither fd leaks (#4031). It exits only on
context cancellation.

**Per-fabric refresh channels (dual-fabric, #4038):** in a redundant
`fabric-link` + `fabric-link-1` cluster the fab0 loop (`populateFabricFwd`)
and the fab1 loop (`populateFabricFwd1`) each own a refresh channel
(`fabricRefreshCh` / `fabricRefreshCh1`). `monitorFabricState` does not tag
events per fabric, so `triggerFabricRefresh()` signals BOTH channels (non-
blocking, capacity 1) and every configured fabric re-resolves on any event —
matching the synchronous `RefreshFabricFwd()`, which already refreshes both
entries. A single shared channel was wrong: a Go send is received by exactly
one waiting goroutine, so one trigger woke only fab0 OR fab1 (whichever won
the receive) and the other fabric's link/neighbor event was dropped until its
30s safety-net tick — degrading the second fabric's sub-second convergence.
A single-fabric cluster leaves `fabricRefreshCh1` nil; the non-blocking send
falls through its `default` arm, so `triggerFabricRefresh()` is a no-op for
the absent fabric.

**Dual-fabric egress selection by parent up-state (#4082):** the
cross-chassis redirect egresses over a fabric parent ifindex, but the
Rust selection (`resolve_fabric_redirect_from_list`,
`userspace-dp/src/afxdp/forwarding/fabric.rs`) historically picked the FIRST
fabric with a valid parent ifindex — functionally `fab0` (the list is
Go-sorted by name). A DOWN `fab0` still has a nonzero parent ifindex (and
a stale/permanent neighbor entry can keep its peer MAC resolved), so the
redirect stayed pinned to `fab0` and blackholed instead of failing over to
an UP `fab1`. The data-path thus lacked the fabric redundancy the
control-plane session-sync path already has (`activeConnLocked`,
`pkg/cluster/sync_conn.go`, prefers conn0/fab0 and falls back to conn1/fab1).

The fix threads a per-fabric `up` flag end to end:

- **Go source of truth.** `buildFabricSnapshots`
  (`pkg/dataplane/userspace/fabric.go`) stamps `FabricSnapshot.Up` from
  `fabricParentUp(parentLinux)`, which reads the parent netdev's live
  oper-state via `netlink.LinkByName`. Detection fails toward "up": only a
  definite kernel down state (admin-down, `OperDown`, `OperLowerLayerDown`,
  `OperNotPresent`) reports not-up; `OperUnknown`/`OperDormant` (common for
  virtual/overlay parents with a live carrier) count as up, so a healthy
  fabric is never mis-marked down. The wire field is `"up"` WITHOUT
  `omitempty` — a genuinely-down fabric must serialize `"up":false`, not
  drop the field.
- **Sub-second propagation, no new monitor.** A carrier change on the
  parent is an `RTM_NEWLINK` oper-state delta that `monitorFabricState`
  (#124) already subscribes to → `triggerFabricRefresh()` →
  `SyncFabricState` → `buildFabricSnapshots` re-push, with the 30s
  safety-net tick as backstop. No userspace link-state monitor is added.
- **Rust selection.** `resolve_fabric_redirect_from_list` prefers the
  first fabric with `parent_ifindex > 0 && up`, walking the stable
  Go-sorted order so both nodes deterministically favor `fab0` while it is
  up (revert-to-primary on recovery, mirroring `activeConnLocked`). If NO
  fabric reports up it falls back to the first resolvable fabric —
  **fail-open**: a blackhole is no worse than a drop, and this preserves
  the pre-#4082 behavior for a genuine all-fabrics-down state.
- **Rolling-upgrade back-compat.** The Rust `FabricSnapshot.up` decodes
  with `#[serde(default = "default_true")]`, so a stale daemon that omits
  the field leaves every fabric reading up=true — bit-identical to the
  pre-#4082 pin-to-first behavior.

Single-fabric clusters are unaffected: one fabric in the list is selected
whether or not its `up` flag is momentarily false (fail-open). **Validation
gap:** the tested loss cluster and the standalone VM both run a single
`fab0`, so no harness currently exercises the live `fab0`-down/`fab1`-up
failover; the unit test (`fabric_redirect_prefers_up_fabric_4082`) covers
the selection logic, but end-to-end dual-fabric failover needs a
two-parent cluster build-out.

### Fix 2: VRRP Coordinated Preemption (Defense-in-depth)

**Concept:** All VRRP instances preempt simultaneously when `ReleaseSyncHold()`
fires after bulk session sync completes, minimizing the asymmetric window from
seconds to milliseconds.

| File | Change |
|------|--------|
| `pkg/vrrp/instance.go` | `preemptNowCh` channel + `triggerPreemptNow()` + select case in `run()` |
| `pkg/vrrp/manager.go` | Call `triggerPreemptNow()` in `ReleaseSyncHold()` |
| `pkg/vrrp/vrrp_test.go` | 3 new tests for coordinated preemption |

### Fix 3: BPF RST State Protection (Defense-in-depth)

**Concept:** In `handle_ct_hit_v4/v6`, when `META_FLAG_KERNEL_ROUTE` is set, skip
the RST→CLOSED state transition. The kernel may drop the packet (no route), so
the RST never reaches the peer — don't poison session state based on a packet
that won't be delivered.

| File | Change |
|------|--------|
| `bpf/xdp/xdp_conntrack.c` | Skip state→CLOSED when `meta->meta_flags & META_FLAG_KERNEL_ROUTE` |

## Bugs Found and Resolved

### Bug 1: `fabric_fwd` map not registered in Go loader

**Symptom:** `cluster: failed to update fabric_fwd map: fabric_fwd map not found`
repeated every 2 seconds on both nodes.

**Root cause:** The `fabric_fwd` ARRAY map is defined in `bpf/headers/xpf_maps.h`
and compiled into the xdp_zone ELF object. The bpf2go codegen creates
`zoneObjs.FabricFwd`, but `loader_ebpf.go` did not register it in `m.maps[]`
or add it to `MapReplacements`.

**Fix:** Added two lines to `loadAllObjects()`:
```go
m.maps["fabric_fwd"] = zoneObjs.FabricFwd
replaceOpts.MapReplacements["fabric_fwd"] = zoneObjs.FabricFwd
```

**Commit:** `5044ec1`

### Bug 2: (Pre-existing) WAN gateway unreachable in test environment

**Symptom:** `ping 1.1.1.1` and `ping 172.16.50.1` fail from fw0 and
cluster-lan-host.

**Status:** Pre-existing test environment issue — the upstream router at
172.16.50.1 is not present in the Incus bridge setup. Not related to the fabric
forwarding changes. LAN connectivity (ping 10.0.60.1) works correctly.

## Verification Results

| Check | Result |
|-------|--------|
| `make generate` | 14 BPF programs compiled (9 XDP + 5 TC) |
| `make test` | All tests pass (including 3 new VRRP tests) |
| `make build` + `make build-ctl` | Clean build |
| `make cluster-deploy` | Deployed to both nodes |
| Cluster status | fw0 primary, fw1 secondary, all RGs healthy |
| `fabric_fwd` map | Populated on both nodes (`fabric cross-chassis redirect enabled`) |
| LAN connectivity | Working (cluster-lan-host → 10.0.60.1) |
| WAN connectivity | Pre-existing test env limitation (no upstream router) |

## Commits

1. `dae87cb` — Fix TCP session death on VRRP failback: fabric cross-chassis redirect
   (46 files, 459 insertions, 29 deletions)
2. `5044ec1` — Register fabric_fwd BPF map in loader to fix map-not-found error
   (1 file, 2 insertions)

## Architecture Reference

```
                    ┌─────────────────┐
                    │   WAN Router    │
                    │  172.16.50.1    │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────┴─────────┐       ┌───────────┴───────────┐
    │      fw0          │       │        fw1            │
    │  ge-0-0-1.50      │       │  ge-7-0-1.50          │
    │  (WAN MASTER)     │       │  (WAN BACKUP)         │
    │                   │ fab0  │                       │
    │  ──────────────── ├───────┤ ──────────────────    │
    │                   │       │                       │
    │  ge-0-0-0         │       │  ge-7-0-0             │
    │  (LAN BACKUP*)    │       │  (LAN MASTER*)        │
    └─────────┬─────────┘       └───────────┬───────────┘
              │                             │
              └──────────────┬──────────────┘
                             │
                    ┌────────┴────────┐
                    │  LAN Hosts      │
                    │  10.0.60.0/24   │
                    └─────────────────┘

    * During the 2.1s failback window

    Normal path:   WAN → fw0 → FIB → LAN
    Failback path: WAN → fw0 → FIB FAIL → fabric → fw1 → FIB → LAN
```

## Userspace dataplane: FabricRedirect unsendable fail-closed (#1946)

The Rust AF_XDP helper resolves a `FabricRedirect` disposition
(`resolve_fabric_redirect`, `userspace-dp/src/afxdp/forwarding/fabric.rs`)
into an L2 redirect: re-header the original packet with the fabric
peer/local MACs and TX it out the fabric parent so the **peer** runs it
through its full pipeline. A FabricRedirect frame is therefore a
cross-chassis L2 redirect — it is **never** a packet for the local kernel
FIB.

There are two rare conditions where the helper cannot TX a FabricRedirect
to the peer, across both the desc-frame path and the Prebuilt fast path
(an embedded-ICMP NAT-reversed error whose resolution turned into a
fabric redirect via `finalize_embedded_icmp_resolution`):

1. **No XSK binding on the fabric parent** — the bind is not yet ready or
   `bind()` failed (`tx/dispatch/mod.rs`, the
   `resolve_pending_forward_target_binding` `None` arm — both the
   desc-frame fallback and the Prebuilt fast path).
2. **Build/enqueue failure** — the fabric parent binding exists but the
   forward-frame build or TX-ring enqueue failed
   (`handle_forward_build_failure`, `tx/dispatch/slow_path.rs`, for the
   desc-frame path; the Prebuilt local-enqueue failure arm in
   `tx/dispatch/mod.rs`).

In all of these the frame is **dropped fail-closed** and counted on the
per-binding `fabric_redirect_unsendable_drops` counter (surfaced on
`BindingStatus`; Go `FabricRedirectUnsendableDrops`), with a distinct
exception reason (`fabric_redirect_no_binding` vs
`fabric_redirect_build_failed`) for path observability. It is **not**
reinjected to the local kernel slow path.

Reinjecting a FabricRedirect locally would re-introduce exactly the
wrong-path / session-poisoning hazard this whole mechanism exists to
avoid (the kernel-route fallback in the asymmetric-routing window), plus
the slow-path reinject primitive strips L2 and applies NAT — wrong for a
fabric redirect that wants the original L2 frame, pre-NAT. This is the
same class of fail-closed gate as the #1873 R-C
`tunnel_encap_unresolved_drops` tunnel-reinject guard.

Before #1946 this was asymmetric: an `Owned` (GRE-decapped copy) no-
binding frame was raw-reinjected while a `Live` (raw in-UMEM) one was
silently dropped by the filtered `maybe_reinject_slow_path` wrapper
(`FabricRedirect` is excluded by `is_slow_path_eligible`), and the
build-failure path raw-reinjected both. #1946 makes all of them drop
fail-closed + count.

## Standby session retention on the userspace wheel (#2120)

Fabric cross-chassis forwarding keeps a flow alive across a VRRP
failback, but it only helps if the new primary still HAS the synced
session to redirect for. The standby must therefore RETAIN its synced
sessions until it is promoted.

In the eBPF era the Go conntrack GC's `IsLocalPrimary` gate kept the
standby from aging synced sessions. After the eBPF retirement
(#1373/#1476) the Go GC is `SkipSweep`'d in userspace mode (its
`IsLocalPrimary` gate is dead code) and expiry moved to the Rust
per-worker timer wheel, which had NO standby gate — so the standby
silently reaped long-lived peer-synced sessions at ~300 s (TCP idle) with
no local refresh, and the newly-promoted primary then dropped their return
traffic as a brand-new connection (#131 reintroduced).

#2120 restores the contract as a **per-RG standby retention gate in the
wheel** (`userspace-dp/src/session/expire.rs`): the standby HOLDS a
peer-synced session for an RG it does not currently FORWARD
(`HAGroupRuntime::is_forwarding_active`, the same lease-backed predicate
the fabric-redirect path trusts), self-heals it on promotion via the
`rg_epochs` edge (including the node-level `rg_epochs[0]` for
`owner_rg_id == 0` fabric/reverse entries), and reaps it at a bounded
`min(3 × timeout, ~7 d)` ceiling if a primary delete is lost. The epoch
bump moved BEFORE `rg_runtime.store` in `afxdp/ha/state.rs::update_ha_state` so
a worker that sees the active RG always sees the bumped epoch (airtight
self-heal). The control-plane sync sweep is unchanged — retention is the
wheel's job, not the sweep's (see `pkg/cluster/README.md` and
`userspace-dp/src/session/README.md` "Standby retention"). This keeps
#270's empty-sweep back-off and avoids the >1/s control-socket contention
CLAUDE.md warns against.

## Fabric-link build/refresh observability + persistence (#3773)

A fabric redirect can only fire if a `FabricLink` was actually built for
the parent interface. Two resolution passes build them:

- **snapshot build** — `populate_fabrics`
  (`userspace-dp/src/afxdp/forwarding_build/fib.rs`), run for every
  `build_forwarding_state` (config apply + route-churn `bump_fib`).
- **runtime refresh** — `resolve_fabric_links_from_snapshots`
  (`userspace-dp/src/afxdp/forwarding/fabric.rs`), driven by the Go daemon's
  `SyncFabricState`/`refreshFabricFwd` (`update_fabrics` control verb) once
  ARP/NDP resolves the peer MAC that was unresolved at initial build.

### Peer-MAC resolution is constrained to the peer's identity (#6554)

Every peer-MAC resolution that reaches the dataplane is keyed on the
**configured fabric peer address**:

- `FabricSnapshot.peer_mac` comes from `buildFabricPeerMAC`
  (`pkg/dataplane/userspace/fabric.go`) — an address-matched neighbour
  lookup on the overlay, then the parent. It applies the same validity
  predicate as `refreshFabricFwd`, `FabricNeighUsable`: a 6-byte Ethernet
  address in a NUD state the kernel believes. Until #6598 it applied
  NEITHER check and took any address-matched entry with a non-nil
  `HardwareAddr`, so the LIVE resolver was laxer than the one #6554
  hardened — and an entry that had gone `NUD_FAILED` while retaining the
  peer's old lladdr, exactly what the `programRethMAC` link
  DOWN → set-MAC → link UP sequence produces, was accepted as the
  cross-chassis redirect destination.

  When nothing qualifies it returns empty, and empty is a deliberate
  degrade rather than a gap: the dataplane treats an empty `peer_mac` as
  UNRESOLVED and falls back to its own neighbour table, which is
  NUD-allowlisted at insert (#3771 M12) — a STRICTER resolver than the
  stale entry that used to be returned, not a laxer one. If that cannot
  answer either, the link is skipped as
  `FabricSkipReason::UnresolvedPeerMac`, which is counted and recorded by
  name. Both beat forwarding to a MAC the peer no longer owns, which is
  silent and looks like a working fabric.

  The predicate has ONE definition, in the package that owns the live
  resolver, and `pkg/daemon` consumes it at all five of its fabric
  neighbour decisions (the ARP/NDP probe gate, the link-local candidate
  filter, fab0's overlay and parent legs, fab1's leg). Both packages
  answer the same question, so a disagreement between them is a defect by
  construction rather than a difference of policy — hence one definition
  rather than two that agree. `TestFabricNeighPredicateHasOneDefinition_6598`
  walks the AST of `daemon_ha_fabric.go` and fails both if a `NUD_*`
  constant is named there again and if the delegating call count changes,
  so re-duplicating the mask AND deleting a check outright are both
  caught. Note that `usableNUD` in `daemon_neighbor_listener.go` is a
  DIFFERENT set (it admits `NUD_NOARP` and is a publish-time filter for
  the neighbour snapshot) and is deliberately not folded in. #7443 wrote
  that separation into a comment at BOTH masks, each naming the other and
  the question it answers, so a future single-sourcing pass cannot read
  the divergence as drift and "fix" it. What is recorded is that keeping
  them apart is deliberate; what is NOT recorded anywhere is a rationale
  for excluding `NUD_NOARP` from `FabricNeighValidStates` specifically,
  and the comment says so rather than inventing one.

  **The live resolver is bound by a test, not just the helper it calls
  (#7443).** #6598's coverage was a table over `selectFabricPeerMAC` plus
  the AST scan above. Neither executed `buildFabricPeerMAC`, so restoring
  that function's body to the pre-#6598 inline loop — the exact shipped
  defect — passed `go vet` and both full suites; `selectFabricPeerMAC`
  went dead under the revert, but Go does not error on an unused
  package-level function and this repo runs no `unused`/staticcheck gate,
  so nothing complained. The netlink read now goes through the
  `fabricNeighListFn` seam (same shape as `ruleListFn` in `routes.go`, and
  as the `d.linkByNameFn`/`d.neighListFn` seams #6554 added for this
  purpose), and `fabric_peer_mac_binding_7443_test.go` drives the real
  resolver against a synthetic neighbour table: a `NUD_FAILED` entry
  holding the peer's old lladdr must not become the redirect MAC, the
  overlay→parent fallback must survive rejecting the overlay entry, a
  usable overlay entry must stop the search, and a v6 peer must be looked
  up on `FAMILY_V6`. Restoring the pre-#6598 body now fails on an
  assertion — `buildFabricPeerMAC = "02:bf:72:cc:00:01", want ""` — with
  `go vet` still clean; with the new fixture removed the same revert goes
  green again, which is what makes it a closure rather than a claim.
- The Rust redirect's own late resolution
  (`resolve_fabric_links_from_snapshots`) looks the peer up in
  `dynamic_neighbors` keyed on `(ifindex, peer_addr)`.

The Go daemon's `refreshFabricFwd` (`pkg/daemon/daemon_ha_fabric.go`) has
one leg that has **no peer address to match on**: after overlay ARP and
parent ARP both miss, it sweeps the fabric parent's IPv6 NDP table for a
link-local neighbour. That table is deliberately seeded by pinging
`ff02::1` (all-nodes link-local multicast) in `probeFabricNeighbor`, so
**every** IPv6-speaking host on the fabric segment answers and lands in
it. Before #6554 the sweep took the first non-self link-local entry it
found — on a shared fabric segment that is an unrelated adjacent host.

`selectFabricPeerLinkLocalMAC` now constrains the sweep to the peer's
identity, strongest constraint first:

1. **Known peer MAC.** `refreshFabricFwd`/`refreshFabricFwd1` cache the
   MAC of every ADDRESS-MATCHED resolution (`d.fabricPeerMAC`,
   `d.fabricPeerMAC1`) — the MAC that actually answered for the
   configured peer address. When that identity is known, only a
   neighbour bearing it is accepted. The cache is never written by the
   fallback itself (a bad guess must not self-confirm) and is dropped
   when the configured peer address changes, so a re-pointed fabric is
   not pinned to the old chassis and a legitimately changed peer MAC
   self-heals on the next address-matched resolution.
2. **Checked point-to-point assumption.** On a cold start with no
   address-matched observation yet — the crash-recovery case this
   fallback exists for — the sole eligible neighbour is accepted and an
   ambiguous segment (two or more distinct neighbour MACs) is refused.
   Candidates are deduplicated by MAC, so a peer owning several
   link-local addresses on one NIC still counts as one host.

Ineligible entries never become candidates: a non-`fe80::/10` address, an
unusable NUD state, a group-bit (multicast) MAC, or this node's own MAC.

**Fail direction — refuse, do not fall back to permissive.** A refusal
returns no MAC, which lands on the existing "peer neighbour missing"
path: `retainFabricFwdOnNeighborMiss` keeps a previously-good
`fabric_fwd` entry, otherwise `clearFabricFwd0` clears it and
`fabricPopulated` stays false. That is the *same* state the node already
occupies whenever the peer genuinely does not resolve on a normal fabric
— not a new degradation mode. It does **not** blackhole cross-chassis
traffic: the dataplane's redirect takes its destination MAC from
`FabricSnapshot.peer_mac`, resolved independently and strictly by peer
address. What a refusal does cost is the `fabricPopulated` latch, which
feeds the RG takeover-readiness gate (`daemon_ha.go`, evaluated only
while the peer is alive) — so the node advertises `fabric forwarding
path not ready` instead of falsely reporting a fabric it cannot identify.
Accepting a stranger's MAC was the worse failure: it reported success,
latched readiness, ended the fast-retry probe loop early, and logged a
peer MAC belonging to an unrelated host during an HA incident.

Distinct from #6458, which validates the **receive** side (zone-encoded
fabric-ingress stamps); this constrains the **daemon-side identity check**
that decides when the fabric is declared ready.

Scope limit, stated precisely because it bounds the severity: the MAC this
path programs lands in the retired-eBPF `fabric_fwd` map
(`UpdateFabricFwd`, `pkg/dataplane/maps_fabric.go`). The live Rust redirect
does **not** read it — `resolve_fabric_redirect_from_list` takes
`neighbor_mac` from `FabricSnapshot.PeerMAC`, which
`pkg/dataplane/userspace/fabric.go` re-derives with its own
**address-matched** neighbour lookup (`buildFabricPeerMAC`, which matches
on `neigh.IP.Equal(peer)` and has no link-local fallback). So a
mis-identified peer accepted here never becomes an L2 destination for
cross-chassis frames. That argument designates `buildFabricPeerMAC` as
the trustworthy path, and when it was written that path was the LAXER of
the two — it checked neither NUD state nor address length. #6598 closed
that gap, so the designation now holds. The damage is exactly the three effects listed
above — false readiness, a truncated fast-retry probe loop, and a
misleading `peer_mac` log line during an HA incident.

One coupling that the word "independent" above does NOT cover, and that an
operator debugging a slow fabric bring-up needs to know. The *resolver* is
independent, but its *refresh trigger* is not: `refreshFabricFwd` calls
`SyncFabricState` only on its SUCCESS path, and that verb is the sole caller of
the Rust `Coordinator::refresh_fabric_links`
(`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs`) — i.e. the only thing
that drives the helper's `dynamic_neighbors` late resolution outside a full
forwarding rebuild. So when this path REFUSES an ambiguous peer, the push does
not fire either.

The one scenario where that is observable: the peer address is present in the
helper's neighbour map but absent or NUD-invalid in the daemon's view, on an
ambiguous segment. Before the #6554 constraint, the decoy made the refresh
"succeed", which fired `SyncFabricState`, and Rust then resolved the CORRECT MAC
by address. Now the push waits for the next full forwarding rebuild. This is not
a blackhole — `resolve_fabric_redirect` returning `None` puts the packet on its
normal non-fabric disposition, the same safe path #5686 relies on — but it is a
real latency coupling, not an independence.

Calling `SyncFabricState` on the refusal path as well is deliberately NOT done.
This leg runs on every neighbour event plus the 30 s tick plus the 2 s
reconcile-driven `triggerFabricRefresh`, and the control socket is shared with
status poll, HA sync, session installs, and snapshot sync; CLAUDE.md is explicit
that a new control-socket caller above 1/s starves session installs during bulk
sync. The coupling is documented rather than removed.

### M13 — skipped fabric links are counted + named (was a silent `continue`)

Before #3773 each pass dropped a fabric link on a bare `continue` when
`parent_ifindex <= 0`, the `peer_address` was unparseable, the `local_mac`
was unresolvable, or the `peer_mac` was unresolvable — **no counter, log,
or status**. An HA cross-chassis fabric link that silently failed to
install (and therefore silently did not forward) was invisible; the
operator had no way to see an unresolved fabric.

Both passes now route the skip-vs-install decision through the shared
`build_fabric_link_or_skip` classifier, which partitions skips into two
cumulative diagnostic atomics (`forwarding/fabric.rs`):

- **`FABRIC_LINK_SKIPPED_MALFORMED`** — an invalid parent ifindex, an
  unparseable peer address, or a **non-empty** local/peer MAC string that
  failed to parse. A config/environment fault that will not self-heal.
  Surfaced as `xpf_userspace_fabric_link_skipped_malformed_total`.
- **`FABRIC_LINK_UNRESOLVED_PEER`** — an **empty** peer/local MAC field
  still awaiting neighbor/interface resolution: the expected transient of
  the late-resolution `SyncFabricState` path (peer MAC empty until ARP/NDP
  resolves). Briefly non-zero at startup is normal; a persistently
  climbing value means a fabric peer is not resolving. Surfaced as
  `xpf_userspace_fabric_link_unresolved_peer_total`.

Fabric is an HA *optimization*, not enforcement, so a malformed link is
**skipped-with-visibility, not fail-closed-whole-snapshot** — the rest of
the forwarding state still applies (a single bad fabric stanza must not
blackhole the whole dataplane). This mirrors the #3771 M12
`NEIGHBOR_UNKNOWN_STATE_SKIPPED` diagnostic-atomic pattern.

The counters quantify; a named journal line qualifies. Each build/refresh
records its skips (by fabric name + reason) in
`ForwardingState.fabric_skips`, and `log_fabric_skip_transition`
(`coordinator/mod.rs`, mirroring `log_wg_endpoint_set_transition`) emits
`fabric skip set changed (<path>): [...] => [...]` **only when the set
changes** — so a persistently unresolved/malformed fabric logs ONCE when
it first appears (or changes reason), not on every 30s `SyncFabricState`
tick or route-churn `bump_fib`. The `snapshot-refresh` path prunes a skip
whose parent was re-added by the preserved-fabric merge (a link kept from
the prior resolved set is not reported as skipped).

### L4 — the `update_fabrics` refresh is now persisted

`update_fabrics` (`server/handlers/mod.rs`) was the only mutating control
verb that neither updated the stored snapshot nor set `persist_state`, so
a late-resolved peer/local MAC lived **only** in the coordinator's
in-memory forwarding state. The published state file (read by the Go
control plane's `show` surface, and the last record a consumer sees) kept
the stale apply-time (unresolved) fabric MACs.

The handler now folds the freshly-resolved `FabricSnapshot`s into the
stored snapshot and flags a write **only when the set actually changed**
— so the 30s periodic refresh does not rewrite the state file on every
unchanged tick.

**Restart continuity is explicit and is provided by the Go control plane,
not this file.** The helper starts with `snapshot: None`
(`server/lifecycle.rs`) and never self-restores from the state file; on
restart the daemon re-applies the full snapshot and re-runs
`populateFabricFwd` (500 ms fast retries → 30 s periodic), which
re-resolves and re-syncs the fabric MACs within seconds. The persisted
fabric set is therefore the **observability snapshot** (so `show` reflects
the resolved truth), not the restore source.

### L5 — the Go control plane persists the resolved set too (#5306)

The Rust-side persistence above (#3773/#3833) closed the *state-file*
staleness, but the Go control plane had the mirror-image gap.
`SyncFabricState` (`pkg/dataplane/userspace/manager_fabric_sync.go`) resolved the
peer/local MACs via `buildFabricSnapshots` and shipped them to the helper
over `update_fabrics`, but it never wrote the resolved set back into Go's
own `m.lastSnapshot.Fabrics`. The Go snapshot therefore kept the
apply-time (unresolved-MAC) fabrics.

That mattered because the **partial-rebuild publish paths** —
`PublishRouteOverlaySnapshot` (ip-monitoring), the policy-scheduler
republish, and the #5134 worker-arm re-apply — each start from
`next := *m.lastSnapshot` and rebuild **only** `Routes`, re-publishing every
other section (Fabrics included) verbatim. With the stale Fabrics still in
`m.lastSnapshot`, the next such `apply_snapshot` re-shipped the
unresolved-MAC fabrics and **silently reverted** the helper to the
unresolved fabric MAC — during the exact HA window fabric cross-chassis
forwarding exists to preserve.

`SyncFabricState` now writes the resolved set back into
`m.lastSnapshot.Fabrics` after a successful `update_fabrics`
(`persistResolvedFabricsLocked`, mirroring `RegenerateNeighborSnapshot`'s
post-publish writeback): it advances the generation + `publishedSnapshot`
and refreshes `lastSnapshotHash`, and is a no-op when the fabric set is
unchanged so the periodic refresh does not churn the generation. A
subsequent partial rebuild's `next := *m.lastSnapshot` now carries the
resolved fabrics forward instead of reverting them. The writeback is
gated on the send succeeding (mutate-after-success), so
`m.lastSnapshot.Fabrics` is the last set Go saw the helper accept. That is
not always what the helper holds: a deadline or EOF can follow an
`update_fabrics` the helper applied. #9684 marks the section unknown on
such a failure, and the next partial-rebuild publish re-samples the fabric
rows instead of inheriting the old ones. The re-sample keeps each row's plan
half (the parent interface and netdev, the netdev's ifindex and queue count,
and the device verdict) and refreshes every other field, so it never moves
the binding plan. A plan-half change needs a full apply; #9803 is
`update_fabrics` storing one without it
(`pkg/dataplane/userspace/partial_update_outcome_9684.go`).

## Same-parent peer replacement must invalidate the stale peer (#5686 M01)

The two fabric-authority paths PRESERVE an already-resolved `FabricLink`
across a build/refresh that could not re-resolve it: `refresh_fabric_links`
(the `SyncFabricState` / `update_fabrics` path) keeps the prior working set
when *nothing* resolves this pass, and `refresh_runtime_snapshot_inner` (the
config-apply path) merges old links back for any parent absent from the new
build. That preserve exists because a fabric peer's neighbor MAC resolves
asynchronously — the snapshot for a parent can be present but UNRESOLVED
(empty `peer_mac`) for a window until ARP/NDP completes, and blindly wiping
the resolved link during that window would blackhole cross-chassis
forwarding.

The bug (codex-review-182 M01): the preserve/merge keyed only on
`parent_ifindex`. When a fabric peer under the SAME parent is **replaced**
(the configured `peer_address` changes), the replacement arrives UNRESOLVED,
so it is skipped and absent from the new resolved set — and the preserve
logic kept the OLD link because its parent still existed. During the
replacement's resolution window the STALE old peer therefore remained a valid
`resolve_fabric_redirect` target, and a synced-session packet could be
fabric-redirected to a peer that is no longer current.

**The exact window:** from the moment the replacement `peer_address` is
staged (a new snapshot for parent X names peer `P_new`, still unresolved)
until `P_new`'s neighbor MAC resolves. Throughout that window the old link
`X → P_old` was authoritative AND `P_new` was not yet installable.

**Fix — invalidate-before-accept, keyed on peer identity.** A preserved link
is SUPERSEDED when the incoming snapshots configure its parent but name a
different, parseable peer address
(`fabric_link_superseded_by_snapshots`, `afxdp/forwarding/fabric.rs`). A
superseded link is dropped from the preserved/merged set *before* it can be
kept, in both paths. Consequences:

- The moment the replacement is staged, `X → P_old` is gone. It is never
  again returned by `resolve_fabric_redirect`.
- While `P_new` is unresolved, `resolve_fabric_redirect` yields **no target**
  for parent X, so the synced-session packet takes its normal non-fabric
  disposition (its local/forward path) — the safe fallback, never a
  wrong-peer redirect. This matches the pre-existing fail-closed contract:
  redirecting to "nothing" degrades to normal forwarding, not a silent drop.
- When `P_new` resolves, it installs normally and becomes the redirect
  target.

Only a same-parent **different-peer** snapshot supersedes. A snapshot that
still names the same peer (the steady-state 30 s refresh) does not — the
working link is preserved unchanged. A snapshot that OMITS the parent
entirely (fabric removed, not replaced) does not — link teardown is a
separate concern and the preserve-across-unresolved behavior is retained. An
unparseable replacement address is ignored (the malformed new link cannot
resolve anyway).

**Reader visibility.** The pruned set is stored into BOTH the full
`ha.runtime` view's forwarding Arc (the worker's authoritative per-tick
reload) AND the
worker fast-path `ha.fabrics` Arc. The worker overwrites its
`forwarding.fabrics` from `ha.fabrics` only when that Arc is non-empty, so
leaving a stale non-empty `ha.fabrics` would re-add the superseded link the
`ha.runtime` store just removed — both must be updated in lock-step. A
torn read (old link gone, replacement not yet visible) is harmless here
because "no target → safe fallback"; the invariant that must never break is
that the OLD link is not readable after the replacement is staged.

Guarded by `refresh_fabric_links_replacement_peer_invalidates_stale_old_5686`
(the fail-on-revert: neutralizing the prune makes the "old peer is no longer
a redirect target" assertion go RED),
`refresh_fabric_links_replacement_leaves_other_parent_untouched_5686`
(a different-parent peer is unaffected during the replacement window), and
`fabric_link_superseded_by_snapshots_only_on_same_parent_different_peer_5686`
(the supersession predicate).

## Rate-based flood screens are not re-counted on fabric-redirected traffic (#4155)

A packet that ingresses the **non-owner** node for a session the RG **owner**
owns is screened on the ingress node and then fabric-redirected to the owner
(the Fix 1 path above). Before #4155 the owner **re-ran** the full screen stage
on that redirected packet, so the **rate-based flood counters** (`icmp-flood`,
`udp-flood`, `syn-flood`) counted the **same packet twice** against the
per-zone / per-destination flood thresholds. A legitimate high-pps synced
session could then false-trip a flood `Drop` on the owner — dropping exactly the
traffic fabric forwarding exists to keep alive during failback /
asymmetric-routing windows. This also diverges from vSRX, which does not
re-apply screens to fabric-forwarded traffic.

**Fix.** Stage 9 (`stage_classify_fabric_ingress`, `afxdp/poll_stages.rs`)
already sets `FABRIC_INGRESS_FLAG` on `meta.meta_flags` for a fabric-redirected
packet. Stage 10 (`stage_screen_check`) now derives
`skip_rate_flood = (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0` and threads it
into `ScreenState::check_packet_with_zone_id_opts` /
`check_flowless_screens_opts` (`screen/mod.rs`). When set, the screen runtime
runs the **stateless** per-packet screens (land, ping-of-death, teardrop,
icmp-fragment, source-route — idempotent, so re-running them on the owner is
correct) and then returns before the **rate-based** flood counters, so the
owner never re-counts the packet. The per-destination flood sketches (#4132) are
left intact — the fix skips the re-count, it does not disable the screen. The
per-`(zone, src)` **scan/sweep** new-flow counter is skipped the same way at the
session-miss decision in `poll_descriptor/mod.rs` (gated on
`packet_fabric_ingress`), for the sync-race window in which a fabric-redirected
packet arrives before its synced session installs; the per-IP session-limit
check there still runs because it guards the owner's own `SessionTable`, which
the ingress node did not populate.

The flood screen therefore fires **once**, on the true cluster-ingress node.
RED-on-revert coverage: `screen/tests.rs`
(`fabric_skip_does_not_count_{icmp,udp,syn}_flood_4155`,
`fabric_skip_leaves_direct_ingress_counting_intact_4155`, plus the stateless
scope guards) and `afxdp/poll_stages.rs`
(`fabric_ingress_skips_rate_flood_direct_still_counts_4155`, driving the live
`stage_screen_check`).

## The cluster-peer return fast path must not adopt NEW UDP flows (#4439)

`cluster_peer_return_fast_path` (`userspace-dp/src/afxdp/forwarding/fabric.rs`,
called from the session-MISS decision in `poll_descriptor/mod.rs`) exists for
the sync-race sub-window: a packet the active RG owner already
policy/NAT-validated is fabric-redirected to the peer, arrives before the
synced session installs, and must still be handed to the local egress instead
of being treated as a brand-new flow. It builds a NAT-less
(`NatDecision::default()`), reverse-keyed (`is_reverse: true`) seed and
forwards the packet.

It is reached **only after** `resolve_flow_session_decision` misses in every
scope (local + synced forward key + forward-NAT reply key), so a genuine
established flow's return packet — including the whole failback-preservation
case above — is served by the synced session and never lands here. Anything
reaching this fast path is therefore **session-less**.

**The bug.** This fast path may fire ONLY for packets that are provably RETURN
traffic. Every protocol with a packet-level flow-initiator marker is excluded:
TCP excludes the initial SYN, ICMP excludes the echo REQUEST. **UDP has no such
marker** — any datagram can open a new flow, and there is no "non-initiating
UDP" form. Before #4439 a session-less UDP datagram that was a genuinely NEW
forward flow (e.g. an outbound flow that ingressed the non-owner node and was
fabric-redirected to the RG owner) was adopted by this fast path as return
traffic. Two failures followed on the owner:

1. **NAT bypass.** The reverse seed carried `NatDecision::default()`, so the
   **source-NAT** a new outbound flow requires was never applied — the packet
   left with its private source address/port.
2. **Session-state corruption.** The owner installed a **reverse-keyed**
   (`SessionOrigin::ReverseFlow`) session for what was actually a forward flow,
   so subsequent packets and the real reply resolved against a mis-directioned
   session.

Confirmed 3× (ps-013/014/015).

**The fix.** `cluster_peer_return_fast_path` now returns `None` for
`meta.protocol == PROTO_UDP`, completing the flow-initiator-exclusion
invariant (TCP-SYN, ICMP-echo-request, and now all UDP). A session-less UDP
packet falls through to the normal forward decision, where — because the RG
owner resolves it to a `ForwardCandidate` (not a `FabricRedirect`) — source-NAT
is applied (`apply_nat = !fabric_redirect || apply_nat_on_fabric` is `true` for
a non-redirect egress) and a FORWARD session is installed. The session-miss
forward path already anticipates fabric-ingress packets (the #4155 sync-race
`packet_fabric_ingress` handling), so no other change is required; the
non-owner keeps redirecting the original pre-NAT frame (`apply_nat_on_fabric`
stays `false`), matching the Fix 1 "peer processes it through its full
pipeline" design.

The legitimate fabric-forward for an established synced session is untouched:
it is served by `resolve_flow_session_decision` (the synced session + #2120
standby retention), not by this session-less fast path. TCP (non-SYN) and ICMP
(echo-reply) return traffic continue to fast-path as before.

RED-on-revert coverage: `forwarding/tests.rs`
`cluster_peer_return_fast_path_skips_udp_new_flow_4439` (UDP against the same
ForwardCandidate-resolving target the ICMP-reply test uses — returns `Some` on
revert, `None` with the fix) alongside the preserved
`cluster_peer_return_fast_path_allows_sfmix_to_lan_reply` (ICMP echo reply
still fast-paths) and `_skips_pure_tcp_syn` / `_skips_icmp_echo_request`.

## The return fast path must not adopt a bare RST/FIN either (#4453)

The #4439 UDP exclusion left one class of session-less packet still adopted:
a **bare TCP RST/FIN** (`is_closing(flags) && !has_syn(flags)`). It is NOT an
initial SYN, so the `is_initial_syn` exclusion above misses it, and it is not
UDP. Reaching this fast path it was therefore fast-pathed into a NAT-less,
reverse-keyed seed — the same seed-a-closing-session failure the local
session-miss path already rejects.

**The bug.** #4400 added `strict_syn_check_drops_new_flow(protocol, flags) ==
PROTO_TCP && is_closing(flags) && !has_syn(flags)` and dropped a bare RST/FIN
on the LOCAL session-MISS cold path — an immediately-closing session has no
forwarding value (pure churn, a cheap RST/FIN-flood DoS surface). But the
fabric return fast path had no equivalent guard. A transit bare RST/FIN to a
locally-**HAInactive** RG is converted to a `FabricRedirect` by the safety net
(`resolve_fabric_redirect` / the HAInactive downgrade in
`enforce_ha_resolution_snapshot`) and forwarded to the peer. On the peer it
arrives as **fabric ingress**, misses every session scope, and
`cluster_peer_return_fast_path` adopted it — installing on the peer, **via the
trusted fabric path**, exactly the phantom-closing session the peer's own
#4400 guard prevents locally. It is gated behind the trusted internal fabric
link (not externally forgeable without targeting an HAInactive RG), so the
impact is per-worker session-table churn on the peer, not a data-plane
compromise — but it defeats the #4400 invariant across the fabric.

**The fix.** `cluster_peer_return_fast_path` now returns `None` for
`PROTO_TCP && is_closing(flags) && !has_syn(flags)` (the SAME predicate as
#4400). A bare RST/FIN falls through to the peer's normal forward decision,
whose own session-miss #4400 guard drops it — no reverse seed installed. This
completes the fast-path flow-initiator-exclusion invariant: it fires ONLY for
provably-return traffic, excluding the TCP initial SYN, the ICMP echo request,
all UDP, AND the bare TCP RST/FIN. The legitimate fabric-forward for an
established synced session is untouched — an established flow's real RST/FIN is
served by `resolve_flow_session_decision` (the synced session) before this
point, so it is a session HIT, never session-less. TCP data (non-SYN,
non-closing) and ICMP echo-reply return traffic continue to fast-path.

RED-on-revert coverage: `forwarding/tests.rs`
`cluster_peer_return_fast_path_skips_bare_rst_fin_4453` (bare RST / FIN /
FIN|ACK / RST|ACK against the same ForwardCandidate-resolving target the
ICMP-reply test uses — returns `Some` on revert, `None` with the fix)
alongside the preserved `_allows_sfmix_to_lan_reply`,
`_skips_udp_new_flow_4439`, `_skips_pure_tcp_syn`, and
`_skips_icmp_echo_request`.

## Every markerless protocol must be excluded, not just UDP (#4414)

#4439 excluded UDP and #4453 excluded the bare TCP RST/FIN, but the guard was
still enumerated protocol-by-protocol. Its own stated invariant — *fire only
for provably-return traffic, and every protocol without a flow-initiator
marker (like UDP) can open a NEW flow so must be excluded* — was applied to
UDP alone. **Every other markerless L4 was left adopted:** ESP, AH, GRE, SCTP,
OSPF, and any other IP protocol that is neither TCP nor ICMP/ICMPv6 has no
"non-initiating" form, exactly like UDP.

**The bug.** A session-less packet of such a protocol — a genuinely NEW
forward flow (e.g. an outbound ESP/GRE/SCTP flow that ingressed the
locally-**HAInactive** node and was fabric-redirected to the RG owner) —
reached `cluster_peer_return_fast_path`, resolved to a `ForwardCandidate`, and
was adopted as return traffic. The two #4439 failures followed on the owner,
now for the whole non-TCP/non-ICMP protocol space:

1. **NAT bypass.** The reverse seed carried `NatDecision::default()`, and the
   redirecting node keeps `apply_nat_on_fabric = false` (it forwards the
   original pre-NAT frame, deferring NAT to the owner), so the source-NAT a
   new outbound flow requires was applied by *neither* node — the internal
   source address/port left on the wire.
2. **Session-state corruption.** The owner installed a **reverse-keyed**
   (`SessionOrigin::ReverseFlow`) session for what was actually a forward
   flow, so subsequent packets and the real reply resolved against a
   mis-directioned session.

Both failures share one root cause: a NON-return flow taking the return fast
path. Confirmed 2× (opus-review-171 M-3 / ps-review-017 P7).

**The fix.** `cluster_peer_return_fast_path` now returns `None` for any
`meta.protocol` that is not `PROTO_TCP`, `PROTO_ICMP`, or `PROTO_ICMPV6`
(subsuming the #4439 UDP-only guard). Only TCP and ICMP/ICMPv6 carry a
distinguishable initiator form — TCP excludes the initial SYN and bare RST/FIN,
ICMP excludes the echo REQUEST — so the surviving admitted set is exactly the
provably-return forms: established TCP (non-SYN, non-closing) and ICMP/ICMPv6
echo-reply / error responses. A markerless-protocol packet falls through to
the owner's normal forward decision, where — because the RG owner resolves it
to a `ForwardCandidate` (not a `FabricRedirect`) — source-NAT is applied
(`apply_nat = !fabric_redirect || apply_nat_on_fabric` is `true` for a
non-redirect egress) and a FORWARD session is installed. This closes BOTH the
NAT bypass and the reverse-seed corruption in one change, since both stem from
the single "non-return flow on the return fast path" root cause.

The legitimate fabric-forward for an established synced session is untouched:
it is served by `resolve_flow_session_decision` (the synced session + #2120
standby retention) before this session-less fast path, so it is a session HIT.

This completes the flow-initiator-exclusion invariant as a positive
allow-list rather than a growing deny-list: the fast path fires ONLY for TCP
and ICMP/ICMPv6 in their return forms, and refuses UDP and every other
markerless protocol.

RED-on-revert coverage: `forwarding/tests.rs`
`cluster_peer_return_fast_path_skips_markerless_proto_new_flow_4414` (ESP / AH
/ GRE / SCTP / OSPF against the same ForwardCandidate-resolving target the
ICMP-reply test uses — returns `Some` on revert, `None` with the fix)
alongside the preserved `_allows_sfmix_to_lan_reply`,
`_skips_udp_new_flow_4439`, `_skips_bare_rst_fin_4453`, `_skips_pure_tcp_syn`,
and `_skips_icmp_echo_request`.

## The zone-encoded stamp must prove it came from the peer (#6458)

The zone-encoded synthetic source MAC (`02:bf:72:fe:<hi>:<lo>`) exists so a
new flow whose ingress-RG primary and egress-RG primary differ — split-RG
active/active steady state, or an asymmetric failover window — can be
punted raw to the egress RG owner and admitted there under the TRUE zone
pair. Before #6458 the receive-side decode
(`parse_zone_encoded_fabric_ingress_from_frame`) validated only fabric
ingress + magic bytes + that the zone id exists, and every session-MISS
consumer (zone-pair policy, screens, SYN cookie, IKE admission,
host-inbound, `cluster_peer_return_fast_path`) preferred the decoded
override over the interface-derived zone. `StableZoneID` is a public FNV-1a
name hash (`pkg/config/zoneid.go`), so any L2-adjacent host on the fabric
segment could compute the stamp offline and PICK the ingress zone the
receiving node evaluates under — a fail-open of the zone-policy, screen,
and host-inbound trust boundaries (a forged `mgmt` stamp made the
management plane reachable from the fabric segment with no transit policy
at all).

### Why validation, not removal

Deleting the override on session miss (the issue's option (a)) fails
closed but ALSO fails the legitimate case the stamp exists for: the owner
can no longer evaluate the true zone pair for a punted new flow, so every
split-RG active/active flow and every asymmetric-window new flow
default-denies permanently (see
`docs/active-active-new-connections.md`). The stamp is the only carrier of
the true ingress zone on the receiver, so the fix VALIDATES it instead.

### The validation (receive side)

A stamp is honored only when ALL of the following hold, in addition to the
pre-existing gates (fabric ingress, magic, id != 0, zone exists):

- **V1a — unicast to our fabric link.** The frame's destination MAC must
  equal the matched fabric link's `FabricLink.local_mac`
  (`forwarding::fabric::zone_encoded_fabric_stamp_valid`). The legitimate
  sender always unicasts the redirect to the peer's fabric MAC
  (`resolve_fabric_redirect_from_list` sets
  `neighbor_mac = fabric.peer_mac`; on the IPVLAN fabric the peer's
  neighbor MAC and the receiver's `local_mac` are the same
  parent-shared MAC). Broadcast/multicast sprays and off-target frames
  are rejected.
- **V1b — RG binding.** The claimed zone must have at least one RG-bound
  member interface (new `ForwardingState.zone_to_rgs`, built from
  `ifindex_to_zone_id` x `EgressInterface.redundancy_group`), and NONE of
  its bound RGs may be forwarding-active LOCALLY. A legitimate stamp means
  "this packet ingressed the PEER in this zone"; when the claimed zone's
  RG is primary on the RECEIVER the traffic ingresses locally and the peer
  has no business stamping it. Zones with no RG-bound members (`mgmt`,
  `control`, empty zones) can never be legitimately stamped — this kills
  the host-inbound variant. Evaluated once at stage 9
  (`stage_classify_fabric_ingress`), so screens / SYN cookie / IKE
  admission consume only validated zones.
- **V2 — owner binding.** At every session-MISS zone-pair computation
  (flow-backed, flowless transit, flowless local-delivery, and the
  MissingNeighbor arm) the validated override is honored only when the
  resolution's owner RG (`owner_rg_for_resolution`) is forwarding-active
  locally (`gate_fabric_zone_override_on_owner_rg`): the peer punts a new
  flow to us only because WE own its egress RG. This binds the stamp to
  the packet's actual forwarding outcome, including the rg-0
  local-delivery case V1b cannot see.

### Resulting posture

- **Single-primary cluster (the normal mode):** the primary rejects every
  stamp (V1b: every zone's RGs are ALL local); the backup rejects every
  stamp for new-flow purposes (V2: no owner RG is locally active, and
  transit resolutions are HAInactive there anyway) — INCLUDING the
  Stage-11 IKE host-inbound gate, which applies the same V2 owner binding
  resolved from the packet's local destination address
  (`gate_fabric_zone_override_on_local_owner_rg`, review fold: a forged
  stamped NEW IKE initiation to the backup's reth address is denied and
  never seeds the #6471 live-exchange table). Both nodes fail closed; the
  host-inbound and transit variants are dead on both.
- **Split-RG active/active:** exactly the stamp shapes matching the live
  RG split (claimed-zone RG remote + resolution-owner RG local) are
  honored — the legitimate punt keeps working (pinned by
  `legitimate_fabric_punted_flow_still_admitted_6458` and
  `legitimate_fabric_punted_host_inbound_still_admitted_6458`). A zone
  spanning MULTIPLE RGs keeps the stamp whenever at least one bound RG is
  peer-active (the V1b NONE-active form over-rejected that shape; the
  `zone_encoded_fabric_stamp_honored_for_multi_rg_zone_split_6458` pin
  covers it).
- **A rejected stamp** degrades the frame to today's UNSTAMPED
  fabric-frame posture (the fabric interface's own zone governs policy,
  screens, and host-inbound) — never below it. The subsequent default-deny
  is accounted on the normal policy-deny paths; a dedicated reject counter
  is deferred (it needs proto + Go status plumbing).

### Residual (accepted, documented)

On a SHARED fabric segment with a live RG split, an attacker can clone the
exact stamp shape of a currently-legitimate punt (remote-RG zone, unicast
dst) — byte-identical to the real thing at L2, so no receiver-side check
can reject it without also rejecting the legitimate flow. Full closure on
a shared segment requires a cryptographic boundary: run the fabric
direct-attached (the Junos requirement) or under MACsec. This is the same
trust-domain boundary #4107 draws for the fabric CONTROL plane; the data
path now fails closed everywhere EXCEPT this documented clone case.

RED-on-revert coverage: `forwarding/tests.rs`
(`zone_encoded_fabric_stamp_rejected_on_non_unicast_dst_6458`,
`_rejected_when_claimed_zone_rg_local_6458`,
`_rejected_for_zone_without_rg_members_6458`,
`gate_fabric_zone_override_on_owner_rg_6458`,
`zone_to_rgs_built_from_member_redundancy_groups_6458`) and the poll-loop
end-to-end pins in `afxdp/tests_fabric_zone_stamp.rs`
(`forged_fabric_stamp_denied_when_claimed_zone_rg_is_local_6458` — RED
when the V1b check is neutralized;
`forged_fabric_stamp_denied_for_host_inbound_when_owner_rg_remote_6458` —
RED when the V2 gate is neutralized), plus the split-RG preservation pins
named above.

## The cluster-peer return fast path is removed (#6478)

The sections above describing `cluster_peer_return_fast_path` and its
#4439/#4453/#4414 guard set are HISTORICAL. The fast path adopted
session-less fabric-ingress TCP SYN-ACK / ACK / ICMP echo-reply forms
into a NAT-less (`NatDecision::default()`), reverse-keyed
(`SessionOrigin::ReverseFlow`) seed gated only on the zone-encoded stamp
— the residual the guard set deliberately left open for the sync-race
sub-window. After #6458's stamp validation a forged frame can still pass
V1 on any node where the claimed zone's RG is remote (the single-primary
backup, and every split-RG placement), so the seed stayed forgeable: one
packet forwarded with no policy and no NAT, plus same-tuple fabric-ingress
packets hitting the seed for its lifetime. (The verifier's owner-sync hop
was refuted — reverse + fabric_ingress seeds are excluded from every
export path — so the residual was always confined to the receiving node.)

The fast path and its call site are REMOVED. Session-less fabric-ingress
packets now take the normal session-miss path: zone-pair policy under the
#6458-validated zone, source-NAT applied, a FORWARD session when
permitted — the standard Junos no-syn-check asymmetric-routing pickup
(#3152), identical to the packet arriving on the real interface. The
sync-race sub-window the fast path covered (a peer-punted return packet
arriving before its synced session installs) reverts to a drop, which the
#6478 verifier explicitly prefers over unauthenticated seeding. A genuine
established flow's return traffic is unaffected: it is a session HIT
served by `resolve_flow_session_decision` (synced session + #2120 standby
retention) and never reached the session-less fast path.

### Two corrections to the paragraph above (#7770)

Both were measured against the code path rather than reasoned from it, and
both changed what the residual is.

**The drop is a POLICY DEFAULT-DENY, not `HAInactive`.** This section used
to attribute it to "the return direction's resolution on the receiving node
is HAInactive until the RG converges". It is not. Driving a session-less
`wan -> lan` fabric-ingress return frame through the real poll loop with the
LAN RG local and the WAN RG remote emits
`PolicyDeny action=0 reason=5 ingress_zone=wan egress_zone=lan
policy_id=4294967295`, with `missing_neigh=0`, zero sessions installed and
zero forwards queued. `reason=5` is the TRANSIT policy deny and
`policy_id=4294967295` is the no-match default. The mechanism is that
`wan -> lan` has no permit **by design** — return traffic is admitted by a
SESSION, never by policy — so the receiving node is being asked for a
decision policy alone can never authorise. That matters because the two
attributions imply different fixes: an `HAInactive` drop resolves itself
when the RG converges, and a default-deny does not.

**It is not "confined to the race window", because the window does not
close.** The old wording — "until the RG converges", "the loss is confined
to the race window" — describes a transient. A LAN/WAN redundancy-group
SPLIT (RG0+RG1 on one node, the LAN RG on the other) is a legitimate steady
state reached by two supported `request chassis cluster failover
redundancy-group N node M` commands, and nothing warns that the groups are
now split. In that placement the RGs never converge, so every NEW flow
re-enters the race and pays one packet — measured at 12.5% of an 8-packet
probe in both address families, unchanged on a fresh probe 45 s later.
Long-lived TCP absorbs it as one retransmit; short request/response flows
and UDP (DNS especially) do not. The remedy is below; this paragraph is kept
because the two attributions above are what a reader has to have discarded
before the remedy makes sense.

**Coverage note.** The two RED-on-revert cells listed below drive
`lan -> wan` — the fixture's only permitted pair — so neither exercises the
return direction this residual lives in. That direction is now pinned by
`fabric_ingress_return_traffic_is_denied_on_the_lan_node_7770` in the same
file, which asserts the deny's zone pair and `policy_id` rather than only
the absence of a session (an unstamped frame produces byte-identical
counters). Measured: implementing "skip policy for fabric-ingress packets"
— the tempting fix, ruled dead because it would upgrade the residual below
into a full zone-policy bypass — reds that one cell and no other in the
suite.

### The remedy: the punting node adjudicates and seeds (#7770)

The design question the thread posed was WHERE the return-path authorisation
record lives. It lives on the punting node, and it is an ordinary SESSION.

When a session-MISS packet's resolution is `FabricRedirect` — the flow is about
to leave across the fabric because the peer owns its egress RG — the punting
node now evaluates the flow's REAL zone pair and, on a permit, installs a
`SessionOrigin::FabricPuntSeed` session for it before punting.
`should_seed_fabric_punt` is the gate and `fabric_punt_seed_metadata` does the
adjudication (`afxdp/forwarding/fabric.rs`); the arm is in the session-miss
block of `poll_descriptor`. The peer's return then arrives off the fabric and
is a session HIT, served by `resolve_flow_session_decision` exactly as return
traffic is supposed to be — never by policy, which is the thing `wan -> lan`
can never grant.

**Direction of the change.** It adds no drop site: a deny, an unresolvable zone
pair or a full session table all leave the packet's disposition untouched and
the punt proceeds exactly as before, with the peer adjudicating it as it does
today. Nothing that is permitted today becomes denied. One thing that is denied
today becomes permitted — the reply of a flow this node itself ingressed and
its own policy permitted — and that is not a privilege the requester did not
already hold.

**Why it is not the option that was ruled dead.** "Skip policy for
fabric-ingress packets" would honour a claim carried in the fabric stamp, which
on a shared fabric segment during exactly this split is forgeable (#6458's
accepted residual). The seed is the opposite: it is minted only from a packet
that ingressed on one of THIS node's own interfaces and passed THIS node's own
policy. `should_seed_fabric_punt`'s `!fabric_ingress` condition is what
guarantees that, and it is asserted directly
(`should_seed_fabric_punt_binds_each_condition_7770`) because inline in the poll
loop it was unreachable-by-construction and no mutation could bind it.

**Why the record was ALSO said to be dead.** The earlier framing rejected "the
redirecting node records the session" on the grounds that the redirecting node
"never evaluates policy for the flow, so it would be minting sessions for
traffic it never authorised". That was a description of the code, not a
constraint on it. Adding the evaluation is the difference, and it costs one
policy lookup on a path that only exists while an RG is split.

**What the seed deliberately is not.** It is NAT-free and is only seeded for a
flow carrying no ingress translation. The peer's NAT is transparent to the
punting node — the peer translates on its egress and untranslates on its
ingress, so the punting node sees tuple `T` outbound and `reverse(T)` inbound
whatever happened in between — but an ingress DNAT applied on the punting node
would rewrite the tuple before the punt, so those flows keep the old behaviour
rather than seeding a key that would not match. It carries no
`policy_counter*` (the peer counts the policy hit when it adjudicates the
punted packet; counting here too would double-count every punted flow) and no
`log_session_*` (one flow must not emit SESSION_CREATE/CLOSE records from two
nodes). It does not bump `session_creates`, so the punting node's
operator-visible create accounting is unchanged.

**It never leaves the node.** `SessionOrigin::is_transient_local_seed` covers
it, so the helper emits no Open delta for it and the owner-RG bulk export skips
it — the authoritative session for a punted flow is the peer's, and two nodes
claiming authority for one flow is what #518/#5007 exist to prevent. The Go
daemon filters the origin as well
(`transientLocalSeedOrigins`, `pkg/daemon/daemon_ha_userspace_stream.go`),
belt to that suspenders, because #6599 measured what a FabricRedirect-
disposition Open delta does when it reaches the peer: it overwrites the owner's
authoritative session family under latest-generation-wins, and a punt seed is
the worst shape of that class (right disposition, no NAT). The two lists are
held in agreement by `TestTransientLocalSeedOriginsLockstepWithRust7770`, which
parses the helper's own classification rather than restating it.

**The state cost, named.** During a sustained split the punting node now holds
one session per punted flow where it previously held none, bounded by the same
`max_sessions` cap as any other session and idling out on the admitting
application's window. That is the same order as the session count the peer
already holds for those flows.

RED-on-revert coverage for the remedy:
`fabric_punt_seed_admits_the_peers_return_7770` (punt seeds; return admitted;
plus a no-seed control and a denied-punt control, either of which alone would
let a blanket relaxation pass),
`fabric_ingress_never_mints_a_punt_seed_7770`, and
`should_seed_fabric_punt_binds_each_condition_7770`.
`fabric_ingress_return_traffic_is_denied_on_the_lan_node_7770` is UNCHANGED and
still green: an unsolicited fabric-ingress return, with no seed behind it, is
still denied.

RED-on-revert coverage: `afxdp/tests_fabric_zone_stamp.rs`
`fabric_ingress_syn_ack_seeds_no_reverse_session_6478` and
`fabric_ingress_icmp_echo_reply_seeds_no_reverse_session_6478` — both
drive the real poll loop with a validated-stamp SYN-ACK / echo-reply in
the split-RG placement and assert the packet tuple NEVER resolves to a
`SessionOrigin::ReverseFlow` seed (verified RED against the pre-removal
code: the lookup returns `Some(ReverseFlow)`), and that the SYN-ACK
installs the policy-path forward + reverse companion pair with
source-NAT instead. The #4439/#4453/#4414 guard tests were removed with
the function they guarded.

## The fabric link can be lost at COMMIT, not just at runtime (#8444)

Everything above assumes `cc.FabricInterface` is set. It is not configured
directly — it is DERIVED, and until #8444 a typo could leave it empty with no
commit-time signal at all.

`deriveFabricInterface` (`pkg/config/compiler_derivations.go`) walks the `fabN`
interfaces and selects the first whose `member-interfaces` list contains a name
that both parses to an FPC slot (`InterfaceSlot`) and maps to THIS node
(`SlotToNodeID`). Everything in this document is gated downstream of that:
`pkg/daemon/daemon_run_bringup.go` skips every fabric bring-up when the derived
interface is empty. So a member name that does not parse produces no fabric
link, no cross-chassis redirect, no session sync and no config sync — while the
config commits clean and `show configuration` reads back exactly what was typed.

Two spellings reached that state, both measured through `configstore.CheckText`:

- `fabster` — an outright typo (no `-<fpc>/` to parse);
- `ge-0-0-0` — the KERNEL name form. This one matters more than it looks: it is
  what networkd renames the NIC to and what several other surfaces in this tree
  accept, so it is a plausible thing to type in a fabric stanza. It derived
  nothing on EITHER node **until #8829**, which is no longer true: `InterfaceSlot`
  now parses the operational dash spelling, so `ge-0-0-0`/`ge-7-0-0` derive
  `fab0`/`fab1` exactly like the slash form, and both spellings reach the same
  kernel netdev at bring-up because every consumer normalises through
  `LinuxIfName` (which is idempotent on the dash form). It is therefore no
  longer rejected, and no longer an outage.

`validateFabricMemberDefinedStrict` rejects the remaining case — a member that
parses to no FPC slot at all, such as `fabster` — at commit / commit-check,
naming the fab interface and the offending member. It checks slot-parseability,
NOT existence under `interfaces` — a fabric member is a bare NIC and correctly
has no `interfaces` stanza of its own (neither `ge-0/0/0` nor `ge-7/0/0` has one
in `docs/ha-cluster-userspace.conf`), so an existence check would have rejected
the canonical production config on both nodes. The tolerant `Store.Load` /
`Store.SyncApply` ingress downgrades the rejection to a warning (#1960
no-brick). Full rationale, the measured derivation table, and the deliberate
scope boundary (`ge-0/0/99` — parses, derives, then fails visibly at netlink) are
in `docs/config-schema.md` § "chassis-cluster fabric `member-interfaces` name
validation (#8444)".
