# userspace-dp/src/server/

Control-socket lifecycle and request dispatch. The Go daemon talks to
this surface over a Unix socket using a newline-delimited text protocol.

## Files

- `mod.rs` — module root, public API surface.
- `lifecycle.rs` — `run()` is the daemon entry called from `main.rs`.
  Argv parsing (`--workers N`, `--control-socket PATH`, etc.),
  socket setup (control + a derived dedicated session-install
  socket so session installs don't share the control channel),
  sysctl tuning, signal handling.
  - **Socket-buffer sysctls are raise-only (#2970).** `run()` bumps the
    host-global `rmem_default`/`rmem_max`/`wmem_default`/`wmem_max` to a
    64 MiB target (`SOCKBUF_TARGET`) so AF_XDP copy-mode sockets receive
    at line rate, but it only ever *raises* — `raise_only_value` /
    `raise_sysctl` skip the write when the current value is already
    `>=` target. The target is kept equal to the Go control plane's
    `tuneSocketBuffers` desired (`pkg/dataplane/userspace/process.go`,
    `const desired = 67108864`); the Go side raises these before
    launching the helper, so whichever runs second is a no-op rather
    than a fight. Earlier the helper unconditionally wrote 16 MiB and
    clobbered Go's 64 MiB (and any operator-tuned larger value) back
    down, reintroducing receive drops.
  - **Stale-socket-only unlink guard (#2974).** Before binding the control
    and derived session sockets, `run()` clears any leftover inode via
    `remove_stale_socket`, which `symlink_metadata`-inspects the path and
    removes it ONLY when it is a real Unix socket (a stale socket from a
    prior run — the happy path). A regular file, directory, symlink, or any
    other object at the path is refused with a diagnostic naming the path
    and observed type, and the startup sites propagate that as a bind abort
    — the root helper takes `--control-socket` as an argument, so it must
    fail closed rather than silently delete a wrong path. The shutdown
    cleanup uses the same guard but keeps its best-effort posture: a
    non-socket logs a warning and does not fail shutdown. (`symlink_metadata`
    does not follow symlinks, so a symlink reports as a symlink, not a
    socket, and is left in place.)
- `state.rs` — `ServerState`: coordinator handle, latest config
  snapshot, session-table handle, policy state.
- `handlers/` — request dispatch (`handlers/mod.rs` is the
  `handle_stream` dispatcher). One per-verb file per request kind
  (`apply_snapshot`, `set_forwarding_state`, `set_queue_state`,
  `inject_packet`, `stop_workers`, `rebind`, …).
  - **The state-file persist never gates response delivery (#5294).**
    `drain_session_deltas` (`handlers/session_deltas.rs`) and the owner-RG
    export mirror (`handlers/export.rs` → `owner_rg_collect`)
    DESTRUCTIVELY drain deltas out of the per-binding RPC-fallback buffers /
    workers into `response.session_deltas` and set `persist_state`. The
    dispatcher tail used to run the FALLIBLE `write_state(...)?` BEFORE
    encoding the response, so a local state-file error short-circuited the
    send: the batch was already popped off the queue yet never reached the
    peer AND was not persisted — a permanent HA session divergence (the
    standby never learns those open/close events, the local copy is gone, and
    no loss-of-sync latch is armed for a `write_state` failure, unlike the
    #5290 budget-overflow path). The tail now ALWAYS encodes+flushes the
    response (delta order preserved end-to-end) and only THEN surfaces a
    persist error to the accept loop (logged). That is sound because the state
    file is best-effort observability, not a restore source (the Go control
    plane re-applies the full snapshot on restart) and self-corrects on the
    next periodic `write_state`. Pinned by
    `drain_session_deltas_survive_write_state_failure_5294` (a rigged
    `write_state` failure must still deliver every drained delta; reverting to
    pop-then-fallible-write drops the batch → EOF on the client read → RED).
- `helpers/` — shared daemon-loop utilities, split into cohesive
  submodules (#6234) behind a narrow `helpers/mod.rs` re-export facade so
  every `server::helpers::<name>` call site is unchanged:
  - `helpers/status.rs` — `refresh_status` cold-path projection onto
    `ProcessStatus` plus the capability/forwarding predicates
    (`should_run_afxdp`, `reconcile_status_bindings`,
    `set_bindings_forwarding_armed`, `forwarding_unsupported_error`).
  - `helpers/session_sync.rs` — HA synced key/entry reconstruction and the
    #4565 NAT64 cross-family reverse rebuild.
  - `helpers/planning.rs` — the binding-settle predicates, the canonical
    same-plan hash key, and the RX-queue / binding replanner
    (`replan_queues`, `replan_bindings_from_candidates`,
    `summarize_queues`, `effective_rx_queues`, `plan_key_rx_queues`,
    `include_userspace_binding_interface`). Hash ownership and layout
    ownership stay in ONE module — separating them invites the same-plan /
    stale-layout regressions fixed by #2915/#2916/#3007/#3175.
  - `helpers/persistence.rs` — the owned state payload build and the
    lock-free `write_state`.
  - **`write_state` holds the `ServerState` lock only to snapshot, not to
    persist (#5469).** Persisting the state file used to run
    `refresh_status`, `serde_json::to_vec_pretty` over the whole
    `ProcessStatus` + `ConfigSnapshot`, AND `StateWriter::persist` (file +
    parent-dir fsync) all under the `ServerState` lock. Because the fallback
    session-delta poll sets `persist_state` on every nonempty request, under
    session churn each delta poll serialized+fsynced the full state while
    holding the lock that also gates snapshot apply, status, and HA/control
    ops — a lock convoy. `write_state` now holds the lock ONLY long enough to
    `refresh_status` and clone a minimal owned payload (`build_state_payload`,
    the sole guard-touching half) plus a cheap Arc bump of the writer handle,
    then DROPS the guard before `encode()` (the `to_vec_pretty`) and
    `persist`. All persists still funnel through `StateWriter`'s single writer
    thread and publish via temp+atomic-rename (`finalize_durably`), so
    concurrent lock-free writers never tear the file; semantics are
    last-writer-wins and any transient staleness self-corrects on the next
    periodic write. `write_state_releases_lock_before_persist` is the
    fail-on-revert guard (a same-thread `try_lock` at the persist point, which
    a non-reentrant `Mutex` grants only if the guard was truly dropped).
  - **`wait_for_binding_settle` releases the lock across every sleep
    (#5862).** The three arms that reconcile bindings —
    `set_forwarding_state`, `set_queue_state`, `set_binding_state` — end by
    polling until bindings quiesce, up to 2 s at 50 ms. That poll used to run
    inside the locked `match`, holding the whole server's mutex across its
    sleeps.
    That is not a latency nit, because of what shares the mutex. The HA
    session socket is a SEPARATE socket accepted on a SEPARATE thread
    (`lifecycle.rs`, #452), but its one verb — `sync_session` — dispatches
    through the same `Arc<Mutex<ServerState>>`, so the socket split never
    split the critical section. The Go side budgets 3 s for a session
    round-trip (`sessionSyncRoundtripDeadline`,
    `pkg/dataplane/userspace/process_control.go`) and #5380 aborts the REST
    of a bulk batch on the first transport failure — so a settle overlapping
    a mirror burst can DROP the remainder of a batch of up to 255 session
    mirrors, during exactly the failover this path exists to serve.
    The handlers now only RECORD that a settle is owed; `handle_request` runs
    it after the guard drops and re-derives the response status under a fresh
    short acquisition, the same locked-kick / unlocked-wait split #2962
    (owner-RG export ack-wait) and #4054 (bulk export push) already use.
    Interleaving between polls is the point, not a hazard: this is a
    convergence wait, not a transaction, and the predicate is re-evaluated
    from scratch each iteration.
    Guarded by two fail-on-revert tests —
    `wait_for_binding_settle_releases_state_lock_between_polls` (the helper)
    and `sync_session_is_served_during_a_forwarding_settle_wait` (the handler
    wiring, driven through the real dispatcher).
    **Still under the lock, and NOT closed by this change** (see the tracking
    issue): the 10 s worker-readiness barrier and the 500 ms mlx5 quiesce
    reachable from `apply_snapshot` -> `Coordinator::reconcile`, the unbounded
    worker `join()` in `stop_and_clear`, and the BPF pin-open syscalls in the
    reconcile preflight. `ServerState` itself is still one mutex over four
    fields.
- `tests.rs` — colocated unit tests for the dispatcher, the per-verb
  handler error/gating arms, and the pure helper predicates (#1653
  §3.1). Handlers are driven through the real `handle_stream` call site
  over a socketpair, so a test fails if the dispatch wiring or
  status-field population regresses (the #1642 drift class).

## Request protocol

Each request is one JSON object per line, response is one JSON object.
The shapes are mirrored in `pkg/dataplane/userspace/protocol.go` on the
Go side; **the JSON tags ARE the contract** — changing one without
updating the other breaks the helper.

`ConfigSnapshot.version` is a compatibility gate, not just documentation.
The helper accepts only the current snapshot protocol version — EXACT equality,
on both mutating verbs (`apply_snapshot` and `bump_fib_generation`). This
prevents a new daemon from publishing fields such as policy-scheduler inactive
bits, source-NAT persistent-lease settings, or scoped-global zone SETS to a
helper that would silently ignore them. Bump `CONFIG_SNAPSHOT_PROTOCOL_VERSION`
(`protocol/control.rs`) and the Go mirror `ProtocolVersion` TOGETHER whenever a
change makes an older reader interpret the same bytes differently — in
particular whenever a new field becomes authoritative over an existing one.
Leaving the version unchanged for such a field is what caused #5488: the
plural `match_from_zones`/`match_to_zones` scope became authoritative in #4626
while the version stayed at 3, so a pre-#4626 helper at the same advertised
version read only the singular field and NARROWED a multi-zone global deny (a
rolling-upgrade fail-open).

`ConfigSnapshot.content_digest` (#9520, v15) binds a generation to its content.
The Go control plane stamps its content hash on every `apply_snapshot`, and
`apply` refuses a snapshot that reuses the installed generation when the two
digests differ or either is empty, before any mutation and at any
`fib_generation`. The error starts with `SNAPSHOT_CONTENT_CONFLICT_PREFIX`
(`protocol/control.rs`), which Go reads as proof that this process holds the
generation and answers by republishing on the next one. `update_fabrics` and
`update_neighbors` clear the installed digest when they change enforced
content. The helper never recomputes the digest, so it needs no canonical
serialization here; `docs/flow-cache-simplification.md` has the mechanism.

A bump is owed for a SEMANTIC change too, not only a new field: #6691 moved
5 -> 6 for a refusal rule that reinterpreted existing rows (no field changed),
then 6 -> 7 for `FabricSnapshot.parent_unbindable`. That last field exists
because a fabric MEMBER needs no interface stanza on the Go side, so the parent
netdev usually has no `InterfaceSnapshot` to carry the device-level flags, and
`snapshot_refuses_parent_netdev`'s unanimity tally over an EMPTY owner set
answers "not refused" — this plane then plans an AF_XDP binding on a netdev the
control plane refused. The fabric's own vote is computed Go-side because half
its evidence (kernel link kind `xfrm`) is an RTM_GETLINK dump this process does
not take. `ownerless_fabric_parent_is_refused` is the fail-on-revert guard, and
it carries the reference cluster's shape as its negative control: an ownerless
parent that is NOT marked unbindable must still be planned.

The helper reports `session_export_paging_protocol_version` in status (#9344).
`export_owner_rg_sessions` answers a ~60-byte request with the owner-RG session
set, and until #9344 the only COMPLETE request was `max = 0` — the unbounded
set, which crosses the Go control socket's 64 MiB response cap at roughly 7.8k
sessions per worker on a six-queue box and makes the HA cold prime fail
permanently. Version 1 means the helper honours `SessionExportRequest`'s
`continuation` flag and reports `session_export_more`, so the caller can PAGE
one window across several capped responses. A continuation kicks no worker,
consumes no export sequence and waits for no acks: every page of a window comes
from the single phase 1 that opened it, because re-kicking would produce a
second full set from a different instant and the receiver reconciles
authoritatively against the delimited window (#5085). A caller seeing version 0
must ask for the unbounded set instead — an older helper honours `max` by
TRUNCATING and reports no more-bit, so paging it loses the remainder silently.

The helper also reports `config_snapshot_protocol_version` in status so a new
daemon can fail closed before sending snapshots that require newer runtime
semantics to an older helper binary that predates the gate. If the daemon
detects an incompatible helper while any of the gated features is configured —
scheduled policies, per-pool source-NAT `persistent-nat` settings, or a
scoped-global policy whose zone scope holds MORE THAN ONE zone on a side
(#5488) — it sends `set_forwarding_state armed=false` before returning the
compile/publish error; the old helper must not keep forwarding a stale snapshot
that ignores those semantics. The Go-side gate list is
`requiredProtocolGateSentinels` in `pkg/dataplane/userspace/manager_compile.go`;
every gate must be registered there or the commit is promoted against a
disarmed dataplane (#2138). If that disarm ITSELF fails on a publish path whose
classifier BPF maps were already mutated in place, the daemon additionally
drives the `userspace_ctrl` shim to `Enabled=0` so transit falls back to the
kernel-only fail-closed posture rather than running maps a generation ahead of
the applied snapshot (#5488 F7, mirroring #4959).

`inject_packet_tuple_protocol_version` is the corresponding status gate for
`inject_packet` requests that set `emit_on_wire=true`. Those requests must carry
the complete tuple metadata (`source_ip`, `destination_ip`, protocol, and ports)
on the control wire; helpers reject legacy emit-on-wire requests instead of
synthesizing tuple identity locally.

## Reconciliation

`replan_queues` derives the binding plan from the current
`ConfigSnapshot`: enumerate userspace-binding interfaces, count their
RX queues, and emit one `BindingStatus` per `(queue_id, interface)`
pair. The binding-candidate decision is a single shared invariant
(#2915): `replan_queues`, the plan-key hash
(`update_snapshot_binding_plan_key`), and the Go authoritative allowlist
(`UserspaceBoundLinuxInterfaces` /
`userspaceSkipsIngressInterface`) all filter through the same exclusion
contract — `include_userspace_binding_interface` (zoned, non-tunnel,
non-local-fabric, excluding `fxp*`/`em*`/`fab*`/`lo0`, interfaces carrying
the snapshot's `secure_tunnel` flag, and `mgmt`/`control`
zones). That flag is shipped by the control plane as an OWNERSHIP **or
KERNEL-DEVICE-KIND** verdict since #6691 round 8 — an earlier revision of this
sentence said ownership alone, which stopped being true when the live-xfrmi half
landed — not
the name shape `st<N>` — an earlier revision of this line said `st<N>`, which
the section 30 lines below already repudiates. The hash MUST cover exactly the interfaces the planner acts on, so
a change to a non-candidate interface never spuriously bumps the plan key
and a `ge-*`/`xe-*`/`et-*` netdev placed in a mgmt/control/tunnel/fabric
context is never planned as an AF_XDP binding the rest of the system does
not account for.

### IPsec secure tunnels are excluded, deliberately (#5619)

An `st<N>` secure tunnel gets **no** AF_XDP binding, and its ifindex stays
out of the ingress-adjudication map and the RSS allowlist.

Route-based IPsec decrypts in the **kernel** XFRM stack, which delivers the
plaintext on the xfrmi netdev (`xfrmi_rcv_cb` sets `skb->dev`, then
`xfrm_input` → `gro_cells_receive` → `__netif_receive_skb_core`), and the
dataplane has no path to hand a plaintext frame back *into* an xfrmi for the
egress direction.

The reason the exclusion is **load-bearing**, and the one that can be
demonstrated without a NIC, is that admitting the tunnel mints an AF_XDP
binding on a netdev this dataplane can never transmit back into. An xfrm
interface has exactly **one** RX queue (`ip -d link` reports `numrxqueues 1`;
`/sys/class/net/<if>/queues` holds a single `rx-0`), so the binding is real,
consumes a slot against `MAX_BINDING_SLOTS`, and can only drop.

**Until #7497 the harm was global, and every cite of this exclusion led with
that.** `replan_bindings_from_candidates` took the **global minimum** queue
count across every candidate, so one zoned xfrmi re-planned *every physical
interface on the box* onto a single queue and a single worker — the #3091
single-worker regression by another route. Since #7497 each interface
contributes its own `min(rx_queues, 16)`, so a spurious xfrmi costs **one
spurious binding** and no other interface's queue count moves.

That change also retired the guard this section used to name.
`secure_tunnel_would_collapse_the_global_queue_count` asserted that the LAN
kept its own queue count; under per-interface planning that is true whether or
not the exclusion exists, so the test passed with
`include_userspace_binding_interface` mutated to admit the tunnel — it had
stopped being a fail-on-revert. The live guards are
`secure_tunnel_adds_nothing_to_the_binding_plan` and
`binding_candidate_excludes_secure_tunnel`, both measured to fail under that
mutation.

It is also why the exclusion cannot be split: an ifindex left in the
shim's ingress-adjudication map with no READY binding takes
`drop_degraded_transit` (`userspace-xdp/src/lib.rs`, `BINDING_MISSING`), so
"adjudicate but do not bind" is the dead-tunnel configuration, not a
compromise.

Earlier revisions of this section claimed instead that an XSK *cannot come up*
on a virtual netdev, so admitting the interface would find no usable binding
and drop the plaintext. Zero-copy indeed cannot bind there, but zero-copy is
not required for every socket role: `XskSocketRole::Private` returns `false`
from `requires_zerocopy`, `bind_flag_candidates_for_interface` offers a
generic-XDP interface `COPY_ONLY_BIND_FLAGS`, and a failed shared-UMEM group
falls back to a private socket (`fallback_shared_group_to_private`). A
copy-mode binding is reachable in this code, so that claim was never
established and is not relied on here.

**The cost is a policy gap, not a drop.** Decrypted plaintext traverses Linux
routing with no xpf zone policy. That is #5619's open half, tracked in #6700.

Before #5619 the exclusion happened by **accident**: the Go snapshot resolved
`st0.0` to the nonexistent netdev `st0` (the unit-0 collapse), so the unit
carried ifindex 0 and fell out of every ifindex-keyed set. #5619 fixed that
name — the reconciler creates the device under the AUTHORED `bind-interface`
string, which for `bind-interface st0.0` is `st0.0` and for `bind-interface st0`
is `st0`, so it is read back from the config rather than reconstructed from the
ref (`Config.SecureTunnelUnitNetdev`) — which is why the exclusion is now
stated explicitly on both planes. Since #6691 round 5 it is keyed on
OWNERSHIP: the Go control plane resolves `Config.SecureTunnelNetdevForRef` once
and ships the verdict as the snapshot's `secure_tunnel` flag, and this plane
reads that flag. Pinned by `binding_candidate_excludes_secure_tunnel` here and
`TestUnownedStNameKeepsItsDataplaneRole` in Go.

**An unbound `st` interface keeps its dataplane role.** An earlier revision said
the exclusion "keys on the interface NAME, not on the presence of a VPN", and
justified it with "authoring an `st`-named interface without a route-based VPN
is not a supported topology — `st` is the secure-tunnel namespace". Both halves
were wrong, and together they were the #6691 round-5 blocker.

Nothing reserves the `st` prefix. The Go schema (`schema_interfaces.go`) accepts
a wildcard interface name, so

```
set interfaces st5 unit 0 family inet address 192.0.2.1/24
set security zones security-zone trust interfaces st5.0
```

is a valid config naming a real physical NIC with no VPN anywhere — supported by
construction, because the config language admits it. Keying the exclusion on the
name dropped that interface out of the ingress map, the binding plan and the RSS
allowlist: a traffic outage on a working NIC.

The exclusion is therefore keyed on OWNERSHIP — or, since #6691 round 8, on the
kernel's DEVICE KIND. An `st` name is a secure tunnel when an IPsec
configuration BINDS it (`Config.SecureTunnelNetdevForRef`) or when the netdev it
resolves to actually has link kind `xfrm` (`liveXfrmNetdevs`); an unowned `st5`
that is neither keeps adjudication, binding and RSS. The kernel half exists
because every config-keyed predicate is blind to a live xfrmi the config no
longer describes: a failed `LinkDel` retains one (`pkg/routing`, #4901) while
the apply proceeds on a deferred error, and a daemon restart leaves an untracked
one that no sweep enumerates. `pkg/routing/xfrm.go`,
which actually creates the xfrmi devices, does not call that resolver; the two
agree because both derive names and if_ids through `config.XFRMIfNameAndID` and
both treat one if_id claimed by two distinct names as unresolvable. A shared
derivation, not a shared function.

Ownership is decided on the AUTHORED SPELLING, not on the if_id alone
(#6691 round 6). `strconv.Atoi` erases a leading `+` and leading zeros, so
`st5`, `st05` and `st+5` all derive if_id `0x50001` under three DIFFERENT device
names — and routing creates the device under the authored name. Keying on the
if_id alone let `bind-interface st05` claim a wildcard-authored NIC named `st5`
and strip it of its binding. The if_id is still what the COLLISION veto keys
on, because that is the key routing collides on.

That comparison is DIRECTIONAL, and the two questions are asked in a fixed
order (#6691 round 7):

    no name owner        -> unbound
    owner + collision    -> collision veto
    owner + no collision -> bound

A DOTTED ref (`st5.0`) is a logical unit and resolves through either authored
spelling, because a bare `st5` and an explicit `st5.0` are one xfrmi under two
names. A BARE ref (`st5`) is a base row whose netdev is literally `st5`, so it
is a secure tunnel only when a VPN authored that exact bare name — round 6
compared bases only, and `bind-interface st5.0` therefore claimed the `st5`
row and stripped a live NIC of its binding. Ordering matters for the same
reason: round 6 returned the collision verdict before ownership had been
established, so two spellings colliding on an if_id (`st05` and `st0005`)
vetoed `st5.0` even though neither of them creates a device called `st5`, and
the unit row named a netdev that exists on no box.

**The NAME of an unbound `st` interface is unchanged from the merge base.** A
round-5 revision of this section claimed `snapshotLinuxName` now returns `st0.0`
where the merge base returned `st0`; that was the resolver half of the exclusion
still being keyed on the name shape, and it is fixed. When no VPN binds the
unit, `SecureTunnelUnitNetdev` declines and the ordinary resolution names the
real device — the NIC, the `parent.vlanid` VLAN device, the `TunnelNameMap` GRE
device. Only a bound unit resolves through the authored `bind-interface`.

The `st<N>` range still matters, but only as a LEXICAL rule and only where a
lexical question is asked: `IsSecureTunnelIfName` accepts `st<N>` for N in
`[0, 65536)`, the range `XFRMIfNameAndID` builds an if_id for, and
`SecureTunnelUnitNetdev` uses it to resolve `st<N>.<unit>` to a netdev name. It
is no longer an input to the exclusion on either plane, so the range boundary
can no longer strip a live interface of its binding. What the range still
decides is what can be OWNED at all: an out-of-range name yields no if_id, and
#5297 rejects it as a `bind-interface` at commit, so it can never be a tunnel.

**Search scope of the "one resolver" claim — it is narrower than "every
resolver in the tree".** #6691 unified the secure-tunnel rule across the three
resolvers that answer "what kernel netdev does this Junos unit ref name?" for
the userspace dataplane and the junos-host `iifname` scope:
`Config.ResolveKernelIfName` (`pkg/config/types.go`),
`userspace.snapshotLinuxName` (`pkg/dataplane/userspace/interfaces.go`) and
`config.junosHostLinuxName` (`pkg/config/junos_host_deny.go`), all now calling
`Config.SecureTunnelUnitNetdev`. The Rust classifier mirror that used to sit
alongside them is gone: round 5 replaced it with the snapshot's `secure_tunnel`
flag, so the name grammar is no longer duplicated across the language boundary
and cannot drift.

Audited and deliberately NOT changed, each filed instead so this claim is not
broader than the sweep:

| site | disposition |
|---|---|
| `dataplane.resolveInterfaceRef` (`compiler_iface.go:73`) | over-matches `st*` (#6728); reconstructs the name from the ref (#6729) |
| `dataplane.buildInterfaceNetworkdModels` (`compiler_iface.go:805`) | raw prefix branch drops every unit of `start0` (#6730) |
| ip-monitoring next-hop validator (`compiler_services.go:1058`) | raw prefix rejection, fails closed (#6731) |
| `daemon.resolveConfigSubnetLinuxName` (`daemon_dhcp.go:279`) | has no production caller — referenced only by its own test |

The first three are LIVE on the userspace path (`CompileUserspaceShim` →
`CompileConfig` → `compileZones`), not retired-eBPF-only. Not audited: resolvers
outside the Junos-ref → netdev question (`LinuxIfName`'s `/`→`-` transform,
`ResolveReth`, `ResolveFab`) and anything in `pkg/frr`, `pkg/networkd` or
`pkg/routing` beyond `xfrm.go`, whose contract this change reads but does not
alter.

The consequence is real and operator-visible: **decrypted IPsec plaintext
traverses Linux routing with no xpf zone policy.** That is #5619's open half —
closing it needs the dataplane to own the xfrmi end-to-end, including a
plaintext egress path into the tunnel. Deleting either exclusion without
building that path re-opens the drop above rather than fixing the gap.

**Scope of the exclusion — it is narrower than "the dataplane ignores secure
tunnels".** The Go predicate `userspaceSkipsIngressInterface` has **four** call
sites, not three (corrected in #6691 round 8 — the earlier text listed only the
sets whose contents visibly change): `buildUserspaceIngressIfindexes` (the
ingress-adjudication map), `UserspaceBoundLinuxInterfaces` (the name-keyed
RSS/AF_XDP allowlist), `snapshotBindingPlanKey` (the plan-key hash — excluding
the row is what keeps the key from churning when a tunnel appears or moves),
and `buildUserspaceIngressBindingAliases`, which is **inert** for the xfrmi's
own row because an xfrmi has no parent ifindex. The ORDER in that sentence was
wrong: `buildUserspaceIngressBindingAliases` calls
`userspaceSkipsIngressInterface` FIRST and reaches the `ParentIfindex` guard
after, so for the xfrmi's own row it is the predicate that drops it, not the
guard. The guard is what drops a VLAN SIBLING, whose own netdev cannot exist on
an ARPHRD_NONE parent — and a PLAIN sibling does reach the refusal, which is
what `TestAliasTableRefusesOnAReachablePlainSibling` exercises. The AF_XDP binding
**plan** is gated on this side by the mirrored
`include_userspace_binding_interface`, off the `secure_tunnel` flag, not by a
fifth Go call site. Since
#5619 made the xfrmi's ifindex resolve, the tunnel *does* enter the forwarding
state built by `populate_interfaces`
(`afxdp/forwarding_build/interfaces.rs`), which gates on `ifindex > 0` rather
than on this predicate — so `name_to_ifindex` and the zone map see it.

**The refused-netdev index, and why it takes EVERY owner rather than any
(#6691 rounds 8 and 9).** Three of those four sets let a row contribute a
netdev that is *not its own*: a VLAN child binds its physical parent (#2917).
So a zoned sibling unit of a bound secure tunnel can hand the dataplane exactly
the netdev the base row was refused for, and asking the row-level predicate
again at each site cannot catch it — the child passes it. Round 8 answered with
a netdev-keyed index: `buildUserspaceRefusedNetdevs`
(`pkg/dataplane/userspace/ingress_exclusions.go`) on the Go side, and
`snapshot_refuses_parent_netdev` / `binding_target_is_refused` (`planning.rs`)
here, the latter read by BOTH the candidate loop and the plan-key filter so the
#2915 hash/layout invariant is a property of the code.

Round 8 refused a netdev as soon as *any* row was unbindable for it, and that
was a regression: it reads a **disagreement between two rows** as a refusal.
Rows do disagree. The Go builder sets a unit row's `tunnel` flag to
`iface.Tunnel != nil || unit.Tunnel != nil`, and a unit-0 row with no vlan-id
resolves to the BASE netdev, so `set interfaces wgN unit 0 tunnel mode
wireguard` — the canonical WireGuard spelling — ships an unbindable `wgN.0` row
and a bindable `wgN` base row on ONE netdev. Under the ANY rule the netdev left
the Go RSS allowlist while this planner still planned a binding for it, and on
a `ge-*` NIC the netdev's zoned VLAN sibling also left the ingress-adjudication
map and the binding-alias table.

Both planes now refuse a netdev only when **every contributor that speaks for
it** is unbindable. The question the index answers is "is this netdev, as a
DEVICE, one we must never bind?", and a device cannot be both: when its owners
disagree, at least one owner is an ordinary data interface that will contribute
the netdev on its own account, so refusing cannot prevent the binding and can
only strip traffic.

**Who speaks for a netdev** (#6691 rounds 10 and 11 — an earlier revision of this
paragraph said the planes refuse a netdev "never when the netdev has no owner at
all", and that has been false since round 10):

- A **row that owns the netdev** — a row whose bind target is its own netdev,
  i.e. not a VLAN child redirecting onto a parent — always speaks for it.
- A **VLAN child** casts no COUNTED vote: it binds the PARENT, so it says nothing
  about whether the parent may be bound, and the refusal question about the child
  is answered on the target. Scope that to the TALLY. An abstaining row still
  carries its own `verdictNeedsProtocol` (`iface.SecureTunnel`), so a VLAN child
  that is a secure tunnel DOES arm `snapshotRequiresRefusalProtocol` even though
  it contributes nothing to any `netdevOwnerTally`. That is deliberate: the v5
  field on the row means an older helper plans a binding this control plane
  refuses, which is true whoever wins the tally — the protocol question is asked
  per contributor, the refusal question per netdev.

  **Reproducing this needs a precondition the sentence above does not carry
  (#7022): the CHILD's own netdev must be the secure tunnel.** `iface.SecureTunnel`
  is `secureTunnelOwned(cfg, ref) || liveXfrm[netdev]`, and for `st0` with
  `unit N vlan-id 100` the child's netdev is `st0.100` — so the flag lands on the
  child only when a VPN binds that unit ref, or when `st0.100` is ITSELF a live
  xfrmi. Point the kernel half at the base instead and the flag lands on `st0`,
  which is not a VLAN child and DOES cast a counted vote: the arming is real but
  it arrives by the ordinary contributor path, not by the abstaining one this
  bullet describes. A reader who reproduces it that way sees a different
  mechanism and concludes the doc is wrong when it is merely incomplete.
  Measured both ways by
  `TestVlanChildArmsOnlyWhenItsOwnNetdevIsLiveXfrm7022`
  (`pkg/dataplane/userspace`), which asserts BOTH rows in BOTH directions —
  asserting only "the child is armed" would pass against an implementation that
  armed every row.
- A **fabric parent** speaks for its netdev only where NO row does. A fabric
  MEMBER needs no `set interfaces` stanza, so a fabric parent routinely has no
  `InterfaceSnapshot` at all — and the round-9 rule, tallying over rows alone,
  answered "not refused" over an EMPTY bucket and planned an AF_XDP binding on a
  netdev the control plane refused. Round 10 gave the fabric a vote
  (`FabricSnapshot.parent_unbindable`, the field the protocol moved to 7 for);
  round 11 made it a FALLBACK rather than a co-voter, because two owners computing
  one device's verdict from different evidence can DISAGREE, and unanimity reads a
  disagreement as an admission. So a row-ownerless fabric parent marked unbindable
  **is** refused — unanimity over a bucket of one — while a row-owned one leaves
  the decision entirely to the rows. `ownerless_fabric_parent_is_refused` and
  `TestOwnerlessFabricParentIsRefused` are the fail-on-revert guards.

A netdev with no contributor at all never enters the tally, so the zero-owner
fall-through in `netdevOwnerTally.refused` (Go) is unreachable rather than
permissive; `snapshotNetdevVotes` (Go) is the single enumeration of who
contributes, read by both the tally and the required-protocol gate so the two
scopes cannot drift.

The secure-tunnel exclusion is unaffected, and it survives on the ownership
half rather than on a special case: under `bind-interface st10` the only row
whose netdev is `st10` is the base xfrmi row (a `unit 5 vlan-id 100` sibling
resolves to `st10.100`), so that bucket is unanimous. A `unit 0` sibling shares
the netdev but is itself a secure tunnel by the same ownership oracle, so that
bucket is unanimous too.

Two consequences worth knowing. First, for a row that owns its own netdev the
refusal is now **structurally unreachable** — such a row only reaches the check
after passing the row-level exclusion, so it is a bindable owner of its own
bucket — which puts the Go rule in the same shape as this file's
`binding_target_is_refused`, whose non-VLAN arm is the literal `false`. Second,
the ANY rule diverged the planes in the dangerous direction: with a `mgmt`-zoned
base plus a unit-0 tunnel row and a trust VLAN child, this planner produced NO
binding for a netdev whose ifindex the Go ingress map still carried, and an
ifindex in the ingress map with no READY binding is `drop_degraded_transit`
(BINDING_MISSING). `a_netdev_with_a_bindable_owner_is_not_refused`
(`main_tests.rs`) is the fail-on-revert guard for that shape.

**The caller list is not an enumeration of the sets.** Round 8 bounded its own
work with "a redirect can only launder within the sets the predicate gates, so
the sites are the predicate's callers per plane, four in Go and two in Rust".
That is false: the FABRIC loops contribute to the same sets without consulting
the predicate or the index — `replan_queues`' fabric pass here, and
`add(fab.ParentLinuxName)` / `key := uint32(fab.ParentIfindex)` in the Go
`interfaces.go` / `maps_sync.go`. Measured with a Tunnel-class member
(`set interfaces fab0 fabric-options member-interfaces gr-0/0/3`, interface-level
tunnel on the member), the refused netdev is in the ingress set and in the
allowlist. It is PRE-EXISTING (master's fabric loops are identical), and it was
CLOSED in round 9 (#6998) rather than deferred, because it is REACHABLE.

The reasoning that once called it unreachable is worth keeping visible, because
it read correctly and was answering the wrong question: "`LocalFabricMember`
resolves only for slot-shaped member names, so an `st*` member yields no fabric
row at all" is a statement about the NAME-keyed exclusion, and it did not survive
round 8 keying the exclusion on device KIND. A slot-shaped `ge-0/0/0` created out
of band as an `xfrm` device is both refused and a legal fabric member, so EVERY
Go loop that plans a binding from a snapshot row or a fabric row asks the refused
index. That predicate is the claim; a count is not, and this paragraph carried a
wrong one for several rounds — it said "four" while the tree held three (round 8)
and then five. As of this writing the sites are `interfaces.go` (bind target —
`refusesName`; fabric parent — `refusesNetdev`) and `maps_sync.go` (ingress row,
fabric parent, binding alias — all `refusesNetdev`). Regenerate that list rather
than trusting it:
`grep -rn 'refused\.refuses' pkg/dataplane/userspace/ --include='*.go' | grep -v '_test\.go'`. To bound a laundering question,
enumerate every CONTRIBUTOR to the set, not every caller of the predicate.

**Ask with BOTH identities, because the two keys are sampled apart (#6691 round
16).** Until this round the Go readers split on which key they asked — the
`interfaces.go` pair by NAME, the `maps_sync.go` trio by IFINDEX — and an
earlier revision of the sentence above recorded that split as a neutral fact.
It was a defect. `buildUserspaceRefusedNetdevs` gives a netdev a NAME bucket
from any counted vote that carries a name, but an IFINDEX bucket only from a
vote whose own `buildLinkSnapshot` resolved (`vote.ifindex > 0`,
`snapshotNetdevVotes`) — and **a snapshot is not one netlink sample**.
`buildInterfaceSnapshots` takes one per base row and a second per unit row for
that unit's parent; `buildFabricSnapshotsFrom` takes its own; and
`SyncFabricState` refreshes the fabric rows ALONE and persists them back into
`m.lastSnapshot` beside interface rows that were never re-sampled
(`persistResolvedFabricsLocked`). One netdev can therefore be named by a row
whose lookup MISSED — no ifindex bucket — while a sibling row or a fabric row
carries its live ifindex.

This plane asks by NAME with no ifindex filter, in both
`snapshot_refuses_parent_netdev`'s owner walk and the
`binding_target_is_refused` a VLAN child's bind target routes through. So on a
skewed snapshot every name-keyed reader refused the netdev and planned no
binding, while the ifindex-keyed readers admitted its ifindex to the
ingress-adjudication map — and an ifindex there with no READY binding is
`drop_degraded_transit` (BINDING_MISSING). Measured at `76045dfae`:

| snapshot | Go ingress | Rust plan |
|---|---|---|
| rows `{gr-0-0-3 ifindex 0, tunnel}` + fabric `{gr-0-0-3, parent ifindex 20}` | `[20]` | `{}` |
| rows `{ge-0-0-5 ifindex 0, tunnel}` + `{ge-0-0-5.100 ifindex 12, parent 11}` | `[11 12]`, alias `12→11` | `{}` |

`userspaceRefusedNetdevs.refusesNetdev(name, ifindex)` is now the single
predicate every caller holding both identities asks, so the divergence cannot be
re-introduced one site at a time. A caller holding only a name — the bind-target
arm of `UserspaceBoundLinuxInterfaces`, name-keyed by contract because `ethtool`
consumes names — still asks `refusesName`. The Go guards are
`TestSkewedFabricSampleKeepsIngressAndAllowlistAgreed` and
`TestSkewedParentSampleKeepsTheChildOutOfAdjudication`
(`fabric_sample_skew_6691_test.go`), each with a per-site fail-on-revert; the
Rust half — that an owning row at ifindex 0 still refuses — is pinned by
`zero_ifindex_owner_row_still_refuses_the_fabric_parent` (`main_tests.rs`).

It does **not** enter the **egress map**. `populate_egress` needs a source MAC
and takes it from the interface's own `hardware_addr`, else the parent's MAC,
else the `tunnel` flag. An xfrmi is `ARPHRD_NONE` (no MAC), has no parent
ifindex, and a secure-tunnel unit carries no `tunnel` flag (the Go snapshot sets
it from `iface.Tunnel`/`unit.Tunnel`, which a `bind-interface` stanza does not
populate) — so the row hits `None => continue` and no `EgressInterface` is
built. An earlier revision of this paragraph asserted the egress map saw it;
that was wrong, and the consequence is spelled out under "what the adjudication
decides" below. Note the resolution applies to the `<ip>@<iface>` next-hop
encoding: an authored `next-hop st0.0` still reaches `parse_route_next_hop` as
the bare string `"st0.0"`, which returns `(None, None)` and leaves the target at
`(0, 0)` on both revisions. Measured — do not restate this as "a static route
`next-hop st0.0` now resolves"; it does not.

**This DOES move a disposition, and the executing site is the FIB, not the TX
dispatcher.** An earlier revision of this paragraph claimed the change was
disposition-neutral because an egress ifindex with no XSK binding is dropped by
the TX dispatcher as `missing_egress_binding`. That was retracted: for a
LAN→tunnel packet **neither revision reaches the TX dispatcher** — the FIB
claims the packet first, at `forwarding/fib.rs`'s `if ifindex <= 0` versus the
neighbor lookup below it, gated upstream by `populate_interfaces`'
`if iface.ifindex <= 0 { continue }`.

Measured across 2 bind-interface spellings × 3 next-hops × 2 destinations:
**4 of 12 flip, all four in the dotted spelling (4 of its 6), zero for bare
`st0`.** Every flip is `NoRoute` (egress 0) → `MissingNeighbor` (egress 42).
Only unit 0 collapses — unit-row ifindex merge-base→head is `st0` 42→42,
`st0.0` **0→42**, `st10.5` 42→42, `st0.7` 42→42 — and for a bare `st0` the
collapsed name *is* the device.

This is a **correction, not a regression.** `bind-interface st0` and `st0.0` are
one tunnel (same if_id, same unit ref `st0.0`), and before this change the same
tunnel took different dispositions depending on how it was spelled.
`MissingNeighbor` is not invented here: it is what master already does for this
flow on the canonical bare spelling. The `NoRoute` was the artifact.

**What the adjudication decides today — and the #6722 dependency.** Both
dispositions are `is_slow_path_eligible`. `NoRoute` falls straight to the
reinject gate with zone policy never evaluated; `MissingNeighbor` resolves zone
ids from the egress ifindex and evaluates policy, and a deny converts to
`PolicyDenied` and `break … RecycleAndContinue`, which skips the reinject.

An earlier revision of this section said a matching permit falls through to the
same reinject, so that only deployments with **no** `from-zone <lan> to-zone
<tunnel-zone>` permit change. **That is false at this commit.** Because
`populate_egress` builds no `EgressInterface` for the MAC-less xfrmi (above),
the egress zone id reads **0**, and `evaluate_policy_result_l3_aware` wraps its
entire rule walk — exact zone pair, the #3090 wildcard tiers *and* `junos-global`
— in `if from_id != 0 && to_id != 0`. A flow with either zone unknown matches
**nothing** and falls to the default action, so an authored permit does not
rescue it.

That MAC-less-egress zone resolution is a **pre-existing defect, tracked as
#6713 and fixed by open PR #6722** (which touches
`forwarding_build/interfaces.rs` and `forwarding/mod.rs`). It is not introduced
here — this change only makes the dotted spelling reach the same code path the
bare spelling already took. **The permit-preserves-delivery behaviour described
above requires #6722 to land**; until then a LAN→tunnel transit flow is denied
regardless of policy, on both spellings.

Do **not** "fix" this by widening the exclusion into those maps. An interface
absent from the zone map resolves to `zone_id = 0`, and per the guard just
cited a zone-0 flow matches no rule at all — not even `from-zone any to-zone
any` — so widening would trade an adjudicable interface for one whose
disposition no policy can influence. (An earlier revision claimed the opposite,
that an any/any permit *matches* zone pair (0, 0) with no zone guard; the guard
is right there in `policy.rs` and has been since #3110.) Separately,
whether the negative-neighbor cache (3 s TTL) can fast-fail a *permitted*
LAN→tunnel flow is tracked as #6710; it is pre-existing on master for bare
`st0`, and this change extends its reach to the dotted spelling.

The same-plan fast path in `apply_snapshot` (`handlers/snapshot.rs`) relies
on this coupling for correctness (#2916): when `snapshot_binding_plan_key` is
unchanged it skips `replan_queues` entirely (it only reconciles/refreshes the
running bindings, never re-deriving the layout). That is sound only because
the hash covers EVERY snapshot-derived field `replan_queues` consumes to build
the layout — the candidate set (shared predicate, above) plus, per candidate,
`linux_name` (bound netdev + dedup key), `ifindex` (per-binding ifindex), and
`rx_queues` (queue count), plus the fabric parents and `workers`/`ring_entries`
/`shared_umem`. Any new field the planner starts reading MUST be folded into
`update_snapshot_binding_plan_key`, or a same-plan refresh will leave a stale
worker layout. `plan_key_covers_every_replan_queues_input` (#2916) pins this:
mutating any planner-consumed field bumps the key (and is shown to change the
produced layout), so a dropped hash field goes RED.

`rx_queues` is folded in via its EFFECTIVE value, not the raw snapshot field
(#3007). When the snapshot carries the degenerate `rx_queues == 0` fallback,
`replan_queues` resolves the real channel count from sysfs
(`rx_queue_count` → `/sys/class/net/<if>/queues`), and THAT count drives the
layout. `effective_rx_queues(snapshot_rx_queues, linux_name)` is the single
resolution path shared by both the planner and the hash, so the dedup key can
never disagree with the layout: a nonzero snapshot never reads sysfs (the key
stays byte-identical to the raw-field hash), while a 0 snapshot folds the
sysfs-resolved count in — so an out-of-band channel change (`ethtool -L <if>
combined N`, no config commit) bumps the key and forces a replan instead of
taking the same-plan-skip. `plan_key_folds_sysfs_resolved_rx_queues_when_snapshot_is_zero`
and `plan_key_for_nonzero_rx_queues_ignores_sysfs` pin both halves.

For an ORPHAN VLAN child — a VLAN unit whose physical parent is NOT itself a
binding candidate — the planner re-keys the child onto its parent netdev and
uses the parent's HARDWARE queue count (`rx_queue_count(parent)`), never the
child's lone software queue (#3091). The plan key must hash the SAME value, so
`plan_key_rx_queues(snapshot, iface, linux_name)` is the single resolution path
for the hash: for the orphan case it returns `rx_queue_count(parent)`, matching
the layout; for the normal VLAN case (parent IS a candidate, child deduped onto
it and covered by the parent's own physical key entry) and physical/non-VLAN
ifaces it returns `effective_rx_queues(...)` exactly as #3007. Before #3175 the
key hashed the child's own software-queue count, so an out-of-band `ethtool -L
<parent> combined N` on the parent of an orphan VLAN child did NOT bump the key
→ same-plan-skip → stale layout. `plan_key_folds_parent_sysfs_queues_for_orphan_vlan_child`
and `plan_key_for_normal_vlan_child_ignores_parent_sysfs` pin the orphan re-key
and the normal-case no-regression.

The Rust planner does:

```rust
binding.worker_id = (queue_id % workers.max(1)) as u32;
```

so modulo assignment can map multiple queues onto the same worker
when `queues > workers`. The Go side's
`pkg/daemon/rss_indirection.go` reshapes RSS indirection only on
**mlx5** drivers, concentrating traffic onto queues `0..active-1`
where `active = min(workers, bound)` and `bound = min(queues,
BindingQueuesPerIface)` (it does not change the Rust planner's
per-interface queue count).

`active` is bounded by BOUND queues and not by `workers` alone (#7497).
The planner binds `min(rx_queues, 16)` per interface, so a NIC with more
RX queues than the stride has queues with no AF_XDP socket at all, and
feeding one is not merely wasteful: the shim resolves no binding and
takes `drop_degraded_transit`, so every transit packet steered there is
dropped while the interface reads up. Before that fix the fed set was
`[0, workers)` and could overrun the bound set — measured at
`workers=20, hwq=32` feeding 20 queues with 16 bound. Two of the wrong
cases never reached vector construction at all: `workers >= queues` took
the skip branch and left the kernel default feeding every hardware
queue, and so did `workers == 1`.

With `workers == 1` it still spreads rather than concentrating onto
queue 0 (#5124 — pinning would serialize the worker on one IRQ), but it
spreads across the BOUND queues, not every hardware queue. When
`active == queues` — everything bound and worker-served — it leaves the
live RSS table untouched, since the round-robin default already feeds
exactly that set. On
non-mlx5 drivers (i40e, etc.) it doesn't reshape at all. The default
RSS table is restored either when the kill switch fires
(`enabled == false`), or via `maybeRestoreDefault()` on the
`active >= queues > 1` skip path — there to undo a
concentrated table left by an earlier `workers < queues`
configuration (#805). On non-mlx5 + `workers > 1 && workers <
queues`, modulo collision can leave one worker bound to multiple
queues. See PR #1243's kill record for why i40e doesn't reshape.

## Gotchas

- `reconcile_status_bindings` has two arms. When `should_run_afxdp`
  holds it runs `Coordinator::reconcile` and returns its
  `Result<(), afxdp::ReconcileError>` (#3789): a pre-teardown abort
  (integrity build fault or a missing / unopenable mandatory pin) surfaces
  as `Err`, and the `apply_snapshot` handler's full-apply /
  same-plan-`needs_reconcile` legs fail closed on it — restoring the prior
  snapshot + status fields and reporting `ok=false` instead of persisting
  the rejected snapshot (see `docs/userspace-dataplane-architecture.md`,
  "Control-plane handler observes the reconcile outcome"). The
  already-accepted-snapshot callers reconcile a registration toggle / rebind
  / forwarding-state change, not a new config, so there is no rejected
  snapshot to un-persist — but the reconcile can still fault (mandatory-pin
  preflight / forwarding-build integrity error). #5621: `set_binding_state`,
  `set_queue_state`, and `rebind` (#6134) — and `set_forwarding_state`
  (#6135, the 4th site #5621 had excluded) — now SURFACE that `Err` (report
  `ok=false` + "`<site> reconcile failed: {err}`", refresh status, and return
  BEFORE `wait_for_binding_settle` / `persist_state=true`) instead of the old
  `let _ = reconcile_status_bindings(..)` discard that acked `ok=true` after a
  failed (re)bind; `rebind::handle` took a `response` parameter for this.
  #4952: the reconcile `Err` now also carries `ReconcileError::WorkerSpawn`
  — the one variant raised AFTER teardown (a `bring_up_workers`
  `spawn_supervised_worker` / `pthread_create` EAGAIN/ENOMEM leaves a queue
  set with no XSK-bound worker). The already-accepted-snapshot callers
  (`set_binding_state` / `set_queue_state` / `rebind` / `set_forwarding_state`)
  already fail closed on ANY `Err`, so they surface it unchanged. The
  `apply_snapshot` full-apply and same-plan-`needs_reconcile` legs SPECIAL-CASE
  it: unlike the pre-teardown integrity/map faults (where the prior workers
  stayed live and restoring `existing_bindings` is truthful), the old workers
  are GONE here — so they report `ok=false` + "`worker spawn failed after
  teardown (...)`", refresh status to the REAL post-teardown per-binding state
  (they do NOT restore `existing_bindings`), roll the in-memory baseline back
  to the prior good snapshot + status generation, and return BEFORE
  `persist_state=true` (the broken snapshot must never become the boot
  baseline). Pre-#4952 `bring_up_workers` returned `()` and swallowed the
  spawn error (overwriting `last_reconcile_stage` with `spawned:..`), so the
  handler acked `ok=true` and persisted a dataplane-down snapshot — a silent
  forwarding outage with no retry. Regression-tested per leg: the
  same-plan-`needs_reconcile` leg by
  `post_teardown_spawn_failure_fails_closed_no_persist_4952`, and the
  full-apply (plan-change) leg by
  `full_apply_post_teardown_spawn_failure_fails_closed_no_persist_6140`
  (#6140 — the full-apply arm was previously covered only transitively).
  #5143: `ReconcileError::WorkerBindIncomplete` is the SECOND post-teardown
  variant — a worker that SPAWNED but whose in-thread XSK/UMEM bind did not
  bring up its full planned queue set (a live-but-unbound worker whose
  heartbeat used to satisfy the supervisor), caught by `bring_up_workers`'
  per-worker startup readiness barrier (HEARTBEAT != READINESS). Both
  `apply_snapshot` legs handle it IDENTICALLY to `WorkerSpawn` (the shared
  `WorkerSpawn(stage) | WorkerBindIncomplete(stage)` arm): `ok=false`, roll
  the in-memory baseline back, refresh status to the REAL post-teardown
  per-binding state, and return BEFORE `persist_state=true`. Only the error
  verb differs — "`worker bind incomplete after teardown (...)`" vs "`worker
  spawn failed after teardown (...)`" — so the #4952/#6140 assertions that
  pin the "worker spawn failed" wording stay green. Regression-tested (full-
  apply leg) by
  `full_apply_post_spawn_inthread_bind_failure_fails_closed_no_persist_5143`.
  When
  `should_run_afxdp` does NOT hold (forwarding disarmed / unsupported) it
  `stop()`s every worker and then routes the per-binding status through
  `refresh_bindings` — which sends each now-workerless slot through
  `zero_unbound_slot`, clearing the FULL survivor set
  (`socket_ifindex`/`socket_queue_id`/`socket_bind_flags`,
  `flow_cache_capacity`, `active_flow_count`, every counter gauge, the
  latency histograms, plus `bound`/`xsk_registered`/`xsk_bind_mode`/
  `zero_copy`/`socket_fd`/`ready`/`last_error`) and rebuilds the CoS
  owner→worker map empty. This is the SAME tail the `no_snapshot`
  reconcile arm runs (#2515). Do NOT replace it with a hand-clear of a
  subset of fields: #2794 was exactly that bug — the disarmed arm left
  `socket_ifindex`/`queue_id`/`bind_flags` + `flow_cache_capacity`/
  `active_flow_count` stale, so `show` reported a disarmed slot as if
  still bound on its old queue.
- `defer_workers=true` requests skip the worker spawn until the next
  reconcile. Used during RETH MAC programming so workers don't bind to
  an interface that's about to drop and re-add its MAC. **The deferred
  apply still runs the pre-teardown integrity build before ack/persist
  (#5171).** Although the spawn is deferred, the snapshot is still ACKed +
  persisted as the boot baseline, so it must be fully buildable with all
  mandatory resources. The defer branch of `handlers/snapshot.rs` calls
  `guard.afxdp.validate_snapshot_buildable(Some(&snapshot))` — the SAME
  policy preflight + mandatory-map openability + full forwarding build
  that `reconcile` runs, factored out side-effect-free — BEFORE the
  side-effecting tunnel/WG prunes and the `guard.snapshot` swap, and fails
  closed on error (restore the bumped status generation/capabilities,
  `ok=false`, no persist), exactly mirroring the #3766/#3789 same-plan
  capture-restore legs. It cannot reuse `reconcile_status_bindings`: with
  forwarding not yet armed (arming follows the deferred bring-up) that
  takes the disarmed STOP path (a teardown with no integrity build), and
  when armed it would spawn workers — both wrong for a deferred apply.
  Pre-#5171 the defer path skipped this build, so a non-buildable config
  (bad interface address / CoS queue / NAT64 / NPTv6 rule, or a
  MISSING/UNOPENABLE mandatory map pin) was acked `ok=true` and persisted
  as the boot baseline, only to fail-OPEN at the later deferred bring-up
  (whose re-apply/rebind failures are warning-only) — a fail-open on a
  security appliance.
- Session installs run on a **dedicated** session-install socket
  (`derive_session_socket_path` next to the control socket), so they
  do not share the control-channel queue with status poll, HA sync,
  snapshot sync, and forwarding sync. The control channel is still
  shared by those other callers; adding a new caller there at >1 Hz
  can still starve the other low-frequency control operations.
  - Each session round-trip is one-request-per-connection: the Go side
    dials this socket, sends one newline-framed request, reads one
    response, and closes. If this thread is hung (accepts but never
    replies), the Go side bounds a single round-trip with a dial timeout
    plus a read/write deadline (`sessionSyncDialTimeout` /
    `sessionSyncRoundtripDeadline`, `pkg/dataplane/userspace`). A **bulk**
    Go caller (batch/clear session delete, up to 256 requests per chunk)
    additionally fast-fails the whole batch on the first transport failure
    (`errSessionHelperUnreachable`) instead of paying that deadline once
    per request, so a hung helper cannot stall bulk session ops — nor
    repeatedly hold the Go-side `sessionMu` and starve live installs — for
    minutes (#5380). Clear-all (`ClearAllSessions`) walks the mirror one
    4096-key chunk at a time and issues a helper delete per chunk, so it
    additionally guards the per-chunk delete on the same sentinel: once a
    transport failure is recorded the remaining chunks skip the helper delete
    (the BPF mirror still clears fully), bringing a full clear-all under a hung
    helper to ~one round-trip deadline total rather than one per chunk
    (~2440 chunks/family on a max table). The session mirror is best-effort;
    the periodic sweep retries once this thread is healthy again.
