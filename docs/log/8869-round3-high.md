# Issue 8869 — GEMINI-049 round-three high-lane adjudication

Research record only. Product code was read-only. This lane wrote this file and
filed only defects whose mechanism and consequence remained RED at current
master.

## Scope and method

- Worktree/branch: `/home/ps/git/pi-xpf/.claude/worktrees/8869-r3high`,
  `research/8869-r3high`
- Report: `/tmp/gemini-review-049.md`
- Comparison base: `b0f3aba21aede755573fb61714d3bfad15b795ab`
- Current master measured: `6fa3310c0609c4f2cb8547021db8cfa9ceda5883`
- Prior evidence consulted: `docs/log/8869.md`,
  `docs/log/8869-round2.md`, `docs/research/8869-adjudication.md`, and issue
  `#8869` comments.

Each row below separates the mechanism from the consequence. A static finding
was not filed merely because the cited code pattern existed: filing required a
current-master consequence, with the scope bounded where the original report
overstated it. No row was dismissed mechanically.

## Verdict summary

| Finding | Mechanism at base/current master | Consequence at current master | Disposition |
|---|---|---|---|
| `004` | The cited policy-only path can evaluate an over-limit flowless tuple, but the actual packet loop already gates it. | `poll_descriptor` drops and recycles a genuine over-limit IPv6 chain before policy evaluation. The prior `evaluate_policy` probe bypassed this gate. | **REFUTED — wrong when written** |
| `027` | The cited NAT helper is not the validation boundary. The Go compiler already computes deterministic capacity and rejects `totalBlocks < hostCount` at base; master expands CIDR/singular pool members and saturates arithmetic. | Undersized deterministic pools do not commit cleanly through the cited compiler path. Base could over-refuse some pool forms, but did not under-refuse them. | **REFUTED — wrong when written** |
| `055` | `electRG`'s preempt arm returns `electNoChange, ""` for an incumbent winner; only the non-preempt dual-active branch returns the reaffirm reason that emits `DualActiveWin`. Same shape at base and master. | Direct-VIP (`noRethVRRP`) winner does not schedule the post-split-brain GARP/NA refresh; ownership reconciliation also does not announce an already-owned VIP. | **FILED #10426** |
| `057` | A global `IsLocalPrimaryAny` callback exists in the Go GC wiring at base/master. | The supported userspace runtime sets `gc.SkipSweep = true`; the sweep returns before role checks/deletes. eBPF is retired, so the reported live consequence has no supported caller. | **REFUTED — dead legacy path** |
| `065` | Base overwrote `policySchedulerActive` before route-overlay publication. | Master separates desired from applied state and commits the applied cache only after helper success (`630dd9bb2`, #10005). | **FIXED-SINCE `630dd9bb2`** |
| `066` | Base schedule/overlay paths bypassed the full wrapper. Master still uses the narrower `requestApplySnapshotLocked` helper, not `publishSnapshotFailClosedLocked`. | Both callers return an error for retry: scheduler republish retries on its next tick and route coalescing stays dirty. No measured “operator commit required” or permanent dead manager consequence. | **REFUTED — consequence unproven/overstated** |
| `069` | `acceptLoop` holds `es.mu` while `clearPendingCallbackFrames` takes `pendingFlushMu`; the same lock nesting remains. | Production callbacks do not call `writeFrame`/`SendDrainRequest`, and no reverse `pendingFlushMu -> es.mu` edge exists. The proposed ABBA deadlock is not a live route. | **REFUTED — consequence unproven** |
| `071` | General ingress qualification is fixed since `a7d102c5f`, but shared-parent, lifeline, and VRF-slave exclusions can leave a zone with no matchable ingress device. The ingress emitter returns without a scoped rule and the bare destination rules remain. | An excluded-everywhere zone can still fall through to destination-only host-inbound judgment and admit a cross-zone host-bound packet. Existing VRF-only fixture measures `IngressNetdevs=nil`, no rule, warning only. | **FILED #10431** |
| `073` | The unzoned address deny remains a destination-only drop in the `input` base chain at base/master. | Transit packets route through `forward`, not `input`; a packet that reaches `input` is host/local-delivery traffic. The report's transit/DNAT consequence is therefore not established by this rule. | **REFUTED — scope/consequence wrong** |
| `076` | Route-based wildcard defaults apply only when both local and remote selectors are empty. A selector-shaped local-only identity leaves remote empty. Same condition at base/master. | strongSwan's empty remote side narrows to the peer endpoint /32; routed transit destinations miss the XFRM policy and blackhole. | **FILED #10427** |
| `079` | Reload is followed by a synchronous restore of `rp_filter` (`xpf-usp0` and `xpf-usp1` on master); no dedicated networkd `.network` ownership/watcher is present. | The report's asynchronous post-restore overwrite was not measured: this environment has no active `systemd-networkd`, and source/tests only establish the synchronous reload reset and restoration. | **DEFERRED — requires managed-networkd/inotify measurement** |
| `083` | Fabric HMAC signs only domain + time window; method is logging-only, verifier accepts ±1 window, plaintext listener has no nonce/replay cache. Same at base/master. | Full interceptor-chain merits execution showed a captured operator token replays across the allowlisted destructive RPCs for 30–59 seconds. No periodic token source; heartbeat is domain-separated. | **FILED #10429** |
| `090` | The reported one-shot stream authorization existed at base. | Current REST wraps streams in `watchReadAuthorization`; gRPC wraps streams in `authorizeStreamContinuously`, from merged fix PR #9258. | **DUPLICATE/FIXED #9051** |
| `093` | Memfile parser packs v4 `client_id` and `hwaddr` into one identity, then `splitV4Identity` recovers only one; `syncLeaseToKea` omits empty `hw-address`. Same at base/master. | Kea requires `hw-address` for IPv4 `lease4-add`; every Option-61 row in the fallback loses its MAC and is rejected during takeover seeding. | **FILED #10428** |

Counts for the 14 assigned rows (10 pending Highs plus `004`, `071`, `083`,
`090` confirmations): **FILED 5** (`#10426`, `#10427`, `#10428`, `#10429`,
`#10431`); **REFUTED 6**; **FIXED-SINCE 1**; **DEFERRED 1**;
**DUPLICATE 1**.

## Evidence and adjudication notes

### `004` — actual packet path already fails closed

At both base and master, `userspace-dp/src/afxdp/poll_descriptor/mod.rs`
checks `flow.is_none()` and calls `ipv6_ext_header_over_limit_drop`; when it
returns true the descriptor is recycled and the loop `continue`s. The helper
increments `ipv6_ext_header_dropped`. The policy-only probe recorded in the
prior merits log invoked `evaluate_policy` directly and therefore did not
exercise this packet gate. The existing explicit-drop disposition is already
the design decision for the over-limit case; no issue was filed.

### `027` — validation existed at the comparison base

The base compiler's deterministic-pool validation (`pkg/config/compiler_nat_source.go`)
computes `blocksPerIP`, `totalBlocks`, and rejects IPv4 pools with insufficient
capacity. Master retains that gate and fixes the separate over-refusal by
expanding pool hosts (CIDR and singular `pool.Address`) with saturating
arithmetic (`:890-953`). The report's cited
`pkg/dataplane/userspace/nat_source.go` helper only constructs runtime fields;
it is not the missing cross-field validation boundary.

### `055` — preempt incumbent has no reaffirm event

At `pkg/cluster/election.go:174-208`, the preempt branch resolves priority/tie
ownership but always returns `electNoChange, ""` when the incumbent remains
primary. The non-preempt branch at `:215-237` returns
`"Dual-active: winner stays"`. `runElection` emits `DualActiveWin` only for the
latter reason (`:364-406`). `daemon_ha.go:612-617` schedules the direct
announce only for that event, while `daemon_ha_vip.go:154-172` announces only
when ownership changes or a VIP is newly added. There is no periodic direct-VIP
GARP ticker. The filed defect is bounded to direct-VIP mode; VRRP-advertised
RETH deployments are outside the consequence.

### `057` — Go GC role callback is unreachable for supported sessions

`daemon_run.go:241-260` wires `IsLocalPrimaryAny`, but the same setup detects
`userspaceSessionDeltaDrainer` and sets `SkipSweep`. `conntrack/gc.go:252-300`
returns before session iteration, expiry, role evaluation, and delete callbacks
when that flag is true. The runtime builder defaults an empty dataplane type to
userspace and the legacy eBPF backend returns the retired-backend error. The
reported Active/Active deletion trace would require a supported runtime that
runs this Go map sweep, so the row is refuted rather than filed.

### `065` — applied scheduler state was separated after the base

Base `manager_overlay.go:117-126` assigned `m.policySchedulerActive` before
publication. Master commit `630dd9bb2fa545e9397e0758730114c012b4bd09`
(`fix: separate applied scheduler state from desired state (#10005)`) stages
`policySchedulerDesired`; `m.policySchedulerActive` is committed only after
`requestApplySnapshotLocked` succeeds. This is fixed since the comparison base.

### `066` — direct publication remains, but the claimed dead-manager outcome does not

The current schedule path (`manager_compile.go:995-1073`) and route path
(`manager_overlay.go:103-272`) use `requestApplySnapshotLocked`; they do not
invoke the full `publishSnapshotFailClosedLocked` wrapper. That preserves the
mechanism observation but not the report's consequence. The scheduler caller
(`daemon_scheduler.go:277-321`) explicitly records failure and retries on its
next tick. The route listener (`daemon_route_listener.go:229-263`) returns false
on publication failure, keeping its coalesced dirty state for retry. The report's
own base evidence also says the schedule path reports failure for autonomous
retry. No base/current measurement showed a permanent outage requiring an
operator commit; no issue was filed.

### `069` — no production reverse lock edge

Base and master `eventstream.go` hold `es.mu` through `clearPendingCallbackFrames`
(`:540-555`, `:1412-1425`) and hold `pendingFlushMu` while dispatching callbacks
(`:1427-1520`). The alleged ABBA requires a callback to acquire `es.mu`, but the
installed production callbacks in `daemon_ha_userspace_stream.go:330-348,414-495`
perform session-sync/event-buffer work and do not call `writeFrame` or
`SendDrainRequest`. `writeFrame` is reached from ACK/control paths, not those
callbacks. The lock nesting is worth maintenance review, but the reported
helper-reconnect deadlock consequence is not a validated live defect.

### `071` — only the excluded-everywhere residual remains

The broad finding was fixed by `a7d102c5f`/#9637: ordinary zone rules are
`iifname`-qualified. The remaining path is explicit in
`zones_host_inbound.go:563-586`: shared parents, lifelines, and VRF slaves are
excluded; `netlink_hostinbound_ingress_9637.go` returns when the resolved set is
empty; `netlink_hostinbound.go:157-178` still emits the destination-only zone
rules. The current `junos_host_vrf_scope_6619_test.go` row “VRF-enslaved, only
interface” measures the state as `wantScoped=nil`, `wantRules=false`, warning
only. A warning does not enforce the configured cross-zone perimeter while the
commit succeeds. Issue #10431 records the narrow residual and requires
VRF-master (or equivalent fail-closed) handling.

### `073` — input-chain rule cannot be a routed-transit drop

`emitUnzonedHostInboundDenyNetlink` (`netlink_hostinbound.go:180-187`) emits a
bare `daddr` drop, but `netlink_installer.go:169-175` installs this table's base
chain at `ChainHookInput`. Routed transit traffic is adjudicated by the
`forward` hook. A packet that reaches `input` has already been classified for
local delivery; calling that transit does not establish the claimed
consequence. No issue was filed.

### `076` — asymmetric selector omission narrows route-based VPNs

`pkg/ipsec/policy.go:534-539,541-614` retains
`routeBasedDefaultTS = "0.0.0.0/0,::/0"` but applies it only under
`local == "" && remote == "" && xfrmiIfID(...) > 0`. Selector-shaped local-only
identity survives the `IsTrafficSelectorShape` gate and leaves remote empty.
The in-tree strongSwan 6.0.5 measurement records endpoint `/32` policies for
an omitted selector and `/0` policies for explicit wildcard selectors. Issue
#10427 requires independent defaults for each empty side while preserving
explicit selectors and policy-based VPN behavior.

### `079` — asynchronous overwrite is not yet measured

Master `networkd.go:697-734` restores `rp_filter=0` for both slow-path TUNs
immediately after reload/reconfigure tails. Existing tests model networkd's
synchronous reload reset and verify that the manager-only tail restores the
value, including when another reload owner discharges global debt. The claimed
later worker write after the restore needs a real systemd-networkd-managed
interface plus inotify/netlink observation; `systemd-networkd` is inactive in
the adjudication environment. This is deferred, not dismissed and not filed.

### `083` — method-unbound fabric token replay

The token implementation (`pkg/grpcapi/fabric_auth.go:122-160,269-330`) signs
domain and time window only; `method` affects logging, not verification. The
fabric server remains plaintext (`server.go:959-976`), and allowlisting plus
request-action checks still admit `ClearSessions` and both safe failover forms.
The prior full interceptor-chain execution measured a 30–59 second
cross-method replay window. Issue #10429 records the bounded consequence and
requires method binding (or mTLS) with a cross-method regression.

### `090` — duplicate of merged stream reauthorization fix

Issue #9051 is closed by merged PR #9258. Current REST authorization calls
`watchReadAuthorization` (`pkg/api/authz.go:961` and
`authz_stream_reauth_9051.go`), and current gRPC stream interception calls
`authorizeStreamContinuously` (`pkg/grpcapi/authz.go:373` and its
`authz_stream_reauth_9051.go`). The report's base behavior is therefore already
owned by #9051.

### `093` — v4 memfile identity is lossy

`ddns_leases.go:75-78,483,522-535` requires both v4 columns, then
`identity4` chooses `cid:` over `mac:`. `lease_sync.go:361-435,462-473`
recovers an empty hardware address for a `cid:` identity. The seed renderer at
`:652-706` copies that empty field into an `omitempty` `hw-address`. Kea's
`lease4-add` contract makes `hw-address` mandatory for IPv4. Issue #10428
requires preserving both fields through memfile fallback and seeding both.

## Filed issues

All filed issues have the required `bug` and `source:gemini-review-049`
labels, and each title/body carries its finding ID:

| Finding | Issue | Required acceptance |
|---|---:|---|
| `055` | [#10426](https://github.com/psaab/xpf/issues/10426) | Preempt incumbent dual-active resolution emits `DualActiveWin` and drives direct-VIP announce, with election and daemon regressions. |
| `076` | [#10427](https://github.com/psaab/xpf/issues/10427) | Route-based VPN defaults each empty selector independently; local-only and remote-only render tests pass without widening policy-based VPNs. |
| `093` | [#10428](https://github.com/psaab/xpf/issues/10428) | Option-61 memfile rows seed Kea `lease4-add` with both `client-id` and `hw-address`. |
| `083` | [#10429](https://github.com/psaab/xpf/issues/10429) | Captured `GetStatus` token cannot authorize `ClearSessions`/failover; rotation/skew behavior remains intact. |
| `071` | [#10431](https://github.com/psaab/xpf/issues/10431) | Excluded-everywhere host-inbound zones are scoped on matchable master/parent devices or fail closed; VRF/shared/lifeline regressions cover the residual. |

## Scoped verification

Executed on current master before writing this log:

- `go test ./pkg/dataplane/userspace -run
  'TestJunosHostIngressScopeCoverage6619|TestZoneHostInboundViewIngressNetdevs9637|TestHostInboundViewIngressNetdevsExcludesSharedClaims9637' -count=1`
  — PASS (`0.138s`).
- `go test ./pkg/dhcpserver -run 'Test.*(LeaseSync|Memfile|LeaseSource)' -count=1`
  — PASS (`0.018s`).
- `go test ./pkg/cluster -run 'Test.*(Election|DualActive|Preempt)' -count=1`
  — PASS (`0.469s`).
- `go test ./pkg/ipsec -run 'Test.*(Selector|Traffic|Route)' -count=1`
  — PASS (`0.006s`).

These are scoped evidence checks only; project-wide validation remains the
parent lane's responsibility.
