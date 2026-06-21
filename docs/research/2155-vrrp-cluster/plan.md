# Research plan — VRRP HA cluster: IPv6-advert drop (#2155) + UpdateInstances orphan (#2156)

Status: PLAN-READY (both bugs)
Worktree: `.claude/worktrees/2155-research` (branch `research/2155-vrrp-cluster`)
Base: `origin/master` @ `36400cff4`
Scope: `pkg/vrrp` (RX path + instance lifecycle) and its docs. No dataplane,
no config-grammar, no cluster-state-machine changes. Each bug is independent and
can ship as its own PR; combine only if the engineer prefers a single
VRRP/HA smoke run.

---

## 1. Problem statement

Two independent defects in the native VRRPv3 manager (`pkg/vrrp`), both filed
from agy-review-016 against master, both VRRP/HA-smoke class.

### #2155 — IPv6 VRRP adverts with extension headers are dropped (LOW)
The AF_PACKET RX path assumes an IPv6 VRRP advertisement has **no** IPv6
extension headers:

- `openAfPacketReceiver` (`manager.go` ~600-650) attaches a cBPF program that,
  for IPv6, loads the IPv6 **base** header's Next-Header byte at a fixed offset
  (20 untagged / 24 for 802.1Q) and accepts only `== 112`. If a peer inserts
  any extension header (Hop-by-Hop, Routing, Destination Options, …), the base
  Next-Header is that ext-header's protocol (e.g. 0 for Hop-by-Hop), `jeq 112`
  fails, and the kernel drops the frame **before xpf ever sees it**.
- Even if such a frame reached `parseAfPacketIPv6` (`instance.go` ~776-823), it
  hardcodes `const ipv6HeaderLen = 40` and slices the VRRP payload at `ip6[40:]`.
  With an ext-header present, offset 40 lands inside the ext-header, the VRID
  byte check (`payload[1]`) and `ParseVRRPPacket` version/checksum checks fail,
  and the advert is discarded.

Consequence: a non-xpf VRRP speaker (or an unusual stack) that emits ext-headers
on the VRRP multicast is invisible to xpf → both nodes can believe they are
master → split brain. **Rarity is the entire severity argument:** xpf's own
IPv6 sender (`openIPv6Socket` via `ip6:112`, `SendGratuitousIPv6Burst`) emits a
bare base header with hop-limit 255 and no ext-headers, and RFC 5798 VRRPv3 IPv6
adverts are normally sent that way. The base-header IPv6 path **works today**
(proven by `TestAfPacket_IPv6UntaggedFrame` / `_IPv6VlanTaggedFrame`). This bug
is strictly the ext-header tail.

### #2156 — UpdateInstances orphans an instance on transient link/socket failure (MEDIUM)
`UpdateInstances` (`manager.go` 249-285), on the "VIPs changed → must restart"
branch, tears the old instance down and removes it from the runtime map
**before** the replacement is built:

```go
existing.stop()
delete(m.instances, key)            // removed unconditionally
iface, err := net.InterfaceByName(inst.Interface)
if err != nil { ...; continue }     // orphan: gone, no retry
vi := newInstance(...); vi.desiredPreempt = inst.Preempt
if err := vi.openSocket(); err != nil { ...; continue } // orphan
m.instances[key] = vi
```

If `net.InterfaceByName` (257) or `vi.openSocket()` (271) fails — member
interface transiently down, mid-rename by networkd, or carrier-flap during the
config apply — the function `continue`s with the old entry already deleted and
no new entry inserted. There is **no Failed/Pending placeholder and no retry**.
That RG silently drops out of VRRP election until the operator re-commits.
This is the "membership-guard-must-be-atomic" failure mode from MEMORY
(#1800 U8): the teardown is not atomic with the successful rebuild.

---

## 2. Goals / non-goals

Goals:
- #2155: let IPv6 VRRP adverts carrying extension headers reach the state
  machine, while keeping the AF_PACKET filter tight (still proto-112-only).
- #2156: make `UpdateInstances` orphan-free — a transient link/socket failure
  must never leave an RG with zero participating instances, and the system must
  self-recover when the interface returns, without an operator re-commit.

Non-goals:
- No change to the VRRP wire format, checksum, advert cadence, or election
  semantics.
- No new config grammar; no dataplane/Rust changes.
- #2155: no attempt to make xpf *send* ext-headers (it never should).
- #2156: not a rewrite of the sync-hold / track-state seeding logic — reuse the
  existing `seedTrackState` / link-watcher machinery.

---

## 3. Current behavior (as-built, verified against source)

RX path (per instance, started in `run()`):
- If `afPacketFD >= 0` → `receiverAfPacket()` (the production path on the loss
  cluster, since RETH VRRP runs on VLAN sub-interfaces `reth0.50` etc.). The
  AF_PACKET socket is `SOCK_RAW + ETH_P_ALL` with the cBPF `SO_ATTACH_FILTER`
  from `openAfPacketReceiver`.
- Else → `receiver()` (IPv4 raw `ip4:112`) and, if `ipv6Conn != nil`,
  `receiverIPv6()` (IPv6 raw `ip6:112`). **The raw `ip6:112` socket has no cBPF
  filter and no fixed-40 assumption** — the kernel strips the IPv6 header
  (including ext-headers) and hands `ReadFrom` the upper-layer VRRP payload
  directly. So the #2155 ext-header bug is confined to the **AF_PACKET path**;
  the raw-socket fallback already handles ext-headers correctly. On the loss
  cluster, AF_PACKET is the live path (VLAN sub-interfaces), so the bug is real
  there.

The IPv4 AF_PACKET parse (`parseAfPacketIPv4`) already walks IHL
(`ihl := int(ip[0]&0x0F)*4`) and slices `ip[ihl:]` — it tolerates IPv4 options.
The IPv6 parse does **not** do the equivalent ext-header walk. This is the exact
IPv4/IPv6 asymmetry the fix must close.

`UpdateInstances` lifecycle:
- Called from two sites (both under churn): `daemon_apply.go:1132` (config
  commit) and `daemon_ha.go:320` (debounced 500ms cluster priority update). It
  holds `m.mu` for the whole diff.
- Three sub-cases for an existing key: (a) no change → `continue`; (b) only
  priority/preempt/track changed (VIPs equal) → `updateConfig` in-place, **no
  teardown** (deliberately, to avoid a 3s master-down gap); (c) **VIPs changed**
  → `stop()` + `delete` + rebuild (the buggy branch).
- New-key creation runs the same `InterfaceByName` + `openSocket` + `go run()`
  sequence and the same `continue`-on-error orphan, but a *new* key that fails
  to build was never in the map, so "orphan" there is just "not yet created"
  (the next `UpdateInstances` retries it). The acute bug is the VIPs-changed
  branch that **deletes a working instance first**.

Recovery hooks that already exist (reuse, don't reinvent):
- `reconcileRGStateLoop` (`daemon_ha.go:461`) ticks every **2s** and on
  `reconcileNowCh`. It currently only *reads* `InstanceStates()` to reconcile
  rg_active / blackhole / VIP posture — it does **not** call `UpdateInstances`.
- The singleton link-watcher (`runLinkWatcher`, `track.go`) streams netlink
  link up/down but only feeds `trackDown` — it does not rebuild instances.

Takeover-gate coupling (critical for #2156 design — see §6):
`RGVRRPReady(rgID, hasRETH)` (`manager.go:405`) returns **ready** if *any*
instance exists for VRID `100+rgID`. It does not inspect instance health. So a
naive "leave a placeholder in `m.instances`" fix would make a non-running
placeholder **falsely satisfy the HA takeover gate** (`daemon_ha_vip.go:49`) →
the daemon could lift blackholes / claim VIPs for an RG whose VRRP isn't
actually running. The placeholder must be health-aware end-to-end.

---

## 4. Root cause

- **#2155:** the AF_PACKET RX assumes IPv6 base-header-only. Two coupled
  fixed-offset assumptions — the cBPF Next-Header match at offset 20/24, and
  `parseAfPacketIPv6`'s hardcoded `ipv6HeaderLen = 40` — neither walks the
  IPv6 ext-header chain. (The raw `ip6:112` fallback is fine; only AF_PACKET is
  affected.)
- **#2156:** non-atomic membership mutation — `delete(m.instances, key)` happens
  before the replacement is proven buildable, and the error path `continue`s
  without restoring the old entry or registering a retry.

---

## 5. #2155 — design options

The constraint: **let proto-112 IPv6 frames with ext-headers through, keep the
filter from flooding the receiver with all IPv6 multicast.** Two places must
change in lockstep — the cBPF prefilter AND the Go parser — because a frame the
filter admits but the parser mis-slices is no better than a dropped frame.

### Option A (recommended) — broaden the cBPF to "any IPv6 to the VRRP path", walk ext-headers in Go
cBPF: replace the fixed-offset Next-Header `== 112` test with one that accepts
IPv6 frames and defers upper-layer protocol identification to Go. Keep IPv4 and
the 802.1Q demux exactly as-is (IPv4 already walks IHL in Go). Two tightening
sub-choices for the IPv6 arm:

- A1: accept **all** IPv6 frames at the filter, do all proto-112 + dst-mcast +
  ext-header validation in `parseAfPacketIPv6`. Simplest cBPF; slightly more
  Go-side work per IPv6 frame (acceptable — IPv6 multicast volume on a RETH
  segment is tiny, and `receiverAfPacket` already runs per-frame Go logic).
- A2: keep a cheap cBPF guard that still rejects obvious non-VRRP — e.g. match
  the IPv6 base Next-Header against the small set {112, 0 (Hop-by-Hop),
  43 (Routing), 60 (Dest-Opts), 44 (Fragment)} so single-ext-header VRRP and
  bare VRRP pass while ordinary TCP/UDP/ICMPv6 are still dropped in-kernel.
  Tighter than A1 but does not handle a *chain* of ext-headers (the second
  ext-header's type is invisible to a fixed-offset cBPF). cBPF ext-header
  *chain* walking is not practical (no loops, fixed program).

**Recommendation: A2 on RETH VLANs that carry IPv6 data traffic; A1 only where
they do not** (revised by SMR-r1 F6). The in-kernel filter's job is volume
reduction; authoritative validation already happens in Go (`ParseVRRPPacket`
checks version, type, checksum; the parser checks hop-limit 255 and VRID). The
Go-side ext-header walk (below) is identical under both A1 and A2 — the only
difference is how much the cBPF pre-drops in-kernel.

- A1 (accept all IPv6 at the filter) is the simplest cBPF, but on a RETH VLAN
  that carries real IPv6 data (the loss cluster's `reth0.80` carries the
  `2001:559:8585:80::200` iperf3 target) it wakes `receiverAfPacket` for ALL
  IPv6 traffic and discards non-112 in Go — needless load.
- A2 (match the IPv6 base Next-Header against {112, 0, 43, 60, 44}) keeps
  ordinary IPv6 TCP/UDP/ICMPv6/ND dropped in-kernel while admitting any frame
  whose FIRST header is an extension header or VRRP — which is exactly the
  VRRP-with-ext-header set. A2's only structural miss is a frame whose first
  header is some other non-ext, non-112 protocol, which is never VRRP. A2 cannot
  see the *second* header in a chain (fixed-offset cBPF), but it does not need
  to: any chained VRRP advert starts with an ext-header that A2 admits, then the
  Go walk resolves the rest.

So **A2 is the better default on the smoke target** (data-bearing IPv6 VLAN);
fall back to A1 only when the VLAN provably carries no IPv6 data. Both share the
bounded Go walk and match the IPv4 arm's "filter-loose, validate-in-Go" shape
(IPv4 already passes proto-112 in-kernel then re-validates TTL/IHL in Go).

Go-side ext-header walk in `parseAfPacketIPv6` (and the mirrored test helper):
- Start `nh := ip6[6]` (base Next-Header), `off := ethHeaderLen + 40`.
- Loop while `nh` is an ext-header type with the standard
  `(NextHeader, HdrExtLen)` shape — **0** Hop-by-Hop, **43** Routing, **60**
  Destination Options, **51** AH (special length unit), and treat **44**
  Fragment as a hard stop (a fragmented VRRP advert is non-conformant — drop).
  For HBH/Routing/Dest-Opts: `nh = buf[off]; off += (buf[off+1]+1)*8`. For AH:
  `off += (buf[off+1]+2)*4`. Bounds-check `off` against `n` every step; cap the
  iteration count (e.g. ≤ 8) to bound a malicious header chain.
- Stop when `nh == 112` → VRRP payload begins at `off`. Any other terminal
  protocol → drop. Then keep the existing hop-limit-255, self-filter, VRID, and
  `ParseVRRPPacket` checks, but slice at the **walked** `off`, not fixed 40.
- Source/destination IPs still come from the base header (`ip6[8:24]`,
  `ip6[24:40]`) — ext-headers do not move them.

### Option B — document-only (the issue's "minimum")
Add a homogeneous-peer note to `pkg/vrrp/README.md` + `docs/ha-cluster*.conf`
caveats stating xpf assumes RFC-5798 base-header IPv6 adverts and does not
parse ext-header VRRP on the AF_PACKET path. **Not recommended as the sole
fix** — it leaves a real (if rare) split-brain trigger and a latent IPv4/IPv6
asymmetry, and the walk is small and well-bounded. Keep the doc note *in
addition* to Option A (document the bound: chains > 8 ext-headers, AH, and
fragmented adverts are dropped by design).

### #2155 recommendation
**Option A1 + a docs note.** Broaden the cBPF IPv6 arm to accept all IPv6,
add a bounded ext-header walk in `parseAfPacketIPv6` (and the test mirror), and
document the homogeneous-peer expectation plus the explicit drop bounds.
Keep IPv4 and 802.1Q demux untouched.

---

## 6. #2156 — design options

The constraint: orphan-free + self-recovering + the placeholder must not lie to
`RGVRRPReady` (the HA takeover gate, §3). Two structurally different fixes.

### Option A (recommended primary) — build-before-teardown
Resolve the new interface and open the new socket **before** stopping/deleting
the old instance. On any build error, **leave the old instance running** and
`continue` (it keeps advertising the old VIPs until the next `UpdateInstances`
retries). Only after a fully-built replacement do `existing.stop()` +
`delete` + `m.instances[key] = vi` + `go vi.run()`.

Why this is the strongest fix:
- It is the literal repair of the non-atomic mutation — the working instance is
  never removed unless its replacement is proven buildable. Matches the
  "check inside the acting lock / state equals desired after every mutation"
  discipline (#1800 U8).
- No new placeholder state, so `RGVRRPReady` / `States` / `InstanceStates` /
  `Status` are unchanged and cannot be fooled.
- Self-recovery is free: the two existing `UpdateInstances` callers
  (config-commit and the 500ms debounced cluster path) re-drive the diff; the
  next call after the interface returns succeeds and swaps in the new VIPs.

The one behavioral nuance to document: during the failure window the RG keeps
advertising the **old** VIP set, not the new one. That is strictly better than
the current "no instance at all," and the operator's intended VIPs land on the
next retry. (If the VIP change was a *removal* of a VIP, the old VIP lingers
until retry — acceptable; the alternative today is total loss of the RG.)

Edge cases A must handle:
- Sync-hold: the new instance must still get `instCfg.Preempt=false` +
  `desiredPreempt` exactly as the current code does — move that block to the
  build-before-teardown ordering, don't drop it.
- Tracked interface: `seedTrackState` must run on the new instance before
  `go run()` (as today). Build the instance and seed *before* the old `stop()`.
- `openSocket` partial success: `openSocket` already tolerates a failed
  AF_PACKET open (logs, raw-only) and a failed IPv6 socket — only a failed
  *primary* `openPerInterfaceSocket` returns an error. Build-before-teardown
  must close the half-open new socket if it then decides to abort (it won't —
  if `openSocket` returns nil we commit). Confirm no fd leak on the abort path
  (there is none: if `openSocket` errors it has already closed its own conn).

### Option B (recommended companion) — proactive retry so a *persistent* failure still recovers
Build-before-teardown (A) self-recovers **only because the existing callers
re-drive the diff.** The config-commit caller fires once; the debounced cluster
caller fires only on cluster-state events. If the interface is down for, say,
10s with no cluster event and no re-commit, A alone will not retry until the
next event. To guarantee bounded self-recovery, add a lightweight retry:

- B1 (recommended): in `reconcileRGStateLoop` (already a 2s safety-net ticker),
  re-invoke the VRRP instance reconcile. Cheapest hook: have the loop call a
  new `Daemon.reconcileVRRPInstances()` that recomputes the desired set
  (`CollectInstances` + `CollectRethInstances`) and calls
  `UpdateInstances`. With A in place, a still-missing instance is simply
  re-attempted every 2s and swaps in once the interface is up — no new state in
  `pkg/vrrp`. This reuses the documented "safety net for dropped events" loop.
- B2 (alternative): a Pending placeholder kept in `m.instances` with a
  `running bool` field, retried by the link-watcher when the member interface
  comes up. **Rejected as primary** because (i) it adds health-state that
  `RGVRRPReady` MUST then learn to ignore (a `running==false` placeholder must
  NOT satisfy the takeover gate — otherwise the daemon claims VIPs for a dead
  RG), touching the gate, `States`, `InstanceStates`, and `Status`; (ii) the
  link-watcher currently keys on `TrackInterface`, not the VRRP member
  interface, so it would need a second mapping. Higher blast radius for the same
  outcome A+B1 gives with less surface.

### #2156 recommendation
**Option A (build-before-teardown) as the core fix, plus B1 (2s reconcile
re-drive of UpdateInstances) for bounded self-recovery on a persistent
failure.** A makes the mutation atomic; B1 guarantees recovery without a
re-commit and without new placeholder state. Explicitly reject B2.

PLAN-KILL note: neither bug is a kill candidate. #2155 is borderline
(LOW + rare), but the fix is small and closes a real asymmetry, so ship Option
A1 rather than doc-only. If the engineer wants the absolute minimum, doc-only
(Option B for #2155) is a defensible fallback — flag it for the approver.

---

## 7. Proposed implementation (for the /engineer pass — not implemented here)

#2155 (AF_PACKET IPv6 ext-header tolerance):
1. `manager.go` `openAfPacketReceiver`: rewrite the IPv6 arm of the cBPF so an
   IPv6 frame (untagged and 802.1Q) is accepted regardless of base Next-Header;
   IPv4 and the 0x8100/0x88a8 demux unchanged. Re-number jump offsets carefully
   and keep the inline offset comments accurate.
2. `instance.go` `parseAfPacketIPv6`: add a bounded ext-header walk (types
   0/43/60/51; 44 Fragment = drop — no userspace reassembly and VRRP adverts are
   never legitimately fragmented; <=8 iterations; bounds-checked) that yields the
   VRRP payload offset; slice at the walked offset. Note the two length-unit
   conventions in code comments: HBH/Routing/Dest-Opts use `(HdrExtLen+1)*8`
   (8-byte units), AH uses `(PayloadLen+2)*4` (4-byte units) — mixing them is the
   classic walk bug. Keep hop-limit-255, self-filter, VRID, `ParseVRRPPacket`.
3. `vrrp_test.go`: extend the `parseAfPacketIPv6Frame` test mirror with the same
   walk and add cases — bare base header (regression), single Hop-by-Hop,
   chained HBH+Dest-Opts, Routing, AH, Fragment (must drop), chain-too-long
   (must drop), 802.1Q + ext-header. Add a frame builder that emits ext-headers.
4. Docs: `pkg/vrrp/README.md` Sockets/Gotchas — note AF_PACKET now walks IPv6
   ext-headers, the explicit drop bounds (>8 chain, AH-overflow, fragmented), and
   that the raw `ip6:112` fallback is ext-header-safe for the common ext-headers
   (kernel walks them) — do NOT over-claim AH/fragmented safety on either path.

#2156 (orphan-free UpdateInstances + self-recovery):
1. `manager.go` `UpdateInstances`: reorder the VIPs-changed branch to
   build-before-teardown — resolve iface, `newInstance`, `openSocket`, seed
   track state into a *local* `vi`; on any error log + `continue` leaving
   `existing` untouched; only on full success `existing.stop()` + `delete` +
   `m.instances[key] = vi` + `go vi.run()`. Preserve the sync-hold preempt and
   `desiredPreempt` handling. (Optionally apply the same build-before-commit
   shape to the new-key path for symmetry, though it is already non-destructive.)
2. `daemon_ha.go` `reconcileRGStateLoop`: add a `reconcileVRRPInstances()`
   re-drive (B1) so a persistent interface failure recovers within ~2s without a
   re-commit. Mirror the loop's existing `if d.cluster == nil || d.vrrpMgr ==
   nil { return }` nil-guards. Guard against churn — it just recomputes the
   desired set and calls the now-idempotent `UpdateInstances` (a no-change diff
   is already a cheap no-op via the `continue` paths; a priority-only delta hits
   the in-place `updateConfig` path, NOT a restart, so B1 cannot cause a restart
   storm).
3. Tests: a manager-level test with an injectable interface/socket-open seam
   (the package already injects `linkState`/`subscribeLinks`; add a parallel
   seam for `InterfaceByName`/`openSocket` or test via a fake that fails once
   then succeeds) asserting: on a transient build failure the old instance stays
   in `m.instances` (no orphan, no double-run), and a subsequent
   `UpdateInstances` succeeds and swaps it. Assert `RGVRRPReady` stays truthful
   throughout (old instance present = ready; never a phantom-ready hole).
4. Docs: `pkg/vrrp/README.md` lifecycle note — VIP-change restart is
   build-before-teardown (old instance survives a transient member-link failure
   and is retried), and CLAUDE.md HA section if the failover contract wording
   needs it (likely not — timing is unchanged).

---

## 8. Test / validation strategy

Unit (CI, `make test`):
- #2155: the extended `parseAfPacketIPv6Frame` table (bare/HBH/chain/Routing/
  AH/Fragment-drop/too-long-drop/VLAN+ext). cBPF cannot be unit-tested without a
  socket, so assert the *Go* walk; the cBPF broadening is validated by the smoke
  (a real ext-header advert reaching the receiver) + manual `tcpdump`.
- #2156: the build-before-teardown atomicity test (transient-fail-then-succeed
  seam) + a `RGVRRPReady`-stays-truthful assertion + a no-double-run assertion
  (the old instance's goroutine is not stopped on the failed path; the new one
  is not started). Add `-race`.

Smoke (parent runs — loss userspace cluster, **`make test-failover`**):
- Mandatory per CLAUDE.md: any VRRP change must pass `make test-failover`
  (iperf3 through the cluster while cycling RG failovers, expect 0 drops).
- #2155 extra: on the WAN VLAN sub-interface, inject an IPv6 VRRP advert with a
  Hop-by-Hop ext-header from a host and confirm the receiver counts it
  (`RXDropStats` / journald) and the peer's IPv6 election is unaffected. If the
  injection harness is impractical, at minimum confirm normal IPv6 RETH failover
  still works (regression) and rely on the Go walk unit tests for the
  ext-header logic.
- #2156 extra: commit a VIP change to a RETH RG while flapping the member
  interface (down during apply, up shortly after) and confirm the RG never
  drops out of election and the new VIP lands within ~2s (B1 retry) — the
  "config-change-during-link-flap repro" the issue asks for.

Endurance: a 3-cycle `make test-failover` to catch any latent double-run /
goroutine-leak from the lifecycle reorder.

---

## 9. Blast radius

Touched (production):
- `pkg/vrrp/manager.go`: `openAfPacketReceiver` (cBPF), `UpdateInstances`
  (lifecycle reorder).
- `pkg/vrrp/instance.go`: `parseAfPacketIPv6` (ext-header walk).
- `pkg/daemon/daemon_ha.go`: `reconcileRGStateLoop` + new
  `reconcileVRRPInstances` (B1).

Touched (tests/docs):
- `pkg/vrrp/vrrp_test.go` (parse mirror + lifecycle test), `pkg/vrrp/README.md`,
  possibly CLAUDE.md HA note.

Untouched (verified): wire format / `packet.go` checksum, advert cadence,
election (`handleBackupRx`/`handleMasterRx`), sync-hold gate (#2082), GARP
(#2081/#2152), track.go semantics, `ResignRG`/`ForceRGMaster`/`UpdateRGPriority`,
the raw `ip6:112` fallback receiver, dataplane/Rust, config grammar.

Callers to re-verify for #2156: `RGVRRPReady` (gate truthfulness — the headline
risk), `States`, `InstanceStates`, `Status`, `RXDropStats` — all must see no new
phantom/placeholder entries under Option A (they won't; A adds no new state).

---

## 10. Risks & mitigations

- **R1 (#2155 cBPF re-numbering):** off-by-one in cBPF jump targets silently
  drops *all* IPv6 (or admits garbage). Mitigation: keep the IPv4 arm
  byte-identical; change only the IPv6 jump/accept; verify with a live
  `tcpdump`-style capture and the regression IPv6 failover smoke.
- **R2 (#2155 malicious ext-header chain):** unbounded walk = CPU DoS on the RX
  goroutine. Mitigation: hard iteration cap (≤8) + per-step bounds check; drop
  on overflow. Documented as a deliberate bound.
- **R3 (#2156 build-before-teardown leaves stale VIPs during the failure
  window):** the old instance keeps advertising old VIPs until retry.
  Mitigation: this is strictly better than today's total RG loss; document the
  window; B1 bounds it to ~2s.
- **R4 (#2156 double-run):** if the reorder accidentally starts the new
  `run()` while the old goroutine is still live for the same key. Mitigation:
  `existing.stop()` (which blocks on `<-vi.stopped`) MUST complete before
  `go vi.run()` on success; the failure path never starts a new `run()`. Unit
  test asserts exactly one goroutine per key after each transition.
- **R5 (#2156 `stop()` blocks under `m.mu`):** `existing.stop()` already blocks
  on `<-vi.stopped` while holding `m.mu` today — the reorder does not worsen
  this (it only moves the blocking call *after* the new build). No new lock
  risk; note for the reviewer that this is pre-existing behavior.
- **R6 (B1 churn):** the 2s re-drive of `UpdateInstances` must be a true no-op
  on a steady config. Mitigation: the existing no-change `continue` paths make
  it cheap; assert no log spam (state-transition logs only fire on real change).
- **R7 (scope creep):** keep each bug to its own diff; do not refactor the RX
  receivers or the lifecycle beyond the two surgical changes.

---

## 11. Recommendation summary (per bug)

- **#2155 → PLAN-READY.** Option **A2** (cBPF IPv6 arm matches base Next-Header
  against {112,0,43,60,44} so ordinary IPv6 traffic stays kernel-dropped on the
  data-bearing RETH VLAN) **+ a bounded ext-header walk** in `parseAfPacketIPv6`
  and the test mirror **+ a docs note** on the homogeneous-peer expectation and
  the explicit drop bounds (chain > 8, AH-overflow, fragmented). Use A1 (accept
  all IPv6 at the filter) only where the VLAN provably carries no IPv6 data. The
  raw `ip6:112` fallback is ext-header-safe for the common ext-headers (kernel
  walks them); AH/fragmented VRRP is out of scope on both paths. Doc-only
  (Option B) is a defensible minimum fallback if the approver wants to defer the
  walk.
- **#2156 → PLAN-READY.** Option **A** (build-before-teardown — never delete a
  working instance until its replacement is proven buildable) **+ B1** (re-drive
  `UpdateInstances` from the existing 2s `reconcileRGStateLoop` for bounded
  self-recovery). Reject **B2** (Pending placeholder) — it adds health-state
  that `RGVRRPReady` would have to learn to ignore, with no benefit over A+B1.

Both are independent PRs (or one combined PR with a single VRRP/HA smoke run).
Each MUST pass `make test-failover` before merge.
