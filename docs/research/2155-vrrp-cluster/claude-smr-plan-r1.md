# Claude SMR (hostile self-review) — plan r1 for #2155 + #2156

Reviewer posture: hostile. Companion lane (Codex/AGY) degraded → companion-free
converged review. I attack my own plan; findings are graded
BLOCKER / MAJOR / MINOR / NIT with a disposition. Verdict at the end.

---

## Verified-against-source claims (no hand-waving)

- **Only the AF_PACKET socket carries a cBPF filter.** `SO_ATTACH_FILTER` is
  attached exclusively in `openAfPacketReceiver` (`manager.go:641`). The IPv6
  send/recv fallback uses `net.ListenPacket("ip6:112")` (`manager.go:656`), a
  kernel-protocol-bound raw socket with **no** `SO_ATTACH_FILTER`. So the #2155
  ext-header drop is genuinely confined to the AF_PACKET path. ✔ (claim in §3/§5
  stands)
- **IPv4 AF_PACKET already walks IHL** (`ip[0]&0x0F)*4`, `ip[ihl:]`,
  `instance.go:733-751`) while IPv6 hardcodes 40. The asymmetry is real. ✔
- **`RGVRRPReady` returns ready if any instance exists for the VRID**, with no
  health check (`manager.go:405-423`), and it gates HA takeover
  (`daemon_ha_vip.go:49`). The "placeholder must not lie to the gate" concern is
  real and correctly steers #2156 to Option A (no new state). ✔
- **`reconcileRGStateLoop` ticks every 2s** and does NOT currently call
  `UpdateInstances` (`daemon_ha.go:461-478`, body reads `InstanceStates()` only).
  So B1 is a genuine *addition*, not a duplication. ✔
- **`existing.stop()` blocks on `<-vi.stopped` under `m.mu`** today
  (`instance.go:1361-1377`, called from `UpdateInstances` under `m.mu`). R5's
  "pre-existing, not worsened" framing is accurate. ✔

---

## Findings

### F1 (MAJOR) — Is the AF_PACKET path even the live RX path, or is #2155 dead on the cluster?
`run()` (`instance.go:432`) starts `receiverAfPacket()` whenever
`afPacketFD >= 0`, and `openSocket()` opens AF_PACKET for **every** interface
type, not just VLANs (`instance.go:150`, unconditional). So on the loss cluster
(RETH VRRP on `reth0.50`/`reth0.80` VLAN sub-interfaces) the **AF_PACKET path is
the live path** and `receiverIPv6` is only the fallback when AF_PACKET open
fails. Therefore #2155 is live, not dead. BUT — the plan must NOT claim the raw
`ip6:112` fallback "saves us in production": in production AF_PACKET is primary,
so the ext-header drop *does* bite a real deployment with an ext-header peer.
Disposition: §3 already says "AF_PACKET is the live path on the loss cluster, so
the bug is real there" — adequate, but I tightened the wording mentally: the
fallback is cold in normal operation. No plan edit required; the recommendation
(fix the AF_PACKET path) is correct precisely because it is the hot path. RESOLVED
(claim was already correct; this finding confirms severity, doesn't change it).

### F2 (MAJOR) — AH (proto 51) length unit and the "raw socket is already correct" claim.
Two sub-issues:
- (a) The plan's AH length math: AH `Payload Len` field is in **4-byte units
  minus 2** (RFC 4302), i.e. total AH length = `(PayloadLen + 2) * 4`. The plan
  states `off += (buf[off+1]+2)*4` — correct. But HBH/Routing/Dest-Opts use
  **8-byte units, `(HdrExtLen + 1) * 8`**, also stated correctly. Keep both unit
  conventions explicit in the engineer's code comments — mixing them is the
  classic ext-header-walk bug. NIT-level for the plan; flag for /engineer.
- (b) The plan claims the raw `ip6:112` fallback is "already ext-header-safe."
  This is true for HBH/Routing/Dest-Opts/Fragment (the kernel transparently
  processes those before delivering the proto-112 upper layer). It is **NOT
  guaranteed for AH** — with an AH header, the kernel's protocol demux may treat
  AH as the upper layer (proto 51) and never deliver to the proto-112 socket, or
  deliver the AH-wrapped payload. Since AH-on-VRRP is even rarer than plain
  ext-headers and the plan already DROPS AH on the AF_PACKET walk after bounds,
  the asymmetry is immaterial. Disposition: soften the README claim to "the raw
  `ip6:112` fallback is ext-header-safe for the common ext-headers (kernel walks
  them); AH/fragmented VRRP is out of scope on both paths." PLAN EDIT: tighten
  §5 step-4 / §11 wording. Severity: MAJOR only because an over-broad README
  claim would mislead a future reader. Folded into the plan's drop-bounds note.

### F3 (MAJOR) — #2156 Option A: does build-before-teardown actually avoid double-binding the socket?
Concern: the new instance opens a raw `ip4:112` socket + AF_PACKET on the same
ifindex **while the old instance's sockets are still open** (old not yet
stopped). Can two AF_PACKET sockets on the same ifindex coexist? Yes — AF_PACKET
SOCK_RAW sockets are not exclusive; multiple can bind the same ifindex (that's
how tcpdump coexists with the daemon). The raw `ip4:112` socket binds
`0.0.0.0` with `SO_BINDTODEVICE` (non-VLAN) — also non-exclusive. So
build-before-teardown does NOT hit an EADDRINUSE/EBUSY. ✔ But: for the brief
overlap window BOTH instances' receivers are live and both could `sendAdvert`
if the old one is MASTER. The old one is MASTER and keeps advertising (correct);
the new one starts in `StateInitialize`→`StateBackup` in `run()` and won't
advert until elected — and we only `go vi.run()` AFTER `existing.stop()`
completes. So there is **no** overlap of two running `run()` loops for the same
key (stop() blocks on `<-vi.stopped` before we start the new run()). The socket
overlap is only between "new sockets open" and "old stop()" — receivers, not
state machines. The new receiver feeds an rxCh whose `run()` hasn't started, so
its rxCh just buffers/drops harmlessly. RESOLVED — A is safe; the engineer must
keep the `go vi.run()` strictly after `existing.stop()`.

### F4 (MAJOR) — B1 re-drive double-frees / restarts instances every 2s?
If `reconcileVRRPInstances` recomputes the desired set and calls
`UpdateInstances` every 2s, does the VIPs-changed branch fire spuriously and
restart healthy instances (the very 3s-master-down-gap the code warns against)?
No — only if `vipsEqual` returns false, which requires a *real* VIP change. On a
steady config, every key hits the `continue` no-change path. BUT a subtle trap:
`CollectRethInstances` priority comes from `localPriority[rgID]` =
`d.cluster.LocalPriorities()`, which **changes on cluster events**. A priority
change hits the in-place `updateConfig` path (VIPs equal), NOT a restart — safe.
So B1 cannot cause a restart storm. ✔ Mitigation R6 stands. One add: B1 must NOT
run before the cluster/config is initialized (nil guards), matching the existing
loop's `if d.cluster == nil || d.vrrpMgr == nil { return }`. PLAN EDIT: note the
nil-guard in §7 step-2 for B1. Folded.

### F5 (MINOR) — #2156 Option A and the *new-key* orphan.
The plan correctly notes the new-key path's `continue`-on-error is "not yet
created" (benign) because the key was never in the map and the next
`UpdateInstances` retries. With B1, that retry is now bounded to 2s — good. But
the plan should state explicitly that A's reorder is applied to the
**VIPs-changed** branch (the acute bug) and that the new-key path benefits from
B1 without needing a reorder. §7 step-1 says "optionally apply the same shape
to the new-key path for symmetry" — fine. No edit; severity MINOR.

### F6 (MINOR) — cBPF A1 "accept all IPv6" widens the receiver's load.
Accepting all IPv6 frames at the filter means `receiverAfPacket` now sees ALL
IPv6 multicast/unicast on the segment (ND, MLD, ICMPv6, IPv6 TCP/UDP) and
discards non-112 in Go. On a busy RETH segment this is more wakeups. Counter:
(a) the IPv4 arm already does proto-matching in the filter, so A1 makes IPv4 and
IPv6 *asymmetric* in filter tightness — slightly inelegant; (b) volume: a RETH
transit/data VLAN can carry real IPv6 traffic. This is the one place A2 (the
small-allowlist cBPF: {112,0,43,60,44}) is genuinely better — it keeps ordinary
IPv6 TCP/UDP/ICMPv6 dropped in-kernel while admitting single-ext-header VRRP.
Re-weighing: A2 handles the *common* case (one ext-header) in-kernel and the Go
walk still handles whatever A2 admits; only a >1-ext-header *chain* whose first
header is NOT in the allowlist would be dropped — but the allowlist already
contains all the ext-header start types, so A2 admits any frame whose FIRST
header is an ext-header or 112, which is exactly the VRRP-with-ext-header set.
A2's only true miss is a frame starting with a non-ext, non-112 protocol — which
is never VRRP. **Re-recommendation: prefer A2 over A1 on the cluster's data
VLANs to avoid the load.** This is a genuine improvement over the plan's A1.
PLAN DISPOSITION: I am NOT silently flipping the recommendation — I record it as
a strong MINOR→MAJOR-adjacent reconsideration for the /engineer + approver:
**A2 if RETH VLANs carry IPv6 data traffic; A1 if they don't.** The loss
cluster's `reth0.80` DOES carry IPv6 data (`2001:559:8585:80::200` iperf3
target), so **A2 is the better default here.** Folding a note into the plan
recommendation. Severity: MAJOR (it changes the recommended cBPF shape on the
actual smoke target).

### F7 (MINOR) — Fragment header (44) as a hard stop is correct, but state why.
A fragmented VRRP advert means the first fragment may not contain the full VRRP
header, and reassembly in userspace is out of scope. Dropping on proto-44 is
correct (RFC 5798 adverts are small, single-packet). The plan says "drop" — add
the *why* (no userspace reassembly; VRRP adverts are never legitimately
fragmented). NIT. Folded into §5.

### F8 (NIT) — Test for cBPF.
The plan correctly says cBPF can't be unit-tested without a socket and leans on
smoke + the Go walk tests. Acceptable. An optional stronger move: a Linux-only
integration test that opens a real AF_PACKET socket on a veth, attaches the
filter, and verifies an ext-header proto-112 frame passes — but that needs
NET_RAW and a veth, heavier than CI wants. Leave to the engineer's discretion;
the smoke covers it. No edit.

### F9 (NIT) — Combined vs separate PRs.
Both bugs touch `manager.go` and `README.md`. A combined PR shares one
`make test-failover`. But #2155 is LOW/rare and #2156 is MEDIUM/operational —
different urgency. Recommend separate PRs unless the engineer wants one smoke
run; the plan already says this. No edit.

---

## Plan edits folded (from F2, F4, F6, F7)
1. §5/§11: prefer **A2** (small ext-header-start allowlist cBPF) over A1 on
   RETH VLANs that carry IPv6 data traffic (the loss cluster's `reth0.80`
   does) — A1 only when the VLAN carries no IPv6 data. Both share the same
   Go-side bounded walk.
2. §5 step-4 / README: soften the "raw `ip6:112` fallback is ext-header-safe"
   claim to "safe for the common ext-headers; AH/fragmented out of scope on both
   paths."
3. §7 B1: add the `d.cluster==nil || d.vrrpMgr==nil` nil-guard note.
4. §5: state *why* Fragment (44) is a hard drop (no userspace reassembly;
   adverts are never legitimately fragmented).

These are refinements, not reversals — the core recommendations (fix the
AF_PACKET IPv6 path with a bounded Go ext-header walk + tight cBPF; make
UpdateInstances build-before-teardown + 2s reconcile re-drive) survive hostile
review intact.

---

## PLAN-KILL assessment
- **#2156:** NOT a kill. Clear MEDIUM correctness bug, small atomic fix,
  reuses existing recovery loop. SHIP.
- **#2155:** NOT a kill, but the *closest* candidate (LOW + rare trigger +
  xpf never emits ext-headers). The fix is small and bounded and closes a real
  IPv4/IPv6 asymmetry, so doc-only is a fallback, not the recommendation. If the
  approver deems the ext-header peer scenario out of the threat model, doc-only
  (Option B) is acceptable and would close the issue as plan-deferred-lab.

## Verdict
**PLAN-READY for both bugs**, with the four folded refinements. No companion
round available (lane degraded); this SMR is the convergence gate. The
recommended cBPF shape for #2155 on the smoke target is **A2** (post-SMR), with
A1 as the simpler alternative where IPv6 data traffic is absent.
