package vrrp

import (
	"encoding/binary"
	"log/slog"
	"net"
	"runtime"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// minGARPInterval is the minimum spacing between GARP bursts (dampening).
const minGARPInterval = 500 * time.Millisecond

// garpDampened reports whether a GARP burst should be suppressed given the
// wall-clock UnixNano of the previous burst and of now. A negative elapsed
// (backward wall-clock step — time.Unix(0, last) carries no monotonic
// reading) is treated as send-allowed: dampening for the step duration would
// suppress failover GARP bursts and blackhole traffic right after becoming
// MASTER (#1792). The storage stays wall-clock; the clamp alone closes the
// hazard, and an extra GARP burst after a forward step is harmless.
func garpDampened(lastNanos, nowNanos int64) bool {
	if lastNanos <= 0 {
		return false
	}
	elapsed := time.Duration(nowNanos - lastNanos)
	return elapsed >= 0 && elapsed < minGARPInterval
}

// garpSendAllowed reports whether sendGARP should proceed to emit a burst,
// given the current epoch state and whether the caller requested a forced
// send. It centralises the two suppression gates so the decision can be
// unit-tested without performing real network I/O:
//
//   - Epoch dedup: skip if a GARP for the current garpEpoch was already
//     completed (lastGARPEpoch == garpEpoch, epoch > 0). This applies to
//     BOTH forced and non-forced sends — a forced caller is expected to bump
//     garpEpoch first (see ReconcileVIPs/becomeMaster), so the dedup only
//     suppresses a genuine duplicate for the same transition, never the
//     intended forced send.
//   - Time dampener: skip if the previous burst was < minGARPInterval ago
//     (garpDampened). This applies to the NORMAL (force == false) path only
//     while the node remains in the same ownership tenure. If it relinquished
//     mastership since that burst, a peer may have changed neighbor bindings,
//     so a rapid failback must announce again. A forced send BYPASSES the
//     dampener: ReconcileVIPs runs after programRethMAC changed the RETH
//     virtual MAC, so peers hold a stale ARP entry and the post-MAC-change
//     GARP is critical even if a routine GARP happened within 500ms (#2081).
//
// The two-argument seam is used by focused tests; sendGARP passes its captured
// owner generation to the internal decision so a concurrent transition cannot
// make a prior-tenure GARP look like a burst from the new tenure.
func (vi *vrrpInstance) garpSendAllowed(force bool, nowNanos int64) bool {
	return vi.garpSendAllowedForOwner(force, nowNanos, vi.ownerGen.Load())
}

func (vi *vrrpInstance) garpSendAllowedForOwner(force bool, nowNanos int64, ownerGen uint64) bool {
	epoch := vi.garpEpoch.Load()
	if vi.lastGARPEpoch.Load() == epoch && epoch > 0 {
		slog.Debug("vrrp: GARP already sent for this epoch",
			"key", vi.key(), "epoch", epoch)
		return false
	}
	if force {
		// Forced sends (post-MAC-change reconcile via ReconcileVIPs) bypass
		// the time dampener — the dampener exists only to rate-limit routine
		// GARP and must never suppress a MAC-change correction (#2081).
		return true
	}
	if last := vi.lastGARPTime.Load(); garpDampened(last, nowNanos) &&
		vi.lastGARPOwnerGen.Load() == ownerGen {
		slog.Debug("vrrp: GARP dampened (too soon)",
			"key", vi.key(), "elapsed", time.Duration(nowNanos-last))
		return false
	}
	return true
}

// arpProbeFn is the gateway ARP-probe sender used by sendGARP. It is a
// package var so tests can capture the sender/target sendGARP passes,
// proving the probe carries the VIP (not the interface primary) as the ARP
// sender (#2152) without performing real AF_PACKET I/O.
var arpProbeFn = cluster.SendARPProbe

// garpBurstFn / naBurstFn are the IPv4 gratuitous-ARP / IPv6 unsolicited-NA
// burst senders used by sendGARP. They are package vars so tests can capture
// the burst COUNT sendGARP passes, proving the #5695 runtime clamp bounds the
// effective per-VIP burst budget without performing real AF_PACKET I/O.
var (
	garpBurstFn = cluster.SendGratuitousARPBurstGated
	naBurstFn   = cluster.SendGratuitousIPv6BurstGated
)

// GatewayProbeTarget computes the supplementary gateway-probe target for an
// IPv4 VIP subnet: the first usable host address (network address + 1), which
// is the most common gateway address. The second return value reports whether
// a sensible target exists; when it is false the caller MUST skip the
// supplementary targeted probe (the broadcast GARP burst in
// SendGratuitousARPBurst always fires regardless and remains the primary
// mechanism).
//
// It returns ok=false when no usable network+1 host exists inside the subnet:
//   - non-IPv4 ipNet (defensive; the caller invokes this only on the v4 path)
//   - /32 host route — the VIP is the only address, there is no gateway host
//   - /31 RFC 3021 point-to-point — no network/broadcast, no ".1" host; the
//     peer is reachable via the broadcast GARP burst, so skip the directed
//     probe rather than emit one to a synthesized address
//
// Pre-#2377 the target was computed by forcing the network address's last
// octet to .1 (gwIP[3] = 1). That only lands inside the subnet for /24 or
// shorter: for a longer subnet whose network address does not end in .0 (e.g.
// VIP 10.0.61.18/28, network 10.0.61.16) the forced .1 (10.0.61.1) falls
// OUTSIDE the subnet (.16-.31) and the probe went to a foreign address.
// Computing network+1 from the masked CIDR keeps the target inside the subnet
// for every prefix length.
//
// Exported as the single source of truth for the gateway-probe target so the
// daemon's direct-mode (private-rg-election / no-reth-vrrp) GARP path in
// pkg/daemon reuses the identical derivation instead of re-deriving the
// forced-.1 target that #2377 removed here (#3922).
func GatewayProbeTarget(ipNet *net.IPNet) (net.IP, bool) {
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil, false
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, false
	}
	// /31 and /32 have no usable network+1 host inside the subnet.
	if ones >= 31 {
		return nil, false
	}
	// ipNet.IP is the masked network address (net.ParseCIDR), so +1 is the
	// first usable host regardless of the original last octet.
	netVal := binary.BigEndian.Uint32(ip4)
	gwIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(gwIP, netVal+1)
	return gwIP, true
}

// sendGARP sends gratuitous ARP (IPv4) and unsolicited NA (IPv6) for all VIPs.
// Uses burst mode: one immediate pair then background follow-ups at 50ms intervals.
// After each IPv4 GARP burst, also sends a standard ARP probe to the subnet's
// first usable host (network address + 1), the most common gateway address
// (see GatewayProbeTarget; skipped on /31 and /32). Some routers ignore
// gratuitous ARP but always update their ARP cache when they receive a
// standard ARP Request with the VIP as the source address.
//
// force bypasses the 500ms time dampener (but not the per-epoch dedup) so a
// post-MAC-change reconcile GARP is always emitted. A normal send also bypasses
// dampening when it follows a completed MASTER tenure that has since ended;
// neighbors may have learned the peer's MAC while this node was BACKUP.
//
func (vi *vrrpInstance) sendGARP(force bool) {
	vi.vipMu.Lock()
	vips := vi.vipsSnapshot()
	epoch := vi.garpEpoch.Load()
	ownerGen := vi.ownerGen.Load()
	count, ok := vi.reserveGARPBurstLocked(vips, epoch, ownerGen, force)
	vi.vipMu.Unlock()
	if ok {
		vi.sendGARPReserved(vips, epoch, ownerGen, count)
	}
}

// addPendingGARPVIPsLocked records canonical VIP identities whose synchronous
// initial frame has not yet been confirmed. Canonical keys let an in-flight
// sender clear its entry after a spelling-only update. The caller holds vipMu.
func (vi *vrrpInstance) addPendingGARPVIPsLocked(vips []string) {
	if len(vips) == 0 {
		return
	}
	if vi.pendingGARPVIPs == nil {
		vi.pendingGARPVIPs = make(map[string]struct{}, len(vips))
	}
	for _, vip := range vips {
		vi.pendingGARPVIPs[canonicalVIPIdentity(vip)] = struct{}{}
	}
}

// markGARPAnnouncedLocked clears one canonical VIP identity after its
// synchronous first frame succeeds while its captured ownership and membership
// token is still current. The caller holds vipMu.
func (vi *vrrpInstance) markGARPAnnouncedLocked(vip string) {
	delete(vi.pendingGARPVIPs, canonicalVIPIdentity(vip))
	if len(vi.pendingGARPVIPs) == 0 {
		vi.pendingGARPVIPs = nil
	}
}

// pendingGARPForSetLocked drops no-longer-current canonical identities,
// retains current unannounced ones, and optionally adds successful new VIPs.
// The result renders current-set spellings in order for the next bounded send
// pass. The caller holds vipMu.
func (vi *vrrpInstance) pendingGARPForSetLocked(current, added []string, includeAdded bool) []string {
	if len(vi.pendingGARPVIPs) == 0 && (!includeAdded || len(added) == 0) {
		vi.pendingGARPVIPs = nil
		return nil
	}
	next := make(map[string]struct{}, len(vi.pendingGARPVIPs)+len(added))
	for _, vip := range current {
		id := canonicalVIPIdentity(vip)
		if _, pending := vi.pendingGARPVIPs[id]; pending {
			next[id] = struct{}{}
		}
	}
	if includeAdded {
		for _, vip := range added {
			next[canonicalVIPIdentity(vip)] = struct{}{}
		}
	}
	if len(next) == 0 {
		vi.pendingGARPVIPs = nil
		return nil
	}
	vi.pendingGARPVIPs = next
	announcements := make([]string, 0, len(next))
	for _, vip := range current {
		if _, pending := next[canonicalVIPIdentity(vip)]; pending {
			announcements = append(announcements, vip)
		}
	}
	return announcements
}

// sendGARPFor emits a burst for a stable VIP snapshot and its captured epochs.
// It validates each VIP under vipMu and holds the lock only through that VIP's
// synchronous first frame and optional gateway probe. A concurrent withdrawal
// can therefore fence the remaining snapshot after one VIP instead of waiting
// for a potentially large whole-set burst. Unsent current VIPs are tracked
// under vipMu so an update can carry surviving work into the new epoch.
// Pure-add commits without an interrupted send still announce only new VIPs.
func (vi *vrrpInstance) sendGARPFor(vips []string, epoch, ownerGen uint64, force bool) {
	vi.vipMu.Lock()
	count, ok := vi.reserveGARPBurstLocked(vips, epoch, ownerGen, force)
	vi.vipMu.Unlock()
	if !ok {
		return
	}
	vi.sendGARPReserved(vips, epoch, ownerGen, count)
}

// reserveGARPBurstLocked validates and reserves one burst before callers drop
// vipMu. The caller holds vipMu, including the full-set snapshot path, so a
// membership update cannot invalidate a snapshot before its pending VIPs are
// recorded.
func (vi *vrrpInstance) reserveGARPBurstLocked(vips []string, epoch, ownerGen uint64, force bool) (int, bool) {
	if vi.getState() != StateMaster ||
		vi.ownerGen.Load() != ownerGen ||
		vi.garpEpoch.Load() != epoch ||
		!vi.garpSendAllowedForOwner(force, time.Now().UnixNano(), ownerGen) {
		return 0, false
	}
	// #8597 (muse-004 K20): under vi.mu — updateConfig writes this field on the
	// manager goroutine while sendGARP runs on the run loop, on detached
	// `go vi.sendGARP` goroutines, AND synchronously from ReconcileVIPs.
	count := vi.garpCount()
	if count <= 0 {
		count = 3 // default
	} else if clamped, was := config.ClampGratuitousARPCount(count); was {
		// #5695 (codex-182 M16): an unbounded configured count fans the full
		// per-VIP burst (1 immediate frame + (count-1) 50ms follow-ups) on
		// every failover — a self-inflicted CPU/socket-exhaustion vector.
		// Clamp to the runtime safety maximum. Warn at most ONCE per instance
		// (never per-send: sendGARP runs on the per-failover path — logging
		// rules forbid a Warn inside it).
		if vi.garpClampWarned.CompareAndSwap(false, true) {
			slog.Warn("vrrp: gratuitous-arp-count clamped to runtime safety maximum",
				"key", vi.key(), "configured", count, "clamped", clamped,
				"max", config.GratuitousARPBurstClamp)
		}
		count = clamped
	}
	// Reserve this epoch before releasing vipMu. Per-VIP lock handoffs would
	// otherwise let a duplicate same-epoch send begin before this burst stores
	// lastGARPEpoch at completion.
	vi.lastGARPOwnerGen.Store(ownerGen)
	vi.lastGARPEpoch.Store(epoch)
	vi.addPendingGARPVIPsLocked(vips)
	return count, true
}

func (vi *vrrpInstance) sendGARPReserved(vips []string, epoch, ownerGen uint64, count int) {
	stillMaster := func() bool {
		return vi.getState() == StateMaster &&
			vi.ownerGen.Load() == ownerGen &&
			vi.garpEpoch.Load() == epoch
	}
	for _, vip := range vips {
		vi.vipMu.Lock()
		if vi.getState() != StateMaster ||
			vi.ownerGen.Load() != ownerGen ||
			vi.garpEpoch.Load() != epoch {
			vi.vipMu.Unlock()
			return
		}
		ip, ipNet, err := net.ParseCIDR(vip)
		if err != nil {
			vi.vipMu.Unlock()
			continue
		}
		announced := false
		if ip.To4() != nil {
			if err := garpBurstFn(vi.cfg.Interface, ip, count, stillMaster); err != nil {
				slog.Warn("vrrp: GARP failed", "key", vi.key(), "vip", ip, "err", err)
			} else {
				announced = true
			}
			// Probe the first usable host (network address + 1) of the
			// VIP subnet — this is the most common gateway address. The
			// ARP Request's source IP/MAC forces the gateway to update its
			// ARP cache for the VIP. GatewayProbeTarget returns ok=false on
			// /31 and /32, where no in-subnet gateway host exists; the
			// broadcast GARP burst above still fires (#2377).
			gwIP, ok := GatewayProbeTarget(ipNet)
			if ok && !gwIP.Equal(ip.To4()) {
				// Send the probe with the VIP as the ARP sender so the
				// gateway re-binds VIP to our (new) MAC, not the primary IP (#2152).
				if err := arpProbeFn(vi.cfg.Interface, ip.To4(), gwIP); err != nil {
					slog.Warn("vrrp: gateway ARP probe failed",
						"key", vi.key(), "gw", gwIP, "err", err)
				} else {
					slog.Info("vrrp: probed subnet gateway",
						"key", vi.key(), "gw", gwIP, "interface", vi.cfg.Interface)
				}
			}
		} else {
			if err := naBurstFn(vi.cfg.Interface, ip, count, stillMaster); err != nil {
				slog.Warn("vrrp: NA failed", "key", vi.key(), "vip", ip, "err", err)
			} else {
				announced = true
			}
		}
		if announced && stillMaster() {
			vi.markGARPAnnouncedLocked(vip)
		}
		vi.vipMu.Unlock()
		// Give a waiting membership update or demotion a chance to acquire
		// vipMu before this sender starts the next VIP.
		runtime.Gosched()
	}
	vi.lastGARPTime.Store(time.Now().UnixNano())
}
