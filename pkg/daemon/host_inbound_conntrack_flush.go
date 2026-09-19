package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5566: stale kernel host-inbound authorization on a coarse tightening.
//
// The xpf_hostinbound kernel chain leads with `ct state established,related
// accept` (buildHostInboundFilterPayload), which precedes every per-zone coarse
// host-inbound catch-all DROP. Replacing the xpf_hostinbound table does NOT flush
// Linux netfilter conntrack, so a direct-kernel host connection admitted under a
// LOOSER prior config (e.g. an SSH/HTTPS/SNMP session) keeps riding that leading
// established-accept after the operator REMOVES the service — the new per-zone
// drop never sees the flow's original-direction packets. That is a host-inbound
// false-allow limited to the direct-kernel delivery path: the Rust userspace
// local-delivery path already re-checks the effective host-inbound set on every
// session hit and tears a now-denied session down
// (userspace-dp/src/afxdp/poll_descriptor/mod.rs), but the kernel path had no
// equivalent teardown.
//
// The fix reconciles kernel conntrack against the JUST-APPLIED host-inbound set
// after every successful real apply: any established/related kernel conntrack
// entry whose ORIGINAL-direction destination is a firewall-local host-inbound
// address under a default-deny AND whose (proto, dport) is NOT admitted by the
// CURRENT coarse host-inbound set is deleted, so the next original-direction
// packet is re-evaluated against the new rules (and dropped by the per-zone
// catch-all) instead of short-circuiting on the established-accept. This mirrors
// the Rust per-hit re-eval/teardown. Because the flush condition is "not admitted
// by the CURRENT config", a still-permitted service's connections are never
// flushed — a reconcile, not an edge-triggered delta, so it is regression-safe on
// loosening and no-op commits and needs no persisted prior-config snapshot.
//
// Only firewall-local addresses that carry a catch-all DROP are eligible (the
// covered set). Management / cluster-control lifeline INTERFACES (fxp0 / em0 /
// fab*) are excluded from the host-inbound views by BuildZoneHostInboundViews, so
// an address reachable ONLY through a lifeline is never in the covered set and its
// conntrack is never flushed. That exclusion is by INTERFACE, not by address
// VALUE. A management address ALSO configured on a non-lifeline interface IS in
// the covered set: shared onto a zone that ADMITS the service it keeps that
// service's admit tuple and its established sessions are preserved, but shared
// onto an UNZONED interface (#4420) or a zone with NO host-inbound-traffic stanza
// (#3405) it is recorded with an EMPTY admit set and every established entry to it
// — including a live operator SSH session — is flushed. So this reconcile CAN tear
// down management on those topologies, and the "already-established sessions
// survive" mitigation for the #6492 fence window does not hold there. See
// docs/host-inbound-service-matrix.md, "Lifeline exclusion is by INTERFACE, not by
// address value". Kernel netfilter conntrack on
// this appliance tracks only host-terminated / kernel-forwarded flows (transit
// forwarding runs through userspace-dp's own session table, not netfilter
// conntrack), so the table swept here is small.

// conntrackDeleteFilters is the netfilter-conntrack delete seam. It deletes every
// entry in the main conntrack table (both families are queried by the caller)
// that matches any supplied filter. A package var so the #5566 reconcile is
// unit-testable without a live kernel conntrack subsystem (mirrors the
// nftApplyPayload seam).
var conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	return netlink.ConntrackDeleteFilters(netlink.ConntrackTable, family, filters...)
}

// hostInboundAdmit records the CURRENT coarse host-inbound admit set for one
// firewall-local destination address, unioned across every zone view whose
// address set contains it (an address reachable from >1 zone is admitted if ANY
// of those zones admits — matching the nft chain, which emits a per-zone accept
// keyed on destination address only). An address present in the covered set with
// an otherwise-empty admit (e.g. an addressed-but-unzoned interface, #4420) is
// fully denied except for the global exemptions handled in MatchConntrackFlow.
type hostInboundAdmit struct {
	allowsAll bool               // `system-services all` / any-service → keep everything
	tcp       []config.PortRange // admitted TCP destination ports
	udp       []config.PortRange // admitted UDP destination ports
	protos    map[uint8]bool     // admitted bare IP protocols (e.g. gre=47)
}

// add folds one structured host-inbound admit tuple (the #3627 B1a SSOT
// config.L4Match) into the address's admit set. ICMP/ICMPv6 admits are NOT
// recorded here: ND/PMTUD/error subtypes are globally accepted and echo-request
// conntrack is short-lived, so ICMP is never flushed (MatchConntrackFlow returns
// early for it). The ident-reset marker (Reject) does not admit TCP/113 — it
// RESETS it — so it is skipped (a stale tcp/113 entry is therefore flushable).
func (a *hostInboundAdmit) add(m config.L4Match) {
	if m.Reject {
		return
	}
	switch m.Proto {
	case config.HostInboundProtoTCP:
		a.tcp = append(a.tcp, m.Ports...)
	case config.HostInboundProtoUDP:
		a.udp = append(a.udp, m.Ports...)
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		// globally accepted / short-lived — not tracked for flushing.
	default:
		if a.protos == nil {
			a.protos = map[uint8]bool{}
		}
		a.protos[m.Proto] = true
	}
}

// hostInboundConntrackFlushFilter is the netlink CustomConntrackFilter that
// selects now-denied host-inbound kernel conntrack entries for deletion (#5566).
// It matches a flow iff the flow's ORIGINAL-direction destination is a covered
// firewall-local host-inbound address AND the flow's (proto, dport) is not
// admitted by the current coarse host-inbound set for that address and is not a
// global exemption (ESP/AH, ICMP ND/PMTUD, the WireGuard listen port).
type hostInboundConntrackFlushFilter struct {
	admit   map[netip.Addr]*hostInboundAdmit
	wgPorts []uint16
}

// MatchConntrackFlow reports whether the flow is a now-denied host-inbound entry
// to flush. It is deliberately conservative — it returns false (keep) for any
// flow it cannot prove is denied — so it can never delete a permitted or
// non-host-inbound flow.
func (f *hostInboundConntrackFlushFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil {
		return false
	}
	// Original-direction destination = the firewall-local address the remote
	// client connected to. Transit / host-originated flows have a non-local
	// original destination and so are never in the covered admit map.
	dst, ok := netip.AddrFromSlice(flow.Forward.DstIP)
	if !ok {
		return false
	}
	a := f.admit[dst.Unmap()]
	if a == nil {
		// Not a covered host-inbound deny address (includes every lifeline /
		// fully-permitted / non-local destination) — never flush.
		return false
	}
	if a.allowsAll {
		// Zone opened to all services (`system-services all`) — keep everything.
		// buildHostInboundConntrackFlushFilter already drops allows-all addresses
		// from the covered map, so this is a defensive guard that keeps the matcher
		// correct if that exclusion is ever changed.
		return false
	}
	proto := flow.Forward.Protocol
	switch proto {
	case 50, 51:
		// Raw ESP / AH: globally exempt (host-terminated IPsec is decrypted by the
		// kernel XFRM stack before any host-inbound deny) — mirror the chain accept.
		return false
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		// ND / PMTUD / ICMP-error are globally accepted and echo conntrack is
		// short-lived — never flush ICMP.
		return false
	case config.HostInboundProtoTCP:
		if portInRanges(flow.Forward.DstPort, a.tcp) {
			return false
		}
	case config.HostInboundProtoUDP:
		if f.isWireGuardPort(flow.Forward.DstPort) {
			return false
		}
		if portInRanges(flow.Forward.DstPort, a.udp) {
			return false
		}
	default:
		if a.protos[proto] {
			return false
		}
	}
	// Covered address, current config does not admit this (proto, dport), and it is
	// not a global exemption → the entry rides the leading established-accept under
	// stale authorization. Flush it so the next packet is re-evaluated.
	return true
}

// isWireGuardPort reports whether the destination UDP port is a configured
// WireGuard listen port, which the host-inbound chain admits globally (#5582) so
// the shim-steered outer transport reaches the kernel WG socket.
func (f *hostInboundConntrackFlushFilter) isWireGuardPort(port uint16) bool {
	for _, p := range f.wgPorts {
		if p == port {
			return true
		}
	}
	return false
}

// portInRanges reports whether port falls in any inclusive PortRange.
func portInRanges(port uint16, ranges []config.PortRange) bool {
	for _, r := range ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// buildHostInboundConntrackFlushFilter assembles the #5566 flush filter from the
// SAME structured host-inbound SSOT the nft chain renders from
// (config.HostInboundServiceMatch / HostInboundProtocolMatch), so the flush's
// admit decision cannot drift from the kernel chain's per-zone accepts. Returns
// nil when there is no covered firewall-local address (nothing to reconcile).
func buildHostInboundConntrackFlushFilter(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) *hostInboundConntrackFlushFilter {
	admit := map[netip.Addr]*hostInboundAdmit{}
	ensure := func(addr string) *hostInboundAdmit {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return nil
		}
		key := ip.Unmap()
		e := admit[key]
		if e == nil {
			e = &hostInboundAdmit{}
			admit[key] = e
		}
		return e
	}
	addFamily := func(v dpuserspace.ZoneHostInboundView, family string, addrs []string) {
		allowsAll := hostInboundAllowsAll(v)
		for _, addr := range addrs {
			e := ensure(addr)
			if e == nil {
				continue
			}
			if allowsAll {
				e.allowsAll = true
				continue
			}
			for _, svc := range v.SystemServices {
				for _, m := range config.HostInboundServiceMatch(svc, family) {
					e.add(m)
				}
			}
			for _, proto := range v.Protocols {
				for _, m := range config.HostInboundProtocolMatch(proto, family) {
					e.add(m)
				}
			}
		}
	}
	for _, v := range views {
		addFamily(v, "ip", v.V4Addrs)
		addFamily(v, "ip6", v.V6Addrs)
	}
	// #4420 HI-2: addressed-but-unzoned firewall-local addresses carry a catch-all
	// DROP with no service accepts — fully denied except the global exemptions, so
	// record them with an empty admit set.
	for _, addr := range unzonedV4 {
		ensure(addr)
	}
	for _, addr := range unzonedV6 {
		ensure(addr)
	}
	// An address reachable from an `all` / any-service zone gets a bare
	// `daddr <addr> accept` in the nft chain (no catch-all DROP), so every flow to
	// it is admitted — it is not "covered" by a default-deny and must never be
	// flushed even if a DIFFERENT zone view also names it (union: allows-all wins,
	// mirroring the chain's accept rule). Drop those entries so the covered set
	// equals the addresses that actually carry a default-deny.
	for addr, a := range admit {
		if a.allowsAll {
			delete(admit, addr)
		}
	}
	if len(admit) == 0 {
		return nil
	}
	return &hostInboundConntrackFlushFilter{admit: admit, wgPorts: wgListenPorts}
}

// flushDeniedHostInboundConntrack reconciles Linux netfilter conntrack against
// the just-applied host-inbound set (#5566): it deletes every established/related
// kernel conntrack entry whose original-direction destination is a covered
// firewall-local host-inbound address that the CURRENT coarse rules no longer
// admit, so a service removed from a zone can no longer leave an existing
// direct-kernel connection authorized under the old config via the chain's
// leading `ct state established,related accept`.
//
// Best effort: the nft host-inbound table is already applied, so enforcement for
// NEW connections holds regardless. A conntrack flush failure only leaves
// PRE-EXISTING flows on their old authorization (the pre-fix behavior), so it is
// logged rather than surfaced as a commit failure — failing the commit would roll
// back correct enforcement over a transient conntrack-subsystem error.
// #6802: it returns whether every family's delete SUCCEEDED. A failure is still
// not a commit failure — the rationale above is sound and unchanged — but before
// #6802 it was not anything else either: no return value, no dirty flag, no
// counter, no metric, and no periodic reconcile re-ran it. Every ticker under
// pkg/daemon was enumerated and none re-drives applyConfig,
// applyHostInboundFilter or this flush, so the only re-attempt was the next
// externally-triggered apply — itself gated on InstallHostInbound succeeding.
//
// The failure direction is what makes that a defect rather than a tradeoff: the
// stale entry rides the chain's leading `ct state established,related accept`,
// so a now-DENIED host-inbound flow keeps working. It fails OPEN, and it stayed
// open until the flow closed or timed out.
//
// The caller records the outcome as retry DEBT and an always-on owner re-drives
// it (hostInboundConntrackReassertLoop), which is the same shape #6793 used for
// a dead RA sender: surface the failure, keep the state a retry needs, and let a
// cheap always-on gate re-drive it.
func (d *Daemon) flushDeniedHostInboundConntrack(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) bool {
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, wgListenPorts)
	if filter == nil {
		return true
	}
	var flushed uint
	ok := true
	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		n, err := conntrackDeleteFilters(family, filter)
		if err != nil {
			slog.Warn("host-inbound conntrack reconcile failed: existing direct-kernel connections to a now-denied host service may retain OLD authorization until they close or time out",
				"family", family, "err", err)
			// Keep going: the OTHER family's stale entries are independent and
			// still worth flushing. `continue` here is deliberate, not a
			// swallow — the failure is carried out in the return value.
			ok = false
			continue
		}
		flushed += n
	}
	if flushed > 0 {
		slog.Info("host-inbound conntrack reconcile: flushed now-denied kernel conntrack entries so stale direct-kernel host connections are re-evaluated against the current host-inbound set",
			"flushed", flushed)
	}
	return ok
}

// hostInboundConntrackFlushRequest is the exact desired set a flush was called
// with (#6802). The retry owner re-drives THIS, not a freshly-derived set: a
// retry that re-derived the set from the current config would silently attempt a
// different revocation than the one that failed, and the two differ exactly when
// a commit landed in between — which is when getting it wrong matters most.
type hostInboundConntrackFlushRequest struct {
	views         []dpuserspace.ZoneHostInboundView
	unzonedV4     []string
	unzonedV6     []string
	wgListenPorts []uint16
}

// noteHostInboundConntrackFlush records the outcome of a revocation attempt
// (#6802): on failure it retains the request as retry debt and counts it; on
// success it clears any debt, because a later successful flush over the CURRENT
// desired set has already revoked everything an older failed one would have.
//
// Clearing on success is safe for that reason and not merely convenient: the
// filter is built from the desired set, and a superset revocation subsumes an
// earlier one. Retaining stale debt after a good flush would make the owner
// re-drive a revocation whose target no longer exists.
func (d *Daemon) noteHostInboundConntrackFlush(req hostInboundConntrackFlushRequest, ok bool) {
	if ok {
		d.hostInboundConntrackDebt.Store(nil)
		return
	}
	d.hostInboundConntrackFlushFailures.Add(1)
	r := req
	d.hostInboundConntrackDebt.Store(&r)
	slog.Warn("host-inbound conntrack revocation failed; retaining retry debt " +
		"so an always-on owner re-drives it — until it succeeds, a now-denied " +
		"host-inbound flow may still be authorized by the chain's leading " +
		"established/related accept (#6802)")
}

// hostInboundConntrackReassertInterval is the cadence of the #6802 retry owner.
// A stale entry means a denied service is still reachable, so recovery wants to
// be prompt; but the retry is a conntrack dump+delete, so it must not run at the
// 2s cadence of the cluster reconcile. 30s matches proxyARPReassertInterval and
// raDeadSenderReassertInterval, the other always-on self-heal loops.
var hostInboundConntrackReassertInterval = 30 * time.Second

// hostInboundConntrackReassertLoop is the retry owner a failed revocation did
// not have (#6802).
//
// Every ticker under pkg/daemon was enumerated when this issue was measured —
// DDNS, RPM, HA fabric, HA, IPsec rebind, DHCP lease sync, neighbor, proxy-ARP,
// archive, kernel self-recover — and NONE re-runs applyConfig,
// applyHostInboundFilter or the flush. So the only re-attempt was the next
// externally-triggered apply, itself gated on InstallHostInbound succeeding.
//
// Always-on and mode-agnostic, mirroring proxyARPReassertLoop: free on the
// common path because the gate is a single atomic pointer load, so it costs
// nothing on a node whose revocations have all succeeded.
func (d *Daemon) hostInboundConntrackReassertLoop(ctx context.Context) {
	t := time.NewTicker(hostInboundConntrackReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.retryHostInboundConntrackFlushOnce(ctx)
			d.retryHostInputFenceConntrackFlushOnce(ctx)
		}
	}
}

// retryHostInboundConntrackFlushOnce re-drives one owed revocation.
//
// It takes applySem before acting, for the #4001 reason the proxy-ARP loop
// gives: an apply may be mid-flight, and re-driving a revocation against a
// half-applied host-inbound set could revoke flows the in-flight apply is about
// to re-admit. The debt is re-read INSIDE the semaphore because the commit this
// tick queued behind may already have flushed successfully and cleared it —
// re-driving then would be a conntrack dump for nothing.
func (d *Daemon) retryHostInboundConntrackFlushOnce(ctx context.Context) {
	if d.hostInboundConntrackDebt.Load() == nil {
		return
	}
	if d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	req := d.hostInboundConntrackDebt.Load()
	if req == nil {
		return
	}
	slog.Info("host-inbound conntrack revocation: re-driving a failed flush (#6802)")
	ok := d.flushDeniedHostInboundConntrack(req.views, req.unzonedV4, req.unzonedV6, req.wgListenPorts)
	d.noteHostInboundConntrackFlush(*req, ok)
}

// HostInboundConntrackFlushFailures reports the #6802 revocation failure count
// for the metrics collector.
func (d *Daemon) HostInboundConntrackFlushFailures() uint64 {
	return d.hostInboundConntrackFlushFailures.Load()
}

// HostInboundConntrackRevocationOwed reports whether a revocation is still owed
// (#6802) — the operator-facing form of "a now-denied host-inbound flow may
// still be authorized".
func (d *Daemon) HostInboundConntrackRevocationOwed() bool {
	return d.hostInboundConntrackDebt.Load() != nil
}
