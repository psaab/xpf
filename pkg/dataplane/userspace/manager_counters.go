package userspace

// Counter bridging for the userspace dataplane: aggregates the helper's
// per-binding counters from a status poll and pushes the deltas into the BPF
// global-counter / NAT-rule / per-zone offset maps the CLI, gRPC, REST and
// Prometheus read surfaces already consume.

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/dataplane"
)

type userspaceCounterSnapshot struct {
	rxPackets         uint64
	txPackets         uint64
	forwardPackets    uint64
	sessionCreates    uint64
	sessionExpires    uint64
	policyDenied      uint64
	hostInboundDenied uint64
	unknownVLANDrops  uint64
	dstMACDrops       uint64
	screenDrops       uint64
	// #3343: per-screen-reason drop tallies, indexed by the
	// dataplane.ScreenReasonCounters ordinal. Summed across bindings and pushed
	// into each reason's GlobalCtrScreen* counter so the per-reason
	// screen-statistics surfaces are no longer stuck at 0.
	screenReasonDrops [dataplane.ScreenReasonDropCount]uint64
	synCookieSent     uint64
	synCookieValid    uint64
	synCookieInvalid  uint64
	synCookieBypass   uint64
	snatPackets       uint64
	dnatPackets       uint64
	nat64Translations uint64
	// #4477: source-NAT allocation failures, summed across bindings. Pushed
	// into dataplane.GlobalCtrNATAllocFail; also a term of the aggregate
	// "Packets dropped" total pushed into dataplane.GlobalCtrDrops.
	natAllocFail uint64
}

// totalDrops (#4477) is the aggregate "Packets dropped" figure surfaced by
// GlobalCtrDrops. It sums the firewall's ENFORCEMENT drops — policy denies,
// screen/IDS drops, host-inbound admission denies, unknown-VLAN rejects,
// destination-MAC rejects, and source-NAT allocation failures. These are
// exactly the six breakdown lines rendered beneath "Packets dropped" in
// `show security flow statistics`, so the aggregate equals the sum of its parts
// (a total-with-breakdown, not a double count into any single reason's own
// index). Before #4477 GlobalCtrDrops
// was never written and printed a false, always-0 value.
//
// #4508: this is ENFORCEMENT drops only, NOT the literal total of every packet
// the dataplane discards. Deliberately EXCLUDED (counted elsewhere or not
// folded here), so "Packets dropped" UNDERCOUNTS total discards:
//   - no-route / missing-neighbor drops — bumped as route_miss_packets /
//     neighbor_miss_packets and surfaced separately as "Route misses:" in the
//     helper status (see pkg/dataplane/userspace/format/status.go);
//   - fabric-forwarding drops (dataplane.GlobalCtrFabricFwdDrop, idx 32);
//   - VLAN-push failures (dataplane.GlobalCtrVlanPushFail, idx 40);
//   - UMEM slice drops, which have no GlobalCtrDrops contribution;
//   - NAT64 fail-closed drops (distinct from source-NAT alloc failure).
//
// If a true total is ever wanted, extend this sum to include those indices —
// but keep the display label verbatim for vSRX parity. Doc: the "Packets
// dropped" scope caveat in docs/junos-cli-reference.md.
func (s userspaceCounterSnapshot) totalDrops() uint64 {
	return s.policyDenied + s.screenDrops + s.hostInboundDenied +
		s.unknownVLANDrops + s.dstMACDrops + s.natAllocFail
}

// sumBindingCounters aggregates counters across all bindings in a status response.
func sumBindingCounters(status *ProcessStatus) userspaceCounterSnapshot {
	var s userspaceCounterSnapshot
	for i := range status.Bindings {
		b := &status.Bindings[i]
		s.rxPackets += b.RXPackets
		s.txPackets += b.TXPackets
		s.forwardPackets += b.ForwardCandidatePkts
		s.sessionCreates += b.SessionCreates
		s.sessionExpires += b.SessionExpires
		s.policyDenied += b.PolicyDeniedPackets
		s.hostInboundDenied += b.HostInboundDeniedPackets
		s.unknownVLANDrops += b.UnknownVLANDropped
		s.dstMACDrops += b.DstMACDropped
		s.screenDrops += b.ScreenDrops
		// #3343: sum each per-reason ordinal. The Rust helper always sends a
		// fixed-length array, but guard the length so a short/old wire payload
		// (or an over-length future one) cannot panic the status poll.
		for i := 0; i < len(b.ScreenReasonDrops) && i < dataplane.ScreenReasonDropCount; i++ {
			s.screenReasonDrops[i] += b.ScreenReasonDrops[i]
		}
		s.synCookieSent += b.SYNCookieSynAckSent
		s.synCookieValid += b.SYNCookieAckValid
		s.synCookieInvalid += b.SYNCookieAckInvalid
		s.synCookieBypass += b.SYNCookieBypass
		s.snatPackets += b.SNATPackets
		s.dnatPackets += b.DNATPackets
		s.nat64Translations += b.Nat64Translations
		s.natAllocFail += b.NatAllocFail
	}
	return s
}

// syncBPFCountersPreIncrementObserver is a test-only seam: it fires inside
// syncBPFCountersLocked after the delta baseline has advanced
// (prevBindingCounters = cur) but BEFORE the IncrementGlobalCounter loop
// applies those deltas to the offset map. It is nil in production (the only
// runtime cost is a nil check on the 1/s counter sync). The #5098 review-fold
// atomicity test uses it to drive a concurrent ClearAllCounters through the
// exact window a status poll can be interrupted at, proving the clear cannot
// leave a residual in the just-reset offset.
var syncBPFCountersPreIncrementObserver func()

// syncBPFCountersLocked computes counter deltas since the last status poll
// and writes them into the BPF global_counters per-CPU array map.
// This ensures that packets forwarded by the userspace helper (which bypass
// the BPF pipeline) are reflected in ReadGlobalCounter results.
func (m *Manager) syncBPFCountersLocked(status *ProcessStatus) {
	cur := sumBindingCounters(status)
	prev := m.prevBindingCounters
	m.prevBindingCounters = cur

	// On the first poll (prev is all zeros) the entire cumulative count
	// becomes the delta. This is correct — the helper has been counting
	// since launch, and none of those packets appeared in BPF counters.
	type counterDelta struct {
		index uint32
		delta uint64
	}

	deltas := []counterDelta{
		{dataplane.GlobalCtrRxPackets, safeDelta(cur.rxPackets, prev.rxPackets)},
		{dataplane.GlobalCtrTxPackets, safeDelta(cur.txPackets, prev.txPackets)},
		{dataplane.GlobalCtrSessionsNew, safeDelta(cur.sessionCreates, prev.sessionCreates)},
		{dataplane.GlobalCtrSessionsClosed, safeDelta(cur.sessionExpires, prev.sessionExpires)},
		// #4477/#10498: GlobalCtrDrops includes the enforcement/admission
		// reasons below; named VLAN/MAC deltas also get dedicated indices.
		{dataplane.GlobalCtrDrops, safeDelta(cur.totalDrops(), prev.totalDrops())},
		{dataplane.GlobalCtrNATAllocFail, safeDelta(cur.natAllocFail, prev.natAllocFail)},
		{dataplane.GlobalCtrPolicyDeny, safeDelta(cur.policyDenied, prev.policyDenied)},
		// #3326: surface host-inbound admission denies into the counter the CLI,
		// gRPC status, REST, and Prometheus collector already read
		// (GlobalCtrHostInboundDeny). The Rust helper counts each host-inbound
		// drop per-binding; this delta-push mirrors the policy-deny plumbing so
		// host-inbound enforcement is observable (was always 0 before #3326).
		{dataplane.GlobalCtrHostInboundDeny, safeDelta(cur.hostInboundDenied, prev.hostInboundDenied)},
		{dataplane.GlobalCtrUnknownVLANDrops, safeDelta(cur.unknownVLANDrops, prev.unknownVLANDrops)},
		{dataplane.GlobalCtrDstMACDrops, safeDelta(cur.dstMACDrops, prev.dstMACDrops)},
		{dataplane.GlobalCtrScreenDrops, safeDelta(cur.screenDrops, prev.screenDrops)},
		// Challenge decisions are not "sent" until the worker admits a
		// SYN-ACK reply into bounded TX. Secret-unavailable and reply
		// budget drops remain userspace-local diagnostics.
		{dataplane.GlobalCtrSyncookieSent, safeDelta(cur.synCookieSent, prev.synCookieSent)},
		{dataplane.GlobalCtrSyncookieValid, safeDelta(cur.synCookieValid, prev.synCookieValid)},
		{dataplane.GlobalCtrSyncookieInvalid, safeDelta(cur.synCookieInvalid, prev.synCookieInvalid)},
		{dataplane.GlobalCtrSyncookieBypass, safeDelta(cur.synCookieBypass, prev.synCookieBypass)},
		// #2161: surface NAT64 translations into the global counter the CLI,
		// gRPC status, and Prometheus collector already read
		// (GlobalCtrNAT64Xlate). The Rust helper counts each v6<->v4 xlate
		// per-binding; this delta-push mirrors the snat/dnat plumbing so
		// `show security flow statistics` reflects live NAT64 translation.
		{dataplane.GlobalCtrNAT64Xlate, safeDelta(cur.nat64Translations, prev.nat64Translations)},
	}

	// #3343: push each per-screen-reason drop delta into its GlobalCtrScreen*
	// index, mirroring the aggregate GlobalCtrScreenDrops / SYN-cookie plumbing
	// above. Without this every per-reason counter the CLI/gRPC/REST/Prometheus
	// screen-statistics surfaces read stayed at 0 even while the aggregate rose
	// under attack. Ordinal i maps to dataplane.ScreenReasonCounters[i].Index.
	for i := range dataplane.ScreenReasonCounters {
		deltas = append(deltas, counterDelta{
			index: dataplane.ScreenReasonCounters[i].Index,
			delta: safeDelta(cur.screenReasonDrops[i], prev.screenReasonDrops[i]),
		})
	}

	if syncBPFCountersPreIncrementObserver != nil {
		syncBPFCountersPreIncrementObserver()
	}

	for _, d := range deltas {
		if d.delta == 0 {
			continue
		}
		if err := m.bpfShim.IncrementGlobalCounter(d.index, d.delta); err != nil {
			slog.Debug("userspace: failed to increment BPF global counter",
				"index", d.index, "delta", d.delta, "err", err)
		}
	}

	// #2218: mirror the helper's per-rule SNAT/DNAT/static-NAT translation hit
	// counters into the bpfShim offset map so Manager.ReadNATRuleCounter (and
	// `show security nat source/destination/static rule`) reports live hits.
	// The helper reports cumulative totals keyed by the compiler-assigned
	// counter ID; SetNATRuleCounterOffset stores them absolutely.
	for i := range status.NATRuleCounters {
		c := &status.NATRuleCounters[i]
		if c.CounterID == 0 {
			continue
		}
		m.bpfShim.SetNATRuleCounterOffset(uint32(c.CounterID), dataplane.CounterValue{
			Packets: c.Packets,
			Bytes:   c.Bytes,
		})
	}

	// #3651: mirror the helper's pre-summed per-zone traffic totals into the
	// bpfShim zone-counter offset map so Manager.ReadZoneCounters (and thus
	// `show security zones` Traffic statistics, REST /security/zones, and the
	// Prometheus collector) reports live per-zone volume instead of
	// ErrCounterNotPopulated ("not available"). The helper reports cumulative
	// totals keyed by the stable zone id.
	//
	// REPLACE the whole map rather than setting row by row. The published block
	// is a complete sparse set rebuilt each poll, so a zone that disappears from
	// it must disappear here too: a per-row SetZoneCounterOffset can only add or
	// overwrite, which strands the last value of any zone the helper stops
	// reporting and leaves every read surface serving a FROZEN total. That is
	// reachable in normal operation — a zone pushed past the helper's hot-path
	// slot capacity by a later config keeps its retained totals but stops being
	// counted, so its row drops out while the zone stays configured. See
	// ReplaceZoneCounterOffsets for the full disappearance taxonomy.
	zoneRows := make(map[uint16][2]dataplane.CounterValue, len(status.ZoneTrafficCounters))
	for i := range status.ZoneTrafficCounters {
		z := &status.ZoneTrafficCounters[i]
		zoneRows[z.ZoneID] = [2]dataplane.CounterValue{
			{Packets: z.IngressPackets, Bytes: z.IngressBytes},
			{Packets: z.EgressPackets, Bytes: z.EgressBytes},
		}
	}
	m.bpfShim.ReplaceZoneCounterOffsets(zoneRows)

	// #3651: the same mirror for the helper's pre-summed per-zone FLOOD-event
	// totals, so Manager.ReadFloodCounters (and thus `show security screen
	// ids-option statistics`) reports live SYN/ICMP/UDP flood-event counts
	// instead of ErrCounterNotPopulated ("not available"). Only the three counts
	// are sourced; FloodState's legacy WindowStart/SynproxyActive fields
	// belonged to the deleted eBPF rate-limiter state and stay zero.
	//
	// REPLACE the whole map rather than setting row by row, for the identical
	// reason as the traffic block above: the published set is complete and
	// rebuilt each poll, so a zone that disappears from it must disappear here
	// too. A per-row SetFloodCounterOffset can only add or overwrite, which
	// strands the last value of any zone the helper stops reporting and leaves
	// the screen-statistics surface serving a FROZEN flood count. That is
	// reachable in normal operation — a zone pushed past the helper's slot
	// capacity by a later config keeps its retained counts but stops being
	// counted, so its row drops out while the zone stays configured. See
	// ReplaceFloodCounterOffsets for the full disappearance taxonomy.
	floodRows := make(map[uint16]dataplane.FloodState, len(status.ZoneFloodCounters))
	for i := range status.ZoneFloodCounters {
		f := &status.ZoneFloodCounters[i]
		floodRows[f.ZoneID] = dataplane.FloodState{
			SynCount:  f.SynFloodEvents,
			ICMPCount: f.ICMPFloodEvents,
			UDPCount:  f.UDPFloodEvents,
		}
	}
	m.bpfShim.ReplaceFloodCounterOffsets(floodRows)
}

// safeDelta returns cur - prev. On counter reset (prev > cur), returns cur
// as the delta so counters don't undercount after helper restarts.
func safeDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return cur // counter reset: treat current cumulative as delta
	}
	return cur - prev
}
