package api

import (
	"net"
	"net/http"
	"sort"

	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
	var stats GlobalStats

	// #3681 (H04/H05/L03): the kernel nftables host-inbound DROP counters are
	// the PRIMARY host-inbound enforcement signal (distinct from the userspace-dp
	// HostInboundDeny below — not a double count). The `inet xpf_hostinbound`
	// chain is installed by the daemon INDEPENDENT of dataplane load state and
	// keeps dropping control-plane traffic in a config-only / degraded boot, so
	// read it BEFORE the dataplane gate — matching the Prometheus collector
	// (collectHostInboundKernelDenies runs before its dataplane gate). Otherwise
	// REST automation loses the host-inbound signal exactly when management-plane
	// exposure matters most. `readHostInboundDenyCounters` is the same
	// package-var indirection the collector uses, so this path is unit-testable
	// without a live kernel.
	//
	// #3681 (H05): mirror the #3345 "counter unavailable != zero" contract — on a
	// netlink read failure mark the aggregate Unavailable (its 0 is NOT
	// authoritative) instead of silently reporting a misleading "0 denies". The
	// Prometheus analogue omits the series and bumps xpf_counter_read_errors_total.
	//
	// #3681 (L03): keep the per-zone/family breakdown so the aggregate scalar's
	// [zone, family] dimensions (WAN-v4 vs WAN-v6 vs unexpected-internal-zone —
	// the incident-response signal) are not lost.
	//
	// #5719: the same marker covers a COUNTERLESS table. The #5644 cold-boot
	// fail-closed fence installs `inet xpf_hostinbound` with catch-all DROPs and
	// deliberately NO named counters, so while it enforces, the object walk
	// returns an empty set from a table that is actively dropping host-bound
	// traffic — publishing `host_inbound_kernel_denies: 0` with no marker would
	// certify "no denies" during exactly the degraded window that most needs the
	// signal. An ABSENT table stays an authoritative 0 (no enforcement really is
	// no denies), and a table whose real deny counters merely READ zero also
	// stays authoritative: those counter objects exist, so the read is Counted.
	kc, nftState, err := readHostInboundDenyCounters()
	switch {
	case err != nil:
		stats.HostInboundKernelDeniesUnavailable = true
	case nftState == xnft.HostInboundTableCounterless:
		stats.HostInboundKernelDeniesUnavailable = true
	default:
		for _, ctr := range kc {
			stats.HostInboundKernelDenies += ctr.Packets
			stats.HostInboundKernelDenyDetail = append(stats.HostInboundKernelDenyDetail,
				HostInboundKernelDenyCount{
					Zone:    ctr.Zone,
					Family:  ctr.Family,
					Packets: ctr.Packets,
					Bytes:   ctr.Bytes,
				})
		}
	}

	// #3681 (H04): the userspace-dp global counters below genuinely require a
	// loaded dataplane. On a degraded / config-only boot return a PARTIAL
	// response (200) carrying the dataplane-independent kernel host-inbound
	// counters read above plus an explicit DataplaneDegraded flag, instead of a
	// blanket 503 that would hide the host-inbound signal. The scope of the gate
	// is now exactly the counters that depend on the dataplane.
	if s.dp == nil || !s.dp.IsLoaded() {
		stats.DataplaneDegraded = true
		writeOK(w, stats)
		return
	}

	// #3345: surface a global-counter read failure instead of silently
	// reporting 0. A degraded userspace shim / counter bridge must not be
	// indistinguishable from "no events" — for a security appliance,
	// "counter unavailable" and "zero attacks" cannot look identical.
	var readErr error
	readCounter := func(idx uint32) uint64 {
		v, err := s.dp.ReadGlobalCounter(idx)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}

	stats.RxPackets = readCounter(dataplane.GlobalCtrRxPackets)
	stats.TxPackets = readCounter(dataplane.GlobalCtrTxPackets)
	stats.Drops = readCounter(dataplane.GlobalCtrDrops)
	stats.UnknownVLANDrops = readCounter(dataplane.GlobalCtrUnknownVLANDrops)
	stats.DstMACDrops = readCounter(dataplane.GlobalCtrDstMACDrops)
	stats.SessionsCreated = readCounter(dataplane.GlobalCtrSessionsNew)
	stats.SessionsClosed = readCounter(dataplane.GlobalCtrSessionsClosed)
	stats.ScreenDrops = readCounter(dataplane.GlobalCtrScreenDrops)
	stats.PolicyDenies = readCounter(dataplane.GlobalCtrPolicyDeny)
	stats.NATAllocFails = readCounter(dataplane.GlobalCtrNATAllocFail)
	stats.HostInboundDeny = readCounter(dataplane.GlobalCtrHostInboundDeny)
	stats.HostInboundAllowed = readCounter(dataplane.GlobalCtrHostInbound)
	stats.NAT64Translations = readCounter(dataplane.GlobalCtrNAT64Xlate)
	stats.TCEgressPackets = readCounter(dataplane.GlobalCtrTCEgressPackets)
	stats.FabricRedirects = readCounter(dataplane.GlobalCtrFabricRedirect)
	stats.FabricFwdDrops = readCounter(dataplane.GlobalCtrFabricFwdDrop)
	stats.FlowCacheHits = readCounter(dataplane.GlobalCtrFlowCacheHit)
	stats.FlowCacheMisses = readCounter(dataplane.GlobalCtrFlowCacheMiss)
	stats.FlowCacheFlushes = readCounter(dataplane.GlobalCtrFlowCacheFlush)
	stats.FlowCacheInvalidates = readCounter(dataplane.GlobalCtrFlowCacheInvalidate)

	if readErr != nil {
		writeError(w, http.StatusInternalServerError,
			"global counter read failed: "+readErr.Error())
		return
	}

	writeOK(w, stats)
}

func (s *Server) ifaceStatsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []InterfaceStats{})
		return
	}

	// Build interface->zone map
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		// Translate Junos config name to Linux kernel ifname (#1565).
		iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
		if err != nil {
			continue
		}
		is := InterfaceStats{
			Name:    ifName,
			Ifindex: iface.Index,
			Zone:    ifZone[ifName],
		}
		// #3464: a per-interface counter read failure used to `continue`,
		// dropping the whole interface row — so a degraded counter bridge made
		// the interface VANISH (indistinguishable from "not configured"). Keep
		// the row with an explicit Unavailable marker (counters left 0 but not
		// authoritative) so a read failure is distinguishable from a real idle
		// 0. Uniform with REST /interfaces, gRPC GetInterfaces, and the
		// Prometheus xpf_interface_counter_read_errors_total contract.
		if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err != nil {
			is.Unavailable = true
		} else {
			is.RxPackets = ctrs.RxPackets
			is.RxBytes = ctrs.RxBytes
			is.TxPackets = ctrs.TxPackets
			is.TxBytes = ctrs.TxBytes
		}
		result = append(result, is)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) zoneStatsHandler(w http.ResponseWriter, _ *http.Request) {
	s.zonesHandler(w, nil)
}

func (s *Server) clearCountersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}
	if err := s.dp.ClearAllCounters(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}
