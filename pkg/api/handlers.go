package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/vrrp"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, Response{Success: true, Data: data})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Response{Success: false, Error: msg})
}

// healthHandler surfaces dataplane compile health (#758) alongside the
// simple "ok" probe. When the dataplane compile has failed and has
// never succeeded since startup, return 503 with a structured "status:
// degraded" payload so operators scanning a probe can distinguish the
// catastrophic-silent-fail case from a healthy daemon.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{"status": "ok"}
	if s.compileHealthFn != nil {
		h := s.compileHealthFn()
		payload["compile_ever_succeeded"] = h.EverSucceeded
		payload["compile_failure_count"] = h.FailureCount
		if h.LastError != "" {
			payload["compile_last_error"] = h.LastError
		}
		if h.LastErrorUnixSec != 0 {
			payload["compile_last_error_unix"] = h.LastErrorUnixSec
		}
		if !h.EverSucceeded && h.FailureCount > 0 {
			payload["status"] = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "dataplane compile has never succeeded"})
			return
		}
	}
	writeOK(w, payload)
}

func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = len(cfg.Security.Zones)
	}
	if s.gc != nil {
		stats := s.gc.Stats()
		resp.SessionCount = stats.TotalEntries
	}
	writeOK(w, resp)
}

func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	readCounter := func(idx uint32) uint64 {
		v, _ := s.dp.ReadGlobalCounter(idx)
		return v
	}

	stats := GlobalStats{
		RxPackets:            readCounter(dataplane.GlobalCtrRxPackets),
		TxPackets:            readCounter(dataplane.GlobalCtrTxPackets),
		Drops:                readCounter(dataplane.GlobalCtrDrops),
		SessionsCreated:      readCounter(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:       readCounter(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:          readCounter(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:         readCounter(dataplane.GlobalCtrPolicyDeny),
		NATAllocFails:        readCounter(dataplane.GlobalCtrNATAllocFail),
		HostInboundDeny:      readCounter(dataplane.GlobalCtrHostInboundDeny),
		TCEgressPackets:      readCounter(dataplane.GlobalCtrTCEgressPackets),
		FabricRedirects:      readCounter(dataplane.GlobalCtrFabricRedirect),
		FabricFwdDrops:       readCounter(dataplane.GlobalCtrFabricFwdDrop),
		FlowCacheHits:        readCounter(dataplane.GlobalCtrFlowCacheHit),
		FlowCacheMisses:      readCounter(dataplane.GlobalCtrFlowCacheMiss),
		FlowCacheFlushes:     readCounter(dataplane.GlobalCtrFlowCacheFlush),
		FlowCacheInvalidates: readCounter(dataplane.GlobalCtrFlowCacheInvalidate),
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
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			continue
		}
		ctrs, err := s.dp.ReadInterfaceCounters(iface.Index)
		if err != nil {
			continue
		}
		result = append(result, InterfaceStats{
			Name:      ifName,
			Ifindex:   iface.Index,
			Zone:      ifZone[ifName],
			RxPackets: ctrs.RxPackets,
			RxBytes:   ctrs.RxBytes,
			TxPackets: ctrs.TxPackets,
			TxBytes:   ctrs.TxBytes,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) zoneStatsHandler(w http.ResponseWriter, _ *http.Request) {
	s.zonesHandler(w, nil)
}

func (s *Server) zonesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ZoneInfo{})
		return
	}

	cr := s.applyResult()
	var zones []ZoneInfo
	for zoneName, zone := range cfg.Security.Zones {
		zi := ZoneInfo{
			Name:       zoneName,
			Interfaces: zone.Interfaces,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}

		// Host-inbound services
		if zone.HostInboundTraffic != nil {
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.SystemServices...)
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.Protocols...)
		}
		if zi.HostInbound == nil {
			zi.HostInbound = []string{}
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}

		// Zone ID + counters
		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.ID = id
				if s.dp != nil && s.dp.IsLoaded() {
					if ing, err := s.dp.ReadZoneCounters(id, 0); err == nil {
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
					}
					if eg, err := s.dp.ReadZoneCounters(id, 1); err == nil {
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		zones = append(zones, zi)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	writeOK(w, zones)
}

func (s *Server) policiesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []PolicyInfo{})
		return
	}

	var policySetID uint32
	var result []PolicyInfo
	for _, zpp := range cfg.Security.Policies {
		pi := PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for _, rule := range zpp.Policies {
			pr := PolicyRule{
				Name:         rule.Name,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}

			if s.dp != nil && s.dp.IsLoaded() {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(len(pi.Rules))
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
		policySetID++
	}
	writeOK(w, result)
}

func (s *Server) natSourceHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATSourceInfo{})
		return
	}

	var result []NATSourceInfo
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			info := NATSourceInfo{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
			}
			if rule.Then.Interface {
				info.Type = "interface"
			} else if rule.Then.PoolName != "" {
				info.Type = "pool"
				info.Pool = rule.Then.PoolName
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) natDestHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		writeOK(w, []NATDestInfo{})
		return
	}

	var result []NATDestInfo
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			info := NATDestInfo{
				Name:    rule.Name,
				DstAddr: rule.Match.DestinationAddress,
			}
			if rule.Match.DestinationPort > 0 {
				info.DstPort = uint16(rule.Match.DestinationPort)
			}
			if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
				info.TranslateIP = pool.Address
				if pool.Port > 0 {
					info.TranslatePort = uint16(pool.Port)
				}
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) screenHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ScreenInfo{})
		return
	}

	var result []ScreenInfo
	for name, profile := range cfg.Security.Screen {
		si := ScreenInfo{Name: name}
		si.Checks = screenChecks(profile)
		if si.Checks == nil {
			si.Checks = []string{}
		}
		result = append(result, si)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeOK(w, []EventEntry{})
		return
	}

	limit := queryInt(r, "limit", 50)
	if limit > 10000 {
		limit = 10000
	}

	filter := logging.EventFilter{
		Zone:     queryUint16(r, "zone", 0),
		Action:   r.URL.Query().Get("action"),
		Protocol: r.URL.Query().Get("protocol"),
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	result := make([]EventEntry, len(events))
	for i, ev := range events {
		result[i] = EventEntry{
			Time:         ev.Time.Format(time.RFC3339),
			Type:         ev.Type,
			SrcAddr:      ev.SrcAddr,
			DstAddr:      ev.DstAddr,
			Protocol:     ev.Protocol,
			Action:       ev.Action,
			PolicyID:     ev.PolicyID,
			InZone:       ev.InZone,
			OutZone:      ev.OutZone,
			ScreenCheck:  ev.ScreenCheck,
			SessionPkts:  ev.SessionPkts,
			SessionBytes: ev.SessionBytes,
		}
	}
	writeOK(w, result)
}

func (s *Server) interfacesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []InterfaceStats{})
		return
	}

	// Build interface->zone map
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		is := InterfaceStats{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			is.Ifindex = iface.Index
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					is.RxPackets = ctrs.RxPackets
					is.RxBytes = ctrs.RxBytes
					is.TxPackets = ctrs.TxPackets
					is.TxBytes = ctrs.TxBytes
				}
			}
		}
		result = append(result, is)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) dhcpLeasesHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPLeaseInfo{})
		return
	}

	leases := s.dhcp.Leases()
	result := make([]DHCPLeaseInfo, len(leases))
	for i, l := range leases {
		family := "inet"
		if l.Family == 6 {
			family = "inet6"
		}
		info := DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    family,
			Address:   l.Address.String(),
			LeaseTime: l.LeaseTime.String(),
			Obtained:  l.Obtained.Format(time.RFC3339),
		}
		if l.Gateway.IsValid() {
			info.Gateway = l.Gateway.String()
		}
		for _, dns := range l.DNS {
			info.DNS = append(info.DNS, dns.String())
		}
		if info.DNS == nil {
			info.DNS = []string{}
		}
		result[i] = info
	}
	writeOK(w, result)
}

func (s *Server) routesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []RouteInfo{})
		return
	}

	var result []RouteInfo
	for _, r := range cfg.RoutingOptions.StaticRoutes {
		if r.NextTable != "" {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				NextTable:   r.NextTable,
				Preference:  r.Preference,
			})
			continue
		}
		if r.Discard || len(r.NextHops) == 0 {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				Preference:  r.Preference,
			})
			continue
		}
		for _, nh := range r.NextHops {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				NextHop:     nh.Address,
				Interface:   nh.Interface,
				Preference:  r.Preference,
			})
		}
	}
	if result == nil {
		result = []RouteInfo{}
	}
	writeOK(w, result)
}

func (s *Server) configHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, nil)
		return
	}
	writeOK(w, cfg)
}

// --- helpers ---

func (s *Server) applyResult() *dataplane.ApplyResult {
	if s.dp == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(s.dp)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func queryUint16(r *http.Request, key string, def uint16) uint16 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return def
	}
	return uint16(n)
}

// allInterfaceNames returns a deduplicated set of interface names from
// both the interfaces config and zone declarations.
func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[ifName] = true
	}
	for _, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			names[ifName] = true
		}
	}
	return names
}

func policyActionStr(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case dataplane.ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func screenChecks(p *config.ScreenProfile) []string {
	var checks []string
	if p.TCP.SynFlood != nil {
		checks = append(checks, "syn-flood")
	}
	if p.TCP.Land {
		checks = append(checks, "land")
	}
	if p.TCP.WinNuke {
		checks = append(checks, "winnuke")
	}
	if p.TCP.SynFrag {
		checks = append(checks, "syn-frag")
	}
	if p.TCP.SynFin {
		checks = append(checks, "syn-fin")
	}
	if p.TCP.NoFlag {
		checks = append(checks, "tcp-no-flag")
	}
	if p.TCP.FinNoAck {
		checks = append(checks, "fin-no-ack")
	}
	if p.ICMP.PingDeath {
		checks = append(checks, "ping-death")
	}
	if p.ICMP.FloodThreshold > 0 {
		checks = append(checks, "icmp-flood")
	}
	if p.UDP.FloodThreshold > 0 {
		checks = append(checks, "udp-flood")
	}
	if p.IP.SourceRouteOption {
		checks = append(checks, "source-route-option")
	}
	if p.IP.TearDrop {
		checks = append(checks, "tear-drop")
	}
	return checks
}

// --- Routing protocol handlers ---

func (s *Server) ospfHandler(w http.ResponseWriter, r *http.Request) {
	if s.frr == nil {
		writeOK(w, TextResponse{Output: "FRR not available"})
		return
	}
	typ := r.URL.Query().Get("type")
	switch typ {
	case "database":
		output, err := s.frr.GetOSPFDatabase()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, TextResponse{Output: output})
	default:
		neighbors, err := s.frr.GetOSPFNeighbors()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var b strings.Builder
		for _, n := range neighbors {
			fmt.Fprintf(&b, "%-18s %-10s %-16s %-18s %s\n",
				n.NeighborID, n.Priority, n.State, n.Address, n.Interface)
		}
		writeOK(w, TextResponse{Output: b.String()})
	}
}

func (s *Server) bgpHandler(w http.ResponseWriter, r *http.Request) {
	if s.frr == nil {
		writeOK(w, TextResponse{Output: "FRR not available"})
		return
	}
	typ := r.URL.Query().Get("type")
	var b strings.Builder
	switch typ {
	case "routes":
		routes, err := s.frr.GetBGPRoutes()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, route := range routes {
			fmt.Fprintf(&b, "%-24s %-20s %s\n", route.Network, route.NextHop, route.Path)
		}
	default:
		peers, err := s.frr.GetBGPSummary()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, p := range peers {
			fmt.Fprintf(&b, "%-20s %-8s %-10s %-10s %-12s %s\n",
				p.Neighbor, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State)
		}
	}
	writeOK(w, TextResponse{Output: b.String()})
}

// --- IPsec handler ---

func (s *Server) ipsecSAHandler(w http.ResponseWriter, _ *http.Request) {
	if s.ipsec == nil {
		writeOK(w, TextResponse{Output: "IPsec not available"})
		return
	}
	sas, err := s.ipsec.GetSAStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var b strings.Builder
	for _, sa := range sas {
		fmt.Fprintf(&b, "SA: %s  State: %s", sa.Name, sa.State)
		if sa.LocalAddr != "" {
			fmt.Fprintf(&b, "  Local: %s", sa.LocalAddr)
		}
		if sa.RemoteAddr != "" {
			fmt.Fprintf(&b, "  Remote: %s", sa.RemoteAddr)
		}
		b.WriteString("\n")
	}
	writeOK(w, TextResponse{Output: b.String()})
}

// --- NAT pool/rule stats handlers ---

func (s *Server) natPoolStatsHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATPoolStatsInfo{})
		return
	}

	var result []NATPoolStatsInfo

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		used := 0

		if s.dp != nil && s.dp.IsLoaded() {
			if cr := s.applyResult(); cr != nil {
				if id, ok := cr.PoolIDs[name]; ok {
					cnt, err := s.dp.ReadNATPortCounter(uint32(id))
					if err == nil {
						used = int(cnt)
					}
				}
			}
		}

		avail := totalPorts - used
		if avail < 0 {
			avail = 0
		}
		util := "0.0%"
		if totalPorts > 0 {
			util = fmt.Sprintf("%.1f%%", float64(used)/float64(totalPorts)*100)
		}

		result = append(result, NATPoolStatsInfo{
			Name:           name,
			Address:        strings.Join(pool.Addresses, ","),
			TotalPorts:     totalPorts,
			UsedPorts:      used,
			AvailablePorts: avail,
			Utilization:    util,
		})
	}

	// Interface-mode pools
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				used := 0
				if s.dp != nil && s.dp.IsLoaded() {
					_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
						if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
							used++
						}
						return true
					})
				}
				result = append(result, NATPoolStatsInfo{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   used,
					IsInterface: true,
				})
			}
		}
	}

	if result == nil {
		result = []NATPoolStatsInfo{}
	}
	writeOK(w, result)
}

func (s *Server) natRuleStatsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATRuleStatsInfo{})
		return
	}

	ruleSetFilter := r.URL.Query().Get("rule_set")
	var result []NATRuleStatsInfo

	for _, rs := range cfg.Security.NAT.Source {
		if ruleSetFilter != "" && rs.Name != ruleSetFilter {
			continue
		}
		for _, rule := range rs.Rules {
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			var hitPkts, hitBytes uint64
			if s.dp != nil && s.dp.IsLoaded() {
				if cr := s.applyResult(); cr != nil {
					ruleKey := rs.Name + "/" + rule.Name
					if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
						cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
						if err == nil {
							hitPkts = cnt.Packets
							hitBytes = cnt.Bytes
						}
					}
				}
			}

			result = append(result, NATRuleStatsInfo{
				RuleSet:    rs.Name,
				RuleName:   rule.Name,
				FromZone:   rs.FromZone,
				ToZone:     rs.ToZone,
				Action:     action,
				SrcMatch:   srcMatch,
				DstMatch:   dstMatch,
				HitPackets: hitPkts,
				HitBytes:   hitBytes,
			})
		}
	}

	if result == nil {
		result = []NATRuleStatsInfo{}
	}
	writeOK(w, result)
}

// --- VRRP handler ---

func (s *Server) vrrpHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	resp := VRRPStatusResponse{
		Instances: []VRRPInstanceInfo{},
	}

	if cfg != nil {
		instances := vrrp.CollectInstances(cfg)
		var states map[string]string
		if s.vrrpMgr != nil {
			states = s.vrrpMgr.States()
		}
		for _, inst := range instances {
			addrs := inst.VirtualAddresses
			if addrs == nil {
				addrs = []string{}
			}
			key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
			state := "INIT"
			if st, ok := states[key]; ok {
				state = st
			}
			resp.Instances = append(resp.Instances, VRRPInstanceInfo{
				Interface:        inst.Interface,
				GroupID:          inst.GroupID,
				State:            state,
				Priority:         inst.Priority,
				VirtualAddresses: addrs,
				Preempt:          inst.Preempt,
			})
		}
	}

	if s.vrrpMgr != nil {
		resp.ServiceStatus = s.vrrpMgr.Status()
	} else {
		resp.ServiceStatus = "VRRP: not running\n"
	}
	writeOK(w, resp)
}

// --- Policy match handler ---

func (s *Server) matchPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, MatchPoliciesResult{Action: "deny (default)"})
		return
	}

	fromZone := r.URL.Query().Get("from_zone")
	toZone := r.URL.Query().Get("to_zone")
	srcIP := net.ParseIP(r.URL.Query().Get("src_ip"))
	dstIP := net.ParseIP(r.URL.Query().Get("dst_ip"))
	dstPort := queryInt(r, "dst_port", 0)
	proto := r.URL.Query().Get("protocol")

	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != fromZone || zpp.ToZone != toZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if !matchPolicyAddr(pol.Match.SourceAddresses, srcIP, cfg) {
				continue
			}
			if !matchPolicyAddr(pol.Match.DestinationAddresses, dstIP, cfg) {
				continue
			}
			if !matchPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
				continue
			}

			writeOK(w, MatchPoliciesResult{
				Matched:      true,
				PolicyName:   pol.Name,
				Action:       policyActionStr(pol.Action),
				SrcAddresses: pol.Match.SourceAddresses,
				DstAddresses: pol.Match.DestinationAddresses,
				Applications: pol.Match.Applications,
			})
			return
		}
	}

	writeOK(w, MatchPoliciesResult{Action: "deny (default)"})
}

// matchPolicyAddr checks if an IP matches any address references.
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		if matchPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchPolicyApp checks if a protocol/port matches application references.
func matchPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
}

// --- Interfaces detail handler ---

func (s *Server) interfacesDetailHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, TextResponse{Output: "no active configuration\n"})
		return
	}

	filterName := r.URL.Query().Get("filter")
	terse := r.URL.Query().Get("terse") == "true"

	if terse {
		s.writeInterfacesTerse(w, cfg, filterName)
		return
	}

	s.writeInterfacesDetail(w, cfg, filterName)
}

func (s *Server) writeInterfacesTerse(w http.ResponseWriter, cfg *config.Config, filterName string) {
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	// Build RETH mappings
	physToReth := make(map[string]string) // physical member → reth parent
	rethToPhys := cfg.RethToPhysical()    // reth → physical member
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg.RedundantParent != "" {
			physToReth[ifCfg.Name] = ifCfg.RedundantParent
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", "Interface", "Admin", "Link", "Addresses")

	var ifNames []string
	for ifName := range allInterfaceNames(cfg) {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		baseName := strings.SplitN(ifName, ".", 2)[0]

		// Physical RETH member: show aenet --> rethN[.M]
		if rethName, ok := physToReth[baseName]; ok {
			kernelIf := config.LinuxIfName(baseName)
			iface, err := net.InterfaceByName(kernelIf)
			admin, link := "down", "down"
			if err == nil {
				if iface.Flags&net.FlagUp != 0 {
					admin = "up"
				}
				if data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate"); err == nil {
					if strings.TrimSpace(string(data)) == "up" {
						link = "up"
					}
				}
			}
			aenetTarget := rethName
			if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
				aenetTarget = rethName + "." + parts[1]
			}
			fmt.Fprintf(&b, "%-20s %-10s %-10s aenet --> %s\n", ifName, admin, link, aenetTarget)
			continue
		}

		// RETH interface: get addresses from config, status from physical member
		if physMember, ok := rethToPhys[baseName]; ok {
			kernelPhys := config.LinuxIfName(physMember)
			iface, err := net.InterfaceByName(kernelPhys)
			admin, link := "down", "down"
			if err == nil {
				if iface.Flags&net.FlagUp != 0 {
					admin = "up"
				}
				if data, err := os.ReadFile("/sys/class/net/" + kernelPhys + "/operstate"); err == nil {
					if strings.TrimSpace(string(data)) == "up" {
						link = "up"
					}
				}
			}
			var addrs []string
			if ifCfg, ok := cfg.Interfaces.Interfaces[baseName]; ok {
				// Determine which unit to look up
				unitNum := 0
				if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
					fmt.Sscanf(parts[1], "%d", &unitNum)
				}
				if unit, ok := ifCfg.Units[unitNum]; ok {
					addrs = append(addrs, unit.Addresses...)
				}
			}
			addrStr := strings.Join(addrs, ", ")
			if addrStr == "" {
				addrStr = "-"
			}
			fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", ifName, admin, link, addrStr)
			continue
		}

		// Normal interface: get addresses from kernel
		kernelName := config.LinuxIfName(ifName)
		iface, err := net.InterfaceByName(kernelName)
		admin, link := "down", "down"
		var addrs []string
		if err == nil {
			if iface.Flags&net.FlagUp != 0 {
				admin = "up"
			}
			if data, err := os.ReadFile("/sys/class/net/" + kernelName + "/operstate"); err == nil {
				if strings.TrimSpace(string(data)) == "up" {
					link = "up"
				}
			}
			if ifAddrs, err := iface.Addrs(); err == nil {
				for _, a := range ifAddrs {
					addrs = append(addrs, a.String())
				}
			}
		}
		addrStr := strings.Join(addrs, ", ")
		if addrStr == "" {
			addrStr = "-"
		}
		fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", ifName, admin, link, addrStr)
	}

	writeOK(w, TextResponse{Output: b.String()})
}

func (s *Server) writeInterfacesDetail(w http.ResponseWriter, cfg *config.Config, filterName string) {
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	var b strings.Builder
	var ifNames []string
	for ifName := range allInterfaceNames(cfg) {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			fmt.Fprintf(&b, "Interface: %s, Not present\n\n", ifName)
			continue
		}

		linkUp := "Down"
		if iface.Flags&net.FlagUp != 0 {
			linkUp = "Up"
		}
		if data, err := os.ReadFile("/sys/class/net/" + ifName + "/operstate"); err == nil {
			if strings.TrimSpace(string(data)) == "up" {
				linkUp = "Up"
			}
		}

		fmt.Fprintf(&b, "Interface: %s, Physical link is %s\n", ifName, linkUp)
		fmt.Fprintf(&b, "  MTU: %d", iface.MTU)
		if len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&b, ", MAC: %s", iface.HardwareAddr)
		}
		b.WriteString("\n")

		if zone, ok := ifaceZoneName[ifName]; ok {
			fmt.Fprintf(&b, "  Zone: %s\n", zone)
		}

		if s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintf(&b, "  BPF Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(&b, "  BPF Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		if addrs, err := iface.Addrs(); err == nil && len(addrs) > 0 {
			fmt.Fprintf(&b, "  Addresses:\n")
			for _, a := range addrs {
				fmt.Fprintf(&b, "    %s\n", a.String())
			}
		}

		// DHCP annotations
		if s.dhcp != nil {
			if lease := s.dhcp.LeaseFor(ifName, dhcp.AFInet); lease != nil {
				fmt.Fprintf(&b, "  DHCPv4: %s (gw %s)\n", lease.Address, lease.Gateway)
			}
			if lease := s.dhcp.LeaseFor(ifName, dhcp.AFInet6); lease != nil {
				fmt.Fprintf(&b, "  DHCPv6: %s (gw %s)\n", lease.Address, lease.Gateway)
			}
		}

		b.WriteString("\n")
	}

	writeOK(w, TextResponse{Output: b.String()})
}

// --- System info handler ---

func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	var b strings.Builder

	switch typ {
	case "uptime":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			writeError(w, http.StatusInternalServerError, "unexpected /proc/uptime format")
			return
		}
		var upSec float64
		fmt.Sscanf(fields[0], "%f", &upSec)

		days := int(upSec) / 86400
		hours := (int(upSec) % 86400) / 3600
		mins := (int(upSec) % 3600) / 60
		secs := int(upSec) % 60

		now := time.Now()
		fmt.Fprintf(&b, "Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
		if days > 0 {
			fmt.Fprintf(&b, "System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
		} else {
			fmt.Fprintf(&b, "System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
		}

	case "memory":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		info := make(map[string]uint64)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				info[key] = val
			}
		}
		total := info["MemTotal"]
		free := info["MemFree"]
		buffers := info["Buffers"]
		cached := info["Cached"]
		available := info["MemAvailable"]
		used := total - free - buffers - cached

		fmt.Fprintf(&b, "%-20s %10s\n", "Type", "kB")
		fmt.Fprintf(&b, "%-20s %10d\n", "Total memory", total)
		fmt.Fprintf(&b, "%-20s %10d\n", "Used memory", used)
		fmt.Fprintf(&b, "%-20s %10d\n", "Free memory", free)
		fmt.Fprintf(&b, "%-20s %10d\n", "Buffers", buffers)
		fmt.Fprintf(&b, "%-20s %10d\n", "Cached", cached)
		fmt.Fprintf(&b, "%-20s %10d\n", "Available", available)
		if total > 0 {
			fmt.Fprintf(&b, "Utilization: %.1f%%\n", float64(used)/float64(total)*100)
		}

	default:
		writeError(w, http.StatusBadRequest, "type parameter required (uptime, memory)")
		return
	}

	writeOK(w, TextResponse{Output: b.String()})
}

// --- DHCP identifiers handler ---

func (s *Server) dhcpIdentifiersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPClientIdentifierInfo{})
		return
	}

	duids := s.dhcp.DUIDs()
	result := make([]DHCPClientIdentifierInfo, len(duids))
	for i, d := range duids {
		result[i] = DHCPClientIdentifierInfo{
			Interface: d.Interface,
			Type:      d.Type,
			Display:   d.Display,
			Hex:       d.HexBytes,
		}
	}
	writeOK(w, result)
}

// --- Mutation handlers ---

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

// --- Diagnostic handlers ---

func (s *Server) pingHandler(w http.ResponseWriter, r *http.Request) {
	var req PingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}

	count := req.Count
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100
	}

	args := []string{"-c", fmt.Sprintf("%d", count)}
	if req.Source != "" {
		args = append(args, "-I", req.Source)
	}
	if req.Size > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", req.Size))
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		vrfDev := req.RoutingInstance
		if !strings.HasPrefix(vrfDev, "vrf-") {
			vrfDev = "vrf-" + vrfDev
		}
		cmd = append(cmd, "ip", "vrf", "exec", vrfDev)
	}
	cmd = append(cmd, "ping")
	cmd = append(cmd, args...)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	output := string(out)
	if err != nil {
		output += "\n" + err.Error()
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	var req TracerouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}

	args := []string{}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		vrfDev := req.RoutingInstance
		if !strings.HasPrefix(vrfDev, "vrf-") {
			vrfDev = "vrf-" + vrfDev
		}
		cmd = append(cmd, "ip", "vrf", "exec", vrfDev)
	}
	cmd = append(cmd, "traceroute")
	cmd = append(cmd, args...)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	output := string(out)
	if err != nil {
		output += "\n" + err.Error()
	}
	writeOK(w, TextResponse{Output: output})
}

// --- Config management handlers ---

func (s *Server) configEnterHandler(w http.ResponseWriter, _ *http.Request) {
	if err := s.store.EnterConfigure(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configExitHandler(w http.ResponseWriter, _ *http.Request) {
	s.store.ExitConfigure()
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configStatusHandler(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, ConfigModeStatus{
		InConfigMode:   s.store.InConfigMode(),
		Dirty:          s.store.IsDirty(),
		ConfirmPending: s.store.IsConfirmPending(),
	})
}

func (s *Server) configSetHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.SetFromInput(req.Input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.DeleteFromInput(req.Input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitHandler(w http.ResponseWriter, r *http.Request) {
	if s.store.IsConfirmPending() {
		if err := s.store.ConfirmCommit(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, map[string]string{"status": "ok"})
		return
	}

	if s.commitFn == nil {
		writeError(w, http.StatusInternalServerError, "commit handler not wired")
		return
	}
	if _, err := s.commitFn(r.Context(), ""); err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitCheckHandler(w http.ResponseWriter, _ *http.Request) {
	if _, err := s.store.CommitCheck(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configRollbackHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigRollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.Rollback(req.N); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	target := r.URL.Query().Get("target")

	var output string
	switch {
	case target == "active" && format == "set":
		output = s.store.ShowActiveSet()
	case target == "active" && format == "json":
		output = s.store.ShowActiveJSON()
	case target == "active" && format == "xml":
		output = s.store.ShowActiveXML()
	case target == "active":
		output = s.store.ShowActive()
	case format == "set":
		output = s.store.ShowCandidateSet()
	case format == "json":
		output = s.store.ShowCandidateJSON()
	case format == "xml":
		output = s.store.ShowCandidateXML()
	default:
		output = s.store.ShowCandidate()
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configExportHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "set"
	}
	var output string
	switch format {
	case "set":
		output = s.store.ShowActiveSet()
	case "text":
		output = s.store.ShowActive()
	case "json":
		output = s.store.ShowActiveJSON()
	case "xml":
		output = s.store.ShowActiveXML()
	default:
		writeError(w, http.StatusBadRequest, "unsupported format: "+format+"; use set, text, json, or xml")
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configCompareHandler(w http.ResponseWriter, r *http.Request) {
	rollbackN := queryInt(r, "rollback", 0)
	if rollbackN > 0 {
		diff, err := s.store.ShowCompareRollback(rollbackN)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, TextResponse{Output: diff})
		return
	}
	writeOK(w, TextResponse{Output: s.store.ShowCompare()})
}

func (s *Server) configHistoryHandler(w http.ResponseWriter, _ *http.Request) {
	entries := s.store.ListHistory()
	result := make([]HistoryEntry, len(entries))
	for i, e := range entries {
		result[i] = HistoryEntry{
			Index:     i + 1,
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
		}
	}
	writeOK(w, result)
}

func (s *Server) configSearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "missing q parameter")
		return
	}
	text := s.store.ShowActive()
	var results []ConfigSearchResult
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, query) {
			results = append(results, ConfigSearchResult{LineNumber: i + 1, Line: line})
		}
	}
	writeOK(w, results)
}

func (s *Server) configLoadHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigLoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content required")
		return
	}

	switch req.Mode {
	case "override":
		if err := s.store.LoadOverride(req.Content); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "merge", "":
		if err := s.store.LoadMerge(req.Content); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown load mode: %s (use 'override' or 'merge')", req.Mode))
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitConfirmedHandler(w http.ResponseWriter, r *http.Request) {
	var req CommitConfirmedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if s.commitConfirmedFn == nil {
		writeError(w, http.StatusInternalServerError, "commit-confirmed handler not wired")
		return
	}
	if _, err := s.commitConfirmedFn(r.Context(), req.Minutes); err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configConfirmHandler(w http.ResponseWriter, _ *http.Request) {
	if err := s.store.ConfirmCommit(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowRollbackHandler(w http.ResponseWriter, r *http.Request) {
	n := queryInt(r, "n", 1)
	format := r.URL.Query().Get("format")

	var output string
	var err error
	if format == "set" {
		output, err = s.store.ShowRollbackSet(n)
	} else {
		output, err = s.store.ShowRollback(n)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, TextResponse{Output: output})
}

// --- DHCP identifier clear handler ---

func (s *Server) clearDHCPIdentifiersHandler(w http.ResponseWriter, r *http.Request) {
	if s.dhcp == nil {
		writeOK(w, map[string]string{"message": "No DHCP clients running"})
		return
	}

	var req ClearDHCPIdentifierRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	if req.Interface != "" {
		if err := s.dhcp.ClearDUID(req.Interface); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, map[string]string{"message": fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface)})
		return
	}

	s.dhcp.ClearAllDUIDs()
	writeOK(w, map[string]string{"message": "All DHCPv6 DUIDs cleared"})
}

// --- ShowText handler ---

func (s *Server) showTextHandler(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic parameter required")
		return
	}

	cfg := s.store.ActiveConfig()
	var buf strings.Builder

	switch topic {
	case "schedulers":
		if cfg == nil || len(cfg.Schedulers) == 0 {
			buf.WriteString("No schedulers configured\n")
		} else {
			for name, sched := range cfg.Schedulers {
				fmt.Fprintf(&buf, "Scheduler: %s\n", name)
				if sched.StartTime != "" {
					fmt.Fprintf(&buf, "  Start time: %s\n", sched.StartTime)
				}
				if sched.StopTime != "" {
					fmt.Fprintf(&buf, "  Stop time:  %s\n", sched.StopTime)
				}
				if sched.StartDate != "" {
					fmt.Fprintf(&buf, "  Start date: %s\n", sched.StartDate)
				}
				if sched.StopDate != "" {
					fmt.Fprintf(&buf, "  Stop date:  %s\n", sched.StopDate)
				}
				if sched.Daily {
					buf.WriteString("  Recurrence: daily\n")
				}
				buf.WriteString("\n")
			}
		}

	case "snmp":
		if cfg == nil || cfg.System.SNMP == nil {
			buf.WriteString("No SNMP configured\n")
		} else {
			snmpCfg := cfg.System.SNMP
			if snmpCfg.Location != "" {
				fmt.Fprintf(&buf, "Location:    %s\n", snmpCfg.Location)
			}
			if snmpCfg.Contact != "" {
				fmt.Fprintf(&buf, "Contact:     %s\n", snmpCfg.Contact)
			}
			if snmpCfg.Description != "" {
				fmt.Fprintf(&buf, "Description: %s\n", snmpCfg.Description)
			}
			if len(snmpCfg.Communities) > 0 {
				buf.WriteString("Communities:\n")
				for name, comm := range snmpCfg.Communities {
					fmt.Fprintf(&buf, "  %s: %s\n", name, comm.Authorization)
				}
			}
			if len(snmpCfg.TrapGroups) > 0 {
				buf.WriteString("Trap groups:\n")
				for name, tg := range snmpCfg.TrapGroups {
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(tg.Targets, ", "))
				}
			}
		}

	case "dhcp-relay":
		if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
			buf.WriteString("No DHCP relay configured\n")
		} else {
			relay := cfg.ForwardingOptions.DHCPRelay
			if len(relay.ServerGroups) > 0 {
				buf.WriteString("Server groups:\n")
				for name, sg := range relay.ServerGroups {
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(sg.Servers, ", "))
				}
			}
			if len(relay.Groups) > 0 {
				buf.WriteString("Relay groups:\n")
				for name, g := range relay.Groups {
					fmt.Fprintf(&buf, "  %s:\n", name)
					fmt.Fprintf(&buf, "    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
					fmt.Fprintf(&buf, "    Active server group: %s\n", g.ActiveServerGroup)
				}
			}
		}

	case "firewall":
		hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
		if !hasFilters {
			buf.WriteString("No firewall filters configured\n")
		} else {
			printFilters := func(family string, filters map[string]*config.FirewallFilter) {
				for name, filter := range filters {
					fmt.Fprintf(&buf, "Filter: %s (family: %s)\n", name, family)
					for _, term := range filter.Terms {
						fmt.Fprintf(&buf, "  Term: %s\n", term.Name)
						if term.Protocol != "" {
							fmt.Fprintf(&buf, "    From protocol: %s\n", term.Protocol)
						}
						if len(term.DestinationPorts) > 0 {
							fmt.Fprintf(&buf, "    From destination-port: %s\n", strings.Join(term.DestinationPorts, ", "))
						}
						if len(term.SourceAddresses) > 0 {
							fmt.Fprintf(&buf, "    From source-address: %s\n", strings.Join(term.SourceAddresses, ", "))
						}
						if term.DSCP != "" {
							fmt.Fprintf(&buf, "    From dscp: %s\n", term.DSCP)
						}
						if term.Action != "" {
							fmt.Fprintf(&buf, "    Then: %s\n", term.Action)
						}
					}
					buf.WriteString("\n")
				}
			}
			printFilters("inet", cfg.Firewall.FiltersInet)
			printFilters("inet6", cfg.Firewall.FiltersInet6)
		}

	case "alg":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			alg := cfg.Security.ALG
			boolStr := func(b bool) string {
				if b {
					return "enabled"
				}
				return "disabled"
			}
			fmt.Fprintf(&buf, "SIP:  %s\n", boolStr(!alg.SIPDisable))
			fmt.Fprintf(&buf, "FTP:  %s\n", boolStr(!alg.FTPDisable))
			fmt.Fprintf(&buf, "TFTP: %s\n", boolStr(!alg.TFTPDisable))
			fmt.Fprintf(&buf, "DNS:  %s\n", boolStr(!alg.DNSDisable))
		}

	case "dynamic-address":
		if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
			buf.WriteString("No dynamic address feeds configured\n")
		} else {
			for name, feed := range cfg.Security.DynamicAddress.FeedServers {
				fmt.Fprintf(&buf, "Feed server: %s\n", name)
				fmt.Fprintf(&buf, "  URL: %s\n", feed.URL)
				if feed.FeedName != "" {
					fmt.Fprintf(&buf, "  Feed name: %s\n", feed.FeedName)
				}
				if feed.UpdateInterval > 0 {
					fmt.Fprintf(&buf, "  Update interval: %ds\n", feed.UpdateInterval)
				}
				if feed.HoldInterval > 0 {
					fmt.Fprintf(&buf, "  Hold interval: %ds\n", feed.HoldInterval)
				}
				buf.WriteString("\n")
			}
		}

	case "address-book":
		if cfg == nil || cfg.Security.AddressBook == nil {
			buf.WriteString("No address book configured\n")
		} else {
			ab := cfg.Security.AddressBook
			if len(ab.Addresses) > 0 {
				buf.WriteString("Addresses:\n")
				for name, addr := range ab.Addresses {
					fmt.Fprintf(&buf, "  %-20s %s\n", name, addr.Value)
				}
			}
			if len(ab.AddressSets) > 0 {
				buf.WriteString("Address sets:\n")
				for name, as := range ab.AddressSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Addresses, ", "))
				}
			}
		}

	case "applications":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			if len(cfg.Applications.Applications) > 0 {
				buf.WriteString("Applications:\n")
				for name, app := range cfg.Applications.Applications {
					fmt.Fprintf(&buf, "  %-20s proto=%-6s", name, app.Protocol)
					if app.DestinationPort != "" {
						fmt.Fprintf(&buf, " dst-port=%s", app.DestinationPort)
					}
					buf.WriteString("\n")
				}
			}
			if len(cfg.Applications.ApplicationSets) > 0 {
				buf.WriteString("Application sets:\n")
				for name, as := range cfg.Applications.ApplicationSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Applications, ", "))
				}
			}
		}

	case "flow-monitoring":
		if cfg == nil || cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil {
			buf.WriteString("No flow monitoring configured\n")
		} else {
			v9 := cfg.Services.FlowMonitoring.Version9
			buf.WriteString("Flow monitoring (NetFlow v9):\n")
			for name, tmpl := range v9.Templates {
				fmt.Fprintf(&buf, "  Template: %s\n", name)
				if tmpl.FlowActiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
				}
				if tmpl.FlowInactiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
				}
				if tmpl.TemplateRefreshRate > 0 {
					fmt.Fprintf(&buf, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
				}
			}
		}

	case "flow-timeouts":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			flow := cfg.Security.Flow
			buf.WriteString("Flow session timeouts:\n")
			if flow.TCPSession != nil {
				fmt.Fprintf(&buf, "  TCP established:      %ds\n", flow.TCPSession.EstablishedTimeout)
				fmt.Fprintf(&buf, "  TCP initial:          %ds\n", flow.TCPSession.InitialTimeout)
				fmt.Fprintf(&buf, "  TCP closing:          %ds\n", flow.TCPSession.ClosingTimeout)
				fmt.Fprintf(&buf, "  TCP time-wait:        %ds\n", flow.TCPSession.TimeWaitTimeout)
			}
			fmt.Fprintf(&buf, "  UDP session:          %ds\n", flow.UDPSessionTimeout)
			fmt.Fprintf(&buf, "  ICMP session:         %ds\n", flow.ICMPSessionTimeout)
			if flow.TCPMSSIPsecVPN > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (IPsec VPN):  %d\n", flow.TCPMSSIPsecVPN)
			}
			if flow.TCPMSSGreIn > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE in):     %d\n", flow.TCPMSSGreIn)
			}
			if flow.TCPMSSGreOut > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE out):    %d\n", flow.TCPMSSGreOut)
			}
			if flow.AllowDNSReply {
				buf.WriteString("  Allow DNS reply:      enabled\n")
			}
			if flow.AllowEmbeddedICMP {
				buf.WriteString("  Allow embedded ICMP:  enabled\n")
			}
		}

	case "nat-static":
		if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
			buf.WriteString("No static NAT rules configured.\n")
		} else {
			for _, rs := range cfg.Security.NAT.Static {
				fmt.Fprintf(&buf, "Static NAT rule-set: %s\n", rs.Name)
				fmt.Fprintf(&buf, "  From zone: %s\n", rs.FromZone)
				for _, rule := range rs.Rules {
					fmt.Fprintf(&buf, "  Rule: %s\n", rule.Name)
					fmt.Fprintf(&buf, "    Match destination-address: %s\n", rule.Match)
					if rule.IsNPTv6 {
						fmt.Fprintf(&buf, "    Then nptv6-prefix:         %s\n", rule.Then)
					} else {
						fmt.Fprintf(&buf, "    Then static-nat prefix:    %s\n", rule.Then)
					}
				}
				buf.WriteString("\n")
			}
		}

	case "nat-nptv6":
		if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
			buf.WriteString("No NPTv6 rules configured.\n")
		} else {
			found := false
			for _, rs := range cfg.Security.NAT.Static {
				for _, rule := range rs.Rules {
					if !rule.IsNPTv6 {
						continue
					}
					if !found {
						fmt.Fprintf(&buf, "%-20s %-20s %-50s %-50s\n",
							"Rule-set", "Rule", "External prefix", "Internal prefix")
						found = true
					}
					fmt.Fprintf(&buf, "%-20s %-20s %-50s %-50s\n",
						rs.Name, rule.Name, rule.Match, rule.Then)
				}
			}
			if !found {
				buf.WriteString("No NPTv6 rules configured.\n")
			}
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown topic: %s", topic))
		return
	}

	writeOK(w, TextResponse{Output: buf.String()})
}

// --- Config annotate handler ---

func (s *Server) configAnnotateHandler(w http.ResponseWriter, r *http.Request) {
	var req AnnotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Error: err.Error()})
		return
	}
	if req.Path == "" || req.Comment == "" {
		writeJSON(w, http.StatusBadRequest, Response{Error: "path and comment are required"})
		return
	}
	pathParts := strings.Fields(req.Path)
	if err := s.store.Annotate(pathParts, req.Comment); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, Response{Success: true})
}

// --- Session zone-pair summary handler ---

func (s *Server) systemBuffersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, []BufferInfo{})
		return
	}

	stats := s.dp.GetMapStats()
	buffers := make([]BufferInfo, 0, len(stats))
	for _, st := range stats {
		usage := 0.0
		status := "OK"
		if st.MaxEntries > 0 && st.Type != "Array" && st.Type != "PerCPUArray" {
			usage = float64(st.UsedCount) / float64(st.MaxEntries) * 100
			if usage >= 90 {
				status = "CRITICAL"
			} else if usage >= 80 {
				status = "WARNING"
			}
		}
		buffers = append(buffers, BufferInfo{
			Name:         st.Name,
			Type:         st.Type,
			MaxEntries:   int(st.MaxEntries),
			UsedCount:    int(st.UsedCount),
			UsagePercent: usage,
			Status:       status,
		})
	}
	writeOK(w, buffers)
}

// --- System action handler ---

func (s *Server) systemActionHandler(w http.ResponseWriter, r *http.Request) {
	var req SystemActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	switch req.Action {
	case "reboot":
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "reboot").Run()
		}()
		writeOK(w, map[string]string{"message": "System going down for reboot NOW!"})

	case "halt":
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "halt").Run()
		}()
		writeOK(w, map[string]string{"message": "System halting NOW!"})

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown action: %s (use 'reboot' or 'halt')", req.Action))
	}
}
