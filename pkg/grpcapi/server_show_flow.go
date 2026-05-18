// Phase 5 of #1043: extract the flow-related ShowText case bodies into
// dedicated methods. Same methodology as Phases 1-4 (#1148, #1150,
// #1151, #1153): semantic relocation, no behavior change. Each case
// body is moved verbatim apart from `&buf` references becoming `buf`
// (passed-in `*strings.Builder`) and the original
// `if … { … } else { … }` flattened into early-return form. Output is
// unchanged.

package grpcapi

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// showFlowMonitoring renders NetFlow v9 template configuration.
func (s *Server) showFlowMonitoring(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil {
		buf.WriteString("No flow monitoring configured\n")
		return
	}
	v9 := cfg.Services.FlowMonitoring.Version9
	buf.WriteString("Flow monitoring (NetFlow v9):\n")
	for name, tmpl := range v9.Templates {
		fmt.Fprintf(buf, "  Template: %s\n", name)
		if tmpl.FlowActiveTimeout > 0 {
			fmt.Fprintf(buf, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
		}
		if tmpl.FlowInactiveTimeout > 0 {
			fmt.Fprintf(buf, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
		}
		if tmpl.TemplateRefreshRate > 0 {
			fmt.Fprintf(buf, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
		}
	}
}

// showFlowTimeouts renders TCP/UDP/ICMP session timeouts and assorted
// flow toggles (allow-dns-reply, embedded ICMP, GRE acceleration,
// power mode).
func (s *Server) showFlowTimeouts(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	flow := cfg.Security.Flow
	buf.WriteString("Flow session timeouts:\n")
	if flow.TCPSession != nil {
		fmt.Fprintf(buf, "  TCP established:      %ds\n", flow.TCPSession.EstablishedTimeout)
		fmt.Fprintf(buf, "  TCP initial:          %ds\n", flow.TCPSession.InitialTimeout)
		fmt.Fprintf(buf, "  TCP closing:          %ds\n", flow.TCPSession.ClosingTimeout)
		fmt.Fprintf(buf, "  TCP time-wait:        %ds\n", flow.TCPSession.TimeWaitTimeout)
	}
	fmt.Fprintf(buf, "  UDP session:          %ds\n", flow.UDPSessionTimeout)
	fmt.Fprintf(buf, "  ICMP session:         %ds\n", flow.ICMPSessionTimeout)
	if flow.TCPMSSIPsecVPN > 0 {
		fmt.Fprintf(buf, "  TCP MSS (IPsec VPN):  %d\n", flow.TCPMSSIPsecVPN)
	}
	if flow.TCPMSSGreIn > 0 {
		fmt.Fprintf(buf, "  TCP MSS (GRE in):     %d\n", flow.TCPMSSGreIn)
	}
	if flow.TCPMSSGreOut > 0 {
		fmt.Fprintf(buf, "  TCP MSS (GRE out):    %d\n", flow.TCPMSSGreOut)
	}
	if flow.AllowDNSReply {
		buf.WriteString("  Allow DNS reply:      enabled\n")
	}
	if flow.AllowEmbeddedICMP {
		buf.WriteString("  Allow embedded ICMP:  enabled\n")
	}
	if flow.GREPerformanceAcceleration {
		buf.WriteString("  GRE acceleration:     enabled\n")
	}
	if flow.PowerModeDisable {
		buf.WriteString("  Power mode:           disabled\n")
	}
}

// showFlowStatistics renders global flow counters (sessions, packets,
// drops, NAT, screen, host-inbound, NAT64, flow cache).
func (s *Server) showFlowStatistics(buf *strings.Builder) {
	if s.dp == nil || !s.dp.IsLoaded() {
		buf.WriteString("Flow statistics: dataplane not loaded\n")
		return
	}
	readCtr := func(idx uint32) uint64 {
		v, _ := s.dp.ReadGlobalCounter(idx)
		return v
	}
	sessNew := readCtr(dataplane.GlobalCtrSessionsNew)
	sessClosed := readCtr(dataplane.GlobalCtrSessionsClosed)
	buf.WriteString("Flow statistics:\n")
	fmt.Fprintf(buf, "  %-30s %d\n", "Current sessions:", sessNew-sessClosed)
	fmt.Fprintf(buf, "  %-30s %d\n", "Sessions created:", sessNew)
	fmt.Fprintf(buf, "  %-30s %d\n", "Sessions closed:", sessClosed)
	buf.WriteString("\n")
	fmt.Fprintf(buf, "  %-30s %d\n", "Packets received:", readCtr(dataplane.GlobalCtrRxPackets))
	fmt.Fprintf(buf, "  %-30s %d\n", "Packets transmitted:", readCtr(dataplane.GlobalCtrTxPackets))
	fmt.Fprintf(buf, "  %-30s %d\n", "Packets dropped:", readCtr(dataplane.GlobalCtrDrops))
	fmt.Fprintf(buf, "  %-30s %d\n", "TC egress packets:", readCtr(dataplane.GlobalCtrTCEgressPackets))
	buf.WriteString("\n")
	fmt.Fprintf(buf, "  %-30s %d\n", "Policy deny:", readCtr(dataplane.GlobalCtrPolicyDeny))
	fmt.Fprintf(buf, "  %-30s %d\n", "NAT allocation failures:", readCtr(dataplane.GlobalCtrNATAllocFail))
	fmt.Fprintf(buf, "  %-30s %d\n", "Screen drops:", readCtr(dataplane.GlobalCtrScreenDrops))
	fmt.Fprintf(buf, "  %-30s %d\n", "Host-inbound denies:", readCtr(dataplane.GlobalCtrHostInboundDeny))
	fmt.Fprintf(buf, "  %-30s %d\n", "Host-inbound allowed:", readCtr(dataplane.GlobalCtrHostInbound))
	fmt.Fprintf(buf, "  %-30s %d\n", "NAT64 translations:", readCtr(dataplane.GlobalCtrNAT64Xlate))
	cacheHit := readCtr(dataplane.GlobalCtrFlowCacheHit)
	cacheMiss := readCtr(dataplane.GlobalCtrFlowCacheMiss)
	if cacheHit > 0 || cacheMiss > 0 {
		buf.WriteString("\n")
		fmt.Fprintf(buf, "  %-30s %d\n", "Flow cache hits:", cacheHit)
		fmt.Fprintf(buf, "  %-30s %d\n", "Flow cache misses:", cacheMiss)
		fmt.Fprintf(buf, "  %-30s %d\n", "Flow cache flushes:", readCtr(dataplane.GlobalCtrFlowCacheFlush))
		fmt.Fprintf(buf, "  %-30s %d\n", "Flow cache invalidations:", readCtr(dataplane.GlobalCtrFlowCacheInvalidate))
		if cacheHit+cacheMiss > 0 {
			hitRate := float64(cacheHit) / float64(cacheHit+cacheMiss) * 100
			fmt.Fprintf(buf, "  %-30s %.1f%%\n", "Flow cache hit rate:", hitRate)
		}
	}
}

// showSessionsTop renders the top-N (default 20) sessions sorted by
// bytes or packets, walking both v4 and v6 session tables.
// `topic` is "sessions-top:bytes" or "sessions-top:packets".
func (s *Server) showSessionsTop(cfg *config.Config, topic string, buf *strings.Builder) {
	if s.dp == nil || !s.dp.IsLoaded() {
		buf.WriteString("Dataplane not loaded\n")
		return
	}
	sortByBytes := topic == "sessions-top:bytes"
	sortLabel := "bytes"
	if !sortByBytes {
		sortLabel = "packets"
	}

	type topEntry struct {
		src, dst, proto, zone, app string
		fwdPkts, revPkts           uint64
		fwdBytes, revBytes         uint64
		age                        int64
	}
	now := monotonicSeconds()
	zoneNames := make(map[uint16]string)
	var appNames map[uint16]string
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
		appNames = cr.AppNames
	}
	var entries []topEntry

	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		inZ := zoneNames[val.IngressZone]
		outZ := zoneNames[val.EgressZone]
		if inZ == "" {
			inZ = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZ == "" {
			outZ = fmt.Sprintf("%d", val.EgressZone)
		}
		var age int64
		if now > val.Created {
			age = int64(now - val.Created)
		}
		entries = append(entries, topEntry{
			src:      fmt.Sprintf("%s:%d", net.IP(key.SrcIP[:]), ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("%s:%d", net.IP(key.DstIP[:]), ntohs(key.DstPort)),
			proto:    protoName(key.Protocol),
			zone:     inZ + "->" + outZ,
			app:      appid.ResolveSessionName(appNames, cfg, key.Protocol, ntohs(key.DstPort), val.AppID),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		})
		return true
	})

	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		inZ := zoneNames[val.IngressZone]
		outZ := zoneNames[val.EgressZone]
		if inZ == "" {
			inZ = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZ == "" {
			outZ = fmt.Sprintf("%d", val.EgressZone)
		}
		var age int64
		if now > val.Created {
			age = int64(now - val.Created)
		}
		entries = append(entries, topEntry{
			src:      fmt.Sprintf("[%s]:%d", net.IP(key.SrcIP[:]), ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("[%s]:%d", net.IP(key.DstIP[:]), ntohs(key.DstPort)),
			proto:    protoName(key.Protocol),
			zone:     inZ + "->" + outZ,
			app:      appid.ResolveSessionName(appNames, cfg, key.Protocol, ntohs(key.DstPort), val.AppID),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		})
		return true
	})

	if sortByBytes {
		sort.Slice(entries, func(i, j int) bool {
			return (entries[i].fwdBytes + entries[i].revBytes) > (entries[j].fwdBytes + entries[j].revBytes)
		})
	} else {
		sort.Slice(entries, func(i, j int) bool {
			return (entries[i].fwdPkts + entries[i].revPkts) > (entries[j].fwdPkts + entries[j].revPkts)
		})
	}

	limit := 20
	if limit > len(entries) {
		limit = len(entries)
	}
	fmt.Fprintf(buf, "Top %d sessions by %s (of %d total):\n", limit, sortLabel, len(entries))
	fmt.Fprintf(buf, "%-5s %-22s %-22s %-5s %-20s %12s %12s %5s %s\n",
		"#", "Source", "Destination", "Proto", "Zone", "Bytes(f/r)", "Pkts(f/r)", "Age", "App")
	for i := 0; i < limit; i++ {
		e := entries[i]
		fmt.Fprintf(buf, "%-5d %-22s %-22s %-5s %-20s %5d/%-6d %5d/%-6d %5d %s\n",
			i+1, e.src, e.dst, e.proto, e.zone,
			e.fwdBytes, e.revBytes, e.fwdPkts, e.revPkts, e.age, e.app)
	}
}

// showFlowTraceoptions renders the flow traceoptions log file
// configuration and any packet-filter selectors.
func (s *Server) showFlowTraceoptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	opts := cfg.Security.Flow.Traceoptions
	if opts == nil || opts.File == "" {
		buf.WriteString("Flow traceoptions: not configured\n")
		return
	}
	buf.WriteString("Flow traceoptions:\n")
	fmt.Fprintf(buf, "  File:           %s\n", opts.File)
	if opts.FileSize > 0 {
		fmt.Fprintf(buf, "  File size:      %d bytes\n", opts.FileSize)
	}
	if opts.FileCount > 0 {
		fmt.Fprintf(buf, "  File count:     %d\n", opts.FileCount)
	}
	if len(opts.Flags) > 0 {
		fmt.Fprintf(buf, "  Flags:          %s\n", strings.Join(opts.Flags, ", "))
	}
	if len(opts.PacketFilters) > 0 {
		buf.WriteString("  Packet filters:\n")
		for _, pf := range opts.PacketFilters {
			fmt.Fprintf(buf, "    %s:", pf.Name)
			if pf.SourcePrefix != "" {
				fmt.Fprintf(buf, " src=%s", pf.SourcePrefix)
			}
			if pf.DestinationPrefix != "" {
				fmt.Fprintf(buf, " dst=%s", pf.DestinationPrefix)
			}
			buf.WriteString("\n")
		}
	}
}
