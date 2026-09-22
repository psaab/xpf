// Phase 5 of #1043: extract the flow-related ShowText case bodies into
// dedicated methods. Same methodology as Phases 1-4 (#1148, #1150,
// #1151, #1153): semantic relocation, no behavior change. Each case
// body is moved verbatim apart from `&buf` references becoming `buf`
// (passed-in `*strings.Builder`) and the original
// `if … { … } else { … }` flattened into early-return form. Output is
// unchanged.

package grpcapi

import (
	"container/heap"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// showFlowMonitoringStatistics renders per-collector NetFlow v9 / IPFIX
// write-health (#2464): for every running exporter collector, its write
// attempt/failure counters, the current reachability, and the last
// success / failure timestamps. Before this, a collector going
// unreachable was invisible — every failed UDP write was debug-logged and
// dropped while the exporter kept counting "exported", so an operator got
// no warning that forensics/compliance flow data was being silently lost.
func (s *Server) showFlowMonitoringStatistics(buf *strings.Builder) {
	if s.flowCollectorHealthFn == nil {
		buf.WriteString("No flow export configured\n")
		return
	}
	health := s.flowCollectorHealthFn()
	if len(health) == 0 {
		buf.WriteString("No flow export configured\n")
		return
	}
	buf.WriteString("Flow export collector statistics:\n")
	for _, h := range health {
		state := "up"
		if !h.Healthy {
			state = "DOWN"
		}
		fmt.Fprintf(buf, "  Collector %s (%s)", h.Address, h.Protocol)
		if h.SourceAddress != "" {
			fmt.Fprintf(buf, " source %s", h.SourceAddress)
		}
		if h.Instance != "" {
			fmt.Fprintf(buf, " instance %s", h.Instance)
		}
		if h.Template != "" {
			fmt.Fprintf(buf, " template %s", h.Template)
		}
		buf.WriteString("\n")
		fmt.Fprintf(buf, "    State:          %s\n", state)
		fmt.Fprintf(buf, "    Write attempts: %d\n", h.WriteAttempts)
		fmt.Fprintf(buf, "    Write failures: %d\n", h.WriteFailures)
		if h.WriteSkipped > 0 {
			fmt.Fprintf(buf, "    Write skipped:  %d (unhealthy backoff)\n", h.WriteSkipped)
		}
		if !h.LastSuccessTime.IsZero() {
			fmt.Fprintf(buf, "    Last success:   %s\n", h.LastSuccessTime.Format("2006-01-02 15:04:05"))
		}
		if !h.LastFailureTime.IsZero() {
			fmt.Fprintf(buf, "    Last failure:   %s\n", h.LastFailureTime.Format("2006-01-02 15:04:05"))
		}
		if h.LastError != "" {
			fmt.Fprintf(buf, "    Last error:     %s\n", h.LastError)
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
		// #6539: only established-timeout has a dataplane wire carrier. The
		// other three are committed and stored but never leave the control
		// plane, so they are annotated rather than printed in the same shape
		// as the enforced one. config.AnnotateTCPSessionTimeout is the single
		// authority shared with the REST/CLI surfaces and the commit advisory.
		tcpRow := func(label, leaf string, secs int) {
			fmt.Fprintf(buf, "  %-21s %s\n", label+":",
				config.AnnotateTCPSessionTimeout(leaf, fmt.Sprintf("%ds", secs)))
		}
		tcpRow("TCP established", config.TCPSessionEstablishedTimeoutLeaf, flow.TCPSession.EstablishedTimeout)
		tcpRow("TCP initial", config.TCPSessionInitialTimeoutLeaf, flow.TCPSession.InitialTimeout)
		tcpRow("TCP closing", config.TCPSessionClosingTimeoutLeaf, flow.TCPSession.ClosingTimeout)
		tcpRow("TCP time-wait", config.TCPSessionTimeWaitTimeoutLeaf, flow.TCPSession.TimeWaitTimeout)
	}
	fmt.Fprintf(buf, "  UDP session:          %ds\n", flow.UDPSessionTimeout)
	fmt.Fprintf(buf, "  ICMP session:         %ds\n", flow.ICMPSessionTimeout)
	if flow.TCPMSSAllTCP > 0 {
		fmt.Fprintf(buf, "  TCP MSS (all-tcp):    %d\n", flow.TCPMSSAllTCP)
	}
	if flow.TCPMSSIPsecVPN > 0 {
		// #2486: ipsec-vpn is rejected at commit; a value can only appear
		// from a leniently-loaded legacy config and is NOT enforced.
		fmt.Fprintf(buf, "  TCP MSS (IPsec VPN):  %d (not enforced)\n", flow.TCPMSSIPsecVPN)
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
		// #5804: accepted-only. Same wording contract as the local CLI
		// (pkg/cli/cli_show_flow.go) — a remote operator must not read a
		// stronger claim than an on-box one.
		buf.WriteString("  GRE acceleration:     configured (accepted-only; GRE sessions remain 5-tuple keyed — #5804)\n")
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
	// #3345: surface a counter-read failure rather than emitting clean zeros
	// that hide a degraded counter bridge.
	var readErr error
	readCtr := func(idx uint32) uint64 {
		v, err := s.dp.ReadGlobalCounter(idx)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}
	sessNew := readCtr(dataplane.GlobalCtrSessionsNew)
	sessClosed := readCtr(dataplane.GlobalCtrSessionsClosed)
	buf.WriteString("Flow statistics:\n")
	fmt.Fprintf(buf, "  %-30s %d\n", "Current sessions:", dataplane.CurrentSessions(sessNew, sessClosed))
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
	fmt.Fprintf(buf, "  %-30s %d\n", "Unknown VLAN drops:", readCtr(dataplane.GlobalCtrUnknownVLANDrops))
	fmt.Fprintf(buf, "  %-30s %d\n", "Destination MAC drops:", readCtr(dataplane.GlobalCtrDstMACDrops))
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
	if readErr != nil {
		fmt.Fprintf(buf, "warning: global counter read failed (statistics may be incomplete): %v\n", readErr)
	}
}

// resolveSessionName is a package-level indirection over
// appid.ResolveSessionName so the bounded top-K deferral in
// showSessionsTop (enrich only the <=K survivors, never all N sessions)
// can be asserted by a counting fake in tests. Production always binds
// appid.ResolveSessionName.
var resolveSessionName = appid.ResolveSessionName

// topSessionsK is the fixed row count `show ... sessions-top` renders
// (Junos-style top-20). Selection is bounded to this many survivors via
// a min-heap so a busy firewall (up to ~10M sessions) pays O(N log K)
// comparisons + O(K) enrichment for a read-only status call, instead of
// O(N log N) sort + O(N) fmt.Sprintf/appid enrichment (#5319).
const topSessionsK = 20

// topCand carries only the CHEAP raw fields needed to (a) rank a session
// by the selected metric and (b) enrich the <=K survivors afterwards. No
// fmt.Sprintf / appid work happens until a candidate is known to be in
// the top K.
type topCand struct {
	metric                               uint64 // fwdBytes+revBytes OR fwdPkts+revPkts
	isV6                                 bool
	srcIP, dstIP                         net.IP
	srcPort, dstPort                     uint16 // network order, as in the key
	proto                                uint8
	inZone, outZone                      uint16
	appID                                uint16
	fwdPkts, revPkts, fwdBytes, revBytes uint64
	created                              uint64
}

// topCandHeap is a MIN-heap on metric: the root is the smallest of the
// current top-K, so a new candidate displaces it only when strictly
// larger.
type topCandHeap []topCand

func (h topCandHeap) Len() int           { return len(h) }
func (h topCandHeap) Less(i, j int) bool { return h[i].metric < h[j].metric }
func (h topCandHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *topCandHeap) Push(x any)        { *h = append(*h, x.(topCand)) }
func (h *topCandHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// showSessionsTop renders the top-N (default 20) sessions sorted by
// bytes or packets, walking both v4 and v6 session tables.
// `topic` is "sessions-top:bytes" or "sessions-top:packets".
//
// Selection is bounded (#5319): a size-K min-heap keeps only the K
// highest-metric forward sessions while walking the tables, ranking on
// the raw byte/packet counter (cheap, comparable) and deferring the
// fmt.Sprintf + appid.ResolveSessionName enrichment to the <=K
// survivors. A backend iterator error (e.g. helper restart mid-scan) is
// surfaced as codes.Internal instead of returning a partial ranking as
// success (the errors were previously assigned to `_`).
func (s *Server) showSessionsTop(cfg *config.Config, topic string, buf *strings.Builder) error {
	if s.dp == nil || !s.dp.IsLoaded() {
		buf.WriteString("Dataplane not loaded\n")
		return nil
	}

	// Admission bound (#5708, codex-review-182 M35): the top-K selection is a
	// full v4+v6 conntrack-table walk (same per-bucket BPF-map lock contention
	// as GetSessionSummary). The #5319 bounded top-K caps only the OUTPUT (K
	// survivors), not the WALK, so an unbounded concurrent `show ... top`
	// scrape flood still multiplies lock contention. Gate it through the SAME
	// shared limiter as the GetSessions/GetSessionSummary/GetZonePairSummary
	// RPCs and the REST session scans; an over-cap scan surfaces as
	// codes.ResourceExhausted (ShowText returns this handler error verbatim).
	// Release on every exit path via defer.
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		return status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	sortByBytes := topic == "sessions-top:bytes"
	sortLabel := "bytes"
	if !sortByBytes {
		sortLabel = "packets"
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

	h := &topCandHeap{}
	total := 0
	// consider offers a candidate to the bounded top-K. It fills the heap
	// to K, then only displaces the current minimum when the candidate is
	// strictly larger — so at most K entries are ever retained and no
	// enrichment happens here.
	consider := func(c topCand) {
		total++
		if h.Len() < topSessionsK {
			heap.Push(h, c)
			return
		}
		if c.metric > (*h)[0].metric {
			(*h)[0] = c
			heap.Fix(h, 0)
		}
	}

	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		metric := val.FwdBytes + val.RevBytes
		if !sortByBytes {
			metric = val.FwdPackets + val.RevPackets
		}
		srcIP := make(net.IP, len(key.SrcIP))
		copy(srcIP, key.SrcIP[:])
		dstIP := make(net.IP, len(key.DstIP))
		copy(dstIP, key.DstIP[:])
		consider(topCand{
			metric:   metric,
			srcIP:    srcIP,
			dstIP:    dstIP,
			srcPort:  key.SrcPort,
			dstPort:  key.DstPort,
			proto:    key.Protocol,
			inZone:   val.IngressZone,
			outZone:  val.EgressZone,
			appID:    val.AppID,
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			created:  val.Created,
		})
		return true
	}); err != nil {
		return status.Errorf(codes.Internal, "v4 session iteration: %v", err)
	}

	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		metric := val.FwdBytes + val.RevBytes
		if !sortByBytes {
			metric = val.FwdPackets + val.RevPackets
		}
		srcIP := make(net.IP, len(key.SrcIP))
		copy(srcIP, key.SrcIP[:])
		dstIP := make(net.IP, len(key.DstIP))
		copy(dstIP, key.DstIP[:])
		consider(topCand{
			metric:   metric,
			isV6:     true,
			srcIP:    srcIP,
			dstIP:    dstIP,
			srcPort:  key.SrcPort,
			dstPort:  key.DstPort,
			proto:    key.Protocol,
			inZone:   val.IngressZone,
			outZone:  val.EgressZone,
			appID:    val.AppID,
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			created:  val.Created,
		})
		return true
	}); err != nil {
		return status.Errorf(codes.Internal, "v6 session iteration: %v", err)
	}

	// Order the <=K survivors with the SAME descending comparator the
	// original full sort used (metric already equals fwd+rev bytes or
	// fwd+rev packets), then enrich only these rows.
	survivors := []topCand(*h)
	sort.Slice(survivors, func(i, j int) bool {
		return survivors[i].metric > survivors[j].metric
	})

	limit := topSessionsK
	if limit > len(survivors) {
		limit = len(survivors)
	}
	fmt.Fprintf(buf, "Top %d sessions by %s (of %d total):\n", limit, sortLabel, total)
	fmt.Fprintf(buf, "%-5s %-22s %-22s %-5s %-20s %12s %12s %5s %s\n",
		"#", "Source", "Destination", "Proto", "Zone", "Bytes(f/r)", "Pkts(f/r)", "Age", "App")
	for i := 0; i < limit; i++ {
		c := survivors[i]
		inZ := zoneNames[c.inZone]
		outZ := zoneNames[c.outZone]
		if inZ == "" {
			inZ = fmt.Sprintf("%d", c.inZone)
		}
		if outZ == "" {
			outZ = fmt.Sprintf("%d", c.outZone)
		}
		var src, dst string
		if c.isV6 {
			src = fmt.Sprintf("[%s]:%d", c.srcIP, ntohs(c.srcPort))
			dst = fmt.Sprintf("[%s]:%d", c.dstIP, ntohs(c.dstPort))
		} else {
			src = fmt.Sprintf("%s:%d", c.srcIP, ntohs(c.srcPort))
			dst = fmt.Sprintf("%s:%d", c.dstIP, ntohs(c.dstPort))
		}
		var age int64
		if now > c.created {
			age = int64(now - c.created)
		}
		app := resolveSessionName(appNames, cfg, c.proto, ntohs(c.srcPort), ntohs(c.dstPort), c.appID)
		fmt.Fprintf(buf, "%-5d %-22s %-22s %-5s %-20s %5d/%-6d %5d/%-6d %5d %s\n",
			i+1, src, dst, protoName(c.proto), inZ+"->"+outZ,
			c.fwdBytes, c.revBytes, c.fwdPkts, c.revPkts, age, app)
	}
	return nil
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
