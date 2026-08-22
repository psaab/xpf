package grpcapi

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/metadata"
)

// Command trees are defined in pkg/cmdtree (single source of truth).
// gRPC completion uses cmdtree.CompleteFromTree directly.

// --- helpers ---

// resolveFabricParent returns the physical parent interface name if name is a
// fabric IPVLAN overlay (fab0/fab1). Monitor commands should show wire-level
// fabric traffic, not the overlay (#135, #136).
func resolveFabricParent(name string) string {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return name
	}
	if ipv, ok := link.(*netlink.IPVlan); ok {
		parent, err := netlink.LinkByIndex(ipv.Attrs().ParentIndex)
		if err == nil {
			return parent.Attrs().Name
		}
	}
	return name
}

func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[ifName] = true
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
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

// protoName renders an IP protocol number as its canonical lowercase name,
// falling back to the numeric form for an unnamed protocol. The named set is
// owned by appid.ProtocolName (the #2949 SSOT) so gRPC, REST, and the catalog
// agree on which protocols are named.
func protoName(p uint8) string {
	if name := appid.ProtocolName(p); name != "" {
		return name
	}
	return fmt.Sprintf("%d", p)
}

func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, v)
	return ip
}

func (s *Server) dataplaneLoaded() bool {
	return s != nil && s.dp != nil && s.dp.IsLoaded()
}

func (s *Server) loadedApplyResult() *dataplane.ApplyResult {
	if !s.dataplaneLoaded() {
		return nil
	}
	return s.applyResult()
}

func (s *Server) sessionStore() dataplane.SessionStore {
	if s == nil {
		return dataplane.SessionStoreOf(nil)
	}
	return dataplane.SessionStoreOf(s.dp)
}

func (s *Server) telemetry() dataplane.Telemetry {
	if s == nil {
		return dataplane.TelemetryOf(nil)
	}
	return dataplane.TelemetryOf(s.dp)
}

type natRuleSetKey struct{ from, to string }

// natSessionCounts accumulates active-translation counts in int64 so a
// session table larger than MaxInt32 cannot wrap the counter NEGATIVE while
// it is being built (#5250 A8-b2 F3). Every protobuf hand-off saturates
// through clampInt32 (server_nat.go) instead of a bare int32 conversion.
type natSessionCounts struct {
	total           int64
	ruleSetSessions map[natRuleSetKey]int64
}

func (s *Server) countSNATSessions(zoneByID map[uint16]string) natSessionCounts {
	return s.countNATSessions(dataplane.SessFlagSNAT, zoneByID)
}

func (s *Server) countDNATSessions(zoneByID map[uint16]string) natSessionCounts {
	return s.countNATSessions(dataplane.SessFlagDNAT, zoneByID)
}

func (s *Server) countNATSessions(flag uint16, zoneByID map[uint16]string) natSessionCounts {
	counts := natSessionCounts{
		ruleSetSessions: make(map[natRuleSetKey]int64),
	}
	if !s.dataplaneLoaded() {
		return counts
	}

	add := func(isReverse uint8, flags uint16, ingressZone, egressZone uint16) {
		if isReverse != 0 || flags&flag == 0 {
			return
		}
		counts.total++
		if zoneByID != nil {
			counts.ruleSetSessions[natRuleSetKey{zoneByID[ingressZone], zoneByID[egressZone]}]++
		}
	}

	sessions := s.sessionStore()
	_ = sessions.ForEachV4(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		add(val.IsReverse, val.Flags, val.IngressZone, val.EgressZone)
		return true
	})
	_ = sessions.ForEachV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		add(val.IsReverse, val.Flags, val.IngressZone, val.EgressZone)
		return true
	})
	return counts
}

type builtinApp struct {
	proto uint8
	port  uint16
}

var builtinApps = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		for name, app := range cfg.Applications.Applications {
			var appProto uint8
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				appProto = 6
			case "udp":
				appProto = 17
			case "icmp":
				appProto = 1
			default:
				continue
			}
			if appProto != proto {
				continue
			}
			portStr := app.DestinationPort
			if portStr == "" {
				continue
			}
			if strings.Contains(portStr, "-") {
				parts := strings.SplitN(portStr, "-", 2)
				lo, err1 := strconv.Atoi(parts[0])
				hi, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && int(dstPort) >= lo && int(dstPort) <= hi {
					return name
				}
			} else {
				if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort {
					return name
				}
			}
		}
	}
	for name, ba := range builtinApps {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

func lookupAppFilter(appName string, cfg *config.Config) (proto uint8, port uint16, ok bool) {
	if ba, found := builtinApps[appName]; found {
		return ba.proto, ba.port, true
	}
	if cfg != nil {
		if app, found := cfg.Applications.Applications[appName]; found {
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				proto = 6
			case "udp":
				proto = 17
			case "icmp":
				proto = 1
			default:
				return 0, 0, false
			}
			if app.DestinationPort != "" {
				if v, err := strconv.Atoi(app.DestinationPort); err == nil {
					return proto, uint16(v), true
				}
			}
		}
	}
	return 0, 0, false
}

// screenChecks delegates to config.ScreenChecks, the single source of truth
// shared with the REST API (#3327). A nil screen-profile map value (reachable
// on the tolerant / HA-sync config path the runtime walker skips) renders as
// "no checks" rather than panicking on p.TCP.SynFlood (#3476).
func screenChecks(p *config.ScreenProfile) []string {
	return config.ScreenChecks(p)
}

func fmtPref(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

func boolStatus(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// writeChronyTracking parses chronyc tracking output and writes key fields.
func writeChronyTracking(buf *strings.Builder, output string) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, " : "); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+3:])
			fields[key] = val
		}
	}

	fmt.Fprintln(buf, "\nNTP sync status:")
	for _, pair := range [][2]string{
		{"Reference ID", "Reference"},
		{"Stratum", "Stratum"},
		{"Ref time (UTC)", "Reference time"},
		{"System time", "System time offset"},
		{"Last offset", "Last offset"},
		{"RMS offset", "RMS offset"},
		{"Frequency", "Frequency"},
		{"Root delay", "Root delay"},
		{"Root dispersion", "Root dispersion"},
		{"Update interval", "Poll interval"},
		{"Leap status", "Leap status"},
	} {
		if v, ok := fields[pair[0]]; ok {
			fmt.Fprintf(buf, "  %s: %s\n", pair[1], v)
		}
	}
}

func neighStateStr(state int) string {
	switch state {
	case netlink.NUD_REACHABLE:
		return "reachable"
	case netlink.NUD_STALE:
		return "stale"
	case netlink.NUD_DELAY:
		return "delay"
	case netlink.NUD_PROBE:
		return "probe"
	case netlink.NUD_FAILED:
		return "failed"
	case netlink.NUD_PERMANENT:
		return "permanent"
	case netlink.NUD_INCOMPLETE:
		return "incomplete"
	case netlink.NUD_NOARP:
		return "noarp"
	default:
		return "unknown"
	}
}

// writeNeighSummary writes a neighbor table summary (total + per-state + per-interface counts).
func writeNeighSummary(buf *strings.Builder, neighbors []netlink.Neigh, stateFn func(int) string) {
	var total int
	stateCounts := make(map[string]int)
	ifaceCounts := make(map[string]int)
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		total++
		stateCounts[stateFn(n.State)]++
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifaceCounts[link.Attrs().Name]++
		}
	}
	fmt.Fprintf(buf, "Total entries: %d", total)
	if total > 0 {
		var parts []string
		for _, s := range []string{"reachable", "stale", "permanent", "delay", "probe", "failed", "incomplete"} {
			if cnt := stateCounts[s]; cnt > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", s, cnt))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(buf, " (%s)", strings.Join(parts, ", "))
		}
	}
	fmt.Fprintln(buf)
	if len(ifaceCounts) > 1 {
		var ifNames []string
		for name := range ifaceCounts {
			ifNames = append(ifNames, name)
		}
		sort.Strings(ifNames)
		for _, name := range ifNames {
			fmt.Fprintf(buf, "  %-12s %d entries\n", name, ifaceCounts[name])
		}
	}
	fmt.Fprintln(buf)
}

// --- SystemAction RPC ---

func peerForwardedFromContext(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	return len(md.Get("x-peer-forwarded")) > 0
}
