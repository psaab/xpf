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
)

// Command trees are defined in pkg/cmdtree (single source of truth).
// gRPC completion uses cmdtree.CompleteFromTree directly.

// --- helpers ---

// canonicalInterfaceName returns the canonical row identity for a
// config/zone interface reference (#15726). A unit-0 reference
// ("reth0.0", "ge-0/0/0.0") denotes the same logical interface as its
// bare base: both resolve to the same kernel device via
// ResolveKernelIfName. Collapsing unit 0 to the base keeps one row
// per physical interface instead of a duplicate bare + ".0" pair with
// split zone attribution. Non-zero units, bare names, and declared
// dotted interface names are returned unchanged (a declared dotted
// name outranks the parse via SplitInterfaceUnitRef).
func canonicalInterfaceName(cfg *config.Config, ref string) string {
	if cfg == nil {
		return ref
	}
	s := cfg.SplitInterfaceUnitRef(ref)
	if s.HasUnit {
		if n, _, err := config.CanonicalLogicalUnit(s.UnitTok); err == nil && n == 0 {
			return s.Base
		}
	}
	return ref
}

// interfaceZoneMap builds the interface->zone map keyed by canonical
// name (#15726) so a zone binding written as "reth0.0" attaches to the
// canonical "reth0" row.
func interfaceZoneMap(cfg *config.Config) map[string]string {
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifZone[canonicalInterfaceName(cfg, ifName)] = zoneName
		}
	}
	return ifZone
}

// allInterfaceNames returns a deduplicated set of canonical interface
// names from both the interfaces config and zone declarations
// (#15726: unit-0 refs collapse to their base).
func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[canonicalInterfaceName(cfg, ifName)] = true
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			names[canonicalInterfaceName(cfg, ifName)] = true
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

// sessionOriginLabel renders a row's stored provenance (#16110), mirroring
// pkg/cli's label: "local" or "cluster-synced" (peer-synced row).
// Promotion clears the cluster-synced flag, so a promoted row reads
// "local" — its stored provenance after promotion.
func sessionOriginLabel(flags uint16) string {
	if flags&dataplane.SessFlagClusterSynced != 0 {
		return "cluster-synced"
	}
	return "local"
}

// effectiveNATSrcPort/DstPort: address-only NAT (flag set, stored port 0)
// preserves the original port — never render a synthesized 0 (#16110).
func effectiveNATSrcPort(flags uint16, natPort, srcPort uint16) uint16 {
	if flags&dataplane.SessFlagSNAT != 0 && natPort == 0 {
		return srcPort
	}
	return natPort
}

func effectiveNATDstPort(flags uint16, natPort, dstPort uint16) uint16 {
	if flags&dataplane.SessFlagDNAT != 0 && natPort == 0 {
		return dstPort
	}
	return natPort
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
	// #8321 finding 16: sessions aggregated by INGRESS zone alone, across
	// every egress zone.
	//
	// `ruleSetSessions` is keyed {ingressZone, egressZone} from the session's
	// real zones, and a DESTINATION rule-set has no `to` clause -- the
	// compiler calls only applyNATFromScope, so `rs.ToZone` is always "". A
	// real session's egress zone is never "", so the {FromZone, ""} lookup
	// could never match and GetNATDestination returned an EMPTY
	// RuleSetSessions on every call, whatever the traffic.
	//
	// A source rule-set does carry a to-zone, so it keeps the pair key. This
	// index exists for the zone-pair-less case rather than replacing it.
	fromZoneSessions map[string]int64
}

// ruleSetSessionCount resolves the active-session count for one NAT rule-set.
//
// #8321 finding 16: the resolution rule lives here, in ONE place that both
// GetNATDestination and its tests call. A test that reimplemented the two-step
// lookup would pass against a production copy that had changed — the defect
// this fixes was itself a lookup key that no longer matched what the writer
// produced, and reproducing that shape in the test would be a poor way to
// guard it.
//
// A rule-set that NAMES an egress zone keeps the tighter pair key. Only a
// rule-set with no `to` clause falls back to the from-zone aggregate, so a
// future to-bearing destination rule-set is not silently widened.
func (c natSessionCounts) ruleSetSessionCount(fromZone, toZone string) (int64, bool) {
	if cnt, ok := c.ruleSetSessions[natRuleSetKey{fromZone, toZone}]; ok {
		return cnt, true
	}
	if toZone == "" {
		cnt, ok := c.fromZoneSessions[fromZone]
		return cnt, ok
	}
	return 0, false
}

func (s *Server) countSNATSessions(ctx context.Context, zoneByID map[uint16]string) natSessionCounts {
	return s.countNATSessions(ctx, dataplane.SessFlagSNAT, zoneByID)
}

func (s *Server) countDNATSessions(ctx context.Context, zoneByID map[uint16]string) natSessionCounts {
	return s.countNATSessions(ctx, dataplane.SessFlagDNAT, zoneByID)
}

// countNATSessions walks the FULL v4+v6 conntrack table. Callers must have
// taken a sessionWalkLimiter slot first — the walk holds per-bucket BPF-map
// locks against the live session-sync path, so an unadmitted one starves
// session installs on the shared control socket.
//
// ctx is the admission LEASE context from AcquireCtx, not merely the request
// context, and it is sampled inside both callbacks (#6553). Without it the
// walk ran to completion after the client was gone, holding a slot the
// hardened surfaces were queueing for: because REST and gRPC share ONE 4-slot
// diagcmd.SessionWalkLimiter, an un-cancellable gRPC walk degrades the REST
// twin that does honour cancellation. A cancelled walk returns the partial
// tally rather than an error — the caller renders a count, and a truncated
// count for a client that has already disconnected is not worth an error path.
func (s *Server) countNATSessions(ctx context.Context, flag uint16, zoneByID map[uint16]string) natSessionCounts {
	counts := natSessionCounts{
		ruleSetSessions:  make(map[natRuleSetKey]int64),
		fromZoneSessions: make(map[string]int64),
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
			// #8321 finding 16: the same session, indexed by ingress zone alone,
			// for rule-sets that do not name an egress zone.
			counts.fromZoneSessions[zoneByID[ingressZone]]++
		}
	}

	sessions := s.sessionStore()
	_ = sessions.ForEachV4(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if ctx != nil && ctx.Err() != nil {
			return false // client gone / lease cancelled — stop the walk
		}
		add(val.IsReverse, val.Flags, val.IngressZone, val.EgressZone)
		return true
	})
	_ = sessions.ForEachV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if ctx != nil && ctx.Err() != nil {
			return false
		}
		add(val.IsReverse, val.Flags, val.IngressZone, val.EgressZone)
		return true
	})
	return counts
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

// neighDisplayable reports whether a neighbor has enough information to
// render. Linux omits NDA_LLADDR for unresolved entries in these states.
func neighDisplayable(n netlink.Neigh) bool {
	return n.IP != nil && (n.HardwareAddr != nil ||
		n.State&(netlink.NUD_INCOMPLETE|netlink.NUD_FAILED) != 0)
}

func neighMACDisplay(n netlink.Neigh) string {
	if len(n.HardwareAddr) != 0 {
		return n.HardwareAddr.String()
	}
	if n.State&netlink.NUD_INCOMPLETE != 0 {
		return "(incomplete)"
	}
	if n.State&netlink.NUD_FAILED != 0 {
		return "(failed)"
	}
	return "-"
}

// neighborLinkNames resolves each interface index at most once per dump.
func neighborLinkNames(neighbors []netlink.Neigh, linkByIndex func(int) (netlink.Link, error)) map[int]string {
	names := make(map[int]string)
	resolved := make(map[int]bool)
	for _, n := range neighbors {
		if !neighDisplayable(n) || resolved[n.LinkIndex] {
			continue
		}
		resolved[n.LinkIndex] = true
		if link, err := linkByIndex(n.LinkIndex); err == nil {
			names[n.LinkIndex] = link.Attrs().Name
		}
	}
	return names
}

// writeNeighSummary writes a neighbor table summary (total + per-state + per-interface counts).
func writeNeighSummary(buf *strings.Builder, neighbors []netlink.Neigh, stateFn func(int) string, linkNames map[int]string) {
	var total int
	stateCounts := make(map[string]int)
	ifaceCounts := make(map[string]int)
	for _, n := range neighbors {
		if !neighDisplayable(n) {
			continue
		}
		total++
		stateCounts[stateFn(n.State)]++
		if name := linkNames[n.LinkIndex]; name != "" {
			ifaceCounts[name]++
		}
	}
	fmt.Fprintf(buf, "Total entries: %d", total)
	if total > 0 {
		var parts []string
		for _, s := range []string{"reachable", "stale", "permanent", "delay", "probe", "failed", "incomplete", "noarp", "unknown"} {
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

// peerForwardedFromContext reports whether this request was forwarded by the
// cluster peer.
//
// #5883: it reads the in-process capability (peer_marker_5883.go), NOT the
// `x-peer-forwarded` header. Only the fabric listener's interceptor promotes
// that header into the capability, and only after #4107 auth has accepted the
// call; the loopback listener strips it and promotes nothing. A caller cannot
// set a context value, so the marker is no longer forgeable by anyone who can
// merely reach a listener.
func peerForwardedFromContext(ctx context.Context) bool {
	return peerMarkersFromContext(ctx).forwarded
}
