package grpcapi

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type sessionEgressKey struct {
	ifindex uint32
	vlanID  uint16
}

// sessionWalkLimiter is the aggregate concurrency bound for the gRPC
// session-table walk paths (GetSessions list, GetSessionSummary,
// GetZonePairSummary, the ShowText "sessions-top:*" scan in
// server_show_flow.go, and the ClearSessions clear — both its clear-all and
// filtered full-table walks, #5779). It aliases the
// process-wide diagcmd.SessionWalkLimiter — the SAME instance the REST
// session list/summary/zone-pair handlers use (pkg/api/sessions.go) — so a
// session scan admitted over gRPC and one admitted over REST draw from one
// aggregate MaxConcurrentSessionWalks budget. Before #5708 the gRPC scans had
// NO admission bound, so a gRPC caller could issue unbounded full v4+v6
// conntrack-table walks (each holding per-bucket BPF-map locks against the
// live session-sync path), bypassing the REST gate — a CPU/contention DoS
// (codex-review-182 M35). Acquire is fail-fast; over-cap gRPC scans return
// codes.ResourceExhausted (the gRPC analog of the REST HTTP 429, matching the
// diagnostic ping/traceroute handlers, #5057). A package var so a test can
// swap in a fresh small-capacity limiter.
var sessionWalkLimiter = diagcmd.SessionWalkLimiter

func (s *Server) GetSessions(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	// Admission bound (#5708, codex-review-182 M35): GetSessions drives a full
	// v4+v6 conntrack-table walk (both the cursor and legacy paths below, plus
	// the peer fan-out) that contends with the live dataplane session-sync path
	// for per-bucket BPF-map locks. Acquire a slot fail-fast BEFORE the walk so
	// a concurrent gRPC scrape flood is rejected with ResourceExhausted rather
	// than each driving its own simultaneous walk. The limiter is SHARED with
	// the REST session scans, so a mix of REST+gRPC callers cannot collectively
	// exceed the aggregate bound. Release on every exit path via defer.
	//
	// #5880: use the request-graph-aware AcquireCtx so a REST list/summary
	// handler that already holds a slot and delegates to this RPC IN-PROCESS
	// (carrying the admission lease on ctx) REUSES that slot instead of
	// re-acquiring the same limiter and self-rejecting its own include_peer
	// fan-out at capacity. A direct external gRPC call carries no lease and
	// acquires exactly one slot as before.
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	// req.Offset is a signed int32; a negative value made the legacy
	// path's `idx >= offset` test true for the first row (silently
	// behaving like offset 0) and was ignored entirely by the cursor
	// path. Reject it centrally — BEFORE the PageSize branch — so both
	// the cursor and legacy paths surface bad input as InvalidArgument
	// rather than a full page returned as success (#3439 L2).
	if req.Offset < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid offset %d", req.Offset)
	}

	// #5557: reject a negative page_size for symmetry with Offset above.
	// req.PageSize is a signed int32; a negative value silently fell
	// through the `PageSize > 0` guard below into the legacy limit/offset
	// path — surfacing bad input as a full page returned as success
	// rather than InvalidArgument.
	if req.PageSize < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid page_size %d", req.PageSize)
	}

	// #5557: reject a negative limit for symmetry with Offset and PageSize.
	// req.Limit is a signed int32 consumed only by the legacy path, where
	// `limit <= 0` collapses to the default page of 100 — so a NEGATIVE limit
	// silently behaved like the default rather than surfacing bad input.
	// limit == 0 is preserved as the legitimate default-100 sentinel; only a
	// strictly negative limit is an error.
	if req.Limit < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid limit %d", req.Limit)
	}

	// Cursor-based pagination: when page_size > 0, use cursor path.
	if req.PageSize > 0 {
		return s.getSessionsCursor(ctx, req)
	}

	// Legacy limit/offset path (backward compatible).
	return s.getSessionsLegacy(ctx, req)
}

// getSessionsCursor implements cursor-based pagination.
// It iterates only up to page_size matching entries, avoids full-table
// scans for the total count (uses SessionCount instead), and skips
// enrichment when no_enrich is set.
//
// The cursor-iteration provider interface (sessionCursorIterator)
// lives in runtime.go alongside grpcRuntime and the userspace
// provider probes; we fall through to the legacy full-table scan
// when the underlying dataplane does not satisfy it.
func (s *Server) getSessionsCursor(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	iterDP, ok := s.dpProbe().(sessionCursorIterator)
	if !ok {
		// Dataplane doesn't support cursor iteration; fall back to legacy.
		return s.getSessionsLegacy(ctx, req)
	}

	pageSize := int(req.PageSize)
	if pageSize > 10000 {
		pageSize = 10000
	}

	filter := s.buildSessionFilter(req)
	if err := filter.validate(); err != nil {
		return nil, err
	}
	noEnrich := req.NoEnrich

	now := monotonicSeconds()
	all := make([]*pb.SessionEntry, 0, pageSize)

	// Determine HA state for session display.
	haActive := true
	if s.cluster != nil {
		haActive = s.cluster.IsLocalPrimary(0)
	}

	// Parse page_token to determine where to resume.
	startV4 := true  // iterate v4 sessions
	startV6 := false // iterate v6 after v4
	var cursorV4 *dataplane.SessionKey
	var cursorV6 *dataplane.SessionKeyV6

	if req.PageToken != "" {
		kind, keyBytes, err := parsePageToken(req.PageToken)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page_token: %v", err)
		}
		switch kind {
		case "v4":
			k, err := decodeSessionKeyV4(keyBytes)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid v4 page_token: %v", err)
			}
			cursorV4 = &k
		case "v6start":
			startV4 = false
			startV6 = true
		case "v6":
			startV4 = false
			startV6 = true
			k, err := decodeSessionKeyV6(keyBytes)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid v6 page_token: %v", err)
			}
			cursorV6 = &k
		}
	}

	var lastV4Key dataplane.SessionKey
	var lastV6Key dataplane.SessionKeyV6
	v4Exhausted := !startV4
	v6Exhausted := true // set to false when we start v6

	// Phase 1: iterate v4 sessions from cursor.
	//
	// The adapter's cursor delegation can return
	// dpuserspace.ErrCursorIterationUnsupported when the embedded
	// dataplane is nil or does not implement cursor iteration
	// (test/edge configurations only — production
	// LegacyDataPlaneAdapter wraps a *dataplane.Manager which does
	// implement it). Detecting that sentinel and falling back to
	// the legacy offset/limit pagination preserves the master/
	// pre-#1516 user-visible behavior in those edge cases instead
	// of surfacing a codes.Internal to the client.
	if startV4 {
		if err := iterDP.IterateSessionsFrom(cursorV4, func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if len(all) >= pageSize {
				return false // page full
			}
			if !filter.matchV4(key, val) {
				return true
			}
			if !noEnrich {
				if rev, err := s.dp.GetSessionV4(val.ReverseKey); err == nil {
					val.RevPackets += rev.RevPackets
					val.RevBytes += rev.RevBytes
					val.FwdPackets += rev.FwdPackets
					val.FwdBytes += rev.FwdBytes
				}
			}
			se := sessionEntryV4(key, val, now, filter.zoneNames, filter.policyNames, filter.zoneIfaces, filter.egressIfaces, haActive)
			if !noEnrich {
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
			lastV4Key = key
			return true
		}); err != nil {
			if errors.Is(err, dpuserspace.ErrCursorIterationUnsupported) {
				return s.getSessionsLegacy(ctx, req)
			}
			return nil, status.Errorf(codes.Internal, "v4 session iteration: %v", err)
		}
		if len(all) >= pageSize {
			// Page is full from v4; next page token resumes v4.
			resp := &pb.GetSessionsResponse{
				Sessions:      all,
				NextPageToken: encodePageTokenV4(lastV4Key),
			}
			if err := s.setSessionsTotal(resp, filter); err != nil {
				return nil, err
			}
			s.setSessionsNodeID(resp)
			s.fetchPeerSessions(ctx, req, resp)
			return resp, nil
		}
		v4Exhausted = true
		startV6 = true
	}

	// Phase 2: iterate v6 sessions.
	if startV6 {
		v6Exhausted = false
		if err := iterDP.IterateSessionsV6From(cursorV6, func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if len(all) >= pageSize {
				return false
			}
			if !filter.matchV6(key, val) {
				return true
			}
			if !noEnrich {
				if rev, err := s.dp.GetSessionV6(val.ReverseKey); err == nil {
					val.RevPackets += rev.RevPackets
					val.RevBytes += rev.RevBytes
					val.FwdPackets += rev.FwdPackets
					val.FwdBytes += rev.FwdBytes
				}
			}
			se := sessionEntryV6(key, val, now, filter.zoneNames, filter.policyNames, filter.zoneIfaces, filter.egressIfaces, haActive)
			if !noEnrich {
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
			lastV6Key = key
			return true
		}); err != nil {
			if errors.Is(err, dpuserspace.ErrCursorIterationUnsupported) {
				return s.getSessionsLegacy(ctx, req)
			}
			return nil, status.Errorf(codes.Internal, "v6 session iteration: %v", err)
		}
		if len(all) >= pageSize {
			resp := &pb.GetSessionsResponse{
				Sessions:      all,
				NextPageToken: encodePageTokenV6(lastV6Key),
			}
			if err := s.setSessionsTotal(resp, filter); err != nil {
				return nil, err
			}
			s.setSessionsNodeID(resp)
			s.fetchPeerSessions(ctx, req, resp)
			return resp, nil
		}
		v6Exhausted = true
	}

	// Both v4 and v6 are exhausted — last page.
	_ = v4Exhausted
	_ = v6Exhausted
	resp := &pb.GetSessionsResponse{
		Sessions: all,
		// NextPageToken is empty — no more data.
	}
	if err := s.setSessionsTotal(resp, filter); err != nil {
		return nil, err
	}
	s.setSessionsNodeID(resp)
	s.fetchPeerSessions(ctx, req, resp)
	return resp, nil
}

// setSessionsTotal sets the Total field on the response to the exact count
// of filter-matching sessions.
//
// With no filters active, the lightweight SessionCount() avoids a scan (it
// counts forward map entries directly). With filters active, a count-only
// scan — no reverse-entry merge, no app resolution, no allocation — yields
// the REAL filtered total instead of the -1 sentinel the cursor path used
// to return (#5034 / C175-HC-073). matchV4/matchV6 already skip reverse
// entries, so the count is forward-only, matching both SessionCount() and
// the legacy path's idx total. A filtered session view — including a
// cluster peer's session detail — now reports a meaningful "Total
// sessions" count rather than a negative sentinel.
//
// An iterator error is propagated (codes.Internal) so a partial count
// fails the RPC rather than surfacing as a successful under-count, matching
// the #2469 discipline for the page-iteration scans above.
func (s *Server) setSessionsTotal(resp *pb.GetSessionsResponse, f *sessionFilter) error {
	if !f.hasFilters {
		v4, v6 := s.dp.SessionCount()
		resp.Total = clampInt32(int64(v4) + int64(v6))
		return nil
	}
	total := 0
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if f.matchV4(key, val) {
			total++
		}
		return true
	}); err != nil {
		return status.Errorf(codes.Internal, "v4 session count: %v", err)
	}
	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if f.matchV6(key, val) {
			total++
		}
		return true
	}); err != nil {
		return status.Errorf(codes.Internal, "v6 session count: %v", err)
	}
	resp.Total = clampInt32(int64(total))
	return nil
}

func (s *Server) setSessionsNodeID(resp *pb.GetSessionsResponse) {
	if s.cluster != nil {
		resp.NodeId = int32(s.cluster.NodeID())
	}
}

// sessionFilter holds pre-computed filter state for session iteration.
type sessionFilter struct {
	zoneFilter   uint16
	protoFilter  string
	srcNet       *net.IPNet
	dstNet       *net.IPNet
	srcPort      uint16
	dstPort      uint16
	natOnly      bool
	appFilter    string
	ifaceFilter  string
	snatPool     string       // source-nat-pool filter: pool name ("" = off)
	snatPoolNets []*net.IPNet // resolved pool address set
	snatPoolOK   bool         // pool name resolved to a configured source pool
	inputErr     error        // invalid filter input (bad prefix/port) — must fail the RPC
	cfg          *config.Config
	zoneNames    map[uint16]string
	zoneIfaces   map[uint16]string
	egressIfaces map[sessionEgressKey]string
	policyNames  map[uint32]string
	appNames     map[uint16]string
	hasFilters   bool // true if any filter narrows results
}

// parseSessionPrefix parses an operator prefix filter — a CIDR or a
// bare IP (bare IPs become host networks).
func parseSessionPrefix(prefix string) (*net.IPNet, error) {
	cidr := prefix
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	return n, err
}

// setInputErr records the first invalid-input error.
func (f *sessionFilter) setInputErr(err error) {
	if f.inputErr == nil {
		f.inputErr = err
	}
}

// protoFilterMatches matches a session protocol against an operator
// filter string: case-insensitive protocol name (tcp/udp/icmp/icmpv6/
// gre/esp/sctp/...) or a numeric IP protocol ("47" matches GRE sessions
// even though protoName(47) renders "gre"). Resolution goes through
// appid.ProtocolNumberLenient so name-only tokens with no protoName()
// reverse (e.g. "sctp"=132, "ospf"=89) still match their sessions AND a
// display-only name the strict ProtocolNumber does not reverse
// ("ipv6"=41, #3393) matches its sessions too. An unknown token (e.g.
// "tcpip") matches nothing — buildSessionFilter rejects such tokens with
// InvalidArgument before iteration so an unparseable protocol is
// surfaced rather than returned as an empty success (#3439 L2).
func protoFilterMatches(p uint8, filter string) bool {
	if n, ok := appid.ProtocolNumberLenient(filter); ok {
		return n == p
	}
	return false
}

// validate reports operator-input errors that must fail the RPC rather
// than silently match nothing (or, worse for clear paths, match
// everything).
func (f *sessionFilter) validate() error {
	if f.inputErr != nil {
		return f.inputErr
	}
	if f.snatPool != "" && !f.snatPoolOK {
		return status.Errorf(codes.InvalidArgument, "source NAT pool %q not found", f.snatPool)
	}
	return nil
}

func (s *Server) buildSessionFilter(req *pb.GetSessionsRequest) *sessionFilter {
	f := &sessionFilter{
		zoneFilter:  uint16(req.Zone),
		protoFilter: req.Protocol,
		srcPort:     uint16(req.SourcePort),
		dstPort:     uint16(req.DestinationPort),
		// NOTE: every invalid-input branch below must set f.inputErr
		// instead of silently zeroing the predicate. The clear path
		// shares this matcher: a request like source_port=65536 or
		// source_prefix=10.0.0.300 carries a non-empty filter (so the
		// clear-all guard is bypassed) but a zeroed predicate would
		// match EVERY session — a filtered clear degrading to
		// clear-all (Codex r2 Critical).
		natOnly:      req.NatOnly,
		appFilter:    req.Application,
		ifaceFilter:  req.InterfaceFilter,
		snatPool:     req.SourceNatPool,
		cfg:          s.store.ActiveConfig(),
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16]string),
		egressIfaces: make(map[sessionEgressKey]string),
	}
	f.hasFilters = f.zoneFilter != 0 || f.protoFilter != "" || req.SourcePrefix != "" ||
		req.DestinationPrefix != "" || f.srcPort != 0 || f.dstPort != 0 ||
		f.natOnly || f.appFilter != "" || f.ifaceFilter != "" || f.snatPool != ""
	if f.snatPool != "" && f.cfg != nil {
		f.snatPoolNets, f.snatPoolOK = config.SourceNATPoolNets(&f.cfg.Security.NAT, f.snatPool)
	}
	if req.Zone > 65535 {
		f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid zone id %d", req.Zone))
	}
	if req.SourcePort > 65535 {
		f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid source port %d", req.SourcePort))
	}
	if req.DestinationPort > 65535 {
		f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid destination port %d", req.DestinationPort))
	}
	// Validate the protocol token. protoFilterMatches returns false for
	// an unparseable token (e.g. "tcpip"), so an invalid protocol would
	// otherwise iterate to an empty list and return as a *successful*
	// RPC — indistinguishable from "no such sessions". Reject it here so
	// the predicate is never silently inert (and, on the shared clear
	// path, so a typo'd protocol never widens to clear-all) (#3439 L2).
	if f.protoFilter != "" {
		if _, ok := appid.ProtocolNumberLenient(f.protoFilter); !ok {
			f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid protocol %q", f.protoFilter))
		}
	}

	// Parse CIDR prefix filters.
	if req.SourcePrefix != "" {
		n, err := parseSessionPrefix(req.SourcePrefix)
		if err != nil {
			f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid source prefix %q", req.SourcePrefix))
		}
		f.srcNet = n
	}
	if req.DestinationPrefix != "" {
		n, err := parseSessionPrefix(req.DestinationPrefix)
		if err != nil {
			f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid destination prefix %q", req.DestinationPrefix))
		}
		f.dstNet = n
	}

	// Build zone/policy/app name maps.
	cr := s.applyResult()
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			f.zoneNames[id] = name
		}
		f.policyNames = cr.PolicyNames
		f.appNames = cr.AppNames
	}
	if f.cfg != nil && cr != nil {
		for zoneName, zone := range f.cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
				f.zoneIfaces[zid] = zone.Interfaces[0]
			}
		}
		// RangeInterfaces/RangeUnits skip present-but-nil InterfaceConfig/
		// InterfaceUnit slots admitted by the tolerant load / HA config-sync
		// path (#3494/#5068); a raw range nil-derefs and panics the in-process
		// daemon during a remote session display (#5813).
		config.RangeInterfaces(f.cfg, func(ifName string, ifc *config.InterfaceConfig) {
			resolvedParent := config.LinuxIfName(strings.SplitN(f.cfg.ResolveReth(ifName), ".", 2)[0])
			parentLink, err := net.InterfaceByName(resolvedParent)
			if err != nil {
				return
			}
			config.RangeUnits(ifc, func(_ int, unit *config.InterfaceUnit) {
				displayName := ifName
				if unit.Number != 0 || unit.VlanID != 0 {
					displayName = fmt.Sprintf("%s.%d", ifName, unit.Number)
				}
				vlanID := uint16(unit.VlanID)
				if vlanID == 0 && unit.Number > 0 {
					vlanID = uint16(unit.Number)
				}
				key := sessionEgressKey{
					ifindex: uint32(parentLink.Index),
					vlanID:  vlanID,
				}
				if _, exists := f.egressIfaces[key]; !exists {
					f.egressIfaces[key] = displayName
				}
			})
		})
	}
	return f
}

func (f *sessionFilter) matchV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if val.IsReverse != 0 {
		return false
	}
	if f.zoneFilter != 0 && val.IngressZone != f.zoneFilter && val.EgressZone != f.zoneFilter {
		return false
	}
	if f.protoFilter != "" && !protoFilterMatches(key.Protocol, f.protoFilter) {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if f.srcPort != 0 && ntohs(key.SrcPort) != f.srcPort {
		return false
	}
	if f.dstPort != 0 && ntohs(key.DstPort) != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if f.appFilter != "" && !appid.SessionMatches(f.appFilter, f.appNames, f.cfg,
		key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
		return false
	}
	if f.ifaceFilter != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, f.zoneIfaces, f.egressIfaces)
		if !sessionIfaceMatches(f.ifaceFilter, inIf) && !sessionIfaceMatches(f.ifaceFilter, outIf) {
			return false
		}
	}
	if f.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 ||
			!config.IPInNets(uint32ToIP(val.NATSrcIP), f.snatPoolNets) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) matchV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if val.IsReverse != 0 {
		return false
	}
	if f.zoneFilter != 0 && val.IngressZone != f.zoneFilter && val.EgressZone != f.zoneFilter {
		return false
	}
	if f.protoFilter != "" && !protoFilterMatches(key.Protocol, f.protoFilter) {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if f.srcPort != 0 && ntohs(key.SrcPort) != f.srcPort {
		return false
	}
	if f.dstPort != 0 && ntohs(key.DstPort) != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if f.appFilter != "" && !appid.SessionMatches(f.appFilter, f.appNames, f.cfg,
		key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
		return false
	}
	if f.ifaceFilter != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, f.zoneIfaces, f.egressIfaces)
		if !sessionIfaceMatches(f.ifaceFilter, inIf) && !sessionIfaceMatches(f.ifaceFilter, outIf) {
			return false
		}
	}
	if f.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 ||
			!config.IPInNets(net.IP(val.NATSrcIP[:]), f.snatPoolNets) {
			return false
		}
	}
	return true
}

// fetchPeerSessions fetches sessions from the cluster peer if requested.
func (s *Server) fetchPeerSessions(ctx context.Context, req *pb.GetSessionsRequest, resp *pb.GetSessionsResponse) {
	if !req.GetIncludePeer() || s.cluster == nil || !s.cluster.PeerAlive() {
		return
	}
	// When paginating via page_token, suppress peer results — the caller
	// is on a later local page but the peer would return its first page,
	// producing misleading mixed-page responses. Peer sessions should
	// only be fetched on the first page (no token).
	if req.GetPageToken() != "" {
		return
	}
	conn, err := s.dialPeer()
	if err != nil {
		slog.Warn("failed to dial peer for sessions", "err", err)
		return
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	peerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Forward all filters but NOT include_peer — prevents recursion.
	peerReq := &pb.GetSessionsRequest{
		Limit:             req.Limit,
		Offset:            req.Offset,
		Zone:              req.Zone,
		Protocol:          req.Protocol,
		SourcePrefix:      req.SourcePrefix,
		DestinationPrefix: req.DestinationPrefix,
		SourcePort:        req.SourcePort,
		DestinationPort:   req.DestinationPort,
		NatOnly:           req.NatOnly,
		Application:       req.Application,
		InterfaceFilter:   req.InterfaceFilter,
		SourceNatPool:     req.SourceNatPool,
		// Do NOT forward PageToken to peer — tokens encode local BPF map
		// keys and are meaningless on a different node's keyspace. Peer
		// always returns its full (first-page) result set.
		PageSize: req.PageSize,
		NoEnrich: req.NoEnrich,
	}
	peerResp, err := client.GetSessions(peerCtx, peerReq)
	if err != nil {
		slog.Warn("failed to fetch peer sessions", "err", err)
	} else {
		// #6851/#4626: the peer resolved these policy NAMES itself, so a peer
		// running a pre-#4626 build sent the name of ITS first configured
		// policy for every session carrying the reserved id 0 — host-inbound,
		// fabric, tunnel, and its entire table if IT is in turn syncing from an
		// older node. The #4626 guard covers rows THIS node renders from a raw
		// id; it does not cover a name arriving as DATA. Without this, the
		// misattribution is republished unchanged on every local surface: gRPC
		// clients, the REST `peer` block (sessionListFromPB), and the CLI.
		//
		// Only RESERVED ids are overridden — see PeerSessionPolicyName for why
		// re-resolving an unreserved peer id against the LOCAL map would be a
		// fresh misattribution rather than a fix.
		//
		// This is the choke point for the gRPC and REST surfaces: REST reaches
		// the peer through this same in-process response (writeSessionList
		// reads `pr.GetPeer()`), so guarding here covers both at once.
		//
		// It does NOT cover the on-box interactive CLI (#6851). `pkg/cli`
		// dials the peer daemon itself (session_filter.go dialPeer) and sets no
		// IncludePeer, so it neither passes through here nor triggers the
		// peer's own fan-out. That surface sanitizes at its own ingress —
		// sanitizePeerSessionPolicyNames — for the same reason and via the same
		// dataplane.PeerSessionPolicyName decision. Two call sites, one
		// decision function: a third normalization rule is what would rot.
		// The REMOTE cli binary is not a third case; it sets IncludePeer and
		// arrives here.
		attachPeerSessions(resp, peerResp)
	}
}

// attachPeerSessions sanitizes a fan-out response's policy names and attaches
// it (#6851).
//
// The ATTACH lives inside the sanitizing function deliberately. Keeping them as
// two statements at the call site would let a future edit drop the guard while
// leaving the attach — the failure mode this whole PR is about, silent and
// green. Fused, the two cannot be separated by deleting a line.
//
// SCOPED (#6851 review): "fused" is a shape argument, not an enforced one.
// `attachPeerSessions(resp, nil)` on its own does NOT compile — peerResp goes
// unused — but with `_ = peerResp` beside it the whole suite passes while every
// peer session is dropped from all three surfaces. So this reads as loud to an
// OPERATOR (peer rows vanish), not to CI. Do not cite it as test-enforced.
//
// Residual, stated rather than implied: the tests below drive this function, so
// they bind the sanitize-and-attach pair. They do NOT bind `fetchPeerSessions`'
// call TO it — that needs a live cluster.Manager with PeerAlive() plus a real
// authenticated peer dial, neither of which is reachable from a unit test.
// Replacing this call with a bare `resp.Peer = peerResp` would not be caught
// here.
func attachPeerSessions(resp, peerResp *pb.GetSessionsResponse) {
	sanitizePeerPolicyNames(peerResp)
	resp.Peer = peerResp
}

// sanitizePeerPolicyNames rewrites the policy name of every peer session whose
// id is reserved, in place.
func sanitizePeerPolicyNames(peerResp *pb.GetSessionsResponse) {
	if peerResp == nil {
		return
	}
	for _, e := range peerResp.GetSessions() {
		if e == nil {
			continue
		}
		e.PolicyName = dataplane.PeerSessionPolicyName(e.GetPolicyName(), e.GetPolicyId())
	}
	// A peer that itself fanned out (it should not — include_peer is not
	// forwarded, precisely to prevent recursion) would nest another response
	// here. Guard it rather than assume the invariant holds across versions.
	sanitizePeerPolicyNames(peerResp.GetPeer())
}

// getSessionsLegacy is the original limit/offset iteration path.
func (s *Server) getSessionsLegacy(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}
	// req.Offset (signed int32) is validated for negativity centrally in
	// GetSessions before path dispatch (#3439 L2).
	offset := int(req.Offset)
	noEnrich := req.NoEnrich

	filter := s.buildSessionFilter(req)
	if err := filter.validate(); err != nil {
		return nil, err
	}
	now := monotonicSeconds()
	all := make([]*pb.SessionEntry, 0, limit)
	idx := 0

	// Determine HA state for session display.
	haActive := true // standalone default
	if s.cluster != nil {
		haActive = s.cluster.IsLocalPrimary(0)
	}

	// A backend iterator error (e.g. helper restart mid-scan) must fail
	// the RPC rather than returning a partial session list as success —
	// matching the cursor path above (#2469).
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if !filter.matchV4(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			if !noEnrich {
				// Merge counters from reverse entry.
				if rev, err := s.dp.GetSessionV4(val.ReverseKey); err == nil {
					val.RevPackets += rev.RevPackets
					val.RevBytes += rev.RevBytes
					val.FwdPackets += rev.FwdPackets
					val.FwdBytes += rev.FwdBytes
				}
			}
			se := sessionEntryV4(key, val, now, filter.zoneNames, filter.policyNames, filter.zoneIfaces, filter.egressIfaces, haActive)
			if !noEnrich {
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
		}
		idx++
		return true
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "v4 session iteration: %v", err)
	}

	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if !filter.matchV6(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			if !noEnrich {
				if rev, err := s.dp.GetSessionV6(val.ReverseKey); err == nil {
					val.RevPackets += rev.RevPackets
					val.RevBytes += rev.RevBytes
					val.FwdPackets += rev.FwdPackets
					val.FwdBytes += rev.FwdBytes
				}
			}
			se := sessionEntryV6(key, val, now, filter.zoneNames, filter.policyNames, filter.zoneIfaces, filter.egressIfaces, haActive)
			if !noEnrich {
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
		}
		idx++
		return true
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "v6 session iteration: %v", err)
	}

	resp := &pb.GetSessionsResponse{
		Total:    int32(idx),
		Limit:    int32(limit),
		Offset:   int32(offset),
		Sessions: all,
	}

	s.setSessionsNodeID(resp)
	s.fetchPeerSessions(ctx, req, resp)
	return resp, nil
}

func (s *Server) GetSessionSummary(ctx context.Context, req *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	// Admission bound (#5708, codex-review-182 M35): the summary is an
	// unconditional full v4+v6 conntrack-table walk (same per-bucket BPF-map
	// lock contention as the list). Gate it through the SAME shared limiter as
	// GetSessions and the REST scans so a gRPC scrape flood cannot drive
	// unbounded concurrent walks. Release on every exit path via defer.
	//
	// #5880: AcquireCtx reuses an in-process admission lease so a REST
	// summary handler delegating here for include_peer does not double-charge
	// the limiter; a direct external gRPC caller acquires once as before.
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	resp := &pb.GetSessionSummaryResponse{}

	// Set node ID from cluster manager (0 if standalone).
	if s.cluster != nil {
		resp.NodeId = int32(s.cluster.NodeID())
	}

	// A partial scan under-counts the summary; fail the RPC rather than
	// returning a healthy-looking but incomplete summary (#2469).
	if err := s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		resp.TotalEntries++
		if val.IsReverse == 0 {
			resp.ForwardOnly++
			resp.Ipv4Sessions++
			if val.State == dataplane.SessStateEstablished {
				resp.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				resp.SnatSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				resp.DnatSessions++
			}
		}
		return true
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "v4 session iteration: %v", err)
	}

	if err := s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		resp.TotalEntries++
		if val.IsReverse == 0 {
			resp.ForwardOnly++
			resp.Ipv6Sessions++
			if val.State == dataplane.SessStateEstablished {
				resp.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				resp.SnatSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				resp.DnatSessions++
			}
		}
		return true
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "v6 session iteration: %v", err)
	}

	// max_sessions is the dataplane's dynamic session-table capacity (#5323):
	// the live AF_XDP helper publishes worker_count x per-worker capacity. A
	// dataplane with no userspace status surface leaves it 0 = unknown, so a
	// consumer renders "unknown" rather than the old hardcoded 10000000.
	if st, err := s.userspaceDataplaneStatus(); err == nil {
		resp.MaxSessions = st.MaxSessions
	}

	// Fetch peer summary if requested (#5320). A peer-fetch failure is now
	// classified as UNREACHABLE (visible incompleteness) instead of being
	// logged and swallowed with peer=nil, which was indistinguishable from a
	// healthy standalone node. The local totals are still returned — the local
	// view is useful — but the response says whether it is complete.
	if req.GetIncludePeer() {
		peerResp, perr := s.proxyPeerSessionSummary(ctx)
		switch {
		case perr != nil:
			slog.Warn("failed to fetch peer session summary", "err", perr)
			resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE
			resp.PeerError = perr.Error()
		case peerResp != nil:
			resp.Peer = peerResp
			resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_OK
		default:
			// (nil, nil): standalone node (NOT_APPLICABLE) or a clustered node
			// whose peer heartbeat is currently lost (UNREACHABLE — a partition,
			// not standalone).
			resp.PeerStatus = s.peerAbsentStatus()
		}
	} else {
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE
	}

	return resp, nil
}

// peerAbsentStatus classifies a (nil, nil) peer fetch (#5320): a genuinely
// standalone node (no cluster manager) is NOT_APPLICABLE, while a cluster node
// whose peer is currently not alive is UNREACHABLE — its summary is LOCAL-ONLY
// and understates cluster-wide state, so the incompleteness must be visible.
func (s *Server) peerAbsentStatus() pb.PeerFetchStatus {
	if s.cluster != nil && !s.cluster.PeerAlive() {
		return pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE
	}
	return pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE
}

// proxyPeerSessionSummary forwards a session-summary request to the cluster
// peer for the include_peer fan-out (#5320), mirroring proxyPeerZonePairSummary.
// A wired peerSessionSummaryFn (test seam) takes precedence; otherwise it dials
// the peer only when one is alive, returning (nil, nil) for a standalone node /
// dead peer so the caller can classify the absence. The forwarded request
// carries include_peer=false so the peer answers from its local table without
// recursing back.
func (s *Server) proxyPeerSessionSummary(ctx context.Context) (*pb.GetSessionSummaryResponse, error) {
	if s.peerSessionSummaryFn != nil {
		return s.peerSessionSummaryFn(ctx)
	}
	if s.cluster == nil || !s.cluster.PeerAlive() {
		return nil, nil
	}
	conn, err := s.dialPeer()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	peerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return pb.NewBpfrxServiceClient(conn).GetSessionSummary(peerCtx, &pb.GetSessionSummaryRequest{})
}

// GetZonePairSummary aggregates the local session table by (ingress-zone,
// egress-zone) pair with a per-protocol-class breakdown (tcp/udp/icmp/other),
// the gRPC analog of the REST sessionZonePairHandler. It exists so the REST
// zone-pair endpoint has an RPC to forward to for cross-node fan-out (#3592);
// before this RPC the breakdown was computed REST-locally with no peer path.
//
// include_peer mirrors GetSessionSummary: when set (and this is not itself a
// forwarded peer request) the local node fans out to the cluster peer and
// stamps the peer's OWN breakdown under resp.Peer. The peer request carries
// the x-peer-forwarded metadata recursion guard (proxyPeerZonePairSummary), so
// the peer answers from its local table without recursing back. A standalone
// node, an unreachable peer, or a failed peer RPC leaves resp.Peer nil (a
// read summary degrades gracefully rather than failing the whole call).
func (s *Server) GetZonePairSummary(ctx context.Context, req *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	// Admission bound (#5708, codex-review-182 M35): the zone-pair breakdown is
	// an unconditional full v4+v6 conntrack-table walk (computeZonePairSummary,
	// same per-bucket BPF-map lock contention as GetSessionSummary). Gate it
	// through the SAME shared limiter as GetSessions/GetSessionSummary and the
	// REST scans — the REST zone-pair handler is already gated, so without this
	// zone-pairs is bounded on REST but unbounded on gRPC. Release on every exit
	// path via defer; the peer fan-out below dials the peer (which gates its own
	// walk), so this holds only the local slot.
	//
	// #5880: AcquireCtx reuses an in-process admission lease so a REST zone-pair
	// handler delegating here for include_peer does not double-charge the
	// limiter; a direct external gRPC caller acquires once as before.
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	resp := &pb.GetZonePairSummaryResponse{}
	if s.cluster != nil {
		resp.NodeId = int32(s.cluster.NodeID())
	}

	pairs, err := s.computeZonePairSummary()
	if err != nil {
		return nil, err
	}
	resp.ZonePairs = pairs

	// Fan out to the peer when the operator opted in AND this is not itself a
	// forwarded peer request (recursion guard). proxyPeerZonePairSummary stamps
	// x-peer-forwarded on the outgoing context and, in production, dials the
	// peer only when one is alive; a unit test wires peerZonePairSummaryFn.
	if req.GetIncludePeer() && !peerForwardedFromContext(ctx) {
		peerResp, perr := s.proxyPeerZonePairSummary(ctx, &pb.GetZonePairSummaryRequest{})
		switch {
		case perr != nil:
			// #5320: surface the failure (UNREACHABLE) instead of swallowing it
			// with peer=nil, which looked like a healthy standalone breakdown.
			slog.Warn("failed to fetch peer zone-pair summary", "err", perr)
			resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE
			resp.PeerError = perr.Error()
		case peerResp != nil:
			resp.Peer = peerResp
			resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_OK
		default:
			resp.PeerStatus = s.peerAbsentStatus()
		}
	} else {
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE
	}

	return resp, nil
}

// computeZonePairSummary iterates the local v4+v6 session tables and returns
// the per-zone-pair protocol breakdown, sorted by (from_zone, to_zone). A
// backend iterator error fails the call rather than returning a partial,
// healthy-looking breakdown (#2469), matching GetSessionSummary.
func (s *Server) computeZonePairSummary() ([]*pb.ZonePairSessionSummary, error) {
	zoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}

	type zpKey struct{ from, to uint16 }
	counts := make(map[zpKey]*pb.ZonePairSessionSummary)

	countSession := func(inZone, outZone uint16, proto uint8) {
		k := zpKey{inZone, outZone}
		zp, ok := counts[k]
		if !ok {
			zp = &pb.ZonePairSessionSummary{
				FromZone: zoneNames[inZone],
				ToZone:   zoneNames[outZone],
			}
			if zp.FromZone == "" {
				zp.FromZone = fmt.Sprintf("zone-%d", inZone)
			}
			if zp.ToZone == "" {
				zp.ToZone = fmt.Sprintf("zone-%d", outZone)
			}
			counts[k] = zp
		}
		switch proto {
		case 6:
			zp.Tcp++
		case 17:
			zp.Udp++
		case 1, dataplane.ProtoICMPv6:
			zp.Icmp++
		default:
			zp.Other++
		}
		zp.Total++
	}

	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "v4 session iteration: %v", err)
	}
	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "v6 session iteration: %v", err)
	}

	result := make([]*pb.ZonePairSessionSummary, 0, len(counts))
	for _, zp := range counts {
		result = append(result, zp)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FromZone != result[j].FromZone {
			return result[i].FromZone < result[j].FromZone
		}
		return result[i].ToZone < result[j].ToZone
	})
	return result, nil
}

// proxyPeerZonePairSummary forwards a zone-pair summary request to the cluster
// peer, stamping x-peer-forwarded so the peer does not fan back out (#3592).
// It mirrors proxyPeerSystemAction: a wired peerZonePairSummaryFn (test seam)
// takes precedence; otherwise it dials the peer only when one is alive,
// returning (nil, nil) for a standalone node / dead peer so the caller leaves
// resp.Peer nil without logging a spurious failure.
func (s *Server) proxyPeerZonePairSummary(ctx context.Context, req *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
	peerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	peerCtx = metadata.AppendToOutgoingContext(peerCtx, "x-peer-forwarded", "1")
	if s.peerZonePairSummaryFn != nil {
		return s.peerZonePairSummaryFn(peerCtx, req)
	}
	if s.cluster == nil || !s.cluster.PeerAlive() {
		return nil, nil
	}
	conn, err := s.dialPeer()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return pb.NewBpfrxServiceClient(conn).GetZonePairSummary(peerCtx, req)
}

func (s *Server) ClearSessions(ctx context.Context, req *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	// Admission bound (#5779): ClearSessions drives a full v4+v6 conntrack-table
	// walk on BOTH branches — the clear-all path (ClearAllSessions is a chunked
	// full-table scan+delete, not O(1)) and the filtered path
	// (clearFilteredSessionsV4/V6, cursor or rescan) — each holding per-bucket
	// BPF-map locks that contend with the live session-sync path. This is the
	// same DoS class as the #5708 read scans, on the mutation path. Gate the
	// whole handler through the SAME shared limiter as the read scans; acquire
	// ONCE here so both branches (and the peer fan-out below) draw a single
	// slot, and a REST clear that delegates to this RPC is not double-charged.
	// Over-cap clears get codes.ResourceExhausted. There is no keyed
	// single-session (no-walk) branch in ClearSessions to exempt. Release on
	// every exit path via defer.
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	// Check if this is a forwarded request from a peer (prevent recursion).
	forwarded := false
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-peer-forwarded"); len(vals) > 0 {
			forwarded = true
		}
	}

	// If no filters, clear all
	if req.SourcePrefix == "" && req.DestinationPrefix == "" &&
		req.Protocol == "" && req.Zone == "" &&
		req.SourcePort == 0 && req.DestinationPort == 0 &&
		req.Application == "" && req.Interface == "" &&
		!req.NatOnly && req.SourceNatPool == "" {
		v4, v6, err := s.dp.ClearAllSessions()
		var agg clearErrors
		// Chunked clear-all is NON-atomic (#5882): ClearAllSessions walks and
		// deletes the IPv4 table, THEN the IPv6 table (clearSessionsChunkedV4
		// then …V6 in maps_session.go), so a V6-phase failure can leave IPv4
		// already fully deleted. ClearAllSessions returns the PARTIAL v4/v6
		// counts alongside the error, so surface them via the response
		// Failures / FailureSummary instead of discarding them behind a bare
		// RPC error — EXACTLY as the filtered clear path below does. An
		// operator/monitor then learns what was actually revoked (e.g. IPv4
		// cleared, IPv6 failed → retry only IPv6) instead of "0 cleared + hard
		// error". agg.add ignores a nil err, so the success path is unchanged
		// (Failures==0, accurate counts).
		agg.add("clear-all", err)
		if !forwarded {
			agg.add("peer clear", s.clearPeerSessions(req))
		}
		resp := &pb.ClearSessionsResponse{
			Ipv4Cleared: int32(v4),
			Ipv6Cleared: int32(v6),
		}
		agg.apply(resp)
		return resp, nil
	}

	// Build the SAME filter the show path uses (matchV4/matchV6) so
	// show and clear can never diverge (#1827 PR-3). This also fixes
	// the former inline filter comparing network-order key ports to
	// host-order request ports, and adds the interface / nat-only /
	// source-nat-pool filters the CLI advertises.
	getReq := &pb.GetSessionsRequest{
		Protocol:          req.Protocol,
		SourcePrefix:      req.SourcePrefix,
		DestinationPrefix: req.DestinationPrefix,
		SourcePort:        req.SourcePort,
		DestinationPort:   req.DestinationPort,
		NatOnly:           req.NatOnly,
		Application:       req.Application,
		InterfaceFilter:   req.Interface,
		SourceNatPool:     req.SourceNatPool,
	}
	if req.Zone != "" {
		// An unresolvable zone must fail the RPC: leaving the zone ID
		// at 0 would silently widen the clear to every zone.
		var zoneID uint16
		if cr := s.applyResult(); cr != nil {
			zoneID = cr.ZoneIDs[req.Zone]
		}
		if zoneID == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "zone %q not found", req.Zone)
		}
		getReq.Zone = uint32(zoneID)
	}
	filter := s.buildSessionFilter(getReq)
	if err := filter.validate(); err != nil {
		return nil, err
	}

	var agg clearErrors

	// Clear matching IPv4 + IPv6 sessions with a BOUNDED handler working set
	// (#5454). The pre-#5454 path materialized EVERY matching forward key,
	// reverse companion, and DNAT companion into unbounded slices before the
	// first delete — O(N) handler-goroutine allocation where N is up to the
	// full (multi-million entry) session table. ClearSessions is fabric-
	// reachable (fabricAllowedUnaryMethods), so a PSK-holding peer could
	// trigger a broad filtered clear that retained hundreds of MB and stalled
	// the control-plane GC / OOM-killed the daemon. The helpers below hold at
	// most O(clearFilteredBatch) keys regardless of how many sessions match.
	v4Deleted := s.clearFilteredSessionsV4(ctx, filter, &agg)
	v6Deleted := s.clearFilteredSessionsV6(ctx, filter, &agg)

	if !forwarded {
		agg.add("peer clear", s.clearPeerSessions(req))
	}
	resp := &pb.ClearSessionsResponse{
		Ipv4Cleared: int32(v4Deleted),
		Ipv6Cleared: int32(v6Deleted),
	}
	agg.apply(resp)
	return resp, nil
}

// clearFilteredBatch bounds the number of matching session keys the filtered
// ClearSessions path holds in the handler goroutine at once (#5454). The
// session table can hold millions of entries; the pre-#5454 path collected
// every match (forward + reverse + DNAT keys) before deleting, an O(matches)
// allocation a fabric-reachable caller could weaponize. Collection now stops at
// this many forward keys, deletes that chunk, and resumes, so peak key-slice
// memory is O(clearFilteredBatch), not O(matches). It is a var (not const) so a
// test can shrink it to exercise the multi-chunk path with a small table.
var clearFilteredBatch = 1024

// clearFilteredBatchObserver, when non-nil, is invoked once per collected key
// chunk with len(chunk) (the forward-key count). It is a test-only seam that
// lets a unit test assert the filtered clear collects keys in bounded chunks
// instead of one N-sized slice (#5454). A revert to the collect-all-then-delete
// path reports a single len==matches chunk, so the bounded-working-set
// assertion goes RED. Production leaves it nil.
var clearFilteredBatchObserver func(chunkLen int)

// clearBatchV4 accumulates one bounded chunk of matching v4 session keys plus
// each matched session's reverse and DNAT companion keys, then deletes them.
type clearBatchV4 struct {
	fwd  []dataplane.SessionKey
	rev  []dataplane.SessionKey
	dnat []dataplane.DNATKey
}

func (b *clearBatchV4) reset() {
	b.fwd = b.fwd[:0]
	b.rev = b.rev[:0]
	b.dnat = b.dnat[:0]
}

// collect appends a matched session's forward key plus its reverse and DNAT
// companions, mirroring the exact key construction the pre-#5454 inline path
// used: the reverse companion is keyed on the TRANSLATED tuple val.ReverseKey
// (NOT a naive src/dst swap — #2733), skipped when ReverseKey.Protocol == 0
// (no companion installed); the DNAT companion key uses the write-side host-
// order encoding (#2406) and only for dynamic (non-static) SNAT sessions.
// Returns true once the forward chunk has reached clearFilteredBatch.
func (b *clearBatchV4) collect(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	b.fwd = append(b.fwd, key)
	if val.ReverseKey.Protocol != 0 {
		b.rev = append(b.rev, val.ReverseKey)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 &&
		val.Flags&dataplane.SessFlagStaticNAT == 0 {
		b.dnat = append(b.dnat, dataplane.DNATKeyForSessionV4(key, val))
	}
	return len(b.fwd) >= clearFilteredBatch
}

// deleteAll deletes the collected forward keys (counting successes), reverse
// companions, and DNAT companions, aggregating failures exactly as the
// pre-#5454 inline path did (a benign ErrKeyNotExist on the computed reverse /
// DNAT companion of a NAT'd session is not a failure — #2468). Returns the
// number of forward sessions successfully deleted.
func (b *clearBatchV4) deleteAll(s *Server, agg *clearErrors) int {
	deleted := 0
	for _, key := range b.fwd {
		err := s.dp.DeleteSession(key)
		if err == nil {
			deleted++
			continue
		}
		// A forward key already gone is benign here (GC race / anchor-restart
		// re-collect — see addExceptNotFound): not our delete, not a failure.
		agg.addExceptNotFound("v4 forward delete", err)
	}
	for _, key := range b.rev {
		agg.addExceptNotFound("v4 reverse delete", s.dp.DeleteSession(key))
	}
	for _, dk := range b.dnat {
		agg.addExceptNotFound("v4 DNAT companion delete", s.dp.DeleteDNATEntry(dk))
	}
	return deleted
}

// clearFilteredSessionsV4 deletes every v4 session matching filter, plus each
// matched session's reverse and DNAT companion, while holding at most
// O(clearFilteredBatch) keys in the handler goroutine (#5454). It returns the
// number of forward sessions deleted and records sub-operation failures on agg.
//
// Iterate-delete safety: the session table is a cilium/ebpf HASH map. Deleting
// the just-returned key from inside a live Map.Iterate() is UNSAFE — the next
// BPF_MAP_GET_NEXT_KEY on the now-absent key restarts iteration from the first
// bucket (kernel htab_map_get_next_key), so the iterator can repeat keys, skip
// keys, or abort with ErrIterationAborted (see cilium/ebpf MapIterator.Next).
// We therefore never delete during a live iterate: we collect a bounded chunk
// of matching keys and delete it only AFTER the iterate call returns.
//
// To keep the whole clear a single O(N) forward pass — rather than the O(N^2)
// a per-chunk fresh re-scan would cost when a filter matches a large fraction
// of a multi-million-entry table, which would trade the memory DoS for a CPU-
// stall DoS able to starve the HA watchdog (#4719) — we resume via
// IterateSessionsFrom from a LIVE anchor: the last key of the previous chunk is
// deliberately left undeleted so the cursor anchored on it stays valid, and it
// is deleted one round later once the cursor has advanced past it. A dataplane
// without cursor iteration (test/edge only — production's LegacyDataPlaneAdapter
// always implements it, compile-asserted in pkg/dataplane/userspace) falls back
// to a bounded fresh-rescan.
func (s *Server) clearFilteredSessionsV4(ctx context.Context, filter *sessionFilter, agg *clearErrors) int {
	iterDP, ok := s.dpProbe().(sessionCursorIterator)
	if !ok {
		return s.clearFilteredSessionsV4Rescan(ctx, filter, agg)
	}
	deleted := 0
	var a, b clearBatchV4
	cur, prev := &a, &b
	prevValid := false // prev holds the previous chunk, deferred for delete
	var cursor *dataplane.SessionKey
	for {
		if ctx.Err() != nil {
			if prevValid {
				deleted += prev.deleteAll(s, agg)
			}
			agg.add("v4 clear canceled", ctx.Err())
			return deleted
		}
		cur.reset()
		examined := 0
		canceled := false
		iterErr := iterDP.IterateSessionsFrom(cursor, func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			examined++
			if examined&0x3ff == 0 && ctx.Err() != nil {
				canceled = true
				return false // long non-matching run: stop promptly on cancel
			}
			if !filter.matchV4(key, val) {
				return true
			}
			return !cur.collect(key, val) // stop once the chunk is full
		})
		agg.add("v4 iterate", iterErr)
		if clearFilteredBatchObserver != nil {
			clearFilteredBatchObserver(len(cur.fwd))
		}
		// The previous chunk's anchor stayed live through this iterate (we
		// resumed from it), so it is safe to delete now that the call returned.
		if prevValid {
			deleted += prev.deleteAll(s, agg)
			prevValid = false
		}
		full := len(cur.fwd) >= clearFilteredBatch && iterErr == nil && !canceled
		if !full {
			deleted += cur.deleteAll(s, agg)
			if canceled {
				agg.add("v4 clear canceled", ctx.Err())
			}
			return deleted
		}
		// Carry this chunk (including its last key, the anchor) to the next
		// round; resume from the anchor, left undeleted so the cursor stays
		// valid. Ping-pong the two buffers so peak memory is O(chunk).
		anchor := cur.fwd[len(cur.fwd)-1]
		cursor = &anchor
		cur, prev = prev, cur
		prevValid = true
	}
}

// clearFilteredSessionsV4Rescan is the bounded fallback for a dataplane that
// does not implement cursor iteration (test/edge only). It collects up to
// clearFilteredBatch matching keys via a fresh full iterate (stopping before
// any delete, so no delete-during-iterate), deletes that chunk, then re-scans:
// because every collected key was deleted, a fresh scan returns the next chunk,
// so the loop converges while holding only O(chunk) keys.
func (s *Server) clearFilteredSessionsV4Rescan(ctx context.Context, filter *sessionFilter, agg *clearErrors) int {
	deleted := 0
	var b clearBatchV4
	for {
		if ctx.Err() != nil {
			agg.add("v4 clear canceled", ctx.Err())
			return deleted
		}
		b.reset()
		iterErr := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if !filter.matchV4(key, val) {
				return true
			}
			return !b.collect(key, val)
		})
		agg.add("v4 iterate", iterErr)
		if clearFilteredBatchObserver != nil {
			clearFilteredBatchObserver(len(b.fwd))
		}
		if len(b.fwd) == 0 {
			return deleted
		}
		deleted += b.deleteAll(s, agg)
		// A short chunk (or an iterate error) means the scan reached the end.
		if len(b.fwd) < clearFilteredBatch || iterErr != nil {
			return deleted
		}
	}
}

// clearBatchV6 is the IPv6 analogue of clearBatchV4.
type clearBatchV6 struct {
	fwd  []dataplane.SessionKeyV6
	rev  []dataplane.SessionKeyV6
	dnat []dataplane.DNATKeyV6
}

func (b *clearBatchV6) reset() {
	b.fwd = b.fwd[:0]
	b.rev = b.rev[:0]
	b.dnat = b.dnat[:0]
}

func (b *clearBatchV6) collect(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	b.fwd = append(b.fwd, key)
	if val.ReverseKey.Protocol != 0 {
		b.rev = append(b.rev, val.ReverseKey)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 &&
		val.Flags&dataplane.SessFlagStaticNAT == 0 {
		b.dnat = append(b.dnat, dataplane.DNATKeyForSessionV6(key, val))
	}
	return len(b.fwd) >= clearFilteredBatch
}

func (b *clearBatchV6) deleteAll(s *Server, agg *clearErrors) int {
	deleted := 0
	for _, key := range b.fwd {
		err := s.dp.DeleteSessionV6(key)
		if err == nil {
			deleted++
			continue
		}
		// Already-gone forward key is benign here (see clearBatchV4.deleteAll).
		agg.addExceptNotFound("v6 forward delete", err)
	}
	for _, key := range b.rev {
		agg.addExceptNotFound("v6 reverse delete", s.dp.DeleteSessionV6(key))
	}
	for _, dk := range b.dnat {
		agg.addExceptNotFound("v6 DNAT companion delete", s.dp.DeleteDNATEntryV6(dk))
	}
	return deleted
}

// clearFilteredSessionsV6 is the IPv6 analogue of clearFilteredSessionsV4; see
// that function for the iterate-delete-safety and bounded-cursor rationale.
func (s *Server) clearFilteredSessionsV6(ctx context.Context, filter *sessionFilter, agg *clearErrors) int {
	iterDP, ok := s.dpProbe().(sessionCursorIterator)
	if !ok {
		return s.clearFilteredSessionsV6Rescan(ctx, filter, agg)
	}
	deleted := 0
	var a, b clearBatchV6
	cur, prev := &a, &b
	prevValid := false
	var cursor *dataplane.SessionKeyV6
	for {
		if ctx.Err() != nil {
			if prevValid {
				deleted += prev.deleteAll(s, agg)
			}
			agg.add("v6 clear canceled", ctx.Err())
			return deleted
		}
		cur.reset()
		examined := 0
		canceled := false
		iterErr := iterDP.IterateSessionsV6From(cursor, func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			examined++
			if examined&0x3ff == 0 && ctx.Err() != nil {
				canceled = true
				return false
			}
			if !filter.matchV6(key, val) {
				return true
			}
			return !cur.collect(key, val)
		})
		agg.add("v6 iterate", iterErr)
		if clearFilteredBatchObserver != nil {
			clearFilteredBatchObserver(len(cur.fwd))
		}
		if prevValid {
			deleted += prev.deleteAll(s, agg)
			prevValid = false
		}
		full := len(cur.fwd) >= clearFilteredBatch && iterErr == nil && !canceled
		if !full {
			deleted += cur.deleteAll(s, agg)
			if canceled {
				agg.add("v6 clear canceled", ctx.Err())
			}
			return deleted
		}
		anchor := cur.fwd[len(cur.fwd)-1]
		cursor = &anchor
		cur, prev = prev, cur
		prevValid = true
	}
}

// clearFilteredSessionsV6Rescan is the bounded fallback analogue of
// clearFilteredSessionsV4Rescan.
func (s *Server) clearFilteredSessionsV6Rescan(ctx context.Context, filter *sessionFilter, agg *clearErrors) int {
	deleted := 0
	var b clearBatchV6
	for {
		if ctx.Err() != nil {
			agg.add("v6 clear canceled", ctx.Err())
			return deleted
		}
		b.reset()
		iterErr := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if !filter.matchV6(key, val) {
				return true
			}
			return !b.collect(key, val)
		})
		agg.add("v6 iterate", iterErr)
		if clearFilteredBatchObserver != nil {
			clearFilteredBatchObserver(len(b.fwd))
		}
		if len(b.fwd) == 0 {
			return deleted
		}
		deleted += b.deleteAll(s, agg)
		if len(b.fwd) < clearFilteredBatch || iterErr != nil {
			return deleted
		}
	}
}

// clearPeerSessions forwards a ClearSessions request to the cluster peer.
// Uses x-peer-forwarded metadata to prevent infinite recursion. Returns
// a non-nil error if the peer is unreachable or its clear failed so the
// caller can report the partial success (#2468) rather than silently
// leaving the peer holding the sessions. The error names the PEER NODE so
// the failure_summary is operator-actionable (#3423) — a bare "dial peer"
// did not say which node still holds uncleared sessions.
//
// A standalone node (no cluster manager) has no peer to clear and
// returns nil — not a failure.
func (s *Server) clearPeerSessions(req *pb.ClearSessionsRequest) error {
	if s.cluster == nil {
		return nil
	}
	peerID := s.peerNodeIDForMsg()
	conn, err := s.dialPeer()
	if err != nil {
		return fmt.Errorf("dial peer node %d: %w", peerID, err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	if _, err := pb.NewBpfrxServiceClient(conn).ClearSessions(ctx, req); err != nil {
		return fmt.Errorf("peer node %d ClearSessions: %w", peerID, err)
	}
	return nil
}

// peerNodeIDForMsg returns the cluster peer's node id for operator-facing
// failure messages (#3423). PeerNodeID() is authoritative once a heartbeat
// has been seen; before that it defaults to the local id, so fall back to the
// deterministic other node of the two-node cluster (node ids are 0/1). The
// caller has already guarded s.cluster != nil.
func (s *Server) peerNodeIDForMsg() int {
	local := s.cluster.NodeID()
	if pid := s.cluster.PeerNodeID(); pid != local {
		return pid
	}
	return 1 - local
}

// clearErrors accumulates per-operation failures across a session clear
// without aborting the clear: enumeration, forward/reverse/companion
// deletes, and the HA peer-clear RPC each report independently so an
// operator sees the FULL failure picture instead of a bare success
// (#2468). nil errors (the common case) are ignored.
//
// The failure-STRING buffer is bounded to clearErrorsPartsCap entries with a
// trailing "…and N more" summary (#5531 review): a filtered clear over a
// multi-million-entry table could, in a degenerate cause (e.g. a GC race that
// re-collects and re-deletes keys), otherwise accumulate O(matches) failure
// strings — a residual unbounded-memory path this fix exists to close. count
// stays exact (a cheap int) so Failures is still honest; only the string slice
// is capped.
type clearErrors struct {
	count    int
	parts    []string
	overflow int // failures beyond clearErrorsPartsCap, summarized as a count
}

// clearErrorsPartsCap bounds the number of distinct failure strings retained.
const clearErrorsPartsCap = 64

// add records a failed sub-operation. nil errors are no-ops.
func (e *clearErrors) add(op string, err error) {
	if err == nil {
		return
	}
	e.count++
	if len(e.parts) < clearErrorsPartsCap {
		e.parts = append(e.parts, fmt.Sprintf("%s: %v", op, err))
	} else {
		e.overflow++
	}
}

// addExceptNotFound is add() for delete operations whose target key is
// COMPUTED, not enumerated — the reverse-session companion (a naive
// src/dst swap of the forward key) and the DNAT companion entry. For a
// NAT'd session those computed keys frequently do not exist (the real
// reverse companion is keyed on the TRANSLATED tuple val.ReverseKey, not
// the naive swap), so the dataplane returns ebpf.ErrKeyNotExist. That is
// a benign idempotent not-found, NOT a clear failure — counting it would
// make a fully-successful NAT'd-session clear spuriously report
// Failures>0 (#2468). Any OTHER delete error (EIO/EINVAL/...) is a real
// failure and is aggregated. The bounded filtered clear (#5454/#5531) routes
// its FORWARD delete through this path too: an enumerated forward key can be
// legitimately gone by delete time — the GC reaped it, or a restart-from-
// bucket-0 after a GC-deleted anchor re-collected a key a prior chunk already
// deleted — and treating that as a failure would both inflate Failures and,
// at O(matches) re-deletes, regrow the failure-string buffer this fix bounds.
func (e *clearErrors) addExceptNotFound(op string, err error) {
	if err == nil || dataplane.IsKeyNotFound(err) {
		return
	}
	e.add(op, err)
}

// summary returns a single-line description of all accumulated failures,
// bounded to clearErrorsPartsCap distinct entries plus a trailing overflow
// count so the string can never grow O(matches).
func (e *clearErrors) summary() string {
	if e.overflow == 0 {
		return strings.Join(e.parts, "; ")
	}
	return fmt.Sprintf("%s; …and %d more", strings.Join(e.parts, "; "), e.overflow)
}

// apply records the accumulated failure count and summary on the
// response so a remote caller learns the clear was partial.
func (e *clearErrors) apply(resp *pb.ClearSessionsResponse) {
	resp.Failures = int32(e.count)
	resp.FailureSummary = e.summary()
}

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64, zoneNames map[uint16]string, policyNames map[uint32]string, zoneIfaces map[uint16]string, egressIfaces map[sessionEgressKey]string, haActive bool) *pb.SessionEntry {
	inIf := zoneIfaces[val.IngressZone]
	if inIf == "" {
		inIf = zoneNames[val.IngressZone]
	}
	outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, zoneIfaces, egressIfaces)
	if outIf == "" {
		outIf = zoneNames[val.EgressZone]
	}
	se := &pb.SessionEntry{
		SrcAddr:  net.IP(key.SrcIP[:]).String(),
		DstAddr:  net.IP(key.DstIP[:]).String(),
		SrcPort:  uint32(ntohs(key.SrcPort)),
		DstPort:  uint32(ntohs(key.DstPort)),
		Protocol: protoName(key.Protocol),
		State:    sessionStateName(val.State),
		PolicyId: val.PolicyID,
		// #4626: reserved ids must not be resolved through the compiled map.
		PolicyName:       dataplane.SessionPolicyName(policyNames, val.PolicyID),
		IngressZone:      uint32(val.IngressZone),
		EgressZone:       uint32(val.EgressZone),
		IngressZoneName:  zoneNames[val.IngressZone],
		EgressZoneName:   zoneNames[val.EgressZone],
		IngressInterface: inIf,
		EgressInterface:  outIf,
		FwdPackets:       val.FwdPackets,
		FwdBytes:         val.FwdBytes,
		RevPackets:       val.RevPackets,
		RevBytes:         val.RevBytes,
		TimeoutSeconds:   val.Timeout,
		SessionId:        val.SessionID,
		HaActive:         haActive,
	}
	if val.Created > 0 && now > val.Created {
		se.AgeSeconds = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.IdleSeconds = int64(now - val.LastSeen)
	}
	var natParts []string
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort)))
		se.NatSrcAddr = uint32ToIP(val.NATSrcIP).String()
		se.NatSrcPort = uint32(ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort)))
		se.NatDstAddr = uint32ToIP(val.NATDstIP).String()
		se.NatDstPort = uint32(ntohs(val.NATDstPort))
	}
	se.Nat = strings.Join(natParts, "; ")
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64, zoneNames map[uint16]string, policyNames map[uint32]string, zoneIfaces map[uint16]string, egressIfaces map[sessionEgressKey]string, haActive bool) *pb.SessionEntry {
	inIf := zoneIfaces[val.IngressZone]
	if inIf == "" {
		inIf = zoneNames[val.IngressZone]
	}
	outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, zoneIfaces, egressIfaces)
	if outIf == "" {
		outIf = zoneNames[val.EgressZone]
	}
	se := &pb.SessionEntry{
		SrcAddr:  net.IP(key.SrcIP[:]).String(),
		DstAddr:  net.IP(key.DstIP[:]).String(),
		SrcPort:  uint32(ntohs(key.SrcPort)),
		DstPort:  uint32(ntohs(key.DstPort)),
		Protocol: protoName(key.Protocol),
		State:    sessionStateName(val.State),
		PolicyId: val.PolicyID,
		// #4626: reserved ids must not be resolved through the compiled map.
		PolicyName:       dataplane.SessionPolicyName(policyNames, val.PolicyID),
		IngressZone:      uint32(val.IngressZone),
		EgressZone:       uint32(val.EgressZone),
		IngressZoneName:  zoneNames[val.IngressZone],
		EgressZoneName:   zoneNames[val.EgressZone],
		IngressInterface: inIf,
		EgressInterface:  outIf,
		FwdPackets:       val.FwdPackets,
		FwdBytes:         val.FwdBytes,
		RevPackets:       val.RevPackets,
		RevBytes:         val.RevBytes,
		TimeoutSeconds:   val.Timeout,
		SessionId:        val.SessionID,
		HaActive:         haActive,
	}
	if val.Created > 0 && now > val.Created {
		se.AgeSeconds = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.IdleSeconds = int64(now - val.LastSeen)
	}
	var natParts []string
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("SNAT [%s]:%d", net.IP(val.NATSrcIP[:]).String(), ntohs(val.NATSrcPort)))
		se.NatSrcAddr = net.IP(val.NATSrcIP[:]).String()
		se.NatSrcPort = uint32(ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("DNAT [%s]:%d", net.IP(val.NATDstIP[:]).String(), ntohs(val.NATDstPort)))
		se.NatDstAddr = net.IP(val.NATDstIP[:]).String()
		se.NatDstPort = uint32(ntohs(val.NATDstPort))
	}
	se.Nat = strings.Join(natParts, "; ")
	return se
}

// sessionIfaceMatches checks whether ifName matches a filter interface name,
// including parent-to-subinterface matching (e.g. "ge-0/0/0" matches "ge-0/0/0.50").
func sessionIfaceMatches(filter, ifName string) bool {
	if ifName == "" {
		return false
	}
	return ifName == filter || strings.HasPrefix(ifName, filter+".")
}

// resolveSessionEgressIface resolves a session's egress interface from FIB result,
// falling back to the zone's first interface.
func resolveSessionEgressIface(fibIfindex uint32, fibVlanID uint16, egressZone uint16, zoneIfaces map[uint16]string, egressIfaces map[sessionEgressKey]string) string {
	if fibIfindex != 0 {
		if ifName, ok := egressIfaces[sessionEgressKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return ifName
		}
	}
	return zoneIfaces[egressZone]
}

func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// --- Cursor-based pagination helpers for GetSessions ---

// Page token format: "v4:<hex-key>" | "v6:<hex-key>" | "v6start"
// v4:<key> means "resume v4 iteration after this key, then v6"
// v6:<key> means "v4 done, resume v6 iteration after this key"
// v6start means "v4 done, start v6 from the beginning"

func encodePageTokenV4(key dataplane.SessionKey) string {
	b := make([]byte, binary.Size(key))
	copy(b[0:4], key.SrcIP[:])
	copy(b[4:8], key.DstIP[:])
	binary.NativeEndian.PutUint16(b[8:10], key.SrcPort)
	binary.NativeEndian.PutUint16(b[10:12], key.DstPort)
	b[12] = key.Protocol
	// pad bytes b[13:16]
	return base64.RawURLEncoding.EncodeToString([]byte("v4:" + hex.EncodeToString(b)))
}

func encodePageTokenV6(key dataplane.SessionKeyV6) string {
	b := make([]byte, binary.Size(key))
	copy(b[0:16], key.SrcIP[:])
	copy(b[16:32], key.DstIP[:])
	binary.NativeEndian.PutUint16(b[32:34], key.SrcPort)
	binary.NativeEndian.PutUint16(b[34:36], key.DstPort)
	b[36] = key.Protocol
	// pad bytes b[37:40]
	return base64.RawURLEncoding.EncodeToString([]byte("v6:" + hex.EncodeToString(b)))
}

func encodePageTokenV6Start() string {
	return base64.RawURLEncoding.EncodeToString([]byte("v6start"))
}

// maxPageTokenLen caps the encoded page_token before any base64/hex decode
// (#5649, C181-C11). The longest legitimate token is "v6:" plus the hex of a
// SessionKeyV6 (base64 of ~83 bytes, under 128); anything larger is
// noncanonical. Without this cap a caller could send a token near the 16 MiB
// gRPC receive limit and force transient base64/hex allocations many times the
// key size before the ABI prefix decode discards the excess. 256 leaves ample
// headroom for the real formats while rejecting the amplification.
const maxPageTokenLen = 256

// parsePageToken returns kind ("v4", "v6", "v6start") and raw key bytes.
func parsePageToken(token string) (kind string, keyBytes []byte, err error) {
	if len(token) > maxPageTokenLen {
		return "", nil, fmt.Errorf("page_token too long: %d bytes", len(token))
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", nil, fmt.Errorf("invalid page_token encoding: %w", err)
	}
	s := string(raw)
	if s == "v6start" {
		return "v6start", nil, nil
	}
	if strings.HasPrefix(s, "v4:") {
		b, err := hex.DecodeString(s[3:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v4 page_token hex: %w", err)
		}
		return "v4", b, nil
	}
	if strings.HasPrefix(s, "v6:") {
		b, err := hex.DecodeString(s[3:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v6 page_token hex: %w", err)
		}
		return "v6", b, nil
	}
	return "", nil, fmt.Errorf("invalid page_token prefix")
}

func decodeSessionKeyV4(b []byte) (dataplane.SessionKey, error) {
	var key dataplane.SessionKey
	// #5649 (C181-C11): require the EXACT ABI key length. A `<` check accepted
	// trailing bytes, so many distinct oversized tokens hex-decoded to the same
	// cursor (a noncanonical opaque token) and amplified allocations. The
	// encoder always emits exactly binary.Size(key) bytes.
	if len(b) != binary.Size(key) {
		return key, fmt.Errorf("v4 key wrong length: %d (want %d)", len(b), binary.Size(key))
	}
	copy(key.SrcIP[:], b[0:4])
	copy(key.DstIP[:], b[4:8])
	key.SrcPort = binary.NativeEndian.Uint16(b[8:10])
	key.DstPort = binary.NativeEndian.Uint16(b[10:12])
	key.Protocol = b[12]
	return key, nil
}

func decodeSessionKeyV6(b []byte) (dataplane.SessionKeyV6, error) {
	var key dataplane.SessionKeyV6
	// #5649 (C181-C11): exact ABI key length — see decodeSessionKeyV4.
	if len(b) != binary.Size(key) {
		return key, fmt.Errorf("v6 key wrong length: %d (want %d)", len(b), binary.Size(key))
	}
	copy(key.SrcIP[:], b[0:16])
	copy(key.DstIP[:], b[16:32])
	key.SrcPort = binary.NativeEndian.Uint16(b[32:34])
	key.DstPort = binary.NativeEndian.Uint16(b[34:36])
	key.Protocol = b[36]
	return key, nil
}
