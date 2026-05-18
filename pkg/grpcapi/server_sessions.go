package grpcapi

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type sessionEgressKey struct {
	ifindex uint32
	vlanID  uint16
}

func (s *Server) GetSessions(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	// Cursor-based pagination: when page_size > 0, use cursor path.
	if req.PageSize > 0 {
		return s.getSessionsCursor(ctx, req)
	}

	// Legacy limit/offset path (backward compatible).
	return s.getSessionsLegacy(ctx, req)
}

// sessionIteratorFrom is implemented by dataplane.Manager to support
// cursor-based BPF map iteration.
type sessionIteratorFrom interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// getSessionsCursor implements cursor-based pagination.
// It iterates only up to page_size matching entries, avoids full-table
// scans for the total count (uses SessionCount instead), and skips
// enrichment when no_enrich is set.
func (s *Server) getSessionsCursor(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	iterDP, ok := s.dp.(sessionIteratorFrom)
	if !ok {
		// Dataplane doesn't support cursor iteration; fall back to legacy.
		return s.getSessionsLegacy(ctx, req)
	}

	pageSize := int(req.PageSize)
	if pageSize > 10000 {
		pageSize = 10000
	}

	filter := s.buildSessionFilter(req)
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
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
			lastV4Key = key
			return true
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "v4 session iteration: %v", err)
		}
		if len(all) >= pageSize {
			// Page is full from v4; next page token resumes v4.
			resp := &pb.GetSessionsResponse{
				Sessions:      all,
				NextPageToken: encodePageTokenV4(lastV4Key),
			}
			s.setSessionsTotal(resp, filter)
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
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
			lastV6Key = key
			return true
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "v6 session iteration: %v", err)
		}
		if len(all) >= pageSize {
			resp := &pb.GetSessionsResponse{
				Sessions:      all,
				NextPageToken: encodePageTokenV6(lastV6Key),
			}
			s.setSessionsTotal(resp, filter)
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
	s.setSessionsTotal(resp, filter)
	s.setSessionsNodeID(resp)
	s.fetchPeerSessions(ctx, req, resp)
	return resp, nil
}

// setSessionsTotal sets the Total field on the response.
// When no filters are active, use the lightweight SessionCount() to avoid
// a full-table enrichment scan.  With filters, total is set to -1
// (unknown) since computing it would require a full scan.
func (s *Server) setSessionsTotal(resp *pb.GetSessionsResponse, f *sessionFilter) {
	if f.hasFilters {
		resp.Total = -1 // filtered total is unknown without full scan
		return
	}
	v4, v6 := s.dp.SessionCount()
	resp.Total = int32(v4 + v6)
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
	cfg          *config.Config
	zoneNames    map[uint16]string
	zoneIfaces   map[uint16]string
	egressIfaces map[sessionEgressKey]string
	policyNames  map[uint32]string
	appNames     map[uint16]string
	hasFilters   bool // true if any filter narrows results
}

func (s *Server) buildSessionFilter(req *pb.GetSessionsRequest) *sessionFilter {
	f := &sessionFilter{
		zoneFilter:   uint16(req.Zone),
		protoFilter:  req.Protocol,
		srcPort:      uint16(req.SourcePort),
		dstPort:      uint16(req.DestinationPort),
		natOnly:      req.NatOnly,
		appFilter:    req.Application,
		ifaceFilter:  req.InterfaceFilter,
		cfg:          s.store.ActiveConfig(),
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16]string),
		egressIfaces: make(map[sessionEgressKey]string),
	}
	f.hasFilters = f.zoneFilter != 0 || f.protoFilter != "" || req.SourcePrefix != "" ||
		req.DestinationPrefix != "" || f.srcPort != 0 || f.dstPort != 0 ||
		f.natOnly || f.appFilter != "" || f.ifaceFilter != ""

	// Parse CIDR prefix filters.
	if req.SourcePrefix != "" {
		cidr := req.SourcePrefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, f.srcNet, _ = net.ParseCIDR(cidr)
	}
	if req.DestinationPrefix != "" {
		cidr := req.DestinationPrefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, f.dstNet, _ = net.ParseCIDR(cidr)
	}

	// Build zone/policy/app name maps.
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			f.zoneNames[id] = name
		}
		f.policyNames = cr.PolicyNames
		f.appNames = cr.AppNames
	}
	if f.cfg != nil {
		for zoneName, zone := range f.cfg.Security.Zones {
			if cr := s.applyResult(); cr != nil {
				if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
					f.zoneIfaces[zid] = zone.Interfaces[0]
				}
			}
		}
		for ifName, ifc := range f.cfg.Interfaces.Interfaces {
			resolvedParent := config.LinuxIfName(strings.SplitN(f.cfg.ResolveReth(ifName), ".", 2)[0])
			parentLink, err := net.InterfaceByName(resolvedParent)
			if err != nil {
				continue
			}
			for _, unit := range ifc.Units {
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
			}
		}
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
	if f.protoFilter != "" && !strings.EqualFold(protoName(key.Protocol), f.protoFilter) {
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
		key.Protocol, ntohs(key.DstPort), val.AppID) {
		return false
	}
	if f.ifaceFilter != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, f.zoneIfaces, f.egressIfaces)
		if !sessionIfaceMatches(f.ifaceFilter, inIf) && !sessionIfaceMatches(f.ifaceFilter, outIf) {
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
	if f.protoFilter != "" && !strings.EqualFold(protoName(key.Protocol), f.protoFilter) {
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
		key.Protocol, ntohs(key.DstPort), val.AppID) {
		return false
	}
	if f.ifaceFilter != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, f.zoneIfaces, f.egressIfaces)
		if !sessionIfaceMatches(f.ifaceFilter, inIf) && !sessionIfaceMatches(f.ifaceFilter, outIf) {
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
		resp.Peer = peerResp
	}
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
	offset := int(req.Offset)
	noEnrich := req.NoEnrich

	filter := s.buildSessionFilter(req)
	now := monotonicSeconds()
	all := make([]*pb.SessionEntry, 0, limit)
	idx := 0

	// Determine HA state for session display.
	haActive := true // standalone default
	if s.cluster != nil {
		haActive = s.cluster.IsLocalPrimary(0)
	}

	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
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
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
		}
		idx++
		return true
	})

	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
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
				se.Application = appid.ResolveSessionName(filter.appNames, filter.cfg, key.Protocol, ntohs(key.DstPort), val.AppID)
			}
			all = append(all, se)
		}
		idx++
		return true
	})

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

	resp := &pb.GetSessionSummaryResponse{}

	// Set node ID from cluster manager (0 if standalone).
	if s.cluster != nil {
		resp.NodeId = int32(s.cluster.NodeID())
	}

	_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
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
	})

	_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
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
	})

	// Fetch peer summary if requested and in cluster mode.
	if req.GetIncludePeer() && s.cluster != nil && s.cluster.PeerAlive() {
		conn, err := s.dialPeer()
		if err == nil {
			defer conn.Close()
			client := pb.NewBpfrxServiceClient(conn)
			peerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			// Do NOT set include_peer on the peer request — prevents recursion.
			peerResp, err := client.GetSessionSummary(peerCtx, &pb.GetSessionSummaryRequest{})
			if err != nil {
				slog.Warn("failed to fetch peer session summary", "err", err)
			} else {
				resp.Peer = peerResp
			}
		} else {
			slog.Warn("failed to dial peer for session summary", "err", err)
		}
	}

	return resp, nil
}

func (s *Server) ClearSessions(ctx context.Context, req *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

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
		req.Application == "" {
		v4, v6, err := s.dp.ClearAllSessions()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		if !forwarded {
			s.clearPeerSessions(req)
		}
		return &pb.ClearSessionsResponse{
			Ipv4Cleared: int32(v4),
			Ipv6Cleared: int32(v6),
		}, nil
	}

	// Build filter
	var srcNet, dstNet *net.IPNet
	if req.SourcePrefix != "" {
		cidr := req.SourcePrefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, srcNet, _ = net.ParseCIDR(cidr)
	}
	if req.DestinationPrefix != "" {
		cidr := req.DestinationPrefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, dstNet, _ = net.ParseCIDR(cidr)
	}

	var proto uint8
	switch strings.ToLower(req.Protocol) {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	case "icmp":
		proto = 1
	}

	clearCfg := s.store.ActiveConfig()
	var appNames map[uint16]string
	if cr := s.applyResult(); cr != nil {
		appNames = cr.AppNames
	}

	var zoneID uint16
	if req.Zone != "" {
		if cr := s.applyResult(); cr != nil {
			zoneID = cr.ZoneIDs[req.Zone]
		}
	}

	// Clear matching IPv4 sessions
	v4Deleted := 0
	var v4Keys []dataplane.SessionKey
	var v4RevKeys []dataplane.SessionKey
	var snatDNATKeys []dataplane.DNATKey
	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if proto != 0 && key.Protocol != proto {
			return true
		}
		if srcNet != nil && !srcNet.Contains(net.IP(key.SrcIP[:])) {
			return true
		}
		if dstNet != nil && !dstNet.Contains(net.IP(key.DstIP[:])) {
			return true
		}
		if zoneID != 0 && val.IngressZone != zoneID && val.EgressZone != zoneID {
			return true
		}
		if req.SourcePort != 0 && key.SrcPort != uint16(req.SourcePort) {
			return true
		}
		if req.DestinationPort != 0 && key.DstPort != uint16(req.DestinationPort) {
			return true
		}
		if req.Application != "" && !appid.SessionMatches(req.Application, appNames, clearCfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return true
		}
		v4Keys = append(v4Keys, key)
		v4RevKeys = append(v4RevKeys, dataplane.SessionKey{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, dataplane.DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	})

	for _, key := range v4Keys {
		if err := s.dp.DeleteSession(key); err == nil {
			v4Deleted++
		}
	}
	for _, key := range v4RevKeys {
		s.dp.DeleteSession(key)
	}
	for _, dk := range snatDNATKeys {
		s.dp.DeleteDNATEntry(dk)
	}

	// Clear matching IPv6 sessions
	v6Deleted := 0
	var v6Keys []dataplane.SessionKeyV6
	var v6RevKeys []dataplane.SessionKeyV6
	var snatDNATKeysV6 []dataplane.DNATKeyV6
	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if proto != 0 && key.Protocol != proto {
			return true
		}
		if srcNet != nil && !srcNet.Contains(net.IP(key.SrcIP[:])) {
			return true
		}
		if dstNet != nil && !dstNet.Contains(net.IP(key.DstIP[:])) {
			return true
		}
		if zoneID != 0 && val.IngressZone != zoneID && val.EgressZone != zoneID {
			return true
		}
		if req.SourcePort != 0 && key.SrcPort != uint16(req.SourcePort) {
			return true
		}
		if req.DestinationPort != 0 && key.DstPort != uint16(req.DestinationPort) {
			return true
		}
		if req.Application != "" && !appid.SessionMatches(req.Application, appNames, clearCfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return true
		}
		v6Keys = append(v6Keys, key)
		v6RevKeys = append(v6RevKeys, dataplane.SessionKeyV6{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, dataplane.DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	})

	for _, key := range v6Keys {
		if err := s.dp.DeleteSessionV6(key); err == nil {
			v6Deleted++
		}
	}
	for _, key := range v6RevKeys {
		s.dp.DeleteSessionV6(key)
	}
	for _, dk := range snatDNATKeysV6 {
		s.dp.DeleteDNATEntryV6(dk)
	}

	if !forwarded {
		s.clearPeerSessions(req)
	}
	return &pb.ClearSessionsResponse{
		Ipv4Cleared: int32(v4Deleted),
		Ipv6Cleared: int32(v6Deleted),
	}, nil
}

// clearPeerSessions forwards a ClearSessions request to the cluster peer.
// Uses x-peer-forwarded metadata to prevent infinite recursion.
func (s *Server) clearPeerSessions(req *pb.ClearSessionsRequest) {
	conn, err := s.dialPeer()
	if err != nil {
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	_, _ = pb.NewBpfrxServiceClient(conn).ClearSessions(ctx, req)
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
	outIf := egressIfaces[sessionEgressKey{ifindex: val.FibIfindex, vlanID: val.FibVlanID}]
	if outIf == "" {
		outIf = zoneIfaces[val.EgressZone]
		if outIf == "" {
			outIf = zoneNames[val.EgressZone]
		}
	}
	se := &pb.SessionEntry{
		SrcAddr:          net.IP(key.SrcIP[:]).String(),
		DstAddr:          net.IP(key.DstIP[:]).String(),
		SrcPort:          uint32(ntohs(key.SrcPort)),
		DstPort:          uint32(ntohs(key.DstPort)),
		Protocol:         protoName(key.Protocol),
		State:            sessionStateName(val.State),
		PolicyId:         val.PolicyID,
		PolicyName:       policyNames[val.PolicyID],
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
	outIf := egressIfaces[sessionEgressKey{ifindex: val.FibIfindex, vlanID: val.FibVlanID}]
	if outIf == "" {
		outIf = zoneIfaces[val.EgressZone]
		if outIf == "" {
			outIf = zoneNames[val.EgressZone]
		}
	}
	se := &pb.SessionEntry{
		SrcAddr:          net.IP(key.SrcIP[:]).String(),
		DstAddr:          net.IP(key.DstIP[:]).String(),
		SrcPort:          uint32(ntohs(key.SrcPort)),
		DstPort:          uint32(ntohs(key.DstPort)),
		Protocol:         protoName(key.Protocol),
		State:            sessionStateName(val.State),
		PolicyId:         val.PolicyID,
		PolicyName:       policyNames[val.PolicyID],
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

// parsePageToken returns kind ("v4", "v6", "v6start") and raw key bytes.
func parsePageToken(token string) (kind string, keyBytes []byte, err error) {
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
	if len(b) < binary.Size(key) {
		return key, fmt.Errorf("v4 key too short: %d", len(b))
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
	if len(b) < binary.Size(key) {
		return key, fmt.Errorf("v6 key too short: %d", len(b))
	}
	copy(key.SrcIP[:], b[0:16])
	copy(key.DstIP[:], b[16:32])
	key.SrcPort = binary.NativeEndian.Uint16(b[32:34])
	key.DstPort = binary.NativeEndian.Uint16(b[34:36])
	key.Protocol = b[36]
	return key, nil
}
