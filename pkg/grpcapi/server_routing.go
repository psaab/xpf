package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/routing"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/termsafe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxGRPCRoutes = frr.MaxBGPRoutes
	maxGRPCBGPOutputBytes = 8 << 20
	maxConcurrentGRPCRIBStreams = 2
	bgpGRPCStreamBudget = 10 * time.Minute
)

var (
	grpcBGPStreamLimiter = diagcmd.NewLimiter(maxConcurrentGRPCRIBStreams)
	errGRPCBGPOutputLimit = errors.New("gRPC BGP routes response byte limit reached")
)

// #6468 D2: the routing show RPCs return captured `vtysh` stdout, and the
// remote `cli` prints resp.Output VERBATIM (cmd/cli/show_protocols.go:
// fmt.Print(resp.Output)) — the same terminal the in-process CLI writes to,
// reached over a different transport. That stdout carries text a REMOTE PEER
// advertised: the BGP hostname capability, IS-IS dynamic hostname TLVs, OSPF
// router IDs. Every Output on these handlers therefore passes through
// termsafe.SanitizeBlockForDisplay, the mirror of the fmt.Print guards in
// pkg/cli/cli_show_routing.go.
//
// The guard sits on the RESPONSE, not on each vtysh branch, so a case added to
// one of these switches later is covered by construction — the fail-open
// direction is what left this half of the class unfixed to begin with. The
// branches that build a structured table instead of returning raw stdout pay
// nothing: clean text takes the sanitizer's allocation-free fast path.

func (s *Server) GetRoutes(ctx context.Context, _ *pb.GetRoutesRequest) (*pb.GetRoutesResponse, error) {
	if s.routing == nil {
		return &pb.GetRoutesResponse{}, nil
	}

	resp := &pb.GetRoutesResponse{}
	appendRoute := func(route *pb.RouteInfo) bool {
		if len(resp.Routes) == maxGRPCRoutes {
			resp.Truncated = true
			return false
		}
		resp.Routes = append(resp.Routes, route)
		return true
	}
	stopped, err := s.routing.StreamRoutes(func(e routing.RouteEntry) bool {
		// ECMP route: emit one RouteInfo per equal-cost next-hop so the
		// structured view lists all of them, while counting each leg against
		// the response cap.
		if len(e.NextHops) > 0 {
			for _, nh := range e.NextHops {
				if !appendRoute(&pb.RouteInfo{
					Destination: e.Destination,
					NextHop:     nh.Gateway,
					Interface:   nh.Interface,
					Preference:  int32(e.Preference),
					Protocol:    e.Protocol,
				}) {
					return false
				}
			}
			return true
		}
		return appendRoute(&pb.RouteInfo{
			Destination: e.Destination,
			NextHop:     e.NextHop,
			Interface:   e.Interface,
			Preference:  int32(e.Preference),
			Protocol:    e.Protocol,
		})
	})
	resp.Truncated = resp.Truncated || stopped
	if err != nil {
		// A total failure (no routes: every family's dump failed) stays a
		// hard gRPC error. A partial per-family failure still has usable
		// routes; the response now marks only cap truncation, so surface the
		// family failure via logging and return its successful routes (#5125).
		if len(resp.Routes) == 0 {
			return nil, frrStatusErr("get routes", err)
		}
		slog.Warn("GetRoutes returning partial route dump", "error", err)
	}
	return resp, nil
}

func (s *Server) GetOSPFStatus(ctx context.Context, req *pb.GetOSPFStatusRequest) (*pb.GetOSPFStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetOSPFStatusResponse{Output: "FRR not available"}, nil
	}
	var output string
	var err error
	switch req.Type {
	case "neighbor-detail":
		output, err = s.frr.GetOSPFNeighborDetail(ctx)
	case "database":
		output, err = s.frr.GetOSPFDatabase(ctx)
	case "interface":
		output, err = s.frr.GetOSPFInterface(ctx)
	case "routes":
		output, err = s.frr.GetOSPFRoutes(ctx)
	default:
		neighbors, nerr := s.frr.GetOSPFNeighbors(ctx)
		if nerr != nil {
			return nil, frrStatusErr("", nerr)
		}
		var b strings.Builder
		for _, n := range neighbors {
			fmt.Fprintf(&b, "%-18s %-10s %-16s %-18s %s\n",
				termsafe.SanitizeRowForDisplay(
					n.NeighborID, n.Priority, n.State, n.Address, n.Interface)...)
		}
		output = b.String()
	}
	if err != nil {
		return nil, frrStatusErr("", err)
	}
	return &pb.GetOSPFStatusResponse{Output: termsafe.SanitizeBlockForDisplay(output)}, nil
}

func (s *Server) GetBGPStatus(ctx context.Context, req *pb.GetBGPStatusRequest) (*pb.GetBGPStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetBGPStatusResponse{Output: "FRR not available"}, nil
	}
	var b strings.Builder
	switch req.Type {
	case "routes":
		return s.getBGPStatusRoutes(ctx)
	case "groups":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) == 0 {
			b.WriteString("No BGP groups configured\n")
		} else {
			// Group neighbors by GroupName
			groups := make(map[string][]*config.BGPNeighbor)
			for _, n := range cfg.Protocols.BGP.Neighbors {
				name := n.GroupName
				if name == "" {
					name = "(ungrouped)"
				}
				groups[name] = append(groups[name], n)
			}
			names := make([]string, 0, len(groups))
			for name := range groups {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				neighbors := groups[name]
				var peerAS uint32
				var exports []string
				if len(neighbors) > 0 {
					peerAS = neighbors[0].PeerAS
					exports = neighbors[0].Export
				}
				fmt.Fprintf(&b, "Group: %s  Peer-AS: %d  Neighbors: %d\n", name, peerAS, len(neighbors))
				if len(exports) > 0 {
					fmt.Fprintf(&b, "  Export: %s\n", strings.Join(exports, ", "))
				}
				for _, n := range neighbors {
					desc := ""
					if n.Description != "" {
						desc = " (" + n.Description + ")"
					}
					fmt.Fprintf(&b, "  Neighbor: %s%s\n", n.Address, desc)
				}
				b.WriteString("\n")
			}
		}
	default:
		// "received-routes:<ip>" for neighbor received routes.
		// Validate the IP at the trust boundary (this handler is reachable
		// over the UNAUTHENTICATED local gRPC listener) so a malformed or
		// newline-bearing token is rejected with InvalidArgument before it
		// reaches the vtysh command line. The frr wrappers re-check as the
		// load-bearing belt (#4588).
		if strings.HasPrefix(req.Type, "received-routes:") {
			ip := strings.TrimPrefix(req.Type, "received-routes:")
			if net.ParseIP(ip) == nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid neighbor IP %q", ip)
			}
			output, err := s.frr.GetBGPNeighborReceivedRoutes(ctx, ip)
			if err != nil {
				return nil, frrStatusErr("", err)
			}
			return &pb.GetBGPStatusResponse{Output: termsafe.SanitizeBlockForDisplay(output)}, nil
		}
		// "advertised-routes:<ip>" for neighbor advertised routes
		if strings.HasPrefix(req.Type, "advertised-routes:") {
			ip := strings.TrimPrefix(req.Type, "advertised-routes:")
			if net.ParseIP(ip) == nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid neighbor IP %q", ip)
			}
			output, err := s.frr.GetBGPNeighborAdvertisedRoutes(ctx, ip)
			if err != nil {
				return nil, frrStatusErr("", err)
			}
			return &pb.GetBGPStatusResponse{Output: termsafe.SanitizeBlockForDisplay(output)}, nil
		}
		// "neighbor" or "neighbor:<ip>" for detailed neighbor info.
		// An empty ip selects every neighbor (legal); a non-empty ip must
		// parse as an IP address before it reaches vtysh (#4588).
		if req.Type == "neighbor" || strings.HasPrefix(req.Type, "neighbor:") {
			ip := ""
			if strings.HasPrefix(req.Type, "neighbor:") {
				ip = strings.TrimPrefix(req.Type, "neighbor:")
			}
			if ip != "" && net.ParseIP(ip) == nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid neighbor IP %q", ip)
			}
			output, err := s.frr.GetBGPNeighborDetail(ctx, ip)
			if err != nil {
				return nil, frrStatusErr("", err)
			}
			return &pb.GetBGPStatusResponse{Output: termsafe.SanitizeBlockForDisplay(output)}, nil
		}
		peers, err := s.frr.GetBGPSummary(ctx)
		if err != nil {
			return nil, frrStatusErr("", err)
		}
		fmt.Fprintf(&b, "%-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
			"Neighbor", "AF", "AS", "MsgRcvd", "MsgSent", "Up/Down", "State", "PfxRcd")
		for _, p := range peers {
			fmt.Fprintf(&b, "%-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
				termsafe.SanitizeRowForDisplay(
					p.Neighbor, p.AddressFamily, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State, p.PfxRcd)...)
		}
	}
	return &pb.GetBGPStatusResponse{Output: termsafe.SanitizeBlockForDisplay(b.String())}, nil
}

func (s *Server) getBGPStatusRoutes(ctx context.Context) (*pb.GetBGPStatusResponse, error) {
	release, err := grpcBGPStreamLimiter.Acquire()
	if err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "BGP route stream admission refused: %v", err)
	}
	defer release()

	streamCtx, cancel := context.WithTimeout(ctx, bgpGRPCStreamBudget)
	defer cancel()
	if err := streamCtx.Err(); err != nil {
		return nil, frrStatusErr("", err)
	}

	notice := fmt.Sprintf("... table truncated at %d routes or %d response bytes; use the CLI 'show route protocol bgp' for the full table\n",
		maxGRPCRoutes, maxGRPCBGPOutputBytes)
	var b strings.Builder
	b.Grow(64 << 10)
	byteTruncated := false
	routeTruncated, err := s.frr.StreamBGPRoutes(streamCtx, maxGRPCRoutes, func(r frr.BGPRoute) error {
		cells := termsafe.SanitizeRowForDisplay(r.Network, r.NextHop, r.Path)
		networkWidth := len(cells[0].(string))
		if networkWidth < 24 {
			networkWidth = 24
		}
		nextHopWidth := len(cells[1].(string))
		if nextHopWidth < 20 {
			nextHopWidth = 20
		}
		// Include the two separators and trailing newline. Byte lengths may
		// overestimate Unicode display width, which only truncates earlier.
		lineBytes := networkWidth + nextHopWidth + len(cells[2].(string)) + 3
		if b.Len()+lineBytes > maxGRPCBGPOutputBytes-len(notice) {
			byteTruncated = true
			return errGRPCBGPOutputLimit
		}
		fmt.Fprintf(&b, "%-24s %-20s %s\n", cells...)
		return nil
	})
	if errors.Is(err, errGRPCBGPOutputLimit) {
		err = nil
		routeTruncated = true
	}
	if err != nil {
		return nil, frrStatusErr("", err)
	}
	if routeTruncated || byteTruncated {
		b.WriteString(notice)
	}
	return &pb.GetBGPStatusResponse{Output: termsafe.SanitizeBlockForDisplay(b.String())}, nil
}

func (s *Server) GetRIPStatus(ctx context.Context, _ *pb.GetRIPStatusRequest) (*pb.GetRIPStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetRIPStatusResponse{Output: "FRR not available"}, nil
	}
	routes, err := s.frr.GetRIPRoutes(ctx)
	if err != nil {
		return nil, frrStatusErr("", err)
	}
	var b strings.Builder
	if len(routes) == 0 {
		b.WriteString("No RIP routes\n")
	} else {
		fmt.Fprintf(&b, "  %-20s %-18s %-8s %s\n", "Network", "Next Hop", "Metric", "Interface")
		for _, r := range routes {
			fmt.Fprintf(&b, "  %-20s %-18s %-8s %s\n",
				termsafe.SanitizeRowForDisplay(r.Network, r.NextHop, r.Metric, r.Interface)...)
		}
	}
	return &pb.GetRIPStatusResponse{Output: b.String()}, nil
}

func (s *Server) GetISISStatus(ctx context.Context, req *pb.GetISISStatusRequest) (*pb.GetISISStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetISISStatusResponse{Output: "FRR not available"}, nil
	}
	var b strings.Builder
	switch req.Type {
	case "adjacency-detail":
		output, err := s.frr.GetISISAdjacencyDetail(ctx)
		if err != nil {
			return nil, frrStatusErr("", err)
		}
		b.WriteString(output)
	case "routes":
		output, err := s.frr.GetISISRoutes(ctx)
		if err != nil {
			return nil, frrStatusErr("", err)
		}
		b.WriteString(output)
	case "database":
		output, err := s.frr.GetISISDatabase(ctx)
		if err != nil {
			return nil, frrStatusErr("", err)
		}
		b.WriteString(output)
	default:
		adjs, err := s.frr.GetISISAdjacency(ctx)
		if err != nil {
			return nil, frrStatusErr("", err)
		}
		if len(adjs) == 0 {
			b.WriteString("No IS-IS adjacencies\n")
		} else {
			fmt.Fprintf(&b, "  %-20s %-14s %-10s %-10s %s\n",
				"System ID", "Interface", "Level", "State", "Hold Time")
			for _, a := range adjs {
				// #7430: an unparseable row is REPORTED, not dropped. A dropped row is
				// indistinguishable from "no such adjacency" to an operator debugging a
				// missing neighbour, and points at the wrong problem. Rendering it with
				// empty derived fields would report a neighbour in state "" — quieter
				// than column-forgery but still false — so the raw line is shown under a
				// single heading instead of split across the parsed columns.
				//
				// Raw is peer-influenced text and goes through termsafe exactly as the
				// parsed cells do (#6468).
				if a.Malformed {
					fmt.Fprintf(&b, "  %s\n",
						termsafe.SanitizeForDisplay("<unparseable IS-IS neighbor row: "+a.Raw+">"))
					continue
				}
				fmt.Fprintf(&b, "  %-20s %-14s %-10s %-10s %s\n",
					termsafe.SanitizeRowForDisplay(
						a.SystemID, a.Interface, a.Level, a.State, a.HoldTime)...)
			}
		}
	}
	return &pb.GetISISStatusResponse{Output: termsafe.SanitizeBlockForDisplay(b.String())}, nil
}

func (s *Server) GetIPsecSA(_ context.Context, _ *pb.GetIPsecSARequest) (*pb.GetIPsecSAResponse, error) {
	if s.ipsec == nil {
		return &pb.GetIPsecSAResponse{Output: "IPsec not available"}, nil
	}
	sas, err := s.ipsec.GetSAStatus()
	if err != nil {
		return nil, frrStatusErr("", err)
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
	return &pb.GetIPsecSAResponse{Output: b.String()}, nil
}
