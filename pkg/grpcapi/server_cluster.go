package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/feeds"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// buildInterfacesInput gathers cluster interface data for FormatInterfaces.

// buildInterfacesInput gathers cluster interface data for FormatInterfaces.
func (s *Server) buildInterfacesInput() cluster.InterfacesInput {
	var input cluster.InterfacesInput
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return input
	}
	cc := cfg.Chassis.Cluster
	input.ControlInterface = cc.ControlInterface
	input.FabricInterface = cc.FabricInterface
	if fabIfc, ok := config.LookupInterface(cfg, cc.FabricInterface); ok {
		input.FabricMembers = fabIfc.FabricMembers
	}
	input.Fabric1Interface = cc.Fabric1Interface
	if fab1Ifc, ok := config.LookupInterface(cfg, cc.Fabric1Interface); ok {
		input.Fabric1Members = fab1Ifc.FabricMembers
	}

	// Build RETH info from config.
	rethMap := cfg.RethToPhysical() // reth-name -> physical-member
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil { // #5886: tolerant load / HA sync can leave a present-but-nil slot
			continue
		}
		if ifc.RedundancyGroup > 0 && strings.HasPrefix(name, "reth") {
			status := "Up"
			if phys, ok := rethMap[name]; ok {
				linuxName := config.LinuxIfName(phys)
				link, err := netlink.LinkByName(linuxName)
				if err != nil || !cluster.LinkAttrsUp(link.Attrs()) {
					status = "Down"
				}
			}
			input.Reths = append(input.Reths, cluster.RethInfo{
				Name:            name,
				RedundancyGroup: ifc.RedundancyGroup,
				Status:          status,
			})
		}
	}
	sort.Slice(input.Reths, func(i, j int) bool { return input.Reths[i].Name < input.Reths[j].Name })

	// Build local interface monitor info.
	localMonMap := make(map[string]bool) // track which interfaces are local
	monStatuses := make(map[int][]routing.InterfaceMonitorStatus)
	if s.routing != nil {
		if ms := s.routing.InterfaceMonitorStatuses(); ms != nil {
			monStatuses = ms
		}
	}
	for _, rg := range cc.RedundancyGroups {
		if statuses, ok := monStatuses[rg.ID]; ok {
			for _, st := range statuses {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:        st.Interface,
					Weight:           st.Weight,
					Up:               st.Up,
					RedundancyGroup:  rg.ID,
					ConfiguredWeight: st.ConfiguredWeight, // #6589
					Clamped:          st.Clamped,
				})
				localMonMap[st.Interface] = true
			}
		} else {
			// #4480: no live status available for this RG's monitors —
			// the routing interface-monitor sweep has not (yet) produced a
			// link-state result. Surface the honest "unknown as Down"
			// (Up:false) rather than the observability lie of Up:true, which
			// let a DOWN monitored uplink render as healthy. This matches the
			// peer branch's config-only fill below, which already reports
			// Up:false. Display path only — the failover decision reads the
			// live routing statuses, not this fallback.
			for _, mon := range rg.InterfaceMonitors {
				// #6549: render the weight the election would APPLY, not the
				// raw configured one. An out-of-range weight survives the
				// tolerant load / peer-sync compile (#1960 no-brick) and the
				// runtime bounds it to [0,255]; reporting the raw value here
				// would be an observability lie on exactly the config where
				// the operator most needs the truth.
				w, clamped := config.ClampInterfaceMonitorWeight(mon.Weight)
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:        mon.Interface,
					Weight:           w,
					Up:               false,
					RedundancyGroup:  rg.ID,
					ConfiguredWeight: mon.Weight,
					Clamped:          clamped, // #6589
				})
				localMonMap[mon.Interface] = true
			}
		}
	}

	// Build peer interface monitor info from heartbeat.
	if s.cluster != nil {
		peerLive := s.cluster.PeerMonitorStatuses()
		peerMap := make(map[string]bool)
		for _, pm := range peerLive {
			peerMap[pm.Interface] = true
			input.PeerMonitors = append(input.PeerMonitors, pm)
		}
		// Fill config-only peer monitors (not local, not in heartbeat) as down.
		for _, rg := range cc.RedundancyGroups {
			for _, mon := range rg.InterfaceMonitors {
				if localMonMap[mon.Interface] {
					continue
				}
				if peerMap[mon.Interface] {
					continue
				}
				// #6549: the peer bounds this weight the same way we do, so
				// render the effective value rather than the raw config one.
				w, clamped := config.ClampInterfaceMonitorWeight(mon.Weight)
				input.PeerMonitors = append(input.PeerMonitors, cluster.InterfaceMonitorInfo{
					Interface:        mon.Interface,
					Weight:           w,
					Up:               false,
					RedundancyGroup:  rg.ID,
					ConfiguredWeight: mon.Weight,
					Clamped:          clamped, // #6589
				})
			}
		}
	}

	return input
}

func (s *Server) MatchPolicies(_ context.Context, req *pb.MatchPoliciesRequest) (*pb.MatchPoliciesResponse, error) {
	// Decode proto optionals (transport-only): present ports/ICMP keep
	// #17081 literal-zero presence; ranged here, then shared Validate.
	srcPort, err := grpcPortValue(req.SourcePort)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid source-port: %v", err)
	}
	dstPort, err := grpcPortValue(req.DestinationPort)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid destination-port: %v", err)
	}
	icmpType, err := grpcICMPValue(req.IcmpType)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid icmp-type: %v", err)
	}
	icmpCode, err := grpcICMPValue(req.IcmpCode)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid icmp-code: %v", err)
	}
	r := policymatch.Request{FromZone: req.FromZone, ToZone: req.ToZone, SrcIP: req.SourceIp, DstIP: req.DestinationIp, Protocol: req.Protocol, SrcPort: srcPort, DstPort: dstPort, ICMPType: icmpType, ICMPCode: icmpCode, NonFirstFragment: req.NonFirstFragment, IngressInterface: req.IngressInterface}
	cfg := s.store.ActiveConfig()
	// #17198: shared Validate runs config-independent grammar BEFORE the
	// cfg==nil verdict (#3709 boot window, previously REST-only); with a
	// live config it also validates ingress_interface (#5579).
	if err := r.Validate(cfg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if cfg == nil {
		// #3375: deterministic fail-closed default deny + queried zones.
		nilRes := policymatch.Result{DefaultUsed: true, Action: config.PolicyDeny}
		return &pb.MatchPoliciesResponse{Action: nilRes.DisplayAction(), DefaultUsed: true, QueriedFromZone: req.FromZone, QueriedToZone: req.ToZone}, nil
	}
	// #3042/#17198: shared Assemble + VerdictFrom own assembly/projection.
	res := policymatch.Match(cfg, policymatch.Assemble(cfg, r, s.matchLive(cfg)))
	return verdictToProto(policymatch.VerdictFrom(res, req.FromZone, req.ToZone), res), nil
}

// matchLive assembles shared Live inputs (overlay, feed debt, scheduler).
func (s *Server) matchLive(cfg *config.Config) policymatch.Live {
	var overlay map[string][]string
	if s.feedOverlayFn != nil {
		overlay = s.feedOverlayFn()
	}
	live := policymatch.Live{FeedOverlay: overlay, PolicyInactiveForFn: s.policyInactiveForFn(cfg)}
	if s.feedsFn != nil {
		live.Feeds = policymatch.FeedInfos(s.feedsFn(), func(i feeds.FeedInfo) bool { return i.PublicationDebt })
	}
	return live
}

// verdictToProto copies the shared Verdict (#17198) onto the proto response,
// preserving per-branch wire semantics (PolicyId only on match #3623,
// ContentRejectionReasons REST/local-only per #14362 note in git history).
func verdictToProto(v policymatch.Verdict, res policymatch.Result) *pb.MatchPoliciesResponse {
	out := &pb.MatchPoliciesResponse{
		PostNatInputNote: v.PostNATInputNote, Matched: v.Matched, Action: v.Action,
		QueriedFromZone: v.QueriedFromZone, QueriedToZone: v.QueriedToZone,
	}
	if v.HostInboundStatus != "" {
		out.HostInbound = hostInboundToProto(res.HostInbound)
	}
	switch {
	case v.ContentRejected:
		out.ContentRejected = true
		out.UnsupportedTupleFamily = v.UnsupportedTupleFamily
		out.V4MappedCompatIngressDrop = v.V4MappedCompatIngressDrop
	case v.V4MappedCompatIngressDrop:
		out.V4MappedCompatIngressDrop = true
		out.UnsupportedTupleFamily = v.UnsupportedTupleFamily
	case v.HostInboundUnmatched:
		out.HostInboundUnmatched = true
	case !v.Matched:
		out.DefaultUsed = v.DefaultUsed
		out.UnzonedIngress = v.UnzonedIngress
		out.HostOriginated = v.HostOriginated
		out.UnzonedEgress = v.UnzonedEgress
		out.UnsupportedTupleFamily = v.UnsupportedTupleFamily
		out.FeedPublicationDebt = v.FeedPublicationDebt
		out.FeedPublicationDebtFeeds = v.FeedPublicationDebtFeeds
		out.FeedPublicationDebtNote = v.FeedPublicationDebtNote
		out.RouteDropBeforePolicy = v.RouteDropBeforePolicy
		out.RouteDropClass = v.RouteDropClass
		out.RouteDropNote = v.RouteDropNote
	default:
		out.PolicyName = v.PolicyName
		out.Global = v.Global
		out.FromZone = v.FromZone
		out.ToZone = v.ToZone
		out.PolicyId = proto.Uint32(v.PolicyID)
		out.RuleId = v.RuleID
		out.SourceAddressExcluded = v.SourceAddressExcluded
		out.DestinationAddressExcluded = v.DestinationAddressExcluded
		out.Description = v.Description
		out.SchedulerName = v.SchedulerName
		out.SchedulerActive = v.SchedulerActive
		out.SrcAddresses = v.SrcAddresses
		out.DstAddresses = v.DstAddresses
		out.Applications = v.Applications
		out.RouteDropBeforePolicy = v.RouteDropBeforePolicy
		out.RouteDropClass = v.RouteDropClass
		out.RouteDropNote = v.RouteDropNote
		out.FragmentAssociatedDeny = v.FragmentAssociatedDeny
		out.FragmentDenyNote = v.FragmentDenyNote
	}
	return out
}

// grpcPortValue converts an optional proto3 int32 port field into the
// *uint16 the shared simulator consumes (#17081). nil (absent) stays nil
// (omitted); a present value, including literal 0, is validated and kept.
func grpcPortValue(v *int32) (*uint16, error) {
	if v == nil {
		return nil, nil
	}
	if err := policymatch.ValidatePort(int(*v)); err != nil {
		return nil, err
	}
	return policymatch.PortPtr(uint16(*v)), nil
}

// grpcICMPValue converts an optional proto3 uint32 ICMP type/code field into
// the *uint8 the shared simulator consumes (#3284). nil (field absent) stays
// nil (unspecified). A present value must fit the 8-bit ICMP type/code space;
// anything above 255 is rejected rather than truncated.
func grpcICMPValue(v *uint32) (*uint8, error) {
	if v == nil {
		return nil, nil
	}
	if *v > 255 {
		return nil, fmt.Errorf("%d out of range (0-255)", *v)
	}
	u := uint8(*v)
	return &u, nil
}

// hostInboundToProto projects the shared host-inbound-traffic classifier verdict
// (policymatch.Result.HostInbound, #3627 B1a) onto the structured proto message
// so a gRPC MatchPolicies caller sees WHICH host-inbound-traffic
// system-service/protocol token admits a host-bound tuple — the same detail the
// local CLI `show security match-policies` prints (#4352). It reads the same
// SSOT-backed classifier the CLI and REST surfaces read, so the three cannot
// drift (#3375). Returns nil (field omitted on the wire) for a nil admission (an
// off-host query has no host-inbound gate) or a not-computed status (no meaningful
// admission to report), matching the CLI, which prints nothing in those cases.
func hostInboundToProto(a *dpuserspace.HostInboundAdmission) *pb.HostInboundAdmission {
	if a == nil || a.Status == dpuserspace.HostInboundNotComputed {
		return nil
	}
	return &pb.HostInboundAdmission{
		Status:      hostInboundStatusToProto(a.Status),
		Token:       a.Token,
		Kind:        a.Kind,
		Description: a.Describe(),
	}
}

// hostInboundStatusToProto maps the Go classifier status enum to the proto enum
// explicitly (rather than trusting numeric coincidence) so a future reordering
// of either enum fails to compile here instead of silently mislabeling a verdict.
func hostInboundStatusToProto(s dpuserspace.HostInboundStatus) pb.HostInboundAdmissionStatus {
	switch s {
	case dpuserspace.HostInboundIndeterminate:
		return pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_INDETERMINATE
	case dpuserspace.HostInboundGlobalAccept:
		return pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_GLOBAL_ACCEPT
	case dpuserspace.HostInboundTokenAdmit:
		return pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_TOKEN_ADMIT
	case dpuserspace.HostInboundDenied:
		return pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_DENIED
	case dpuserspace.HostInboundAmbiguous:
		return pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_AMBIGUOUS
	default:
		return pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_NOT_COMPUTED
	}
}

// grpcResolveAddress looks up a named address in the global address book and returns its CIDR suffix.
//
// #9523: a match-all keyword is never looked up as a name, so the text detail
// shows what the dataplane enforces even when a tolerant-loaded object carries
// the keyword's name.
func grpcResolveAddress(cfg *config.Config, name string) string {
	if config.IsPolicyAddressWildcardKeyword(name) {
		return ""
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return ""
	}
	if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
		return " (" + addr.Value + ")"
	}
	if _, ok := ab.AddressSets[name]; ok {
		return " (address-set)"
	}
	return ""
}

// --- Mutation RPCs ---

func (s *Server) ClearCounters(_ context.Context, _ *pb.ClearCountersRequest) (*pb.ClearCountersResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	// #2114/#6743 r2-N4: a clear that RACES a setDataplane(nil) passes the
	// pre-check above and then fails inside the live indirection's
	// forwarder with dataplane.ErrNotPublished. Mapping that to
	// codes.Internal reports the daemon's own lifecycle state as a server
	// fault, and reports the IDENTICAL operator-visible condition with a
	// different code purely because of WHEN the cell cleared — the
	// inconsistency dataplaneActionError exists to remove. Every other
	// failure still maps to Internal.
	if err := s.dp.ClearAllCounters(); err != nil {
		return nil, dataplaneActionError(err)
	}
	return &pb.ClearCountersResponse{}, nil
}
