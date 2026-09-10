package grpcapi

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

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
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		// #3375: with no active config the verdict is the deterministic
		// fail-closed default deny — render the same explicit string + typed
		// default_used bit REST returns, so a gRPC client never sees a BLANK
		// action and mis-reads the no-config posture as "no answer".
		nilRes := policymatch.Result{DefaultUsed: true, Action: config.PolicyDeny}
		return &pb.MatchPoliciesResponse{
			Action:      nilRes.DisplayAction(),
			DefaultUsed: true,
			// #3627 M06: echo the queried zone pair even on the no-config
			// fail-closed default deny so a stored diagnostic proves which
			// zone pair produced the verdict.
			QueriedFromZone: req.FromZone,
			QueriedToZone:   req.ToZone,
		}, nil
	}

	// #3355 (H06): the CLI surfaces (show security match-policies / test
	// policy) require BOTH zones; gRPC accepted a missing zone and evaluated as
	// if the empty string were a zone, which the #3355 defined-zone guard would
	// then send straight to the default-policy — a misleading silent verdict for
	// what is really a malformed query. Reject it for parity with the CLI.
	if req.FromZone == "" || req.ToZone == "" {
		return nil, status.Errorf(codes.InvalidArgument, "from-zone and to-zone are required")
	}

	// An empty source/destination IP means "unspecified" (match any),
	// which is a legitimate simulator query. A NON-EMPTY but malformed
	// value is an operator error: net.ParseIP returns nil and
	// matchPolicyAddr treats nil as a wildcard, which would yield a
	// false-positive PERMIT verdict (#1711). Reject it explicitly so the
	// simulator never silently turns garbage input into "any".
	if req.SourceIp != "" && net.ParseIP(req.SourceIp) == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid source-ip %q", req.SourceIp)
	}
	if req.DestinationIp != "" && net.ParseIP(req.DestinationIp) == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid destination-ip %q", req.DestinationIp)
	}

	parsedSrc := net.ParseIP(req.SourceIp)
	parsedDst := net.ParseIP(req.DestinationIp)

	// A negative or >65535 port cannot describe a real packet. The int32
	// wire field accepts both; left unchecked they pass through to the
	// shared matcher, whose port term gates on port > 0, so a negative
	// value silently becomes "no port constraint" and yields a misleading
	// verdict (#3116). 0 stays the unspecified wildcard (proto3 cannot
	// distinguish an unset scalar from 0).
	if err := policymatch.ValidatePort(int(req.SourcePort)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid source-port: %v", err)
	}
	if err := policymatch.ValidatePort(int(req.DestinationPort)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid destination-port: %v", err)
	}

	// A non-empty but unknown/out-of-range protocol token ("tcpp", "999") must
	// not pass through to the shared matcher, whose matchApp short-circuits to
	// match-any for an unresolvable protocol, yielding a misleading verdict for
	// a policy using `application any` (#3108). An empty value stays the
	// unspecified wildcard (match any protocol).
	if err := policymatch.ValidateProtocol(req.Protocol); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// #3284: thread the optional ICMP/ICMPv6 type/code into the simulator so a
	// type-constrained application term (junos-ping = type 8) matches only the
	// declared type. The proto3 optional uint32 carries presence; values
	// outside [0,255] cannot describe a real ICMP packet, so reject them
	// rather than truncate to 8 bits (which would silently alias e.g. 264->8).
	icmpType, err := grpcICMPValue(req.IcmpType)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid icmp-type: %v", err)
	}
	icmpCode, err := grpcICMPValue(req.IcmpCode)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid icmp-code: %v", err)
	}

	// #5579: validate the optional ingress-interface selector against the live
	// config — it must name an interface assigned to from_zone, and must not be a
	// management/cluster lifeline (served unconditionally). An unknown /
	// zone-mismatched / lifeline ref is a fail-closed InvalidArgument, mirroring
	// the src_ip / port / protocol validators above, so the host-inbound
	// classifier is only ever scoped to a real interface of the queried zone.
	if err := dpuserspace.ResolveHostInboundIngressInterface(cfg, req.FromZone, req.IngressInterface); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// #3042: delegate to the single shared simulator so gRPC agrees with the
	// runtime evaluator (exact zone-pair -> wildcard-zone tiers (#3090) ->
	// scoped global (#3148) -> default-policy, predefined + nested-app-set +
	// literal-CIDR + any-ipv4/any-ipv6 + exclusion + feed overlay). The
	// pre-#3042 loop skipped globals, hard-coded "deny (default)", and missed
	// predefined apps / literal CIDRs.
	var overlay map[string][]string
	if s.feedOverlayFn != nil {
		overlay = s.feedOverlayFn()
	}
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone: req.FromZone,
		ToZone:   req.ToZone,
		SrcIP:    parsedSrc,
		DstIP:    parsedDst,
		// #6377: colon-strict text family from the RAW request string so the
		// unsupported-tuple gate does not fold an IPv4-mapped IPv6 source to v4
		// (net.ParseIP has discarded the ':' above).
		SrcFamily: config.NATAddrFamily(req.SourceIp),
		DstFamily: config.NATAddrFamily(req.DestinationIp),
		Protocol:  req.Protocol,
		SrcPort:   int(req.SourcePort),
		DstPort:   int(req.DestinationPort),
		ICMPType:  icmpType,
		ICMPCode:  icmpCode,
		// #5572: a non-first IP fragment (no L4 header) is the flowless packet
		// shape the dataplane calls l4_present == false; the simulator then
		// reproduces the #4569 fragment-associated deny. false (default) is a
		// normal L4-present packet, so an existing client is unchanged.
		NonFirstFragment: req.NonFirstFragment,
		// #5579: scope the host-inbound classifier to this ingress interface's
		// effective view (validated above). "" = zone-scoped, unchanged.
		IngressInterface: req.IngressInterface,
		FeedOverlay:      overlay,
		// #3104: skip scheduler-inactive policies like the runtime does, so the
		// simulator falls through to the next active rule / default-policy.
		PolicyInactiveFn: s.policyInactiveFn(),
	})
	// #3285: a `to-zone junos-host` query that matched no host-bound policy is
	// NOT a transit default — the dataplane host gate returns None (local
	// delivery; no global/default fallback). Signal it explicitly so the client
	// does not render a misleading default-policy verdict for the host path.
	if res.ContentRejected {
		// #3727: the dataplane fails this config closed (unexpandable
		// application-set) and enforces none of its policies. Render the SSOT
		// fail-closed action string (self-describing) so a gRPC client does not
		// read a fabricated permit/deny/default verdict. Matched/DefaultUsed stay
		// false; the structured response has no dedicated content-rejected field,
		// so the explanatory Action string carries the posture (the reasons are
		// surfaced in full on the REST and `test policy` text surfaces).
		return &pb.MatchPoliciesResponse{
			Matched:         false,
			Action:          res.DisplayAction(),
			QueriedFromZone: req.FromZone,
			QueriedToZone:   req.ToZone,
		}, nil
	}
	if res.HostInboundUnmatched {
		// #3375: render the same explanatory action string REST returns instead
		// of leaving it blank, so a gRPC client showing `action` directly gets a
		// self-describing host-inbound verdict (DisplayAction is the SSOT shared
		// with REST). Matched stays false and there is no default-policy fallback.
		return &pb.MatchPoliciesResponse{
			Matched:              false,
			HostInboundUnmatched: true,
			Action:               res.DisplayAction(),
			// #3627 M06: echo the queried zone pair on the host-inbound path so
			// the diagnostic names the tested zones (the host gate returns no
			// matched-policy scope to fill from_zone/to_zone).
			QueriedFromZone: req.FromZone,
			QueriedToZone:   req.ToZone,
			// #3627 B1a: name the admitting host-inbound-traffic token (or report
			// deny / global-accept / indeterminate) so a gRPC client sees WHICH
			// system-service/protocol governs local delivery for this tuple, the
			// same detail the local CLI prints (#4352). nil off-host / not-computed.
			HostInbound: hostInboundToProto(res.HostInbound),
		}, nil
	}
	if !res.Matched {
		return &pb.MatchPoliciesResponse{
			Matched:     false,
			Action:      res.DisplayAction(),
			DefaultUsed: res.DefaultUsed,
			// #3627 M06: echo the queried zone pair on the no-match/default path
			// so a stored default-deny diagnostic proves which zone pair was
			// tested (from_zone/to_zone carry matched-policy scope, unset here).
			QueriedFromZone: req.FromZone,
			QueriedToZone:   req.ToZone,
			// #4373 (E4/H2/H7): a multicast/broadcast/unspecified/loopback
			// destination is dropped at route before policy, so even the default
			// verdict does not describe real forwarding — carry the advisory.
			RouteDropBeforePolicy: res.RouteDropBeforePolicy,
			RouteDropClass:        res.RouteDropClass,
			RouteDropNote:         res.RouteDropNote(),
		}, nil
	}
	return &pb.MatchPoliciesResponse{
		Matched:    true,
		PolicyName: res.PolicyName,
		Global:     res.Global,
		FromZone:   res.FromZone,
		ToZone:     res.ToZone,
		// #3627 M06: also echo the queried zone pair on a positive match. It is
		// the query context, distinct from from_zone/to_zone (the matched
		// policy's declared scope), which can differ for a wildcard-zone or
		// global match.
		QueriedFromZone: req.FromZone,
		QueriedToZone:   req.ToZone,
		// #3623: proto3 explicit presence — set only on a match, so a matched
		// first policy (runtime id 0) is distinguishable on the wire from an
		// unmatched response (field absent). The two early returns above leave
		// PolicyId unset for the unmatched / host-inbound cases.
		PolicyId: proto.Uint32(res.PolicyID),
		// #3668: the stable rule identity (inventory join key) + the
		// source/destination address-exclusion flags so a positive verdict for a
		// negated-address rule conveys the exclusion instead of reading backwards.
		RuleId:                     res.RuleID,
		SourceAddressExcluded:      res.SourceAddressExcluded,
		DestinationAddressExcluded: res.DestinationAddressExcluded,
		// #3685 M05: the matched policy's description (ticket / change context),
		// mirroring the inventory and local CLI result over the same
		// policymatch.Result.
		Description: res.Description,
		// #3685 M06: name the scheduler time-gate and confirm it is currently
		// admitting the rule. A positive match here is by construction active
		// (policyInactiveFn already skipped a scheduler-inactive rule, #3414), so
		// SchedulerActive is true only for a scheduled policy and omitted for an
		// always-on one.
		SchedulerName:   res.SchedulerName,
		SchedulerActive: res.SchedulerName != "",
		Action:          res.DisplayAction(),
		SrcAddresses:    res.SrcAddresses,
		DstAddresses:    res.DstAddresses,
		Applications:    res.Applications,
		// #3627 B1a: a matched `to-zone junos-host` policy still passes through
		// the separate host-inbound-traffic admission gate, so carry the
		// classifier verdict here too (present for any host-bound query; nil for
		// a transit/global match, which has no host gate).
		HostInbound: hostInboundToProto(res.HostInbound),
		// #4373 (E4/H2/H7): a matched policy for a multicast/broadcast/
		// unspecified/loopback destination still does not forward — the flow is
		// dropped at route before policy. Carry the advisory so a positive match
		// verdict is not read as real forwarding.
		RouteDropBeforePolicy: res.RouteDropBeforePolicy,
		RouteDropClass:        res.RouteDropClass,
		RouteDropNote:         res.RouteDropNote(),
		// #5572: a non-first fragment whose permit was overridden to an
		// overlapping port-bearing deny carries the advisory so a gRPC client
		// explains the over-drop identically to the CLI + REST surfaces. The
		// response is already attributed to the enforcing deny above.
		FragmentAssociatedDeny: res.FragmentAssociatedDeny,
		FragmentDenyNote:       res.FragmentDenyNote(),
	}, nil
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

func (s *Server) Complete(_ context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
	// req.Pos is the caller-supplied cursor offset into req.Line. It is an
	// int32 on the wire, so a crafted negative value would make the
	// upper-bound guard below pass (int(-1) < len(text)) and slice
	// text[:-1], panicking the handler goroutine. Reject negatives outright;
	// Pos > len is already safe because the slice is then skipped.
	if req.Pos < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid position")
	}
	text := req.Line
	if int(req.Pos) < len(text) {
		// req.Pos is a BYTE offset into req.Line. Refuse a cut that would
		// land inside a multibyte UTF-8 rune rather than slice a code point
		// in half and emit corrupted completion text. A byte offset is a
		// valid boundary when the byte at that index is a rune start (an
		// ASCII byte or a leading multibyte byte), not a 10xxxxxx
		// continuation byte (#4970).
		if !utf8.RuneStart(text[req.Pos]) {
			return nil, status.Error(codes.InvalidArgument, "position splits a UTF-8 rune")
		}
		text = text[:req.Pos]
	}

	// Pipe filter completion: "show ... | <tab>"
	if candidates := s.completePipeFilter(text); candidates != nil {
		sort.Strings(candidates)
		return &pb.CompleteResponse{Candidates: candidates}, nil
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var pairs []completionPair
	if req.ConfigMode {
		pairs = s.completeConfigPairs(words, partial)
	} else {
		pairs = s.completeOperationalPairs(words, partial)
	}

	sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	resp := &pb.CompleteResponse{
		Candidates:   make([]string, len(pairs)),
		Descriptions: make([]string, len(pairs)),
	}
	for i, p := range pairs {
		resp.Candidates[i] = p.name
		resp.Descriptions[i] = p.desc
	}
	return resp, nil
}

// pipeFilterNames lists available pipe filters for completion.
var pipeFilterNames = []string{"count", "display", "except", "find", "grep", "last", "match", "no-more"}

// completePipeFilter returns pipe filter candidates if the text contains "|".
// Returns nil if no pipe is present (caller should proceed with normal completion).
func (s *Server) completePipeFilter(text string) []string {
	idx := strings.LastIndex(text, "|")
	if idx < 0 {
		return nil
	}
	after := strings.TrimSpace(text[idx+1:])
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	// Right after "|" or "| " — all filters
	if after == "" || (trailingSpace && after == "") {
		return pipeFilterNames
	}

	// User has typed a complete filter + space — no more completions (freeform arg)
	if trailingSpace {
		return []string{}
	}

	// Partial filter name
	var candidates []string
	for _, f := range pipeFilterNames {
		if strings.HasPrefix(f, after) {
			candidates = append(candidates, f)
		}
	}
	return candidates
}

func filterCompletionPairs(tree map[string]*cmdtree.Node, prefix string) []completionPair {
	pairs := make([]completionPair, 0, len(tree))
	for name, node := range tree {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			pairs = append(pairs, completionPair{name: name, desc: node.Desc})
		}
	}
	return pairs
}

func resolveShowConfigurationWords(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	show, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.OperationalTree), words[0])
	if !ok || show != "show" {
		return nil, false
	}
	showNode := cmdtree.OperationalTree[show]
	if showNode == nil || showNode.Children == nil {
		return nil, false
	}
	conf, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(showNode.Children), words[1])
	if !ok || conf != "configuration" {
		return nil, false
	}
	return words[2:], true
}

func (s *Server) completionValueProvider() config.ValueProvider {
	if s == nil || s.store == nil {
		return nil
	}
	return s.valueProvider
}

func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
	// "show configuration <path>" — delegate sub-path to config schema
	if subPath, ok := resolveShowConfigurationWords(words); ok {
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
			subPath = resolvedPath
		}
		schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
		if schemaCompletions != nil {
			var pairs []completionPair
			for _, sc := range schemaCompletions {
				if partial == "" || strings.HasPrefix(sc.Name, partial) {
					pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
				}
			}
			if len(pairs) > 0 {
				return pairs
			}
		}
	}
	var cfg *config.Config
	if s.store != nil {
		cfg = s.store.ActiveConfig()
	}
	candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
	pairs := make([]completionPair, len(candidates))
	for i, c := range candidates {
		pairs[i] = completionPair{name: c.Name, desc: c.Desc}
	}
	return pairs
}

func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
	if len(words) == 0 {
		return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
	}

	resolvedTop, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), words[0])
	if !ok {
		if len(words) == 1 {
			return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
		}
		return nil
	}

	switch resolvedTop {
	case "set", "delete", "activate", "deactivate", "show", "edit":
		// #2051: activate/deactivate complete with schema parity to delete
		// (paths to existing nodes), reusing the shared schema completer.
		pathWords := words[1:]
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
			pathWords = resolvedPath
		}
		schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
		if schemaCompletions == nil {
			return nil
		}
		var pairs []completionPair
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
			}
		}
		return pairs
	case "run":
		var cfg *config.Config
		if s.store != nil {
			cfg = s.store.ActiveConfig()
		}
		names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
		var pairs []completionPair
		for _, name := range names {
			pairs = append(pairs, completionPair{name: name})
		}
		return pairs
	case "commit", "load":
		if len(words) == 1 {
			node := cmdtree.ConfigTopLevel[resolvedTop]
			if node == nil || node.Children == nil {
				return nil
			}
			var pairs []completionPair
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					pairs = append(pairs, completionPair{name: name, desc: child.Desc})
				}
			}
			return pairs
		}
		return nil
	default:
		return nil
	}
}

func appendPredefinedApplicationSetCompletions(out []config.SchemaCompletion) []config.SchemaCompletion {
	emitted := make(map[string]struct{}, len(out)+len(config.PredefinedApplicationSets))
	for _, candidate := range out {
		emitted[candidate.Name] = struct{}{}
	}
	for name := range config.PredefinedApplicationSets {
		if _, exists := emitted[name]; exists {
			continue
		}
		out = append(out, config.SchemaCompletion{
			Name: name,
			Desc: "predefined application-set",
		})
		emitted[name] = struct{}{}
	}
	return out
}

func (s *Server) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
	if s == nil || s.store == nil {
		return nil
	}
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	switch hint {
	case config.ValueHintZoneName:
		var out []config.SchemaCompletion
		for name, zone := range cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			desc := zone.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintAddressName:
		var out []config.SchemaCompletion
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintAppName:
		var out []config.SchemaCompletion
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return appendPredefinedApplicationSetCompletions(out)
	case config.ValueHintAppSetName:
		var out []config.SchemaCompletion
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		return appendPredefinedApplicationSetCompletions(out)
	case config.ValueHintPoolName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.NAT.SourcePools {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "source pool"})
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				out = append(out, config.SchemaCompletion{Name: name, Desc: "destination pool"})
			}
		}
		return out
	case config.ValueHintScreenProfile:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Screen {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "screen profile"})
		}
		return out
	case config.ValueHintStreamName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Log.Streams {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "log stream"})
		}
		return out
	case config.ValueHintInterfaceName:
		var out []config.SchemaCompletion
		for name, iface := range cfg.Interfaces.Interfaces {
			if iface == nil { // #5886: skip a present-but-nil slot
				continue
			}
			desc := iface.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintPolicyAddress:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any IPv4 or IPv6 address"},
			{Name: "any-ipv4", Desc: "Any IPv4 address"},
			{Name: "any-ipv6", Desc: "Any IPv6 address"},
		}
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintPolicyApp:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any application"},
		}
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return appendPredefinedApplicationSetCompletions(out)
	case config.ValueHintPolicyName:
		var policies []*config.Policy
		for i, tok := range path {
			if tok == "from-zone" && i+3 < len(path) && path[i+2] == "to-zone" {
				fromZone := path[i+1]
				toZone := path[i+3]
				for _, zpp := range cfg.Security.Policies {
					// #3476: skip a nil zone-pair set (tolerant / HA-sync
					// path) rather than dereferencing zpp.FromZone.
					if zpp == nil {
						continue
					}
					if zpp.FromZone == fromZone && zpp.ToZone == toZone {
						policies = zpp.Policies
						break
					}
				}
				break
			}
			if tok == "global" {
				policies = cfg.Security.GlobalPolicies
				break
			}
		}
		var out []config.SchemaCompletion
		for _, pol := range policies {
			// #3476: skip a nil policy (Policies / GlobalPolicies are
			// []*Policy) rather than dereferencing pol.Description.
			if pol == nil {
				continue
			}
			desc := pol.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: pol.Name, Desc: desc})
		}
		return out
	case config.ValueHintUnitNumber:
		var ifaceName string
		for i, tok := range path {
			if tok == "interfaces" && i+1 < len(path) {
				ifaceName = path[i+1]
				break
			}
		}
		if ifaceName == "" {
			return nil
		}
		iface := cfg.Interfaces.Interfaces[ifaceName]
		if iface == nil {
			return nil
		}
		var out []config.SchemaCompletion
		for num, unit := range iface.Units {
			if unit == nil { // #5886: skip a present-but-nil unit
				continue
			}
			desc := unit.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})
		}
		return out
	}
	return nil
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

// --- Completion RPC ---

// completionPair holds a candidate name and optional description.
type completionPair struct {
	name string
	desc string
}
