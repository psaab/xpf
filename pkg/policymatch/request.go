// Shared MatchPolicies front-end (#17198): Request validation, Query
// assembly and Result projection live ONCE here so REST, gRPC and the CLI
// surfaces cannot diverge again (#3709 landed REST-only; #5720 wired the
// typed unsupported_tuple_family bit everywhere except REST).
package policymatch

import (
	"fmt"
	"net"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type Request struct {
	FromZone         string
	ToZone           string
	SrcIP            string // raw text; "" = unspecified
	DstIP            string // raw text; "" = unspecified
	Protocol         string // "" = unspecified
	SrcPort          *uint16
	DstPort          *uint16
	ICMPType         *uint8
	ICMPCode         *uint8
	NonFirstFragment bool
	IngressInterface string // "" = zone-scoped
}

// Validate runs the config-independent grammar checks first (zones, IPs,
// ports, protocol, ICMP) so a malformed query fails identically during the
// boot window (cfg == nil, #3709) and once a config is live, then — only
// with a live config — the config-dependent ingress-interface check.
// Port/ICMP presence values arrive already ranged by the transport
// decoders (grpcPortValue/grpcICMPValue/REST present-value parsing);
// Validate re-checks ICMP range for direct callers. Callers map the shared
// hyphenated zone/IP wording to their historical surface wording where needed.
func (r Request) Validate(cfg *config.Config) error {
	if r.FromZone == "" || r.ToZone == "" {
		return fmt.Errorf("from-zone and to-zone are required")
	}
	if r.SrcIP != "" && net.ParseIP(r.SrcIP) == nil {
		return fmt.Errorf("invalid source-ip %q", r.SrcIP)
	}
	if r.DstIP != "" && net.ParseIP(r.DstIP) == nil {
		return fmt.Errorf("invalid destination-ip %q", r.DstIP)
	}
	if err := ValidateProtocol(r.Protocol); err != nil {
		return err
	}
	if r.ICMPType != nil && *r.ICMPType > 255 {
		return fmt.Errorf("invalid icmp-type: %d out of range (0-255)", *r.ICMPType)
	}
	if r.ICMPCode != nil && *r.ICMPCode > 255 {
		return fmt.Errorf("invalid icmp-code: %d out of range (0-255)", *r.ICMPCode)
	}
	if cfg != nil {
		if err := dpuserspace.ResolveHostInboundIngressInterface(cfg, r.FromZone, r.IngressInterface); err != nil {
			return err
		}
	}
	return nil
}

// Live carries the daemon-local simulator inputs a surface threads into
// Match: the feed overlay, the raw feed-info map (publication debt is
// derived here, once), and the action-aware scheduler predicate already
// bound by the surface (each surface's latch/applied-state wiring stays
// its own; Assemble only consumes the predicate).
type Live struct {
	FeedOverlay         map[string][]string
	Feeds               map[string]FeedInfo
	PolicyInactiveForFn func(*config.Policy) bool
}

// FeedInfo is the minimal feed shape Assemble needs (PublicationDebt only),
// so policymatch does not import pkg/feeds. Surfaces adapt their
// feeds.FeedInfo map via FeedInfos.
type FeedInfo struct {
	PublicationDebt bool
}

// FeedInfos adapts a surface's feed-info map to the shared shape. It takes
// the debt bit as a function value to avoid an import cycle with pkg/feeds.
func FeedInfos[T any](in map[string]T, debt func(T) bool) map[string]FeedInfo {
	if in == nil {
		return nil
	}
	out := make(map[string]FeedInfo, len(in))
	for name, info := range in {
		out[name] = FeedInfo{PublicationDebt: debt(info)}
	}
	return out
}

// PublicationDebt derives the debt set from Live.Feeds (shared loop).
func (l Live) PublicationDebt() map[string]bool {
	var debt map[string]bool
	for name, info := range l.Feeds {
		if info.PublicationDebt {
			if debt == nil {
				debt = make(map[string]bool)
			}
			debt[name] = true
		}
	}
	return debt
}

// Assemble builds the Query for cfg+r under live, owning the
// publication-debt loop and the family threading (#6377) once. cfg must be
// non-nil (callers render the no-config verdict before assembling).
func Assemble(cfg *config.Config, r Request, live Live) Query {
	return Query{
		FromZone:            r.FromZone,
		ToZone:              r.ToZone,
		SrcIP:               net.ParseIP(r.SrcIP),
		DstIP:               net.ParseIP(r.DstIP),
		SrcFamily:           config.NATAddrFamily(r.SrcIP),
		DstFamily:           config.NATAddrFamily(r.DstIP),
		Protocol:            r.Protocol,
		SrcPort:             r.SrcPort,
		DstPort:             r.DstPort,
		ICMPType:            r.ICMPType,
		ICMPCode:            r.ICMPCode,
		NonFirstFragment:    r.NonFirstFragment,
		IngressInterface:    r.IngressInterface,
		FeedOverlay:         live.FeedOverlay,
		FeedPublicationDebt: live.PublicationDebt(),
		PolicyInactiveForFn: live.PolicyInactiveForFn,
	}
}

// Evaluate validates (config-independent checks first), then — for a live
// config — assembles and runs Match. For cfg == nil it returns the
// #3375 fail-closed default-deny Result after validation, so every surface
// renders the boot-window verdict from the same code.
func Evaluate(cfg *config.Config, r Request, live Live) (Result, error) {
	if err := r.Validate(cfg); err != nil {
		return Result{}, err
	}
	if cfg == nil {
		return Result{DefaultUsed: true, Action: config.PolicyDeny}, nil
	}
	return Match(cfg, Assemble(cfg, r, live)), nil
}

// Verdict is the flattened, transport-neutral projection of Result built
// once (including UnsupportedTupleFamily and ContentRejectionReasons).
// REST marshals it (via api.MatchPoliciesResult aliases), gRPC copies it,
// CLIs render from Result directly. Field names mirror the REST JSON /
// proto semantics; PolicyIDSet distinguishes matched-id-0 (#3623).
type Verdict struct {
	Matched                    bool
	Global                     bool
	DefaultUsed                bool
	PolicyName                 string
	PolicyID                   uint32
	PolicyIDSet                bool
	RuleID                     string
	Description                string
	SchedulerName              string
	SchedulerActive            bool
	Action                     string // DisplayAction()
	FromZone                   string // matched scope
	ToZone                     string
	QueriedFromZone            string
	QueriedToZone              string
	SrcAddresses               []string
	DstAddresses               []string
	SourceAddressExcluded      bool
	DestinationAddressExcluded bool
	Applications               []string
	HostInboundUnmatched       bool
	ContentRejected            bool
	ContentRejectionReasons    []string
	UnzonedIngress             bool
	HostOriginated             bool
	UnzonedEgress              bool
	UnsupportedTupleFamily     bool
	V4MappedCompatIngressDrop  bool
	RouteDropBeforePolicy      bool
	RouteDropClass             string
	RouteDropNote              string
	FragmentAssociatedDeny     bool
	FragmentDenyNote           string
	FeedPublicationDebt        bool
	FeedPublicationDebtFeeds   []string
	FeedPublicationDebtNote    string
	PostNATInputNote           string
	HostInboundStatus          string // "" = absent
	HostInboundToken           string
	HostInboundKind            string
	HostInboundDescription     string
}

// VerdictFrom builds the flattened Verdict for res over the queried zone
// pair. It encodes the per-branch field selection the surfaces used to
// hand-write (ContentRejected / V4Mapped / HostInboundUnmatched /
// unmatched / matched), so a new Result field is projected in one place.
func VerdictFrom(res Result, queriedFrom, queriedTo string) Verdict {
	v := Verdict{
		QueriedFromZone:  queriedFrom,
		QueriedToZone:    queriedTo,
		PostNATInputNote: res.PostNATInputNote,
		Action:           res.DisplayAction(),
	}
	// HostInbound rides matched-host and unmatched-host verdicts only.
	if res.HostInbound != nil && res.HostInbound.Status != dpuserspace.HostInboundNotComputed {
		v.HostInboundStatus = res.HostInbound.Status.String()
		v.HostInboundToken = res.HostInbound.Token
		v.HostInboundKind = res.HostInbound.Kind
		v.HostInboundDescription = res.HostInbound.Describe()
	}
	switch {
	case res.ContentRejected:
		v.ContentRejected = true
		v.ContentRejectionReasons = res.ContentRejectionReasons
		// #9993: the impossible-tuple / ingress-drop advisories still ride a
		// content-rejected result; keep the typed bits visible.
		v.UnsupportedTupleFamily = res.UnsupportedTupleFamily
		v.V4MappedCompatIngressDrop = res.V4MappedCompatIngressDrop
	case res.V4MappedCompatIngressDrop:
		v.V4MappedCompatIngressDrop = true
		v.UnsupportedTupleFamily = res.UnsupportedTupleFamily
	case res.HostInboundUnmatched:
		v.HostInboundUnmatched = true
	case !res.Matched:
		v.DefaultUsed = res.DefaultUsed
		v.FeedPublicationDebt = res.FeedPublicationDebt
		v.FeedPublicationDebtFeeds = res.FeedPublicationDebtNames
		v.FeedPublicationDebtNote = res.FeedPublicationDebtNote()
		v.UnzonedIngress = res.UnzonedIngress
		v.HostOriginated = res.HostOriginated
		v.UnzonedEgress = res.UnzonedEgress
		v.UnsupportedTupleFamily = res.UnsupportedTupleFamily
		v.RouteDropBeforePolicy = res.RouteDropBeforePolicy
		v.RouteDropClass = res.RouteDropClass
		v.RouteDropNote = res.RouteDropNote()
	default:
		v.Matched = true
		v.PolicyName = res.PolicyName
		v.Global = res.Global
		v.FromZone = res.FromZone
		v.ToZone = res.ToZone
		v.PolicyID = res.PolicyID
		v.PolicyIDSet = true
		v.RuleID = res.RuleID
		v.Description = res.Description
		v.SchedulerName = res.SchedulerName
		v.SchedulerActive = res.SchedulerName != ""
		v.SrcAddresses = res.SrcAddresses
		v.DstAddresses = res.DstAddresses
		v.SourceAddressExcluded = res.SourceAddressExcluded
		v.DestinationAddressExcluded = res.DestinationAddressExcluded
		v.Applications = res.Applications
		v.RouteDropBeforePolicy = res.RouteDropBeforePolicy
		v.RouteDropClass = res.RouteDropClass
		v.RouteDropNote = res.RouteDropNote()
		v.FragmentAssociatedDeny = res.FragmentAssociatedDeny
		v.FragmentDenyNote = res.FragmentDenyNote()
	}
	return v
}
