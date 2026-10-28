package grpcapi

import (
	"github.com/psaab/xpf/pkg/argforms"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16067: argument-scoped allow/deny-commands regexes never fired remotely.
//
// The gRPC gate used to evaluate ONLY the argument-free canonical command
// (`show route table`, `ping`), so a pattern written against argument text
// — `^show route table secret-vrf`, `^ping 10\.99\.`, `^show log .*` —
// matched on the box and never here: an under-deny, fail-open for that
// class of pattern. This file builds the FULL canonicalised command from
// the decoded request (topic + packed parameters, typed RPC fields,
// ShowText filter) so both surfaces judge the same string the on-box
// gate judges (pkg/cli evaluateCommandRegex matches the full line).
//
// The reconstruction mirrors each handler's own decoder: a topic segment
// the handler would reject (unknown selector key, duplicate key,
// malformed segment) yields no command at all, and the caller denies for
// a restricted class rather than judging a string the handler will not
// run. Every reconstructed string is canonicalised against
// cmdtree.OperationalTree; a string that does not canonicalise to itself
// is likewise unresolved. That is the same fail-closed rule the tables
// already apply to an unmapped topic or verb.

// #17179: the reconstruction itself now lives once in
// pkg/argforms/argforms.go (ShowTextForms / SessionForms / MatchForms /
// EventsForms / CanonicalForms / ChargeForms); this file keeps only the
// gRPC method dispatch onto it and the gRPC surface's advisory samples.
// The hand-cloned REST copy (the former rest*Forms in pkg/api) is
// deleted; REST adapters decode query/body into the same wire requests
// and call the same optopic functions, so the two surfaces cannot
// disagree on what an operator's regex means.

// rpcArgumentForms returns the full argument-bearing forms of the command
// an RPC performs, plus its argument-free charge. The full forms are
// ALTERNATIVE spellings of the same command (EvaluateForms unanimity):
// the executed spelling, and — for ShowText filter forms whose selector
// keywords the on-box gate strips into selector spellings — the forms
// canonicalForms would produce there. ok=false means the request cannot
// be named, so a restricted class must deny.
func rpcArgumentForms(cfg *config.Config, fullMethod string, req any, base string) ([]string, bool) {
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return nil, false
	}
	switch method {
	case showTextMethodName:
		st, isShow := req.(*pb.ShowTextRequest)
		if !isShow || st == nil {
			return nil, false
		}
		return argforms.ShowTextForms(base, st)
	case "Ping":
		pr, isPing := req.(*pb.PingRequest)
		if !isPing || pr == nil {
			return nil, false
		}
		if pr.GetTarget() == "" {
			return nil, false
		}
		full := "ping " + pr.GetTarget()
		if pr.GetSource() != "" {
			full += " source " + pr.GetSource()
		}
		if pr.GetRoutingInstance() != "" {
			full += " routing-instance " + pr.GetRoutingInstance()
		}
		return argforms.CanonicalForms(full, base)
	case "Traceroute":
		tr, isTrace := req.(*pb.TracerouteRequest)
		if !isTrace || tr == nil {
			return nil, false
		}
		if tr.GetTarget() == "" {
			return nil, false
		}
		full := "traceroute " + tr.GetTarget()
		if tr.GetSource() != "" {
			full += " source " + tr.GetSource()
		}
		if tr.GetRoutingInstance() != "" {
			full += " routing-instance " + tr.GetRoutingInstance()
		}
		return argforms.CanonicalForms(full, base)
	case "GetSessions":
		gr, isSess := req.(*pb.GetSessionsRequest)
		if !isSess || gr == nil {
			return nil, false
		}
		return argforms.SessionForms(cfg, gr, base)
	case "GetSessionSummary":
		// #16378 fold: GetSessionSummary carries the SAME selector set
		// as GetSessions (buildSessionSummaryFilter forwards every
		// field), but it fell through to the bare
		// `show security flow session summary` charge, so a filtered
		// summary was judged as an unfiltered one — an argument-scoped
		// deny on the selector never fired. Reconstruct the filtered
		// list command; the summary charge stays a form so an anchored
		// `^show security flow session summary$` deny still fires only
		// on the unfiltered execution (its full form differs).
		sr, isSum := req.(*pb.GetSessionSummaryRequest)
		if !isSum || sr == nil {
			return nil, false
		}
		forms, ok := argforms.SessionForms(cfg, &pb.GetSessionsRequest{
			Zone:              sr.GetZone(),
			Protocol:          sr.GetProtocol(),
			SourcePrefix:      sr.GetSourcePrefix(),
			DestinationPrefix: sr.GetDestinationPrefix(),
			SourcePort:        sr.GetSourcePort(),
			DestinationPort:   sr.GetDestinationPort(),
			NatOnly:           sr.GetNatOnly(),
			Application:       sr.GetApplication(),
			InterfaceFilter:   sr.GetInterfaceFilter(),
			SourceNatPool:     sr.GetSourceNatPool(),
		}, "show security flow session")
		if !ok {
			return nil, false
		}
		if forms[0] == "show security flow session" {
			// Unfiltered: the executed command IS the summary.
			return argforms.ChargeForms(base), true
		}
		return forms, true
	case "GetZonePairSummary":
		// No selectors (only include_peer); the bare charge executes.
		return argforms.ChargeForms(base), true
	case "GetEvents":
		// #16378 fold: GetEvents carries zone/action/protocol filters
		// charged as `show log`; it fell through to the bare charge.
		er, isEv := req.(*pb.GetEventsRequest)
		if !isEv || er == nil {
			return nil, false
		}
		return argforms.EventsForms(cfg, er, base)
	case "ClearSessions":
		cr, isClear := req.(*pb.ClearSessionsRequest)
		if !isClear || cr == nil {
			return nil, false
		}
		return argforms.ClearSessionsForms(cr, base)
	case "MonitorInterface":
		mr, isMon := req.(*pb.MonitorInterfaceRequest)
		if !isMon || mr == nil {
			return nil, false
		}
		if mr.GetInterfaceName() == "" {
			return argforms.ChargeForms(base), true
		}
		return argforms.CanonicalForms(base+" "+mr.GetInterfaceName(), base)
	case "MatchPolicies":
		mp, isMatch := req.(*pb.MatchPoliciesRequest)
		if !isMatch || mp == nil {
			return nil, false
		}
		return argforms.MatchForms(mp, base)
	case "ShowInterfacesDetail":
		sd, isDetail := req.(*pb.ShowInterfacesDetailRequest)
		if !isDetail || sd == nil {
			return nil, false
		}
		// #16605: the request discriminates the typed line — Terse
		// selects `show interfaces terse` (or, filtered, the
		// name-filtered terse table the cli refuses to type but the
		// handler serves), bare/filtered selects `show interfaces
		// [<name>]`. Judge that line as forms[0]; the `detail` charge
		// and the sibling spelling join via withAliasForms16605.
		if sd.GetFilter() == "" {
			if sd.GetTerse() {
				return argforms.CanonicalForms("show interfaces terse", base)
			}
			return argforms.CanonicalForms("show interfaces", base)
		}
		// The handler applies the filter as a prefix in terse mode too
		// (showInterfacesTerse receives filterName and skips
		// non-matching rows), so a filtered terse request still
		// executes the filtered command (#16378 fold). The typed
		// spelling is the judged form; the `detail <name>` charge
		// spelling does not canonicalise (detail takes no name in
		// the tree), so only the bare `detail` charge form carries
		// that spelling's path.
		if sd.GetTerse() {
			return argforms.CanonicalForms("show interfaces "+sd.GetFilter(), base)
		}
		return argforms.CanonicalForms("show interfaces "+sd.GetFilter(), base)
	}
	// Every other method's typed fields are selectors the on-box command
	// does not carry as free argument text the operator typed (or the
	// charge is already argument-complete); the bare charge is the form,
	// expanded to its canonical spellings (#16472).
	return argforms.ChargeForms(base), true
}

// argumentSampleCommands16067 are exemplar argument-bearing commands
// this surface can produce, one per argument slot shape, registered
// for the commit-time advisory so an argument-scoped pattern that can
// fire here is not reported on-box-only (#16067). The slot values are
// placeholders; the advisory derives its witnesses from the operator's
// own pattern, never from these values.
var argumentSampleCommands16067 = []string{
	"show firewall filter f1",
	"show security screen ids-option prof1",
	"show security zones trust detail",
	"ping 192.0.2.1",
	"ping 192.0.2.1 source 192.0.2.2",
	"traceroute 192.0.2.1",
	"show route table inet.0",
	"show route protocol bgp",
	"show route 192.0.2.0/24",
	"show log messages",
	"show log messages 50",
	"show security screen statistics zone trust",
	"show security screen ids-option prof1",
	"show interfaces ge-0/0/0",
	"show interfaces detail ge-0/0/0",
	"show class-of-service classifier name public type dscp",
	"show firewall filter f1 family inet",
	"test policy from-zone trust to-zone untrust",
	"test routing destination 192.0.2.0/24",
	"test security-zone interface ge-0/0/0",
	"show security flow session zone trust",
	"show security match-policies from-zone trust to-zone untrust",
}

func init() {
	config.RegisterCommandSurfaceArgumentSamples(grpcSurfaceName, func() []string {
		return append([]string(nil), argumentSampleCommands16067...)
	})
}
