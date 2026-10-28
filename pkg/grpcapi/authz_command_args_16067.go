package grpcapi

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/argforms"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/diagcmd"
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
//
// #17184: there is NO bare-charge default. A method whose fields carry
// operator argument text needs a switch arm; a method whose fields do
// not must be named in methodsWithoutArgumentForms with a reason. The
// pre-#17184 default returned the bare charge for every unlisted
// method, so GetNATDeterministic, ClearDHCPClientIdentifier,
// MonitorPacketDrop and GetNATRuleStats escaped argument-scoped
// denies (and the #16378 fold had already caught five more RPCs in
// the same default).
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
		// #17184 fold (M2): the handler REJECTS a target/source/
		// routing-instance over diagcmd.MaxArgLen (checkDiagArgs,
		// #6904) and never executes such a request, so judge the
		// handler-rejected shape unnameable rather than spelling a
		// command that will not run. Count/size are clamped, never
		// rejected, so they are spelled at their executed values
		// (M1: `ping <host> count <N> size <N>` on-box spelling).
		if err := diagcmd.CheckArgs(pr.GetTarget(), pr.GetSource(), pr.GetRoutingInstance()); err != nil {
			return nil, false
		}
		full := "ping " + pr.GetTarget()
		if pr.GetCount() != 0 {
			full += " count " + strconv.Itoa(diagcmd.ClampPingCount(int(pr.GetCount())))
		}
		if pr.GetSource() != "" {
			full += " source " + pr.GetSource()
		}
		if pr.GetSize() > 0 {
			sz := int(pr.GetSize())
			if sz > diagcmd.MaxPingSize {
				sz = diagcmd.MaxPingSize
			}
			full += " size " + strconv.Itoa(sz)
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
		// #17184 fold (M2): same handler-rejected bound as Ping.
		if err := diagcmd.CheckArgs(tr.GetTarget(), tr.GetSource(), tr.GetRoutingInstance()); err != nil {
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
	case "GetNATDeterministic":
		dr, isDet := req.(*pb.GetNATDeterministicRequest)
		if !isDet || dr == nil {
			return nil, false
		}
		return natDeterministicArgumentForms(dr, base)
	case "ClearDHCPClientIdentifier":
		cr, isClear := req.(*pb.ClearDHCPClientIdentifierRequest)
		if !isClear || cr == nil {
			return nil, false
		}
		if cr.GetInterface() == "" {
			return argforms.ChargeForms(base), true
		}
		return argforms.CanonicalForms(base+" interface "+cr.GetInterface(), base)
	case "MonitorPacketDrop":
		mr, isMon := req.(*pb.MonitorPacketDropRequest)
		if !isMon || mr == nil {
			return nil, false
		}
		return packetDropArgumentForms(mr, base)
	case "GetNATRuleStats":
		nr, isNAT := req.(*pb.GetNATRuleStatsRequest)
		if !isNAT || nr == nil {
			return nil, false
		}
		return natRuleStatsArgumentForms(nr, base)
	}
	if _, named := methodsWithoutArgumentForms[method]; named {
		return argforms.ChargeForms(base), true
	}
	return nil, false
}

// methodsWithoutArgumentForms records, WITH A REASON, every method
// whose request fields do NOT carry operator argument text the on-box
// command spells, so the bare charge IS its argument-complete form
// (#17184, mirroring methodsWithoutCanonicalCommand). A method in
// neither this map nor the rpcArgumentForms switch is unnameable and
// denies for a restricted class; TestEveryRequestFieldIsReconstructedOrNamedAbsent17184
// keeps both directions honest against the generated descriptor and
// the switch's own case labels. Request-decoded families (ShowText,
// SystemAction, GetSystemInfo, GetBGPStatus) reconstruct inside their
// arms/helpers and are named here only for the census direction.
var methodsWithoutArgumentForms = map[string]string{
	"EnterConfigure":           "config-mode entry; governed by deny-configuration, not deny-commands (#9633)",
	"ExitConfigure":            "config-mode exit; governed by deny-configuration (#9633)",
	"Set":                      "configuration mutation; governed by deny-configuration (#9633)",
	"Delete":                   "configuration mutation; governed by deny-configuration (#9633)",
	"Load":                     "configuration content adjudicated per written path (#9633/#9892)",
	"Commit":                   "acts on the candidate as a whole; comment is not command argument text",
	"CommitCheck":              "no request fields; acts on the candidate as a whole",
	"CommitConfirmed":          "minutes is a timer value, not command argument text",
	"ConfirmCommit":            "no request fields; resolves a pending commit",
	"Rollback":                 "governed by deny-configuration; n selects a saved candidate, not command argument text (#9633)",
	"Complete":                 "typed line adjudicated by authorizeCompleteRPCCommand (#14952), not rpcArgumentForms",
	"GetStatus":                "session plumbing probe; exempt from the operational gate (#15077)",
	"GetConfigModeStatus":      "session plumbing probe; exempt from the operational gate (#15077)",
	"ShowConfig":               "config-read path adjudicated by authorizeRPCConfigRead (#14707); format/target are render selectors the command does not spell",
	"ShowCompare":              "config-read path adjudicated by authorizeRPCConfigRead (#14707)",
	"ShowRollback":             "config-read path adjudicated by authorizeRPCConfigRead (#14707)",
	"ListHistory":              "no request fields; the bare charge is argument-complete",
	"GetGlobalStats":           "no request fields; the bare charge is argument-complete",
	"GetZones":                 "no request fields; the bare charge is argument-complete",
	"GetPolicies":              "no request fields; the bare charge is argument-complete",
	"GetNATSource":             "no request fields; the bare charge is argument-complete",
	"GetNATDestination":        "no request fields; the bare charge is argument-complete",
	"GetScreen":                "no request fields; the bare charge is argument-complete",
	"GetDHCPLeases":            "no request fields; the bare charge is argument-complete",
	"GetDHCPClientIdentifiers": "no request fields; the bare charge is argument-complete",
	"GetRoutes":                "no request fields; the bare charge is argument-complete",
	"GetIPsecSA":               "no request fields; the bare charge is argument-complete",
	"GetNATPoolStats":          "no request fields; the bare charge is argument-complete",
	"GetVRRPStatus":            "no request fields; the bare charge is argument-complete",
	"ClearCounters":            "no request fields; the bare charge is argument-complete",
	"GetD11AttestationLedger":  "no request fields; privileged evidence read with no operator command",
	"GetOSPFStatus":            "type selects a status view rpcCanonicalCommand cannot name; no canonical command exists in the tree",
	"GetRIPStatus":             "no request fields and no canonical command exists in the tree",
	"GetISISStatus":            "type selects a status view rpcCanonicalCommand cannot name; no canonical command exists in the tree",
	"GetInterfaces":            "no request fields; the bare charge is argument-complete",
	"SystemAction":             "verb selects the command via rpcCanonicalCommand; target/candidate fields are not command argument text",
	"GetSystemInfo":            "type selects a fixed command via systemInfoCanonicalCommand; no free argument text",
	"GetBGPStatus":             "type selects a fixed command via bgpStatusCanonicalCommand; no free argument text",
}

// natDeterministicArgumentForms rebuilds the deterministic-NAT lookup
// line (#17184). Direction selects the spelling the handler executes;
// an unspecified direction, or the selected direction's missing
// host/ip/port, is a request the handler answers as malformed, so it
// is unnameable here rather than judged on the bare charge.
func natDeterministicArgumentForms(dr *pb.GetNATDeterministicRequest, base string) ([]string, bool) {
	var full string
	switch dr.GetDirection() {
	case pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD:
		if dr.GetInternalHost() == "" {
			return nil, false
		}
		full = base + " internal-host " + dr.GetInternalHost()
	case pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE:
		if dr.GetNatIp() == "" || dr.GetNatPort() == 0 || dr.GetNatPort() > 65535 {
			return nil, false
		}
		full = base + " nat-ip " + dr.GetNatIp() + " nat-port " + strconv.Itoa(int(dr.GetNatPort()))
	default:
		return nil, false
	}
	if dr.GetPool() != "" {
		full += " pool " + dr.GetPool()
	}
	return argforms.CanonicalForms(full, base)
}

// packetDropArgumentForms rebuilds `monitor security packet-drop ...`
// from the request's selectors in the CLI parser's field order
// (cmd/cli/monitor.go); the node is an Options node, so any order
// canonicalises to itself. Out-of-range ports/count the handler
// rejects are unnameable.
func packetDropArgumentForms(mr *pb.MonitorPacketDropRequest, base string) ([]string, bool) {
	if mr.GetSourcePort() > 65535 || mr.GetDestinationPort() > 65535 || mr.GetCount() < 0 || mr.GetCount() > 8192 {
		return nil, false
	}
	full := base
	if v := mr.GetSourcePrefix(); v != "" {
		full += " source-prefix " + v
	}
	if v := mr.GetDestinationPrefix(); v != "" {
		full += " destination-prefix " + v
	}
	if v := mr.GetSourcePort(); v != 0 {
		full += " source-port " + strconv.Itoa(int(v))
	}
	if v := mr.GetDestinationPort(); v != 0 {
		full += " destination-port " + strconv.Itoa(int(v))
	}
	if v := mr.GetProtocol(); v != "" {
		full += " protocol " + v
	}
	if v := mr.GetFromZone(); v != "" {
		full += " from-zone " + v
	}
	if v := mr.GetInterface(); v != "" {
		full += " interface " + v
	}
	if v := mr.GetCount(); v != 0 {
		full += " count " + strconv.Itoa(int(v))
	}
	if v := mr.GetNode(); v != "" {
		full += " node " + v
	}
	if full == base {
		return argforms.ChargeForms(base), true
	}
	return argforms.CanonicalForms(full, base)
}

// natRuleStatsArgumentForms rebuilds the rule-set/rule argument text
// (#17184). The charge already ends in `rule` (the family leaf), and
// `rule-set` is its SIBLING under source/destination, so the rule-set
// spelling is built from the family prefix, never by appending to
// the charge. Both selectors may be present in one request; the CLI
// spells them as two different commands (`... rule-set <name>` lists
// a set, `... rule <name>` filters by rule), so both spellings join
// the form set and EvaluateForms unanimity lets a deny on either
// veto.
func natRuleStatsArgumentForms(nr *pb.GetNATRuleStatsRequest, base string) ([]string, bool) {
	ruleSet, rule := nr.GetRuleSet(), nr.GetRule()
	family := strings.TrimSuffix(base, " rule")
	if family == base {
		return nil, false
	}
	switch {
	case ruleSet == "" && rule == "":
		return argforms.ChargeForms(base), true
	case ruleSet != "" && rule != "":
		bySet, ok := argforms.CanonicalForms(family+" rule-set "+ruleSet, base)
		if !ok {
			return nil, false
		}
		byRule, ok := argforms.CanonicalForms(base+" "+rule, base)
		if !ok {
			return nil, false
		}
		seen := map[string]bool{}
		var forms []string
		for _, group := range [][]string{bySet, byRule} {
			for _, f := range group {
				if !seen[f] {
					seen[f] = true
					forms = append(forms, f)
				}
			}
		}
		return forms, true
	case ruleSet != "":
		return argforms.CanonicalForms(family+" rule-set "+ruleSet, base)
	default:
		return argforms.CanonicalForms(base+" "+rule, base)
	}
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
	"ping 192.0.2.1 count 5 size 1400",
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
	"show security nat source deterministic-nat internal-host 192.0.2.1",
	"show security nat source deterministic-nat nat-ip 192.0.2.1 nat-port 1024",
	"clear dhcp client-identifier interface ge-0/0/0",
	"monitor security packet-drop source-prefix 192.0.2.0/24",
	"show security nat source rule-set rs1",
	"show security nat source rule r1",
}

func init() {
	config.RegisterCommandSurfaceArgumentSamples(grpcSurfaceName, func() []string {
		return append([]string(nil), argumentSampleCommands16067...)
	})
}
