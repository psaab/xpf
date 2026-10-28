package grpcapi

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
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
		return showTextArgumentForms(base, st)
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
		return canonicalArgumentForms(full, base)
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
		return canonicalArgumentForms(full, base)
	case "GetSessions":
		gr, isSess := req.(*pb.GetSessionsRequest)
		if !isSess || gr == nil {
			return nil, false
		}
		return sessionArgumentForms(cfg, gr, base)
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
		forms, ok := sessionArgumentForms(cfg, &pb.GetSessionsRequest{
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
			return chargeForms16472(base), true
		}
		return forms, true
	case "GetZonePairSummary":
		// No selectors (only include_peer); the bare charge executes.
		return chargeForms16472(base), true
	case "GetEvents":
		// #16378 fold: GetEvents carries zone/action/protocol filters
		// charged as `show log`; it fell through to the bare charge.
		er, isEv := req.(*pb.GetEventsRequest)
		if !isEv || er == nil {
			return nil, false
		}
		return eventsArgumentForms(cfg, er, base)
	case "ClearSessions":
		cr, isClear := req.(*pb.ClearSessionsRequest)
		if !isClear || cr == nil {
			return nil, false
		}
		return clearSessionsArgumentForms(cr, base)
	case "MonitorInterface":
		mr, isMon := req.(*pb.MonitorInterfaceRequest)
		if !isMon || mr == nil {
			return nil, false
		}
		if mr.GetInterfaceName() == "" {
			return chargeForms16472(base), true
		}
		return canonicalArgumentForms(base+" "+mr.GetInterfaceName(), base)
	case "MatchPolicies":
		mp, isMatch := req.(*pb.MatchPoliciesRequest)
		if !isMatch || mp == nil {
			return nil, false
		}
		return matchPoliciesArgumentForms(mp, base)
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
				return canonicalArgumentForms("show interfaces terse", base)
			}
			return canonicalArgumentForms("show interfaces", base)
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
			return canonicalArgumentForms("show interfaces "+sd.GetFilter(), base)
		}
		return canonicalArgumentForms("show interfaces "+sd.GetFilter(), base)
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
			return chargeForms16472(base), true
		}
		return canonicalArgumentForms(base+" interface "+cr.GetInterface(), base)
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
		return chargeForms16472(base), true
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
	return canonicalArgumentForms(full, base)
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
		return chargeForms16472(base), true
	}
	return canonicalArgumentForms(full, base)
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
		return chargeForms16472(base), true
	case ruleSet != "" && rule != "":
		bySet, ok := canonicalArgumentForms(family+" rule-set "+ruleSet, base)
		if !ok {
			return nil, false
		}
		byRule, ok := canonicalArgumentForms(base+" "+rule, base)
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
		return canonicalArgumentForms(family+" rule-set "+ruleSet, base)
	default:
		return canonicalArgumentForms(base+" "+rule, base)
	}
}

// canonicalArgumentForms validates full against the operational tree: it
// must canonicalise to itself, exactly as the table entries must
// (#8057). The bare charge is always an additional form, mirroring the
// on-box gate's argument-free prefix form (#9022), so an anchored path
// deny still fires when arguments are present.
//
// #16472: when the full line canonicalises, its CanonicalForms (base,
// keyword-full and selector spellings) join the form set, so the remote
// gate judges the same argument-free spellings the console derives
// from the typed line. The gate additionally applies the console's
// #14687 distinct-narrower rescue (shared cmdtree helper) on a denial.
func canonicalArgumentForms(full, base string) ([]string, bool) {
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(full))
	if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != full {
		return nil, false
	}
	return argumentFormsWithCanonical16472(full, base, canon), true
}

// argumentFormsWithCanonical16472 assembles the remote form set for one
// executed command: the full line, the registry charge, and the
// canonical forms (base / keyword-full / selectors) of both the full
// line and the charge. Duplicates are dropped, order preserved with
// the full line first (EvaluateForms' verdicts[0] convention). The
// allow-bearing #14687 rescue divergence is documented at the gate.
func argumentFormsWithCanonical16472(full, base string, canon []string) []string {
	seen := map[string]bool{}
	var forms []string
	add := func(f string) {
		if f != "" && !seen[f] {
			seen[f] = true
			forms = append(forms, f)
		}
	}
	add(full)
	add(base)
	if canon != nil {
		b, f, sels, _ := cmdtree.CanonicalForms(canon)
		add(b)
		add(f)
		for _, s := range sels {
			add(s)
		}
	}
	// The charge's OWN canonical forms only (#16472 narrowed): a
	// selector spelling the charge does not itself declare
	// (`show security policies` under the `... detail` charge,
	// `show route` under `show route table`) must not become a
	// remote form, or an anchored deny on it would fire remotely
	// while the executed console command is allowed. Deriving a
	// value-bearing full form's forms is likewise excluded: the
	// full slice's forms already entered via canon above.
	return forms
}

// chargeForms16472 expands a bare registry charge into its canonical
// form set (charge + base/full/selector spellings). Used where the
// executed command IS the charge (no argument to reconstruct).
func chargeForms16472(base string) []string {
	forms := []string{base}
	if bc, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(base)); res == cmdtree.CanonicalOK {
		b, f, sels, _ := cmdtree.CanonicalForms(bc)
		for _, x := range append([]string{b, f}, sels...) {
			dup := false
			for _, g := range forms {
				if g == x {
					dup = true
				}
			}
			if !dup && x != "" {
				forms = append(forms, x)
			}
		}
	}
	return forms
}

// canonicalFormsOf16472 returns the CanonicalForms of an already
// canonical token slice, for the gate's #14687 rescue check.
func canonicalFormsOf16472(canon []string) (base, full string, selectors []string, chain string) {
	return cmdtree.CanonicalForms(canon)
}

// eventsArgumentForms rebuilds `show security log …` from a GetEvents
// request. GetEvents is charged as `show log`, but it reads the
// security event buffer (server_show_events.go), whose on-box command
// is `show security log [zone Z] [protocol P] [action A]`; judging the
// bare `show log` missed every selector (#16378 fold).
func eventsArgumentForms(cfg *config.Config, er *pb.GetEventsRequest, base string) ([]string, bool) {
	full := "show security log"
	if er.GetHasZone() && er.GetZone() == 0 {
		// Zone 0 is the selectable unknown zone (#3338); it has no
		// configured name, so it cannot be spelled on-box.
		return nil, false
	}
	if er.GetZone() != 0 {
		name, ok := zoneNameForID(cfg, er.GetZone())
		if !ok {
			return nil, false
		}
		full += " zone " + name
	}
	if v := er.GetProtocol(); v != "" {
		full += " protocol " + v
	}
	if v := er.GetAction(); v != "" {
		full += " action " + v
	}
	if full == "show security log" {
		return chargeForms16472(base), true
	}
	return canonicalArgumentForms(full, base)
}

// clearSessionsArgumentForms rebuilds `clear security flow session …`
// from a ClearSessions request, whose selectors carry the zone NAME
// already (unlike GetSessions' numeric zone ID).
func clearSessionsArgumentForms(cr *pb.ClearSessionsRequest, base string) ([]string, bool) {
	full := base
	if v := cr.GetZone(); v != "" {
		full += " zone " + v
	}
	if v := cr.GetProtocol(); v != "" {
		full += " protocol " + v
	}
	if v := cr.GetSourcePrefix(); v != "" {
		full += " source-prefix " + v
	}
	if v := cr.GetDestinationPrefix(); v != "" {
		full += " destination-prefix " + v
	}
	if v := cr.GetSourcePort(); v != 0 {
		full += " source-port " + strconv.Itoa(int(v))
	}
	if v := cr.GetDestinationPort(); v != 0 {
		full += " destination-port " + strconv.Itoa(int(v))
	}
	if cr.GetNatOnly() {
		full += " nat-only"
	}
	if v := cr.GetApplication(); v != "" {
		full += " application " + v
	}
	if v := cr.GetInterface(); v != "" {
		full += " interface " + v
	}
	if v := cr.GetSourceNatPool(); v != "" {
		full += " source-nat-pool " + v
	}
	if full == base {
		return chargeForms16472(base), true
	}
	return canonicalArgumentForms(full, base)
}

// showTextArgumentForms reconstructs the executed command from a ShowText
// topic and its Filter. Packed-parameter topics decode with the same
// grammar their handlers use; a malformed packing is unresolved.
func showTextArgumentForms(base string, st *pb.ShowTextRequest) ([]string, bool) {
	topic := st.GetTopic()
	filter := st.GetFilter()

	// Filter-carried selectors: the topic is exact and the Filter holds
	// the argument the operator typed (an interface name, a zone-pair
	// filter text, a session-log filter line). Where the on-box grammar
	// names the selector with a keyword the reconstruction uses it;
	// otherwise the filter follows the command as the on-box line does.
	switch topic {
	case "interfaces-detail", "interfaces-extensive", "interfaces-queue":
		if filter == "" {
			return chargeForms16472(base), true
		}
		return canonicalArgumentForms(base+" "+filter, base)
	case "route-instance":
		if filter == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+filter, base)
	case "zones-detail":
		// #16472: the filter is a bare zone NAME (cmd/cli SplitModifiers
		// selector), so the executed line is the canonicalisable
		// `show security zones <zone> detail`; judging it through
		// CanonicalForms yields the console's exact verdict, including
		// its #14687 rescue (allowed) — where the free-text spelling
		// `... detail <zone>` would have fabricated a denied base hit.
		if filter == "" {
			return chargeForms16472(base), true
		}
		if strings.ContainsAny(filter, " \t") {
			return nil, false
		}
		return canonicalArgumentForms("show security zones "+filter+" detail", base)
	case "policies-detail", "policies-hit-count",
		"chassis-cluster-data-plane-flows", "security-log":
		if filter == "" {
			return chargeForms16472(base), true
		}
		// #16472: policies-detail / policies-hit-count filters are the
		// `from-zone X to-zone Y` selector text cmd/cli's
		// parsePolicyShowQuery admits (server_show_policies_text.go's
		// parseZoneFilter rejects anything else). Reconstruct the
		// console's selector-first spelling — `show security policies
		// from-zone X to-zone Y detail` — and judge it through
		// canonicalArgumentForms, so the anchored base deny
		// (`^show security policies$`) that denies the filtered
		// console line denies here too; a filter the handler would
		// reject is unnameable and denies for a restricted class.
		// The remaining topics (flows, security-log) keep the verbatim
		// free-text spelling: their filters are not zone selectors.
		if topic == "policies-detail" || topic == "policies-hit-count" {
			view := "detail"
			if topic == "policies-hit-count" {
				view = "hit-count"
			}
			return policiesFilterForms16472(base, view, filter)
		}
		forms := []string{base + " " + filter}
		for _, f := range chargeForms16472(base) {
			dup := false
			for _, g := range forms {
				if g == f {
					dup = true
				}
			}
			if !dup {
				forms = append(forms, f)
			}
		}
		return forms, true
	}

	// Topics with no packed parameter: the bare charge is the command.
	if !strings.Contains(topic, ":") {
		return chargeForms16472(base), true
	}

	prefix, rest, _ := strings.Cut(topic, ":")
	_ = rest
	switch prefix {
	case "route-table":
		name := strings.TrimPrefix(topic, "route-table:")
		if name == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "route-protocol":
		name := strings.TrimSpace(strings.TrimPrefix(topic, "route-protocol:"))
		if name == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "route-prefix":
		packed := strings.TrimPrefix(topic, "route-prefix:")
		if packed == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+packed, base)
	case "log":
		// "log:<filename>[:<count>]" — `show log <filename> [<count>]`.
		parts := strings.SplitN(topic, ":", 3)
		if len(parts) < 2 || parts[1] == "" {
			return nil, false
		}
		full := base + " " + parts[1]
		if len(parts) == 3 && parts[2] != "" {
			if _, err := strconv.Atoi(parts[2]); err != nil {
				// The handler ignores a non-numeric count (n stays 50);
				// the executed command is still `show log <name>`.
			} else {
				full += " " + parts[2]
			}
		}
		return argumentFormsWithCanonical16472(full, base, nil), true
	case "applications":
		name := strings.TrimPrefix(topic, "applications:")
		if name == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "class-of-service":
		name := strings.TrimPrefix(topic, "class-of-service:")
		if name == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "interfaces-queue":
		name := strings.TrimPrefix(topic, "interfaces-queue:")
		if name == "" {
			if filter != "" {
				return canonicalArgumentForms(base+" "+filter, base)
			}
			return chargeForms16472(base), true
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "cos-classifier", "cos-rewrite-rule":
		name, typ := cmdtree.ParseCoSNameTypeTopic(topic, prefix)
		full := base
		if name != "" {
			full += " name " + name
		}
		if typ != "" {
			full += " type " + typ
		}
		if full == base {
			return chargeForms16472(base), true
		}
		return canonicalArgumentForms(full, base)
	case "cos-scheduler-map":
		name := strings.TrimPrefix(topic, "cos-scheduler-map:")
		if name == "" {
			return chargeForms16472(base), true
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "screen-ids-option", "screen-ids-option-detail":
		name := strings.TrimPrefix(topic, prefix+":")
		if name == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+name, base)
	case "screen-statistics":
		zone := strings.TrimPrefix(topic, "screen-statistics:")
		if zone == "" {
			return nil, false
		}
		// Registry charge is `show security screen statistics zone`; the
		// on-box spelling carries the zone as that keyword's value.
		return canonicalArgumentForms(base+" "+zone, base)
	case "firewall-filter":
		return firewallFilterForms(topic, "firewall-filter:", base, false)
	case "firewall-effective-filter":
		return firewallFilterForms(topic, "firewall-effective-filter:", base, true)
	case "firewall-effective":
		family := strings.TrimPrefix(topic, "firewall-effective:")
		if family == topic {
			return chargeForms16472(base), true
		}
		switch family {
		case "inet", "inet6":
			return canonicalArgumentForms(base+" family "+family, base)
		}
		return nil, false
	case "test-policy":
		return testPolicyForms(topic, base)
	case "test-routing":
		return testRoutingForms(topic, base)
	case "test-zone":
		return testZoneForms(topic, base)
	case "sessions-top":
		// Registry keys are `sessions-top:bytes|packets`, charged as
		// `show security flow session sort-by bytes|packets` already.
		return chargeForms16472(base), true
	}
	// A packed topic with no decoder here: its parameter cannot be
	// reconstructed, so the request is unnameable in full. The bare
	// charge alone would silently re-open the argument-text gap for
	// that topic, so a restricted class denies.
	return nil, false
}

// policiesFilterForms16472 rebuilds the console spelling of a filtered
// policies detail/hit-count command from its ShowText Filter
// (`from-zone X to-zone Y`, either pair optional, in the order cmd/cli
// joined it). Any other token is a filter the handler rejects
// (parseZoneFilter), so it is unnameable here.
func policiesFilterForms16472(base, view, filter string) ([]string, bool) {
	fields := strings.Fields(filter)
	full := "show security policies"
	seen := map[string]bool{}
	for i := 0; i < len(fields); i++ {
		kw := fields[i]
		if kw != "from-zone" && kw != "to-zone" {
			return nil, false
		}
		if seen[kw] || i+1 >= len(fields) {
			return nil, false
		}
		seen[kw] = true
		full += " " + kw + " " + fields[i+1]
		i++
	}
	full += " " + view
	return canonicalArgumentForms(full, base)
}

// firewallFilterForms decodes `firewall-filter:<name>[:<family>]` (and the
// effective twin) the way showFirewallFilter does: the LAST colon splits
// the family, and only inet/inet6 are families the handler honours.
func firewallFilterForms(topic, prefix, base string, effective bool) ([]string, bool) {
	rest := strings.TrimPrefix(topic, prefix)
	name, family := rest, ""
	if idx := strings.LastIndex(rest, ":"); idx > 0 {
		if fam := rest[idx+1:]; fam == "inet" || fam == "inet6" {
			name, family = rest[:idx], fam
		}
	}
	if name == "" {
		return nil, false
	}
	full := base + " " + name
	if effective {
		full += " effective"
	}
	if family != "" {
		full += " family " + family
	}
	return canonicalArgumentForms(full, base)
}

// packedSelectors parses a `k=v,k=v` packed parameter string with the
// handlers' grammar: malformed segments, empty keys/values, unknown keys
// and duplicate keys are all errors (#3696/#3709 shape).
func packedSelectors(params string, known map[string]bool) (map[string]string, bool) {
	out := make(map[string]string)
	if params == "" {
		return out, true
	}
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, false
		}
		if !known[parts[0]] {
			return nil, false
		}
		if _, dup := out[parts[0]]; dup {
			return nil, false
		}
		out[parts[0]] = parts[1]
	}
	return out, true
}

func testPolicyForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-policy:")
	sel, ok := packedSelectors(params, map[string]bool{
		"from": true, "to": true, "src": true, "dst": true,
		"srcport": true, "port": true, "proto": true,
		"ictype": true, "iccode": true, "frag": true, "iif": true,
	})
	if !ok || sel["from"] == "" || sel["to"] == "" {
		return nil, false
	}
	full := base + " from-zone " + sel["from"] + " to-zone " + sel["to"]
	if v := sel["src"]; v != "" {
		full += " source-ip " + v
	}
	if v := sel["dst"]; v != "" {
		full += " destination-ip " + v
	}
	if v := sel["srcport"]; v != "" {
		full += " source-port " + v
	}
	if v := sel["port"]; v != "" {
		full += " destination-port " + v
	}
	if v := sel["proto"]; v != "" {
		full += " protocol " + v
	}
	if v := sel["ictype"]; v != "" {
		full += " icmp-type " + v
	}
	if v := sel["iccode"]; v != "" {
		full += " icmp-code " + v
	}
	if sel["frag"] == "1" || sel["frag"] == "true" {
		full += " non-first-fragment"
	}
	if v := sel["iif"]; v != "" {
		full += " ingress-interface " + v
	}
	return canonicalArgumentForms(full, base)
}

func testRoutingForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-routing:")
	sel, ok := packedSelectors(params, map[string]bool{"dest": true, "instance": true})
	if !ok || sel["dest"] == "" {
		return nil, false
	}
	full := base + " destination " + sel["dest"]
	if v := sel["instance"]; v != "" {
		full += " instance " + v
	}
	return canonicalArgumentForms(full, base)
}

func testZoneForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-zone:")
	sel, ok := packedSelectors(params, map[string]bool{"interface": true})
	if !ok || sel["interface"] == "" {
		return nil, false
	}
	return canonicalArgumentForms(base+" interface "+sel["interface"], base)
}

// sessionArgumentForms rebuilds `show security flow session …` from a
// GetSessionsRequest. The zone travels as a numeric ID on the wire; it is
// resolved to its configured name through the same StableZoneID space the
// session handlers use, and an unresolvable ID is unnameable.
func sessionArgumentForms(cfg *config.Config, gr *pb.GetSessionsRequest, base string) ([]string, bool) {
	full := base
	if gr.GetZone() != 0 {
		name, ok := zoneNameForID(cfg, gr.GetZone())
		if !ok {
			return nil, false
		}
		full += " zone " + name
	}
	if v := gr.GetProtocol(); v != "" {
		full += " protocol " + v
	}
	if v := gr.GetSourcePrefix(); v != "" {
		full += " source-prefix " + v
	}
	if v := gr.GetDestinationPrefix(); v != "" {
		full += " destination-prefix " + v
	}
	if v := gr.GetSourcePort(); v != 0 {
		full += " source-port " + strconv.Itoa(int(v))
	}
	if v := gr.GetDestinationPort(); v != 0 {
		full += " destination-port " + strconv.Itoa(int(v))
	}
	if gr.GetNatOnly() {
		full += " nat-only"
	}
	if v := gr.GetApplication(); v != "" {
		full += " application " + v
	}
	if v := gr.GetInterfaceFilter(); v != "" {
		full += " interface " + v
	}
	if v := gr.GetSourceNatPool(); v != "" {
		full += " source-nat-pool " + v
	}
	if full == base {
		return chargeForms16472(base), true
	}
	return canonicalArgumentForms(full, base)
}

func matchPoliciesArgumentForms(mp *pb.MatchPoliciesRequest, base string) ([]string, bool) {
	if mp.GetFromZone() == "" || mp.GetToZone() == "" {
		// The handler still evaluates with empty zones; the on-box line
		// cannot be spelled without them, so name only what is present.
		if mp.GetFromZone() == "" && mp.GetToZone() == "" &&
			mp.GetSourceIp() == "" && mp.GetDestinationIp() == "" {
			return chargeForms16472(base), true
		}
	}
	full := base
	if v := mp.GetFromZone(); v != "" {
		full += " from-zone " + v
	}
	if v := mp.GetToZone(); v != "" {
		full += " to-zone " + v
	}
	if v := mp.GetSourceIp(); v != "" {
		full += " source-ip " + v
	}
	if v := mp.GetDestinationIp(); v != "" {
		full += " destination-ip " + v
	}
	if mp.SourcePort != nil {
		full += " source-port " + strconv.Itoa(int(*mp.SourcePort))
	}
	if mp.DestinationPort != nil {
		full += " destination-port " + strconv.Itoa(int(*mp.DestinationPort))
	}
	if v := mp.GetProtocol(); v != "" {
		full += " protocol " + v
	}
	if mp.IcmpType != nil {
		full += " icmp-type " + strconv.Itoa(int(*mp.IcmpType))
	}
	if mp.IcmpCode != nil {
		full += " icmp-code " + strconv.Itoa(int(*mp.IcmpCode))
	}
	if mp.GetNonFirstFragment() {
		full += " non-first-fragment"
	}
	if v := mp.GetIngressInterface(); v != "" {
		full += " ingress-interface " + v
	}
	if full == base {
		return chargeForms16472(base), true
	}
	return canonicalArgumentForms(full, base)
}

// zoneNameForID resolves a wire zone ID to its configured name through
// StableZoneIDOwnerForConfig, the same owner resolution the session
// surfaces render from. ID 0 is the no-filter sentinel, which has no
// on-box name.
func zoneNameForID(cfg *config.Config, id uint32) (string, bool) {
	if cfg == nil || id == 0 {
		return "", false
	}
	name := config.StableZoneIDOwnerForConfig(cfg, id)
	return name, name != ""
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
