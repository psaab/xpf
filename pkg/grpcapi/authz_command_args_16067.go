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
		if sd.GetFilter() == "" {
			return []string{base}, true
		}
		// `show interfaces terse` takes no name; the handler ignores the
		// filter in terse mode, so the executed command is the bare one.
		if sd.GetTerse() {
			return []string{base}, true
		}
		return canonicalArgumentForms(base+" "+sd.GetFilter(), base)
	}
	// Every other method's typed fields are selectors the on-box command
	// does not carry as free argument text the operator typed (or the
	// charge is already argument-complete); the bare charge is the form.
	return []string{base}, true
}

// canonicalArgumentForms validates full against the operational tree: it
// must canonicalise to itself, exactly as the table entries must
// (#8057). The bare charge is always an additional form, mirroring the
// on-box gate's argument-free prefix form (#9022), so an anchored path
// deny still fires when arguments are present.
func canonicalArgumentForms(full, base string) ([]string, bool) {
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(full))
	if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != full {
		return nil, false
	}
	if full == base {
		return []string{base}, true
	}
	return []string{full, base}, true
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
			return []string{base}, true
		}
		return canonicalArgumentForms(base+" "+filter, base)
	case "route-instance":
		if filter == "" {
			return nil, false
		}
		return canonicalArgumentForms(base+" "+filter, base)
	case "zones-detail", "policies-detail", "policies-hit-count",
		"chassis-cluster-data-plane-flows", "security-log":
		if filter == "" {
			return []string{base}, true
		}
		// These filters are free operator text the on-box dispatcher
		// parses positionally (zone names, `from-zone X to-zone Y`
		// pairs, log selectors). Carrying the text verbatim after the
		// command path reproduces the string an argument-scoped regex
		// was written against; the bare form keeps anchored path rules
		// firing. The text is request data, never a keyword source, so
		// it is not canonicalised word-by-word.
		return []string{base + " " + filter, base}, true
	}

	// Topics with no packed parameter: the bare charge is the command.
	if !strings.Contains(topic, ":") {
		return []string{base}, true
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
		return []string{full, base}, true
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
			return []string{base}, true
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
			return []string{base}, true
		}
		return canonicalArgumentForms(full, base)
	case "cos-scheduler-map":
		name := strings.TrimPrefix(topic, "cos-scheduler-map:")
		if name == "" {
			return []string{base}, true
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
			return []string{base}, true
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
		return []string{base}, true
	}
	// A packed topic with no decoder here: its parameter cannot be
	// reconstructed, so the request is unnameable in full. The bare
	// charge alone would silently re-open the argument-text gap for
	// that topic, so a restricted class denies.
	return nil, false
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
		return []string{base}, true
	}
	return canonicalArgumentForms(full, base)
}

func matchPoliciesArgumentForms(mp *pb.MatchPoliciesRequest, base string) ([]string, bool) {
	if mp.GetFromZone() == "" || mp.GetToZone() == "" {
		// The handler still evaluates with empty zones; the on-box line
		// cannot be spelled without them, so name only what is present.
		if mp.GetFromZone() == "" && mp.GetToZone() == "" &&
			mp.GetSourceIp() == "" && mp.GetDestinationIp() == "" {
			return []string{base}, true
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
	if v := mp.GetSourcePort(); v != 0 {
		full += " source-port " + strconv.Itoa(int(v))
	}
	if v := mp.GetDestinationPort(); v != 0 {
		full += " destination-port " + strconv.Itoa(int(v))
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
		return []string{base}, true
	}
	return canonicalArgumentForms(full, base)
}

// zoneNameForID resolves a wire zone ID to its configured name through
// StableZoneIDOwnerForConfig, the same owner resolution the session
// surfaces render from. ID 0 is the no-filter sentinel, which has no
// on-box name.
func zoneNameForID(cfg *config.Config, id uint32) (string, bool) {
	if cfg == nil || id == 0 || id > 65535 {
		return "", false
	}
	name := config.StableZoneIDOwnerForConfig(cfg, uint16(id))
	return name, name != ""
}

// argumentSampleCommands16067 are exemplar argument-bearing commands
// this surface can produce, one per argument slot shape, registered
// for the commit-time advisory so an argument-scoped pattern that can
// fire here is not reported on-box-only (#16067). The slot values are
// placeholders; the advisory derives its witnesses from the operator's
// own pattern, never from these values.
var argumentSampleCommands16067 = []string{
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
