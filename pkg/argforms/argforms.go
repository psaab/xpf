package argforms

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #17179 (R4-Q37-02): the single surface-neutral reconstruction of the
// argument-bearing operational command a remote request performs.
//
// #16067 shipped this logic twice in one commit — pkg/grpcapi
// (authz_command_args_16067.go) and pkg/api (the rest* clones) — and the
// copies already disagreed in opposite directions: gRPC MatchPolicies
// dropped protocol/ports/icmp/fragment/ingress-interface when zones and
// IPs were empty (returning the bare charge), while REST kept them; gRPC
// GetEvents carried zone/protocol/action selectors while the REST
// /security/events route (same `show log` charge, same selectors) had no
// arm at all and judged the bare charge; and the REST show-text decoder
// decoded 28 packed/detail topics showTextHandler 400s, so every served
// (bare) topic fell through to the bare return while tests manufactured
// verdicts for unserved topics. This file is the one implementation both
// surfaces call. It lives in this surface-neutral leaf beside the
// optopic registry (#16136, which owns the topic/verb metadata)
// because pkg/api must not import pkg/grpcapi and pkg/optopic cannot
// host it (pkg/cmdtree derives its topic table from pkg/optopic, so a
// cmdtree-dependent file there would be an import cycle); argforms
// imports only cmdtree/config and the wire types (xpfv1 is a leaf
// generated package). The reconstruction is a
// pure function of (base, topic/filter or typed wire request); decoding
// the wire (query string vs protobuf) stays in each surface's adapter.
//
// The reconstruction mirrors each handler's own decoder: a topic segment
// the handler would reject (unknown selector key, duplicate key,
// malformed segment) yields no command at all, and the caller denies for
// a restricted class rather than judging a string the handler will not
// run. Every reconstructed string is canonicalised against
// cmdtree.OperationalTree; a string that does not canonicalise to itself
// is likewise unresolved. That is the same fail-closed rule the tables
// already apply to an unmapped topic or verb.
//
// Forms are ALTERNATIVE spellings of the same command (EvaluateForms
// unanimity): the executed spelling first, then the argument-free charge,
// then — #16472 — the canonical base/keyword-full/selector spellings of
// both, so an anchored path deny still fires when arguments are present.

// CanonicalForms validates full against the operational tree: it
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
func CanonicalForms(full, base string) ([]string, bool) {
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(full))
	if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != full {
		return nil, false
	}
	return FormsWithCanonical(full, base, canon), true
}

// FormsWithCanonical assembles the remote form set for one
// executed command: the full line, the registry charge, and the
// canonical forms (base / keyword-full / selectors) of both the full
// line and the charge. Duplicates are dropped, order preserved with
// the full line first (EvaluateForms' verdicts[0] convention). The
// allow-bearing #14687 rescue divergence is documented at the gate.
func FormsWithCanonical(full, base string, canon []string) []string {
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

// ChargeForms expands a bare registry charge into its canonical
// form set (charge + base/full/selector spellings). Used where the
// executed command IS the charge (no argument to reconstruct).
func ChargeForms(base string) []string {
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

// CanonicalFormsOf returns the CanonicalForms of an already
// canonical token slice, for the gate's #14687 rescue check.
func CanonicalFormsOf(canon []string) (base, full string, selectors []string, chain string) {
	return cmdtree.CanonicalForms(canon)
}

// EventsForms rebuilds `show security log …` from a GetEvents
// request. GetEvents is charged as `show log`, but it reads the
// security event buffer (server_show_events.go), whose on-box command
// is `show security log [zone Z] [protocol P] [action A]`; judging the
// bare `show log` missed every selector (#16378 fold).
func EventsForms(cfg *config.Config, er *pb.GetEventsRequest, base string) ([]string, bool) {
	full := "show security log"
	if er.GetHasZone() && er.GetZone() == 0 {
		// Zone 0 is the selectable unknown zone (#3338); it has no
		// configured name, so it cannot be spelled on-box.
		return nil, false
	}
	if er.GetZone() != 0 {
		name, ok := ZoneNameForID(cfg, er.GetZone())
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
		return ChargeForms(base), true
	}
	return CanonicalForms(full, base)
}

// ClearSessionsForms rebuilds `clear security flow session …`
// from a ClearSessions request, whose selectors carry the zone NAME
// already (unlike GetSessions' numeric zone ID).
func ClearSessionsForms(cr *pb.ClearSessionsRequest, base string) ([]string, bool) {
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
		return ChargeForms(base), true
	}
	return CanonicalForms(full, base)
}

// ShowTextForms reconstructs the executed command from a ShowText
// topic and its Filter. Packed-parameter topics decode with the same
// grammar their handlers use; a malformed packing is unresolved.
func ShowTextForms(base string, st *pb.ShowTextRequest) ([]string, bool) {
	return showTextForms(base, st.GetTopic(), st.GetFilter())
}

// ShowTextFormsFor is ShowTextForms for a caller that does not hold a
// ShowTextRequest (the REST adapter decodes ?topic=&filter=).
//
// #17179: on the REST surface only the topics showTextHandler serves
// reach this decoder (see RestShowTextTopics17179); a packed topic the
// handler 400s is unnameable here rather than decoded into a verdict
// for a request that never runs.
func ShowTextFormsFor(base, topic, filter string) ([]string, bool) {
	return showTextForms(base, topic, filter)
}

func showTextForms(base, topic, filter string) ([]string, bool) {

	// Filter-carried selectors: the topic is exact and the Filter holds
	// the argument the operator typed (an interface name, a zone-pair
	// filter text, a session-log filter line). Where the on-box grammar
	// names the selector with a keyword the reconstruction uses it;
	// otherwise the filter follows the command as the on-box line does.
	switch topic {
	case "interfaces-detail", "interfaces-extensive", "interfaces-queue":
		if filter == "" {
			return ChargeForms(base), true
		}
		return CanonicalForms(base+" "+filter, base)
	case "route-instance":
		if filter == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+filter, base)
	case "zones-detail":
		// #16472: the filter is a bare zone NAME (cmd/cli SplitModifiers
		// selector), so the executed line is the canonicalisable
		// `show security zones <zone> detail`; judging it through
		// CanonicalForms yields the console's exact verdict, including
		// its #14687 rescue (allowed) — where the free-text spelling
		// `... detail <zone>` would have fabricated a denied base hit.
		if filter == "" {
			return ChargeForms(base), true
		}
		if strings.ContainsAny(filter, " \t") {
			return nil, false
		}
		return CanonicalForms("show security zones "+filter+" detail", base)
	case "policies-detail", "policies-hit-count",
		"chassis-cluster-data-plane-flows", "security-log":
		if filter == "" {
			return ChargeForms(base), true
		}
		// #16472: policies-detail / policies-hit-count filters are the
		// `from-zone X to-zone Y` selector text cmd/cli's
		// parsePolicyShowQuery admits (server_show_policies_text.go's
		// parseZoneFilter rejects anything else). Reconstruct the
		// console's selector-first spelling — `show security policies
		// from-zone X to-zone Y detail` — and judge it through
		// CanonicalForms, so the anchored base deny
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
			return PoliciesFilterForms(base, view, filter)
		}
		forms := []string{base + " " + filter}
		for _, f := range ChargeForms(base) {
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
		return ChargeForms(base), true
	}

	prefix, rest, _ := strings.Cut(topic, ":")
	_ = rest
	switch prefix {
	case "route-table":
		name := strings.TrimPrefix(topic, "route-table:")
		if name == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+name, base)
	case "route-protocol":
		name := strings.TrimSpace(strings.TrimPrefix(topic, "route-protocol:"))
		if name == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+name, base)
	case "route-prefix":
		packed := strings.TrimPrefix(topic, "route-prefix:")
		if packed == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+packed, base)
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
		return FormsWithCanonical(full, base, nil), true
	case "applications":
		name := strings.TrimPrefix(topic, "applications:")
		if name == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+name, base)
	case "class-of-service":
		name := strings.TrimPrefix(topic, "class-of-service:")
		if name == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+name, base)
	case "interfaces-queue":
		name := strings.TrimPrefix(topic, "interfaces-queue:")
		if name == "" {
			if filter != "" {
				return CanonicalForms(base+" "+filter, base)
			}
			return ChargeForms(base), true
		}
		return CanonicalForms(base+" "+name, base)
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
			return ChargeForms(base), true
		}
		return CanonicalForms(full, base)
	case "cos-scheduler-map":
		name := strings.TrimPrefix(topic, "cos-scheduler-map:")
		if name == "" {
			return ChargeForms(base), true
		}
		return CanonicalForms(base+" "+name, base)
	case "screen-ids-option", "screen-ids-option-detail":
		name := strings.TrimPrefix(topic, prefix+":")
		if name == "" {
			return nil, false
		}
		return CanonicalForms(base+" "+name, base)
	case "screen-statistics":
		zone := strings.TrimPrefix(topic, "screen-statistics:")
		if zone == "" {
			return nil, false
		}
		// Registry charge is `show security screen statistics zone`; the
		// on-box spelling carries the zone as that keyword's value.
		return CanonicalForms(base+" "+zone, base)
	case "firewall-filter":
		return FirewallFilterForms(topic, "firewall-filter:", base, false)
	case "firewall-effective-filter":
		return FirewallFilterForms(topic, "firewall-effective-filter:", base, true)
	case "firewall-effective":
		family := strings.TrimPrefix(topic, "firewall-effective:")
		if family == topic {
			return ChargeForms(base), true
		}
		switch family {
		case "inet", "inet6":
			return CanonicalForms(base+" family "+family, base)
		}
		return nil, false
	case "test-policy":
		return TestPolicyForms(topic, base)
	case "test-routing":
		return TestRoutingForms(topic, base)
	case "test-zone":
		return TestZoneForms(topic, base)
	case "sessions-top":
		// Registry keys are `sessions-top:bytes|packets`, charged as
		// `show security flow session sort-by bytes|packets` already.
		return ChargeForms(base), true
	}
	// A packed topic with no decoder here: its parameter cannot be
	// reconstructed, so the request is unnameable in full. The bare
	// charge alone would silently re-open the argument-text gap for
	// that topic, so a restricted class denies.
	return nil, false
}

// PoliciesFilterForms rebuilds the console spelling of a filtered
// policies detail/hit-count command from its ShowText Filter
// (`from-zone X to-zone Y`, either pair optional, in the order cmd/cli
// joined it). Any other token is a filter the handler rejects
// (parseZoneFilter), so it is unnameable here.
func PoliciesFilterForms(base, view, filter string) ([]string, bool) {
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
	return CanonicalForms(full, base)
}

// FirewallFilterForms decodes `firewall-filter:<name>[:<family>]` (and the
// effective twin) the way showFirewallFilter does: the LAST colon splits
// the family, and only inet/inet6 are families the handler honours.
func FirewallFilterForms(topic, prefix, base string, effective bool) ([]string, bool) {
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
	return CanonicalForms(full, base)
}

// PackedSelectors parses a `k=v,k=v` packed parameter string with the
// handlers' grammar: malformed segments, empty keys/values, unknown keys
// and duplicate keys are all errors (#3696/#3709 shape).
func PackedSelectors(params string, known map[string]bool) (map[string]string, bool) {
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

func TestPolicyForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-policy:")
	sel, ok := PackedSelectors(params, map[string]bool{
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
	return CanonicalForms(full, base)
}

func TestRoutingForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-routing:")
	sel, ok := PackedSelectors(params, map[string]bool{"dest": true, "instance": true})
	if !ok || sel["dest"] == "" {
		return nil, false
	}
	full := base + " destination " + sel["dest"]
	if v := sel["instance"]; v != "" {
		full += " instance " + v
	}
	return CanonicalForms(full, base)
}

func TestZoneForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-zone:")
	sel, ok := PackedSelectors(params, map[string]bool{"interface": true})
	if !ok || sel["interface"] == "" {
		return nil, false
	}
	return CanonicalForms(base+" interface "+sel["interface"], base)
}

// SessionForms rebuilds `show security flow session …` from a
// GetSessionsRequest. The zone travels as a numeric ID on the wire; it is
// resolved to its configured name through the same StableZoneID space the
// session handlers use, and an unresolvable ID is unnameable.
func SessionForms(cfg *config.Config, gr *pb.GetSessionsRequest, base string) ([]string, bool) {
	full := base
	if gr.GetZone() != 0 {
		name, ok := ZoneNameForID(cfg, gr.GetZone())
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
		return ChargeForms(base), true
	}
	return CanonicalForms(full, base)
}

// MatchForms rebuilds `show security match-policies …` from a
// MatchPoliciesRequest.
//
// #17179: the gRPC copy used to return the bare charge when from/to zone
// and src/dst IP were all empty, dropping protocol, ports, icmp,
// fragment and ingress-interface — so `MatchPolicies{Protocol:"tcp"}`
// was judged as the unfiltered command and an argument-scoped deny on
// the protocol never fired, while REST (and the on-box line
// `show security match-policies protocol tcp …`, which the console
// denies under `protocol tcp`) kept the selectors. That early return is
// deleted: every present selector is spelled, zones or not, exactly as
// the REST adapter always did. A request with no selectors at all still
// falls through to the bare charge below.
func MatchForms(mp *pb.MatchPoliciesRequest, base string) ([]string, bool) {
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
		return ChargeForms(base), true
	}
	return CanonicalForms(full, base)
}

// ZoneNameForID resolves a wire zone ID to its configured name through
// StableZoneIDOwnerForConfig, the same owner resolution the session
// surfaces render from. ID 0 is the no-filter sentinel, which has no
// on-box name.
func ZoneNameForID(cfg *config.Config, id uint32) (string, bool) {
	if cfg == nil || id == 0 {
		return "", false
	}
	name := config.StableZoneIDOwnerForConfig(cfg, id)
	return name, name != ""
}
