package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// #16067: argument-scoped allow/deny-commands regexes never fired on REST
// either. The route tables charge argument-free commands (`ping`,
// `show route table`), so a pattern written against argument text matched
// on the box and never here. This file builds the full canonicalised
// command from the request — the show-text topic's packed parameters,
// the ping/traceroute body's target and selectors, the session/match
// query selectors — mirroring the gRPC reconstruction in
// pkg/grpcapi/authz_command_args_16067.go, so both remote surfaces judge
// the string the on-box gate judges.
//
// A request whose arguments cannot be reconstructed (malformed packed
// topic, uncanonicalisable spelling, unresolvable zone) yields no forms
// and the caller denies for a restricted class, exactly as an unmapped
// route denies.

// restArgumentForms returns the argument-bearing forms of the command a
// REST request performs alongside its argument-free charge.
func restArgumentForms(cfg *config.Config, route string, r *http.Request, cmd string) ([]string, bool) {
	switch route {
	case "GET /api/v1/show-text":
		topic := r.URL.Query().Get("topic")
		return restShowTextForms(cmd, topic, r.URL.Query().Get("filter"))
	case "POST /api/v1/diagnostics/ping":
		var req PingRequest
		if !decodeBufferedJSON(r, &req) || req.Target == "" {
			return nil, false
		}
		full := "ping " + req.Target
		if req.Source != "" {
			full += " source " + req.Source
		}
		if req.RoutingInstance != "" {
			full += " routing-instance " + req.RoutingInstance
		}
		return restCanonicalForms(full, cmd)
	case "POST /api/v1/diagnostics/traceroute":
		var req TracerouteRequest
		if !decodeBufferedJSON(r, &req) || req.Target == "" {
			return nil, false
		}
		full := "traceroute " + req.Target
		if req.Source != "" {
			full += " source " + req.Source
		}
		if req.RoutingInstance != "" {
			full += " routing-instance " + req.RoutingInstance
		}
		return restCanonicalForms(full, cmd)
	case "GET /api/v1/security/sessions":
		return restSessionForms(cfg, r, cmd)
	case "GET /api/v1/security/sessions/summary", "GET /api/v1/security/sessions/summary/zone-pairs":
		// The summary handlers execute NO session selectors: they walk
		// the whole table (and optionally fan out to the peer). Judging
		// the list selectors here would authorize a command the handler
		// never performs — e.g. a zone-scoped deny would refuse an
		// unfiltered summary, and a zone-scoped allow exception would
		// admit one. The bare summary charge is the only form.
		return restChargeForms16472(cmd), true
	case "GET /api/v1/security/match":
		return restMatchForms(r, cmd)
	case "GET /api/v1/interfaces/detail":
		if name := r.URL.Query().Get("filter"); name != "" {
			// interfacesDetailHandler applies the filter as a prefix
			// even in terse mode (writeInterfacesTerse filters on it),
			// and parses terse with =="true" only — so every other
			// spelling still executes the FILTERED detail command and
			// must be judged as it. Returning the bare charge for a
			// filtered request was "unnameable" in reverse: it let a
			// deny on `show interfaces detail <name>` be stepped
			// around with ?filter=<name>&terse=1 (#16378 fold).
			return restCanonicalForms(cmd+" "+name, cmd)
		}
		return restChargeForms16472(cmd), true
	}
	return restChargeForms16472(cmd), true
}

// decodeBufferedJSON decodes the already-buffered mutation body and
// puts it back, exactly as restActionVerb9952 does, so the handler
// decodes the same bytes it was judged on.
func decodeBufferedJSON(r *http.Request, v any) bool {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return false
	}
	raw, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) == 0 {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

func restCanonicalForms(full, base string) ([]string, bool) {
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(full))
	if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != full {
		return nil, false
	}
	return restArgumentFormsWithCanonical16472(full, base, canon), true
}

// restArgumentFormsWithCanonical16472 is the REST twin of the gRPC
// argumentFormsWithCanonical16472 (#16472): full line, charge, and the
// canonical base/full/selector spellings of both, so an anchored base
// deny fires on REST exactly as on the console and gRPC surfaces.
func restArgumentFormsWithCanonical16472(full, base string, canon []string) []string {
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
		for _, x := range sels {
			add(x)
		}
	}
	return forms
}

// restChargeForms16472 expands a bare REST charge to its canonical spellings.
func restChargeForms16472(base string) []string {
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

// restShowTextForms mirrors the gRPC ShowText reconstruction for the
// REST ?topic= surface, which serves the same topic registry.
func restShowTextForms(base, topic, filter string) ([]string, bool) {
	switch topic {
	case "interfaces-detail", "interfaces-extensive", "interfaces-queue":
		if filter == "" {
			return restChargeForms16472(base), true
		}
		return restCanonicalForms(base+" "+filter, base)
	case "route-instance":
		if filter == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+filter, base)
	case "zones-detail":
		// #16472: bare zone-name filter, as in the gRPC twin.
		if filter == "" {
			return restChargeForms16472(base), true
		}
		if strings.ContainsAny(filter, " \t") {
			return nil, false
		}
		return restCanonicalForms("show security zones "+filter+" detail", base)
	case "policies-detail", "policies-hit-count",
		"chassis-cluster-data-plane-flows", "security-log":
		if filter == "" {
			return restChargeForms16472(base), true
		}
		if topic == "policies-detail" || topic == "policies-hit-count" {
			view := "detail"
			if topic == "policies-hit-count" {
				view = "hit-count"
			}
			return restPoliciesFilterForms16472(base, view, filter)
		}
		forms := []string{base + " " + filter}
		for _, f := range restChargeForms16472(base) {
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
	if !strings.Contains(topic, ":") {
		return restChargeForms16472(base), true
	}
	prefix, _, _ := strings.Cut(topic, ":")
	switch prefix {
	case "route-table":
		name := strings.TrimPrefix(topic, "route-table:")
		if name == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+name, base)
	case "route-protocol":
		name := strings.TrimSpace(strings.TrimPrefix(topic, "route-protocol:"))
		if name == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+name, base)
	case "route-prefix":
		packed := strings.TrimPrefix(topic, "route-prefix:")
		if packed == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+packed, base)
	case "log":
		parts := strings.SplitN(topic, ":", 3)
		if len(parts) < 2 || parts[1] == "" {
			return nil, false
		}
		full := base + " " + parts[1]
		if len(parts) == 3 && parts[2] != "" {
			if _, err := strconv.Atoi(parts[2]); err == nil {
				full += " " + parts[2]
			}
		}
		return restArgumentFormsWithCanonical16472(full, base, nil), true
	case "applications":
		name := strings.TrimPrefix(topic, "applications:")
		if name == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+name, base)
	case "class-of-service":
		name := strings.TrimPrefix(topic, "class-of-service:")
		if name == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+name, base)
	case "interfaces-queue":
		name := strings.TrimPrefix(topic, "interfaces-queue:")
		if name == "" {
			if filter != "" {
				return restCanonicalForms(base+" "+filter, base)
			}
			return restChargeForms16472(base), true
		}
		return restCanonicalForms(base+" "+name, base)
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
			return restChargeForms16472(base), true
		}
		return restCanonicalForms(full, base)
	case "cos-scheduler-map":
		name := strings.TrimPrefix(topic, "cos-scheduler-map:")
		if name == "" {
			return restChargeForms16472(base), true
		}
		return restCanonicalForms(base+" "+name, base)
	case "screen-ids-option", "screen-ids-option-detail":
		name := strings.TrimPrefix(topic, prefix+":")
		if name == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+name, base)
	case "screen-statistics":
		zone := strings.TrimPrefix(topic, "screen-statistics:")
		if zone == "" {
			return nil, false
		}
		return restCanonicalForms(base+" "+zone, base)
	case "firewall-filter":
		return restFirewallForms(topic, "firewall-filter:", base, false)
	case "firewall-effective-filter":
		return restFirewallForms(topic, "firewall-effective-filter:", base, true)
	case "firewall-effective":
		family := strings.TrimPrefix(topic, "firewall-effective:")
		if family == topic {
			return restChargeForms16472(base), true
		}
		if family == "inet" || family == "inet6" {
			return restCanonicalForms(base+" family "+family, base)
		}
		return nil, false
	case "test-policy":
		return restTestPolicyForms(topic, base)
	case "test-routing":
		params := strings.TrimPrefix(topic, "test-routing:")
		sel, ok := restPackedSelectors(params, map[string]bool{"dest": true, "instance": true})
		if !ok || sel["dest"] == "" {
			return nil, false
		}
		full := base + " destination " + sel["dest"]
		if v := sel["instance"]; v != "" {
			full += " instance " + v
		}
		return restCanonicalForms(full, base)
	case "test-zone":
		params := strings.TrimPrefix(topic, "test-zone:")
		sel, ok := restPackedSelectors(params, map[string]bool{"interface": true})
		if !ok || sel["interface"] == "" {
			return nil, false
		}
		return restCanonicalForms(base+" interface "+sel["interface"], base)
	case "sessions-top":
		return restChargeForms16472(base), true
	}
	return nil, false
}

// restPoliciesFilterForms16472 is the REST twin of
// policiesFilterForms16472 in pkg/grpcapi (#16472).
func restPoliciesFilterForms16472(base, view, filter string) ([]string, bool) {
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
	return restCanonicalForms(full, base)
}

func restFirewallForms(topic, prefix, base string, effective bool) ([]string, bool) {
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
	return restCanonicalForms(full, base)
}

func restPackedSelectors(params string, known map[string]bool) (map[string]string, bool) {
	out := make(map[string]string)
	if params == "" {
		return out, true
	}
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !known[parts[0]] {
			return nil, false
		}
		if _, dup := out[parts[0]]; dup {
			return nil, false
		}
		out[parts[0]] = parts[1]
	}
	return out, true
}

func restTestPolicyForms(topic, base string) ([]string, bool) {
	params := strings.TrimPrefix(topic, "test-policy:")
	sel, ok := restPackedSelectors(params, map[string]bool{
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
	return restCanonicalForms(full, base)
}

// restSessionForms rebuilds the session command from the query selectors
// the sessions handlers read (zone name, prefixes, ports, protocol).
func restSessionForms(cfg *config.Config, r *http.Request, base string) ([]string, bool) {
	q := r.URL.Query()
	full := base
	if v := q.Get("zone"); v != "" {
		// REST carries the zone as a numeric ID (peerSessionsRequest
		// ParseUints it into GetSessionsRequest.Zone); resolve it to
		// its configured name, and deny when it names no zone.
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, false
		}
		name, ok := restZoneNameForID(cfg, uint32(id))
		if !ok {
			return nil, false
		}
		full += " zone " + name
	}
	if v := q.Get("protocol"); v != "" {
		full += " protocol " + v
	}
	if v := q.Get("source_prefix"); v != "" {
		full += " source-prefix " + v
	}
	if v := q.Get("destination_prefix"); v != "" {
		full += " destination-prefix " + v
	}
	if v := q.Get("source_port"); v != "" {
		full += " source-port " + v
	}
	if v := q.Get("destination_port"); v != "" {
		full += " destination-port " + v
	}
	if v := q.Get("nat_only"); v != "" {
		// The handler parses with strconv.ParseBool (buildSessionQuery)
		// and 400s on a malformed value, so every ParseBool spelling
		// counts — checking only =="true" let nat_only=1 / =t / =TRUE
		// execute the NAT-only list while the gate judged the
		// unfiltered command (#16378 fold).
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, false
		}
		if b {
			full += " nat-only"
		}
	}
	if v := q.Get("application"); v != "" {
		full += " application " + v
	}
	if v := q.Get("interface"); v != "" {
		full += " interface " + v
	}
	if v := q.Get("source_nat_pool"); v != "" {
		full += " source-nat-pool " + v
	}
	if full == base {
		return restChargeForms16472(base), true
	}
	return restCanonicalForms(full, base)
}

func restMatchForms(r *http.Request, base string) ([]string, bool) {
	q := r.URL.Query()
	full := base
	if v := q.Get("from_zone"); v != "" {
		full += " from-zone " + v
	}
	if v := q.Get("to_zone"); v != "" {
		full += " to-zone " + v
	}
	if v := q.Get("src_ip"); v != "" {
		full += " source-ip " + v
	}
	if v := q.Get("dst_ip"); v != "" {
		full += " destination-ip " + v
	}
	if v := q.Get("src_port"); v != "" {
		full += " source-port " + v
	}
	if v := q.Get("dst_port"); v != "" {
		full += " destination-port " + v
	}
	if v := q.Get("protocol"); v != "" {
		full += " protocol " + v
	}
	if v := q.Get("icmp_type"); v != "" {
		full += " icmp-type " + v
	}
	if v := q.Get("icmp_code"); v != "" {
		full += " icmp-code " + v
	}
	if v := q.Get("non_first_fragment"); v != "" {
		// matchPoliciesHandler parses with strconv.ParseBool and 400s
		// on a malformed value; every ParseBool spelling must carry
		// the fragment selector into the judged command (#16378 fold).
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, false
		}
		if b {
			full += " non-first-fragment"
		}
	}
	if v := q.Get("ingress_interface"); v != "" {
		full += " ingress-interface " + v
	}
	if full == base {
		return restChargeForms16472(base), true
	}
	return restCanonicalForms(full, base)
}

// restZoneNameForID resolves a REST wire zone ID to its configured name
// through StableZoneIDOwnerForConfig, the same owner resolution the
// session surfaces render from.
func restZoneNameForID(cfg *config.Config, id uint32) (string, bool) {
	if cfg == nil || id == 0 || id > 65535 {
		return "", false
	}
	name := config.StableZoneIDOwnerForConfig(cfg, uint16(id))
	return name, name != ""
}

// argumentSampleCommands16067 are the REST surface's exemplar
// argument-bearing commands for the commit-time advisory; see the gRPC
// twin in pkg/grpcapi.
var argumentSampleCommandsREST16067 = []string{
	"show firewall filter f1",
	"show security screen ids-option prof1",
	"show security zones trust detail",
	"ping 192.0.2.1",
	"traceroute 192.0.2.1",
	"show route table inet.0",
	"show route protocol bgp",
	"show log messages",
	"show security screen statistics zone trust",
	"show interfaces detail ge-0/0/0",
	"show security flow session zone trust",
	"show security match-policies from-zone trust to-zone untrust",
	"test policy from-zone trust to-zone untrust",
}

func init() {
	config.RegisterCommandSurfaceArgumentSamples(restSurfaceName9952, func() []string {
		return append([]string(nil), argumentSampleCommandsREST16067...)
	})
}
