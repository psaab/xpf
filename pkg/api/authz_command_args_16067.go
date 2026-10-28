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
	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/logging"
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
	// #17184 fold (Rev18237 B1): request-decoded routes (see
	// restRoutesNoCommand / restRequestCommand9952 and
	// isRequestDecodedRoute9952) arrive here with cmd ALREADY resolved
	// per-request from the request's selector (topic / verb / type).
	// That resolution IS the argument reconstruction for those routes:
	// there is no further argument text the gate must spell beyond what
	// the resolver folded into cmd, except where noted below. Such
	// routes therefore take the bare (fully-resolved) charge. Without
	// this they fell into the (nil,false) default below and were denied
	// for restricted classes even under their own allow — the #15076
	// regression (GET routing/bgp, system/info, POST system/action,
	// security/nat/rules controls refused under their own allow).
	if isRequestDecodedRoute9952(route) {
		switch route {
		case "GET /api/v1/show-text":
			// Show-text packs argument text past the topic
			// resolution (packed parameters, ?filter=); the
			// switch arm below reconstructs it.
			break
		case "GET /api/v1/security/nat/rules":
			// ?rule_set= is argument text the command resolver
			// does NOT fold in (`... rule-set <name>`, a sibling
			// of the charge's `rule` leaf), exactly as
			// GetNATRuleStats spells it.
			if rs := r.URL.Query().Get("rule_set"); rs != "" {
				family := strings.TrimSuffix(cmd, " rule")
				if family == cmd {
					return nil, false
				}
				return restCanonicalForms(family+" rule-set "+rs, cmd)
			}
			return restChargeForms16472(cmd), true
		default:
			// routing/bgp, system/info, system/action: the
			// resolved cmd IS the whole executed line.
			return restChargeForms16472(cmd), true
		}
	}
	switch route {
	case "GET /api/v1/show-text":
		topic := r.URL.Query().Get("topic")
		return restShowTextForms(cmd, topic, r.URL.Query().Get("filter"))
	case "POST /api/v1/diagnostics/ping":
		var req PingRequest
		if !decodeBufferedJSON(r, &req) || req.Target == "" {
			return nil, false
		}
		// #17184 fold (M2): the handler rejects a target/source/
		// routing-instance over diagcmd.MaxArgLen (diagcmd.CheckArgs
		// in pingHandler, #6904) and never executes it, so that
		// shape is unnameable here rather than spelled.
		if err := diagcmd.CheckArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
			return nil, false
		}
		// #17184 fold (M1): count/size are operator-typed ping
		// arguments the on-box command spells (`ping <host>
		// count <N> size <N>`, cmdtree tree.go ping node) and the
		// handler executes (ClampPingCount / MaxPingSize clamp in
		// buildPingArgv). Spell the EXECUTED (clamped) values, in
		// the CLI's option order, so a deny on `count`/`size` text
		// fires here as on the box; before this they were silently
		// left unspelled while the census claimed the route decided.
		full := "ping " + req.Target
		if req.Count != 0 {
			full += " count " + strconv.Itoa(diagcmd.ClampPingCount(req.Count))
		}
		if req.Source != "" {
			full += " source " + req.Source
		}
		if req.Size > 0 {
			sz := req.Size
			if sz > diagcmd.MaxPingSize {
				sz = diagcmd.MaxPingSize
			}
			full += " size " + strconv.Itoa(sz)
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
		// #17184 fold (M2): same handler-rejected bound as ping.
		if err := diagcmd.CheckArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
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
	case "GET /api/v1/security/events":
		// REST twin of eventsArgumentForms: the handler's zone /
		// protocol / action filters execute the
		// `show security log [zone Z] [protocol P] [action A]`
		// command (eventsArgumentForms). Zone travels as a numeric
		// ID (or unknown/none for 0, which has no on-box name);
		// malformed limit/zone/protocol the handler 400s is
		// unnameable here.
		// #17184 fold (M3): `limit` is validated to the handler's
		// exact contract — queryIntStrict AND the >10000 cap the
		// handler 400s on (security.go eventsHandler, #4926) — but
		// deliberately NOT spelled into the command: no on-box
		// events line the gate reconstructs carries a count under
		// the `show log` charge, and GetEvents' limit is likewise
		// unspelled. Validation here only keeps a handler-rejected
		// limit from being judged as an executed read.
		q := r.URL.Query()
		if _, present := q["limit"]; present {
			lim, ok := queryIntStrict(r, "limit", 50)
			if !ok || lim > 10000 {
				return nil, false
			}
		}
		full := "show security log"
		if v := q.Get("zone"); v != "" {
			id, ok := parseEventZoneFilter(v)
			if !ok || id == 0 {
				return nil, false
			}
			name, ok := restZoneNameForID(cfg, uint32(id))
			if !ok {
				return nil, false
			}
			full += " zone " + name
		}
		if v := q.Get("protocol"); v != "" {
			if _, ok := logging.ResolveEventProtocol(v); !ok {
				return nil, false
			}
			full += " protocol " + v
		}
		if v := q.Get("action"); v != "" {
			full += " action " + v
		}
		if full == "show security log" {
			return restChargeForms16472(cmd), true
		}
		return restCanonicalForms(full, cmd)
	case "GET /api/v1/security/nat/deterministic":
		// #17184: forward/reverse lookup arguments (?internal-host=
		// / ?nat-ip=&nat-port=, optional ?pool=), mirroring the gRPC
		// GetNATDeterministic reconstruction.
		q := r.URL.Query()
		switch {
		case q.Get("internal-host") != "":
			full := cmd + " internal-host " + q.Get("internal-host")
			if pool := q.Get("pool"); pool != "" {
				full += " pool " + pool
			}
			return restCanonicalForms(full, cmd)
		case q.Get("nat-ip") != "":
			port, err := strconv.Atoi(q.Get("nat-port"))
			if err != nil || port < 1 || port > 65535 {
				return nil, false
			}
			full := cmd + " nat-ip " + q.Get("nat-ip") + " nat-port " + strconv.Itoa(port)
			if pool := q.Get("pool"); pool != "" {
				full += " pool " + pool
			}
			return restCanonicalForms(full, cmd)
		default:
			// The handler answers a directionless lookup as a typed
			// malformed result; there is no executed lookup line to
			// judge, so a restricted class denies.
			return nil, false
		}
	case "POST /api/v1/dhcp/identifiers/clear":
		// #17184: the body's interface is argument text
		// (`clear dhcp client-identifier interface <name>`); an empty
		// body/interface is the clear-all bare charge. The body was
		// buffered by the mutation pipeline (decodeBufferedJSON puts
		// it back for the handler).
		if r.ContentLength == 0 {
			return restChargeForms16472(cmd), true
		}
		var req ClearDHCPIdentifierRequest
		if !decodeBufferedJSON(r, &req) {
			return nil, false
		}
		if req.Interface == "" {
			return restChargeForms16472(cmd), true
		}
		return restCanonicalForms(cmd+" interface "+req.Interface, cmd)
	}
	// #17184: NO bare-charge default (twin of the gRPC rule). A route
	// whose query/body carries operator argument text needs an arm
	// above; a route whose inputs do not must be named in
	// restRoutesWithoutArgumentForms with a reason. Anything else is
	// unnameable, so a restricted class denies.
	if _, named := restRoutesWithoutArgumentForms[route]; named {
		return restChargeForms16472(cmd), true
	}
	return nil, false
}

// restRoutesWithoutArgumentForms records, WITH A REASON, every
// restRouteCommand route whose query/body carries no operator
// argument text the on-box command spells (#17184, twin of
// methodsWithoutArgumentForms in pkg/grpcapi).
// TestEveryRESTRouteInputIsReconstructedOrNamedAbsent17184 keeps both
// directions honest against restRouteCommand and the switch above.
//
// Request-decoded routes (restRoutesNoCommand entries classified by
// isRequestDecodedRoute9952) are NOT restRouteCommand routes and are
// NOT named here: restArgumentForms returns their bare, fully-resolved
// charge before the switch (Rev18237 B1), and the census covers them
// in its request-decoded arm against restRoutesNoCommand.
var restRoutesWithoutArgumentForms = map[string]string{
	"GET /api/v1/statistics/global":        "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/zones":           "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/policies":        "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/nat/source":      "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/nat/pools":       "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/nat/destination": "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/screen":          "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/ipsec/sa":        "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/security/vrrp":            "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/interfaces":               "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/dhcp/leases":              "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/dhcp/identifiers":         "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/routes":                   "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/config":                   "config-read path adjudicated by authorizeRESTConfigRead (#14707)",
	"GET /api/v1/config/show":              "config-read path adjudicated by authorizeRESTConfigRead (#14707)",
	"GET /api/v1/config/compare":           "config-read path adjudicated by authorizeRESTConfigRead (#14707)",
	"GET /api/v1/config/show-rollback":     "config-read path adjudicated by authorizeRESTConfigRead (#14707)",
	"GET /api/v1/config/export":            "config-read path adjudicated by authorizeRESTConfigRead (#14707)",
	"GET /api/v1/config/search":            "config-read path adjudicated by authorizeRESTConfigRead (#14707)",
	"GET /api/v1/config/history":           "no query/body selectors; the bare charge is argument-complete",
	"GET /api/v1/events/stream":            "stream filters are not command argument text; the bare charge is argument-complete",
	"GET /api/v1/logs/stream":              "stream filters are not command argument text; the bare charge is argument-complete",
	"POST /api/v1/security/sessions/clear": "clear-all body carries no selectors the handler executes (see authz_command_args_16067.go twin note)",
	"POST /api/v1/security/counters/clear": "no body selectors; the bare charge is argument-complete",
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
	if cfg == nil || id == 0 {
		return "", false
	}
	name := config.StableZoneIDOwnerForConfig(cfg, id)
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
	"ping 192.0.2.1 count 5 size 1400",
	"traceroute 192.0.2.1",
	"show route table inet.0",
	"show route protocol bgp",
	"show log messages",
	"show security screen statistics zone trust",
	"show interfaces detail ge-0/0/0",
	"show security flow session zone trust",
	"show security match-policies from-zone trust to-zone untrust",
	"test policy from-zone trust to-zone untrust",
	"show security nat source deterministic-nat internal-host 192.0.2.1",
	"show security nat source deterministic-nat nat-ip 192.0.2.1 nat-port 1024",
	"clear dhcp client-identifier interface ge-0/0/0",
	"show security nat source rule-set rs1",
}

func init() {
	config.RegisterCommandSurfaceArgumentSamples(restSurfaceName9952, func() []string {
		return append([]string(nil), argumentSampleCommandsREST16067...)
	})
}
