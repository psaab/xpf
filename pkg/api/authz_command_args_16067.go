package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/argforms"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

// #16067: argument-scoped allow/deny-commands regexes never fired on REST
// either. The route tables charge argument-free commands (`ping`,
// `show route table`), so a pattern written against argument text matched
// on the box and never here. This file decodes the REST wire (query
// string / JSON body) into the same wire requests the gRPC surface
// judges and hands them to the ONE reconstruction in
// pkg/argforms/argforms.go (#17179), so both remote surfaces judge the
// string the on-box gate judges. The former hand-cloned rest*Forms copy
// of the gRPC reconstruction is deleted: it had already diverged in
// opposite directions (REST kept MatchPolicies selectors the gRPC copy
// dropped when zones/IPs were empty; the gRPC GetEvents arm had no REST
// twin, so /security/events judged the bare `show log` charge).
//
// A request whose arguments cannot be reconstructed (malformed packed
// topic, uncanonicalisable spelling, unresolvable zone, malformed
// boolean/port/zone selector the handler would 400) yields no forms
// and the caller denies for a restricted class, exactly as an unmapped
// route denies.

// restShowTextTopics17179 is the exact set of topics the REST
// show-text route serves. #17179: the gate decodes ONLY these topics;
// every other registry topic — including every packed `prefix:` topic
// — is unnameable here and denies for a restricted class rather than
// manufacturing a verdict for a request that never runs. The set is
// showTextHandler's switch arms (pkg/api/show_text.go) PLUS "version":
// showTextHandler 400s it today, but the route's charge for it is
// resolved from the shared registry (restRequestCommand9952) and
// pinned as served by #15077/#14712 — that pre-existing charge
// contract is out of scope here and must not be silently broken by
// this restriction, so the bare topic stays judged by its charge
// exactly as before. TestRestShowTextTopicsCensus17179 re-derives the
// handler arms from show_text.go and pins this set (arms + version) in
// both directions, so a new handler arm without a gate entry (or vice
// versa) cannot silently reopen the false-coverage gap.
var restShowTextTopics17179 = map[string]bool{
	"version":                             true,
	"schedulers":                          true,
	"snmp":                                true,
	"dhcp-relay":                          true,
	"firewall":                            true,
	"alg":                                 true,
	"user-identification-status":          true,
	"security-user-identification-status": true,
	"dynamic-address":                     true,
	"address-book":                        true,
	"applications":                        true,
	"flow-monitoring":                     true,
	"flow-timeouts":                       true,
	"nat-static":                          true,
	"nat-nptv6":                           true,
}

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
				return argforms.CanonicalForms(family+" rule-set "+rs, cmd)
			}
			return argforms.ChargeForms(cmd), true
		default:
			// routing/bgp, system/info, system/action: the
			// resolved cmd IS the whole executed line.
			return argforms.ChargeForms(cmd), true
		}
	}
	switch route {
	case "GET /api/v1/show-text":
		topic := r.URL.Query().Get("topic")
		if !restShowTextTopics17179[topic] {
			// #17179: showTextHandler 400s this topic; there is no
			// executed command to name, so a restricted class denies
			// rather than judging a packed/detail spelling the
			// handler will not run.
			return nil, false
		}
		return argforms.ShowTextFormsFor(cmd, topic, r.URL.Query().Get("filter"))
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
		return argforms.CanonicalForms(full, cmd)
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
		return argforms.CanonicalForms(full, cmd)
	case "GET /api/v1/security/sessions":
		return sessionFormsFromQuery(cfg, r, cmd)
	case "GET /api/v1/security/sessions/summary", "GET /api/v1/security/sessions/summary/zone-pairs":
		// The summary handlers execute NO session selectors: they walk
		// the whole table (and optionally fan out to the peer). Judging
		// the list selectors here would authorize a command the handler
		// never performs — e.g. a zone-scoped deny would refuse an
		// unfiltered summary, and a zone-scoped allow exception would
		// admit one. The bare summary charge is the only form.
		return argforms.ChargeForms(cmd), true
	case "GET /api/v1/security/events":
		return eventsFormsFromQuery(cfg, r, cmd)
	case "GET /api/v1/security/match":
		return matchFormsFromQuery(r, cmd)
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
			return argforms.CanonicalForms(cmd+" "+name, cmd)
		}
		return argforms.ChargeForms(cmd), true
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
			return argforms.CanonicalForms(full, cmd)
		case q.Get("nat-ip") != "":
			port, err := strconv.Atoi(q.Get("nat-port"))
			if err != nil || port < 1 || port > 65535 {
				return nil, false
			}
			full := cmd + " nat-ip " + q.Get("nat-ip") + " nat-port " + strconv.Itoa(port)
			if pool := q.Get("pool"); pool != "" {
				full += " pool " + pool
			}
			return argforms.CanonicalForms(full, cmd)
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
			return argforms.ChargeForms(cmd), true
		}
		var req ClearDHCPIdentifierRequest
		if !decodeBufferedJSON(r, &req) {
			return nil, false
		}
		if req.Interface == "" {
			return argforms.ChargeForms(cmd), true
		}
		return argforms.CanonicalForms(cmd+" interface "+req.Interface, cmd)
	}
	// #17184: NO bare-charge default (twin of the gRPC rule). A route
	// whose query/body carries operator argument text needs an arm
	// above; a route whose inputs do not must be named in
	// restRoutesWithoutArgumentForms with a reason. Anything else is
	// unnameable, so a restricted class denies.
	if _, named := restRoutesWithoutArgumentForms[route]; named {
		return argforms.ChargeForms(cmd), true
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

// sessionFormsFromQuery decodes the sessions query selectors the handlers
// read (buildSessionQuery / peerSessionsRequest) into a
// GetSessionsRequest and defers to argforms.SessionForms — the same
// decoding REST already used for the peer leg (peerSessionsRequest,
// sessions.go). String selectors are validated here with the handler's
// fail-closed grammar (ParseBool booleans; the zone is the numeric
// StableZoneID the shared decoder resolves to a name, denying when it
// names no zone).
func sessionFormsFromQuery(cfg *config.Config, r *http.Request, base string) ([]string, bool) {
	req, ok := decodeRESTSessionsQuery(r)
	if !ok {
		return nil, false
	}
	return argforms.SessionForms(cfg, req, base)
}

func decodeRESTSessionsQuery(r *http.Request) (*pb.GetSessionsRequest, bool) {
	q := r.URL.Query()
	req := &pb.GetSessionsRequest{
		Protocol:          q.Get("protocol"),
		SourcePrefix:      q.Get("source_prefix"),
		DestinationPrefix: q.Get("destination_prefix"),
		Application:       q.Get("application"),
		InterfaceFilter:   q.Get("interface"),
		SourceNatPool:     q.Get("source_nat_pool"),
	}
	if v := q.Get("zone"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, false
		}
		req.Zone = uint32(id)
	}
	if v := q.Get("source_port"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, false
		}
		req.SourcePort = uint32(n)
	}
	if v := q.Get("destination_port"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, false
		}
		req.DestinationPort = uint32(n)
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
		req.NatOnly = b
	}
	return req, true
}

// eventsFormsFromQuery decodes the /security/events query selectors the
// handler reads (zone via parseEventZoneFilter, protocol via
// logging.ResolveEventProtocol, action verbatim — security.go
// eventsHandler) into a GetEventsRequest and defers to
// argforms.EventsForms. #17179: this route previously had NO arm, so it
// judged the bare `show log` charge and every selector-scoped deny was
// silently allowed (REST under-denied vs GetEvents). A malformed zone
// or protocol the handler would 400 is unnameable here. Zone 0 with
// the parameter present is the selectable unknown zone (#3338): it has
// no configured name, so the shared decoder denies for a restricted
// class, exactly as GetEvents{HasZone, Zone:0} does.
func eventsFormsFromQuery(cfg *config.Config, r *http.Request, base string) ([]string, bool) {
	// #17184 fold (M3): `limit` is validated to the handler's exact
	// contract — queryIntStrict AND the >10000 cap the handler 400s
	// on (security.go eventsHandler, #4926) — but deliberately NOT
	// spelled into the command: no on-box events line the gate
	// reconstructs carries a count under the `show log` charge, and
	// GetEvents' limit is likewise unspelled. Validation here only
	// keeps a handler-rejected limit from being judged as executed.
	if _, present := r.URL.Query()["limit"]; present {
		lim, ok := queryIntStrict(r, "limit", 50)
		if !ok || lim > 10000 {
			return nil, false
		}
	}
	q := r.URL.Query()
	req := &pb.GetEventsRequest{Action: q.Get("action")}
	if proto := q.Get("protocol"); proto != "" {
		if _, ok := logging.ResolveEventProtocol(proto); !ok {
			return nil, false
		}
		req.Protocol = proto
	}
	if _, present := q["zone"]; present {
		z, ok := parseEventZoneFilter(q.Get("zone"))
		if !ok {
			return nil, false
		}
		req.Zone = uint32(z)
		req.HasZone = true
	}
	return argforms.EventsForms(cfg, req, base)
}

// matchFormsFromQuery decodes the match-policies query selectors the handler
// reads (matchPoliciesSelectorKeys, security.go) into a
// MatchPoliciesRequest and defers to argforms.MatchForms. Ports and
// icmp values are present-pointer fields on the wire (#17081): a
// present key — including "0" — is a literal value, an absent key is
// omitted; a present-but-malformed value the handler would 400 is
// unnameable. The fragment boolean keeps the handler's ParseBool
// grammar (#16378 fold).
func matchFormsFromQuery(r *http.Request, base string) ([]string, bool) {
	q := r.URL.Query()
	req := &pb.MatchPoliciesRequest{
		FromZone:         q.Get("from_zone"),
		ToZone:           q.Get("to_zone"),
		SourceIp:         q.Get("src_ip"),
		DestinationIp:    q.Get("dst_ip"),
		Protocol:         q.Get("protocol"),
		IngressInterface: q.Get("ingress_interface"),
	}
	intPtr := func(key string) (*int32, bool) {
		vals, present := q[key]
		if !present {
			return nil, true
		}
		v, err := strconv.ParseInt(vals[0], 10, 32)
		if err != nil {
			return nil, false
		}
		p := int32(v)
		return &p, true
	}
	uintPtr := func(key string) (*uint32, bool) {
		vals, present := q[key]
		if !present {
			return nil, true
		}
		v, err := strconv.ParseUint(vals[0], 10, 32)
		if err != nil {
			return nil, false
		}
		p := uint32(v)
		return &p, true
	}
	var ok bool
	if req.SourcePort, ok = intPtr("src_port"); !ok {
		return nil, false
	}
	if req.DestinationPort, ok = intPtr("dst_port"); !ok {
		return nil, false
	}
	if req.IcmpType, ok = uintPtr("icmp_type"); !ok {
		return nil, false
	}
	if req.IcmpCode, ok = uintPtr("icmp_code"); !ok {
		return nil, false
	}
	if v := q.Get("non_first_fragment"); v != "" {
		// matchPoliciesHandler parses with strconv.ParseBool and 400s
		// on a malformed value; every ParseBool spelling must carry
		// the fragment selector into the judged command (#16378 fold).
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, false
		}
		req.NonFirstFragment = b
	}
	// A present-but-empty port/icmp value is malformed on this surface
	// (the handler 400s it, #17081 fold); ParseInt/ParseUint above
	// already reject "", so no silent degradation to omitted remains.
	return argforms.MatchForms(req, base)
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
