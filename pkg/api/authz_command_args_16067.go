package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/psaab/xpf/pkg/argforms"
	"github.com/psaab/xpf/pkg/config"
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
		full := "ping " + req.Target
		if req.Source != "" {
			full += " source " + req.Source
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
	}
	return argforms.ChargeForms(cmd), true
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
