package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// #9952: `deny-commands` / `allow-commands` on the REST surface.
//
// REST enforced the coarse permission bits and the `*-configuration` regexes and
// NOTHING else. The operational command regexes had no enforcement point in this
// package at all, so a principal whose class narrows its command set by regex had
// that narrowing silently ignored on every REST endpoint — while
// `docs/system-login.md` said all four statements were enforced.
//
// The absence was a MEASUREMENT, not a failed search: `OperationalLoginRegexesFor`
// is the only resolver for these regexes, and it had exactly two non-test
// enforcement callers — `pkg/grpcapi/authz_command_gate_7172.go` and
// `pkg/cli/permissions_regex.go`. The same grep finding both other surfaces is
// what makes "zero in pkg/api" evidence rather than a miss.
//
// ── THE MAPPING IS THE HARD PART, AND IT IS WHY THIS IS A TABLE ──────────────
//
// A REST route is not a CLI command, so the canonical command it performs has to
// be DEFINED rather than derived. gRPC proves the mapping is constructible — it
// has had one since #7172 — and this mirrors its structure deliberately, so a
// reader comparing the two surfaces compares two tables rather than a table and
// an inference.
//
// ── FAIL CLOSED, AND ONLY FOR A CLASS THAT ASKED FOR IT ──────────────────────
//
// Every uncertain path DENIES, and every one of them applies only to a class that
// configured operational regexes. A class with none is unaffected and pays
// nothing — no request it would otherwise serve starts failing.
//
// A route with NO canonical command denies. Not knowing which command we are
// serving, we cannot know that a deny regex fails to match it; treating "cannot
// resolve" as "no match, allow" is precisely the bypass this table exists to
// close. That covers a route added to server.go and to neither table here — the
// census below turns that into a test failure at the first run, but the RUNTIME
// answer is still deny, because a census is a build-time guard and this is the
// request path.
//
// #14146: the declared-no-command arm used to be the exception to that rule —
// a route listed in restRoutesNoCommand returned nil for a restricted class,
// so `deny-commands ".*"` (or an allow-list that permits nothing here) read
// six operational routes REST had decided not to charge. gRPC denies the same
// shape (authorizeRPCCommand: resolved=false denies). The only routes that
// still return nil for a restricted class are the ones with a DIFFERENT
// authorization family in force — config-mode (the *-configuration pair) and
// the genuinely unauthenticated / differently-gated probes (/health, /metrics,
// whose handlers never see a login-class principal here) — and the
// request-decoded routes resolve per-request or deny. Every other declared
// route denies: its reason records why no command EXISTS, not an exemption.

// restRouteCommand maps a registered REST route to the canonical operational
// command it performs.
//
// The values are validated against `cmdtree.OperationalTree` by
// TestEveryRESTRouteCommandResolves9952, using the same rule the gRPC table is
// held to: every word must be a real command KEYWORD and the string must be the
// CANONICAL spelling. A deny regex is matched against this string, so an entry
// that does not resolve means the gate compares against a command no operator can
// run — which is a gate that cannot deny anything an operator would actually be
// told to stop doing.
var restRouteCommand = map[string]string{
	// Read endpoints. Where a gRPC method serves the same data, the command is
	// the SAME STRING it charges, so the two surfaces cannot diverge on what an
	// operator's regex means. (GET /api/v1/status and
	// GET /api/v1/config/status are session plumbing probes with no command
	// charge — see restRoutesNoCommand, #15077.)
	"GET /api/v1/statistics/global":                    "show security flow statistics",
	"GET /api/v1/security/zones":                       "show security zones",
	"GET /api/v1/security/policies":                    "show security policies",
	"GET /api/v1/security/sessions":                    "show security flow session",
	"GET /api/v1/security/sessions/summary":            "show security flow session summary",
	"GET /api/v1/security/sessions/summary/zone-pairs": "show security flow session summary",
	"GET /api/v1/security/match":                       "show security match-policies",
	"GET /api/v1/security/nat/source":                  "show security nat source pool",
	"GET /api/v1/security/nat/pools":                   "show security nat source pool",
	"GET /api/v1/security/nat/destination":             "show security nat destination pool",
	"GET /api/v1/security/nat/deterministic":           "show security nat source deterministic-nat",
	"GET /api/v1/security/screen":                      "show security screen statistics",
	"GET /api/v1/security/events":                      "show log",
	"GET /api/v1/security/ipsec/sa":                    "show security ipsec security-associations",
	"GET /api/v1/interfaces":                           "show interfaces",
	"GET /api/v1/interfaces/detail":                    "show interfaces detail",
	"GET /api/v1/dhcp/leases":                          "show dhcp leases",
	"GET /api/v1/dhcp/identifiers":                     "show dhcp client-identifier",
	"GET /api/v1/routes":                               "show route",
	"GET /api/v1/config":                               "show configuration",
	"GET /api/v1/config/show":                          "show configuration",
	"GET /api/v1/config/compare":                       "show configuration",
	"GET /api/v1/config/show-rollback":                 "show configuration",
	"GET /api/v1/config/export":                        "show configuration",
	"GET /api/v1/config/search":                        "show configuration",
	"GET /api/v1/config/history":                       "show system commit history",
	"GET /api/v1/events/stream":                        "show log",
	"GET /api/v1/logs/stream":                          "show log",

	// Clear and diagnostic endpoints — the class the issue's own matrix names.
	"POST /api/v1/security/sessions/clear": "clear security flow session",
	"POST /api/v1/security/counters/clear": "clear security counters",
	"POST /api/v1/dhcp/identifiers/clear":  "clear dhcp client-identifier",
	"POST /api/v1/diagnostics/ping":        "ping",
	"POST /api/v1/diagnostics/traceroute":  "traceroute",
}

// restRoutesNoCommand names every OTHER registered route with the REASON it has
// no canonical operational command, so that "not in the command table" is a
// decision somebody made rather than an omission nobody noticed.
//
// Being listed here does NOT mean authorized for a restricted class (#14146):
// for a class with operational regexes, authorizeRESTCommand DENIES every
// route in this table except the routes named in restNoCommandExempt14146.
// The reason records why no command EXISTS to evaluate; it is not an
// exemption. The coarse permission bits and, for the config routes, the
// *-configuration regexes still apply on their own paths.
var restRoutesNoCommand = map[string]string{
	"GET /health":  "unauthenticated liveness probe; authMiddleware exempts it unconditionally, so there is no principal to charge",
	"GET /metrics": "Prometheus exposition, not an operational command; gated by the #4162 metrics auth rule",

	// SESSION PLUMBING, NOT COMMANDS (#15077). The REST twins of the
	// gRPC plumbing probes: daemon liveness/cluster facts and
	// config-mode/dirty facts. Neither renders the `show version`
	// banner; `show version` itself is served by GET /api/v1/show-text
	// with topic=version and stays charged there. Charging the probes
	// to `show version` made a version deny (or an allowlist) refuse
	// the liveness facts every other admitted operation depends on.
	// They are exempt from the operational regex gate and governed by
	// the coarse permission authorization alone, exactly as the gRPC
	// probes are — see restNoCommandExempt14146.
	"GET /api/v1/status":        "session plumbing probe (daemon liveness/cluster facts); not an operator command — coarse permission only (#15077)",
	"GET /api/v1/config/status": "session plumbing probe (config-mode/dirty facts); not an operator command — coarse permission only (#15077)",
	// CONFIG-MODE routes are governed by `deny-configuration` /
	// `allow-configuration`, not by `deny-commands` — exactly as the on-box CLI's
	// dispatchConfig applies only checkConfigRegex, and as #9633 established for
	// gRPC. Charging them an operational command here would lock any class with
	// an operational pattern out of configuration over REST, which is the
	// regression #9633 fixed on the other surface.
	"POST /api/v1/config/set":              "config-mode: governed by the *-configuration regexes (#9154/#9890)",
	"POST /api/v1/config/delete":           "config-mode: governed by the *-configuration regexes (#9154/#9890)",
	"POST /api/v1/config/deactivate":       "config-mode: governed by the *-configuration regexes (#9890)",
	"POST /api/v1/config/activate":         "config-mode: governed by the *-configuration regexes (#9890)",
	"POST /api/v1/config/annotate":         "config-mode: governed by the *-configuration regexes (#9890)",
	"POST /api/v1/config/load":             "config-mode: governed by the *-configuration regexes, by CONTENT (#9892)",
	"POST /api/v1/config/rollback":         "config-mode: governed by the *-configuration regexes, by CONTENT (#9892)",
	"POST /api/v1/config/commit":           "config-mode: the commit itself carries no path; the candidate's paths were adjudicated as they were written",
	"POST /api/v1/config/commit-check":     "config-mode: validation only, mutates nothing",
	"POST /api/v1/config/commit-confirmed": "config-mode: same as commit, plus a timer",
	"POST /api/v1/config/confirm":          "config-mode: resolves a pending commit-confirmed, carries no path",
	"POST /api/v1/config/enter":            "config-mode: acquires the configuration lock, carries no path",
	"POST /api/v1/config/exit":             "config-mode: releases the configuration lock, carries no path",

	// Request-decoded routes: the command depends on a field of the request, so
	// it is resolved at call time by restRequestCommand9952 rather than keyed by
	// route. They are listed here so the census sees a decision, not a gap.
	"GET /api/v1/show-text":          "request-decoded: the command is the TOPIC's, resolved per request from cmdtree.ShowTextTopicCommands()",
	"POST /api/v1/system/action":     "request-decoded: the command is the VERB's, resolved per request from authz.SystemActionVerbCommand",
	"GET /api/v1/system/info":        "request-decoded: the command is the TYPE's, resolved per request (show system uptime / show system memory, as gRPC charges GetSystemInfo)",
	"GET /api/v1/routing/bgp":        "request-decoded: the command is the ?type='s, resolved per request (show protocols bgp summary / routes, as gRPC charges GetBGPStatus) (#15076)",
	"GET /api/v1/security/nat/rules": "request-decoded: the command is the ?type=/?nat_type='s, resolved per request (show security nat source/destination rule, as gRPC charges GetNATRuleStats) (#15076)",

	// Read endpoints with no argument-free operational twin. Each is charged
	// nothing rather than charged a command an operator cannot type: an entry
	// that does not resolve in cmdtree is a gate comparing against a string no
	// deny regex will ever be written for. #14146: charged nothing now means
	// DENIED for a restricted class, not allowed — see authorizeRESTCommand.
	"GET /api/v1/statistics/interfaces":   "no argument-free operational twin: `show interfaces statistics` takes an interface name",
	"GET /api/v1/statistics/zones":        "no operational twin: per-zone counters are surfaced by `show security zones`, which is already charged on its own route",
	"GET /api/v1/security/vrrp":           "no argument-free operational twin in the operational tree",
	"GET /api/v1/routing/ospf":            "no argument-free operational twin in the operational tree",
	"GET /api/v1/system/buffers":          "no argument-free operational twin in the operational tree",
	"GET /api/v1/services/flow-exporters": "no operational twin: REST-only observability surface (#2464)",
}

// restNoCommandExempt14146 is the exhaustive set of restRoutesNoCommand routes
// that still return nil for a class with operational regexes. Every member is
// exempt because a DIFFERENT authorization decision governs it, never because
// it is a read: /health and /metrics never carry a login-class principal on
// this path (health is unauthenticated, metrics has its own #4162 rule), the
// config-mode routes are governed by the *-configuration pair (#9633), and
// the two status probes are session plumbing governed by the coarse
// permission authorization alone (#15077).
// TestNoCommandExemptSetIsExactlyTheOtherFamily14146 pins this set so a future
// route cannot be exempted by adding it to restRoutesNoCommand alone.
var restNoCommandExempt14146 = map[string]bool{
	"GET /health":                          true,
	"GET /metrics":                         true,
	"GET /api/v1/status":                   true,
	"GET /api/v1/config/status":            true,
	"POST /api/v1/config/set":              true,
	"POST /api/v1/config/delete":           true,
	"POST /api/v1/config/deactivate":       true,
	"POST /api/v1/config/activate":         true,
	"POST /api/v1/config/annotate":         true,
	"POST /api/v1/config/load":             true,
	"POST /api/v1/config/rollback":         true,
	"POST /api/v1/config/commit":           true,
	"POST /api/v1/config/commit-check":     true,
	"POST /api/v1/config/commit-confirmed": true,
	"POST /api/v1/config/confirm":          true,
	"POST /api/v1/config/enter":            true,
	"POST /api/v1/config/exit":             true,
}

// #11678: the commit-time deny advisory also needs the command set that the
// REST route table can evaluate. REST's mappings are argument-free, so an
// argument-scoped deny may be valid on the box yet never fire on this surface.
const restSurfaceName9952 = "the REST surface"

var allRESTCanonicalCommands9952 = sync.OnceValue(func() []string {
	seen := make(map[string]bool)
	for _, commands := range []map[string]string{
		restRouteCommand,
		cmdtree.ShowTextTopicCommands(),
		authz.SystemActionVerbCommand,
		restSystemInfoCommands14146,
		restBGPCommands15076,
		restNATRuleCommands15076,
	} {
		for _, command := range commands {
			seen[command] = true
		}
	}
	for _, command := range restBGPNATCanonicalCommands15076 {
		seen[command] = true
	}
	out := make([]string, 0, len(seen))
	for command := range seen {
		out = append(out, command)
	}
	sort.Strings(out)
	return out
})

func init() {
	config.RegisterCommandSurface(restSurfaceName9952, allRESTCanonicalCommands9952)
}

// restSystemInfoCommands14146 maps the REST system/info `type` selector to the
// canonical command gRPC charges for the same GetSystemInfo type
// (systemInfoCanonicalCommand in pkg/grpcapi). REST serves only uptime and
// memory (systemInfoHandler's default arm rejects every other type), so those
// are the only two entries; an unknown or missing type resolves to no command
// and therefore denies for a restricted class, exactly as gRPC denies an
// unknown GetSystemInfo type.
var restSystemInfoCommands14146 = map[string]string{
	"uptime": "show system uptime",
	"memory": "show system memory",
}

// restBGPCommands15076 maps the REST bgpHandler `type` selector to the
// command gRPC charges for the same GetBGPStatus selection (#15076).
// bgpHandler serves only summary (default) and routes; any other type
// falls into its summary branch today, but charging it summary would
// repeat the fixed-charge defect, so it resolves to no command and
// denies for a restricted class.
var restBGPCommands15076 = map[string]string{
	"":        "show protocols bgp summary",
	"summary": "show protocols bgp summary",
	"routes":  "show protocols bgp routes",
}

// restNATRuleCommands15076 maps the NAT rules selector to the command
// gRPC charges for GetNATRuleStats. The REST handler always serves
// source rules; `type`/`nat_type` are not handler inputs, so a
// destination (or unknown) selector names a different command than the
// one served and must be charged as that command — denying under a
// destination deny and refusing under a source-only allow — rather
// than silently receiving the source charge (#15076).
var restNATRuleCommands15076 = map[string]string{
	"":            "show security nat source rule",
	"source":      "show security nat source rule",
	"destination": "show security nat destination rule",
}

var restBGPNATCanonicalCommands15076 = []string{
	"show protocols bgp summary",
	"show protocols bgp routes",
	"show security nat source rule",
	"show security nat destination rule",
}

// restRequestCommand9952 resolves the canonical command for the request-decoded
// routes.
//
// UNMAPPED MEANS DENY, and the reason is the one the gRPC gate records for the
// same shape: a topic or verb with no entry is a command we are holding and
// cannot name, so we cannot know a deny regex fails to match it.
func restRequestCommand9952(route string, r *http.Request, actionVerb string) (string, bool) {
	switch route {
	case "GET /api/v1/show-text":
		topic := r.URL.Query().Get("topic")
		cmd, ok := cmdtree.ShowTextTopicCommands()[topic]
		return cmd, ok
	case "POST /api/v1/system/action":
		cmd, ok := authz.SystemActionVerbCommand[actionVerb]
		return cmd, ok
	case "GET /api/v1/system/info":
		cmd, ok := restSystemInfoCommands14146[r.URL.Query().Get("type")]
		return cmd, ok
	case "GET /api/v1/routing/bgp":
		cmd, ok := restBGPCommands15076[r.URL.Query().Get("type")]
		return cmd, ok
	case "GET /api/v1/security/nat/rules":
		sel := r.URL.Query().Get("type")
		if sel == "" {
			sel = r.URL.Query().Get("nat_type")
		}
		cmd, ok := restNATRuleCommands15076[sel]
		return cmd, ok
	}
	return "", false
}

// authorizeRESTCommand enforces the calling class's operational command regexes
// against the canonical command this route performs.
//
// Returns nil when the class configured no operational regexes, which is the
// overwhelmingly common case and is checked before anything else is computed.
//
// A superuser is exempt for the same reason authz.Authorize exempts one: uid 0
// owns the config DB and the daemon process, so a regex denial would be theatre.
// p.Class is empty for a superuser anyway, so this is belt and braces.
func (s *Server) authorizeRESTCommand(r *http.Request, cfg *config.Config, p authz.Principal) error {
	class := p.Class
	if class == "" || p.Superuser {
		return nil
	}
	rules, ok, err := config.OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}

	actionVerb := restActionVerb9952(r)

	// #14712: key the tables on the route as SERVED, not on the raw
	// method. readPermissionFor (#9134) already canonicalizes any safe
	// non-GET method to the GET entry for the coarse permission, so a
	// HEAD request (the only safe non-GET method Go's ServeMux aliases
	// to a GET pattern) passes that gate and reaches here — where the
	// raw "HEAD /api/v1/status" missed every GET-keyed table and hit
	// the fail-closed !mapped denial below. Every regex-restricted
	// class therefore got 403 on 100% of HEAD reads while GET
	// succeeded. Canonicalizing here, with the same isSafeHTTPMethod
	// predicate readPermissionFor uses, makes HEAD follow the GET
	// verdict exactly — including deny cases and the request-decoded
	// routes resolved below. Non-safe methods (the POST mutation
	// family) keep their raw key, so no mutation route is aliased.
	route := canonicalRESTRoute14712(r.Method, r.URL.Path)
	if _, declared := restRoutesNoCommand[route]; declared {
		cmd, resolved := restRequestCommand9952(route, r, actionVerb)
		if !resolved {
			// #14146: a declared route is exempt only when it is in
			// restNoCommandExempt14146 (a different authorization family
			// governs it) — never merely because it was declared. A
			// request-decoded route whose topic, verb, or type we cannot
			// name denies, exactly as gRPC denies an unmapped SystemAction
			// verb — including the PREFIX-FORM verbs, which are parsed out
			// of a packed string by the handler's default branch and
			// therefore cannot appear in any table. Every other declared
			// route (the six operational reads with no canonical twin)
			// denies too: we cannot know a deny regex fails to match a
			// command we cannot name, and an allow-list cannot permit it.
			if restNoCommandExempt14146[route] {
				return nil
			}
			return fmt.Errorf("permission denied: login class %q restricts commands and this "+
				"request has no canonical command to evaluate, so the restriction cannot be "+
				"applied to it", class)
		}
		return evaluateCommand9952(rules, class, cmd)
	}

	cmd, mapped := restRouteCommand[route]
	if !mapped {
		return fmt.Errorf("permission denied: login class %q restricts commands and this route "+
			"has no canonical command to evaluate, so the restriction cannot be applied to it", class)
	}
	return evaluateCommand9952(rules, class, cmd)
}

// restActionVerb9952 reads the SystemAction verb out of the already-buffered
// body and puts the body back, exactly as the sibling `*-configuration` gates
// do, so the handler decodes the same bytes it was judged on.
//
// A body that cannot be read or decoded yields "", which resolves to no command
// and therefore DENIES for a restricted class — the handler would reject it too,
// but the denial must not depend on the handler getting there.
func restActionVerb9952(r *http.Request) string {
	if r.Method+" "+r.URL.Path != "POST /api/v1/system/action" {
		return ""
	}
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	raw, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return ""
	}
	return req.Action
}

// canonicalRESTRoute14712 returns the route key the command tables are
// keyed on: the GET spelling for any safe method, the raw method
// otherwise. This is the same alias readPermissionFor resolves for the
// coarse permission (#9134) — a safe method other than GET reaches the
// GET handler through the mux (HEAD is the one Go's ServeMux actually
// aliases; OPTIONS/TRACE never reach a GET handler), so it is the GET
// entry that governs it here too. Keeping the canonicalization in one
// predicate-shaped helper means a future safe method the mux learns
// to alias is charged identically on both gates rather than reopening
// the #14712 gap on this one.
func canonicalRESTRoute14712(method, path string) string {
	if method != http.MethodGet && isSafeHTTPMethod(method) {
		return http.MethodGet + " " + path
	}
	return method + " " + path
}

func isRequestDecodedRoute9952(route string) bool {
	return route == "GET /api/v1/show-text" || route == "POST /api/v1/system/action" ||
		route == "GET /api/v1/system/info" || route == "GET /api/v1/routing/bgp" ||
		route == "GET /api/v1/security/nat/rules"
}

func evaluateCommand9952(rules config.CompiledLoginRegexes, class, cmd string) error {
	if decision := rules.Evaluate(cmd); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies %q (%s)", class, cmd, decision.Reason)
	}
	return nil
}
