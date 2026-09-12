package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	// operator's regex means.
	"GET /api/v1/status":                               "show version",
	"GET /api/v1/system/info":                          "show version",
	"GET /api/v1/statistics/global":                    "show security flow statistics",
	"GET /api/v1/security/zones":                       "show security zones",
	"GET /api/v1/security/policies":                    "show security policies",
	"GET /api/v1/security/sessions":                    "show security flow session",
	"GET /api/v1/security/sessions/summary":            "show security flow session summary",
	"GET /api/v1/security/sessions/summary/zone-pairs": "show security match-policies",
	"GET /api/v1/security/match":                       "show security match-policies",
	"GET /api/v1/security/nat/source":                  "show security nat source pool",
	"GET /api/v1/security/nat/pools":                   "show security nat source pool",
	"GET /api/v1/security/nat/rules":                   "show security nat source rule",
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
	"GET /api/v1/routing/bgp":                          "show bgp summary",
	"GET /api/v1/config":                               "show configuration",
	"GET /api/v1/config/show":                          "show configuration",
	"GET /api/v1/config/compare":                       "show configuration",
	"GET /api/v1/config/show-rollback":                 "show configuration",
	"GET /api/v1/config/export":                        "show configuration",
	"GET /api/v1/config/search":                        "show configuration",
	"GET /api/v1/config/history":                       "show system commit history",
	// gRPC charges GetConfigModeStatus "show version" (authz_command_table.go).
	// Matched deliberately rather than "improved" here: if that is the wrong
	// command it is wrong IDENTICALLY on both surfaces, which is discoverable;
	// a better answer on one surface only is a divergence nobody sees.
	"GET /api/v1/config/status": "show version",
	"GET /api/v1/events/stream": "show log",
	"GET /api/v1/logs/stream":   "show log",

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
// Being listed here does NOT mean unauthorized: the coarse permission bits and,
// for the config routes, the `*-configuration` regexes still apply. It means the
// `deny-commands` family has nothing to evaluate against this route.
var restRoutesNoCommand = map[string]string{
	"GET /health":  "unauthenticated liveness probe; authMiddleware exempts it unconditionally, so there is no principal to charge",
	"GET /metrics": "Prometheus exposition, not an operational command; gated by the #4162 metrics auth rule",

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
	"GET /api/v1/show-text":      "request-decoded: the command is the TOPIC's, resolved per request from cmdtree.ShowTextTopicCommands()",
	"POST /api/v1/system/action": "request-decoded: the command is the VERB's, resolved per request from authz.SystemActionVerbCommand",

	// Read endpoints with no argument-free operational twin. Each is charged
	// nothing rather than charged a command an operator cannot type: an entry
	// that does not resolve in cmdtree is a gate comparing against a string no
	// deny regex will ever be written for.
	"GET /api/v1/statistics/interfaces":   "no argument-free operational twin: `show interfaces statistics` takes an interface name",
	"GET /api/v1/statistics/zones":        "no operational twin: per-zone counters are surfaced by `show security zones`, which is already charged on its own route",
	"GET /api/v1/security/vrrp":           "no argument-free operational twin in the operational tree",
	"GET /api/v1/routing/ospf":            "no argument-free operational twin in the operational tree",
	"GET /api/v1/system/buffers":          "no argument-free operational twin in the operational tree",
	"GET /api/v1/services/flow-exporters": "no operational twin: REST-only observability surface (#2464)",
}

// restRequestCommand9952 resolves the canonical command for the two
// request-decoded routes.
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
	actionVerb := restActionVerb9952(r)
	rules, ok, err := config.OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}

	route := r.Method + " " + r.URL.Path
	if reason, declared := restRoutesNoCommand[route]; declared {
		cmd, resolved := restRequestCommand9952(route, r, actionVerb)
		if !resolved {
			// A DECLARED route with no per-request command is exempt only when
			// it is not request-decoded. A request-decoded route whose topic or
			// verb we cannot name denies, exactly as gRPC denies an unmapped
			// SystemAction verb — including the PREFIX-FORM verbs, which are
			// parsed out of a packed string by the handler's default branch and
			// therefore cannot appear in any table.
			if isRequestDecodedRoute9952(route) {
				return fmt.Errorf("permission denied: login class %q restricts commands and this "+
					"request has no canonical command to evaluate, so the restriction cannot be "+
					"applied to it", class)
			}
			_ = reason
			return nil
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

func isRequestDecodedRoute9952(route string) bool {
	return route == "GET /api/v1/show-text" || route == "POST /api/v1/system/action"
}

func evaluateCommand9952(rules config.CompiledLoginRegexes, class, cmd string) error {
	if decision := rules.Evaluate(cmd); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies %q (%s)", class, cmd, decision.Reason)
	}
	return nil
}
