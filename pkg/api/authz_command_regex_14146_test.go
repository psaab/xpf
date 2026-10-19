package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// #14146: the six operational reads REST declared as having no canonical
// command, plus the multiplexed system/info variants, skipped deny-commands.
//
// The declaration was the bypass: authorizeRESTCommand returned nil for any
// route listed in restRoutesNoCommand, so a class with deny-commands ".*"
// (still holding PermView) read all six over REST while gRPC denied the
// same shape for unmapped RPCs. And GET /api/v1/system/info was charged the
// flat "show version" for every type, so a deny on "show system memory"
// never fired against ?type=memory.
//
// These cells call authorizeRESTCommand directly (the evaluator) and drive
// the real read middleware (the wiring). Both are needed: a test that only
// calls the gate proves the gate decides; only a test through readAuthz
// proves the decision is obeyed on the six routes.

func cfg14146(t *testing.T, deny, allow string) *config.Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("system {\n    host-name authz-14146;\n    login {\n        class limited {\n            permissions [ view ];\n")
	if deny != "" {
		b.WriteString("            deny-commands \"" + deny + "\";\n")
	}
	if allow != "" {
		b.WriteString("            allow-commands \"" + allow + "\";\n")
	}
	b.WriteString("        }\n        class wideopen {\n            permissions [ view ];\n        }\n    }\n}\n")
	tree, errs := config.NewParser(b.String()).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile: %v", err)
	}
	if _, ok, err := config.OperationalLoginRegexesFor(cfg, "limited"); err != nil || !ok {
		t.Fatalf("fixture class limited has no operational regexes (ok=%v err=%v)", ok, err)
	}
	return cfg
}

var sixRoutes14146 = []string{
	"/api/v1/statistics/interfaces",
	"/api/v1/statistics/zones",
	"/api/v1/security/vrrp",
	"/api/v1/routing/ospf",
	"/api/v1/system/buffers",
	"/api/v1/services/flow-exporters",
}

// TestSixNoCommandRoutesDenyForRestrictedClass14146 is the defect itself:
// deny-commands ".*" must refuse all six declared-no-command reads.
func TestSixNoCommandRoutesDenyForRestrictedClass14146(t *testing.T) {
	cfg := cfg14146(t, ".*", "")
	for _, path := range sixRoutes14146 {
		if err := call9952(t, cfg, "limited", "GET", path, ""); err == nil {
			t.Errorf("GET %s was ALLOWED for deny-commands \".*\"; a declared-no-command route must fail closed (#14146)", path)
		} else if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("GET %s refusal does not read as an authorization denial: %v", path, err)
		}
	}
}

// TestSystemInfoChargesPerTypeCommand14146: the multiplexed route must be
// charged the type's command, as gRPC charges GetSystemInfo — not the flat
// "show version" it was charged before.
func TestSystemInfoChargesPerTypeCommand14146(t *testing.T) {
	memCfg := cfg14146(t, "^show system memory$", "")
	if err := call9952(t, memCfg, "limited", "GET", "/api/v1/system/info?type=memory", ""); err == nil {
		t.Fatal("GET /api/v1/system/info?type=memory was ALLOWED under deny ^show system memory$; it was charged \"show version\" instead of its type command (#14146)")
	}
	// Reference arm: the same deny must not refuse the uptime variant.
	if err := call9952(t, memCfg, "limited", "GET", "/api/v1/system/info?type=uptime", ""); err != nil {
		t.Fatalf("GET /api/v1/system/info?type=uptime was refused by a memory-only deny: %v", err)
	}

	upCfg := cfg14146(t, "^show system uptime$", "")
	if err := call9952(t, upCfg, "limited", "GET", "/api/v1/system/info?type=uptime", ""); err == nil {
		t.Fatal("GET /api/v1/system/info?type=uptime was ALLOWED under deny ^show system uptime$ (#14146)")
	}
	if err := call9952(t, upCfg, "limited", "GET", "/api/v1/system/info?type=memory", ""); err != nil {
		t.Fatalf("GET /api/v1/system/info?type=memory was refused by an uptime-only deny: %v", err)
	}

	// Unknown and missing types resolve to no command and deny, as gRPC
	// denies an unknown GetSystemInfo type.
	anyCfg := cfg14146(t, "^show version$", "")
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/info?type=bogus"} {
		if err := call9952(t, anyCfg, "limited", "GET", path, ""); err == nil {
			t.Errorf("GET %s was ALLOWED for a restricted class; an unnamed system/info type must fail closed (#14146)", path)
		}
	}
}

// TestRestrictedClassControls14146 pins the narrowness in both directions:
// a class with no regexes is unaffected on every affected route, and a
// restricted class that is not denied the resolved command keeps working
// where a command exists.
func TestRestrictedClassControls14146(t *testing.T) {
	cfg := cfg14146(t, "^show system memory$", "")
	// No-regex class: nothing changes, including the six and unknown types.
	for _, path := range append(append([]string{}, sixRoutes14146...),
		"/api/v1/system/info?type=memory", "/api/v1/system/info?type=bogus", "/api/v1/system/info") {
		if err := call9952(t, cfg, "wideopen", "GET", path, ""); err != nil {
			t.Errorf("GET %s refused for a class with NO operational regexes: %v", path, err)
		}
	}
	// Allow-list direction: allow-commands is an allowlist, so a class that
	// permits only "show version" must be refused the six (no command to
	// permit) and both system/info types, while "show version" itself works.
	allowCfg := cfg14146(t, "", "^show version$")
	for _, path := range append(append([]string{}, sixRoutes14146...),
		"/api/v1/system/info?type=memory", "/api/v1/system/info?type=uptime") {
		if err := call9952(t, allowCfg, "limited", "GET", path, ""); err == nil {
			t.Errorf("GET %s was ALLOWED under allow-commands \"^show version$\"; an allow-list cannot permit a route with no (or a different) command (#14146)", path)
		}
	}
	if err := call9952(t, allowCfg, "limited", "GET", "/api/v1/status", ""); err != nil {
		t.Fatalf("GET /api/v1/status is session plumbing (#15077) and must stay admitted under any allow-list: %v", err)
	}
	// Superuser exemption is unchanged.
	denyAllCfg := cfg14146(t, ".*", "")
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/v1/statistics/interfaces", nil)
	if err := s.authorizeRESTCommand(r, denyAllCfg, authz.Principal{Class: "limited", Superuser: true}); err != nil {
		t.Fatalf("superuser refused on a no-command route: %v", err)
	}
}

// TestNoCommandExemptSetIsExactlyTheOtherFamily14146 guards the exemption
// mechanism itself: the only declared routes a restricted class may still
// reach are /health, /metrics, the two session-plumbing status probes
// (#15077), and the config-mode family. A future route
// added to restRoutesNoCommand without being added here denies — and this
// test fails if the exempt set drifts from that reviewed set in either
// direction (a stale exemption for a removed route, or a new exemption
// nobody reviewed).
func TestNoCommandExemptSetIsExactlyTheOtherFamily14146(t *testing.T) {
	want := map[string]bool{
		"GET /health": true, "GET /metrics": true,
		"GET /api/v1/status": true, "GET /api/v1/config/status": true,
		"POST /api/v1/config/set": true, "POST /api/v1/config/delete": true,
		"POST /api/v1/config/deactivate": true, "POST /api/v1/config/activate": true,
		"POST /api/v1/config/annotate": true, "POST /api/v1/config/load": true,
		"POST /api/v1/config/rollback": true, "POST /api/v1/config/commit": true,
		"POST /api/v1/config/commit-check": true, "POST /api/v1/config/commit-confirmed": true,
		"POST /api/v1/config/confirm": true, "POST /api/v1/config/enter": true,
		"POST /api/v1/config/exit": true,
	}
	if len(restNoCommandExempt14146) != len(want) {
		t.Fatalf("restNoCommandExempt14146 has %d entries, want exactly %d (the other-family set); got %v", len(restNoCommandExempt14146), len(want), keysOf14146(restNoCommandExempt14146))
	}
	for route := range want {
		if !restNoCommandExempt14146[route] {
			t.Errorf("route %q must be exempt (different authorization family) but is not in restNoCommandExempt14146", route)
		}
		if _, declared := restRoutesNoCommand[route]; !declared {
			t.Errorf("exempt route %q is not declared in restRoutesNoCommand; the exemption is stale", route)
		}
	}
	for route := range restNoCommandExempt14146 {
		if !want[route] {
			t.Errorf("route %q is exempt for a restricted class but is not /health, /metrics, a status probe, or config-mode; a read route must fail closed, not be exempted (#14146/#15077)", route)
		}
	}
	for route := range restRoutesNoCommand {
		if restNoCommandExempt14146[route] || isRequestDecodedRoute9952(route) {
			continue
		}
		found := false
		for _, p := range sixRoutes14146 {
			if route == "GET "+p {
				found = true
			}
		}
		if !found {
			t.Errorf("declared route %q is neither exempt, request-decoded, nor one of the six no-twin reads; classify it deliberately", route)
		}
	}
	// Config-mode routes must stay reachable for a restricted class (the
	// #9633 regression guard, restated against the new mechanism).
	cfg := cfg14146(t, ".*", "")
	for route := range restNoCommandExempt14146 {
		if !strings.HasPrefix(route, "POST /api/v1/config/") {
			continue
		}
		parts := strings.SplitN(route, " ", 2)
		if err := call9952(t, cfg, "limited", parts[0], parts[1], `{}`); err != nil {
			t.Errorf("%s refused by the command gate under deny \".*\"; config-mode is governed by the *-configuration pair (#9633): %v", route, err)
		}
	}
}

// TestSystemInfoCommandsResolve14146 holds the new per-type table to the
// same rule as restRouteCommand: every charged string must be a canonical
// argument-free command in the operational tree.
func TestSystemInfoCommandsResolve14146(t *testing.T) {
	if len(restSystemInfoCommands14146) == 0 {
		t.Fatal("restSystemInfoCommands14146 is empty")
	}
	for typ, cmd := range restSystemInfoCommands14146 {
		words := strings.Fields(cmd)
		if !cmdtree.EveryWordIsAKeyword(cmdtree.OperationalTree, words) {
			t.Errorf("system/info type %q maps to %q, which is not an argument-free command path", typ, cmd)
			continue
		}
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
		if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != cmd {
			t.Errorf("system/info type %q maps to %q, which canonicalizes to %q (%v)", typ, cmd, strings.Join(canon, " "), res)
		}
	}
	// The REST handler serves exactly uptime and memory; the table must not
	// charge a type the handler rejects, nor miss one it serves.
	for _, typ := range []string{"uptime", "memory"} {
		if _, ok := restSystemInfoCommands14146[typ]; !ok {
			t.Errorf("system/info type %q is served by the handler but has no command; it would deny for every restricted class", typ)
		}
	}
}

func keysOf14146(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

const wiringConfig14146 = `
system {
    host-name authz-14146-wiring;
    login {
        class limited {
            permissions [ view clear maintenance ];
            deny-commands ".*";
        }
        user opsuser {
            class limited;
        }
    }
}
`

// TestReadMiddlewareDeniesSixAndSystemInfo14146 drives the real readAuthz
// middleware: deny-commands ".*" must 403 the six routes and both
// system/info variants, while a command the class may still perform is not
// collateral. Before the fix the six returned 200 (handler ran) and
// system/info?type=memory returned 200 under a memory deny.
func TestReadMiddlewareDeniesSixAndSystemInfo14146(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, wiringConfig14146)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
	})
	if _, ok, err := config.OperationalLoginRegexesFor(store.ActiveConfig(), "limited"); err != nil || !ok {
		t.Fatalf("server config has no operational regexes for limited (ok=%v err=%v)", ok, err)
	}
	for _, path := range append(append([]string{}, sixRoutes14146...),
		"/api/v1/system/info?type=memory", "/api/v1/system/info?type=uptime", "/api/v1/system/info") {
		rr := runGuardedConfigRead9324(t, s, path)
		if rr.Code != 403 {
			t.Errorf("GET %s -> %d, want 403 under deny-commands \".*\"; body=%s", path, rr.Code, rr.Body.String())
		}
	}
}
