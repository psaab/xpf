package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17184 REST twin: restArgumentForms had the same bare-charge default.
// The routes whose inputs carry operator argument text now reconstruct
// it (deterministic lookup, NAT rule_set, DHCP clear interface); every
// other charged route is named in restRoutesWithoutArgumentForms, and
// an unlisted route is unnameable (deny for a restricted class).
//
// FAIL-ON-REVERT: restoring `return restChargeForms16472(cmd), true`
// makes every wantDeny cell ALLOWED again.

func TestArgumentFormsREST17184(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, method, path, body string
		wantDeny                          bool
	}{
		{"deterministic forward denied", `^show security nat source deterministic-nat internal-host 10\.0\.0\.5`, "GET", "/api/v1/security/nat/deterministic?internal-host=10.0.0.5", "", true},
		{"deterministic forward other allowed", `^show security nat source deterministic-nat internal-host 10\.0\.0\.5`, "GET", "/api/v1/security/nat/deterministic?internal-host=10.0.0.6", "", false},
		{"deterministic reverse denied", `^show security nat source deterministic-nat nat-ip 192\.0\.2\.1 nat-port 1234$`, "GET", "/api/v1/security/nat/deterministic?nat-ip=192.0.2.1&nat-port=1234", "", true},
		{"deterministic bare still denied", `^show security nat source deterministic-nat$`, "GET", "/api/v1/security/nat/deterministic?internal-host=10.0.0.5", "", true},
		{"nat rule-set denied", `^show security nat source rule-set rs1`, "GET", "/api/v1/security/nat/rules?rule_set=rs1", "", true},
		{"nat rule-set other allowed", `^show security nat source rule-set rs1`, "GET", "/api/v1/security/nat/rules?rule_set=rs2", "", false},
		{"nat rules bare denied", `^show security nat source rule$`, "GET", "/api/v1/security/nat/rules", "", true},
		{"dhcp clear interface denied", `^clear dhcp client-identifier interface ge-0/0/1$`, "POST", "/api/v1/dhcp/identifiers/clear", `{"interface":"ge-0/0/1"}`, true},
		{"dhcp clear other allowed", `^clear dhcp client-identifier interface ge-0/0/1$`, "POST", "/api/v1/dhcp/identifiers/clear", `{"interface":"ge-0/0/2"}`, false},
		{"dhcp clear-all bare denied", `^clear dhcp client-identifier$`, "POST", "/api/v1/dhcp/identifiers/clear", ``, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern)
			err := call9952(t, cfg, "limited", tc.method, tc.path, tc.body)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over %s %s was ALLOWED on REST; the argument must be reconstructed (#17184)", tc.pattern, tc.method, tc.path)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over %s %s refused a command it does not name: %v", tc.pattern, tc.method, tc.path, err)
			}
		})
	}
}

// #17184 fold (M1/M2/M3 + B1): request-decoded routes judge the
// per-request resolved command; ping count/size spell; handler-rejected
// ping/traceroute values and events limit>10000 are unnameable.
func TestArgumentFormsFold17184(t *testing.T) {
	// B1: request-decoded controls under their OWN allow must pass.
	srcOnly := cfg14146(t, "", "^show bgp summary$|^show protocols bgp summary$|^show security nat source rule$|^show system uptime$|^show system memory$|^request system reboot$")
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/routing/bgp", ""},
		{"GET", "/api/v1/routing/bgp?type=summary", ""},
		{"GET", "/api/v1/security/nat/rules", ""},
		{"GET", "/api/v1/system/info?type=uptime", ""},
		{"POST", "/api/v1/system/action", `{"action":"reboot"}`},
	} {
		if err := call9952(t, srcOnly, "limited", tc.method, tc.path, tc.body); err != nil {
			t.Errorf("B1: %s %s refused under its own allow: %v", tc.method, tc.path, err)
		}
	}
	// M1: ping count/size spelled at executed values.
	for _, tc := range []struct {
		name, pattern, body string
		wantDeny            bool
	}{
		{"ping count denied", `^ping 10\.0\.0\.1 count 7$`, `{"target":"10.0.0.1","count":7}`, true},
		{"ping count other allowed", `^ping 10\.0\.0\.1 count 7$`, `{"target":"10.0.0.1","count":8}`, false},
		{"ping size denied", `^ping 10\.0\.0\.1 size 1400$`, `{"target":"10.0.0.1","size":1400}`, true},
		{"ping clamped count denied", `^ping 10\.0\.0\.1 count 100$`, `{"target":"10.0.0.1","count":5000}`, true},
		{"ping clamped size denied", `^ping 10\.0\.0\.1 size 65507$`, `{"target":"10.0.0.1","size":70000}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern)
			err := call9952(t, cfg, "limited", "POST", "/api/v1/diagnostics/ping", tc.body)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over ping was ALLOWED; count/size must be spelled (#17184 M1)", tc.pattern)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over ping refused a command it does not name: %v", tc.pattern, err)
			}
		})
	}
	// M2: handler-rejected over-length target unnameable.
	wide := cfg16067(t, `^show version$`)
	longBody := `{"target":"` + strings.Repeat("a", 600) + `"}`
	if err := call9952(t, wide, "limited", "POST", "/api/v1/diagnostics/ping", longBody); err == nil {
		t.Error("ping with handler-rejected over-length target ALLOWED for restricted class (#17184 M2)")
	}
	// M2 (REST traceroute twin): the REST traceroute arm exists in
	// restArgumentForms (POST /api/v1/diagnostics/traceroute), so the
	// over-length (>diagcmd.MaxArgLen, #6904) unnameable cell is
	// nameable on this surface too — not gRPC-only.
	if err := call9952(t, wide, "limited", "POST", "/api/v1/diagnostics/traceroute", longBody); err == nil {
		t.Error("traceroute with handler-rejected over-length target ALLOWED for restricted class (#17184 M2)")
	}
	// M3: events limit>10000 (handler 400) unnameable; at cap judged normally.
	if err := call9952(t, wide, "limited", "GET", "/api/v1/security/events?limit=10001", ""); err == nil {
		t.Error("events limit=10001 (handler-rejected) ALLOWED for restricted class (#17184 M3)")
	}
	if err := call9952(t, wide, "limited", "GET", "/api/v1/security/events?limit=10000", ""); err != nil {
		t.Errorf("events limit=10000 refused though handler accepts it: %v", err)
	}
	// rule_set still spelled on the request-decoded NAT route.
	rsCfg := cfg16067(t, `^show security nat source rule-set rs1`)
	if err := call9952(t, rsCfg, "limited", "GET", "/api/v1/security/nat/rules?rule_set=rs1", ""); err == nil {
		t.Error("nat rules ?rule_set=rs1 ALLOWED under rule-set deny (#17184)")
	}
}

// restArgumentFormsCases17184 reads the restArgumentForms switch's
// route case labels out of the production source (#5278 discipline).
func restArgumentFormsCases17184(t *testing.T) map[string]bool {
	t.Helper()
	const src = "authz_command_args_16067.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	cases := map[string]bool{}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "restArgumentForms" {
			return true
		}
		// Only the OUTER switch (direct child of the function body)
		// holds route cases; the pre-switch request-decoded dispatch
		// nests its own switch and must not be read as route arms —
		// the census arm below covers those routes separately.
		for _, stmt := range fn.Body.List {
			sw, ok := stmt.(*ast.SwitchStmt)
			if !ok {
				continue
			}
			found = true
			for _, s := range sw.Body.List {
				cc, ok := s.(*ast.CaseClause)
				if !ok || cc.List == nil {
					continue
				}
				for _, expr := range cc.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s: restArgumentForms has a non-literal case label; the census cannot read it", src)
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("unquote %s: %v", lit.Value, err)
					}
					// Multi-route cases name each route separately.
					for _, route := range strings.Split(v, "\x00") {
						cases[route] = true
					}
					cases[v] = true
				}
			}
		}
		return false
	})
	if !found || len(cases) == 0 {
		t.Fatalf("%s: no restArgumentForms switch cases found; the census source is broken", src)
	}
	return cases
}

// TestEveryRESTRouteInputIsReconstructedOrNamedAbsent17184: every
// route in restRouteCommand is decided exactly once — a
// restArgumentForms case (reconstructs) xor a
// restRoutesWithoutArgumentForms entry with a reason. Both stale
// directions fail.
//
// Request-decoded routes are covered in the second arm: every
// restRoutesNoCommand entry classified by isRequestDecodedRoute9952
// must (a) NOT also carry a fixed restRouteCommand charge, and
// (b) NOT be named in restRoutesWithoutArgumentForms (that map is
// for fixed-charge routes only; naming a request-decoded route
// there would re-open the Rev18237 B1 bare-charge confusion).
// Per-request resolution via restRequestCommand9952 is NOT checked
// here — this arm never calls the resolver; that behavior is
// covered end-to-end by the #15076/Fold cells
// (TestBGPRoutesAndNATSelectorsChargedPerRequest15076 and
// TestArgumentFormsFold17184's B1 controls). Conversely every route
// restArgumentForms answers via its pre-switch request-decoded
// bypass must be one of these — the bypass is keyed on
// isRequestDecodedRoute9952, so that set IS the bypass set.
func TestEveryRESTRouteInputIsReconstructedOrNamedAbsent17184(t *testing.T) {
	if len(restRouteCommand) == 0 {
		t.Fatal("restRouteCommand is empty; the census would certify nothing")
	}
	cases := restArgumentFormsCases17184(t)
	for route := range restRouteCommand {
		_, inCases := cases[route]
		reason, named := restRoutesWithoutArgumentForms[route]
		switch {
		case inCases && named:
			t.Errorf("%s is BOTH a restArgumentForms case and named absent; one decision must win", route)
		case !inCases && !named:
			t.Errorf("%s is charged but decided nowhere: add a restArgumentForms arm reconstructing its argument text, or name it in restRoutesWithoutArgumentForms with why (#17184)", route)
		case named && strings.TrimSpace(reason) == "":
			t.Errorf("%s is named absent with an empty reason", route)
		}
	}
	for route := range restRoutesWithoutArgumentForms {
		if _, ok := restRouteCommand[route]; !ok {
			t.Errorf("restRoutesWithoutArgumentForms names %q, which restRouteCommand does not charge — stale entry", route)
		}
		if isRequestDecodedRoute9952(route) {
			t.Errorf("restRoutesWithoutArgumentForms names request-decoded route %q; request-decoded routes take the pre-switch bare-charge bypass (Rev18237 B1), not the named-absent map", route)
		}
	}
	// Request-decoded arm: every restRoutesNoCommand route that
	// isRequestDecodedRoute9952 claims must be request-decoded in
	// fact (declared there, no fixed charge), and every route the
	// predicate claims must be declared — both stale directions.
	decodedCount := 0
	for route, reason := range restRoutesNoCommand {
		if !isRequestDecodedRoute9952(route) {
			continue
		}
		decodedCount++
		if strings.TrimSpace(reason) == "" {
			t.Errorf("request-decoded route %s declared in restRoutesNoCommand with an empty reason", route)
		}
		if _, charged := restRouteCommand[route]; charged {
			t.Errorf("request-decoded route %s also has a fixed restRouteCommand charge; its command must come only from restRequestCommand9952", route)
		}
		if _, named := restRoutesWithoutArgumentForms[route]; named {
			t.Errorf("request-decoded route %s is also named in restRoutesWithoutArgumentForms; one decision must win", route)
		}
		if _, inCases := cases[route]; inCases && route != "GET /api/v1/show-text" {
			// show-text is the one request-decoded route with an
			// outer-switch arm (packed parameters reconstruct
			// there); any other request-decoded outer case would
			// be dead behind the pre-switch bypass.
			t.Errorf("request-decoded route %s has a restArgumentForms switch case that the pre-switch bypass makes unreachable (only show-text reconstructs in the switch)", route)
		}
	}
	if decodedCount == 0 {
		t.Fatal("no request-decoded routes found in restRoutesNoCommand; the census arm would certify nothing")
	}
	// Reverse direction: the predicate must not claim a route that
	// restRoutesNoCommand does not declare request-decoded.
	for _, route := range []string{
		"GET /api/v1/show-text",
		"POST /api/v1/system/action",
		"GET /api/v1/system/info",
		"GET /api/v1/routing/bgp",
		"GET /api/v1/security/nat/rules",
	} {
		if !isRequestDecodedRoute9952(route) {
			t.Errorf("%s is a known request-decoded route but isRequestDecodedRoute9952 does not claim it; the census is stale", route)
		}
		if _, declared := restRoutesNoCommand[route]; !declared {
			t.Errorf("request-decoded route %s is not declared in restRoutesNoCommand; the census declaration is stale", route)
		}
	}
}

// Events filters execute `show security log ...` (the eventsHandler
// twin of GetEvents); they must be judged as that line.
func TestRESTEventsFilters17184(t *testing.T) {
	zonePath := "/api/v1/security/events?zone=" + uitoa(uint(config.StableZoneID("trust")))
	for _, tc := range []struct {
		name, pattern, path string
		wantDeny            bool
	}{
		{"events zone denied", `^show security log zone trust$`, zonePath, true},
		{"events protocol denied", `^show security log protocol tcp$`, "/api/v1/security/events?protocol=tcp", true},
		{"events unfiltered allowed", `^show security log zone trust$`, "/api/v1/security/events", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern)
			err := call9952(t, cfg, "limited", "GET", tc.path, "")
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over GET %s was ALLOWED on REST (#17184)", tc.pattern, tc.path)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over GET %s refused a command it does not name: %v", tc.pattern, tc.path, err)
			}
		})
	}
}
