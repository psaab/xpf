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
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			found = true
			for _, stmt := range sw.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
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
			return false
		})
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
// directions fail. Request-decoded routes (restRoutesNoCommand) are
// classified there by restRequestCommand9952 and never reach
// restArgumentForms' charged-route switch.
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
