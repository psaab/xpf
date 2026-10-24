package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #16067: argument-scoped deny-commands patterns must fire on REST too.

func cfg16067(t *testing.T, deny string) *config.Config {
	t.Helper()
	text := `
system {
    host-name authz-16067;
    login {
        class limited {
            permissions [ view clear maintenance ];
            deny-commands "` + deny + `";
        }
        user opsuser { class limited; }
    }
    security { zones { security-zone trust; security-zone secret-zone; } }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile: %v", err)
	}
	if _, ok, err := config.OperationalLoginRegexesFor(cfg, "limited"); err != nil || !ok {
		t.Fatalf("fixture premise: limited must carry operational regexes (ok=%v err=%v)", ok, err)
	}
	return cfg
}

func TestArgumentScopedDenyFiresOnREST16067(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, method, path, body string
		wantDeny                          bool
	}{
		{"show-text route table denied", `^show route table secret-vrf$`, "GET", "/api/v1/show-text?topic=route-table:secret-vrf", "", true},
		{"show-text route table allowed", `^show route table secret-vrf$`, "GET", "/api/v1/show-text?topic=route-table:public-vrf", "", false},
		{"show-text log denied", `^show log .*`, "GET", "/api/v1/show-text?topic=log:messages", "", true},
		{"ping target denied", `^ping 10\.99\.`, "POST", "/api/v1/diagnostics/ping", `{"target":"10.99.1.1"}`, true},
		{"ping target allowed", `^ping 10\.99\.`, "POST", "/api/v1/diagnostics/ping", `{"target":"10.98.1.1"}`, false},
		{"traceroute denied", `^traceroute 10\.99\.`, "POST", "/api/v1/diagnostics/traceroute", `{"target":"10.99.1.1"}`, true},
		{"match zones denied", `^show security match-policies from-zone trust to-zone secret-zone$`, "GET", "/api/v1/security/match?from_zone=trust&to_zone=secret-zone", "", true},
		{"interfaces filter denied", `^show interfaces detail ge-0/0/9$`, "GET", "/api/v1/interfaces/detail?filter=ge-0/0/9", "", true},
		{"session zone denied", `^show security flow session zone `, "GET", "/api/v1/security/sessions?zone=PLACEHOLDER", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if tc.name == "session zone denied" {
				// Zone travels as its StableZoneID on this surface.
				id := config.StableZoneID("trust")
				path = "/api/v1/security/sessions?zone=" + uitoa(uint(id))
				tc.pattern = `^show security flow session zone trust$`
			}
			cfg := cfg16067(t, tc.pattern)
			err := call9952(t, cfg, "limited", tc.method, path, tc.body)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over %s %s was ALLOWED on REST; argument-scoped denies must fire remotely (#16067)", tc.pattern, tc.method, path)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over %s %s refused a command it does not name: %v", tc.pattern, tc.method, path, err)
			}
		})
	}
}

func uitoa(v uint) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

var _ = authz.Principal{}

// #16378 fold: the summary routes execute no selectors, so a selector
// must neither deny them (via a selector-scoped deny) nor admit them
// (via a selector-scoped allow exception borrowing).
func TestRESTSummariesIgnoreSelectors16067(t *testing.T) {
	zoneID := uitoa(uint(config.StableZoneID("trust")))
	for _, route := range []string{"/api/v1/security/sessions/summary", "/api/v1/security/sessions/summary/zone-pairs"} {
		// A deny written against the filtered LIST command must not
		// refuse the unfiltered summary the handler actually runs.
		cfg := cfg16067(t, `^show security flow session zone trust$`)
		if err := call9952(t, cfg, "limited", "GET", route+"?zone="+zoneID, ""); err != nil {
			t.Errorf("GET %s?zone=%s denied by a list-selector deny the summary never executes: %v", route, zoneID, err)
		}
		// A deny written against the summary itself still fires, with
		// any selector text present.
		cfg = cfg16067(t, `^show security flow session summary$`)
		if err := call9952(t, cfg, "limited", "GET", route+"?zone="+zoneID, ""); err == nil {
			t.Errorf("GET %s?zone=%s allowed under a summary deny; the summary charge must still fire", route, zoneID)
		}
	}
}

// Boolean spellings: nat_only and non_first_fragment are parsed by the
// handlers with strconv.ParseBool, so =1 / =t / =TRUE execute the
// filtered command and must be judged as it (#16378 fold).
func TestRESTBooleanSpellings16067(t *testing.T) {
	for _, spelling := range []string{"1", "t", "TRUE", "True"} {
		cfg := cfg16067(t, `^show security flow session nat-only$`)
		// "show security flow session nat-only" is charged via the
		// reconstructed list command; use an anchored selector deny:
		cfg = cfg16067(t, `nat-only`)
		if err := call9952(t, cfg, "limited", "GET", "/api/v1/security/sessions?nat_only="+spelling, ""); err == nil {
			t.Errorf("sessions?nat_only=%s allowed; ParseBool spellings must carry nat-only into the judged command", spelling)
		}
		cfg = cfg16067(t, `non-first-fragment`)
		if err := call9952(t, cfg, "limited", "GET", "/api/v1/security/match?from_zone=trust&to_zone=secret-zone&non_first_fragment="+spelling, ""); err == nil {
			t.Errorf("match?non_first_fragment=%s allowed; ParseBool spellings must carry the fragment selector", spelling)
		}
	}
	// nat_only=false executes the unfiltered list and stays allowed
	// under a nat-only deny.
	cfg := cfg16067(t, `nat-only`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/security/sessions?nat_only=false", ""); err != nil {
		t.Errorf("nat_only=false must not be judged as nat-only: %v", err)
	}
	// A malformed boolean is unnameable: the handler 400s, and the gate
	// denies for a restricted class rather than judging the bare list.
	cfg = cfg16067(t, `^show version$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/security/sessions?nat_only=bogus", ""); err == nil {
		t.Error("nat_only=bogus allowed for a restricted class; a malformed boolean must deny")
	}
}

// Filtered interface detail (including terse spellings the handler
// still filters on) must be judged as the filtered command (#16378 fold).
func TestRESTFilteredInterfacesDetail16067(t *testing.T) {
	for _, path := range []string{
		"/api/v1/interfaces/detail?filter=ge-0/0/9",
		"/api/v1/interfaces/detail?filter=ge-0/0/9&terse=true",
		"/api/v1/interfaces/detail?filter=ge-0/0/9&terse=1",
	} {
		cfg := cfg16067(t, `^show interfaces detail ge-0/0/9$`)
		if err := call9952(t, cfg, "limited", "GET", path, ""); err == nil {
			t.Errorf("GET %s allowed under a filtered-detail deny; the filter must be judged", path)
		}
	}
}
