package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #9952 behavioural cells. The census beside this file proves every route is
// CLASSIFIED; these prove the classification is OBEYED. A census of tables
// answers "is every route accounted for", never "does a denial deny" — and on
// this surface nothing was asking the second question at all.

const commandClassConfig9952 = `
system {
    host-name authz-9952;
    login {
        class limited {
            permissions [ view clear maintenance ];
            deny-commands "request system reboot|show security flow session|clear security flow session";
        }
        class wideopen {
            permissions [ view clear maintenance ];
        }
    }
}
`

func cmdCfg9952(t *testing.T) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(commandClassConfig9952).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse, so every cell below is vacuous: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile, so every cell below is vacuous: %v", err)
	}
	// PREMISE, asserted rather than assumed: `limited` must actually carry
	// operational regexes and `wideopen` must not, or the refusals below would
	// be vacuous and the control meaningless.
	if _, ok, err := config.OperationalLoginRegexesFor(cfg, "limited"); err != nil || !ok {
		t.Fatalf("fixture class `limited` has no operational regexes (ok=%v err=%v)", ok, err)
	}
	if _, ok, _ := config.OperationalLoginRegexesFor(cfg, "wideopen"); ok {
		t.Fatal("fixture class `wideopen` HAS operational regexes; it is the control and must have none")
	}
	return cfg
}

func call9952(t *testing.T, cfg *config.Config, class, method, path, body string) error {
	t.Helper()
	var r = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	s := &Server{}
	return s.authorizeRESTCommand(r, cfg, authz.Principal{Class: class})
}

// TestDeniedCommandIsRefusedOnREST9952 is the defect itself: before this change
// the class's `deny-commands` had no enforcement point in pkg/api at all.
func TestDeniedCommandIsRefusedOnREST9952(t *testing.T) {
	cfg := cmdCfg9952(t)
	for name, tc := range map[string]struct{ method, path, body string }{
		"read route":    {"GET", "/api/v1/security/sessions", ""},
		"clear route":   {"POST", "/api/v1/security/sessions/clear", `{}`},
		"system action": {"POST", "/api/v1/system/action", `{"action":"reboot"}`},
	} {
		t.Run(name, func(t *testing.T) {
			err := call9952(t, cfg, "limited", tc.method, tc.path, tc.body)
			if err == nil {
				t.Fatalf("%s %s was ALLOWED for a class whose deny-commands covers it (#9952)", tc.method, tc.path)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("refusal does not read as an authorization denial: %v", err)
			}
		})
	}
}

// POSITIVE CONTROL, and it is not optional: without it every refusal above
// could be a gate that refuses everything, and the regex would be untested.
func TestAllowedCommandStillWorksOnREST9952(t *testing.T) {
	cfg := cmdCfg9952(t)
	for name, tc := range map[string]struct{ method, path, body string }{
		"read route not matched by the deny": {"GET", "/api/v1/security/zones", ""},
		"clear route not matched":            {"POST", "/api/v1/security/counters/clear", `{}`},
		"system action not matched":          {"POST", "/api/v1/system/action", `{"action":"clear-arp"}`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call9952(t, cfg, "limited", tc.method, tc.path, tc.body); err != nil {
				t.Fatalf("%s %s was refused for a class whose deny-commands does NOT cover it: %v", tc.method, tc.path, err)
			}
		})
	}
}

// NARROWNESS CONTROL in the other direction: a class with no operational
// regexes must be completely unaffected. Over-denial locks a legitimate
// operator out, which is a different outage rather than a fix — and it is the
// regression this gate is most likely to cause, because it now runs on every
// REST request.
func TestAClassWithNoCommandRegexesIsUnaffected9952(t *testing.T) {
	cfg := cmdCfg9952(t)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/security/sessions", ""},
		{"POST", "/api/v1/security/sessions/clear", `{}`},
		{"POST", "/api/v1/system/action", `{"action":"reboot"}`},
		{"GET", "/health", ""},
		{"POST", "/api/v1/config/set", `{"input":"system host-name x"}`},
		// THE DISCRIMINATING ROW. Every other entry here is a route that is
		// mapped or declared, so a gate that wrongly ran for a class with no
		// regexes would still allow them — an empty ruleset evaluates as
		// "allowed", so the ruleset itself cannot separate the arms. Only an
		// UNMAPPED route can: it is the one place where running the gate at all
		// produces a denial. Mutant Q6 was killed by an unrelated test until
		// this row existed.
		{"GET", "/api/v1/does-not-exist", ""},
	} {
		if err := call9952(t, cfg, "wideopen", tc.method, tc.path, tc.body); err != nil {
			t.Errorf("%s %s refused for a class with NO operational regexes: %v", tc.method, tc.path, err)
		}
	}
	// And the empty class (no class at all) is the same.
	if err := call9952(t, cfg, "", "POST", "/api/v1/system/action", `{"action":"reboot"}`); err != nil {
		t.Errorf("a principal with no class was refused: %v", err)
	}
}

// TestConfigModeRoutesAreNotChargedACommand9952 guards the #9633 regression on
// this surface before it can happen.
//
// Charging a config-mode route an operational command would lock ANY class with
// an operational pattern out of configuration over REST — which is exactly the
// lockout #9633 fixed on gRPC, and it would be introduced here by a table entry
// that looks like diligence.
func TestConfigModeRoutesAreNotChargedACommand9952(t *testing.T) {
	cfg := cmdCfg9952(t)
	for _, path := range []string{
		"/api/v1/config/set", "/api/v1/config/delete", "/api/v1/config/load",
		"/api/v1/config/commit", "/api/v1/config/rollback", "/api/v1/config/enter",
	} {
		if err := call9952(t, cfg, "limited", "POST", path, `{}`); err != nil {
			t.Errorf("POST %s was refused by the COMMAND gate; config-mode routes are governed "+
				"by the *-configuration regexes and charging them here locks a class with any "+
				"operational pattern out of configuration (#9633): %v", path, err)
		}
	}
}

// TestAPrefixFormVerbDenies9952 is the trap the gRPC gate documents, carried
// over because it is the one a reader is most likely to assume is handled.
//
// `cluster-failover:1:node0` and the `userspace-*` dataplane control forms are
// parsed out of a packed string by the handler's DEFAULT branch, so they have no
// case label, cannot appear in the verb table, and cannot be added to it. A
// table that looks complete is a floor over what the handler DISPATCHES, not a
// census of what it ACCEPTS. They must deny by the unmapped rule.
func TestAPrefixFormVerbDenies9952(t *testing.T) {
	cfg := cmdCfg9952(t)
	for _, verb := range []string{"cluster-failover:1:node0", "userspace-dp-restart", "not-a-verb"} {
		err := call9952(t, cfg, "limited", "POST", "/api/v1/system/action", `{"action":"`+verb+`"}`)
		if err == nil {
			t.Errorf("verb %q was ALLOWED with no canonical command; treating \"cannot resolve\" as "+
				"\"no match, allow\" is the bypass the table exists to close", verb)
		}
	}
}

// TestAnUnmappedRouteDenies9952 pins the runtime half of the census.
//
// The census makes an unclassified route a build failure. This makes it a
// DENIAL, because a census is a build-time guard and this is the request path:
// a route added on a branch that never ran the census must still fail closed.
func TestAnUnmappedRouteDenies9952(t *testing.T) {
	cfg := cmdCfg9952(t)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/does-not-exist", ""); err == nil {
		t.Fatal("an unmapped route was ALLOWED for a restricted class; an unclassified route must fail closed")
	}
}

// ── THE WIRING, NOT THE EVALUATOR ───────────────────────────────────────────
//
// Every cell above calls authorizeRESTCommand DIRECTLY. The mutation matrix
// showed what that cannot see: mutants that UNWIRE the gate from the read path
// and from the mutation path — leaving the function intact and simply never
// consulting its verdict — passed all of them.
//
// That is the same escape #9892 found one package over, and it is worth stating
// as a rule rather than a fix: a test that calls the gate proves the gate
// decides; only a test that goes through the SERVER proves the decision is
// obeyed. Both cells below drive the real middleware.

const commandWiringConfig9952 = `
system {
    host-name authz-9952-wiring;
    login {
        class limited {
            permissions [ view clear maintenance ];
            deny-commands "show security flow session|clear security flow session";
        }
        user opsuser {
            class limited;
        }
    }
}
`

func wiringServer9952(t *testing.T) *Server {
	t.Helper()
	usePasswdFixture(t)
	store := authzStore(t, commandWiringConfig9952)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242), // opsuser -> class limited
	})
	// PREMISE: the class must actually resolve with operational regexes through
	// the STORE the server reads, not through a config this test compiled on the
	// side. Otherwise the 403 below could come from anywhere.
	if _, ok, err := config.OperationalLoginRegexesFor(store.ActiveConfig(), "limited"); err != nil || !ok {
		t.Fatalf("the server's active config has no operational regexes for `limited` (ok=%v err=%v); "+
			"this cell would prove nothing", ok, err)
	}
	return s
}

// TestTheREADPathConsultsTheCommandGate9952 is the cell mutant Q1 escaped.
func TestTheREADPathConsultsTheCommandGate9952(t *testing.T) {
	s := wiringServer9952(t)

	denied := runGuardedConfigRead9324(t, s, "/api/v1/security/sessions")
	if denied.Code != 403 {
		t.Fatalf("GET /api/v1/security/sessions -> %d, want 403: the READ path does not consult "+
			"the command gate, so `deny-commands` is computed and ignored (#9952). body=%s",
			denied.Code, denied.Body.String())
	}

	// REFERENCE ARM, in the same run and through the same middleware: a read the
	// class's regex does NOT cover must still be served. Without it a 403 above
	// is equally consistent with a guard that refuses this principal everything.
	allowed := runGuardedConfigRead9324(t, s, "/api/v1/security/zones")
	if allowed.Code != 200 {
		t.Fatalf("GET /api/v1/security/zones -> %d, want 200: a command the regex does not "+
			"match must still be served. body=%s", allowed.Code, allowed.Body.String())
	}
}

// TestTheMUTATION_PathConsultsTheCommandGate9952 is the cell mutant Q2 escaped.
//
// It runs against the real listener rather than the guard function, because the
// mutating leg's ordering — buffer the body, re-authorize, then the three regex
// gates — is exactly what the mutant removes one line from.
func TestTheMUTATION_PathConsultsTheCommandGate9952(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, commandWiringConfig9952)
	_, base := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
	})

	post := func(path, body string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := post("/api/v1/security/sessions/clear", `{}`); code != 403 {
		t.Fatalf("POST /api/v1/security/sessions/clear -> %d, want 403: the MUTATION path does "+
			"not consult the command gate (#9952)", code)
	}
	// REFERENCE ARM: a clear the regex does not match must not be refused by the
	// command gate. It may still fail for an unrelated reason, so the assertion
	// is that it is NOT 403.
	if code := post("/api/v1/security/counters/clear", `{}`); code == 403 {
		t.Fatal("POST /api/v1/security/counters/clear -> 403: a command the regex does not match " +
			"was refused, which is over-denial rather than enforcement")
	}
}
