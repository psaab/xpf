package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #9890: A CENSUS OVER THE REGISTERED CONFIG ROUTES, BECAUSE THE HAND-MAINTAINED
// LIST IS WHAT FAILED.
//
// `restConfigMutationRoutes` gated `set` and `delete`. `deactivate`, `activate`
// and `annotate` were registered POST routes that mutate the candidate BY PATH
// and were in neither the gate nor any statement of why they did not need to
// be. Nothing reported that: the gate returned "not gated" and the request
// proceeded, which is indistinguishable from an adjudicated one.
//
// So the remedy is not a longer list. It is this: every registered
// `POST /api/v1/config/*` route must appear in `restConfigMutationRoutes` (it
// is adjudicated) or in `restConfigRoutesUngated` with a REASON (someone
// decided it cannot carry a denied path). A route in neither fails here, by
// name, on the first run after it is added.
//
// The census reads server.go's registrations rather than a second copy of the
// route list, because a census that consults its own list of what exists cannot
// discover anything.

var muxConfigPostRoute = regexp.MustCompile(`mux\.HandleFunc\("(POST /api/v1/config/[^"]+)"`)

func registeredConfigPostRoutes9890(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("reading server.go: %v", err)
	}
	var out []string
	for _, m := range muxConfigPostRoute.FindAllStringSubmatch(string(src), -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

func TestEveryConfigPostRouteIsGatedOrDeclared9890(t *testing.T) {
	routes := registeredConfigPostRoutes9890(t)

	// EMPTY-SWEEP GUARD. A census that discovers nothing reports a clean board,
	// which is the failure mode it exists to prevent. If the registration
	// spelling in server.go changes, this trips instead of going quiet.
	if len(routes) < 5 {
		t.Fatalf("the census found only %d POST config routes (%v) — the matcher is broken, "+
			"not the router; a census that sweeps an empty set reports a clean board", len(routes), routes)
	}

	for _, route := range routes {
		_, gated := restConfigMutationRoutes[route]
		reason, declared := restConfigRoutesUngated[route]
		switch {
		case gated && declared:
			t.Errorf("%s is BOTH gated and declared ungated — the two tables disagree about "+
				"whether it is adjudicated, and a reader cannot tell which is true", route)
		case gated:
		case declared:
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is declared ungated with an EMPTY reason — the reason is the whole "+
					"artifact here; it is the claim that the route cannot carry a denied path", route)
			}
		default:
			t.Errorf("%s is registered but appears in NEITHER restConfigMutationRoutes nor "+
				"restConfigRoutesUngated (#9890). If it mutates the candidate by path, gate it; "+
				"if it cannot carry a denied path, say so in restConfigRoutesUngated. A route in "+
				"neither is not 'allowed' — it is unexamined, which is how deactivate, activate "+
				"and annotate went ungated.", route)
		}
	}
}

// POSITIVE CONTROL. Without it, a census whose lookup is inverted or whose
// tables are empty reports a clean board over a world where nothing is gated.
func TestConfigRouteCensusSeesAKnownGatedRoute9890(t *testing.T) {
	routes := registeredConfigPostRoutes9890(t)
	var found bool
	for _, r := range routes {
		if r == "POST /api/v1/config/set" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the census did not discover POST /api/v1/config/set, which server.go registers — "+
			"the matcher is broken; every other verdict in this file is then vacuous. Got: %v", routes)
	}
	if _, gated := restConfigMutationRoutes["POST /api/v1/config/set"]; !gated {
		t.Fatal("POST /api/v1/config/set is not in restConfigMutationRoutes — the control route " +
			"for this gate is ungated, so a passing census above means nothing")
	}
	if _, declared := restConfigRoutesUngated["POST /api/v1/config/set"]; declared {
		t.Fatal("POST /api/v1/config/set is declared UNGATED — the control may never be exempted")
	}
}

// The three routes #9890 was about, pinned by name. The census above would
// catch their removal from both tables; this catches them being MOVED into the
// exemption list, which is the cheaper way to make a failing census green.
func TestTheThreeVerbsThatBypassedAreGated9890(t *testing.T) {
	for route, wantVerb := range map[string]string{
		"POST /api/v1/config/deactivate": "deactivate",
		"POST /api/v1/config/activate":   "activate",
		"POST /api/v1/config/annotate":   "annotate",
	} {
		got, gated := restConfigMutationRoutes[route]
		if !gated {
			t.Errorf("%s is not gated (#9890). A regex-restricted principal denied `set <path>` "+
				"reaches the same subtree with this verb; for deactivate that REMOVES the denied "+
				"subtree's enforcement, because an inactive node is excluded from compilation", route)
			continue
		}
		if got.verb != wantVerb {
			t.Errorf("%s is gated as verb %q, want %q — the regexes are evaluated against a "+
				"verb-led line, so the wrong verb adjudicates a line the store never applies",
				route, got.verb, wantVerb)
		}
	}
	// annotate's path arrives in `path`, not `input`. A gate reading `input`
	// would find it empty and allow the request while looking adjudicated —
	// the same silence, one layer in.
	if got := restConfigMutationRoutes["POST /api/v1/config/annotate"]; got.field != pathFromPath {
		t.Errorf("annotate is gated on the `input` field, but its handler reads `path` " +
			"(AnnotateRequest.Path) — the gate would adjudicate an empty string and allow everything")
	}
}
