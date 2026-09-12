package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// #9952: A CENSUS OVER THE REGISTERED ROUTES, plus a resolver check over the
// commands they are charged.
//
// The defect was not a wrong table — it was NO table, and nothing reported that.
// A longer hand-maintained list is the same defect one entry later, so the
// remedy is the #9890 shape: every registered route must appear in
// `restRouteCommand` (it is charged a command) or in `restRoutesNoCommand` with
// a REASON (someone decided it has none). A route in neither fails here, by
// name, on the first run after it is added.
//
// The census reads server.go's registrations rather than a second copy of the
// route list, because a census that consults its own list of what exists cannot
// discover anything.

var muxAnyRoute9952 = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+ [^"]+)"`)

func registeredRoutes9952(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("reading server.go: %v", err)
	}
	var out []string
	for _, m := range muxAnyRoute9952.FindAllStringSubmatch(string(src), -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

func TestEveryRESTRouteIsChargedOrDeclared9952(t *testing.T) {
	routes := registeredRoutes9952(t)

	// EMPTY-SWEEP GUARD. A census that discovers nothing reports a clean board,
	// which is the failure mode it exists to prevent. If the registration
	// spelling in server.go changes, this trips instead of going quiet.
	if len(routes) < 40 {
		t.Fatalf("the census found only %d registered routes — the matcher is broken, not the "+
			"router; a census that sweeps an empty set reports a clean board", len(routes))
	}

	for _, route := range routes {
		_, charged := restRouteCommand[route]
		reason, declared := restRoutesNoCommand[route]
		switch {
		case charged && declared:
			t.Errorf("route %q is BOTH charged a command and declared as having none. "+
				"That is a disagreement about whether it is adjudicated, and a reader "+
				"cannot tell which is true.", route)
		case !charged && !declared:
			t.Errorf("route %q is registered in server.go and appears in NEITHER "+
				"restRouteCommand nor restRoutesNoCommand (#9952). At runtime it DENIES "+
				"for any class with operational regexes, which is safe and is not a "+
				"decision — charge it the command it performs, or declare why it has none.", route)
		case declared && strings.TrimSpace(reason) == "":
			t.Errorf("route %q is declared in restRoutesNoCommand with an EMPTY reason. "+
				"The reason is the whole value of the table: without it the entry is "+
				"indistinguishable from the omission this census exists to catch.", route)
		}
	}

	// The reverse direction: a table entry for a route that is no longer
	// registered is a stale exemption, and a stale exemption is an allowlist
	// covering a route somebody may re-add under a different handler.
	live := map[string]bool{}
	for _, r := range routes {
		live[r] = true
	}
	for _, table := range []map[string]string{restRouteCommand, restRoutesNoCommand} {
		for route := range table {
			if !live[route] {
				t.Errorf("route %q has a table entry but is NOT registered in server.go — "+
					"a stale entry silently covers whatever is registered under that "+
					"spelling next", route)
			}
		}
	}
}

// TestEveryRESTRouteCommandResolves9952 holds this table to the same rule the
// gRPC table has been held to since #7172.
//
// A deny regex is matched against these strings, so an entry that does not
// resolve against the operational tree means the gate compares against a command
// no operator can run — a gate that cannot deny anything an operator would
// actually be told to stop doing, while looking like one that can.
func TestEveryRESTRouteCommandResolves9952(t *testing.T) {
	if len(restRouteCommand) == 0 {
		t.Fatal("restRouteCommand is empty, so this test would certify nothing")
	}
	keys := make([]string, 0, len(restRouteCommand))
	for k := range restRouteCommand {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, route := range keys {
		cmd := restRouteCommand[route]
		words := strings.Fields(cmd)
		if len(words) == 0 {
			t.Errorf("route %q maps to an empty command", route)
			continue
		}
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
		if res != cmdtree.CanonicalOK {
			t.Errorf("route %q maps to %q, which does not resolve against the operational "+
				"tree (%v)", route, cmd, res)
			continue
		}
		if got := strings.Join(canon, " "); got != cmd {
			t.Errorf("route %q maps to %q, which canonicalizes to %q. The table must hold "+
				"the CANONICAL spelling.", route, cmd, got)
		}
	}
}

// TestRESTAndGRPCChargeTheSameCommandForSharedData9952 is the anti-drift cell.
//
// Two surfaces serving the same data must charge the same command, or an
// operator's single `deny-commands` line means two different things depending on
// which port they are on. The pairs below are the ones where a gRPC method and a
// REST route serve the same handler output; the assertion is on the STRING, not
// on a shared constant, because the tables are separate by design and the point
// is to notice when they stop agreeing.
func TestRESTAndGRPCChargeTheSameCommandForSharedData9952(t *testing.T) {
	for route, want := range map[string]string{
		"GET /api/v1/security/sessions":        "show security flow session",
		"GET /api/v1/security/policies":        "show security policies",
		"GET /api/v1/security/zones":           "show security zones",
		"GET /api/v1/routes":                   "show route",
		"GET /api/v1/interfaces":               "show interfaces",
		"POST /api/v1/security/sessions/clear": "clear security flow session",
	} {
		if got := restRouteCommand[route]; got != want {
			t.Errorf("REST charges %q for %q; gRPC charges %q for the same data. One "+
				"`deny-commands` line would mean two different things depending on the "+
				"port the operator is on.", got, route, want)
		}
	}
}
