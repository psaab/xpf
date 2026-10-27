package cmdtree

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRouteProtocolCompletionEqualsSSOT17029 proves the `show route
// protocol` completion is derived from the route-protocol SSOT (#17029):
// it offers exactly the canonical Internal tokens (config.RouteProtocolNames)
// — including dhcp and redirect, which the old hand-maintained list omitted —
// and none of the accept-only aliases (direct/local/kernel, access-internal,
// is-is, access_internal, "access internal"), which NormalizeRouteProtocol
// still accepts. RED on revert: restoring the literal completion list
// reintroduces the missing dhcp/redirect tokens and the alias tokens.
func TestRouteProtocolCompletionEqualsSSOT17029(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "protocol"}, "", nil)
	want := config.RouteProtocolNames()
	if !slices.Equal(cands, want) {
		t.Fatalf("show route protocol completion = %v, want SSOT canonical tokens %v", cands, want)
	}
	for _, token := range []string{"dhcp", "redirect", "connected", "isis"} {
		if !contains(cands, token) {
			t.Errorf("completion missing canonical token %q: %v", token, cands)
		}
	}
	for _, alias := range []string{"direct", "local", "kernel", "access-internal", "access_internal", "access internal", "is-is"} {
		if contains(cands, alias) {
			t.Errorf("completion offers accept-only alias %q: %v", alias, cands)
		}
	}
}
