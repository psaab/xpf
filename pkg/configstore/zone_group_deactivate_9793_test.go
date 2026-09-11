package configstore

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestDeactivateOneZoneOfAGroupIsRefused9793 is #9793's acceptance cell
// through the Store. `deactivate security zones security-zone zga` against a
// `security-zone [ zga zgb ]` group used to report no error and mark the whole
// grouped statement inactive, so BOTH zones left the compiled candidate. It
// must be refused and change nothing; the grouped spelling, which is what
// `show | display set` emits, must still deactivate the statement.
func TestDeactivateOneZoneOfAGroupIsRefused9793(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	if err := s.LoadOverride("security { zones { security-zone [ zga zgb ] { tcp-rst; } } }\n"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	zones := func() []string {
		t.Helper()
		cfg, err := s.CompileCandidate()
		if err != nil {
			t.Fatalf("CompileCandidate: %v", err)
		}
		names := make([]string, 0, len(cfg.Security.Zones))
		for name := range cfg.Security.Zones {
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}
	both := []string{"zga", "zgb"}
	if got := zones(); !reflect.DeepEqual(got, both) {
		t.Fatalf("CONTROL BROKE: want compiled zones %v before any edit, got %v", both, got)
	}

	// The first member is the address that marked the whole statement. A
	// later member never matched the node at all, so it already failed with
	// the walk's "no node matching" and changed nothing; that stays an error,
	// and this cell only requires that it change nothing either.
	for _, tc := range []struct{ line, want string }{
		{"security zones security-zone zga", "#9793"},
		{"security zones security-zone zgb", ""},
	} {
		err := s.DeactivateFromInput(tc.line)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("deactivate %s: want an error containing %q, got %v", tc.line, tc.want, err)
		}
		if got := zones(); !reflect.DeepEqual(got, both) {
			t.Fatalf("a refused deactivate %s changed the compiled zones to %v", tc.line, got)
		}
	}
	if out := s.ShowCandidateSet(); strings.Contains(out, "deactivate ") {
		t.Fatalf("a refused deactivate left an inactive marker:\n%s", out)
	}

	if err := s.DeactivateFromInput("security zones security-zone [ zga zgb ]"); err != nil {
		t.Fatalf("CONTROL BROKE: the grouped spelling must deactivate the whole statement: %v", err)
	}
	if got := zones(); len(got) != 0 {
		t.Fatalf("the grouped deactivate must remove both zones from the compiled candidate, got %v", got)
	}
}
