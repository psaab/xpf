package config

import (
	"strings"
	"testing"
)

// #16638: subsystem-read tokens (network, trace, snmp, interface, rollback)
// are granted the full PermView bucket, which is WIDER than the Junos token
// — PermView admits the whole non-secret configuration and the live session
// table. The old advisory called this "folded to view-only", i.e. folded
// DOWN, and the operator contract claimed the mapping "never grants more
// than the Junos token permits". The mapping itself is deliberate and
// pinned by test 4304; what these tests pin is that the commit advisory
// (and the widened-token list behind it) now states the widening, rollback
// included, and that no precise token is reported as widened.

func advisoryFor16638(t *testing.T, class, perms string) string {
	t.Helper()
	tree := buildTree4303(t, []string{
		"set system login class " + class + " permissions " + perms,
		"set system login user u-" + class + " class " + class,
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile class %q permissions %s: %v", class, perms, err)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, `system login class "`+class+`"`) && strings.Contains(w, "recognized (custom RBAC)") {
			return w
		}
	}
	t.Fatalf("no login-class advisory for %q; warnings=%v", class, c.Warnings)
	return ""
}

func TestLoginClassAdvisoryStatesWidening16638(t *testing.T) {
	for _, tok := range []string{"network", "trace", "snmp", "interface", "rollback"} {
		t.Run(tok, func(t *testing.T) {
			w := advisoryFor16638(t, "noc-"+tok, tok)
			if !strings.Contains(w, "granted full view (wider than Junos "+tok+")") {
				t.Errorf("advisory for permissions %s must state the widening; got: %s", tok, w)
			}
			if strings.Contains(w, "folded to view-only") {
				t.Errorf("advisory for permissions %s still claims a fold down; got: %s", tok, w)
			}
		})
	}
}

// A class mixing a widened token with a precise one names only the widened
// token, and a purely precise class carries no widening claim at all —
// otherwise the advisory cries wolf on classes that did not widen.
func TestLoginClassAdvisoryWideningScope16638(t *testing.T) {
	w := advisoryFor16638(t, "mixedview", "[ view clear network ]")
	if !strings.Contains(w, "permissions [network] granted full view (wider than Junos network)") {
		t.Errorf("mixed class must name only the widened token; got: %s", w)
	}
	for _, cls := range []struct{ name, perms string }{
		{"preciseview", "view"},
		{"precisecfg", "configure"},
		{"preciseall", "all"},
	} {
		w := advisoryFor16638(t, cls.name, cls.perms)
		if strings.Contains(w, "wider than Junos") {
			t.Errorf("class %s (permissions %s) widened nothing but the advisory claims widening: %s", cls.name, cls.perms, w)
		}
	}
}

// The widened list is also pinned at the mapping itself: rollback joins the
// default-arm tokens, view/view-configuration do not, and the mapped bucket
// is exactly PermView (no write bucket follows from a widened token).
func TestMapJunosPermissionsWidenedList16638(t *testing.T) {
	for _, tc := range []struct {
		tok     string
		widened bool
	}{
		{"network", true},
		{"trace", true},
		{"snmp", true},
		{"interface", true},
		{"interface-control", true},
		{"rollback", true},
		{"view", false},
		{"view-configuration", false},
		{"configure", false},
		{"clear", false},
		{"reset", false},
		{"maintenance", false},
		{"all", false},
	} {
		perms, widened := mapJunosPermissions([]string{tc.tok})
		got := len(widened) == 1 && widened[0] == tc.tok
		if got != tc.widened {
			t.Errorf("mapJunosPermissions(%q) widened=%v (list %v), want widened=%v", tc.tok, got, widened, tc.widened)
		}
		if tc.widened {
			if len(perms) != 1 || perms[0] != PermView {
				t.Errorf("widened token %q must map to exactly [PermView] (no write bucket); got %v", tc.tok, perms)
			}
		}
	}
}
