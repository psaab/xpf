package config

// Regression tests for #4348 — a QUOTED value exactly equal to the
// `inactive:` marker text must be preserved, never treated as a Junos
// deactivation marker.
//
// The lexer tokenizes a bare `inactive:` as a single TokenIdentifier (because
// `:` is an identifier character) and a quoted `"inactive:"` as a TokenString.
// parseKeys previously flattened both kinds into one []string, so a quoted
// value equal to the marker text (e.g. `description "inactive:";`) was
// indistinguishable from a bare deactivation marker and got silently
// truncated — the value was dropped and the statement wrongly deactivated.
//
// The parser now carries a parallel token-kind slice and gates BOTH the
// leading (index 0) and inline (index > 0) marker detection on
// `kinds[i] == TokenIdentifier`, so only a bare identifier `inactive:` is a
// marker; a quoted `"inactive:"` stays a literal value.
//
// RED-on-revert: reverting the token-kind gate in parseStatement truncates the
// quoted value (LeadingQuotedValuePreserved -> Keys loses "inactive:" and the
// node is wrongly Inactive; InlineQuotedValuePreserved -> the "inactive:" value
// is dropped from Keys), failing the assertions below.

import (
	"reflect"
	"testing"
)

// TestQuotedInactive_InlineQuotedValuePreserved is the core #4348 regression,
// mirroring the issue's example `description "inactive:";`. The quoted value
// sits at an INLINE position (index 1). It must be preserved as the leaf's
// value; the statement must stay active.
func TestQuotedInactive_InlineQuotedValuePreserved(t *testing.T) {
	tree := parseHierText(t, `interfaces {
    ge-0/0/0 {
        description "inactive:";
    }
}`)
	desc := tree.FindChild("interfaces").FindChild("ge-0/0/0").FindChild("description")
	if desc == nil {
		t.Fatalf("description leaf not found; ge-0/0/0 children=%v",
			tree.FindChild("interfaces").FindChild("ge-0/0/0").Children)
	}
	if desc.Inactive {
		t.Fatal("a quoted \"inactive:\" value must NOT deactivate the statement")
	}
	want := []string{"description", inactiveMarker}
	if !reflect.DeepEqual(desc.Keys, want) {
		t.Fatalf("quoted inline \"inactive:\" truncated: got %v, want %v", desc.Keys, want)
	}
}

// TestQuotedInactive_LeadingQuotedValuePreserved exercises the LEADING (index
// 0) branch: a statement whose first token is the quoted string `"inactive:"`.
// The pre-existing leading handler treated this as a marker and lifted it off,
// losing the value and wrongly deactivating the statement. With the token-kind
// gate the quoted value stays the statement's identity key.
func TestQuotedInactive_LeadingQuotedValuePreserved(t *testing.T) {
	tree := parseHierText(t, `system {
    "inactive:" host-name h;
}`)
	sys := tree.FindChild("system")
	if len(sys.Children) != 1 {
		t.Fatalf("expected 1 child under system, got %d: %+v", len(sys.Children), sys.Children)
	}
	n := sys.Children[0]
	if n.Inactive {
		t.Fatal("a quoted leading \"inactive:\" value must NOT deactivate the statement")
	}
	want := []string{inactiveMarker, "host-name", "h"}
	if !reflect.DeepEqual(n.Keys, want) {
		t.Fatalf("quoted leading \"inactive:\" truncated: got %v, want %v", n.Keys, want)
	}
}

// TestQuotedInactive_BareLeadingMarkerStillDeactivates guards case (2): a bare
// (identifier) leading `inactive:` still lifts into Node.Inactive and strips
// off the keys — unchanged behavior.
func TestQuotedInactive_BareLeadingMarkerStillDeactivates(t *testing.T) {
	tree := parseHierText(t, `system {
    inactive: host-name h;
}`)
	hn := tree.FindChild("system").FindChild("host-name")
	if hn == nil {
		t.Fatalf("host-name not found; system children=%v", tree.FindChild("system").Children)
	}
	if !hn.Inactive {
		t.Fatal("a bare leading inactive: must still deactivate the statement")
	}
	want := []string{"host-name", "h"}
	if !reflect.DeepEqual(hn.Keys, want) {
		t.Fatalf("bare leading inactive: leaked into Keys: got %v, want %v", hn.Keys, want)
	}
}

// TestQuotedInactive_BareInlineMarkerStillDeactivates guards case (3): a bare
// (identifier) inline `inactive:` still drops the marker and every token it
// governs — the #4347 behavior is unchanged.
func TestQuotedInactive_BareInlineMarkerStillDeactivates(t *testing.T) {
	tree := parseHierText(t, `system {
    host-name keep inactive: extra;
}`)
	hn := tree.FindChild("system").FindChild("host-name")
	if hn == nil {
		t.Fatalf("host-name not found; system children=%v", tree.FindChild("system").Children)
	}
	if hn.Inactive {
		t.Fatal("the host-name statement itself must stay active")
	}
	want := []string{"host-name", "keep"}
	if !reflect.DeepEqual(hn.Keys, want) {
		t.Fatalf("bare inline inactive: not pruned: got %v, want %v", hn.Keys, want)
	}
}

// TestQuotedInactive_NormalQuotedValueUnaffected guards case (4): an ordinary
// quoted value (not equal to the marker text) is preserved exactly.
func TestQuotedInactive_NormalQuotedValueUnaffected(t *testing.T) {
	tree := parseHierText(t, `interfaces {
    ge-0/0/0 {
        description "up link";
    }
}`)
	desc := tree.FindChild("interfaces").FindChild("ge-0/0/0").FindChild("description")
	if desc == nil {
		t.Fatal("description leaf not found")
	}
	if desc.Inactive {
		t.Fatal("a normal quoted value must not deactivate the statement")
	}
	want := []string{"description", "up link"}
	if !reflect.DeepEqual(desc.Keys, want) {
		t.Fatalf("normal quoted value altered: got %v, want %v", desc.Keys, want)
	}
}
