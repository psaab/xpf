package config

import "testing"

// #8446. The defect was a COMPOSITION: an untyped schema leaf let any string
// commit, and the FRR renderer's switch on that string had no default arm, so
// an unrecognized value emitted NO is-type line and FRR fell back to level-1-2.
// The result was a silent WIDENING of the router's adjacency scope, and the
// sharpest input was `level-2-only` — the exact string the renderer itself
// emits.

func TestCanonicalISISLevelAcceptsEverySpellingItEmits_8446(t *testing.T) {
	// The renderer emits `is-type level-2-only`. If the canonicalizer ever
	// stops accepting the renderer's OWN output, the round trip that caused
	// this bug is back. This is the regression's core, stated as a property.
	if _, ok := CanonicalISISLevel("level-2-only"); !ok {
		t.Fatal("canonicalizer rejects `level-2-only`, the spelling the FRR renderer emits")
	}
	if got, _ := CanonicalISISLevel("level-2-only"); got != "level-2" {
		t.Errorf("`level-2-only` should collapse onto level-2, got %q", got)
	}
}

func TestCanonicalISISLevelTable_8446(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"level-1", "level-1", true},
		{"level-2", "level-2", true},
		{"level-1-2", "level-1-2", true},
		{"level-2-only", "level-2", true},
		{"  level-1  ", "level-1", true}, // surrounding whitespace tolerated
		{"", DefaultISISLevel, true},     // unset == the documented default
		// Every one of these previously committed clean and rendered NOTHING.
		{"1", "", false},
		{"2", "", false},
		{"level 2", "", false},
		{"LEVEL-2", "", false},
		{"level-3", "", false},
		{"garbage", "", false},
	}
	for _, c := range cases {
		got, ok := CanonicalISISLevel(c.in)
		if ok != c.wantOK {
			t.Errorf("CanonicalISISLevel(%q): ok=%v want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && got != c.want {
			t.Errorf("CanonicalISISLevel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateISISLevelRejectsNonCanonical_8446(t *testing.T) {
	for _, good := range ISISLevelSpellings() {
		if err := ValidateISISLevel(good); err != nil {
			t.Errorf("ValidateISISLevel(%q) rejected an accepted spelling: %v", good, err)
		}
	}
	for _, bad := range []string{"1", "2", "level 2", "LEVEL-2", "level-3", "garbage", "", "   "} {
		if err := ValidateISISLevel(bad); err == nil {
			t.Errorf("ValidateISISLevel(%q) accepted a value the renderer cannot express", bad)
		}
	}
}

// The DEFAULT must be the NARROW level. If it ever becomes level-1-2, the
// renderer belt stops being a belt: an unrecognized value would then widen
// exactly as it did before the fix.
func TestDefaultISISLevelIsNarrow_8446(t *testing.T) {
	if DefaultISISLevel == "level-1-2" {
		t.Fatal("DefaultISISLevel is level-1-2: the renderer belt now WIDENS on an " +
			"unrecognized value, which is the #8446 defect")
	}
	if _, ok := CanonicalISISLevel(DefaultISISLevel); !ok {
		t.Fatalf("DefaultISISLevel %q is not itself a canonical value", DefaultISISLevel)
	}
}
