package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVersionFixture16190 pins the per-sink divergence between this
// ExecStart sink and the Python filename sink (scripts/dist/sign.py,
// unified in #16190) in scripts/dist/version_fixture_16190.json. The
// fixture encodes an expected outcome PER SINK: Go allows the Debian
// epoch ':' and leading '-+_~:'; Python requires an initial alphanumeric
// and drops ':'. Neither policy is changed to match the other.
//
// RED on revert: tighten ValidateVersionSegment with a first-char
// alphanumeric rule (matching Python) and the divergent rows
// ('1:2.0', '-x', ...) fail against the fixture's go column.
func TestVersionFixture16190(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "dist",
		"version_fixture_16190.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx struct {
		Cases []struct {
			Input  string `json:"input"`
			Python string `json:"python"`
			Go     string `json:"go"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	if len(fx.Cases) == 0 {
		t.Fatalf("fixture %s has no cases", path)
	}
	divergent := 0
	for _, c := range fx.Cases {
		if c.Python != "accept" && c.Python != "reject" {
			t.Errorf("fixture input %q: python=%q, want accept/reject",
				c.Input, c.Python)
		}
		if c.Go != "accept" && c.Go != "reject" {
			t.Errorf("fixture input %q: go=%q, want accept/reject",
				c.Input, c.Go)
		}
		if c.Python != c.Go {
			divergent++
		}
		got := ValidateVersionSegment(c.Input) == nil
		want := c.Go == "accept"
		if got != want {
			t.Errorf("ValidateVersionSegment(%q) accept=%v, fixture go=%q",
				c.Input, got, c.Go)
		}
	}
	// The fixture must encode the per-sink table, not a universal one:
	// epoch + every leading-punctuation class diverges (11 rows).
	if divergent < 11 {
		t.Errorf("fixture has %d divergent rows, want >= 11 "+
			"(per-sink table collapsed?)", divergent)
	}
}
