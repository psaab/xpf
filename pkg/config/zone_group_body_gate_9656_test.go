package config

import (
	"strings"
	"testing"
)

// prewalkTree9656 prepares a tree the way compileConfigWithOpts hands it to
// runPreWalkGates: compact stanzas normalized, groups expanded.
func prewalkTree9656(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tr := parse8921(t, "zone group", text)
	if tr == nil {
		return nil
	}
	normalizeCompactStanzas(tr)
	if err := tr.ExpandGroups(); err != nil {
		t.Fatalf("%q: group expansion: %v", text, err)
	}
	return tr
}

// #9656 (M40): a security-zone statement that names two or more zones without a
// non-empty braced body compiled only its first zone. Strict refuses it, naming
// the zones; lenient warns. Measured at e09f425dd, every refused row below
// committed clean.
func TestZoneGroupWithoutBodyIsRefused9656(t *testing.T) {
	const groupG = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } `
	refused := []struct{ name, text, want string }{
		{"packed tail", `security { zones { security-zone [ zga zgb ] screen edge; } }`, "names 2 zones (zga zgb) without a braced body"},
		{"bare leaf", `security { zones { security-zone [ zga zgb ]; } }`, "names 2 zones (zga zgb) without a braced body"},
		{"empty braces", `security { zones { security-zone [ zga zgb ] { } } }`, "names 2 zones (zga zgb) with an empty braced body"},
		{"without brackets", `security { zones { security-zone zga zgb screen edge; } }`, "names 2 zones (zga zgb) without a braced body"},
		{"body emptied by group expansion", groupG + `security { zones { security-zone [ zga zgb ] { apply-groups G; } } }`, "names 2 zones (zga zgb) with an empty braced body"},
		{"packed apply-groups", groupG + `security { zones { security-zone [ zga zgb ] apply-groups G; } }`, "names 2 zones (zga zgb) without a braced body"},
		{"mistyped keyword", `security { zones { security-zone trust scren edge; } }`, "names 3 zones (trust scren edge)"},
		{"compact head", `security zones security-zone [ zga zgb ] screen edge;`, "names 2 zones (zga zgb)"},
		{"more than three zones", `security { zones { security-zone [ za zb zc zd ]; } }`, "names 4 zones (za zb zc …)"},
		{"second security stanza", `security { policies { default-policy { deny-all; } } } security { zones { security-zone [ zga zgb ]; } }`, "names 2 zones (zga zgb)"},
	}
	for _, c := range refused {
		t.Run("refused/"+c.name, func(t *testing.T) {
			tr := prewalkTree9656(t, c.text)
			if tr == nil {
				return
			}
			_, err := validateZoneGroupsHaveBody9656(tr.Children, false)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "(#9656)") {
				t.Errorf("strict: %q: want a refusal naming %q, got %v (#9656)", c.text, c.want, err)
			}
			warnings, err := validateZoneGroupsHaveBody9656(tr.Children, true)
			if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], c.want) {
				t.Errorf("lenient: %q: want one warning naming %q, got %q and %v (#9656)", c.text, c.want, warnings, err)
			}
		})
	}
	allowed := []struct{ name, text string }{
		{"braced body", `security { zones { security-zone [ zga zgb ] { screen edge; } } }`},
		{"braced body naming a keyword zone", `security { zones { security-zone [ zga zgb tcp-rst ] { tcp-rst; } } }`},
		{"single zone with a packed statement", `security { zones { security-zone trust screen edge; } }`},
		{"single zone with an inline apply-groups", groupG + `security { zones { security-zone trust apply-groups G; } }`},
		{"single zones, leaf and empty braces", `security { zones { security-zone trust; security-zone untrust { } } }`},
		{"quoted single zone", `security { zones { security-zone "zg a" description d; } }`},
	}
	for _, c := range allowed {
		t.Run("allowed/"+c.name, func(t *testing.T) {
			tr := prewalkTree9656(t, c.text)
			if tr == nil {
				return
			}
			if w, err := validateZoneGroupsHaveBody9656(tr.Children, false); err != nil || len(w) != 0 {
				t.Errorf("%q: want no refusal, got %v %q (#9656)", c.text, err, w)
			}
		})
	}
}
