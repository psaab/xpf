package config

import (
	"strings"
	"testing"
)

// prewalkTree9656 prepares a tree the way compileConfigWithOpts hands it to
// runPreWalkGates: compact stanzas normalized, groups expanded.
func prewalkTree9656(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tr := parse8921(t, "zone statement", text)
	if tr == nil {
		return nil
	}
	normalizeCompactStanzas(tr)
	if err := tr.ExpandGroups(); err != nil {
		t.Fatalf("%q: group expansion: %v", text, err)
	}
	return tr
}

// #9656 (M40), #9788: a security-zone statement with no braced body compiles
// only its first key as the zone. Strict refuses any key after the name that
// is not a repeat of it, naming the zone that compiles and the dropped text;
// lenient warns. Measured at 6cf4305ab, every refused row below committed
// clean.
func TestZoneStatementTailIsRefused9656(t *testing.T) {
	const groupG = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } `
	var long strings.Builder
	long.WriteString(`security { zones { security-zone [`)
	for i := 0; i < 40; i++ {
		long.WriteString(" z")
		long.WriteString(strings.Repeat("x", 3))
		long.WriteByte(byte('a' + i%26))
	}
	long.WriteString(` ]; } }`)
	refused := []struct{ name, text, want string }{
		{"packed tail", `security { zones { security-zone [ zga zgb ] screen edge; } }`, `without a braced body, only zone "zga" compiles, and "zgb screen edge" is dropped`},
		{"bare leaf", `security { zones { security-zone [ zga zgb ]; } }`, `only zone "zga" compiles, and "zgb" is dropped`},
		{"empty braces", `security { zones { security-zone [ zga zgb ] { } } }`, `with an empty braced body, only zone "zga" compiles, and "zgb" is dropped`},
		{"without brackets", `security { zones { security-zone zga zgb screen edge; } }`, `only zone "zga" compiles, and "zgb screen edge" is dropped`},
		{"body emptied by group expansion", groupG + `security { zones { security-zone [ zga zgb ] { apply-groups G; } } }`, `with an empty braced body, only zone "zga" compiles, and "zgb" is dropped`},
		{"packed apply-groups group", groupG + `security { zones { security-zone [ zga zgb ] apply-groups G; } }`, `only zone "zga" compiles, and "zgb apply-groups G" is dropped`},
		{"single zone with an inline apply-groups", groupG + `security { zones { security-zone trust apply-groups G; } }`, `only zone "trust" compiles, and "apply-groups G" is dropped`},
		{"keyword-named first zone", `security { zones { security-zone [ tcp-rst zgb ]; } }`, `only zone "tcp-rst" compiles, and "zgb" is dropped`},
		{"quoted keyword-named first zone", `security { zones { security-zone [ "tcp-rst" zgb ]; } }`, `only zone "tcp-rst" compiles, and "zgb" is dropped`},
		{"mistyped keyword", `security { zones { security-zone trust scren edge; } }`, `only zone "trust" compiles, and "scren edge" is dropped`},
		{"repeat after another zone", `security { zones { security-zone [ zga zgb zga ]; } }`, `only zone "zga" compiles, and "zgb zga" is dropped`},
		{"compact head", `security zones security-zone [ zga zgb ] screen edge;`, `only zone "zga" compiles, and "zgb screen edge" is dropped`},
		{"long dropped text", long.String(), ` …" is dropped`},
		{"second security stanza", `security { policies { default-policy { deny-all; } } } security { zones { security-zone [ zga zgb ]; } }`, `only zone "zga" compiles, and "zgb" is dropped`},
	}
	for _, c := range refused {
		t.Run("refused/"+c.name, func(t *testing.T) {
			tr := prewalkTree9656(t, c.text)
			if tr == nil {
				return
			}
			_, err := validateZoneStatementTails9656(tr.Children, false)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "(#9656)") {
				t.Errorf("strict: %q: want a refusal containing %q, got %v (#9656)", c.text, c.want, err)
			}
			warnings, err := validateZoneStatementTails9656(tr.Children, true)
			if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], c.want) {
				t.Errorf("lenient: %q: want one warning containing %q, got %q and %v (#9656)", c.text, c.want, warnings, err)
			}
		})
	}
	allowed := []struct{ name, text string }{
		{"braced body", `security { zones { security-zone [ zga zgb ] { screen edge; } } }`},
		{"braced body naming a keyword zone", `security { zones { security-zone [ zga zgb tcp-rst ] { tcp-rst; } } }`},
		{"single zone with a packed statement", `security { zones { security-zone trust screen edge; } }`},
		{"repeated name", `security { zones { security-zone [ zga zga ]; } }`},
		{"single zones, leaf and empty braces", `security { zones { security-zone trust; security-zone untrust { } } }`},
		{"quoted single zone with a statement", `security { zones { security-zone "zg a" description d; } }`},
	}
	for _, c := range allowed {
		t.Run("allowed/"+c.name, func(t *testing.T) {
			tr := prewalkTree9656(t, c.text)
			if tr == nil {
				return
			}
			if w, err := validateZoneStatementTails9656(tr.Children, false); err != nil || len(w) != 0 {
				t.Errorf("%q: want no refusal, got %v %q (#9656)", c.text, err, w)
			}
		})
	}
}
