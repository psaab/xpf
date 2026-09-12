package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

// compiledConfigJSON9620 compiles text on the lenient path and returns its JSON
// with the strict verdict beside it, so a row compares the WHOLE compiled
// config rather than a field someone remembered to look at.
func compiledConfigJSON9620(t *testing.T, text string) (string, string) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	strict := "OK"
	if _, err := CompileConfig(tree); err != nil {
		strict = "REFUSED: " + err.Error()
	}
	lt, _ := NewParser(text).Parse()
	cfg, err := CompileConfigLenient(lt)
	if err != nil {
		t.Fatalf("lenient compile %q: %v", text, err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return strict, buf.String()
}

// #9620 H11: a unit's `family` written without braces dropped the statements
// after the first container head. Measured at master 5d281094d:
//
//	unit 0 { family inet filter input f1 address 10.0.0.1/24; }   address lost
//	unit 0 family inet filter input f1 address 10.0.0.1/24;       address AND filter lost
//
// The second spelling is how the configuration evaded the undefined-filter
// gate that refuses the braced spelling: with the filter reference gone, there
// was nothing left for that gate to refuse.
//
// Two changes make the elided spellings compile like braced. `inet` and `inet6`
// opt into packedStatements, and the splitter walks a container head's own
// elided body instead of refusing the run outright. The unit-elided spelling
// additionally needs the `(unit, family)` admission, because the pass never
// reaches a container it has not created.
func TestPackedUnitFamilyCompilesLikeBraced9620(t *testing.T) {
	const filterDef = `firewall { family inet { filter f1 { term t0 { then accept; } } } } `
	const filterDef6 = `firewall { family inet6 { filter f6 { term t0 { then accept; } } } } `
	for _, c := range []struct{ name, elided, braced string }{
		{"inet, family elided",
			filterDef + `interfaces { ge-0/0/0 { unit 0 { family inet filter input f1 address 10.0.0.1/24; } } }`,
			filterDef + `interfaces { ge-0/0/0 { unit 0 { family inet { filter { input f1; } address 10.0.0.1/24; } } } }`},
		{"inet, unit and family elided",
			filterDef + `interfaces { ge-0/0/0 { unit 0 family inet filter input f1 address 10.0.0.1/24; } }`,
			filterDef + `interfaces { ge-0/0/0 { unit 0 { family inet { filter { input f1; } address 10.0.0.1/24; } } } }`},
		{"inet, address before filter",
			filterDef + `interfaces { ge-0/0/0 { unit 0 { family inet address 10.0.0.1/24 filter input f1; } } }`,
			filterDef + `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter { input f1; } } } } }`},
		{"inet6, family elided",
			filterDef6 + `interfaces { ge-0/0/0 { unit 0 { family inet6 filter input f6 address 2001:db8::1/64; } } }`,
			filterDef6 + `interfaces { ge-0/0/0 { unit 0 { family inet6 { filter { input f6; } address 2001:db8::1/64; } } } }`},
		{"inet6, unit and family elided",
			filterDef6 + `interfaces { ge-0/0/0 { unit 0 family inet6 filter input f6 address 2001:db8::1/64; } }`,
			filterDef6 + `interfaces { ge-0/0/0 { unit 0 { family inet6 { filter { input f6; } address 2001:db8::1/64; } } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			es, ejs := compiledConfigJSON9620(t, c.elided)
			bs, bjs := compiledConfigJSON9620(t, c.braced)
			if es != bs {
				t.Errorf("strict verdicts differ: elided %q, braced %q (#9620 H11)", es, bs)
			}
			if ejs != bjs {
				t.Errorf("the elided spelling does not compile like its braced control (#9620 H11)\n  elided: %s\n  braced: %s", ejs, bjs)
			}
		})
	}
}

// The splitter's own example must not move: `address` IS declared by
// `address-set`, so the walk consumes it into the set's statement and the run
// still returns whole. Splitting there would empty the set and leave a phantom
// address beside it, which is the inversion the refusal existed to prevent.
func TestPackedRunKeepsAContainerHeadsOwnMember9620(t *testing.T) {
	const text = `security { address-book global { address a1 10.0.0.0/8; address-set s1 address a1; } }`
	_, js := compiledConfigJSON9620(t, text)
	if !bytes.Contains([]byte(js), []byte(`"s1"`)) || !bytes.Contains([]byte(js), []byte(`"a1"`)) {
		t.Errorf("the address set lost its member: a token the head itself declares stays inside the head's statement (#9620 H11)\n  %s", js)
	}
	braced := `security { address-book global { address a1 10.0.0.0/8; address-set s1 { address a1; } } }`
	_, bjs := compiledConfigJSON9620(t, braced)
	if js != bjs {
		t.Errorf("the packed address-set no longer compiles like its braced spelling (#9620 H11)\n  packed: %s\n  braced: %s", js, bjs)
	}
}
