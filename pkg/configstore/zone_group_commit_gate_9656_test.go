package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9656 (M40), #9788: a security-zone statement with no braced body compiles
// only its first key as the zone. A statement that would drop more is refused
// at strict commit, naming the zone that compiles and the dropped text. The
// tolerant load path warns. Measured through CheckText at 6cf4305ab, each
// refused row below committed clean.
//
// The hierarchical text that `show configuration` prints, and that cluster
// sync compiles, gets the same refusal: Format drops the brackets.
func TestZoneStatementTailIsRefusedAtCommit9656(t *testing.T) {
	const screens = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	const groupG = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } `
	zones := func(body string) string { return `security { zones { ` + body + ` } }` }
	for _, c := range []struct{ name, text, want string }{
		{"packed tail", screens + zones(`security-zone [ zga zgb ] screen edge;`), `only zone "zga" compiles, and "zgb screen edge" is dropped`},
		{"bare leaf", zones(`security-zone [ zga zgb ];`), `only zone "zga" compiles, and "zgb" is dropped`},
		{"empty braces", zones(`security-zone [ zga zgb ] { }`), `only zone "zga" compiles, and "zgb" is dropped`},
		{"quoted keyword-named first zone", zones(`security-zone [ "tcp-rst" zgb ];`), `only zone "tcp-rst" compiles, and "zgb" is dropped`},
		{"single zone with an inline apply-groups", groupG + zones(`security-zone trust apply-groups G;`), `only zone "trust" compiles, and "apply-groups G" is dropped`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := CheckText(c.text, -1); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("strict: want the #9656 refusal containing %q, got %v", c.want, err)
			}
			tree, perrs := config.NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			rendered := tree.Format()
			if _, err := CheckText(rendered, -1); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("strict, rendered text %q: want the same refusal, got %v (#9656)", rendered, err)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient: want a warning, not the error %v (#9656)", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, c.want) {
					return
				}
			}
			t.Errorf("lenient: no warning containing %q among %q (#9656)", c.want, cfg.Warnings)
		})
	}
}

// CONTROLS: spellings the refusal must leave committing, each compiled with
// every zone it names.
func TestZoneStatementWithBodyStillCommits9656(t *testing.T) {
	const screens = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	zones := func(body string) string { return `security { zones { ` + body + ` } }` }
	for _, c := range []struct {
		name, text string
		has        []string
	}{
		{"braced body", screens + zones(`security-zone [ zga zgb ] { screen edge; }`), []string{`"zga":{"Name":"zga"`, `"zgb":{"Name":"zgb"`, `"ScreenProfile":"edge"`}},
		{"braced body naming a flag-keyword zone", zones(`security-zone [ zga zgb tcp-rst ] { tcp-rst; }`), []string{`"tcp-rst":{"Name":"tcp-rst"`, `"zgb":{"Name":"zgb"`}},
		{"braced body naming a body-holding keyword zone", zones(`security-zone [ zga zgb host-inbound-traffic ] { tcp-rst; }`), []string{`"host-inbound-traffic":{"Name":"host-inbound-traffic"`}},
		{"single zone with a packed statement", screens + zones(`security-zone trust screen edge;`), []string{`"trust":{"Name":"trust"`, `"ScreenProfile":"edge"`}},
		{"repeated name", zones(`security-zone [ zga zga ];`), []string{`"zga":{"Name":"zga"`}},
		{"single zone with an inline apply-macro", zones(`security-zone trust apply-macro M;`), []string{`"trust":{"Name":"trust"`}},
		{"inactive group", zones(`inactive: security-zone [ zga zgb ]; security-zone trust;`), []string{`"trust":{"Name":"trust"`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := CheckText(c.text, -1); err != nil {
				t.Errorf("strict: %q: want a commit, got %v (#9656)", c.text, err)
			}
			tree, perrs := config.NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			b, _ := json.Marshal(cfg.Security.Zones)
			for _, want := range c.has {
				if !strings.Contains(string(b), want) {
					t.Errorf("%q: compiled zones lack %s (#9656)", c.text, want)
				}
			}
		})
	}
	// The flat-set spelling with a statement builds a node WITH a child, which
	// renders braced, so it commits like the braced body.
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		`set security screen ids-option edge icmp ping-death`,
		`set security zones security-zone [ zga zgb ] screen edge`,
	} {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", cmd, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", cmd, err)
		}
	}
	if _, err := CheckText(tree.Format(), -1); err != nil {
		t.Errorf("flat-set group with a statement, rendered %q: want a commit, got %v (#9656)", tree.Format(), err)
	}
}
