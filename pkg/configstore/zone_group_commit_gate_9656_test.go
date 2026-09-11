package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9656 (M40): a security-zone statement that names two or more zones without a
// non-empty braced body is refused at strict commit, and the refusal names the
// zones. The tolerant load path warns. Measured through CheckText at e09f425dd,
// each of these committed and compiled only zone zga:
//
//	security-zone [ zga zgb ] screen edge;
//	security-zone [ zga zgb ];
//	security-zone [ zga zgb ] { }
//
// The rendered text of a refused spelling is refused too. Format drops the
// brackets, and a cluster peer compiles that text.
func TestZoneGroupWithoutBodyIsRefusedAtCommit9656(t *testing.T) {
	const screens = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	zones := func(body string) string { return `security { zones { ` + body + ` } }` }
	for _, c := range []struct{ name, text string }{
		{"packed tail", screens + zones(`security-zone [ zga zgb ] screen edge;`)},
		{"bare leaf", zones(`security-zone [ zga zgb ];`)},
		{"empty braces", zones(`security-zone [ zga zgb ] { }`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			const want = "names 2 zones (zga zgb)"
			if _, err := CheckText(c.text, -1); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("strict: want the #9656 refusal naming %q, got %v", want, err)
			}
			tree, perrs := config.NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			rendered := tree.Format()
			if _, err := CheckText(rendered, -1); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("strict, rendered text %q: want the same refusal, got %v (#9656)", rendered, err)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient: want a warning, not the error %v (#9656)", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, want) {
					return
				}
			}
			t.Errorf("lenient: no warning naming %q among %q (#9656)", want, cfg.Warnings)
		})
	}
}

// CONTROLS: spellings the refusal must leave committing, each compiled with
// every zone it names.
func TestZoneGroupWithBodyStillCommits9656(t *testing.T) {
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
