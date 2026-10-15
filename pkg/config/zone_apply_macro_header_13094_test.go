package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #13094 (deep-review D1-07, #12828 residual): an apply-macro token in a
// security-zone header is a macro application only when it is unbracketed AND
// followed by exactly one macro name. Two shape families dropped authored
// content silently on a clean commit:
//
//   - a childless bracketed group with a member named apply-macro
//     (`security-zone [ trust apply-macro untrust ];`) matched the #9656
//     exemption on spelling alone, so only trust compiled;
//   - a braced statement whose apply-macro header is malformed
//     (`security-zone trust apply-macro { … }`, `… apply-macro M extra { … }`,
//     `security-zone apply-macro M { … }`) had its whole body hidden from zone
//     readers by bracketedGroupInstances8794, which never verified a macro
//     name was present or that nothing followed it.
//
// Strict refuses naming the dropped text; lenient warns and compiles the
// statement as before so a persisted configuration still boots (#1960).
func TestZoneApplyMacroHeaderDropsAreRefused13094(t *testing.T) {
	const screens = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	const ifaces = `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } } `
	zones := func(body string) string { return `security { zones { ` + body + ` } }` }
	refused := []struct{ name, text, want, tag string }{
		{
			"bracketed member named apply-macro hides a zone",
			zones(`security-zone [ trust apply-macro untrust ];`),
			`only zone "trust" compiles, and "apply-macro untrust" is dropped`, "(#9656)",
		},
		{
			"macro name missing under a braced zone body",
			ifaces + zones(`security-zone trust apply-macro { interfaces { ge-0/0/0.0; } }`),
			"apply-macro is missing its macro name", "(#13094)",
		},
		{
			"extra tokens after the macro name",
			ifaces + zones(`security-zone trust apply-macro M extra { interfaces { ge-0/0/0.0; } }`),
			`apply-macro must be followed by exactly its macro name`, "(#13094)",
		},
		{
			"apply-macro in the zone-name slot",
			ifaces + zones(`security-zone apply-macro M { interfaces { ge-0/0/0.0; } }`),
			"apply-macro is written in the zone-name slot, so no zone compiles", "(#13094)",
		},
	}
	for _, c := range refused {
		t.Run("refused/"+c.name, func(t *testing.T) {
			tr := prewalkTree9656(t, c.text)
			if tr == nil {
				return
			}
			_, err := validateZoneStatementTails9656(tr.Children, false)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), c.tag) {
				t.Errorf("strict: %q: want a refusal containing %q %s, got %v", c.text, c.want, c.tag, err)
			}
			warnings, err := validateZoneStatementTails9656(tr.Children, true)
			if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], c.want) {
				t.Errorf("lenient: %q: want one warning containing %q, got %q and %v", c.text, c.want, warnings, err)
			}

			// The same refusal must gate the real compile paths, not only the
			// validator: strict commit errors, tolerant load warns and still
			// boots (#1960).
			tree, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("CompileConfig: want the refusal containing %q, got %v", c.want, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient: want a warning, not the error %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("lenient: no warning containing %q among %q", c.want, cfg.Warnings)
			}
		})
	}

	// Tolerant compile-as-before contract: the malformed braced headers still
	// drop their bodies (now loudly), so a persisted configuration boots with
	// the same zones it had before the gate.
	t.Run("lenient compiles the malformed headers as before", func(t *testing.T) {
		tree, perrs := NewParser(ifaces + zones(`security-zone trust apply-macro { interfaces { ge-0/0/0.0; } }`)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if cfg.Security.Zones["trust"] == nil || len(cfg.Security.Zones["trust"].Interfaces) != 0 {
			t.Errorf("lenient: want zone trust with the body still dropped, got %+v", cfg.Security.Zones["trust"])
		}

		tree, perrs = NewParser(ifaces + zones(`security-zone [ trust apply-macro untrust ];`)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err = CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if cfg.Security.Zones["trust"] == nil || cfg.Security.Zones["untrust"] != nil {
			t.Errorf("lenient: want only zone trust, got %v", zoneNames13094(cfg))
		}
	})

	allowed := []struct {
		name, text string
		has        []string
		noZone     string
	}{
		{
			"well-formed macro tail after a bracketed group",
			screens + zones(`security-zone [ trust untrust ] apply-macro M { screen edge; }`),
			nil, "",
		},
		{
			"bracketed zone literally named apply-macro keeps its body",
			screens + zones(`security-zone [ trust apply-macro ] { screen edge; }`),
			[]string{`"apply-macro":{"Name":"apply-macro"`, `"ScreenProfile":"edge"`}, "",
		},
		{
			"exact inline macro tail stays inert",
			zones(`security-zone trust apply-macro M;`),
			[]string{`"trust":{"Name":"trust"`}, "",
		},
	}
	for _, c := range allowed {
		t.Run("allowed/"+c.name, func(t *testing.T) {
			tr := prewalkTree9656(t, c.text)
			if tr == nil {
				return
			}
			if w, err := validateZoneStatementTails9656(tr.Children, false); err != nil || len(w) != 0 {
				t.Errorf("%q: want no refusal, got %v %q", c.text, err, w)
			}
			tree, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Errorf("strict compile: want a commit, got %v", err)
				return
			}
			b, _ := json.Marshal(cfg.Security.Zones)
			for _, want := range c.has {
				if !strings.Contains(string(b), want) {
					t.Errorf("strict compile: want %s in the compiled zones, got %s", want, string(b))
				}
			}
		})
	}
}

func zoneNames13094(cfg *Config) []string {
	var names []string
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	return names
}
