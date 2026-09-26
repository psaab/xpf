package config

import (
	"strings"
	"testing"
)

func TestServicesUserIdentificationWarns10947(t *testing.T) {
	stanzas := []string{
		"active-directory-access",
		"identity-management",
		"local-authentication-table",
	}
	lines := make([]string, 0, len(stanzas))
	for _, stanza := range stanzas {
		lines = append(lines, "set services user-identification "+stanza)
	}
	tree := buildTree(t, lines)

	for _, tc := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{name: "strict commit", compile: CompileConfig},
		{name: "lenient load", compile: CompileConfigLenient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile(tree)
			if err != nil {
				t.Fatalf("identity configuration must remain loadable: %v", err)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, stanza := range stanzas {
				if !strings.Contains(warnings, stanza) {
					t.Errorf("missing diagnostic naming %q; warnings=%v", stanza, cfg.Warnings)
				}
			}
			if !strings.Contains(warnings, "accepted-only") || !strings.Contains(warnings, "no runtime effect") {
				t.Errorf("diagnostic must state that user-identification is inert; warnings=%v", cfg.Warnings)
			}
		})
	}

	// Tolerant compilation must not rewrite or discard the stored candidate;
	// config display and a future implementation still need the authored data.
	rendered := tree.Format()
	for _, stanza := range stanzas {
		if !strings.Contains(rendered, stanza) {
			t.Errorf("lenient compilation lost %q from the source tree:\n%s", stanza, rendered)
		}
	}
}
