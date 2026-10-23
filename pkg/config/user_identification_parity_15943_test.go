package config

import (
	"strings"
	"testing"
)

// Fold-2 (#16296): the opaque security identity schema must preserve all
// authored leaves in packed/elided and braced/split parity, warn for direct
// stanzas even beside a wrapper, and never schema-reject an authored token.
func TestUserIdentificationPackedSplitParity15943(t *testing.T) {
	pairs := [][2]string{
		{"security { authentication-source { foo; password secretx; } }", "security authentication-source { foo; password secretx; }"},
		{"security { device-information { bar; } }", "security device-information { bar; }"},
		{"security { user-identification { authentication-source { local-authentication-table auth1; } } }", "security user-identification { authentication-source { local-authentication-table auth1; } }"},
		{"security { user-identification { device-information { source foo; } } }", "security user-identification { device-information { source foo; } }"},
	}
	for _, pair := range pairs {
		var formats []string
		for _, src := range pair {
			tree, errs := NewParser(src).Parse()
			if len(errs) > 0 {
				t.Fatalf("%q parse: %v", src, errs)
			}
			_, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("%q compile: %v", src, err)
			}
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("%q schema rejected authored identity leaves: %v", src, err)
			}
			formats = append(formats, normalizeCompactForValidation(tree).Format())
		}
		if formats[0] != formats[1] {
			t.Errorf("packed/split parity differs:\nbraced=%q\nelided=%q", formats[0], formats[1])
		}
	}
}

func TestUserIdentificationDirectWarnsBesideWrapper15943(t *testing.T) {
	tree, errs := NewParser("security { user-identification; authentication-source foo; device-information bar; }").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	// Master's shared walker attributes direct stanzas under the
	// user-identification prefix when a wrapper is present; assert the
	// stanza is NAMED (not suppressed), in either attribution.
	for _, want := range []string{"security user-identification", "authentication-source", "device-information"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing direct/wrapper warning %q: %v", want, cfg.Warnings)
		}
	}
}
