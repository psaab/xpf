package config

import (
	"strings"
	"testing"
)

func alg12833Tree(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tr, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	return tr
}

// #12833 (D2-10): algDisabled read only the FIRST same-protocol child
// (FindChild). A second `ftp` block carrying the only `disable` was silently
// dropped, leaving the ALG enabled on a successful commit. Mutant: revert to
// FindChild -> second-block and third-block cases fail.
func TestALGDuplicateProtoBlocks12833(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"second braced disables", `security { alg { ftp { } ftp { disable; } } }`},
		{"second packed disables", `security { alg { ftp { } ftp disable; } }`},
		{"third braced disables", `security { alg { ftp { } ftp { } ftp { disable; } } }`},
		{"second packed after braced", `security { alg { ftp { } ftp disable; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := alg12833Tree(t, tc.text)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate must accept valid duplicate ALG blocks: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if !cfg.Security.ALG.FTPDisable {
				t.Errorf("FTPDisable=false for %q; later disable silently dropped", tc.text)
			}
		})
	}
	// Ordering control: disable in first block still works, unaffected protos off.
	t.Run("first disables control", func(t *testing.T) {
		cfg, err := CompileConfig(alg12833Tree(t, `security { alg { ftp { disable; } ftp { } } }`))
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Security.ALG.FTPDisable {
			t.Error("first-block disable regressed")
		}
		if cfg.Security.ALG.DNSDisable || cfg.Security.ALG.SIPDisable || cfg.Security.ALG.TFTPDisable {
			t.Error("unrelated ALG incorrectly disabled")
		}
	})
	// Unsupported protos in multiple blocks each reported.
	t.Run("multiple blocks unsupported", func(t *testing.T) {
		cfg, err := CompileConfig(alg12833Tree(t, `security { alg { h323 { gatekeeper; } h323 { gatekeeper; } } }`))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Security.ALG.UnsupportedProtos) != 2 {
			t.Errorf("UnsupportedProtos=%v want 2 h323 entries", cfg.Security.ALG.UnsupportedProtos)
		}
	})
}

// #12833 packed typo: `ftp desable;` packed token must be rejected strict, named.
// Mutant: without rejection, SchemaValidate returns nil.
func TestALGPackedTypoRejected12833(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"packed child typo", `security { alg { ftp desable; } }`},
		{"double-packed typo", `security { alg ftp desable; }`},
		{"unknown token after valid disable", `security { alg { ftp disable bogus; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := alg12833Tree(t, tc.text)
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("SchemaValidate accepted packed typo %q", tc.text)
			}
			if !strings.Contains(err.Error(), "desable") && !strings.Contains(err.Error(), "bogus") {
				t.Errorf("error must name offending token, got %v", err)
			}
		})
	}
	// Braced typo control: existing closed-world rejection remains active.
	t.Run("braced typo control", func(t *testing.T) {
		tree := alg12833Tree(t, `security { alg { ftp { desable; } } }`)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatal("braced typo should be rejected (existing closed-world)")
		}
	})
	// Valid packed spellings accepted (no false reject).
	for _, text := range []string{
		`security { alg { ftp disable; } }`,
		`security { alg ftp disable; }`,
		`security { alg ftp { disable; } }`,
		`security { alg { ftp { disable; } } }`,
		`security { alg { h323 { gatekeeper foo; } } }`,
		`security { alg { h323 gatekeeper; } }`,
	} {
		t.Run("valid/"+text, func(t *testing.T) {
			if err := SchemaValidate(alg12833Tree(t, text), nil); err != nil {
				t.Errorf("valid spelling rejected: %v", err)
			}
		})
	}
	// Tolerant path must not brick: lenient compile succeeds.
	t.Run("lenient compiles packed typo", func(t *testing.T) {
		tree := alg12833Tree(t, `security { alg { ftp desable; } }`)
		if _, err := CompileConfigLenient(tree); err != nil {
			t.Errorf("lenient compile bricked: %v", err)
		}
	})
}
