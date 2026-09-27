package config

import (
	"strings"
	"testing"
)

func TestServicesSSLProxyProfilesWarn10984(t *testing.T) {
	profiles := []string{"forward", "exceptions"}
	setTree := buildTree(t, []string{
		"set services ssl proxy profile forward root-ca enterprise-ca",
		"set services ssl proxy profile forward actions log all",
		"set services ssl proxy profile exceptions root-ca enterprise-ca",
	})
	hierarchicalTree, parseErrors := NewParser(`services {
    ssl {
        proxy {
            profile forward {
                root-ca enterprise-ca;
                actions { log all; }
            }
            profile exceptions {
                root-ca enterprise-ca;
            }
        }
    }
}`).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("hierarchical fixture must parse: %v", parseErrors)
	}

	for _, shape := range []struct {
		name string
		tree *ConfigTree
	}{
		{name: "flat set", tree: setTree},
		{name: "hierarchical", tree: hierarchicalTree},
	} {
		t.Run(shape.name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{
				{name: "strict commit", compile: CompileConfig},
				{name: "lenient load", compile: CompileConfigLenient},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cfg, err := tc.compile(shape.tree)
					if err != nil {
						t.Fatalf("unsupported SSL proxy profiles must remain loadable: %v", err)
					}
					if len(cfg.Warnings) != len(profiles) {
						t.Fatalf("got %d diagnostics for %d profile definitions; warnings=%v",
							len(cfg.Warnings), len(profiles), cfg.Warnings)
					}
					warnings := strings.Join(cfg.Warnings, "\n")
					for _, profile := range profiles {
						if !strings.Contains(warnings, "services ssl proxy profile \""+profile+"\"") {
							t.Errorf("missing diagnostic naming profile %q; warnings=%v", profile, cfg.Warnings)
						}
					}
					for _, want := range []string{"accepted-only", "no runtime effect", "#10984"} {
						if !strings.Contains(warnings, want) {
							t.Errorf("diagnostic missing %q; warnings=%v", want, cfg.Warnings)
						}
					}
				})
			}

			// Warning about the unimplemented profiles must not rewrite their
			// authored definitions; display and persistence continue to use
			// the source tree.
			rendered := shape.tree.Format()
			for _, profile := range profiles {
				if !strings.Contains(rendered, "profile "+profile) {
					t.Errorf("source tree lost SSL proxy profile %q:\n%s", profile, rendered)
				}
			}
		})
	}
}
