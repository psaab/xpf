package config

import (
	"strings"
	"testing"
)

func TestStaticRouteInterfaceQualifiedNextHopTail12790(t *testing.T) {
	invalid := []struct {
		name string
		src  string
	}{
		{
			name: "dangling qualified-next-hop",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 qualified-next-hop; } }`,
		},
		{
			name: "quoted qualified-next-hop tail",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 "qualified-next-hop" 10.0.0.2 preference 250; } }`,
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, tc.src)
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "qualified-next-hop") {
				t.Fatalf("strict compile error = %v, want qualified-next-hop rejection", err)
			}

			cfg, err := CompileConfigLenient(hierTree(t, tc.src))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12790") && strings.Contains(warning, "qualified-next-hop") {
					return
				}
			}
			t.Fatalf("tolerant compile did not warn about the dropped qualified-next-hop tail: %v", cfg.Warnings)
		})
	}

	t.Run("well-formed qualified-next-hop remains accepted", func(t *testing.T) {
		cfg, err := CompileConfig(hierTree(t, `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 qualified-next-hop 10.0.0.2 preference 250; } }`))
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, "#12790") {
				t.Fatalf("valid qualified-next-hop emitted #12790 warning: %q", warning)
			}
		}
	})
}
