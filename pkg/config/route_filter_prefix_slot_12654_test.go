package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRouteFilterPrefixSlotRejected12654(t *testing.T) {
	cases := []struct {
		name, text string
	}{
		{"compact keyword in prefix slot", `policy-options { policy-statement P { term T { from route-filter longer exact; then accept; } } }`},
		{"compact garbage prefix", `policy-options { policy-statement P { term T { from route-filter garbage exact; then accept; } } }`},
		{"compact bare address", `policy-options { policy-statement P { term T { from route-filter 10.0.0.0 exact; then accept; } } }`},
		{"compact out-of-range v4 prefix", `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/33 exact; then accept; } } }`},
		{"compact out-of-range v6 prefix", `policy-options { policy-statement P { term T { from route-filter 2001:db8::/129 exact; then accept; } } }`},
		{"term-line keyword in prefix slot", `policy-options { policy-statement P { term T from route-filter longer exact; term T then accept; } }`},
		{"term-line garbage prefix", `policy-options { policy-statement P { term T from route-filter garbage exact; term T then accept; } }`},
		{"term-line bare address", `policy-options { policy-statement P { term T from route-filter 10.0.0.0 exact; term T then accept; } }`},
		{"term-line out-of-range prefix", `policy-options { policy-statement P { term T from route-filter 2001:db8::/129 exact; term T then accept; } }`},
		{"compact quoted leading-space prefix", `policy-options { policy-statement P { term T { from route-filter " 10.0.0.0/24" exact; then accept; } } }`},
		{"compact quoted trailing-space prefix", `policy-options { policy-statement P { term T { from route-filter "2001:db8::/32 " exact; then accept; } } }`},
		{"term-line quoted leading-space prefix", `policy-options { policy-statement P { term T from route-filter " 10.0.0.0/24" exact; term T then accept; } }`},
		{"term-line quoted trailing-space prefix", `policy-options { policy-statement P { term T from route-filter "2001:db8::/32 " exact; term T then accept; } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := config.NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("Parse: %v", errs)
			}
			_, err := config.CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "route-filter prefix") {
				t.Fatalf("CompileConfig error = %v, want invalid route-filter prefix rejection", err)
			}
			lenient, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			found := false
			for _, warning := range lenient.Warnings {
				if strings.Contains(warning, "route-filter match-type") && strings.Contains(warning, "route-filter prefix") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("tolerant path did not warn about malformed route-filter prefix: %v", lenient.Warnings)
			}
		})
	}
}

func TestRouteFilterPrefixSlotValidControls12654(t *testing.T) {
	for _, text := range []string{
		`policy-options { policy-statement P { term T { from route-filter 0.0.0.0/0 exact; then accept; } } }`,
		`policy-options { policy-statement P { term T { from route-filter 10.0.0.1/32 longer; then accept; } } }`,
		`policy-options { policy-statement P { term T from route-filter ::/0 orlonger; term T then accept; } }`,
		`policy-options { policy-statement P { term T from route-filter 2001:db8::1/128 exact; term T then accept; } }`,
	} {
		tree, errs := config.NewParser(text).Parse()
		if len(errs) != 0 {
			t.Fatalf("Parse(%q): %v", text, errs)
		}
		if _, err := config.CompileConfig(tree); err != nil {
			t.Errorf("CompileConfig(%q): %v", text, err)
		}
	}
}
