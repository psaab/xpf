package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRouteFilterUnknownMatchTypeRejected_12538(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "compact orlongerr",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 orlongerr; then accept; } } }`,
		},
		{
			name: "compact exactt",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 exactt; then accept; } } }`,
		},
		{
			name: "compact bogus keyword",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 bogus; then accept; } } }`,
		},
		{
			name: "compact ipv6 unknown match-type",
			text: `policy-options { policy-statement P { term T { from route-filter 2001:db8::/32 orlongerr; then accept; } } }`,
		},
		{
			name: "compact second filter unknown",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 exact route-filter 192.168.0.0/16 orlongerr; then accept; } } }`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := config.NewParser(tc.text)
			tree, errs := p.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse error: %v", errs)
			}
			err := config.SchemaValidate(tree, nil)
			if err == nil {
				t.Fatal("expected SchemaValidate to reject unknown route-filter match-type, got nil")
			}
			if !strings.Contains(err.Error(), "not a valid route-filter match-type") {
				t.Fatalf("SchemaValidate error = %v, want rejection naming not a valid route-filter match-type", err)
			}

			// CompileConfig must also reject if reached directly
			_, compileErr := config.CompileConfig(tree)
			if compileErr == nil {
				t.Fatal("expected CompileConfig to reject unknown route-filter match-type, got nil")
			}
			if !strings.Contains(compileErr.Error(), "not a valid route-filter match-type") {
				t.Fatalf("CompileConfig error = %v, want rejection naming not a valid route-filter match-type", compileErr)
			}
		})
	}
}

func TestRouteFilterTermLineUnknownMatchTypeRejected_12538(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "term-line orlongerr",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr; term T then accept; } }`,
		},
		{
			name: "term-line packed then",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr then accept; } }`,
		},
		{
			name: "term-line then first",
			text: `policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 orlongerr; } }`,
		},
		{
			name: "term-line with protocol",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr protocol static; term T then accept; } }`,
		},
		{
			name: "term-line ipv6 unknown",
			text: `policy-options { policy-statement P { term T from route-filter 2001:db8::/32 orlongerr; term T then accept; } }`,
		},
		{
			name: "term-line second filter unknown",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 exact route-filter 192.168.0.0/16 orlongerr; term T then accept; } }`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := config.NewParser(tc.text)
			tree, errs := p.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse error: %v", errs)
			}
			_, compileErr := config.CompileConfig(tree)
			if compileErr == nil {
				t.Fatal("expected CompileConfig to reject unknown route-filter match-type, got nil")
			}
			if !strings.Contains(compileErr.Error(), "not a valid route-filter match-type") {
				t.Fatalf("CompileConfig error = %v, want rejection naming not a valid route-filter match-type", compileErr)
			}
		})
	}
}
