package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15204 (A13-03): `system name-server { <ip> <modifier> <value>; }`
// committed clean. The block-list validator checked only each child's
// FIRST key (validateMultiValueLeaf's c.Keys[:1] default), while the
// compiler (firewallMatchValues via compiler_system.go) consumed EVERY
// child key — so a Junos modifier's value that happened to be an IP
// (source-address 10.0.0.2) became an extra resolver, the non-IP modifier
// keywords were silently dropped by the daemon render belt, and any
// routing-instance scoping was lost entirely.
//
// Fail-on-revert: drop allChildKeysAreValues from name-server /
// domain-search in schema_system.go and the modifier cells below go
// GREEN-on-commit again (validator accepts, extra IP compiles in).

func compileNameServers15204(t *testing.T, input string) []string {
	t.Helper()
	p := config.NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("CompileConfig returned nil")
	}
	return cfg.System.NameServers
}

func TestNameServerModifierBlockRefusedStrict15204(t *testing.T) {
	cases := []struct {
		name  string
		input string
		token string
	}{
		{
			name: "src",
			input: `system {
    name-server {
        1.1.1.1 source-address 10.0.0.2;
    }
}`,
			token: "source-address",
		},
		{
			name: "routing-instance-block",
			input: `system {
    name-server {
        1.1.1.1 routing-instance foo;
    }
}`,
			token: "routing-instance",
		},
		{
			name: "ri-flat",
			input: `system {
    name-server 1.1.1.1 routing-instance foo;
}`,
			token: "routing-instance",
		},
		{
			name: "source-address-flat",
			input: `system {
    name-server 1.1.1.1 source-address 10.0.0.2;
}`,
			token: "source-address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := schemaCheck(t, tc.input)
			if err == nil {
				// Show the consequence: the modifier IP compiles in as
				// an extra resolver.
				got := compileNameServers15204(t, tc.input)
				t.Fatalf("SchemaValidate accepted name-server modifier %q; compiled NameServers=%v (modifier value silently became a resolver / modifier dropped)", tc.token, got)
			}
			if !strings.Contains(err.Error(), "name-server") {
				t.Fatalf("error should reference name-server: %v", err)
			}
		})
	}
}

func TestDomainSearchModifierBlockRefusedStrict15204(t *testing.T) {
	// domain-search shares the firewallMatchValues compiler reader, so the
	// same block-child tail must be validated token-by-token. A token that
	// is not a DNS domain must be refused instead of compiled in as an
	// extra search domain.
	input := "system {\n domain-search {\n example.com bad_domain;\n }\n}"
	if err := schemaCheck(t, input); err == nil {
		t.Fatal("SchemaValidate accepted invalid domain-search block-child tail token")
	}
}

func TestNameServerLegitimateShapesStayGreen15204(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "block-list",
			input: `system {
    name-server {
        1.1.1.1;
        8.8.8.8;
    }
}`,
			want: []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name: "bracket-list",
			input: `system {
    name-server [ 1.1.1.1 8.8.8.8 ];
}`,
			want: []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:  "single",
			input: `system { name-server 1.1.1.1; }`,
			want:  []string{"1.1.1.1"},
		},
		{
			name: "block-ipv6",
			input: `system {
    name-server {
        2001:4860:4860::8888;
    }
}`,
			want: []string{"2001:4860:4860::8888"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := schemaCheck(t, tc.input); err != nil {
				t.Fatalf("legitimate name-server shape rejected: %v", err)
			}
			got := compileNameServers15204(t, tc.input)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("NameServers=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestDomainSearchLegitimateShapesStayGreen15204(t *testing.T) {
	for _, input := range []string{
		`system { domain-search { example.com; corp.example.net; } }`,
		`system { domain-search [ example.com corp.example.net ]; }`,
		`system { domain-search example.com; }`,
	} {
		if err := schemaCheck(t, input); err != nil {
			t.Fatalf("legitimate domain-search %q rejected: %v", input, err)
		}
	}
}
