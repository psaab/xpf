package config

import (
	"strings"
	"testing"
)

// #14682 (D9-02): validateFirewallFilterFamilyAnyMatchesAST walked the RAW
// AST (`termInst.node.FindChildren("from")` + `fromNode.Children`) while
// compileFirewall walks `firewallTermFromNodes` + `packedBody`. The compact
// normalizer deliberately excludes (term,from) and omits the prefix-list
// leaves from its `from` fold list, so compact term bodies and one-line
// `from` statements presented ZERO children to the validator: the #4296
// (family-specific matches) and #4426 (single-family prefix-lists) gates
// never fired under `family any`, while dual-compilation installed the
// term into both pools where the v4-only match can never match v6.

func TestFirewallFamilyAnyCompactAndPackedFromRejected(t *testing.T) {
	cases := []struct {
		name string
		tree string
		want []string
	}{
		{
			name: "compact term icmp-type",
			tree: `
firewall {
    family any {
        filter f1 {
            term t-icmp from icmp-type echo-request then discard;
        }
    }
}
`,
			want: []string{"f1", "t-icmp", "#4296", "icmp-type"},
		},
		{
			name: "one-line from source-prefix-list",
			tree: `
policy-options {
    prefix-list v4only 10.0.0.0/8;
}
firewall {
    family any {
        filter f1 {
            term t-pl {
                from source-prefix-list v4only;
                then discard;
            }
        }
    }
}
`,
			want: []string{"f1", "t-pl", "#4426", "v4only"},
		},
		{
			name: "compact term source-prefix-list",
			tree: `
policy-options {
    prefix-list v4only 10.0.0.0/8;
}
firewall {
    family any {
        filter f1 {
            term t-pl from source-prefix-list v4only then discard;
        }
    }
}
`,
			want: []string{"f1", "t-pl", "#4426", "v4only"},
		},
		{
			name: "one-line from source-address",
			tree: `
firewall {
    family any {
        filter f1 {
            term t-addr {
                from source-address 10.0.0.0/8;
                then discard;
            }
        }
    }
}
`,
			want: []string{"f1", "t-addr", "#4296", "source-address"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier(t, tc.tree)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected rejection under family any, got nil")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}

// Lenient path must warn (not silently accept) for the compact spelling.
func TestFirewallFamilyAnyCompactICMPLenientWarns14682(t *testing.T) {
	tree := parseHier(t, `
firewall {
    family any {
        filter f1 {
            term t-icmp from icmp-type echo-request then discard;
        }
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4296") && strings.Contains(w, "icmp-type") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected #4296 warning, got: %v", cfg.Warnings)
	}
}

// Controls: family-agnostic compact matches and a mixed-family prefix-list
// under `family any` must still commit and dual-install.
func TestFirewallFamilyAnyCompactControlsCommit14682(t *testing.T) {
	t.Run("compact protocol", func(t *testing.T) {
		tree := parseHier(t, `
firewall {
    family any {
        filter f1 {
            term t-ok from protocol tcp then accept;
        }
    }
}
`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.Firewall.FiltersInet["f1"] == nil || cfg.Firewall.FiltersInet6["f1"] == nil {
			t.Fatal("family any filter must land in both pools")
		}
	})
	t.Run("compact mixed prefix-list", func(t *testing.T) {
		tree := parseHier(t, `
policy-options {
    prefix-list mixed [ 10.0.0.0/8 2001:db8::/32 ];
}
firewall {
    family any {
        filter f1 {
            term t-mixed from source-prefix-list mixed then discard;
        }
    }
}
`)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig: mixed prefix-list must commit, got: %v", err)
		}
	})
}
