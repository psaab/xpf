package config

import (
	"strings"
	"testing"
)

// #14342: container-form bracketed zone lists silently dropped zone pairs.
//
// The container branch in compilePolicies built pairs from single scalars
// (fzSub.Name(), tzNode.Keys[1], tzSub.Name()) without checking extra keys,
// so `[ trust dmz ]`, `to-zone [ untrust dmz ]`, and a bracketed child under
// a keyless to-zone each compiled strict-clean with only the first pair and
// no MalformedZonePairs record — neither the strict gate nor the tolerant
// poison ever saw the dropped pair.
//
// RED ON REVERT: remove the containerBracketedZoneList14342 checks in
// compilePolicies and each subtest commits clean with only trust->untrust.

const bracketZones14342 = `zones { security-zone trust; security-zone untrust; security-zone dmz; }`

const bracketDeny14342 = `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`

func compileBracket14342(t *testing.T, src string) (*Config, error) {
	t.Helper()
	p := NewParser(`security { ` + bracketZones14342 + ` policies { ` + src + ` } }`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

func compileBracketLenient14342(t *testing.T, src string) *Config {
	t.Helper()
	p := NewParser(`security { ` + bracketZones14342 + ` policies { ` + src + ` } }`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick (#1960): %v", err)
	}
	return cfg
}

func TestContainerFormFromZoneToZoneBracketedListRejectedStrict(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring naming the bracketed list
	}{
		{
			name: "from-zone container bracketed list",
			src:  `from-zone { [ trust dmz ] { to-zone untrust { ` + bracketDeny14342 + ` } } }`,
			want: "[ trust dmz ]",
		},
		{
			name: "to-zone keyed bracketed list",
			src:  `from-zone { trust { to-zone [ untrust dmz ] { ` + bracketDeny14342 + ` } } }`,
			want: "[ untrust dmz ]",
		},
		{
			name: "to-zone container bracketed child",
			src:  `from-zone { trust { to-zone { [ untrust dmz ] { ` + bracketDeny14342 + ` } } } }`,
			want: "[ untrust dmz ]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileBracket14342(t, tc.src); err == nil {
				t.Fatalf("container-form bracketed zone list committed clean; the extra zone pair is silently dropped (#14342)")
			} else if !strings.Contains(err.Error(), "bracketed") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict rejection must name the bracketed list %q, got: %v", tc.want, err)
			}

			cfg := compileBracketLenient14342(t, tc.src)
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatalf("tolerant compile recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", cfg.Security.Policies)
			}
			joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
			if !strings.Contains(joined, "bracketed") || !strings.Contains(joined, tc.want) {
				t.Fatalf("MalformedZonePairs %q does not name bracketed list %q", joined, tc.want)
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatal("tolerant compile did not add the snapshot poison carrier")
			}
			// No phantom single pair may survive on the tolerant path.
			for _, zp := range cfg.Security.Policies {
				if len(zp.Policies) != 0 {
					t.Fatalf("malformed container left a phantom enforced pair %s->%s with %d policies", zp.FromZone, zp.ToZone, len(zp.Policies))
				}
			}
		})
	}
}

// Controls: single-member brackets carry no dropped pair, and the plain
// container spelling must still compile with its policy.
func TestContainerFormSingleBracketAndPlainStillCompile14342(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"single-member from bracket", `from-zone { [ trust ] { to-zone untrust { ` + bracketDeny14342 + ` } } }`},
		{"single-member to bracket", `from-zone { trust { to-zone [ untrust ] { ` + bracketDeny14342 + ` } } }`},
		{"single-member to container bracket", `from-zone { trust { to-zone { [ untrust ] { ` + bracketDeny14342 + ` } } } }`},
		{"plain container", `from-zone { trust { to-zone { untrust { ` + bracketDeny14342 + ` } } } }`},
		{"keyed to-zone container", `from-zone { trust { to-zone untrust { ` + bracketDeny14342 + ` } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := compileBracket14342(t, tc.src)
			if err != nil {
				t.Fatalf("valid container spelling rejected: %v", err)
			}
			if len(cfg.Security.MalformedZonePairs) != 0 {
				t.Fatalf("valid container spelling recorded malformed: %q", cfg.Security.MalformedZonePairs)
			}
			if len(cfg.Security.Policies) != 1 || cfg.Security.Policies[0].FromZone != "trust" ||
				cfg.Security.Policies[0].ToZone != "untrust" || len(cfg.Security.Policies[0].Policies) != 1 {
				t.Fatalf("valid container spelling compiled %v, want one trust->untrust pair with one policy", cfg.Security.Policies)
			}
		})
	}
}
