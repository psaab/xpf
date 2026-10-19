package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14967: a tolerant-compiled address-book entry carrying two distinct
// prefixes (or trailing tokens past its prefix) must fail closed in the
// userspace snapshot path. Before the fix, Address.UsableValue ignored
// both taints, so the book table published the surviving prefix and the
// referencing policy armed on a network the operator did not write.
//
// The config is built through the REAL tolerant compiler (hierarchical
// text -> CompileConfigLenient) so the DuplicatePrefixes /
// TrailingTokens taints are the ones production produces, not hand-set
// fixture state.

func dupCfg14967(t *testing.T, bookBody string) *config.Config {
	t.Helper()
	text := `security { address-book { global { ` + bookBody + ` } } zones { security-zone trust; security-zone untrust; } policies { from-zone trust to-zone untrust { policy p { match { source-address A; destination-address any; application any; } then { deny; } } } } }`
	p := config.NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot: %v", err)
	}
	return cfg
}

func TestTolerantDuplicateAddressNotEnforced14967(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"duplicate prefixes", `address A 10.0.0.1/32; address A 10.0.0.2/32;`},
		{"trailing token", `address A 10.0.0.1/32 bogus;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dupCfg14967(t, tc.body)
			a := cfg.Security.AddressBook.Addresses["A"]
			if a == nil {
				t.Fatalf("A missing")
			}
			if a.UsableValue() != "" {
				t.Fatalf("tainted A usable = %q, want refused", a.UsableValue())
			}
			// Neither authored prefix may be published for A.
			books, _, err := buildAddressBookTable(cfg)
			if err != nil {
				t.Fatalf("buildAddressBookTable: %v", err)
			}
			for _, row := range books {
				for _, pfx := range append(append([]string{}, row.PrefixesV4...), row.PrefixesV6...) {
					if pfx == "10.0.0.1/32" || pfx == "10.0.0.2/32" {
						t.Fatalf("tainted prefix %q published in row %+v", pfx, row)
					}
				}
			}
			// The referencing deny must take the unsupported-address
			// sentinel (whole-snapshot fail-closed), never arm on A.
			rules, err := buildPolicySnapshots(cfg)
			if err != nil {
				t.Fatalf("buildPolicySnapshots: %v", err)
			}
			found := false
			for _, r := range rules {
				blob := r.SourceAddresses
				if strings.Contains(strings.Join(blob, ","), unsupportedAddressSentinel) {
					found = true
				}
				for _, lit := range blob {
					if lit == "10.0.0.1/32" || lit == "10.0.0.2/32" {
						t.Fatalf("policy armed on tainted prefix %q: %+v", lit, r)
					}
				}
			}
			if !found {
				t.Fatalf("no rule carries %q sentinel: %+v", unsupportedAddressSentinel, rules)
			}
		})
	}
}

// Control: a clean entry through the same path still publishes and arms.
func TestTolerantCleanAddressEnforced14967(t *testing.T) {
	cfg := dupCfg14967(t, `address A 10.0.0.1/32;`)
	rules, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	books, _, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatalf("buildAddressBookTable: %v", err)
	}
	published := false
	for _, row := range books {
		for _, pfx := range row.PrefixesV4 {
			if pfx == "10.0.0.1/32" {
				published = true
			}
		}
	}
	if !published {
		t.Fatalf("clean prefix not published: %+v", books)
	}
	for _, r := range rules {
		if strings.Contains(strings.Join(r.SourceAddresses, ","), unsupportedAddressSentinel) {
			t.Fatalf("clean policy unexpectedly sentinel: %+v", r)
		}
	}
}
