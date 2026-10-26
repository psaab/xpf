package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12215: `set security address-book red ...` is a supported named-book shape
// (#15672), not a dropped unknown book. An unattached book is isolated from
// the global namespace; the same-named global token remains resolvable.
func TestSetFormNamedAddressBookScopeDoesNotQuarantineGlobalCollision12215(t *testing.T) {
	pol := "set security policies from-zone trust to-zone untrust policy p1 "
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy deny-all",
		pol + "match source-address shared",
		pol + "match destination-address any",
		pol + "match application any",
		pol + "then deny",
	}
	cases := []struct {
		name  string
		books []string
	}{
		{
			name: "address",
			books: []string{
				"set security address-book global address shared 203.0.113.0/24",
				"set security address-book red address shared 10.0.0.0/8",
			},
		},
		{
			name: "address-set",
			books: []string{
				"set security address-book global address m 10.9.9.9/32",
				"set security address-book global address-set shared address m",
				"set security address-book red address m 10.9.9.8/32",
				"set security address-book red address-set shared address m",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := append(append([]string{}, base...), tc.books...)
			tree := &config.ConfigTree{}
			for _, l := range lines {
				p, err := config.ParseSetCommand(l)
				if err != nil {
					t.Fatalf("parse %q: %v", l, err)
				}
				if err := tree.SetPath(p); err != nil {
					t.Fatalf("setpath %q: %v", l, err)
				}
			}
			if err := config.SchemaValidate(tree); err != nil {
				t.Fatalf("strict schema rejected supported set-form named book: %v", err)
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile rejected supported set-form named book: %v", err)
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build policy snapshots: %v", err)
			}
			assertUnattachedNamedBookLeavesGlobalReference12049(t, cfg, rules, "shared")
			red := cfg.Security.NamedAddressBooks["red"]
			if tc.name == "address" {
				if got := red.Addresses["shared"].UsableValue(); got != "10.0.0.0/8" {
					t.Fatalf("named-book address = %q, want 10.0.0.0/8", got)
				}
			} else if red.AddressSets["shared"] == nil {
				t.Fatal("named-book address-set shared was not retained")
			}
		})
	}
}
