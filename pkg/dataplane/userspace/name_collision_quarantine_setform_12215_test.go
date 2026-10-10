package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12215: the canonical Junos set-form `set security address-book red address
// shared ...` packs the whole tail as ONE leaf under `address-book` (SetPath:
// no schema child for the book name, only `global`). The #12049 collision
// recorder walks only FindChildren("address"/"address-set"), which is empty
// for the packed leaf — so the token escapes the quarantine and the policy
// reference silently resolves to the unrelated global row. The set-form shape
// must quarantine exactly like the braced shape pinned by
// TestLenientNamedAddressBookDropQuarantinesCollision12049.
func TestLenientSetFormNamedAddressBookDropQuarantinesCollision12215(t *testing.T) {
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
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Security.AddressBook == nil {
				t.Fatal("lenient compile produced no global address book")
			}
			if _, ok := cfg.Security.AddressBook.CollidingNames["shared"]; !ok {
				t.Fatalf("set-form named-book entry must quarantine the colliding global token, CollidingNames=%v", cfg.Security.AddressBook.CollidingNames)
			}
			if tc.name == "address-set" {
				if _, ok := cfg.Security.AddressBook.CollidingNames["m"]; ok {
					t.Fatalf("address-set member reference must not be quarantined as a named-book definition, CollidingNames=%v", cfg.Security.AddressBook.CollidingNames)
				}
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 1 {
				t.Fatalf("build policy snapshots: rules=%d err=%v", len(rules), err)
			}
			if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
				t.Fatalf("set-form entry dropped from named address book must not fall through to the same-named global object: literals=%v addresses=%v", rules[0].SourceLiterals, rules[0].SourceAddresses)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "shared") {
				t.Fatalf("content-rejection mirror must name dropped set-form named-book collision, got %q", reasons)
			}
		})
	}
}
