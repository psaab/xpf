package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14946 (D7-01): a malformed entry inside a REFERENCED prefix-list reaches
// the lenient / peer-sync snapshot builder unchecked. Strict commit rejects
// it (#7273), but the tolerant path only warns: ResolveFilterPrefixListAddrs
// copied the entry verbatim (positive) or into the except set, and the Rust
// parse_address dropped it PER-TOKEN. A discard/reject term then enforced
// only the surviving subset and the dropped range fell through to implicit
// accept (positive leg); an except term matched the dropped range the
// operator wrote to exclude (except leg, positive-wins drop).
// FAIL-ON-REVERT: without the AddressUnrepresentable marking in
// buildFilterTermSnapshots, every malformed cell below goes RED.
func TestFilterSnapshotMalformedReferencedPrefixFailsClosed14946(t *testing.T) {
	cases := []struct {
		name      string
		term      *config.FirewallFilterTerm
		lists     map[string]*config.PrefixList
		wantAddrs []string // surviving wire addrs that must still ride along
		checkDst  bool
	}{
		{
			name: "discard positive source partially malformed",
			term: &config.FirewallFilterTerm{Name: "t", Action: "discard",
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt"}}},
			lists:     map[string]*config.PrefixList{"mgmt": {Name: "mgmt", Prefixes: []string{"10.0.0.0/8", "10.0.0.0/99"}}},
			wantAddrs: []string{"10.0.0.0/8", "10.0.0.0/99"},
		},
		{
			name: "accept positive destination partially malformed",
			term: &config.FirewallFilterTerm{Name: "t", Action: "accept",
				DestPrefixLists: []config.PrefixListRef{{Name: "mgmt"}}},
			lists:     map[string]*config.PrefixList{"mgmt": {Name: "mgmt", Prefixes: []string{"192.168.0.0/16", "bogus-entry"}}},
			wantAddrs: []string{"192.168.0.0/16", "bogus-entry"},
			checkDst:  true,
		},
		{
			name: "discard sole except partially malformed",
			term: &config.FirewallFilterTerm{Name: "t", Action: "discard",
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt", Except: true}}},
			lists:     map[string]*config.PrefixList{"mgmt": {Name: "mgmt", Prefixes: []string{"10.0.0.0/8", "10.0.0.0/99"}}},
			wantAddrs: []string{"10.0.0.0/8", "10.0.0.0/99"},
		},
		{
			name: "accept zone-scoped entry in referenced list",
			term: &config.FirewallFilterTerm{Name: "t", Action: "accept",
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt"}}},
			lists:     map[string]*config.PrefixList{"mgmt": {Name: "mgmt", Prefixes: []string{"10.0.0.0/8", "fe80::1%eth0"}}},
			wantAddrs: []string{"10.0.0.0/8", "fe80::1%eth0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.PolicyOptions.PrefixLists = tc.lists
			cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
				"f": {Name: "f", Terms: []*config.FirewallFilterTerm{tc.term}},
			}
			term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
			if !term.AddressUnrepresentable {
				t.Fatalf("malformed referenced prefix-list entry must set AddressUnrepresentable (#14946 fail-open), got %+v", term)
			}
			addrs := term.SourceAddresses
			if tc.checkDst {
				addrs = term.DestAddresses
			}
			if strings.Join(addrs, ",") != strings.Join(tc.wantAddrs, ",") {
				t.Errorf("wire addrs = %v, want verbatim %v (Rust rejects whole snapshot on marker, never narrowed)", addrs, tc.wantAddrs)
			}
		})
	}
}

// End-to-end through the tolerant compiler: the strict gate rejects the
// malformed entry, the lenient path warns and still builds a snapshot —
// which must carry the fail-closed marker.
func TestFilterSnapshotMalformedReferencedPrefixLenient14946(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set policy-options prefix-list mgmt 10.0.0.0/99",
		"set firewall family inet filter f term t from source-prefix-list mgmt",
		"set firewall family inet filter f term t then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile must reject the malformed referenced entry (#7273 control)")
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must remain bootable: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "10.0.0.0/99") {
		t.Fatalf("lenient compile must warn on the malformed entry, got %v", cfg.Warnings)
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.AddressUnrepresentable {
		t.Fatalf("leniently-loaded malformed referenced entry must set AddressUnrepresentable (#14946), got %+v", term)
	}
}

// Control: a fully parseable referenced list (including a bare host entry)
// must NOT be marked — otherwise every legitimate prefix-list filter would
// refuse its snapshot.
func TestFilterSnapshotCleanReferencedPrefixNotMarked14946(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt": {Name: "mgmt", Prefixes: []string{"10.0.0.0/8", "192.168.1.1", "2001:db8::/32"}},
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{
			{Name: "t", Action: "discard", SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt"}}},
		}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.AddressUnrepresentable {
		t.Fatalf("clean referenced prefix-list must not set AddressUnrepresentable, got %+v", term)
	}
	if len(term.SourceAddresses) != 3 {
		t.Fatalf("clean entries must all ride the wire, got %v", term.SourceAddresses)
	}
}
