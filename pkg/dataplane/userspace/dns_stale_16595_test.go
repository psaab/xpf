package userspace

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16595/#17782 — stale SERVFAIL answers stay concrete; empty failed and
// cold-cache-unresolved names get no address sentinel. Deny and excluded
// rules fail closed per rule, while a positive permit with unavailable DNS
// matches none and keeps the snapshot loadable.

func dnsCfg16595(bad *config.Address) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
		"dmz":     {Name: "dmz", Interfaces: []string{"reth0.81"}},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"bad":  bad,
			"good": {Name: "good", Value: "10.0.0.5/32"},
		},
	}
	cfg.Applications.Applications = map[string]*config.Application{
		"good-tcp": {Name: "good-tcp", Protocol: "tcp", DestinationPort: "443"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "block-bad", Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"bad"}, Applications: []string{"any"}}, Action: config.PolicyDeny},
		}},
		{FromZone: "trust", ToZone: "dmz", Policies: []*config.Policy{
			{Name: "permit-good", Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"good"}, Applications: []string{"good-tcp"}}, Action: config.PolicyPermit},
		}},
	}
	return cfg
}

func countSentinels16595(rules []PolicyRuleSnapshot) (addr, app int) {
	raw, _ := json.Marshal(rules)
	addr = strings.Count(string(raw), unsupportedAddressSentinel)
	app = strings.Count(string(raw), unsupportedApplicationSentinel)
	return addr, app
}

func TestDNSStaleRetainedNoSentinel16595(t *testing.T) {
	cfg := dnsCfg16595(&config.Address{Name: "bad", DNSName: "bad.example.com", DNSAddresses: []string{"203.0.113.10/32"}, DNSLookupFailed: true})
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%d err=%v", len(rules), err)
	}
	addr, app := countSentinels16595(rules)
	if addr != 0 || app != 0 {
		t.Fatalf("stale retained must emit no sentinel, addr=%d app=%d rules=%s", addr, app, mustJSON16595(rules))
	}
	// Stale prefix must reach the book row.
	books, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatalf("books: %v", err)
	}
	id, ok := nameToID["bad"]
	if !ok {
		t.Fatal("bad must have a book ID")
	}
	found := false
	for _, b := range books {
		if b.ID == id && strings.Join(b.PrefixesV4, ",") == "203.0.113.10/32" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale prefix not in book row: %+v", books)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected must be empty, got %v", snap.Capabilities.PolicyContentRejected)
	}
}

func dnsUnavailableAddressCases16595() []struct {
	name    string
	address *config.Address
} {
	return []struct {
		name    string
		address *config.Address
	}{
		{"lookup-failed", &config.Address{Name: "bad", DNSName: "bad.example.com", DNSLookupFailed: true}},
		{"unresolved", &config.Address{Name: "bad", DNSName: "bad.example.com", DNSUnresolved: true}},
	}
}

func TestDNSNeverResolvedDenyPerRuleFailClosed16595(t *testing.T) {
	for _, tc := range dnsUnavailableAddressCases16595() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dnsCfg16595(tc.address)
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 2 {
				t.Fatalf("rules=%d err=%v", len(rules), err)
			}
			addr, _ := countSentinels16595(rules)
			if addr != 0 {
				t.Fatalf("unavailable DNS must emit NO address sentinel, got %d in %s", addr, mustJSON16595(rules))
			}
			for _, r := range rules {
				raw, _ := json.Marshal(r)
				if r.Name == "block-bad" && !strings.Contains(string(raw), dnsUnavailableDestinationApplicationSentinel) {
					t.Fatalf("deny with unavailable destination DNS must carry its per-side quarantine marker, got %s", raw)
				}
				if r.Name == "block-bad" && strings.Contains(string(raw), unsupportedApplicationSentinel) {
					t.Fatalf("DNS quarantine must not use the whole-snapshot sentinel, got %s", raw)
				}
				if r.Name == "permit-good" && (strings.Contains(string(raw), unsupportedApplicationSentinel) ||
					strings.Contains(string(raw), dnsUnavailableSourceApplicationSentinel) ||
					strings.Contains(string(raw), dnsUnavailableDestinationApplicationSentinel)) {
					t.Fatalf("sibling permit-good must stay clean, got %s", raw)
				}
			}
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			var sawDNSQuarantineDiagnostic bool
			for _, reason := range snap.Capabilities.PolicyContentRejected {
				if strings.Contains(reason, "unavailable DNS address resolution") &&
					strings.Contains(reason, `destination-address "bad"`) &&
					strings.Contains(reason, "quarantined to deny") &&
					strings.Contains(reason, "sibling rules remain active") {
					sawDNSQuarantineDiagnostic = true
				}
			}
			if !sawDNSQuarantineDiagnostic {
				t.Fatalf("Go DNS quarantine diagnostic must stay visible, got %v", snap.Capabilities.PolicyContentRejected)
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
				t.Fatalf("DNS per-rule quarantine must not block snapshot operations: %v", reasons)
			}
		})
	}
}

func TestDNSNeverResolvedPermitMatchNoneLoads16595(t *testing.T) {
	for _, tc := range dnsUnavailableAddressCases16595() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dnsCfg16595(tc.address)
			cfg.Security.Policies = []*config.ZonePairPolicies{
				{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
					{Name: "permit-bad", Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"bad"}, Applications: []string{"any"}}, Action: config.PolicyPermit},
					{Name: "block-good", Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"good"}, Applications: []string{"any"}}, Action: config.PolicyDeny},
				}},
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 2 {
				t.Fatalf("rules=%d err=%v", len(rules), err)
			}
			addr, app := countSentinels16595(rules)
			if addr != 0 || app != 0 {
				t.Fatalf("positive permit match-none must emit no sentinel, addr=%d app=%d", addr, app)
			}
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if len(snap.Capabilities.PolicyContentRejected) != 0 {
				t.Fatalf("DNS match-none permit must keep the snapshot loadable, got %v", snap.Capabilities.PolicyContentRejected)
			}
			books, nameToID, err := buildAddressBookTable(cfg)
			if err != nil {
				t.Fatalf("address book: %v", err)
			}
			id, ok := nameToID["bad"]
			if !ok {
				t.Fatal("bad must still route as a book reference")
			}
			for _, book := range books {
				if book.ID == id {
					if len(book.PrefixesV4) != 0 || len(book.PrefixesV6) != 0 {
						t.Fatalf("unavailable DNS row must be empty, got %+v", book)
					}
					return
				}
			}
			t.Fatal("bad address book row missing")
		})
	}
}

func TestDNSExcludedNeverResolvedFailsClosed16595(t *testing.T) {
	for _, tc := range dnsUnavailableAddressCases16595() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dnsCfg16595(tc.address)
			cfg.Security.Policies = []*config.ZonePairPolicies{
				{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
					{Name: "permit-not-bad", Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"bad"}, DestinationAddressExcluded: true, Applications: []string{"any"}}, Action: config.PolicyPermit},
				}},
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 1 {
				t.Fatalf("rules=%d err=%v", len(rules), err)
			}
			addr, _ := countSentinels16595(rules)
			if addr != 0 {
				t.Fatalf("excluded DNS must emit no address sentinel, got %s", mustJSON16595(rules))
			}
			raw, _ := json.Marshal(rules[0])
			if !strings.Contains(string(raw), dnsUnavailableDestinationApplicationSentinel) ||
				strings.Contains(string(raw), unsupportedApplicationSentinel) {
				t.Fatalf("excluded unavailable destination must carry only its per-side DNS quarantine marker, got %s", raw)
			}
			if rules[0].Action != string(policyActionPermit) {
				t.Fatalf("Go preserves configured action for Rust quarantine handling, got %q", rules[0].Action)
			}
		})
	}
}

func mustJSON16595(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func TestJunosHostProgramSurvivesDNSFailure16595(t *testing.T) {
	// Compile a valid address-book entry, then replace its value with resolver
	// state. This models a previously accepted DNS name as the cache changes.
	cfg := residualCfg(t, residualBase, []string{
		"set security address-book global address bad-dns 10.0.0.9/32",
	}, policy("deny-bad", "bad-host", "any", "any", "deny"), policy("deny-dns", "bad-dns", "any", "any", "deny"))
	a := cfg.Security.AddressBook.Addresses["bad-dns"]
	a.Value = ""
	a.DNSName = "bad.example.com"
	// Simulate SERVFAIL with no current answer.
	a.DNSAddresses = nil
	a.DNSLookupFailed = true
	if got := residualRuleCount(cfg); got != 1 {
		t.Fatalf("junos-host rules after SERVFAIL = %d, want 1 (static retained; dns entry match-none projects no rule)", got)
	}
	progs := BuildJunosHostPrograms(cfg)
	if len(progs) != 1 {
		t.Fatalf("programs = %d, want 1", len(progs))
	}
	// Successful-empty control: program is withdrawn (static gate unchanged).
	a.DNSLookupFailed = false
	if got := residualRuleCount(cfg); got != 0 {
		t.Fatalf("successful-empty dns-name must keep the pre-#16595 gate (program withdrawn), got %d rules", got)
	}
	// Stale-retained control: the dns rule renders alongside the static rule.
	a.DNSLookupFailed = true
	a.DNSAddresses = []string{"10.0.0.9/32"}
	found := false
	for _, p := range BuildJunosHostPrograms(cfg) {
		for _, r := range append(append([]config.JunosHostDenyRule{}, p.RulesV4...), p.RulesV6...) {
			for _, s := range r.Src {
				if s == "10.0.0.9/32" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("stale dns prefix 10.0.0.9/32 must render in the junos-host program")
	}
}

const dnsQuarantineFixture17722 = "../../../testdata/dns_quarantine_17722.json"

// TestDNSQuarantineSnapshotFixtureFresh17722 pins the full ConfigSnapshot that
// Rust parses in policy_tests.rs, so the cross-language regression exercises
// the exact Go builder wire rather than a hand-transcribed snapshot.
func TestDNSQuarantineSnapshotFixtureFresh17722(t *testing.T) {
	cfg := dnsCfg16595(&config.Address{
		Name:            "bad",
		DNSName:         "bad.example.com",
		DNSLookupFailed: true,
	})
	snapshot, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	// GeneratedAt is an envelope timestamp ignored by policy parsing.
	snapshot.GeneratedAt = time.Time{}
	got, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_17722") == "1" {
		if err := os.WriteFile(dnsQuarantineFixture17722, got, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}
	want, err := os.ReadFile(dnsQuarantineFixture17722)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Go builder DNS quarantine snapshot drifted from %s; regenerate with UPDATE_17722=1 and rerun Go/Rust cells",
			dnsQuarantineFixture17722)
	}
}
