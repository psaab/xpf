package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16595 — SERVFAIL arm: no address sentinel, stale prefix retained, sibling
// rules unmarked; never-resolved deny is per-rule fail-closed (application
// sentinel, no address sentinel / no PolicyContentRejected); never-resolved
// positive permit is match-none and the snapshot loads.

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

func TestDNSNeverResolvedDenyPerRuleFailClosed16595(t *testing.T) {
	cfg := dnsCfg16595(&config.Address{Name: "bad", DNSName: "bad.example.com", DNSLookupFailed: true})
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%d err=%v", len(rules), err)
	}
	addr, _ := countSentinels16595(rules)
	if addr != 0 {
		t.Fatalf("never-resolved DNS must emit NO address sentinel (sentinelRules), got %d in %s", addr, mustJSON16595(rules))
	}
	// The deny rule is poisoned per-rule (application sentinel); sibling is clean.
	for _, r := range rules {
		raw, _ := json.Marshal(r)
		if r.Name == "block-bad" && !strings.Contains(string(raw), unsupportedApplicationSentinel) {
			t.Fatalf("deny with never-resolved DNS must be per-rule fail-closed, got %s", raw)
		}
		if r.Name == "permit-good" && strings.Contains(string(raw), unsupportedApplicationSentinel) {
			t.Fatalf("sibling permit-good must stay clean, got %s", raw)
		}
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	for _, reason := range snap.Capabilities.PolicyContentRejected {
		if strings.Contains(reason, "bad") {
			t.Fatalf("DNS cause must not be a PolicyContentRejected entry: %v", snap.Capabilities.PolicyContentRejected)
		}
	}
}

func TestDNSNeverResolvedPermitMatchNoneLoads16595(t *testing.T) {
	cfg := dnsCfg16595(&config.Address{Name: "bad", DNSName: "bad.example.com", DNSLookupFailed: true})
	// Flip roles: bad is the permit destination, good is a deny sibling.
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
	// Book row for bad is empty (match-none).
	_, nameToID, _ := buildAddressBookTable(cfg)
	if _, ok := nameToID["bad"]; !ok {
		t.Fatal("bad must still route as a book reference")
	}
}

func TestDNSExcludedNeverResolvedFailsClosed16595(t *testing.T) {
	cfg := dnsCfg16595(&config.Address{Name: "bad", DNSName: "bad.example.com", DNSLookupFailed: true})
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
	if !strings.Contains(string(raw), unsupportedApplicationSentinel) {
		t.Fatalf("excluded never-resolved side must be per-rule fail-closed, got %s", raw)
	}
}

func mustJSON16595(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func TestJunosHostProgramSurvivesDNSFailure16595(t *testing.T) {
	// Static deny + dns-name deny to junos-host from untrust. After SERVFAIL
	// (flag set, no addresses) the program must still render the static rule.
	cfg := residualCfg(t, residualBase, []string{
		"set security address-book global address bad-dns dns-name bad.example.com",
	}, policy("deny-bad", "bad-host", "any", "any", "deny"), policy("deny-dns", "bad-dns", "any", "any", "deny"))
	// Simulate SERVFAIL with no prior answer.
	a := cfg.Security.AddressBook.Addresses["bad-dns"]
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
