package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type dp13162 struct {
	DataPlane
	rules   []PolicyRule
	entries map[uint32]string // addrID -> CIDR
	members [][2]uint32
}

func (d *dp13162) SetZonePairPolicy(uint16, uint16, PolicySet) error { return nil }
func (d *dp13162) SetPolicyRule(_ uint32, _ uint32, r PolicyRule) error {
	d.rules = append(d.rules, r)
	return nil
}
func (d *dp13162) DeleteStaleZonePairPolicies(map[ZonePairKey]bool) {}
func (d *dp13162) ClearAddressBookV4() error                        { return nil }
func (d *dp13162) ClearAddressBookV6() error                        { return nil }
func (d *dp13162) ClearAddressMembership() error                    { return nil }
func (d *dp13162) SetAddressBookEntry(cidr string, id uint32) error {
	if d.entries == nil {
		d.entries = make(map[uint32]string)
	}
	d.entries[id] = cidr
	return nil
}
func (d *dp13162) SetAddressMembership(member, set uint32) error {
	d.members = append(d.members, [2]uint32{member, set})
	return nil
}

func cfg13162(src, dst string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
	}
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"threat-feed-addrs": {Name: "threat-feed-addrs"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name: "p1", Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses: []string{src}, DestinationAddresses: []string{dst},
				Applications: []string{"any"},
			},
		}},
	}}
	return cfg
}

func compile13162(t *testing.T, cfg *config.Config) (*dp13162, *CompileResult, error) {
	t.Helper()
	dp := &dp13162{}
	res := &CompileResult{
		ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32),
		AppIDs: make(map[string]uint32), implicitSets: make(map[string]uint32),
		nextAddrID: 1,
	}
	assignZoneIDs(res, cfg)
	if err := compileAddressBook(dp, cfg, res); err != nil {
		t.Fatalf("compileAddressBook: %v", err)
	}
	err := compilePolicies(dp, cfg, res)
	return dp, res, err
}

// #13162 (D4-03): the legacy compiler must lower wildcard and literal tokens,
// and reject feed-bound names whose runtime prefixes it cannot access rather
// than treating them as match-any.
func TestCompilePoliciesAddressTokens13162(t *testing.T) {
	cases := []struct {
		src, wantCIDR string
		// Expected LPM address-book entry materialized for this token.
	}{
		{"any-ipv4", "0.0.0.0/0"},
		{"any4", "0.0.0.0/0"},
		{"any-ipv6", "::/0"},
		{"any6", "::/0"},
		{"10.20.30.0/24", "10.20.30.0/24"},
		{"10.20.30.7", "10.20.30.7/32"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tc := range cases {
		dp, _, err := compile13162(t, cfg13162(tc.src, "any"))
		if err != nil {
			t.Errorf("%s: compilePolicies: %v", tc.src, err)
			continue
		}
		if len(dp.rules) != 1 {
			t.Fatalf("%s: rules = %d, want 1", tc.src, len(dp.rules))
		}
		assertToken := func(direction string, ruleID uint32) {
			if strings.HasPrefix(tc.src, "any-ipv") || strings.HasPrefix(tc.src, "any") {
				var fallbackID uint32
				for id, cidr := range dp.entries {
					if cidr == tc.wantCIDR {
						fallbackID = id
					}
				}
				if fallbackID == 0 || !has13162Membership(dp.members, fallbackID, ruleID) {
					t.Errorf("%s %s: wildcard set %d omits fallback id %d; entries=%v memberships=%v", tc.src, direction, ruleID, fallbackID, dp.entries, dp.members)
				}
			} else if dp.entries[ruleID] != tc.wantCIDR {
				t.Errorf("%s %s: address ID %d maps to %q, want %q", tc.src, direction, ruleID, dp.entries[ruleID], tc.wantCIDR)
			}
		}
		assertToken("source", dp.rules[0].SrcAddrID)
		dp, _, err = compile13162(t, cfg13162("any", tc.src))
		if err != nil {
			t.Errorf("%s destination: compilePolicies: %v", tc.src, err)
			continue
		}
		if len(dp.rules) != 1 {
			t.Fatalf("%s destination: rules=%+v", tc.src, dp.rules)
		}
		assertToken("destination", dp.rules[0].DstAddrID)
	}
	if _, _, err := compile13162(t, cfg13162("threat-feed-addrs", "any")); err == nil || !strings.Contains(err.Error(), "no feed prefixes") {
		t.Errorf("dynamic feed without feed data: expected fail-closed error, got %v", err)
	}

	// Mixed named + literal + wildcard: literal materializes, wildcard drops.
	cfg := cfg13162("any", "any")
	cfg.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"10.0.0.0/8", "any-ipv6"}
	dp, _, err := compile13162(t, cfg)
	if err != nil {
		t.Fatalf("mixed: %v", err)
	}
	if len(dp.rules) != 1 || len(dp.members) != 5 {
		t.Fatalf("mixed: rules=%+v memberships=%v entries=%v", dp.rules, dp.members, dp.entries)
	}
	if _, _, err := compile13162(t, cfg13162("999.1.2.3/24", "any")); err == nil {
		t.Errorf("invalid CIDR: expected error, got nil")
	}
	// A family wildcard must also include more-specific address-book hits;
	// those IDs take precedence over the /0 LPM fallback.
	family := cfg13162("any-ipv4", "any")
	family.Security.AddressBook = &config.AddressBook{Addresses: map[string]*config.Address{
		"private-v4": {Name: "private-v4", Value: "10.0.0.0/8"},
		"private-v6": {Name: "private-v6", Value: "2001:db8::/32"},
	}}
	dp, res, err := compile13162(t, family)
	if err != nil {
		t.Fatalf("family wildcard with address book: %v", err)
	}
	setID := dp.rules[0].SrcAddrID
	if !has13162Membership(dp.members, res.AddrIDs["private-v4"], setID) {
		t.Errorf("IPv4 wildcard set %d omits more-specific v4 book ID %d", setID, res.AddrIDs["private-v4"])
	}
	if has13162Membership(dp.members, res.AddrIDs["private-v6"], setID) {
		t.Errorf("IPv4 wildcard set %d includes IPv6 book ID %d", setID, res.AddrIDs["private-v6"])
	}
	global := cfg13162("any-ipv4", "any")
	global.Security.GlobalPolicies = global.Security.Policies[0].Policies
	global.Security.Policies = nil
	dp, _, err = compile13162(t, global)
	if err != nil || len(dp.rules) != 1 {
		t.Errorf("global policy: rules=%+v entries=%v err=%v", dp.rules, dp.entries, err)
	}
	if err == nil {
		var fallbackID uint32
		for id, cidr := range dp.entries {
			if cidr == "0.0.0.0/0" {
				fallbackID = id
			}
		}
		if !has13162Membership(dp.members, fallbackID, dp.rules[0].SrcAddrID) {
			t.Errorf("global any-ipv4 set omits fallback ID %d", fallbackID)
		}
	}
}

func has13162Membership(members [][2]uint32, memberID, setID uint32) bool {
	for _, member := range members {
		if member[0] == memberID && member[1] == setID {
			return true
		}
	}
	return false
}
