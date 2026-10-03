package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestUnknownAddressSetMemberPoisonsNestedRuntimeResolution11822(t *testing.T) {
	cfg := newBookCfg(map[string]string{
		"good":     "10.0.0.1/32",
		"good-too": "10.0.0.2/32",
	})
	cfg.Security.AddressBook.AddressSets = map[string]*config.AddressSet{
		"bad": {
			Name:           "bad",
			Addresses:      []string{"good"},
			UnknownMembers: []string{"addres"},
		},
		"parent": {
			Name:        "parent",
			Addresses:   []string{"good-too"},
			AddressSets: []string{"bad"},
		},
	}

	if expanded, ok := resolveUserspaceAddressBookEntry(cfg, "parent"); ok {
		t.Fatalf("runtime address resolution accepted the surviving subset %v", expanded)
	}
	if representable := nameRepresentable(cfg.Security.AddressBook, nil, nil, "parent", map[string]bool{}); representable {
		t.Fatal("address-set representability accepted a parent containing an unknown member")
	}
	if v4, v6 := expandBookNameToCIDRs(cfg, nil, "parent"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("address-book row retained partial prefixes: v4=%v v6=%v", v4, v6)
	}
	if prefixes := resolveNATAddressNamePrefixes(cfg, nil, "parent"); len(prefixes) != 0 {
		t.Fatalf("NAT address resolution retained partial prefixes: %v", prefixes)
	}
}
func TestUnknownAddressSetMemberKeepsDenyArmedWithSentinel11822(t *testing.T) {
	cfg := newBookCfg(map[string]string{
		"good":     "10.0.0.1/32",
		"good-too": "10.0.0.2/32",
	})
	cfg.Security.AddressBook.AddressSets = map[string]*config.AddressSet{
		"bad": {
			Name:           "bad",
			Addresses:      []string{"good"},
			UnknownMembers: []string{"addres"},
		},
		"parent": {
			Name:        "parent",
			Addresses:   []string{"good-too"},
			AddressSets: []string{"bad"},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "deny-underpopulated",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"parent"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyDeny,
		}},
	}}

	snapshot, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if len(snapshot.Policies) != 1 {
		t.Fatalf("snapshot policies = %d, want one deny policy", len(snapshot.Policies))
	}
	rule := snapshot.Policies[0]
	hasSentinel := func(values []string) bool {
		for _, value := range values {
			if value == unsupportedAddressSentinel {
				return true
			}
		}
		return false
	}
	if !hasSentinel(rule.DestinationLiterals) || !hasSentinel(rule.DestinationAddresses) {
		t.Fatalf("under-populated deny lost its fail-closed sentinel: literals=%v legacy=%v",
			rule.DestinationLiterals, rule.DestinationAddresses)
	}
	if len(rule.DestinationBookIDs) != 0 {
		t.Fatalf("under-populated deny retained book IDs beside sentinel: %v", rule.DestinationBookIDs)
	}
}
