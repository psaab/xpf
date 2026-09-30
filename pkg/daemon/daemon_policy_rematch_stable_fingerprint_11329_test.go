package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func rematchPolicy11329(name, source string) *config.Policy {
	return &config.Policy{
		Name:   name,
		Action: config.PolicyPermit,
		Match:  config.PolicyMatch{SourceAddresses: []string{source}},
	}
}

func rematchPair11329(from, to string, policies ...*config.Policy) *config.ZonePairPolicies {
	return &config.ZonePairPolicies{FromZone: from, ToZone: to, Policies: policies}
}

func rematchConfig11329(pairs ...*config.ZonePairPolicies) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = pairs
	cfg.Security.PolicyRematch = true
	cfg.Security.PolicyRematchExtensive = true
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses:   map[string]*config.Address{},
		AddressSets: map[string]*config.AddressSet{},
	}
	return cfg
}

func TestPolicyRematchExtensiveIgnoresPositionalPolicyIDs11329(t *testing.T) {
	policy := rematchPolicy11329
	pair := rematchPair11329
	cfg := rematchConfig11329
	tests := []struct {
		name string
		key  string
		old  *config.Config
		new  *config.Config
	}{
		{
			name: "insert before unchanged policy",
			key:  "trust->untrust/p-target",
			old: cfg(pair("trust", "untrust",
				policy("p-first", "10.0.0.1/32"),
				policy("p-target", "10.0.0.2/32"),
				policy("p-tail", "10.0.0.3/32"),
			)),
			new: cfg(pair("trust", "untrust",
				policy("p-first", "10.0.0.1/32"),
				policy("p-added", "10.0.0.4/32"),
				policy("p-target", "10.0.0.2/32"),
				policy("p-tail", "10.0.0.3/32"),
			)),
		},
		{
			name: "delete before unchanged policy",
			key:  "trust->untrust/p-target",
			old: cfg(pair("trust", "untrust",
				policy("p-first", "10.0.0.1/32"),
				policy("p-removed", "10.0.0.4/32"),
				policy("p-target", "10.0.0.2/32"),
				policy("p-tail", "10.0.0.3/32"),
			)),
			new: cfg(pair("trust", "untrust",
				policy("p-first", "10.0.0.1/32"),
				policy("p-target", "10.0.0.2/32"),
				policy("p-tail", "10.0.0.3/32"),
			)),
		},
		{
			name: "reorder unchanged policies",
			key:  "trust->untrust/p-target",
			old: cfg(pair("trust", "untrust",
				policy("p-first", "10.0.0.1/32"),
				policy("p-target", "10.0.0.2/32"),
				policy("p-tail", "10.0.0.3/32"),
			)),
			new: cfg(pair("trust", "untrust",
				policy("p-first", "10.0.0.1/32"),
				policy("p-tail", "10.0.0.3/32"),
				policy("p-target", "10.0.0.2/32"),
			)),
		},
		{
			name: "insert earlier zone-pair set",
			key:  "dmz->wan/p-target",
			old: cfg(
				pair("trust", "untrust", policy("p-first", "10.0.0.1/32")),
				pair("dmz", "wan",
					policy("p-target", "10.0.0.2/32"),
					policy("p-tail", "10.0.0.3/32"),
				),
			),
			new: cfg(
				pair("guest", "wan", policy("p-added", "10.0.0.4/32")),
				pair("trust", "untrust", policy("p-first", "10.0.0.1/32")),
				pair("dmz", "wan",
					policy("p-target", "10.0.0.2/32"),
					policy("p-tail", "10.0.0.3/32"),
				),
			),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldIDs := dpuserspace.PolicyIDsByStableKey(tc.old)
			newIDs := dpuserspace.PolicyIDsByStableKey(tc.new)
			oldID, newID := oldIDs[tc.key], newIDs[tc.key]
			if oldID == 0 || newID == 0 || oldID == newID {
				t.Fatalf("precondition: target ID did not shift: old=%d new=%d", oldID, newID)
			}

			oldFP := dpuserspace.PolicyResolvedFingerprints(tc.old)[tc.key]
			newFP := dpuserspace.PolicyResolvedFingerprints(tc.new)[tc.key]
			if oldFP == "" || newFP == "" {
				t.Fatalf("precondition: target fingerprint missing: old=%q new=%q", oldFP, newFP)
			}
			if oldFP != newFP {
				t.Errorf("unchanged target fingerprint changed with positional ID %d -> %d", oldID, newID)
			}
			if got := changedPolicyRuntimeIDs(tc.old, tc.new, nil, nil); len(got) != 0 {
				t.Errorf("extensive rematch cleared unchanged policies after ID shift %d -> %d: %v",
					oldID, newID, got)
			}
		})
	}
}
