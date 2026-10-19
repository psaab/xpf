package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #15666 (V2-04), acceptance criterion 1 at the daemon gate: under
// `policy-rematch extensive`, toggling `then log`, binding/swapping a
// currently-active scheduler-name, or reordering match-list elements must
// NOT mark the policy changed in changedPolicyRuntimeIDs — the fingerprint
// arm (policyReferencedObjectChanged) previously fired on all of these
// because PolicyResolvedFingerprints hashed the raw snapshot JSON.
//
// The scheduler cases pass explicit active maps: old=nil/nil would make
// PolicyInactive treat any named scheduler as inactive, and that
// active->inactive verdict gate (policySchedulerBecameInactive, #4343) is
// a separate, correct trigger that is not under test here.

func nonVerdictConfig15666(apps []string, log *config.PolicyLog, schedulerName string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.PolicyRematch = true
	cfg.Security.PolicyRematchExtensive = true
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses:   map[string]*config.Address{},
		AddressSets: map[string]*config.AddressSet{},
	}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-a": {Name: "app-a", Protocol: "tcp", DestinationPort: "80"},
		"app-b": {Name: "app-b", Protocol: "tcp", DestinationPort: "443"},
	}
	// p-first occupies the overloaded runtime id 0 (never swept); web is
	// the surviving policy whose sessions are under test.
	web := &config.Policy{
		Name:          "web",
		Action:        config.PolicyPermit,
		Log:           log,
		SchedulerName: schedulerName,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"10.0.1.0/24", "10.0.2.0/24"},
			DestinationAddresses: []string{"any"},
			Applications:         apps,
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{
			{Name: "p-first", Action: config.PolicyPermit, Match: config.PolicyMatch{SourceAddresses: []string{"any"}}},
			web,
		},
	}}
	return cfg
}

func TestPolicyRematchExtensiveIgnoresNonVerdictEdits15666(t *testing.T) {
	base := nonVerdictConfig15666([]string{"app-a", "app-b"}, nil, "")
	webID := dpuserspace.PolicyIDsByStableKey(base)["trust->untrust/web"]
	if webID == 0 {
		t.Fatalf("precondition: web id must be non-zero (0 is the overloaded wire value)")
	}
	active := map[string]bool{"active-sched": true, "other-active-sched": true}

	cases := []struct {
		name               string
		newCfg             *config.Config
		oldSched, newSched map[string]bool
	}{
		{"then log toggle", nonVerdictConfig15666([]string{"app-a", "app-b"},
			&config.PolicyLog{SessionInit: true, SessionClose: true}, ""), nil, nil},
		{"bind active scheduler", nonVerdictConfig15666([]string{"app-a", "app-b"}, nil, "active-sched"), nil, active},
		{"swap active scheduler", nonVerdictConfig15666([]string{"app-a", "app-b"}, nil, "other-active-sched"), active, active},
		{"reorder applications", nonVerdictConfig15666([]string{"app-b", "app-a"}, nil, ""), nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := changedPolicyRuntimeIDs(base, tc.newCfg, tc.oldSched, tc.newSched); len(got) != 0 {
				t.Fatalf("#15666: non-verdict edit %q marked policies changed: %v", tc.name, got)
			}
		})
	}

	// Swap case needs the OLD side bound too: rebuild base with the first
	// scheduler so old->new is active->active under a name change only.
	oldSchedBound := nonVerdictConfig15666([]string{"app-a", "app-b"}, nil, "active-sched")
	if got := changedPolicyRuntimeIDs(oldSchedBound, cases[2].newCfg, active, active); len(got) != 0 {
		t.Fatalf("#15666: active->active scheduler swap marked policies changed: %v", got)
	}

	// Control: a real application-definition change under extensive MUST
	// still clear web's sessions (acceptance criterion 2 at the gate).
	redefined := nonVerdictConfig15666([]string{"app-a", "app-b"}, nil, "")
	redefined.Applications.Applications["app-a"].DestinationPort = "8080"
	if got := changedPolicyRuntimeIDs(base, redefined, nil, nil); len(got) != 1 {
		t.Fatalf("control: application redefinition should clear exactly web (%d): %v", webID, got)
	} else if _, ok := got[webID]; !ok {
		t.Fatalf("control: application redefinition cleared wrong IDs: %v (want %d)", got, webID)
	}
}
