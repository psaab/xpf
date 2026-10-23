package userspace

// #16010 fold: a scheduler marked Unresolvable by tolerant compile is
// never active, so permits gated by it fail closed — but scheduled
// DENY/REJECT rules must stay eligible (suppressing a deny would fail
// open to a later permit), mirroring the fail-closed latch disposition.
//
// FAIL-ON-REVERT: routing buildOneRuleSnapshot back through
// policyRuleInactiveForAction (or dropping the Unresolvable arm in
// policyRuleInactiveForScheduler) makes the deny/reject snapshots
// inactive and this test fails; dropping the scheduler runtime check
// alone does not affect this test because activeState is supplied
// directly — that half is pinned in pkg/scheduler.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildPolicySnapshotsUnresolvableScheduler16010(t *testing.T) {
	mk := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{
			Name:          name,
			SchedulerName: "S",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: action,
		}
	}
	cfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"S": {Name: "S", AllDay: true, StartTime: "09:00:00", StopTime: "17:00:00", Unresolvable: true},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{
			mk("scheduled-deny", config.PolicyDeny),
			mk("scheduled-reject", config.PolicyReject),
			mk("scheduled-permit", config.PolicyPermit),
		},
	}}
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, nil)
	if err != nil {
		t.Fatalf("build address-book table: %v", err)
	}
	// The scheduler runtime reports an unresolvable scheduler inactive.
	state := map[string]bool{"S": false}
	snaps, err := buildPolicySnapshotsWithAddressBookAndFailClosed(cfg, state, nil, nameToID, false)
	if err != nil {
		t.Fatalf("build policy snapshots: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("snapshot count = %d, want 3", len(snaps))
	}
	if snaps[0].Inactive {
		t.Fatal("unresolvable-scheduler deny must remain eligible")
	}
	if snaps[1].Inactive {
		t.Fatal("unresolvable-scheduler reject must remain eligible")
	}
	if !snaps[2].Inactive {
		t.Fatal("unresolvable-scheduler permit must fail closed (inactive)")
	}

	// Control: same policies under an ordinary (resolvable) inactive
	// scheduler keep every action inactive.
	cfg.Schedulers["S"].Unresolvable = false
	normal, err := buildPolicySnapshotsWithAddressBookAndFailClosed(cfg, state, nil, nameToID, false)
	if err != nil {
		t.Fatalf("build control snapshots: %v", err)
	}
	if !normal[0].Inactive || !normal[1].Inactive || !normal[2].Inactive {
		t.Fatalf("ordinary inactive scheduler must keep all actions inactive: deny=%t reject=%t permit=%t",
			normal[0].Inactive, normal[1].Inactive, normal[2].Inactive)
	}
}
