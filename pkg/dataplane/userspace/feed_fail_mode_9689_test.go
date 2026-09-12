package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestDropModeEmptyRowKeepsTheSnapshotEnforceable9689 carries the #9689
// decision through policy lowering. Under fail-mode drop, feeds publishes a
// present empty row: the referencing rule lowers to match-none with no
// unsupported-address sentinel, and an unrelated rule in the same snapshot
// still builds. That is the "later commits are enforced" half of the issue.
// Under retain the binding is omitted, and the sentinel returns (#5645).
func TestDropModeEmptyRowKeepsTheSnapshotEnforceable9689(t *testing.T) {
	cfg := feedPolicyCfg("partners", "any")
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"partners": {Name: "partners", FeedNames: []string{"partner-feed"}, FailMode: "drop"},
	}
	cfg.Security.Policies[0].Policies = append(cfg.Security.Policies[0].Policies, &config.Policy{
		Name:   "unrelated",
		Match:  config.PolicyMatch{SourceAddresses: []string{"192.0.2.0/24"}, DestinationAddresses: []string{"any"}},
		Action: config.PolicyPermit,
	})

	dropSnaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, map[string][]string{"partners": {}})
	if len(dropSnaps) != 2 {
		t.Fatalf("fail-mode drop: %d rules built, want 2", len(dropSnaps))
	}
	if raw, _ := json.Marshal(dropSnaps); strings.Contains(string(raw), unsupportedAddressSentinel) {
		t.Fatalf("fail-mode drop: a rule carries %s, so the whole snapshot would be rejected: %s", unsupportedAddressSentinel, raw)
	}

	retainSnaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, map[string][]string{})
	if raw, _ := json.Marshal(retainSnaps); !strings.Contains(string(raw), unsupportedAddressSentinel) {
		t.Fatalf("control: an omitted binding must still lower to %s (#5645); got %s", unsupportedAddressSentinel, raw)
	}
}
