package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestReadPolicyCountersReturnsUnpublishedForMissingConfiguredRule(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{Policies: []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{Name: "allow-web"}},
	}}}}
	m := New()
	m.bpfShim = nil
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}

	got, err := m.ReadPolicyCounters(0)
	if !errors.Is(err, ErrPolicyCounterUnpublished) {
		t.Fatalf("ReadPolicyCounters = (%+v, %v), want ErrPolicyCounterUnpublished", got, err)
	}
	reader := NewPolicyCounterReader(m, cfg, m.ReadPolicyCounters)
	if got, err := reader(0); !errors.Is(err, ErrPolicyCounterUnpublished) || got != (dataplane.CounterValue{}) {
		t.Fatalf("NewPolicyCounterReader = (%+v, %v), want zero value and ErrPolicyCounterUnpublished", got, err)
	}
	if got != (dataplane.CounterValue{}) {
		t.Fatalf("ReadPolicyCounters value = %+v, want zero alongside unpublished error", got)
	}
}

func TestOfflineCounterClearsRepublishCachedStatus(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clear func(*Manager) error
		check func(ProcessStatus) bool
	}{
		{
			name:  "policy",
			clear: (*Manager).ClearPolicyCounters,
			check: func(s ProcessStatus) bool {
				return len(s.PolicyRuleCounters) == 1 && s.PolicyRuleCounters[0].Packets == 0 && s.PolicyRuleCounters[0].Bytes == 0
			},
		},
		{
			name:  "NAT",
			clear: (*Manager).ClearNATRuleCounters,
			check: func(s ProcessStatus) bool {
				return len(s.NATRuleCounters) == 1 && s.NATRuleCounters[0].Packets == 0 && s.NATRuleCounters[0].Bytes == 0
			},
		},
		{
			name:  "zone",
			clear: (*Manager).ClearZoneCounters,
			check: func(s ProcessStatus) bool { return len(s.ZoneTrafficCounters) == 0 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.bpfShim = nil
			m.setLastStatusLocked(ProcessStatus{
				PID:                 1234,
				PolicyRuleCounters:  []PolicyRuleCounterStatus{{RuleID: "lan->wan/allow-web", Packets: 7, Bytes: 700}},
				NATRuleCounters:     []NATRuleCounterStatus{{CounterID: 1, Packets: 9, Bytes: 900}},
				ZoneTrafficCounters: []ZoneTrafficCounterStatus{{ZoneID: 1, IngressPackets: 3}},
			})
			beforeSeq := m.lastStatusSeq

			if err := tc.clear(m); err != nil {
				t.Fatalf("clear: %v", err)
			}
			if m.lastStatusSeq != beforeSeq+1 {
				t.Fatalf("lastStatusSeq = %d, want %d after cached status mutation", m.lastStatusSeq, beforeSeq+1)
			}
			view, ok := m.CachedStatus()
			if !ok {
				t.Fatal("CachedStatus unavailable after clear")
			}
			if !tc.check(view) {
				t.Fatalf("published status did not reflect clear: %+v", view)
			}
		})
	}
}
func TestOfflineCounterClearDoesNotClaimHelperObservation(t *testing.T) {
	m := New()
	m.bpfShim = nil
	m.lastStatus.PolicyRuleCounters = []PolicyRuleCounterStatus{{
		RuleID:  "lan->wan/allow-web",
		Packets: 7,
		Bytes:   700,
	}}

	if err := m.ClearPolicyCounters(); err != nil {
		t.Fatalf("ClearPolicyCounters: %v", err)
	}
	if m.helperStatusObserved {
		t.Fatal("offline cache clear claimed that a helper status was observed")
	}
	if m.lastStatusSeq != 1 {
		t.Fatalf("lastStatusSeq = %d, want 1 after publishing local cache mutation", m.lastStatusSeq)
	}
	if _, ok := m.CachedStatus(); ok {
		t.Fatal("CachedStatus became available although no helper status was observed")
	}
}
