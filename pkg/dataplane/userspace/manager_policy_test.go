package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestUserspaceSupportsSimpleZonePolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "allow-all",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if snap.DefaultPolicy != "deny" || len(snap.Policies) != 1 || snap.Policies[0].Action != "permit" {
		t.Fatalf("unexpected policy snapshot: %+v", snap.Policies)
	}
}

func TestUserspaceSupportsAddressBookPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"lan-subnet": {Name: "lan-subnet", Value: "10.0.61.0/24"},
			"wan-host":   {Name: "wan-host", Value: "172.16.80.200/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"wan-targets": {
				Name:      "wan-targets",
				Addresses: []string{"wan-host"},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-address-book",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"lan-subnet"},
				DestinationAddresses: []string{"wan-targets"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	if got := snap.Policies[0].SourceAddresses; len(got) != 1 || got[0] != "10.0.61.0/24" {
		t.Fatalf("SourceAddresses = %+v, want expanded address-book prefix", got)
	}
	if got := snap.Policies[0].DestinationAddresses; len(got) != 1 || got[0] != "172.16.80.200/32" {
		t.Fatalf("DestinationAddresses = %+v, want expanded address-set prefix", got)
	}
}

func TestUserspaceSupportsNamedApplicationPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {
			Name:         "web-apps",
			Applications: []string{"junos-http", "junos-https"},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-web",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"web-apps"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 2 {
		t.Fatalf("ApplicationTerms = %+v, want two expanded applications", terms)
	}
	if terms[0].Protocol != "tcp" || terms[0].DestinationPort == "" {
		t.Fatalf("unexpected first application term: %+v", terms[0])
	}
}

func TestUserspaceSupportsGlobalPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "global-allow",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyPermit,
	}}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 || snap.Policies[0].Action != "permit" {
		t.Fatalf("unexpected global-policy snapshot: %+v", snap.Policies)
	}
}

func TestBuildPolicySnapshotsIncludesGlobalPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "zone-allow",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "global-deny-all",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyDeny,
	}}
	snap, _ := buildPolicySnapshots(cfg)
	if len(snap) != 2 {
		t.Fatalf("len(snap) = %d, want 2", len(snap))
	}
	if snap[0].FromZone != "trust" || snap[0].ToZone != "untrust" {
		t.Fatalf("snap[0] = %+v, want zone-specific policy", snap[0])
	}
	if snap[1].FromZone != "junos-global" || snap[1].ToZone != "junos-global" {
		t.Fatalf("snap[1] = %+v, want global policy", snap[1])
	}
	if snap[1].Name != "global-deny-all" {
		t.Fatalf("snap[1].Name = %q, want global-deny-all", snap[1].Name)
	}
}

func TestBuildPolicySnapshotsRoundTripsSchedulerInactiveAndRuleID(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "zone-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:          "global-deny-all",
		SchedulerName: "always",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyDeny,
	}}

	unseeded, _ := buildPolicySnapshots(cfg)
	if len(unseeded) != 2 {
		t.Fatalf("len(unseeded) = %d, want 2", len(unseeded))
	}
	for _, pol := range unseeded {
		if !pol.Inactive {
			t.Fatalf("policy %q inactive = false with nil scheduler state, want fail-closed true", pol.RuleID)
		}
	}

	snap, _ := buildPolicySnapshotsWithSchedulerState(cfg, map[string]bool{
		"workhours": false,
		"always":    true,
	})
	if len(snap) != 2 {
		t.Fatalf("len(snap) = %d, want 2", len(snap))
	}
	if got, want := snap[0].RuleID, "trust->untrust/zone-allow"; got != want {
		t.Fatalf("snap[0].RuleID = %q, want %q", got, want)
	}
	if got, want := snap[0].PolicyID, uint32(0); got != want {
		t.Fatalf("snap[0].PolicyID = %d, want %d", got, want)
	}
	if got, want := snap[0].SchedulerName, "workhours"; got != want {
		t.Fatalf("snap[0].SchedulerName = %q, want %q", got, want)
	}
	if !snap[0].Inactive {
		t.Fatalf("snap[0].Inactive = false, want true for inactive scheduler")
	}
	if got, want := snap[1].RuleID, "junos-global->junos-global/global-deny-all"; got != want {
		t.Fatalf("snap[1].RuleID = %q, want %q", got, want)
	}
	if got, want := snap[1].PolicyID, uint32(dataplane.MaxRulesPerPolicy); got != want {
		t.Fatalf("snap[1].PolicyID = %d, want %d", got, want)
	}
	if snap[1].Inactive {
		t.Fatalf("snap[1].Inactive = true, want false for active scheduler")
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTrip []PolicyRuleSnapshot
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(roundTrip) != 2 {
		t.Fatalf("len(roundTrip) = %d, want 2", len(roundTrip))
	}
	if roundTrip[0].RuleID != snap[0].RuleID ||
		roundTrip[0].PolicyID != snap[0].PolicyID ||
		roundTrip[0].SchedulerName != snap[0].SchedulerName ||
		roundTrip[0].Inactive != snap[0].Inactive {
		t.Fatalf("roundTrip[0] = %+v, want scheduler/inactive/rule_id/policy_id from %+v", roundTrip[0], snap[0])
	}
}

func TestUpdatePolicyScheduleStatePublishesUserspaceSnapshot(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan ControlRequest, 1)
	done := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		reqCh <- req
		_ = json.NewEncoder(conn).Encode(ControlResponse{
			OK: true,
			Status: &ProcessStatus{
				Enabled:                true,
				LastSnapshotGeneration: req.Snapshot.Generation,
				LastFIBGeneration:      req.Snapshot.FIBGeneration,
			},
		})
		done <- struct{}{}
	}()

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for apply_snapshot publish")
	}
	req := <-reqCh
	if req.Type != "apply_snapshot" {
		t.Fatalf("request type = %q, want apply_snapshot", req.Type)
	}
	if req.Snapshot == nil {
		t.Fatal("apply_snapshot missing snapshot")
	}
	if req.Snapshot.Version != ProtocolVersion {
		t.Fatalf("snapshot version = %d, want %d", req.Snapshot.Version, ProtocolVersion)
	}
	if req.Snapshot.Generation <= 7 {
		t.Fatalf("snapshot generation = %d, want > 7", req.Snapshot.Generation)
	}
	if len(req.Snapshot.Policies) != 1 {
		t.Fatalf("policy count = %d, want 1", len(req.Snapshot.Policies))
	}
	pol := req.Snapshot.Policies[0]
	if pol.RuleID != "trust->untrust/scheduled-allow" {
		t.Fatalf("policy rule_id = %q", pol.RuleID)
	}
	if pol.SchedulerName != "workhours" {
		t.Fatalf("scheduler_name = %q", pol.SchedulerName)
	}
	if !pol.Inactive {
		t.Fatalf("inactive = false, want true for inactive scheduler state")
	}
	if m.lastSnapshot == nil || len(m.lastSnapshot.Policies) != 1 || !m.lastSnapshot.Policies[0].Inactive {
		t.Fatalf("manager lastSnapshot did not keep inactive policy bit: %+v", m.lastSnapshot)
	}
}

func TestUpdatePolicyScheduleStateRefusesOldHelperForScheduledPolicies(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan ControlRequest, 2)
	done := make(chan struct{}, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				return
			}
			reqCh <- req
			status := &ProcessStatus{
				PID:             1234,
				ForwardingArmed: true,
			}
			if req.Type == "set_forwarding_state" {
				status.ForwardingArmed = false
			}
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: status,
			})
			conn.Close()
		}
		done <- struct{}{}
	}()

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Action:        config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	m.lastSnapshot.Policies[0].Inactive = false

	m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for status probe")
	}
	req := <-reqCh
	if req.Type != "status" {
		t.Fatalf("first request type = %q, want status", req.Type)
	}
	select {
	case req := <-reqCh:
		if req.Type != "set_forwarding_state" || req.Forwarding == nil || req.Forwarding.Armed {
			t.Fatalf("second request = %+v, want fail-closed set_forwarding_state armed=false", req)
		}
	default:
		t.Fatal("expected fail-closed set_forwarding_state request")
	}
	if m.lastStatus.ForwardingArmed {
		t.Fatal("helper status should be disarmed after protocol mismatch")
	}
	if m.generation != 7 {
		t.Fatalf("generation = %d, want unchanged 7 after protocol mismatch", m.generation)
	}
	if m.lastStatus.PID != 1234 {
		t.Fatalf("lastStatus PID = %d, want status probe PID 1234", m.lastStatus.PID)
	}
	if m.lastSnapshot == nil || len(m.lastSnapshot.Policies) != 1 || m.lastSnapshot.Policies[0].Inactive {
		t.Fatalf("manager should not cache rejected inactive state when publish is refused: %+v", m.lastSnapshot)
	}
}

func TestUpdatePolicyScheduleStateWithoutHelperDoesNotMutateSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Action:        config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	m.lastSnapshot.Policies[0].Inactive = false

	m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})

	if m.generation != 7 {
		t.Fatalf("generation = %d, want unchanged 7", m.generation)
	}
	if m.lastSnapshot == nil || len(m.lastSnapshot.Policies) != 1 || m.lastSnapshot.Policies[0].Inactive {
		t.Fatalf("lastSnapshot mutated without helper: %+v", m.lastSnapshot)
	}
	m.mu.Lock()
	desired, desiredOK := m.policySchedulerDesired["workhours"]
	applied, appliedOK := m.policySchedulerActive["workhours"]
	m.mu.Unlock()
	if !desiredOK || desired {
		t.Fatalf("policySchedulerDesired[workhours] = %t, present=%t; want false and present", desired, desiredOK)
	}
	if appliedOK {
		t.Fatalf("policySchedulerActive[workhours] = %t, present=true; want absent because no helper applied the state", applied)
	}
}
