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

func TestReadPolicyCountersUsesHelperPolicyRuleCounters(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "lan",
				ToZone:   "wan",
				Policies: []*config.Policy{
					{Name: "allow-web"},
					{Name: "allow-dns"},
				},
			}},
			GlobalPolicies: []*config.Policy{{Name: "global-allow"}},
		},
	}
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-dns"), Packets: 7, Bytes: 700},
			{RuleID: stablePolicyRuleID("junos-global", "junos-global", "global-allow"), Packets: 9, Bytes: 900},
		},
	}

	got, err := m.ReadPolicyCounters(1)
	if err != nil {
		t.Fatalf("ReadPolicyCounters lan/wan allow-dns: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 7, Bytes: 700}) {
		t.Fatalf("lan/wan allow-dns counter = %+v, want packets=7 bytes=700", got)
	}

	got, err = m.ReadPolicyCounters(dataplane.MaxRulesPerPolicy)
	if err != nil {
		t.Fatalf("ReadPolicyCounters global: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 9, Bytes: 900}) {
		t.Fatalf("global counter = %+v, want packets=9 bytes=900", got)
	}
}

func TestReadPolicyCountersPreservesScheduledRuleCountersAcrossDeleteReadd(t *testing.T) {
	cfgWithRule := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"workhours": {Name: "workhours"},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "lan",
				ToZone:   "wan",
				Policies: []*config.Policy{{
					Name:          "scheduled-allow",
					SchedulerName: "workhours",
					Count:         true,
				}},
			}},
		},
	}
	cfgWithoutRule := &config.Config{
		Schedulers: cfgWithRule.Schedulers,
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "lan",
				ToZone:   "wan",
			}},
		},
	}

	m := New()
	m.bpfShim = nil
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{{
			RuleID:  stablePolicyRuleID("lan", "wan", "scheduled-allow"),
			Packets: 11,
			Bytes:   1100,
		}},
	}

	m.lastSnapshot = &ConfigSnapshot{Config: cfgWithRule}
	got, err := m.ReadPolicyCounters(0)
	if err != nil {
		t.Fatalf("ReadPolicyCounters before delete: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 11, Bytes: 1100}) {
		t.Fatalf("counter before delete = %+v, want packets=11 bytes=1100", got)
	}

	m.lastSnapshot = &ConfigSnapshot{Config: cfgWithoutRule}
	got, err = m.ReadPolicyCounters(0)
	if err != nil {
		t.Fatalf("ReadPolicyCounters after delete: %v", err)
	}
	if got != (dataplane.CounterValue{}) {
		t.Fatalf("counter after delete = %+v, want zero for absent rule", got)
	}

	m.lastSnapshot = &ConfigSnapshot{Config: cfgWithRule}
	got, err = m.ReadPolicyCounters(0)
	if err != nil {
		t.Fatalf("ReadPolicyCounters after re-add: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 11, Bytes: 1100}) {
		t.Fatalf("counter after re-add = %+v, want packets=11 bytes=1100", got)
	}
}

func TestReadPolicyCountersMapsCommittedScheduledPolicyToHelperIdentity(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy scheduled-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if len(cfg.Security.Policies) != 1 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("unexpected committed policy shape: %+v", cfg.Security.Policies)
	}

	m := New()
	m.bpfShim = nil
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{{
			RuleID:  stablePolicyRuleID("trust", "untrust", "scheduled-allow"),
			Packets: 17,
			Bytes:   1700,
		}},
	}

	got, err := m.ReadPolicyCounters(0)
	if err != nil {
		t.Fatalf("ReadPolicyCounters committed scheduled policy: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 17, Bytes: 1700}) {
		t.Fatalf("committed scheduled policy counter = %+v, want packets=17 bytes=1700", got)
	}
}

func TestClearPolicyCountersZerosCachedHelperCountersWithoutHelper(t *testing.T) {
	m := New()
	m.bpfShim = nil
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-web"), Packets: 7, Bytes: 700},
		},
	}

	if err := m.ClearPolicyCounters(); err != nil {
		t.Fatalf("ClearPolicyCounters: %v", err)
	}
	if got := m.lastStatus.PolicyRuleCounters[0]; got.Packets != 0 || got.Bytes != 0 {
		t.Fatalf("cached helper counter after clear = %+v, want zero packets and bytes", got)
	}
}

func TestClearPolicyCountersUsesHelperIPCAndRecordsStatus(t *testing.T) {
	dir := shortSockDir9322(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	wantRuleID := stablePolicyRuleID("lan", "wan", "allow-web")
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
				PolicyRuleCounters: []PolicyRuleCounterStatus{{
					RuleID: wantRuleID,
				}},
			},
		})
		done <- struct{}{}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{{
			RuleID:  wantRuleID,
			Packets: 7,
			Bytes:   700,
		}},
	}

	m.mu.Lock()
	err = m.clearHelperPolicyCountersLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("clearHelperPolicyCountersLocked: %v", err)
	}
	select {
	case req := <-reqCh:
		if req.Type != "clear_policy_counters" {
			t.Fatalf("request type = %q, want clear_policy_counters", req.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("helper did not receive clear_policy_counters request")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("helper did not finish clear_policy_counters response")
	}
	if len(m.lastStatus.PolicyRuleCounters) != 1 {
		t.Fatalf("len(PolicyRuleCounters) = %d, want 1", len(m.lastStatus.PolicyRuleCounters))
	}
	if got := m.lastStatus.PolicyRuleCounters[0]; got.RuleID != wantRuleID || got.Packets != 0 || got.Bytes != 0 {
		t.Fatalf("helper counter after IPC clear = %+v, want rule_id=%q zero packets/bytes", got, wantRuleID)
	}
}

func TestReadPolicyCountersUsesStatusIPCPolicyRuleCounters(t *testing.T) {
	dir := shortSockDir9322(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	wantRuleID := stablePolicyRuleID("trust", "untrust", "scheduled-allow")
	responses := []PolicyRuleCounterStatus{
		{RuleID: wantRuleID, Packets: 23, Bytes: 2300},
		{RuleID: wantRuleID, Packets: 31, Bytes: 3100},
	}
	reqCh := make(chan ControlRequest, len(responses))
	done := make(chan struct{}, len(responses))
	go func() {
		for _, counter := range responses {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				reqCh <- req
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK: true,
					Status: &ProcessStatus{
						PID:                4321,
						PolicyRuleCounters: []PolicyRuleCounterStatus{counter},
					},
				})
				done <- struct{}{}
			}()
		}
	}()

	cfg := &config.Config{
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{{
					Name:          "scheduled-allow",
					SchedulerName: "workhours",
				}},
			}},
		},
	}
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{{
			RuleID: wantRuleID,
		}},
	}

	refreshStatus := func() {
		t.Helper()
		m.mu.Lock()
		var status ProcessStatus
		err = m.requestLocked(ControlRequest{Type: "status"}, &status)
		if err == nil {
			m.recordHelperStatusLocked(&status)
		}
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("status IPC: %v", err)
		}
		select {
		case req := <-reqCh:
			if req.Type != "status" {
				t.Fatalf("request type = %q, want status", req.Type)
			}
		case <-time.After(time.Second):
			t.Fatal("helper did not receive status request")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("helper did not finish status response")
		}
	}

	refreshStatus()
	got, err := m.ReadPolicyCounters(0)
	if err != nil {
		t.Fatalf("ReadPolicyCounters after status IPC: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 23, Bytes: 2300}) {
		t.Fatalf("counter after status IPC = %+v, want packets=23 bytes=2300", got)
	}

	refreshStatus()
	got, err = m.ReadPolicyCounters(0)
	if err != nil {
		t.Fatalf("ReadPolicyCounters after second status IPC: %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 31, Bytes: 3100}) {
		t.Fatalf("counter after second status IPC = %+v, want packets=31 bytes=3100", got)
	}
}
