package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// F1 repro: with the scheduler latch set (failClosed=true) and the map false,
// a route-overlay publish must keep a scheduled DENY eligible (Inactive=false).
// The overlay path previously discarded the latch during policy rebuilding.
func TestPublishRouteOverlaySnapshotLatchKeepsDenyEligible12273(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x12273f1")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{
			{
				Name:          "scheduled-deny",
				SchedulerName: "workhours",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyDeny,
			},
			{
				Name:          "scheduled-permit",
				SchedulerName: "workhours",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyPermit,
			},
		},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed with the window OPEN so both rules are eligible; the overlay publish
	// below carries the LATCHED closed map.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}

	reqs := startArmControlServer(t, controlSock, 2)

	// Latched closed map: scheduler.ActiveState() reports false while latched.
	published, err := m.PublishRouteOverlaySnapshotWithLatch(cfg, nil, map[string]bool{"workhours": false}, true)
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish (scheduler bits changed), got duplicate-skip")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-deny") {
		t.Fatal("F1 BYPASS: latched scheduled DENY published inactive via route-overlay republish")
	}
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-permit") {
		t.Fatal("latched scheduled permit must remain inactive")
	}
}
