package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #15775: `show chassis cluster fence-status` was advertised in the command
// tree but had no handler: the local dispatcher fell through to the RG
// `status` view for `fence-status`, for any typo, and for trailing garbage.
// Bare subsystem tokens (`fabric`, `control-plane`, ...) printed help
// locally while the remote CLI renders a default view. All surfaces must
// agree: valid views render, unknowns fail closed, bare subsystems render
// the same default view remotely and locally.

func fenceCLI15775(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	manager := cluster.NewManager(0, 1)
	return &CLI{cluster: manager, store: store}
}

func TestShowChassisClusterRejectsUnknownSubcommands15775(t *testing.T) {
	c := fenceCLI15775(t)
	for _, args := range [][]string{
		{"statuz"},
		{"bogus"},
		{"status", "extra"},
		{"interfaces", "extra"},
		{"information", "extra"},
		{"statistics", "extra"},
		{"fence-status", "extra"},
		{"fabric", "bogus"},
		{"fabric", "statistics", "extra"},
		{"control-plane", "bogus"},
		{"control-plane", "statistics", "extra"},
		{"data-plane", "bogus"},
		{"ip-monitoring", "bogus"},
		{"ip-monitoring", "status", "extra"},
	} {
		var runErr error
		out := captureStdout(t, func() { runErr = c.showChassisCluster(args) })
		if runErr == nil {
			t.Errorf("showChassisCluster(%v): expected error, got nil with output %q (silent fallback)", args, out)
		}
	}
}

func TestShowChassisClusterFenceStatus15775(t *testing.T) {
	c := fenceCLI15775(t)
	var runErr error
	out := captureStdout(t, func() { runErr = c.showChassisCluster([]string{"fence-status"}) })
	if runErr != nil {
		t.Fatalf("fence-status: %v", runErr)
	}
	if !strings.Contains(out, "Peer fencing:") {
		t.Errorf("fence-status output lacks 'Peer fencing:':\n%s", out)
	}
	if !strings.Contains(out, "Action: disabled") {
		t.Errorf("fence-status output lacks 'Action: disabled' for unconfigured fencing:\n%s", out)
	}
	// Must NOT be the RG status view.
	if strings.Contains(out, "Redundancy group:") {
		t.Errorf("fence-status silently rendered RG status:\n%s", out)
	}
}

func TestShowChassisClusterBareSubsystemDefaults15775(t *testing.T) {
	c := fenceCLI15775(t)
	// Bare subsystems render their default view (parity with remote), not help.
	for _, args := range [][]string{
		{"fabric"},
		{"control-plane"},
		{"data-plane"},
		{"ip-monitoring"},
	} {
		var runErr error
		out := captureStdout(t, func() { runErr = c.showChassisCluster(args) })
		if runErr != nil {
			t.Errorf("showChassisCluster(%v): %v", args, runErr)
			continue
		}
		if strings.Contains(out, "Possible completions:") {
			t.Errorf("showChassisCluster(%v) printed help-only, want default view:\n%s", args, out)
		}
	}
	// Bare `show chassis cluster` keeps status view.
	var runErr error
	_ = captureStdout(t, func() { runErr = c.showChassisCluster(nil) })
	if runErr != nil {
		t.Fatalf("bare cluster: %v", runErr)
	}
}

func TestShowChassisClusterValidViewsStillWork15775(t *testing.T) {
	c := fenceCLI15775(t)
	for _, args := range [][]string{
		{"status"},
		{"interfaces"},
		{"information"},
		{"statistics"},
		{"fabric", "statistics"},
		{"control-plane", "statistics"},
		{"data-plane", "statistics"},
		{"data-plane", "interfaces"},
		{"ip-monitoring", "status"},
		{"fence-status"},
	} {
		var runErr error
		_ = captureStdout(t, func() { runErr = c.showChassisCluster(args) })
		if runErr != nil {
			t.Errorf("showChassisCluster(%v): unexpected error %v", args, runErr)
		}
	}
}
