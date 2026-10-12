package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// fallbackStore12605 commits a chassis-cluster config with optional extra set
// lines and returns the store. The base fixture leaves the heartbeat knobs
// unset so the config-only path exercises its defaults.
func fallbackStore12605(t *testing.T, extra ...string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-12605",
		"set chassis cluster reth-count 2",
	}
	lines = append(lines, extra...)
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture did not compile chassis cluster")
	}
	return store
}

// TestShowChassisClusterInformationFallbackDefaults12605 pins the config-only
// fallback (#12605): with no live cluster manager and unset heartbeat knobs,
// the gRPC ShowText information view must render the runtime defaults
// (cluster.DefaultHeartbeatInterval 100ms / DefaultHeartbeatThreshold 5),
// not the stale 1000ms/3 literals. Mirror of the pkg/cli cell.
//
// FAIL-ON-REVERT: restoring `hbInterval = 1000` / `hbThreshold = 3` in
// showChassisClusterInformation makes this cell render 1000/3 and go RED.
func TestShowChassisClusterInformationFallbackDefaults12605(t *testing.T) {
	store := fallbackStore12605(t)
	s := &Server{store: store} // cluster nil -> config-only fallback path.
	var buf strings.Builder
	s.showChassisClusterInformation(&buf)
	out := buf.String()
	for _, want := range []string{
		"Heartbeat interval: 100 ms",
		"Heartbeat threshold: 5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config-only fallback lacks %q:\n%s", want, out)
		}
	}
}

// TestShowChassisClusterInformationConfiguredPassthrough12605 pins that
// explicitly configured heartbeat knobs pass through unchanged on the
// config-only path (#12605): only the `== 0` fallback arms changed.
func TestShowChassisClusterInformationConfiguredPassthrough12605(t *testing.T) {
	store := fallbackStore12605(t,
		"set chassis cluster heartbeat-interval 500",
		"set chassis cluster heartbeat-threshold 7",
	)
	s := &Server{store: store} // cluster nil -> config-only fallback path.
	var buf strings.Builder
	s.showChassisClusterInformation(&buf)
	out := buf.String()
	for _, want := range []string{
		"Heartbeat interval: 500 ms",
		"Heartbeat threshold: 7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("configured passthrough lacks %q:\n%s", want, out)
		}
	}
}
