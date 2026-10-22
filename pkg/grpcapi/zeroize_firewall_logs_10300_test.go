package grpcapi

import (
	"context"
	"github.com/psaab/xpf/pkg/factoryreset"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestPerformZeroizeWipeErasesFirewallLogs10300 is the RED-on-revert guard for
// the complete firewall-log surface. It uses the same shared wipe primitive
// both gRPC and the console call, with every host path seamed into a temp tree.
// The pre-fix primitive returns clean while these fixtures remain on disk.

// TestZeroizeReceiptAttestsFirewallLogScope10300 binds the pre-wipe config
// snapshot to the shared gRPC path and pins the operator-facing receipt. A
// clean response must state that the firewall-log scope was erased; the old
// response only said "Configuration erased" and omitted the surviving logs.
func TestZeroizeReceiptAttestsFirewallLogScope10300(t *testing.T) {
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		scheduleStopDaemon = origStop
	})
	var got factoryreset.LogInventory
	stubZeroizeWipes(t, func(_ bool, configDir, configBase, archiveDir string, inv factoryreset.LogInventory, helperPath string) error {
		got = inv
		return nil
	})
	scheduleStopDaemon = func() {}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, set := range []string{
		"set system syslog file messages any any",
		"set system syslog file audit any warning",
		"set security flow traceoptions file trace.log",
	} {
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet(%q): %v", set, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	s := &Server{store: store}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if len(got.SyslogFiles) != 2 || got.SyslogFiles[0] != "messages" || got.SyslogFiles[1] != "audit" || got.TraceFile != "trace.log" {
		t.Fatalf("zeroize did not snapshot configured log inventory before wiping: %+v", got)
	}
	if resp == nil || !strings.Contains(strings.ToLower(resp.Message), "firewall log") {
		t.Fatalf("zeroize receipt omits the firewall-log wipe scope: %+v", resp)
	}
}

// TestZeroizeSnapshotsFirewallInventoryInsideGate10300 prevents an apply-gate
// race: a commit waiting for ZeroizeFn may add a destination before the wipe
// closure runs, and that destination must be included in the final inventory.
func TestZeroizeSnapshotsFirewallInventoryInsideGate10300(t *testing.T) {
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		scheduleStopDaemon = origStop
	})
	var got factoryreset.LogInventory
	stubZeroizeWipes(t, func(_ bool, configDir, configBase, archiveDir string, inv factoryreset.LogInventory, helperPath string) error {
		got = inv
		return nil
	})
	scheduleStopDaemon = func() {}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, set := range []string{
		"set system syslog file messages any any",
		"set security flow traceoptions file trace.log",
	} {
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet(%q): %v", set, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit initial config: %v", err)
	}
	store.ExitConfigure()
	s := &Server{
		store: store,
		zeroizeFn: func(_ context.Context, wipe func() error) error {
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure gated commit: %v", err)
			}
			for _, set := range []string{
				"set system syslog file committed-during-gate any notice",
				"set security flow traceoptions file committed-trace.log",
			} {
				if _, err := store.LoadSet(set); err != nil {
					t.Fatalf("LoadSet(%q): %v", set, err)
				}
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit gated config: %v", err)
			}
			return wipe()
		},
	}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if len(got.SyslogFiles) != 2 || got.SyslogFiles[0] != "messages" || got.SyslogFiles[1] != "committed-during-gate" {
		t.Fatalf("zeroize inventory missed gated syslog destination: %+v", got)
	}
	if got.TraceFile != "committed-trace.log" {
		t.Fatalf("zeroize inventory missed gated trace destination: %+v", got)
	}
}
