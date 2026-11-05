package grpcapi

import (
	"bytes"
	"context"
	"github.com/psaab/xpf/pkg/factoryreset"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSystemActionJournalsDestructiveVerbs pins #4108 F8 at the RPC boundary:
// each destructive maintenance verb (reboot/halt/power-off/zeroize) writes a
// `system_action` audit entry to the configstore journal BEFORE it executes.
// The destructive side effects are stubbed to no-ops via the package seams
// (schedulePowerAction / performZeroizeWipe), so the test drives the real
// SystemAction dispatch WITHOUT taking the host down or wiping /etc/xpf.
//
// RED on revert: dropping the s.logSystemAction(...) call from a case leaves no
// journal entry for that verb and the corresponding subtest fails.
func TestSystemActionJournalsDestructiveVerbs(t *testing.T) {
	// Neutralize the real destructive side effects for the whole test —
	// including the #5281 post-zeroize daemon stop, which the zeroize verb now
	// schedules on a successful wipe.
	origPower := schedulePowerAction
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		schedulePowerAction = origPower
		scheduleStopDaemon = origStop
	})
	var poweredArg string
	var wiped bool
	schedulePowerAction = func(arg string) { poweredArg = arg }
	stubZeroizeWipes(t, func(_ bool, configDir, configBase, archiveDir string, inv factoryreset.LogInventory, helperPath string) error {
		wiped = true
		return nil
	})
	scheduleStopDaemon = func() {}

	cases := []struct {
		action      string
		wantPowered string // systemctl arg expected via schedulePowerAction ("" = none)
		wantWipe    bool
	}{
		{"reboot", "reboot", false},
		{"halt", "halt", false},
		{"power-off", "poweroff", false},
		{"zeroize", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			poweredArg, wiped = "", false
			dir := t.TempDir()
			configPath := filepath.Join(dir, "xpf.conf")
			store := newConfigStore(t, configPath)
			s := &Server{store: store}

			if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: tc.action}); err != nil {
				t.Fatalf("SystemAction(%q): %v", tc.action, err)
			}

			// The destructive effect ran (via the stub), proving the case body
			// executed and did not short-circuit before the journal write.
			if tc.wantPowered != "" && poweredArg != tc.wantPowered {
				t.Errorf("schedulePowerAction arg = %q, want %q", poweredArg, tc.wantPowered)
			}
			if tc.wantWipe != wiped {
				t.Errorf("performZeroizeWipe called = %v, want %v", wiped, tc.wantWipe)
			}

			// The journal entry was persisted to .config.journal (next to the
			// config file) BEFORE the action — a durable, on-disk record.
			journalPath := filepath.Join(dir, ".config.journal")
			data, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatalf("read journal %s: %v", journalPath, err)
			}
			if !bytes.Contains(data, []byte(`"action":"system_action"`)) ||
				!bytes.Contains(data, []byte(`"detail":"`+tc.action+`"`)) {
				t.Errorf("journal missing system_action/%q entry; got:\n%s", tc.action, data)
			}
		})
	}
}

func TestSystemActionUnkeyedGraceRestartRefusedWithoutJournal16016(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	server := &Server{store: store}

	_, err := server.SystemAction(context.Background(), &pb.SystemActionRequest{
		Action: "cluster-unkeyed-grace-restart",
	})
	const refusal = "unkeyed-grace restart is a local recovery action; run it on the node itself"
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != refusal {
		t.Fatalf("SystemAction(cluster-unkeyed-grace-restart) = %v, want FailedPrecondition %q", err, refusal)
	}

	journalPath := filepath.Join(dir, ".config.journal")
	data, err := os.ReadFile(journalPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read action journal: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("refused unkeyed-grace restart wrote action journal records: %s", data)
	}
}
