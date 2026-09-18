package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
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
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		schedulePowerAction = origPower
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})
	var poweredArg string
	var wiped bool
	schedulePowerAction = func(arg string) { poweredArg = arg }
	performZeroizeWipe = func(_, _, _ string) error { wiped = true; return nil }
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
