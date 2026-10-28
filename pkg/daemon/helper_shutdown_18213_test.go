package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sync/semaphore"
)

var (
	_ helperStopIntentMarker = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ helperStopIntentMarker = (*dpuserspace.Manager)(nil)
)

// helperShutdownMarkerDP records the optional lifecycle hook through the real
// shutdown sequence. Like controlShutdownDP, its embedded RuntimeDataPlane is
// never called in the standalone, nil-subsystem harness.
type helperShutdownMarkerDP struct {
	dataplane.RuntimeDataPlane
	events []string
}

func (d *helperShutdownMarkerDP) Start(context.Context) error { return nil }
func (d *helperShutdownMarkerDP) Close() error {
	d.events = append(d.events, "close")
	return nil
}
func (d *helperShutdownMarkerDP) Teardown() error {
	d.events = append(d.events, "teardown")
	return nil
}
func (d *helperShutdownMarkerDP) MarkHelperStopIntent() {
	d.events = append(d.events, "mark-helper-stop-intent")
}
func (d *helperShutdownMarkerDP) BeginControlShutdown() {
	d.events = append(d.events, "bound-control")
}

// TestRunShutdownSequenceMarksHelperIntentBeforeDataplaneTeardown18213 pins
// the real daemon stop wiring. The helper's child shares xpfd.service's
// systemd cgroup, so default control-group SIGTERM can kill it before xpfd's
// ordered shutdown and be miscounted as a #5838 crash. The nonblocking control
// I/O bound must run first because marking takes the manager mutex; the helper
// intent must then be published before other teardown can wait or signal.
// KillMode=mixed ensures systemd gives xpfd first chance to run this path; any
// remaining child is SIGKILLed if xpfd exits or TimeoutStopSec expires.
//
// RED before #18213: deleting the MarkHelperStopIntent dispatch leaves only
// "bound-control" as the first event and fails the assertion below.
func TestRunShutdownSequenceMarksHelperIntentBeforeDataplaneTeardown18213(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	daemonCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dp := &helperShutdownMarkerDP{}
	d := &Daemon{
		store:     store,
		applySem:  semaphore.NewWeighted(1),
		daemonCtx: daemonCtx,
	}
	d.setDataplane(dp)
	var wg sync.WaitGroup
	if err := d.runShutdownSequence(context.Background(), &wg, func() {}, nil); err != nil {
		t.Fatalf("runShutdownSequence: %v", err)
	}
	if len(dp.events) < 2 || dp.events[0] != "bound-control" || dp.events[1] != "mark-helper-stop-intent" {
		t.Fatalf("dataplane shutdown events = %v, want control-I/O bound then helper intent before teardown (#18213)", dp.events)
	}
}

// TestXPFDUnitUsesMixedKillModeForGracefulHelperShutdown18213 pins the
// deployment contract: systemd sends the initial stop signal to xpfd only, so
// xpfd can mark the helper generation intentional and perform its owned
// shutdown/reap. Any remaining child is SIGKILLed if xpfd exits before it or
// TimeoutStopSec expires; systemd does not send the helper the initial SIGTERM.
func TestXPFDUnitUsesMixedKillModeForGracefulHelperShutdown18213(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "incus", "xpfd.service"))
	if err != nil {
		t.Fatalf("read shipped xpfd unit: %v", err)
	}
	inService := false
	killMode := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inService = line == "[Service]"
			continue
		}
		if inService && strings.HasPrefix(line, "KillMode=") {
			killMode = strings.TrimPrefix(line, "KillMode=")
		}
	}
	if killMode != "mixed" {
		t.Fatalf("xpfd.service KillMode = %q, want mixed so systemd cannot SIGTERM the helper before xpfd marks it intentional (#18213)", killMode)
	}
}
