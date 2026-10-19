package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #15728: trailing tokens after a request-system lifecycle/service verb must
// error BEFORE prompting or invoking the underlying action — a scheduled
// spelling (`reboot in 10`) must never silently become an immediate reboot.
func TestRequestSystemTrailingArgsRejected15728(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"reboot in 10", []string{"reboot", "in", "10"}},
		{"halt at 23:00", []string{"halt", "at", "23:00"}},
		{"power-off message", []string{"power-off", "message", "maintenance"}},
		{"zeroize media", []string{"zeroize", "media"}},
		{"software extra", []string{"software", "in-service-upgrade", "extra"}},
		{"dynamic-dns iface", []string{"dynamic-dns", "update", "ge-0/0/0"}},
		{"rescue save extra", []string{"configuration", "rescue", "save", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origPower := consolePowerAction
			t.Cleanup(func() { consolePowerAction = origPower })
			powerCalls := 0
			consolePowerAction = func(string) error { powerCalls++; return nil }

			origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
			t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
			wipeCalls := 0
			zeroizeFullWipe = func(string, string, string, zeroizeLogInventory, string) error {
				wipeCalls++
				return nil
			}
			zeroizeStopDaemon = func() error { return nil }

			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			prompts := 0
			c := &CLI{
				store:   store,
				cluster: cluster.NewManager(0, 1),
				readLineFn: func() (string, error) {
					prompts++
					return "yes", nil
				},
				surfaceADDNSForceFn: func(bool) (bool, string) { return true, "forced" },
			}
			var err error
			captureStdout(t, func() { err = c.handleRequestSystem(tc.args) })
			if err == nil {
				t.Fatalf("handleRequestSystem(%v) = nil; trailing args must be rejected", tc.args)
			}
			if prompts != 0 {
				t.Fatalf("handleRequestSystem(%v) prompted %d times; rejection must precede confirmation", tc.args, prompts)
			}
			if powerCalls != 0 || wipeCalls != 0 {
				t.Fatalf("handleRequestSystem(%v) acted (power=%d wipe=%d); must not invoke action", tc.args, powerCalls, wipeCalls)
			}
		})
	}
}

// #15728: handleRequestSystemSoftware must not panic when c.rl is nil but the
// readLine seam is wired — it must honor the c.readLine confirmation response.
// A "no" answer must cancel without reaching ForceSecondary; on a manager
// with no live peer ForceSecondary errors, so reaching it would surface an
// ISSU error instead of a clean cancel.
func TestHandleRequestSystemSoftwareNilReadline15728(t *testing.T) {
	for _, answer := range []string{"no", "yes"} {
		t.Run(answer, func(t *testing.T) {
			c := &CLI{
				cluster: cluster.NewManager(0, 1),
				// rl deliberately nil; only the readLine seam is wired.
				readLineFn: func() (string, error) { return answer, nil },
			}
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("handleRequestSystemSoftware panicked with nil rl: %v", r)
					}
				}()
				captureStdout(t, func() {
					err = c.handleRequestSystemSoftware([]string{"in-service-upgrade"})
				})
			}()
			if answer == "no" && err != nil {
				t.Fatalf("cancelled ISSU returned error %v; readLine 'no' must be honored as cancel", err)
			}
			if answer == "yes" && err == nil {
				t.Fatalf("ISSU with 'yes' and no live peer returned nil; expected ForceSecondary error, proving confirmation was honored and action attempted")
			}
		})
	}
}
