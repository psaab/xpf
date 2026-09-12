package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// #9725: both gate legs swallow their failures on purpose — propagating one
// would brick management on a boot path — so the transition logs used to state
// the gate's DECISION in language that read as the kernel's STATE ("kernel
// transit forwarding DISABLED"). An operator could be told the node was safe
// while it was still forwarding. The legs now report whether they actually
// actuated, and the callers log that beside the decision.
//
// The read-back is the point: a write that returns nil is not proof the knob
// took the value.
func TestTheTransitSysctlLegReportsWhetherItActuated9725(t *testing.T) {
	t.Run("both knobs take the value", func(t *testing.T) {
		withTempTransitForwardSysctls(t, "1")
		if !writeTransitForwardSysctls(false) {
			t.Errorf("writing both knobs to 0 on writable files reported NOT verified")
		}
		for _, p := range transitForwardSysctlPaths() {
			if got := readKnob9725(t, p); got != "0" {
				t.Errorf("%s = %q after the write, want \"0\"", p, got)
			}
		}
	})

	t.Run("a knob that cannot be written is not claimed", func(t *testing.T) {
		withTempTransitForwardSysctls(t, "1")
		// Replace the first knob with a DIRECTORY: the write fails, and the
		// value stays 1. This is the shape the finding is about — the failure is
		// swallowed, so only the return value can carry it.
		p := transitForwardSysctlPaths()[0]
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove %s: %v", p, err)
		}
		if err := os.MkdirAll(filepath.Join(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if writeTransitForwardSysctls(false) {
			t.Errorf("#9725: the sysctl leg reported VERIFIED while one knob could not be written. "+
				"The failure is deliberately swallowed, so a caller that logs the decision as the kernel's "+
				"state tells an operator the node is closed while it still forwards (%s)", p)
		}
	})

	t.Run("a knob that does not hold the written value is not claimed", func(t *testing.T) {
		withTempTransitForwardSysctls(t, "1")
		if os.Geteuid() == 0 {
			t.Skip("running as root: a 0400 file is still writable, so this shape cannot be produced here")
		}
		p := transitForwardSysctlPaths()[0]
		// A knob that accepts no write and keeps its old value: the shape a
		// read-only /proc or a concurrent writer produces. Read-only permissions
		// reproduce it without any ordering games.
		if err := os.Chmod(p, 0o400); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
		if writeTransitForwardSysctls(false) {
			t.Errorf("#9725: the sysctl leg reported VERIFIED for a knob it could not change (%s)", p)
		}
	})
}
