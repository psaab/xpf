package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestXPFDUnitUsesMixedKillModeForGracefulHelperShutdown18213 pins the
// deployment contract: systemd sends the initial stop signal to xpfd only,
// giving its orderly shutdown path time to retire and stop the helper. Any
// remaining child is SIGKILLed if xpfd exits or TimeoutStopSec expires.
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
		t.Fatalf("xpfd.service KillMode = %q, want mixed so systemd cannot SIGTERM the helper before xpfd retires its generation (#18213)", killMode)
	}
}
