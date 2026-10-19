package configstore

import (
	"strings"
	"testing"
)

// #15171 (B19-01): strict CheckText — the real commit gate — must reject
// tcp-mss values below the Junos floor 64 naming the range, and accept
// 64 / 1350. The value-level assertions live in pkg/config
// (TestTCPMSSFloor15171_*).
func TestCheckTextTCPMSSFloor15171(t *testing.T) {
	for _, text := range []string{
		"security { flow { tcp-mss { gre-in 0; } } }",
		"security { flow { tcp-mss { all-tcp { mss 63; } } } }",
		"security { flow { tcp-mss { gre-out mss 1; } } }",
	} {
		_, err := CheckText(text, -1)
		if err == nil {
			t.Errorf("CheckText ACCEPTED below-floor %q", text)
		} else if !strings.Contains(err.Error(), "tcp-mss") ||
			!strings.Contains(err.Error(), "[64..65535]") {
			t.Errorf("CheckText rejection for %q must name tcp-mss [64..65535]: %v", text, err)
		}
	}
	cfg, err := CheckText("security { flow { tcp-mss { gre-in 64; all-tcp { mss 1350; } } } }", -1)
	if err != nil {
		t.Fatalf("in-range control must pass CheckText: %v", err)
	}
	if cfg.Security.Flow.TCPMSSGreIn != 64 || cfg.Security.Flow.TCPMSSAllTCP != 1350 {
		t.Errorf("control -> greIn=%d all=%d, want 64/1350",
			cfg.Security.Flow.TCPMSSGreIn, cfg.Security.Flow.TCPMSSAllTCP)
	}
}
