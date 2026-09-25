package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// TestShowSecurityLogNegativeCount guards #3342: `show security log -1` must
// return a clean error at the CLI boundary, not crash the daemon. Before the
// fix the negative count flowed into EventBuffer.Latest(-1) ->
// make([]EventRecord, -1), panicking the control-plane process.
//
// FAIL-ON-REVERT: dropping the `v <= 0` boundary check in showSecurityLog
// (and the EventBuffer.Latest guard) makes "-1" panic instead of erroring.
func TestShowSecurityLogNegativeCount(t *testing.T) {
	c := &CLI{eventBuf: logging.NewEventBuffer(16)}
	c.eventBuf.Add(logging.EventRecord{Type: "SESSION_OPEN"})

	for _, arg := range []string{"-1", "-1000", "0"} {
		err := c.showSecurityLog([]string{arg})
		if err == nil {
			t.Errorf("showSecurityLog([%q]) = nil error, want a rejection", arg)
			continue
		}
		if !strings.Contains(err.Error(), "positive") {
			t.Errorf("showSecurityLog([%q]) error = %q, want it to mention 'positive'", arg, err.Error())
		}
	}
}

// TestShowSecurityLogPositiveCount confirms the boundary guard does not break
// the normal positive-count path.
func TestShowSecurityLogPositiveCount(t *testing.T) {
	c := &CLI{eventBuf: logging.NewEventBuffer(16)}
	c.eventBuf.Add(logging.EventRecord{Type: "SESSION_OPEN"})

	if err := c.showSecurityLog([]string{"5"}); err != nil {
		t.Errorf("showSecurityLog([\"5\"]) = %v, want nil", err)
	}
}

func TestShowSecurityLogRendersD11DenialReason11017(t *testing.T) {
	c := &CLI{eventBuf: logging.NewEventBuffer(4)}
	c.eventBuf.Add(logging.EventRecord{
		Type: "POLICY_DENY", Action: "deny", Reason: "D11 UNSUPPORTED_HOOK",
	})
	out := captureStdout(t, func() {
		if err := c.showSecurityLog([]string{"1"}); err != nil {
			t.Fatalf("showSecurityLog: %v", err)
		}
	})
	if !strings.Contains(out, `reason="D11 UNSUPPORTED_HOOK"`) {
		t.Fatalf("D11 operator denial reason missing from security log: %q", out)
	}
}
