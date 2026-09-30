package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// TestShowSecurityLogRejectDistinct11072 pins #11072(d): POLICY_REJECT
// renders RT_FLOW_SESSION_REJECT (a deny renders _DENY — the two used to
// be indistinguishable), and an empty ingress interface renders "unknown"
// instead of borrowing the zone name.
func TestShowSecurityLogRejectDistinct11072(t *testing.T) {
	buf := logging.NewEventBuffer(16)
	buf.Add(logging.EventRecord{Type: "POLICY_REJECT", InZone: 1, OutZone: 2})
	buf.Add(logging.EventRecord{Type: "POLICY_DENY", InZone: 1, OutZone: 2, IngressIface: "ge-0/0/0.0"})
	c := &CLI{
		eventBuf: buf,
		dp: &applyCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
				"trust": 1, "untrust": 2,
			}},
		},
	}
	var callErr error
	out := captureStdout(t, func() { callErr = c.showSecurityLog(nil) })
	if callErr != nil {
		t.Fatalf("showSecurityLog = %v; want nil", callErr)
	}
	if !strings.Contains(out, "RT_FLOW_SESSION_REJECT") {
		t.Fatalf("reject must render distinctly:\n%s", out)
	}
	if !strings.Contains(out, "RT_FLOW_SESSION_DENY") {
		t.Fatalf("deny must keep its tag:\n%s", out)
	}
	if strings.Contains(out, `packet-incoming-interface="trust"`) {
		t.Fatalf("empty iface must not borrow the zone name:\n%s", out)
	}
	if !strings.Contains(out, `packet-incoming-interface="unknown"`) {
		t.Fatalf("empty iface must render unknown:\n%s", out)
	}
	if !strings.Contains(out, `packet-incoming-interface="ge-0/0/0.0"`) {
		t.Fatalf("present iface must render verbatim:\n%s", out)
	}
}
