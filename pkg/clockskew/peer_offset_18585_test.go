package clockskew

import (
	"strings"
	"testing"
)

// #18585: the inter-node alarm names the peer, the direction, the measured
// value, and the fabric-auth bounds.
func TestPeerOffsetAlarmSummary18585(t *testing.T) {
	got := ActiveAlarm{Kind: KindPeerOffset, OffsetSecs: -71.94}.Summary()
	for _, want := range []string{"peer node wall clock is 71.9s behind this node", "authenticated heartbeats", "30-60s", "NTP"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q missing %q", got, want)
		}
	}
	if d := (ActiveAlarm{Kind: KindPeerOffset, OffsetSecs: 12.5}).detail(); !strings.Contains(d, "+12.5s") {
		t.Fatalf("detail %q", d)
	}
}
