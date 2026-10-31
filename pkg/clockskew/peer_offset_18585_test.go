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

// #18585: the peer alarm's syslog lines share the local alarm's RT_SYSTEM
// CLOCK_SKEW_ALARM_* shape and severities, so one filter sees both.
func TestPeerOffsetSyslogLine18585(t *testing.T) {
	sev, msg := PeerOffsetSyslogLine(true, -74.9)
	if sev != SeverityRaise || msg != `RT_SYSTEM - CLOCK_SKEW_ALARM_RAISED cause="peer-offset" detail="peer wall clock -74.9s from this node"` {
		t.Fatalf("raise = (%d, %q)", sev, msg)
	}
	sev, msg = PeerOffsetSyslogLine(false, 0.3)
	if sev != SeverityClear || !strings.HasPrefix(msg, `RT_SYSTEM - CLOCK_SKEW_ALARM_CLEARED reason="peer offset recovered"`) {
		t.Fatalf("clear = (%d, %q)", sev, msg)
	}
}
