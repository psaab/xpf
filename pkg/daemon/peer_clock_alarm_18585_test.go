package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/clockskew"
	"github.com/psaab/xpf/pkg/cluster"
)

// #18585: the heartbeat-measured peer clock alarm reaches the shared clock
// alarm surfaces (show system alarms, show security alarms detail, show
// chassis cluster status), even before the local reference monitor exists.
func TestClockSkewAlarmsIncludePeerOffset18585(t *testing.T) {
	m := cluster.NewManager(0, 22)
	d := &Daemon{cluster: m}
	if got := d.clockSkewAlarms(); len(got) != 0 {
		t.Fatalf("no peer reading: alarms = %+v", got)
	}
	m.NotePeerWallClockForTesting(-72 * time.Second)
	got := d.clockSkewAlarms()
	if len(got) != 1 || got[0].Kind != clockskew.KindPeerOffset || got[0].OffsetSecs > -71 {
		t.Fatalf("alarms = %+v, want one KindPeerOffset at about -72s", got)
	}
	m.NotePeerWallClockForTesting(-1 * time.Second)
	if got := d.clockSkewAlarms(); len(got) != 0 {
		t.Fatalf("cleared peer alarm still listed: %+v", got)
	}
}
