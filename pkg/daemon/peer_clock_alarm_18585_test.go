package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/clockskew"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
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

// #18585 review seat AE: the daemon WIRES the peer alarm to syslog where it
// constructs the cluster manager. Drive the production constructor and
// assert a raise and a clear reach the event reader's local writer in the
// RT_SYSTEM CLOCK_SKEW_ALARM_* shape — deleting the SetPeerClockAlarmHook
// call makes this red.
func TestConstructClusterManagerWiresPeerClockSyslog18585(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	lw, err := logging.NewLocalLogWriter(logging.LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lw.Close() })
	er := logging.NewEventReader(nil, logging.NewEventBuffer(8))
	er.ReplaceLocalWriters([]*logging.LocalLogWriter{lw})
	d := &Daemon{eventReader: er}
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0, ClusterID: 22}
	if !d.constructClusterManager(cfg) {
		t.Fatal("constructClusterManager declined a cluster config")
	}
	d.cluster.NotePeerWallClockForTesting(-72 * time.Second)
	d.cluster.NotePeerWallClockForTesting(-1 * time.Second)
	b, _ := os.ReadFile(path)
	got := string(b)
	for _, want := range []string{`CLOCK_SKEW_ALARM_RAISED cause="peer-offset"`, `CLOCK_SKEW_ALARM_CLEARED reason="peer offset recovered"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("syslog sink is missing %q; got:\n%s", want, got)
		}
	}
}
