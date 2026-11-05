package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

func TestBootAlarmReplay16016(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system.log")
	writer, err := logging.NewLocalLogWriter(logging.LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	d := &Daemon{}
	expiry := time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC)
	d.unkeyedAuthorityGraceAlarmSyslog("stamped", true, expiry)
	d.unkeyedAuthorityGraceAlarmSyslog("expired", true, expiry)

	if got, err := os.ReadFile(path); err != nil {
		t.Fatalf("read pre-readiness sink: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("boot notices were delivered before the event reader was ready: %q", got)
	}

	er := logging.NewEventReader(nil, nil)
	er.SetLocalWriters([]*logging.LocalLogWriter{writer})
	d.setEventReader(er)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replayed notices: %v", err)
	}
	stamped := "RT_SYSTEM - UNKEYED_AUTHORITY_GRACE_STAMPED"
	expired := "RT_SYSTEM - UNKEYED_AUTHORITY_GRACE_EXPIRED"
	if strings.Count(string(got), stamped) != 1 || strings.Count(string(got), expired) != 1 {
		t.Fatalf("sink must receive exactly one RT_SYSTEM STAMPED and EXPIRED notice, got %q", got)
	}
	if strings.Index(string(got), stamped) > strings.Index(string(got), expired) {
		t.Fatalf("boot notices were not replayed in order (STAMPED before EXPIRED): %q", got)
	}
}

func TestManagerExpiredBootAlarmReplaysToSourceLessSink16016(t *testing.T) {
	anchorPath := isolateAuthorityAnchors16016(t)
	expiredAt := time.Now().UTC().Add(-73 * time.Hour)
	record := fmt.Sprintf("v2 %d %d %d\n",
		expiredAt.UnixNano(), expiredAt.UnixNano(), int64(72*time.Hour))
	if err := os.WriteFile(anchorPath, []byte(record), 0o600); err != nil {
		t.Fatalf("seed expired authority anchor: %v", err)
	}

	clusterConfig := &config.ClusterConfig{
		ClusterID:        1,
		NodeID:           0,
		ControlInterface: "em0",
	}
	d := &Daemon{}
	if !d.constructClusterManager(&config.Config{
		Chassis: config.ChassisConfig{Cluster: clusterConfig},
	}) {
		t.Fatal("daemon did not construct a manager from boot cluster config")
	}
	d.cluster.UpdateConfigFromBoot(clusterConfig)
	if !d.cluster.UnkeyedAuthorityExpired() {
		t.Fatal("manager did not load the expired anchor at boot")
	}
	if d.eventReader != nil {
		t.Fatal("boot alarm unexpectedly had an event reader before no-dataplane setup")
	}

	path := filepath.Join(t.TempDir(), "system.log")
	writer, err := logging.NewLocalLogWriter(logging.LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	// The no-dataplane Run path installs a source-less reader; its explicit
	// local sink keeps manager-origin boot alarms deliverable without a runtime.
	er := logging.NewEventReader(nil, logging.NewEventBuffer(16))
	er.SetLocalWriters([]*logging.LocalLogWriter{writer})
	d.setEventReader(er)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manager-origin boot alarm: %v", err)
	}
	expired := "RT_SYSTEM - UNKEYED_AUTHORITY_GRACE_EXPIRED"
	stamped := "RT_SYSTEM - UNKEYED_AUTHORITY_GRACE_STAMPED"
	if strings.Count(string(got), expired) != 1 || strings.Contains(string(got), stamped) {
		t.Fatalf("expired boot must replay exactly one EXPIRED and no STAMPED notice, got %q", got)
	}
}
