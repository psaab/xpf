package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/logging"
	"golang.org/x/sync/semaphore"
)

type bootAlarmCaptureConn16016 struct {
	writes chan []byte
}

func (c *bootAlarmCaptureConn16016) Read([]byte) (int, error) { return 0, io.EOF }
func (c *bootAlarmCaptureConn16016) Write(p []byte) (int, error) {
	c.writes <- append([]byte(nil), p...)
	return len(p), nil
}
func (c *bootAlarmCaptureConn16016) Close() error { return nil }
func (c *bootAlarmCaptureConn16016) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
func (c *bootAlarmCaptureConn16016) RemoteAddr() net.Addr             { return c.LocalAddr() }
func (c *bootAlarmCaptureConn16016) SetDeadline(time.Time) error      { return nil }
func (c *bootAlarmCaptureConn16016) SetReadDeadline(time.Time) error  { return nil }
func (c *bootAlarmCaptureConn16016) SetWriteDeadline(time.Time) error { return nil }

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

func TestDaemonRunNoDataplaneExpiredBootAlarmReachesSink16016(t *testing.T) {
	anchorPath := isolateAuthorityAnchors16016(t)
	const port = 514
	storePath := filepath.Join(t.TempDir(), "xpf.conf")
	configText := fmt.Sprintf(
		"chassis { cluster { cluster-id 1; control-interface em0; } }\n"+
			"security { log { mode stream; stream boot-alarm { host 127.0.0.1; port %d; transport { protocol udp; } } } }",
		port)
	store := newConfigStore(t, storePath)
	if _, err := store.SyncApply(configText, nil); err != nil {
		t.Fatalf("seed unkeyed clustered config and syslog stream: %v", err)
	}
	freshStore := newConfigStore(t, storePath)
	if err := freshStore.Load(); err != nil {
		t.Fatalf("load daemon config: %v", err)
	}
	activeConfig := freshStore.ActiveConfig()
	if activeConfig == nil || activeConfig.Chassis.Cluster == nil ||
		activeConfig.Security.Log.Mode != "stream" || len(activeConfig.Security.Log.Streams) != 1 {
		t.Fatalf("test config did not retain cluster and stream syslog: %+v", activeConfig)
	}

	syslogConn := &bootAlarmCaptureConn16016{writes: make(chan []byte, 8)}
	oldUDPFactory := newSecuritySyslogUDPClientFn
	newSecuritySyslogUDPClientFn = func(_ string, _ int, _ string, protocol string, _ *tls.Config) (*logging.SyslogClient, error) {
		return logging.NewSyslogClientWithConn(syslogConn, protocol), nil
	}
	t.Cleanup(func() {
		newSecuritySyslogUDPClientFn = oldUDPFactory
		_ = syslogConn.Close()
	})
	expiredAt := time.Now().UTC().Add(-73 * time.Hour)
	record := fmt.Sprintf("v2 %d %d %d\n",
		expiredAt.UnixNano(), expiredAt.UnixNano(), int64(72*time.Hour))
	if err := os.WriteFile(anchorPath, []byte(record), 0o600); err != nil {
		t.Fatalf("seed expired authority anchor: %v", err)
	}
	isolateHandoffFlag(t)
	withTempTransitForwardSysctls(t, "1")
	withTransitOwnershipRecord14620(t)
	oldNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return false }
	t.Cleanup(func() { hasNodeIDFileFn = oldNodeIDCheck })

	var runLogs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&runLogs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	confPath, _ := seededFRRConf(t)
	d := &Daemon{
		daemonLockLease: mustTestDaemonLockLease15085(t),
		applySem:        semaphore.NewWeighted(1),
		store:           freshStore,
		frr:             frr.NewForTest(confPath, &frr.RecordingExecutor{}),
		opts: Options{
			ConfigFile:  storePath,
			NoDataplane: true,
			GRPCAddr:    "127.0.0.1:0",
		},
		fatalCh: make(chan error, 1),
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	joined := false
	t.Cleanup(func() {
		cancelRun()
		if !joined {
			d.signalFatal(errors.New("test cleanup after NoDataplane Run failure"))
			select {
			case <-runDone:
			case <-time.After(10 * time.Second):
				t.Error("Daemon.Run did not stop during test cleanup")
			}
		}
		if d.eventReader != nil {
			d.eventReader.ReplaceSyslogClients(nil)
		}
		d.syslogClearCache15231()
	})
	go func() { runDone <- d.Run(runCtx) }()

	var received []string
	overallDeadline := time.Now().Add(10 * time.Second)
	expiredReceived := false
	for !expiredReceived && time.Now().Before(overallDeadline) {
		select {
		case frame := <-syslogConn.writes:
			message := string(frame)
			received = append(received, message)
			expiredReceived = strings.Contains(message, "UNKEYED_AUTHORITY_GRACE_EXPIRED") &&
				strings.Contains(message, `rung="expired"`)
		case runErr := <-runDone:
			joined = true
			t.Fatalf("Daemon.Run returned before the boot alarm reached its sink: %v", runErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !expiredReceived {
		d.signalFatal(errors.New("test stop after missing boot alarm"))
		select {
		case <-runDone:
			joined = true
		case <-time.After(10 * time.Second):
			t.Fatal("Daemon.Run did not stop after missing-alarm diagnostic signal")
		}
		clientCount := 0
		if d.eventReader != nil {
			clientCount = len(d.eventReader.SyslogClients())
		}
		managerExpired := d.cluster != nil && d.cluster.UnkeyedAuthorityExpired()
		bootAlarmReplay.Lock()
		pendingAlarms := len(bootAlarmReplay.pending[d])
		bootAlarmReplay.Unlock()
		t.Fatalf("NoDataplane Daemon.Run did not deliver the expired boot alarm: managerExpired=%t readerNil=%t clients=%d pending=%d logs=%s",
			managerExpired, d.eventReader == nil, clientCount, pendingAlarms, runLogs.String())
	}

	stopAfterNotice := errors.New("test stop after boot alarm delivery")
	d.signalFatal(stopAfterNotice)
	select {
	case runErr := <-runDone:
		joined = true
		if !errors.Is(runErr, stopAfterNotice) {
			t.Fatalf("Daemon.Run returned %v, want its signaled stop", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Daemon.Run did not stop after its fatal signal")
	}
	if d.eventReader != nil {
		d.eventReader.ReplaceSyslogClients(nil)
	}
	d.syslogClearCache15231()

	for {
		select {
		case frame := <-syslogConn.writes:
			received = append(received, string(frame))
		default:
			goto sinkDrained
		}
	}
sinkDrained:
	expired := 0
	stamped := 0
	for _, message := range received {
		if strings.Contains(message, "UNKEYED_AUTHORITY_GRACE_EXPIRED") &&
			strings.Contains(message, `rung="expired"`) {
			expired++
		}
		if strings.Contains(message, "UNKEYED_AUTHORITY_GRACE_STAMPED") {
			stamped++
		}
	}
	if expired != 1 || stamped != 0 {
		t.Fatalf("production NoDataplane Run sink received expired=%d stamped=%d messages=%q",
			expired, stamped, received)
	}
}
