package grpcapi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestPerformZeroizeWipeErasesFirewallLogs10300 is the RED-on-revert guard for
// the complete firewall-log surface. It uses the same shared wipe primitive
// both gRPC and the console call, with every host path seamed into a temp tree.
// The pre-fix primitive returns clean while these fixtures remain on disk.
func TestPerformZeroizeWipeErasesFirewallLogs10300(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system {}\n"))
	hermeticWipe10100(t, root)
	varLog := filepath.Join(root, "var", "log")
	securityDir := filepath.Join(varLog, "xpf")
	flowDir := filepath.Join(varLog, "xpf-flow-trace")
	rsyslogDir := filepath.Join(root, "etc", "rsyslog.d")
	origVarLog, origSecurityDir, origFlowDir, origRsyslogDir :=
		zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir
	t.Cleanup(func() {
		zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir =
			origVarLog, origSecurityDir, origFlowDir, origRsyslogDir
	})
	zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir =
		varLog, securityDir, flowDir, rsyslogDir

	// Static security log and its local-writer generations.
	for _, name := range []string{"security.log", "security.log.1", "security.log.1.gz"} {
		mustWriteFile(t, filepath.Join(securityDir, name), []byte("prior security event"))
	}
	// Dedicated interactive monitor flow-trace namespace is entirely xpf-owned.
	mustWriteFile(t, filepath.Join(flowDir, "monitor.log"), []byte("prior monitor flow"))
	mustWriteFile(t, filepath.Join(flowDir, "monitor.log.1"), []byte("prior monitor flow"))
	// Configured persistent trace uses /var/log/<basename> and rotates there.
	for _, name := range []string{"trace.log", "trace.log.1", "trace.log.1.gz", "trace.log-20260918", "trace.log-2026-09-18.gz"} {
		mustWriteFile(t, filepath.Join(varLog, name), []byte("prior persistent flow"))
	}
	// Configured rsyslog outputs, including common host logrotate forms.
	for _, name := range []string{"messages", "messages.1", "messages.1.gz", "messages-20260918", "messages-2026-09-18.gz", "audit"} {
		mustWriteFile(t, filepath.Join(varLog, name), []byte("prior firewall syslog"))
	}
	mustWriteFile(t, filepath.Join(rsyslogDir, "10-xpf-messages.conf"), []byte("*.*\t/var/log/messages\n"))
	mustWriteFile(t, filepath.Join(rsyslogDir, "10-xpf-audit.conf"), []byte("*.*\t/var/log/audit\n"))
	mustWriteFile(t, filepath.Join(rsyslogDir, "50-default.conf"), []byte("*.*\t/var/log/syslog\n"))
	// Bystanders prove the leg is not a blanket /var/log removal, including a
	// basename the renderer rejects even if a lenient config reaches the wipe.
	mustWriteFile(t, filepath.Join(varLog, "messages-other"), []byte("operator log"))
	mustWriteFile(t, filepath.Join(varLog, "auth.log"), []byte("host log"))
	mustWriteFile(t, filepath.Join(varLog, "operator log"), []byte("unmanaged log"))

	inv := ZeroizeLogInventory{SyslogFiles: []string{"messages", "audit", "operator log"}, TraceFile: "trace.log"}
	if err := PerformZeroizeWipeWithLogInventory(configDir, "xpf.conf", "", inv); err != nil {
		t.Fatalf("PerformZeroizeWipeWithLogInventory returned error: %v", err)
	}

	for _, name := range []string{
		"xpf/security.log", "xpf/security.log.1", "xpf/security.log.1.gz",
		"xpf-flow-trace/monitor.log", "xpf-flow-trace/monitor.log.1",
		"trace.log", "trace.log.1", "trace.log.1.gz", "trace.log-20260918", "trace.log-2026-09-18.gz",
		"messages", "messages.1", "messages.1.gz", "messages-20260918", "messages-2026-09-18.gz", "audit",
	} {
		assertAbsent(t, filepath.Join(varLog, name))
	}
	for _, name := range []string{"10-xpf-messages.conf", "10-xpf-audit.conf"} {
		assertAbsent(t, filepath.Join(rsyslogDir, name))
	}
	assertPresent(t, filepath.Join(rsyslogDir, "50-default.conf"))
	for _, name := range []string{"messages-other", "auth.log", "operator log"} {
		assertPresent(t, filepath.Join(varLog, name))
	}
}

// TestZeroizeFirewallLogsReportsHardlinks10300 pins that every firewall-log
// leg attests inode aliases before unlinking: the managed name disappears, but
// a surviving sibling keeps the bytes and must make zeroize fail closed.
func TestZeroizeFirewallLogsReportsHardlinks10300(t *testing.T) {
	root := t.TempDir()
	seamZeroizeFirewallLogPaths(t, root)
	varLog := filepath.Join(root, "var", "log")
	flowDir := filepath.Join(varLog, "xpf-flow-trace")
	syslogPath := filepath.Join(varLog, "messages")
	flowPath := filepath.Join(flowDir, "monitor.log")
	syslogAlias := filepath.Join(root, "messages-alias")
	flowAlias := filepath.Join(root, "flow-alias")
	mustWriteFile(t, syslogPath, []byte("syslog"))
	mustWriteFile(t, flowPath, []byte("flow"))
	if err := os.Link(syslogPath, syslogAlias); err != nil {
		t.Fatalf("syslog hardlink: %v", err)
	}
	if err := os.Link(flowPath, flowAlias); err != nil {
		t.Fatalf("flow hardlink: %v", err)
	}

	err := zeroizeFirewallLogs(ZeroizeLogInventory{SyslogFiles: []string{"messages"}})
	var hardErr *configstore.FactoryResetHardlinkError
	if !errors.As(err, &hardErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	if len(hardErr.Paths) != 2 {
		t.Fatalf("hardlink census = %+v, want managed syslog and flow paths", hardErr.Paths)
	}
	assertAbsent(t, syslogPath)
	assertAbsent(t, flowPath)
	assertPresent(t, syslogAlias)
	assertPresent(t, flowAlias)
}

// TestZeroizeReceiptAttestsFirewallLogScope10300 binds the pre-wipe config
// snapshot to the shared gRPC path and pins the operator-facing receipt. A
// clean response must state that the firewall-log scope was erased; the old
// response only said "Configuration erased" and omitted the surviving logs.
func TestZeroizeReceiptAttestsFirewallLogScope10300(t *testing.T) {
	origWipe, origStop := performZeroizeWipeWithLogInventory, scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})
	var got ZeroizeLogInventory
	performZeroizeWipeWithLogInventory = func(_, _, _ string, inv ZeroizeLogInventory) error {
		got = inv
		return nil
	}
	scheduleStopDaemon = func() {}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, set := range []string{
		"set system syslog file messages any any",
		"set system syslog file audit any warning",
		"set security flow traceoptions file trace.log",
	} {
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet(%q): %v", set, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	s := &Server{store: store}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if len(got.SyslogFiles) != 2 || got.SyslogFiles[0] != "messages" || got.SyslogFiles[1] != "audit" || got.TraceFile != "trace.log" {
		t.Fatalf("zeroize did not snapshot configured log inventory before wiping: %+v", got)
	}
	if resp == nil || !strings.Contains(strings.ToLower(resp.Message), "firewall log") {
		t.Fatalf("zeroize receipt omits the firewall-log wipe scope: %+v", resp)
	}
}

// TestZeroizeSnapshotsFirewallInventoryInsideGate10300 prevents an apply-gate
// race: a commit waiting for ZeroizeFn may add a destination before the wipe
// closure runs, and that destination must be included in the final inventory.
func TestZeroizeSnapshotsFirewallInventoryInsideGate10300(t *testing.T) {
	origWipe, origStop := performZeroizeWipeWithLogInventory, scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})
	var got ZeroizeLogInventory
	performZeroizeWipeWithLogInventory = func(_, _, _ string, inv ZeroizeLogInventory) error {
		got = inv
		return nil
	}
	scheduleStopDaemon = func() {}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, set := range []string{
		"set system syslog file messages any any",
		"set security flow traceoptions file trace.log",
	} {
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet(%q): %v", set, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit initial config: %v", err)
	}
	store.ExitConfigure()
	s := &Server{
		store: store,
		zeroizeFn: func(_ context.Context, wipe func() error) error {
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure gated commit: %v", err)
			}
			for _, set := range []string{
				"set system syslog file committed-during-gate any notice",
				"set security flow traceoptions file committed-trace.log",
			} {
				if _, err := store.LoadSet(set); err != nil {
					t.Fatalf("LoadSet(%q): %v", set, err)
				}
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit gated config: %v", err)
			}
			return wipe()
		},
	}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if len(got.SyslogFiles) != 2 || got.SyslogFiles[0] != "messages" || got.SyslogFiles[1] != "committed-during-gate" {
		t.Fatalf("zeroize inventory missed gated syslog destination: %+v", got)
	}
	if got.TraceFile != "committed-trace.log" {
		t.Fatalf("zeroize inventory missed gated trace destination: %+v", got)
	}
}

// seamZeroizeFirewallLogPaths keeps direct PerformZeroizeWipe tests hermetic
// now that the exported primitive includes the static firewall-log leg and
// the day-0 loader gate.
func seamZeroizeFirewallLogPaths(t *testing.T, root string) {
	t.Helper()
	varLog := filepath.Join(root, "var", "log")
	securityDir := filepath.Join(varLog, "xpf")
	flowDir := filepath.Join(varLog, "xpf-flow-trace")
	rsyslogDir := filepath.Join(root, "etc", "rsyslog.d")
	origVarLog, origSecurityDir, origFlowDir, origRsyslogDir :=
		zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir
	origPendingPath := configstore.FactoryResetPendingPath
	configstore.FactoryResetPendingPath = filepath.Join(root, "etc", "xpf", configstore.Day0ConfigAppliedBase)
	t.Cleanup(func() { configstore.FactoryResetPendingPath = origPendingPath })
	t.Cleanup(func() {
		zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir =
			origVarLog, origSecurityDir, origFlowDir, origRsyslogDir
	})
	zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir =
		varLog, securityDir, flowDir, rsyslogDir
}
func TestInterruptedZeroizeRemainsFailClosedAndReplaysInventory10742(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "custom-config")
	loaderDir := filepath.Join(root, "etc", "xpf")
	configFile := filepath.Join(configDir, "xpf.conf")
	activeDB := filepath.Join(configDir, ".configdb", "active.json")
	mustWriteFile(t, activeDB, []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, configFile, []byte("system { host-name prior-tenant; }\n"))
	mustWriteFile(t, filepath.Join(configDir, ".config.journal"), []byte("zeroize record\n"))
	hermeticWipe10100(t, root)

	const secret = "prior-tenant-secret-10742"
	rendered := filepath.Join(root, "rendered", "frr", "frr.conf")
	mustWriteFile(t, rendered, []byte("! BEGIN BPFRX MANAGED CONFIG - do not edit this section\n"+secret+"\n! END BPFRX MANAGED CONFIG\n"))

	varLog := filepath.Join(root, "var", "log")
	mustWriteFile(t, filepath.Join(varLog, "trace-10742.log"), []byte("trace"))
	mustWriteFile(t, filepath.Join(varLog, "syslog-10742.log"), []byte("syslog"))
	inventory := ZeroizeLogInventory{
		TraceFile:   "trace-10742.log",
		SyslogFiles: []string{"syslog-10742.log"},
	}
	customArchive := filepath.Join(root, "custom-archive")
	archiveSecret := filepath.Join(customArchive, "config.conf")
	mustWriteFile(t, archiveSecret, []byte(secret))

	// Stop after the durable marker replacement and before any wipe leg. The
	// existing loader gate must skip medium probing, and Store.Load must
	// classify the versioned stamp as an interrupted reset.
	record, err := beginZeroize(configDir, "xpf.conf", customArchive, inventory)
	if err != nil {
		t.Fatalf("write zeroize intent: %v", err)
	}
	loaderMarker := configstore.FactoryResetPendingPath
	configMarker := filepath.Join(configDir, configstore.FactoryResetPendingBase)
	if record.ArchiveDir != customArchive {
		t.Fatalf("pending record archive dir = %q, want %q", record.ArchiveDir, customArchive)
	}
	assertPresent(t, loaderMarker)
	assertPresent(t, configMarker)
	if _, err := beginZeroize(filepath.Join(root, "other-config"), "xpf.conf", "", ZeroizeLogInventory{}); err == nil {
		t.Fatal("pending reset replayed against a different config root")
	}
	assertDay0LoaderSkipsMedia(t, loaderDir)
	store, err := configstore.New(configFile)
	if err != nil {
		t.Fatalf("create config store before wipe: %v", err)
	}
	loadErr := store.Load()
	if !errors.Is(loadErr, configstore.ErrFactoryResetPending) ||
		!errors.Is(loadErr, configstore.ErrConfigAbsentWithHistory) {
		t.Fatalf("pre-wipe Load error = %v, want fail-closed reset marker", loadErr)
	}
	assertPresent(t, activeDB)
	assertPresent(t, configFile)

	originalSync := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = originalSync })
	interrupt := errors.New("simulated interruption after config-state unlink")
	configSyncFailed := false
	zeroizeSyncDir = func(dir string) error {
		if filepath.Clean(dir) == filepath.Clean(configDir) && !configSyncFailed {
			configSyncFailed = true
			if data, err := os.ReadFile(rendered); err != nil || strings.Contains(string(data), secret) {
				t.Errorf("rendered credential leg had not run before the config leg: err=%v content=%q", err, data)
			}
			return interrupt
		}
		return originalSync(dir)
	}

	err = performZeroizeWipeWithLogInventory(configDir, "xpf.conf", customArchive, inventory)
	if !errors.Is(err, interrupt) || !configSyncFailed {
		t.Fatalf("wipe error = %v, want simulated post-config interruption", err)
	}
	assertAbsent(t, activeDB)
	assertAbsent(t, configFile)
	if data, err := os.ReadFile(rendered); err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("rendered credential survived the interrupted wipe: err=%v content=%q", err, data)
	}
	assertAbsent(t, filepath.Join(varLog, "trace-10742.log"))
	assertAbsent(t, filepath.Join(varLog, "syslog-10742.log"))

	// A fresh Store.Load must refuse the apparent empty/factory state instead
	// of permitting day-0 import or normal takeover.
	store, err = configstore.New(configFile)
	if err != nil {
		t.Fatalf("create config store: %v", err)
	}
	loadErr = store.Load()
	if !errors.Is(loadErr, configstore.ErrFactoryResetPending) ||
		!errors.Is(loadErr, configstore.ErrConfigAbsentWithHistory) {
		t.Fatalf("Load error = %v, want fail-closed interrupted-reset marker", loadErr)
	}

	// The retry deliberately supplies the empty values a post-wipe Store would
	// have. The pending record must restore the original archive path and log
	// inventory; the custom archive remains an explicit incomplete-reset error.
	mustWriteFile(t, filepath.Join(varLog, "trace-10742.log"), []byte("late trace generation"))
	mustWriteFile(t, filepath.Join(varLog, "syslog-10742.log"), []byte("late syslog generation"))
	retryErr := performZeroizeWipeWithLogInventory(configDir, "xpf.conf", "", ZeroizeLogInventory{})
	var archiveSkipped *configstore.ArchiveDirSkippedError
	if !errors.As(retryErr, &archiveSkipped) {
		t.Fatalf("retry error = %v, want persisted custom archive ownership failure", retryErr)
	}
	if archiveSkipped.Dir != customArchive {
		t.Fatalf("retry skipped archive %q, want persisted path %q", archiveSkipped.Dir, customArchive)
	}
	assertAbsent(t, filepath.Join(varLog, "trace-10742.log"))
	assertAbsent(t, filepath.Join(varLog, "syslog-10742.log"))
	assertPresent(t, archiveSecret)
	if _, err := os.Stat(loaderMarker); err != nil {
		t.Fatalf("incomplete retry removed loader marker: %v", err)
	}
	if _, err := os.Stat(configMarker); err != nil {
		t.Fatalf("incomplete retry removed config-root marker: %v", err)
	}

	t.Run("successful reset clears loader gate", func(t *testing.T) {
		root := t.TempDir()
		configDir := filepath.Join(root, "custom-config")
		loaderDir := filepath.Join(root, "etc", "xpf")
		configFile := filepath.Join(configDir, "xpf.conf")
		mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
		mustWriteFile(t, configFile, []byte("system { host-name prior-tenant; }\n"))
		mustWriteFile(t, filepath.Join(loaderDir, configstore.Day0ConfigAppliedBase),
			[]byte("applied xpf.conf from /dev/test at 2026-09-25T00:00:00Z\n"))
		hermeticWipe10100(t, root)

		if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
			t.Fatalf("complete factory reset: %v", err)
		}
		assertAbsent(t, configstore.FactoryResetPendingPath)
		assertAbsent(t, filepath.Join(configDir, configstore.FactoryResetPendingBase))

		store, err := configstore.New(configFile)
		if err != nil {
			t.Fatalf("create post-reset config store: %v", err)
		}
		if err := store.Load(); errors.Is(err, configstore.ErrFactoryResetPending) {
			t.Fatalf("post-reset Load still sees pending marker: %v", err)
		}
		assertDay0LoaderProbesMedia(t, loaderDir)
	})
}

func TestZeroizeRejectsDay0MarkerBasenameCollision10742(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "custom-config")
	configBase := configstore.FactoryResetPendingBase
	configFile := filepath.Join(configDir, configBase)
	const contents = "operator config using the reserved marker basename"
	mustWriteFile(t, configFile, []byte(contents))
	hermeticWipe10100(t, root)

	err := PerformZeroizeWipe(configDir, configBase, "")
	if err == nil || !strings.Contains(err.Error(), "conflicts with the reset marker") {
		t.Fatalf("zeroize error = %v, want reset-marker basename conflict", err)
	}
	data, err := os.ReadFile(configFile)
	if err != nil || string(data) != contents {
		t.Fatalf("config was changed before collision refusal: err=%v contents=%q", err, data)
	}
	assertAbsent(t, configstore.FactoryResetPendingPath)
}

func TestCompleteZeroizeKeepsLoaderGateUntilConfigMarkerDurable10742(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "custom-config")
	loaderDir := filepath.Join(root, "etc", "xpf")
	hermeticWipe10100(t, root)

	record, err := beginZeroize(configDir, "xpf.conf", "", ZeroizeLogInventory{})
	if err != nil {
		t.Fatalf("begin zeroize: %v", err)
	}
	loaderMarker := configstore.FactoryResetPendingPath
	originalSync := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = originalSync })
	syncFailure := errors.New("simulated config-marker directory sync failure")
	var syncOrder []string
	zeroizeSyncDir = func(dir string) error {
		syncOrder = append(syncOrder, filepath.Clean(dir))
		if filepath.Clean(dir) == filepath.Clean(configDir) {
			if err := originalSync(dir); err != nil {
				return err
			}
			return syncFailure
		}
		return originalSync(dir)
	}

	if err := completeZeroize(record); !errors.Is(err, syncFailure) {
		t.Fatalf("complete zeroize error = %v, want config-marker sync failure", err)
	}
	if len(syncOrder) == 0 || syncOrder[0] != filepath.Clean(configDir) {
		t.Fatalf("marker sync order = %v, want custom config root first", syncOrder)
	}
	if _, err := os.Stat(loaderMarker); err != nil {
		t.Fatalf("loader gate was removed before config-marker durability: %v", err)
	}
	configMarker := filepath.Join(configDir, configstore.FactoryResetPendingBase)
	if _, err := os.Lstat(configMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config-root marker error = %v, want marker durably removed", err)
	}
	store, err := configstore.New(filepath.Join(configDir, "xpf.conf"))
	if err != nil {
		t.Fatalf("create store for interrupted reset: %v", err)
	}
	if err := store.Load(); !errors.Is(err, configstore.ErrFactoryResetPending) {
		t.Fatalf("Load with loader marker only = %v, want ErrFactoryResetPending", err)
	}
	assertDay0LoaderSkipsMedia(t, loaderDir)
}

func assertDay0LoaderSkipsMedia(t *testing.T, loaderDir string) {
	t.Helper()
	output := runDay0Loader(t, loaderDir)
	if !strings.Contains(output, "day-0 config already applied") || strings.Contains(output, "DAY0_PROBED") {
		t.Fatalf("day-0 loader did not honor the pending reset stamp: %s", output)
	}
}

func assertDay0LoaderProbesMedia(t *testing.T, loaderDir string) {
	t.Helper()
	output := runDay0Loader(t, loaderDir)
	if !strings.Contains(output, "DAY0_PROBED") {
		t.Fatalf("day-0 loader did not resume probing after completed reset: %s", output)
	}
}

func runDay0Loader(t *testing.T, loaderDir string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve regression-test source path")
	}
	loader := filepath.Join(filepath.Dir(sourceFile), "..", "..", "scripts", "image", "xpf-day0-config")
	script := `export XPF_DAY0_SOURCE_ONLY=1
source "$1" || exit 99
XPF_DIR="$2"
REJECT_MARKER="$XPF_DIR/.day0-config-rejected"
MNT="$XPF_DIR/mnt"
STAMP="$XPF_DIR/.day0-config-applied"
XPFD=/bin/true
regen_ssh_host_keys() { :; }
probe_devices() { printf 'fake-device\n'; echo DAY0_PROBED >&2; }
try_device() { return 1; }
main
`
	cmd := exec.Command("bash", "-c", script, "loader-test", loader, loaderDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run day-0 loader: %v: %s", err, output)
	}
	return string(output)
}
