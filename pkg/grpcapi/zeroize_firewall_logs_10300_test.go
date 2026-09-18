package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
// now that the exported primitive includes the static firewall-log leg.
func seamZeroizeFirewallLogPaths(t *testing.T, root string) {
	t.Helper()
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
}
