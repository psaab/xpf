package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

// TestZeroizeTraceConfined16576HostLogSurvives pins #16576 on the wipe side:
// the configured persistent trace basename now resolves inside the dedicated
// flow-trace dir, so wipeFirewallLogs (the narrow, foreign-host-safe leg)
// erases the confined trace + generations but leaves a host log of the same
// name in /var/log byte-identical. Pre-fix the leg resolved the basename
// under /var/log and deleted the host log.
//
// seamZeroizeFirewallLogPaths does NOT plant the appliance marker, and
// wipeFirewallLogs alone never runs the appliance wholesale `logfiles` leg,
// so a surviving auth.log here is attributable to this leg alone.
func TestZeroizeTraceConfined16576HostLogSurvives(t *testing.T) {
	root := t.TempDir()
	seamZeroizeFirewallLogPaths(t, root)
	varLog := filepath.Join(root, "var", "log")
	flowDir := filepath.Join(varLog, "xpf-flow-trace")

	hostBody := []byte("host auth records\n")
	mustWriteFile(t, filepath.Join(varLog, "auth.log"), hostBody)
	for _, name := range []string{"auth.log", "auth.log.1"} {
		mustWriteFile(t, filepath.Join(flowDir, name), []byte("prior confined trace"))
	}

	if err := wipeFirewallLogs(ZeroizeLogInventory{TraceFile: "auth.log"}); err != nil {
		t.Fatalf("wipeFirewallLogs: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(varLog, "auth.log"))
	if err != nil {
		t.Fatalf("host /var/log/auth.log was wiped by the trace leg: %v", err)
	}
	if string(got) != string(hostBody) {
		t.Fatalf("host auth.log = %q, want byte-identical %q", got, hostBody)
	}
	// The whole confined dir (including the trace generations) is gone.
	if _, err := os.Stat(flowDir); !os.IsNotExist(err) {
		t.Fatalf("confined flow-trace dir still present after wipe: %v", err)
	}
}
