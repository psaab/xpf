package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryUpgradeStatusUsesRunningDaemonVersion12143(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	data := "format=1\n" +
		"staged_version=v2\n" +
		"running_version=v1\n" +
		"reason=cut-failed\n" +
		"recovery=xpfd upgrade\n" +
		"recorded_at=2026-10-08T12:00:00Z\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	status := binaryUpgradeStatusSnapshot(path, "v1.5-running-process")
	if status.ReadErr != nil {
		t.Fatalf("binaryUpgradeStatusSnapshot: %v", status.ReadErr)
	}
	if !status.Recorded || status.StagedVersion != "v2" || status.RunningVersion != "v1.5-running-process" {
		t.Fatalf("status = %+v, want staged v2 and running process identity v1.5-running-process", status)
	}
}

func TestProductionAPIServerConfigReadsPendingBinaryUpgradeStatus12143(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	data := "format=1\n" +
		"staged_version=v2\n" +
		"running_version=v1\n" +
		"reason=cut-failed\n" +
		"recovery=xpfd upgrade\n" +
		"recorded_at=2026-10-08T12:00:00Z\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath := daemonBinaryUpgradeStatusPath
	daemonBinaryUpgradeStatusPath = path
	t.Cleanup(func() { daemonBinaryUpgradeStatusPath = oldPath })

	d := &Daemon{opts: Options{Version: "v1.5-running-process"}}
	status := d.apiServerConfig(nil).BinaryUpgradeStatusFn()
	if !status.Readable || !status.Pending {
		t.Fatalf("production apiServerConfig status = %+v, want readable pending state", status)
	}
	if status.StagedVersion != "v2" || status.RunningVersion != "v1.5-running-process" {
		t.Fatalf("production apiServerConfig status versions = staged %q, running %q",
			status.StagedVersion, status.RunningVersion)
	}
}
