package upgrade

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeBinaryUpgradeStatus12143(t *testing.T, path string) {
	t.Helper()
	data := "format=1\n" +
		"staged_version=v2\n" +
		"running_version=v1\n" +
		"reason=cut-failed\n" +
		"recovery=xpfd upgrade\n" +
		"recorded_at=2026-10-08T12:00:00Z\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write binary-upgrade status: %v", err)
	}
}

func TestBinaryUpgradeStatusRendersStagedRunningSkew12143(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writeBinaryUpgradeStatus12143(t, path)

	status := ReadBinaryUpgradeStatus(path)
	if status.ReadErr != nil {
		t.Fatalf("ReadBinaryUpgradeStatus: %v", status.ReadErr)
	}
	if !status.Recorded || status.StagedVersion != "v2" || status.RunningVersion != "v1" {
		t.Fatalf("status = %+v, want recorded staged v2 / running v1", status)
	}
	if status.Reason != "cut-failed" || status.Recovery != "xpfd upgrade" {
		t.Fatalf("status reason/recovery = %q / %q", status.Reason, status.Recovery)
	}
	if want := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC); !status.RecordedAt.Equal(want) {
		t.Errorf("RecordedAt = %s, want %s", status.RecordedAt, want)
	}

	var rendered bytes.Buffer
	RenderBinaryUpgradeStatus(&rendered, status)
	for _, want := range []string{
		"Pending:        yes — staged v2, running v1",
		"Failure:        cut-failed",
		"Recovery:       xpfd upgrade",
	} {
		if !strings.Contains(rendered.String(), want) {
			t.Errorf("status output missing %q:\n%s", want, rendered.String())
		}
	}
}

func TestBinaryUpgradeStatusDistinguishesMissingFromUnreadable12143(t *testing.T) {
	missing := ReadBinaryUpgradeStatus(filepath.Join(t.TempDir(), "absent"))
	if missing.ReadErr != nil || missing.Recorded {
		t.Fatalf("missing status = %+v, want ordinary no-pending state", missing)
	}

	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	if err := os.WriteFile(path, []byte("format=1\nreason=cut-failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := ReadBinaryUpgradeStatus(path)
	if malformed.ReadErr == nil || malformed.Recorded {
		t.Fatalf("malformed status = %+v, want a visible read error, not no-pending", malformed)
	}
	var rendered bytes.Buffer
	RenderBinaryUpgradeStatus(&rendered, malformed)
	if !strings.Contains(rendered.String(), "WARNING: could not read durable postinst status") {
		t.Errorf("unreadable status was not surfaced:\n%s", rendered.String())
	}
}

func TestClearBinaryUpgradeStatusRemovesResolvedFailure12143(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writeBinaryUpgradeStatus12143(t, path)
	if err := ClearBinaryUpgradeStatus(path); err != nil {
		t.Fatalf("ClearBinaryUpgradeStatus: %v", err)
	}
	if got := ReadBinaryUpgradeStatus(path); got.ReadErr != nil || got.Recorded {
		t.Errorf("status after successful cut clear = %+v, want no pending record", got)
	}
}
