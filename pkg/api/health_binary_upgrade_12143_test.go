package api

import (
	"net/http/httptest"
	"testing"
)

func TestHealthReportsOnlyNonSensitiveBinaryUpgradeStatus12143(t *testing.T) {
	server := NewServer(Config{
		Store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		BinaryUpgradeStatusFn: func() BinaryUpgradeStatusSnapshot {
			return BinaryUpgradeStatusSnapshot{
				Readable:       true,
				Pending:        true,
				StagedVersion:  "sensitive-staged-build",
				RunningVersion: "sensitive-running-build",
				Reason:         "cut-failed",
				RecordedAtUnix: 1791460800,
			}
		},
	})
	response := httptest.NewRecorder()
	server.healthHandler(response, httptest.NewRequest("GET", "/health", nil))
	if response.Code != 200 {
		t.Fatalf("status = %d, want 200: a deferred binary cut is informational and must not pull a forwarding node from rotation", response.Code)
	}
	data := unmarshalHealthData(t, response.Body.String())
	if readable, _ := data["binary_upgrade_status_readable"].(bool); !readable {
		t.Errorf("binary_upgrade_status_readable = %v, want true", data["binary_upgrade_status_readable"])
	}
	if pending, _ := data["binary_upgrade_pending"].(bool); !pending {
		t.Errorf("binary_upgrade_pending = %v, want true", data["binary_upgrade_pending"])
	}
	if got, _ := data["binary_upgrade_failure"].(string); got != "cut-failed" {
		t.Errorf("binary_upgrade_failure = %q, want stable reason code cut-failed", got)
	}
	if at, _ := data["binary_upgrade_recorded_at_unix"].(float64); at != 1791460800 {
		t.Errorf("binary_upgrade_recorded_at_unix = %v, want 1791460800", data["binary_upgrade_recorded_at_unix"])
	}
	for _, key := range []string{"binary_upgrade_staged_version", "binary_upgrade_running_version"} {
		if _, present := data[key]; present {
			t.Errorf("%s must not disclose an exact build version on unauthenticated /health", key)
		}
	}
}

func TestHealthReportsBinaryUpgradeStatusReadFailureWithoutLeakingDetail12143(t *testing.T) {
	server := NewServer(Config{
		Store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		BinaryUpgradeStatusFn: func() BinaryUpgradeStatusSnapshot {
			return BinaryUpgradeStatusSnapshot{Readable: false}
		},
	})
	response := httptest.NewRecorder()
	server.healthHandler(response, httptest.NewRequest("GET", "/health", nil))
	if response.Code != 200 {
		t.Fatalf("status = %d, want 200 for an informational status-read failure", response.Code)
	}
	data := unmarshalHealthData(t, response.Body.String())
	if readable, _ := data["binary_upgrade_status_readable"].(bool); readable {
		t.Error("binary_upgrade_status_readable must be false when the durable marker cannot be read")
	}
	if _, present := data["binary_upgrade_pending"]; present {
		t.Error("an unreadable marker must not be misreported as pending or clear")
	}
}

func TestHealthReportsNoPendingBinaryUpgrade12143(t *testing.T) {
	server := NewServer(Config{
		Store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		BinaryUpgradeStatusFn: func() BinaryUpgradeStatusSnapshot {
			return BinaryUpgradeStatusSnapshot{Readable: true}
		},
	})
	response := httptest.NewRecorder()
	server.healthHandler(response, httptest.NewRequest("GET", "/health", nil))
	if response.Code != 200 {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	data := unmarshalHealthData(t, response.Body.String())
	if pending, _ := data["binary_upgrade_pending"].(bool); pending {
		t.Errorf("binary_upgrade_pending = true without a durable failure")
	}
}
