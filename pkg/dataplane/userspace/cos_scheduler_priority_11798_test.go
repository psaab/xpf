package userspace

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildClassOfServiceSnapshotClearsUnknownSchedulerPriority11798(t *testing.T) {
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	snapshot := buildClassOfServiceSnapshot(&config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"bad-scheduler": {Name: "bad-scheduler", Priority: "ultra-high"},
				"good-scheduler": {Name: "good-scheduler", Priority: "strict-high"},
			},
		},
	})
	if snapshot == nil || len(snapshot.Schedulers) != 2 {
		t.Fatalf("snapshot schedulers = %+v, want both entries", snapshot)
	}
	got := make(map[string]string, len(snapshot.Schedulers))
	for _, scheduler := range snapshot.Schedulers {
		got[scheduler.Name] = scheduler.Priority
	}
	if got["bad-scheduler"] != "" {
		t.Errorf("unknown priority reached snapshot: %q, want empty legacy-low default", got["bad-scheduler"])
	}
	if got["good-scheduler"] != "strict-high" {
		t.Errorf("valid priority changed at snapshot boundary: %q", got["good-scheduler"])
	}
	for _, want := range []string{"unknown", "bad-scheduler", "ultra-high", "#11798"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("snapshot warning missing %q: %s", want, logs.String())
		}
	}
}
