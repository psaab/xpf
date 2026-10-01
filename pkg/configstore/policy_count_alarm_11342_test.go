package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const inertCountAlarmConfig11342 = `security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; count { alarm { per-minute-threshold 100; } } }
            }
        }
    }
}`

func assertInertCountAlarmWarning11342(t *testing.T, compiled *config.Config) {
	t.Helper()
	if compiled == nil {
		t.Fatal("tolerant ingress returned a nil config")
	}
	warnings := strings.Join(compiled.Warnings, "\n")
	for _, want := range []string{"then count alarm", "#11342"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("tolerant ingress warnings = %q, want %q", warnings, want)
		}
	}
	if len(compiled.Security.Policies) == 0 || len(compiled.Security.Policies[0].Policies) == 0 ||
		!compiled.Security.Policies[0].Policies[0].Count {
		t.Fatalf("tolerant ingress did not preserve count action: %+v", compiled.Security.Policies)
	}
}

func TestCheckTextRejectsInertPolicyCountAlarm11342(t *testing.T) {
	if _, err := CheckText(inertCountAlarmConfig11342, -1); err == nil {
		t.Fatal("strict commit-check accepted inert then-count alarm")
	} else if !strings.Contains(err.Error(), "alarm") {
		t.Fatalf("CheckText error = %q, want strict alarm rejection", err)
	}
}

func TestSyncApplyWarnsInertPolicyCountAlarm11342(t *testing.T) {
	compiled, err := newTestStore(t).SyncApply(inertCountAlarmConfig11342, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected persisted inert count alarm: %v", err)
	}
	assertInertCountAlarmWarning11342(t, compiled)
}

func TestLoadWarnsInertPolicyCountAlarm11342(t *testing.T) {
	tree, errs := config.NewParser(inertCountAlarmConfig11342).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse persisted config: %v", errs)
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("persist active config: %v", err)
	}

	loaded := newTestStoreAt(t, path)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load rejected persisted inert count alarm: %v", err)
	}
	assertInertCountAlarmWarning11342(t, loaded.ActiveConfig())
}
