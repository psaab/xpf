package frr

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// #18561: ApplyFullIfCurrent writes and reloads only while its predicate
// holds; a superseded render touches neither frr.conf nor FRR.
func TestApplyFullIfCurrentSkipsSupersededRender18561(t *testing.T) {
	rec := &RecordingExecutor{}
	conf := filepath.Join(t.TempDir(), "frr.conf")
	m := NewForTest(conf, rec)
	fc := &FullConfig{ClusterMode: true}

	err := m.ApplyFullIfCurrent(fc, func() bool { return false })
	if !errors.Is(err, ErrFRRApplySuperseded) {
		t.Fatalf("superseded apply returned %v, want ErrFRRApplySuperseded", err)
	}
	if rec.ReloadCalls != 0 {
		t.Fatal("a superseded render reloaded FRR")
	}
	if _, statErr := os.Stat(conf); !os.IsNotExist(statErr) {
		t.Fatalf("a superseded render wrote frr.conf (stat err %v)", statErr)
	}
	if err := m.ApplyFullIfCurrent(&FullConfig{}, func() bool { return false }); !errors.Is(err, ErrFRRApplySuperseded) {
		t.Fatalf("superseded clear returned %v, want ErrFRRApplySuperseded", err)
	}

	if err := m.ApplyFullIfCurrent(fc, func() bool { return true }); err != nil {
		t.Fatalf("current apply: %v", err)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("reload calls = %d after a current apply, want 1", rec.ReloadCalls)
	}
}
