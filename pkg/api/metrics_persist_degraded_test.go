package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestConfigPersistDegradedGauge pins #1799: the
// xpf_daemon_config_persist_degraded gauge must be emitted even when
// the dataplane is NOT loaded (the rest of the collector early-returns
// behind the dp gate, but config persistence is a control-plane health
// signal that matters most precisely when the box is unhealthy), and
// it must track the wired fn's value.
func TestConfigPersistDegradedGauge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		degraded bool
		want     float64
	}{
		{"degraded", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				configPersistDegradedFn: func() bool { return tc.degraded },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			found := false
			for _, mf := range mfs {
				if mf.GetName() != "xpf_daemon_config_persist_degraded" {
					continue
				}
				found = true
				if len(mf.GetMetric()) != 1 {
					t.Fatalf("metric count = %d, want 1", len(mf.GetMetric()))
				}
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != tc.want {
					t.Errorf("gauge = %v, want %v", got, tc.want)
				}
			}
			if !found {
				t.Error("xpf_daemon_config_persist_degraded not emitted with dataplane unloaded")
			}
		})
	}
}

// TestRollbackHistoryDegradedGauge pins #3441: the
// xpf_config_rollback_persist_degraded gauge must be emitted even when the
// dataplane is NOT loaded (rollback-history persistence is a control-plane
// health signal) and must track the wired fn's value.
func TestRollbackHistoryDegradedGauge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		degraded bool
		want     float64
	}{
		{"degraded", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				rollbackHistoryDegradedFn: func() bool { return tc.degraded },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			found := false
			for _, mf := range mfs {
				if mf.GetName() != "xpf_config_rollback_persist_degraded" {
					continue
				}
				found = true
				if len(mf.GetMetric()) != 1 {
					t.Fatalf("metric count = %d, want 1", len(mf.GetMetric()))
				}
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != tc.want {
					t.Errorf("gauge = %v, want %v", got, tc.want)
				}
			}
			if !found {
				t.Error("xpf_config_rollback_persist_degraded not emitted with dataplane unloaded")
			}
		})
	}
}

// TestJournalPermsDegradedGauge pins #9898 F-113: the
// xpf_config_journal_perms_degraded gauge must be emitted even when the
// dataplane is NOT loaded (journal permission repair is a control-plane
// health signal) and must track the wired fn's value.
func TestJournalPermsDegradedGauge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		degraded bool
		want     float64
	}{
		{"degraded", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				journalPermsDegradedFn: func() bool { return tc.degraded },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			found := false
			for _, mf := range mfs {
				if mf.GetName() != "xpf_config_journal_perms_degraded" {
					continue
				}
				found = true
				if len(mf.GetMetric()) != 1 {
					t.Fatalf("metric count = %d, want 1", len(mf.GetMetric()))
				}
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != tc.want {
					t.Errorf("gauge = %v, want %v", got, tc.want)
				}
			}
			if !found {
				t.Error("xpf_config_journal_perms_degraded not emitted with dataplane unloaded")
			}
		})
	}
}

// TestArchiveDegradedMetrics11805 keeps local archive state visible before the
// dataplane gate, so an unloaded daemon still reports both current degradation
// and cumulative failed attempts.
func TestArchiveDegradedMetrics11805(t *testing.T) {
	s := &Server{ // dp intentionally nil — control-plane metrics must still emit
		archiveDegradedFn: func() bool { return true },
		archiveFailureCountFn: func() uint64 {
			return 3
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	foundGauge, foundCounter := false, false
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_config_archive_degraded":
			foundGauge = true
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 1 {
				t.Errorf("archive degraded gauge = %v, want 1", got)
			}
		case "xpf_config_archive_failures_total":
			foundCounter = true
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 3 {
				t.Errorf("archive failure counter = %v, want 3", got)
			}
		}
	}
	if !foundGauge || !foundCounter {
		t.Fatalf("archive metrics missing with dataplane unloaded: gauge=%v counter=%v", foundGauge, foundCounter)
	}
}
