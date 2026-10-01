package dataplane

import (
	"errors"
	"slices"
	"testing"
)

type preMutationOrderingDP11080 struct {
	*recordingDP
	events []string
}

func (d *preMutationOrderingDP11080) SetZoneConfig(zoneID uint16, cfg ZoneConfig) error {
	d.events = append(d.events, "phase-2")
	return d.recordingDP.SetZoneConfig(zoneID, cfg)
}

func TestCompileConfigRunsSnapshotPreflightBeforePhase2_11080(t *testing.T) {
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"}
	dp := &preMutationOrderingDP11080{recordingDP: &recordingDP{}}

	_, err := CompileConfig(dp, cfg, false, func(*CompileResult) error {
		dp.events = append(dp.events, "snapshot-preflight")
		return nil
	})
	if !errors.Is(err, errStopBeforeHostReconcile) {
		t.Fatalf("compile error = %v, want phase-2 tripwire", err)
	}
	if want := []string{"snapshot-preflight", "phase-2"}; !slices.Equal(dp.events, want) {
		t.Fatalf("compiler events = %v, want pre-mutation snapshot validation before Phase 2: %v", dp.events, want)
	}
}
