package monitoriface

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestResetOnDeviceChangeClearsBaselinesAndAnnotates10838(t *testing.T) {
	tracked := "eth0"
	prev := &Snapshot{RxBytes: 100}
	baseline := &Snapshot{RxBytes: 50}

	note := ResetOnDeviceChange("reth0", &tracked, "eth1", &prev, &baseline)
	if tracked != "eth1" {
		t.Fatalf("tracked kernel device = %q, want eth1", tracked)
	}
	if prev != nil || baseline != nil {
		t.Fatalf("device change retained old-device baselines: prev=%v baseline=%v", prev, baseline)
	}
	for _, want := range []string{"reth0", "eth0 -> eth1", "possible RG failover", "baseline reset"} {
		if !strings.Contains(note, want) {
			t.Errorf("device-change note %q missing %q", note, want)
		}
	}

	// Re-reading the same device neither resets the new baseline nor replaces
	// the sticky note with another transition.
	newSnapshot := &Snapshot{RxBytes: 900, Timestamp: time.Now()}
	prev, baseline = newSnapshot, newSnapshot
	if note := ResetOnDeviceChange("reth0", &tracked, "eth1", &prev, &baseline); note != "" {
		t.Fatalf("same-device tick generated note %q", note)
	}
	if prev != newSnapshot || baseline != newSnapshot {
		t.Fatal("same-device tick cleared the new-device baselines")
	}

	var frame bytes.Buffer
	RenderSingleInterface(&frame, "host", "reth0", "eth1", newSnapshot, prev, baseline, time.Now(), note)
	for _, want := range []string{"Note: reth0 device changed eth0 -> eth1", "baseline reset", "Input  bytes:"} {
		if !strings.Contains(frame.String(), want) {
			t.Errorf("rendered frame missing %q:\n%s", want, frame.String())
		}
	}
}
