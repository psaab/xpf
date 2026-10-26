package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade"
)

// #10848 B1 regression pin (Rev17935Glm fold): the pre-publish gate
// itself: deleting gatePublishOnBinaryFloor's floor check fails
// here; the verb's call into the seam is inspection-pinned (the
// verb os.Exits and takes the host-wide lock, so it is not
// unit-driven).
func TestGatePublishOnBinaryFloorRefusesReplay10848(t *testing.T) {
	dir := t.TempDir()
	floorPath := filepath.Join(dir, "binary-floor")
	if err := os.WriteFile(floorPath, []byte("1.2.3\n"), 0o644); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	if err := gatePublishOnBinaryFloor(floorPath, "1.2.2"); err == nil ||
		!strings.Contains(err.Error(), "BELOW") {
		t.Fatalf("below-floor publish must refuse, got: %v", err)
	}
	if err := gatePublishOnBinaryFloor(floorPath, "1.2.3"); err != nil {
		t.Fatalf("at-floor publish must allow: %v", err)
	}
	if err := gatePublishOnBinaryFloor(floorPath, "9.9.9"); err != nil {
		t.Fatalf("above-floor publish must allow: %v", err)
	}
	if err := gatePublishOnBinaryFloor(floorPath, ""); err == nil {
		t.Fatal("empty candidate must refuse once enrolled")
	}
	// Unenrolled: anything publishes.
	missing := filepath.Join(dir, "no-floor")
	if err := gatePublishOnBinaryFloor(missing, "0.0.1"); err != nil {
		t.Fatalf("unenrolled floor must allow: %v", err)
	}
	var _ = upgrade.DefaultBinaryFloorPath
}
