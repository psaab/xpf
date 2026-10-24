package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16029: a forgotten key-rotation finalize left the retired PSK accepted
// indefinitely — no rotation-open timestamp, no age, no alarm. These tests
// pin the fix through the production paths: Manager.UpdateConfig stamps
// the window, controlLinkRotationStatus renders its age, and past
// controlLinkRotationStaleAfter (7 days) the line carries an ALARM naming
// the open window by key ID.
//
// FAIL-ON-REVERT: drop the UpdateConfig stamping (or re-stamp on every
// apply) and TestRotationAgeSurvivesRoutineReapply16029 /
// TestStaleRotationAlarmsByName16029 red; drop only the status alarm and
// the ALARM assertions red while the age assertions stay green, which is
// why both are asserted separately.

func pinRotationClock16029(t *testing.T, now *time.Time) {
	t.Helper()
	orig := controlLinkRotationNow
	controlLinkRotationNow = func() time.Time { return *now }
	t.Cleanup(func() { controlLinkRotationNow = orig })
}

func rotationManager16029(t *testing.T) *Manager {
	t.Helper()
	return NewManager(0, 42)
}

func commitRotation16029(m *Manager, signing, additional []byte) {
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret(string(signing)),
		ControlLinkAuthKeyAlt: config.NewSecret(string(additional)),
	})
}

func TestRotationAgeSurvivesRoutineReapply16029(t *testing.T) {
	now := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	pinRotationClock16029(t, &now)
	m := rotationManager16029(t)

	// No window: no stamp, no age, no line, no alarm.
	commitRotation16029(m, rotKeyA, nil)
	if !m.ControlLinkRotationOpenSince().IsZero() {
		t.Fatal("no additional key must leave the rotation stamp zero")
	}
	if _, stale := m.ControlLinkRotationStale(); stale {
		t.Fatal("no window open must not be stale")
	}
	if line := m.controlLinkRotationStatus(); line != "" {
		t.Fatalf("no window must render no line, got %q", line)
	}

	// Window opens: stamp is the open instant.
	commitRotation16029(m, rotKeyA, rotKeyB)
	opened := m.ControlLinkRotationOpenSince()
	if !opened.Equal(now) {
		t.Fatalf("window opened at %v, want stamp %v", opened, now)
	}

	// A routine re-apply of the identical config a day later must NOT
	// move the stamp — otherwise any commit launders a forgotten
	// rotation's age back to zero.
	now = now.Add(24 * time.Hour)
	commitRotation16029(m, rotKeyA, rotKeyB)
	if got := m.ControlLinkRotationOpenSince(); !got.Equal(opened) {
		t.Fatalf("identical re-apply moved the open stamp %v -> %v; a routine commit must not launder rotation age", opened, got)
	}

	// Swapping only the signing key under the SAME additional key is
	// the same window, not a new one: the stamp must not move either.
	now = now.Add(24 * time.Hour)
	commitRotation16029(m, rotKeyB, rotKeyB)
	if got := m.ControlLinkRotationOpenSince(); !got.Equal(opened) {
		t.Fatalf("signing-key swap under the same additional key moved the stamp %v -> %v; it is the same window", opened, got)
	}
}

// TestRotationWindowIdentity16029 pins which config changes count as a new
// window: a different additional key re-anchors, finalize clears, and
// reopening starts a fresh age.
func TestRotationWindowIdentity16029(t *testing.T) {
	now := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	pinRotationClock16029(t, &now)
	m := rotationManager16029(t)
	rotKeyC := []byte("rotation-key-C-16029-long-enough-for-advice")

	commitRotation16029(m, rotKeyA, rotKeyB)
	first := m.ControlLinkRotationOpenSince()

	// Steps 3-4 shape: signing key swaps to B, additional becomes A.
	// The additional key changed, so this IS a new window on this node
	// (it now accepts the retired A) and must re-anchor.
	now = now.Add(2 * time.Hour)
	commitRotation16029(m, rotKeyB, rotKeyA)
	if got := m.ControlLinkRotationOpenSince(); !got.Equal(now) {
		t.Fatalf("changed additional key must re-anchor: got %v, want %v (first open %v)", got, now, first)
	}
	second := m.ControlLinkRotationOpenSince()

	// Re-applying that same window does not move it.
	now = now.Add(time.Hour)
	commitRotation16029(m, rotKeyB, rotKeyA)
	if got := m.ControlLinkRotationOpenSince(); !got.Equal(second) {
		t.Fatalf("identical re-apply moved stamp %v -> %v", second, got)
	}

	// Finalize clears the stamp; reopening with a third key starts fresh.
	now = now.Add(time.Hour)
	commitRotation16029(m, rotKeyB, nil)
	if !m.ControlLinkRotationOpenSince().IsZero() {
		t.Fatal("finalize (additional cleared) must clear the open stamp")
	}
	if line := m.controlLinkRotationStatus(); line != "" {
		t.Fatalf("finalized window must render no line, got %q", line)
	}
	now = now.Add(time.Hour)
	commitRotation16029(m, rotKeyB, rotKeyC)
	if got := m.ControlLinkRotationOpenSince(); !got.Equal(now) {
		t.Fatalf("reopened window must stamp the reopen instant: got %v, want %v", got, now)
	}
}

// TestStaleRotationAlarmsByName16029 is the decisive acceptance: a window
// open beyond the threshold produces a visible status alarm naming the
// open rotation (its accepted key IDs, never the keys), while a fresh
// window renders only its age.
func TestStaleRotationAlarmsByName16029(t *testing.T) {
	now := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	pinRotationClock16029(t, &now)
	m := rotationManager16029(t)

	commitRotation16029(m, rotKeyB, rotKeyA)
	signing, additional := m.ControlLinkKeyIDs()
	if signing == "" || additional == "" {
		t.Fatal("fixture must have both key IDs")
	}

	// Fresh window: age rendered, no alarm, not stale.
	line := m.controlLinkRotationStatus()
	if !strings.Contains(line, "open for 0h") {
		t.Fatalf("fresh window must render its age, got %q", line)
	}
	if strings.Contains(line, "ALARM") {
		t.Fatalf("fresh window must not alarm, got %q", line)
	}
	if _, stale := m.ControlLinkRotationStale(); stale {
		t.Fatal("fresh window must not be stale")
	}

	// Just under the threshold: still no alarm.
	now = now.Add(controlLinkRotationStaleAfter - time.Hour)
	if _, stale := m.ControlLinkRotationStale(); stale {
		t.Fatal("window under the stale threshold must not be stale")
	}
	if line := m.controlLinkRotationStatus(); strings.Contains(line, "ALARM") {
		t.Fatalf("window under threshold must not alarm, got %q", line)
	}

	// Past the threshold: stale, and the rendered line alarms naming the
	// window by its key IDs (never the key bytes).
	now = now.Add(2 * time.Hour)
	age, stale := m.ControlLinkRotationStale()
	if !stale || age <= controlLinkRotationStaleAfter {
		t.Fatalf("window past threshold must be stale, got age=%v stale=%v", age, stale)
	}
	line = m.controlLinkRotationStatus()
	for _, want := range []string{"ALARM", "still accepted", signing, additional, "open for 7d"} {
		if !strings.Contains(line, want) {
			t.Fatalf("stale line must contain %q, got %q", want, line)
		}
	}
	for _, k := range [][]byte{rotKeyA, rotKeyB} {
		if strings.Contains(line, string(k)) {
			t.Fatalf("stale line rendered a key: %q", line)
		}
	}
	// The alarm must reach the operator surface, not just the helper.
	if stats := m.FormatControlPlaneStatistics(); !strings.Contains(stats, "ALARM") ||
		!strings.Contains(stats, "Key rotation:") {
		t.Fatalf("stale alarm must reach show chassis cluster statistics:\n%s", stats)
	}

	// Finalizing clears the alarm with the window.
	commitRotation16029(m, rotKeyB, nil)
	if _, stale := m.ControlLinkRotationStale(); stale {
		t.Fatal("finalized window must not be stale")
	}
	if stats := m.FormatControlPlaneStatistics(); strings.Contains(stats, "Key rotation:") {
		t.Fatalf("finalized window must render no rotation line:\n%s", stats)
	}
}
