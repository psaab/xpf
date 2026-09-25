package userspace

import (
	"errors"
	"testing"
)

// TestBumpFIBGenerationRestoresBookkeepingOnRefusal10724 pins the retained
// userspace snapshot and allocator to the last helper-confirmed state. The
// helper rejection must not make local state describe an unpublished bump.
func TestBumpFIBGenerationRestoresBookkeepingOnRefusal10724(t *testing.T) {
	h := &fenceHook9696{
		mode: "fixed", fixed: 100,
		fibErr: newHelperRejection("fib generation rollback rejected"),
	}
	m := newFenceManager9696(t, h)
	m.lastSnapshot.FIBGeneration = 17
	m.lastSnapshot.Generation = 4
	m.generation = 4

	_, err := m.BumpFIBGeneration()
	if !errors.Is(err, errHelperRejected) {
		t.Fatalf("BumpFIBGeneration error = %v, want in-band helper refusal", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.FIBGeneration != 17 {
		t.Errorf("lastSnapshot.FIBGeneration = %d after refusal, want restored 17", m.lastSnapshot.FIBGeneration)
	}
	if m.lastSnapshot.Generation != 4 {
		t.Errorf("lastSnapshot.Generation = %d after refusal, want restored 4", m.lastSnapshot.Generation)
	}
	if m.generation != 4 {
		t.Errorf("generation allocator = %d after refusal, want restored 4", m.generation)
	}
}

// A missing response does not prove refusal: the helper may have applied the
// bump before the socket timed out. Keep the advanced generation in that
// unknown-outcome case so the next full snapshot cannot publish a rollback.
func TestBumpFIBGenerationRetainsUnknownOutcomeBookkeeping10724(t *testing.T) {
	transportErr := errors.New("control response deadline expired")
	h := &fenceHook9696{mode: "fixed", fixed: 100, fibErr: transportErr}
	m := newFenceManager9696(t, h)
	m.lastSnapshot.FIBGeneration = 17
	m.lastSnapshot.Generation = 4
	m.generation = 4

	_, err := m.BumpFIBGeneration()
	if !errors.Is(err, transportErr) {
		t.Fatalf("BumpFIBGeneration error = %v, want transport failure", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.FIBGeneration != 0 {
		t.Errorf("lastSnapshot.FIBGeneration = %d after unknown outcome, want proposed generation 0 retained", m.lastSnapshot.FIBGeneration)
	}
	if m.lastSnapshot.Generation != 5 || m.generation != 5 {
		t.Errorf("unknown outcome must retain advanced generation: snapshot=%d allocator=%d, want 5/5",
			m.lastSnapshot.Generation, m.generation)
	}
}
