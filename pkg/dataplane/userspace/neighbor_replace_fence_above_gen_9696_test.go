package userspace

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Test cells for #9696: a #6034 fence answered with an ACK above the sent
// generation must be treated as unacknowledged at BOTH senders.
//
// Fixture pattern follows neighbor_replace_envelope_6034_test.go: an empty
// config makes the kernel sample nil, so the seeded (publishable) neighbor
// always diffs and triggers the replace; the hook models a helper whose
// applied generation is ahead (ACK 100) or echoes the sent generation.

var seededNeighbor9696 = NeighborSnapshot{
	Ifindex: 13,
	Family:  "inet",
	IP:      "172.16.80.200",
	MAC:     "02:aa:bb:cc:dd:ee",
	State:   "reachable",
}

// fenceHook9696 models the helper's ACK. mode "fixed" always reports fixed;
// mode "echo" reports the generation the request carried. fibErr is returned
// for bump_fib_generation requests (nil = the bump lands).
type fenceHook9696 struct {
	mu           sync.Mutex
	mode         string
	fixed        uint64
	fibErr       error
	fibSeen      int
	neighborGens []uint64
}

func (h *fenceHook9696) hook(req ControlRequest, status *ProcessStatus) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch req.Type {
	case "update_neighbors":
		h.neighborGens = append(h.neighborGens, req.NeighborGeneration)
		ack := h.fixed
		if h.mode == "echo" {
			ack = req.NeighborGeneration
		}
		if status != nil {
			*status = ProcessStatus{PID: 4321, ManagerNeighborGeneration: ack}
		}
		return nil
	case "bump_fib_generation":
		h.fibSeen++
		return h.fibErr
	default:
		return nil
	}
}

func (h *fenceHook9696) lastNeighborGen(t *testing.T) uint64 {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.neighborGens) == 0 {
		t.Fatal("no update_neighbors request was sent")
	}
	return h.neighborGens[len(h.neighborGens)-1]
}

func (h *fenceHook9696) setEcho() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mode = "echo"
}

func (h *fenceHook9696) fibRequests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fibSeen
}

// newFenceManager9696 builds a Manager whose cached table holds the seeded
// entry behind a POPULATED index, whose replace counter sits at 4 (next send
// carries 5), and whose #9684 bookkeeping marks both sections — so the cells
// can tell preservation from spurious marking.
func newFenceManager9696(t *testing.T, h *fenceHook9696) *Manager {
	t.Helper()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.controlRequestHook = h.hook
	m.lastSnapshot = &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 4,
		Config:     &config.Config{},
		Neighbors:  []NeighborSnapshot{seededNeighbor9696},
	}
	m.generation = 4
	m.neighborReplaceGen = 4
	m.mu.Lock()
	m.rebuildNeighborIndex()
	m.partialOutcomeUnknown = partialNeighbors | partialFabrics
	m.mu.Unlock()
	return m
}

func cachedNeighbors9696(m *Manager) []NeighborSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]NeighborSnapshot(nil), m.lastSnapshot.Neighbors...)
}

func replaceCounter9696(m *Manager) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.neighborReplaceGen
}

func unknownBits9696(m *Manager) partialSections {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.partialOutcomeUnknown
}

func lookupSeeded9696(m *Manager) *NeighborSnapshot {
	return m.LookupSnapshotNeighbor(13, net.ParseIP("172.16.80.200"))
}

func assertDebtRetained9696(t *testing.T, m *Manager, h *fenceHook9696, wantGen uint64) {
	t.Helper()
	if got := h.lastNeighborGen(t); got != wantGen {
		t.Fatalf("update_neighbors carried generation %d, want %d", got, wantGen)
	}
	if got := cachedNeighbors9696(m); len(got) != 1 || got[0] != seededNeighbor9696 {
		t.Fatalf("fenced replace must retain retry debt: cached neighbors = %+v, want the seeded entry", got)
	}
	if got := lookupSeeded9696(m); got == nil || *got != seededNeighbor9696 {
		t.Fatalf("fenced replace must not rebuild the index away: lookup = %+v, want seeded", got)
	}
	if got, want := unknownBits9696(m), partialNeighbors|partialFabrics; got != want {
		t.Fatalf("fenced replace must preserve #9684 bookkeeping: unknown = %v, want %v", got, want)
	}
}

type neighborSender9696 struct {
	name string
	send func(m *Manager)
}

func neighborSenders9696() []neighborSender9696 {
	return []neighborSender9696{
		{"RegenerateNeighborSnapshot", func(m *Manager) { m.RegenerateNeighborSnapshot() }},
		{"BumpFIBGeneration", func(m *Manager) { _, _ = m.BumpFIBGeneration() }},
	}
}

// F1: an ACK above the sent generation is a fence — retry debt retained,
// table and populated index untouched, #9684 bookkeeping unmutated, counter
// seeded forward from the fencing ACK.
func TestNeighborReplaceFenceAboveGenRetainsDebt9696(t *testing.T) {
	for _, s := range neighborSenders9696() {
		t.Run(s.name, func(t *testing.T) {
			h := &fenceHook9696{mode: "fixed", fixed: 100}
			m := newFenceManager9696(t, h)
			s.send(m)
			assertDebtRetained9696(t, m, h, 5)
			if got := replaceCounter9696(m); got != 100 {
				t.Fatalf("fencing ACK must seed the counter: neighborReplaceGen = %d, want 100", got)
			}
		})
	}
}

// F2: the seeded retry goes out strictly higher than the fence and, once
// accepted, advances the cached view and resolves the section.
func TestNeighborReplaceFencedRecoveryResendsHigher9696(t *testing.T) {
	for _, s := range neighborSenders9696() {
		t.Run(s.name, func(t *testing.T) {
			h := &fenceHook9696{mode: "fixed", fixed: 100}
			m := newFenceManager9696(t, h)
			s.send(m)
			assertDebtRetained9696(t, m, h, 5)

			h.setEcho()
			s.send(m)
			if got := h.lastNeighborGen(t); got != 101 {
				t.Fatalf("retry after a fencing ACK of 100 must carry 101, got %d", got)
			}
			if got := cachedNeighbors9696(m); len(got) != 0 {
				t.Fatalf("accepted retry must advance the cached view to empty, got %+v", got)
			}
			if got := lookupSeeded9696(m); got != nil {
				t.Fatalf("accepted retry must rebuild the index: lookup = %+v, want nil", got)
			}
			if got := unknownBits9696(m); got&partialNeighbors != 0 {
				t.Fatalf("accepted retry must resolve the neighbors section: unknown = %v", got)
			}
			if got := unknownBits9696(m); got&partialFabrics == 0 {
				t.Fatalf("accepted neighbor retry must not resolve fabrics: unknown = %v", got)
			}
		})
	}
}

// F3: a below-gen ACK is unexpected from the current helper (its fence always
// ACKs >= gen) and is handled defensively the same way — debt retained and
// the counter never moves backwards.
func TestNeighborReplaceDefensiveLowerACK9696(t *testing.T) {
	for _, s := range neighborSenders9696() {
		t.Run(s.name, func(t *testing.T) {
			h := &fenceHook9696{mode: "fixed", fixed: 1}
			m := newFenceManager9696(t, h)
			s.send(m)
			assertDebtRetained9696(t, m, h, 5)
			if got := replaceCounter9696(m); got != 5 {
				t.Fatalf("seeding from a lower ACK must be a no-op: neighborReplaceGen = %d, want 5", got)
			}
		})
	}
}

// C1/C2: exact-match and legacy-zero ACKs still apply — the controls that
// prove the fence cells cannot be satisfied by never advancing.
func TestNeighborReplaceExactAndLegacyACKApply9696(t *testing.T) {
	for _, s := range neighborSenders9696() {
		for _, tc := range []struct {
			name string
			ack  uint64
		}{
			{"exact", 5},
			{"legacy-zero", 0},
		} {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				h := &fenceHook9696{mode: "fixed", fixed: tc.ack}
				m := newFenceManager9696(t, h)
				s.send(m)
				if got := h.lastNeighborGen(t); got != 5 {
					t.Fatalf("update_neighbors carried generation %d, want 5", got)
				}
				if got := cachedNeighbors9696(m); len(got) != 0 {
					t.Fatalf("ACK %d must advance the cached view to empty, got %+v", tc.ack, got)
				}
				if got := unknownBits9696(m); got&partialNeighbors != 0 {
					t.Fatalf("ACK %d must resolve the neighbors section: unknown = %v", tc.ack, got)
				}
			})
		}
	}
}

var errInjectedFIB9696 = errors.New("injected bump_fib_generation failure 9696")

// B1: on a fenced neighbor replace BumpFIBGeneration still sends the FIB
// bump (that invalidation is orthogonal), while skipping the neighbor
// writeback — and a failing bump still surfaces the INJECTED error.
func TestBumpFIBGenerationStillSentOnFence9696(t *testing.T) {
	t.Run("bump-sent", func(t *testing.T) {
		h := &fenceHook9696{mode: "fixed", fixed: 100}
		m := newFenceManager9696(t, h)
		_, err := m.BumpFIBGeneration()
		assertDebtRetained9696(t, m, h, 5)
		if got := replaceCounter9696(m); got != 100 {
			t.Fatalf("fencing ACK must seed the counter: neighborReplaceGen = %d, want 100", got)
		}
		if got := h.fibRequests(); got != 1 {
			t.Fatalf("bump_fib_generation requests = %d, want 1 (fence must not suppress the bump)", got)
		}
		// The control-layer bump landed; any error left must be the
		// unprivileged-map shim leg, never a wrapped control failure.
		if err != nil && strings.Contains(err.Error(), "bump fib generation") {
			t.Fatalf("control bump succeeded, so no bump control error may surface: %v", err)
		}
	})

	t.Run("bump-failure-surfaces", func(t *testing.T) {
		h := &fenceHook9696{mode: "fixed", fixed: 100, fibErr: errInjectedFIB9696}
		m := newFenceManager9696(t, h)
		_, err := m.BumpFIBGeneration()
		if !errors.Is(err, errInjectedFIB9696) {
			t.Fatalf("failing FIB bump must surface the injected error, got %v", err)
		}
		assertDebtRetained9696(t, m, h, 5)
		if got := replaceCounter9696(m); got != 100 {
			t.Fatalf("fencing ACK must seed the counter: neighborReplaceGen = %d, want 100", got)
		}
	})
}

// R1: on a fenced replace RegenerateNeighborSnapshot returns before the
// partial-generation bookkeeping — publishedSnapshot, hash, and both
// generation fields stay exactly as they were.
func TestRegenBookkeepingUntouchedOnFence9696(t *testing.T) {
	h := &fenceHook9696{mode: "fixed", fixed: 100}
	m := newFenceManager9696(t, h)
	m.mu.Lock()
	m.publishedSnapshot = 9
	m.lastSnapshotHash = [32]byte{1, 2, 3}
	m.mu.Unlock()

	m.RegenerateNeighborSnapshot()
	assertDebtRetained9696(t, m, h, 5)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.publishedSnapshot != 9 {
		t.Fatalf("publishedSnapshot = %d, want 9 (fence must skip the writeback)", m.publishedSnapshot)
	}
	if m.lastSnapshotHash != [32]byte{1, 2, 3} {
		t.Fatalf("lastSnapshotHash moved on a fenced replace: %x", m.lastSnapshotHash)
	}
	if m.generation != 4 || m.lastSnapshot.Generation != 4 {
		t.Fatalf("generation moved on a fenced replace: m=%d snapshot=%d, want 4/4",
			m.generation, m.lastSnapshot.Generation)
	}
	if m.neighborReplaceGen != 100 {
		t.Fatalf("neighborReplaceGen = %d, want the fencing ACK 100", m.neighborReplaceGen)
	}
}
