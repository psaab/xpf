package userspace

import (
	"bytes"
	"encoding/json"
	"testing"
)

func boolPtr10035(v bool) *bool { return &v }

func setApplied10035(h *fenceHook9696, applied bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.applied = boolPtr10035(applied)
	h.mode = "echo"
}

// #10035: the helper must distinguish an exact-match fence from an applied
// replace. Both return the same manager-neighbor generation ACK, so the
// presence-tracked applied bit is the only signal for this case.
func TestNeighborReplaceExactMatchFenceAppliedBit10035(t *testing.T) {
	for _, sender := range neighborSenders9696() {
		t.Run(sender.name, func(t *testing.T) {
			h := &fenceHook9696{
				mode:    "fixed",
				fixed:   5,
				applied: boolPtr10035(false),
			}
			m := newFenceManager9696(t, h)

			// Sent generation 5 equals the helper's applied generation 5,
			// but the helper fenced it. The cached table and retry debt must
			// remain untouched rather than being falsely acknowledged.
			sender.send(m)
			assertDebtRetained9696(t, m, h, 5)
			if got := replaceCounter9696(m); got != 5 {
				t.Fatalf("exact-match fence must not move the counter backwards: got %d, want 5", got)
			}

			// A present true bit with the same ACK proves the retry landed.
			setApplied10035(h, true)
			sender.send(m)
			if got := h.lastNeighborGen(t); got != 6 {
				t.Fatalf("retry after exact-match fence must carry generation 6, got %d", got)
			}
			if got := cachedNeighbors9696(m); len(got) != 0 {
				t.Fatalf("applied retry must update cached neighbors, got %+v", got)
			}
			if got := lookupSeeded9696(m); got != nil {
				t.Fatalf("applied retry must rebuild the neighbor index, got %+v", got)
			}
			if got := unknownBits9696(m); got&partialNeighbors != 0 {
				t.Fatalf("applied retry must resolve neighbors, unknown=%v", got)
			}
		})
	}
}

// A missing bit is the additive mixed-version fallback: #9696's
// distinguishable ACK-above-generation fence behavior remains unchanged.
func TestNeighborReplaceAppliedBitAbsentKeeps9696Fallback10035(t *testing.T) {
	h := &fenceHook9696{mode: "fixed", fixed: 100}
	m := newFenceManager9696(t, h)
	neighborSenders9696()[0].send(m)
	assertDebtRetained9696(t, m, h, 5)
}

// The applied outcome is additive on the status wire: both boolean values
// survive JSON round-trip, while nil omits the key for older helpers.
func TestNeighborReplaceAppliedBitWire10035(t *testing.T) {
	for _, tc := range []struct {
		name string
		bit  *bool
	}{
		{name: "applied", bit: boolPtr10035(true)},
		{name: "fenced", bit: boolPtr10035(false)},
		{name: "legacy-absent", bit: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(ProcessStatus{NeighborReplaceApplied: tc.bit})
			if err != nil {
				t.Fatalf("marshal status: %v", err)
			}
			var decoded ProcessStatus
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal status: %v", err)
			}
			if tc.bit == nil {
				if bytes.Contains(raw, []byte(`"neighbor_replace_applied"`)) {
					t.Fatalf("legacy status unexpectedly emitted applied-bit: %s", raw)
				}
				if decoded.NeighborReplaceApplied != nil {
					t.Fatalf("legacy status decoded applied-bit = %v, want nil", *decoded.NeighborReplaceApplied)
				}
				return
			}
			if decoded.NeighborReplaceApplied == nil ||
				*decoded.NeighborReplaceApplied != *tc.bit {
				t.Fatalf("decoded applied-bit = %v, want %v",
					decoded.NeighborReplaceApplied, *tc.bit)
			}
		})
	}
}
