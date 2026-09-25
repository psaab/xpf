package dataplane

import (
	"errors"
	"math"
	"testing"

	"github.com/cilium/ebpf"
)

// TestNextFIBGenerationSaturates10724 is the fail-on-revert boundary cell:
// a wrapping increment at MaxUint32 could make an old generation-0 FIB entry
// appear fresh again instead of forcing a re-resolution.
func TestNextFIBGenerationSaturates10724(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   uint32
		want uint32
	}{
		{name: "zero advances", in: 0, want: 1},
		{name: "ordinary value advances", in: 17, want: 18},
		{name: "last representable value advances", in: math.MaxUint32 - 1, want: math.MaxUint32},
		{name: "maximum saturates", in: math.MaxUint32, want: math.MaxUint32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextFIBGeneration(tc.in); got != tc.want {
				t.Fatalf("nextFIBGeneration(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

type fibGenerationMap10724 struct {
	generation uint32
	attempted  uint32
	updateErr  error
}

func (m *fibGenerationMap10724) Lookup(_ interface{}, valueOut interface{}) error {
	*valueOut.(*uint32) = m.generation
	return nil
}

func (m *fibGenerationMap10724) Update(_, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.attempted = value.(uint32)
	if m.updateErr != nil {
		return m.updateErr
	}
	m.generation = m.attempted
	return nil
}

// TestBumpFIBGenerationMapSaturatesAndReturnsPriorOnFailure10724 drives the
// production map-update operation used by Manager.BumpFIBGeneration. It pins
// the MaxUint32 no-wrap boundary and refuses a false-success no-op at
// exhaustion, without requiring an eBPF kernel map in the test environment.
func TestBumpFIBGenerationMapSaturatesAndReturnsPriorOnFailure10724(t *testing.T) {
	t.Run("maximum reports exhaustion instead of false success", func(t *testing.T) {
		m := &fibGenerationMap10724{generation: math.MaxUint32}
		got, err := bumpFIBGenerationMap(m)
		if !errors.Is(err, errFIBGenerationExhausted) {
			t.Fatalf("bumpFIBGenerationMap error = %v, want generation-exhausted error", err)
		}
		if got != math.MaxUint32 || m.generation != math.MaxUint32 || m.attempted != 0 {
			t.Fatalf("exhausted bump returned=%d stored=%d attempted=%d, want MaxUint32 unchanged and no update",
				got, m.generation, m.attempted)
		}
	})

	t.Run("map update failure returns the value map still holds", func(t *testing.T) {
		sentinel := errors.New("map update refused")
		prior := uint32(math.MaxUint32 - 1)
		m := &fibGenerationMap10724{generation: prior, updateErr: sentinel}
		got, err := bumpFIBGenerationMap(m)
		if !errors.Is(err, sentinel) {
			t.Fatalf("bumpFIBGenerationMap error = %v, want wrapped map error", err)
		}
		if got != prior || m.generation != prior || m.attempted != math.MaxUint32 {
			t.Fatalf("failed bump returned=%d map=%d attempted=%d, want prior=%d and attempted MaxUint32",
				got, m.generation, m.attempted, prior)
		}
	})
}
