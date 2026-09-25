package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"

	"github.com/cilium/ebpf"
)

// HA / fabric map accessors.
// Same-package split of maps.go (#1686): fabric cross-chassis forwarding
// config, redundancy-group active state, the HA liveness watchdog, the FIB
// generation counter, and the eBPF no-op lifecycle hooks.

// UpdateFabricFwd writes the fabric cross-chassis forwarding config.
// Pass a zero FabricFwdInfo (Ifindex=0) to disable fabric redirect.
func (m *Manager) UpdateFabricFwd(info FabricFwdInfo) error {
	zm, present, st := m.lookupMapLocked("fabric_fwd")
	if st == registryFresh {
		return fmt.Errorf("%w: fabric_fwd", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("fabric_fwd map not found")
	}
	return zm.Update(uint32(0), info, ebpf.UpdateAny)
}

// UpdateFabricFwd1 writes the secondary fabric cross-chassis forwarding config (key=1).
// Pass a zero FabricFwdInfo (Ifindex=0) to disable fabric1 redirect.
func (m *Manager) UpdateFabricFwd1(info FabricFwdInfo) error {
	zm, present, st := m.lookupMapLocked("fabric_fwd")
	if st == registryFresh {
		return fmt.Errorf("%w: fabric_fwd", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("fabric_fwd map not found")
	}
	return zm.Update(uint32(1), info, ebpf.UpdateAny)
}

// UpdateRGActive sets the active state of a redundancy group in BPF.
// active=true means this node is primary for the RG; false means secondary.
func (m *Manager) UpdateRGActive(rgID int, active bool) error {
	zm, present, st := m.lookupMapLocked("rg_active")
	if st == registryFresh {
		return fmt.Errorf("%w: rg_active", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("rg_active map not found")
	}
	var val uint8
	if active {
		val = 1
	}
	return zm.Update(uint32(rgID), val, ebpf.UpdateAny)
}

// UpdateHAWatchdog writes the current monotonic timestamp (seconds) for a
// redundancy group. BPF checks this to detect userspace liveness — if the
// timestamp is stale (>2s), the RG is treated as inactive (fail-closed).
func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	zm, present, st := m.lookupMapLocked("ha_watchdog")
	if st == registryFresh {
		return fmt.Errorf("%w: ha_watchdog", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("ha_watchdog map not found")
	}
	return zm.Update(uint32(rgID), timestamp, ebpf.UpdateAny)
}

// nextFIBGeneration returns the FIB generation following cur, saturating at
// math.MaxUint32 instead of wrapping to 0 (#10724 DR-26:A6-F5). A wrap would
// make entries still stamped at generation 0 compare fresh again, silently
// skipping the re-resolution the bump exists to force.
func nextFIBGeneration(cur uint32) uint32 {
	if cur == math.MaxUint32 {
		return math.MaxUint32
	}
	return cur + 1
}

type fibGenerationMap interface {
	Lookup(key, valueOut interface{}) error
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

var errFIBGenerationExhausted = errors.New("FIB generation exhausted")

// bumpFIBGenerationMap advances fib_gen_map, returning its old value if the map
// update fails. At MaxUint32, another change cannot advance cached-FIB stamps;
// report exhaustion rather than claiming a successful no-op invalidation.
func bumpFIBGenerationMap(zm fibGenerationMap) (uint32, error) {
	var key uint32
	var gen uint32
	if err := zm.Lookup(key, &gen); err != nil {
		gen = 0
	}
	prev := gen
	gen = nextFIBGeneration(gen)
	if gen == prev {
		return prev, fmt.Errorf("bump fib generation: %w", errFIBGenerationExhausted)
	}
	if err := zm.Update(key, gen, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to bump FIB generation", "err", err)
		return prev, fmt.Errorf("bump fib generation: %w", err)
	}
	slog.Info("bumped FIB generation counter", "generation", gen)
	return gen, nil
}

// BumpFIBGeneration increments the global FIB generation counter, causing
// all cached FIB entries in sessions to miss on the next packet. BPF programs
// compare session.fib_gen against fib_gen_map[0] and re-run bpf_fib_lookup
// when they differ.
//
// This replaces the old InvalidateFIBCache() approach which iterated sessions
// and wrote them back via sm.Update(). That caused RCU replacement of hash map
// entries — BPF programs holding pointers from bpf_map_lookup_elem would write
// to the OLD (about-to-be-freed) entry, losing counter/last_seen updates and
// causing sessions to expire prematurely.
// StartFIBSync is a no-op for eBPF — bpf_fib_lookup handles FIB queries in-kernel.
func (m *Manager) StartFIBSync(_ context.Context) {}

func (m *Manager) NotifyLinkCycle() {} // no-op: eBPF programs survive link cycles

func (m *Manager) SyncFabricState() {} // no-op: eBPF uses fabric_fwd BPF map directly

func (m *Manager) BumpFIBGeneration() (uint32, error) {
	zm, present, st := m.lookupMapLocked("fib_gen_map")
	if st == registryFresh {
		return 0, fmt.Errorf("%w: fib_gen_map", ErrDataplaneNotArmed)
	}
	if !present {
		slog.Warn("fib_gen_map not found, cannot bump FIB generation")
		return 0, fmt.Errorf("fib_gen_map not found")
	}
	return bumpFIBGenerationMap(zm)
}
