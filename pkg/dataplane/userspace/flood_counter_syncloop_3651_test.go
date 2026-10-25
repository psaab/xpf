package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #3651: bind the PRODUCTION status-loop call site for the per-zone FLOOD
// counters.
//
// The pkg/dataplane retention tests drive Manager.ReplaceFloodCounterOffsets
// directly. That proves the replacement primitive and NOT that
// syncBPFCountersLocked uses it — swapping the status loop to per-row
// SetFloodCounterOffset while leaving the primitive correct leaves every one of
// those tests green. This drives two successive ProcessStatus polls through the
// real loop.
//
// FAIL-ON-REVERT: replace the ReplaceFloodCounterOffsets call in
// syncBPFCountersLocked with a `for ... SetFloodCounterOffset` loop and `gone`
// keeps serving its poll-N counts.
func TestSyncBPFCountersReplacesFloodOffsetsAcrossPolls3651(t *testing.T) {
	m := New()
	const kept uint32 = 101 // synthetic slotted zone id (#16557: StableZoneID now exceeds dense slot space)
	const gone uint32 = 102 // synthetic slotted zone id

	// Poll N: the helper publishes both zones.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters: []ZoneFloodCounterStatus{
			{ZoneID: kept, SynFloodEvents: 1, ICMPFloodEvents: 2, UDPFloodEvents: 3},
			{ZoneID: gone, SynFloodEvents: 90, ICMPFloodEvents: 91, UDPFloodEvents: 92},
		},
	})
	m.mu.Unlock()

	if fs, err := m.bpfShim.ReadFloodCounters(gone); err != nil || fs.SynCount != 90 {
		t.Fatalf("poll N: gone zone = %+v err=%v; want SynCount 90, nil", fs, err)
	}

	// Poll N+1: `gone` is no longer published — it lost its hot-path slot, was
	// removed from the config, or the helper restarted. `kept` advances.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters: []ZoneFloodCounterStatus{
			{ZoneID: kept, SynFloodEvents: 5, ICMPFloodEvents: 6, UDPFloodEvents: 7},
		},
	})
	m.mu.Unlock()

	if _, err := m.bpfShim.ReadFloodCounters(gone); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		fs, _ := m.bpfShim.ReadFloodCounters(gone)
		t.Errorf("the status loop left a stale flood offset for a zone the helper "+
			"stopped publishing (%+v, err=%v); want ErrCounterNotPopulated — a "+
			"retained value here is a FROZEN counter that under-reports every "+
			"subsequent flood", fs, err)
	}
	// The still-published zone must ADVANCE: a loop that cleared everything and
	// re-added nothing would pass the assertion above.
	fs, err := m.bpfShim.ReadFloodCounters(kept)
	if err != nil {
		t.Fatalf("kept zone err = %v; want nil", err)
	}
	if fs.SynCount != 5 || fs.ICMPCount != 6 || fs.UDPCount != 7 {
		t.Errorf("kept zone = %+v; want {syn:5 icmp:6 udp:7} — three DISTINCT values, "+
			"so a mirror that crossed two families cannot pass", fs)
	}
}

// The helper-restart / downgrade case through the real loop: an empty block
// clears. Paired with a POPULATED first poll so an implementation that always
// clears cannot pass.
func TestSyncBPFCountersClearsFloodOffsetsWhenHelperStopsPublishing3651(t *testing.T) {
	m := New()
	const id uint32 = 103 // synthetic slotted zone id

	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters:         []ZoneFloodCounterStatus{{ZoneID: id, SynFloodEvents: 3}},
	})
	m.mu.Unlock()
	if fs, err := m.bpfShim.ReadFloodCounters(id); err != nil || fs.SynCount != 3 {
		t.Fatalf("populated poll must be readable first: %+v err=%v", fs, err)
	}

	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{FloodCounterLayoutVersion: 1})
	m.mu.Unlock()
	if _, err := m.bpfShim.ReadFloodCounters(id); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		t.Errorf("an empty published block must clear the flood offsets; err=%v", err)
	}
}

// The HELPER-DOWNGRADE case, which layout version 0 is precisely how the wire
// signals it. Every other test in this file hard-codes
// FloodCounterLayoutVersion 1, so a `if status.FloodCounterLayoutVersion == 0 {
// return }` guard added before the flood block would escape them. That guard
// reads as a natural optimisation — the field's own doc invites it — but a
// downgrade is one of the disappearance cases that MUST clear, or the last
// offsets are stranded forever.
func TestSyncBPFCountersClearsFloodOffsetsOnLayoutVersionZero3651(t *testing.T) {
	m := New()
	const id uint32 = 101

	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters:         []ZoneFloodCounterStatus{{ZoneID: id, SynFloodEvents: 11}},
	})
	m.mu.Unlock()
	if fs, err := m.bpfShim.ReadFloodCounters(id); err != nil || fs.SynCount != 11 {
		t.Fatalf("populated poll must be readable first: %+v err=%v", fs, err)
	}

	// The helper restarts into an OLDER build: layout version 0, no flood block.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{FloodCounterLayoutVersion: 0})
	m.mu.Unlock()
	if _, err := m.bpfShim.ReadFloodCounters(id); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		fs, _ := m.bpfShim.ReadFloodCounters(id)
		t.Errorf("a layout-version-0 (downgraded/restarted) helper left the previous "+
			"flood offsets in place (%+v, err=%v); want ErrCounterNotPopulated", fs, err)
	}
}

// Over-reach guard: the flood mirror must not disturb the per-zone TRAFFIC
// mirror in the same poll, and vice versa. Both blocks are handled in one
// syncBPFCountersLocked pass, so a mirror that reused the wrong map or cleared
// too broadly would show up here. Stays GREEN under the replace-vs-set revert.
func TestSyncBPFCountersKeepsTrafficAndFloodMirrorsIndependent3651(t *testing.T) {
	m := New()
	const id uint32 = 101

	// A poll carrying TRAFFIC only: the flood offsets must read not-populated,
	// and the traffic offsets must be live.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: id, IngressPackets: 7, IngressBytes: 700},
		},
	})
	m.mu.Unlock()
	if v, err := m.bpfShim.ReadZoneCounters(id, 0); err != nil || v.Packets != 7 {
		t.Fatalf("traffic-only poll: zone counters = %+v err=%v; want {7,700} nil", v, err)
	}
	if _, err := m.bpfShim.ReadFloodCounters(id); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		t.Errorf("a traffic-only poll must leave the flood counters not-populated; err=%v", err)
	}

	// A poll carrying FLOOD only: the traffic offsets must now clear (their own
	// replacement contract) while the flood offsets go live. The point of this
	// leg is that the two are driven by their OWN blocks.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters:         []ZoneFloodCounterStatus{{ZoneID: id, ICMPFloodEvents: 4}},
	})
	m.mu.Unlock()
	fs, err := m.bpfShim.ReadFloodCounters(id)
	if err != nil || fs.ICMPCount != 4 {
		t.Errorf("flood-only poll: flood counters = %+v err=%v; want ICMPCount 4, nil", fs, err)
	}
	if fs.SynCount != 0 || fs.UDPCount != 0 {
		t.Errorf("flood-only poll set unrelated families: %+v; want syn=0 udp=0", fs)
	}
	if _, err := m.bpfShim.ReadZoneCounters(id, 0); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		t.Errorf("a flood-only poll must clear the TRAFFIC offsets via their own "+
			"replacement, not retain them; err=%v", err)
	}
}
