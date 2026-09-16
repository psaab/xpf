package daemon

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6198 regression coverage for the node-local BPF-ABI SessionID minted by the
// HA-synced session converters.
//
// The pre-fix composition was:
//
//	SessionID: uint64(now)<<16 | uint64(delta.Slot&0xffff)
//
// `now` is CLOCK_MONOTONIC SECONDS and `delta.Slot` is the AF_XDP BINDING slot
// (`BindingIdentity.slot` — one per interface/queue, a handful per node), which
// the binary event stream carrying the primary delta path never even decodes
// (`decodeSessionEvent` leaves it 0). Every session converted within one
// monotonic second therefore collapsed onto ONE id.

func sessionDeltaV4ForSessionID(srcPort uint16, slot uint32) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 2, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200",
		SrcPort: srcPort, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		Slot: slot,
	}
}

func sessionDeltaV6ForSessionID(srcPort uint16, slot uint32) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 10, Protocol: 6,
		SrcIP: "2001:559:8585:bf01::102", DstIP: "2001:559:8585:80::200",
		SrcPort: srcPort, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		Slot: slot,
	}
}

// TestUserspaceSyncedSessionIDDistinctPerSession6198 is the fail-on-revert pin.
//
// It converts many DISTINCT sessions that share the binding slot the event
// stream actually produces (0) and asserts every minted SessionID is unique.
// Restoring `uint64(now)<<16 | uint64(delta.Slot&0xffff)` makes this RED as an
// assertion: a few hundred conversions cannot span a monotonic second boundary
// more than once, so the pre-fix code yields at most two distinct ids.
func TestUserspaceSyncedSessionIDDistinctPerSession6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	const sessions = 512

	for _, tc := range []struct {
		name    string
		convert func(uint16, uint32) (uint64, bool)
	}{
		{
			name: "v4",
			convert: func(port uint16, slot uint32) (uint64, bool) {
				_, val, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(port, slot), zoneIDs)
				return val.SessionID, ok
			},
		},
		{
			name: "v6",
			convert: func(port uint16, slot uint32) (uint64, bool) {
				_, val, ok := userspaceSessionFromDeltaV6(sessionDeltaV6ForSessionID(port, slot), zoneIDs)
				return val.SessionID, ok
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[uint64]uint16, sessions)
			for i := 0; i < sessions; i++ {
				port := uint16(30000 + i)
				id, ok := tc.convert(port, 0)
				if !ok {
					t.Fatalf("expected %s delta (src port %d) to convert", tc.name, port)
				}
				if prev, dup := seen[id]; dup {
					t.Fatalf("%s SessionID collision: src ports %d and %d both minted id %#x "+
						"(%d distinct sessions produced only %d distinct ids) — the synced "+
						"session id is not an identity",
						tc.name, prev, port, id, i+1, len(seen))
				}
				seen[id] = port
			}
			if len(seen) != sessions {
				t.Fatalf("%s: %d distinct ids for %d sessions", tc.name, len(seen), sessions)
			}
		})
	}
}

// TestUserspaceSyncedSessionIDSlotBoundary6198 covers the literal aliasing the
// issue names: slots that differ by a multiple of 65536 are indistinguishable
// under `Slot & 0xffff`. Slot no longer participates in the identity at all, so
// these sessions get distinct ids. Restoring the mask makes the 65536/65537
// pairs collide with 0/1 within a monotonic second.
func TestUserspaceSyncedSessionIDSlotBoundary6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	slots := []uint32{0, 1, 65535, 65536, 65537, 131072}

	seen := make(map[uint64]uint32, len(slots))
	for i, slot := range slots {
		// Distinct sessions (distinct source ports) that happen to land on
		// different binding slots — including slots that alias under the old
		// 16-bit mask.
		_, val, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(uint16(40000+i), slot), zoneIDs)
		if !ok {
			t.Fatalf("expected delta on slot %d to convert", slot)
		}
		if prev, dup := seen[val.SessionID]; dup {
			t.Fatalf("SessionID collision: slots %d and %d both minted id %#x — "+
				"slot %d aliases slot %d under a 16-bit mask", prev, slot, val.SessionID, slot, prev)
		}
		seen[val.SessionID] = slot
	}
}

// TestUserspaceSyncedSessionIDDistinctSlotsBelowBoundary6198 is the NEGATIVE
// CONTROL: it must pass BOTH with and without the fix.
//
// Two sessions on distinct binding slots BELOW the 16-bit boundary always got
// distinct ids, because the pre-fix composition put the slot in the low 16 bits
// (`now<<16 | slot`), so slots 1 and 2 differ regardless of `now`. A control
// that also reds on revert would be a co-signer, not a control.
func TestUserspaceSyncedSessionIDDistinctSlotsBelowBoundary6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}

	_, valA, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(41000, 1), zoneIDs)
	if !ok {
		t.Fatal("expected slot-1 delta to convert")
	}
	_, valB, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(41001, 2), zoneIDs)
	if !ok {
		t.Fatal("expected slot-2 delta to convert")
	}
	if valA.SessionID == valB.SessionID {
		t.Fatalf("slots 1 and 2 shared SessionID %#x", valA.SessionID)
	}
}

// TestUserspaceSyncedSessionIDNamespaceDisjointFromDataplane6198 pins the
// namespace reservation: a Go-minted id must never be mistakable for a Rust
// dataplane id (`(worker_id & 0xFFFF) << 48 | counter48`, worker ids being tiny
// queue indices), because both are written into the same BPF conntrack mirror
// field. It also pins the "never 0" property — 0 is the sentinel that makes
// `flowSessionDisplayID` fall back to the per-row ordinal.
func TestUserspaceSyncedSessionIDNamespaceDisjointFromDataplane6198(t *testing.T) {
	for i := 0; i < 64; i++ {
		id := nextUserspaceSyncedSessionID()
		if id == 0 {
			t.Fatal("minted the 0 sentinel")
		}
		if hi := id >> 48; hi != 0xFFFF {
			t.Fatalf("minted id %#x has namespace %#x, want %#x — it could alias a "+
				"dataplane id from worker %d", id, hi, 0xFFFF, hi)
		}
	}
}

// oneSecondOfUptimeNanos is one second expressed in the units
// userspaceSyncedSessionIDSeed consumes.
const oneSecondOfUptimeNanos = uint64(1_000_000_000)

// TestUserspaceSyncedSessionIDSeedSurvivesRestart6198 pins the cross-restart
// anti-reuse property across a WHOLE second of uptime.
//
// An unseeded counter would re-mint 1, 2, 3… after an xpfd restart and collide
// with entries the peer's mirror still holds from the previous incarnation. The
// old now<<16|Slot composition did NOT have that flaw (CLOCK_MONOTONIC keeps
// increasing across a daemon restart), so seeding is what keeps this change a
// strict improvement rather than a trade.
//
// This is also the NEGATIVE CONTROL for the sub-second case below: a full second
// separates two incarnations under a second-resolution seed just as well as under
// a nanosecond one, so this test passes in both worlds.
func TestUserspaceSyncedSessionIDSeedSurvivesRestart6198(t *testing.T) {
	// ~11.6 days of uptime, well inside the 48-bit seed space.
	const uptime = uint64(1_000_000) * oneSecondOfUptimeNanos
	seedA := userspaceSyncedSessionIDSeed(uptime)
	seedB := userspaceSyncedSessionIDSeed(uptime + oneSecondOfUptimeNanos)

	if seedB <= seedA {
		t.Fatalf("a later incarnation seeds at %#x, not above the earlier %#x", seedB, seedA)
	}

	// Incarnation A must not reach incarnation B's seed. The bound is A's AVERAGE
	// mint rate over that second; 100k conversions/second is already well above
	// what the dataplane sustains.
	const mintedInThatSecond = uint64(100_000)
	if seedA+mintedInThatSecond >= seedB {
		t.Fatalf("incarnation A averaging %d ids/s reaches incarnation B's seed "+
			"(%#x + %d >= %#x) — ids would repeat across a restart",
			mintedInThatSecond, seedA, mintedInThatSecond, seedB)
	}

	// The seed must stay inside the counter space so it can never bleed into the
	// namespace bits.
	if seedB&^userspaceSyncedSessionIDCounterMask != 0 {
		t.Fatalf("seed %#x escapes the 48-bit counter mask", seedB)
	}
}

// TestUserspaceSyncedSessionIDSeedDistinctWithinOneSecond6198 drives the case the
// whole-second test above CANNOT see: two incarnations whose first allocations
// land inside the SAME integer monotonic second.
//
// That is the common restart, not the exotic one — systemd's `RestartSec=1` puts
// a crash-restart squarely in the window, and the sub-second phase is uniform, so
// on average half of all restarts land in it. A seed read at second resolution
// gives both incarnations the SAME value and they repeat from their very first
// id. Every separation below is far longer than a process teardown+exec, and
// every one is invisible to a whole-second seed.
func TestUserspaceSyncedSessionIDSeedDistinctWithinOneSecond6198(t *testing.T) {
	// Uptime 1e6 s + 0.25 s: mid-second, so every offset below stays inside the
	// same integer second.
	const base = uint64(1_000_000)*oneSecondOfUptimeNanos + 250_000_000

	for _, sep := range []struct {
		name  string
		nanos uint64
	}{
		{"1ms", 1_000_000},
		{"10ms", 10_000_000},
		{"100ms", 100_000_000},
		{"700ms", 700_000_000},
	} {
		t.Run(sep.name, func(t *testing.T) {
			// Guard the fixture: if the offset crossed a second boundary a
			// second-resolution seed would legitimately differ and the test
			// would be vacuous.
			if base/oneSecondOfUptimeNanos != (base+sep.nanos)/oneSecondOfUptimeNanos {
				t.Fatalf("fixture error: a %s offset from %d ns crosses a second "+
					"boundary, so this case does not exercise the same-second window",
					sep.name, base)
			}
			seedA := userspaceSyncedSessionIDSeed(base)
			seedB := userspaceSyncedSessionIDSeed(base + sep.nanos)
			if seedA == seedB {
				t.Fatalf("two incarnations %s apart within one monotonic second "+
					"share seed %#x — the restart re-mints from the same first id, "+
					"so the new incarnation's ids collide with the previous one's "+
					"entries still in the peer's mirror", sep.name, seedA)
			}
			if seedB <= seedA {
				t.Fatalf("later incarnation seeds at %#x, not above the earlier %#x", seedB, seedA)
			}
		})
	}
}

// TestUserspaceSyncedSessionIDIsSeededFromBootClock6198 pins that the allocator
// actually APPLIES the seed — the properties above are worthless if
// nextUserspaceSyncedSessionID never calls it. An unseeded counter would still be
// in the low thousands after a whole test binary's worth of mints; a seeded one
// starts at least one second of uptime above zero.
func TestUserspaceSyncedSessionIDIsSeededFromBootClock6198(t *testing.T) {
	if daemonMonotonicNanos() < oneSecondOfUptimeNanos {
		t.Skip("system uptime < 1s: the boot-clock seed carries no signal yet")
	}
	counter := nextUserspaceSyncedSessionID() &^ userspaceSyncedSessionIDNamespace
	if floor := userspaceSyncedSessionIDSeed(oneSecondOfUptimeNanos); counter < floor {
		t.Fatalf("counter %d is below one second of seeded space (%d) — the "+
			"allocator is not seeded from the boot clock, so ids repeat across a restart",
			counter, floor)
	}
}

// TestUserspaceSyncedSessionIDWrapEmitsNoDuplicate6198 drives the allocator TO
// the 48-bit boundary, not near it.
//
// The counter must skip the reserved `0` — and the skip has to be COMMITTED to
// the atomic. Correcting only the returned copy (`Add(1) & mask; if counter == 0
// { counter = 1 }`) leaves the atomic holding the masked-zero value, so the call
// AFTER the wrap reads 1 and returns the id just handed out. The duplicate stays
// inside the namespace, so nothing downstream looks wrong — uniqueness just
// silently stops holding.
//
// The wrap is reachable rather than theoretical: the seed consumes counter space,
// so the distance to it depends on uptime phase.
func TestUserspaceSyncedSessionIDWrapEmitsNoDuplicate6198(t *testing.T) {
	// Let the lazy boot-clock seed fire first, so the Store below is not
	// overwritten by it, then restore the allocator for any later test.
	_ = nextUserspaceSyncedSessionID()
	saved := userspaceSyncedSessionIDs.Load()
	t.Cleanup(func() { userspaceSyncedSessionIDs.Store(saved) })

	// One short of the last representable counter value.
	userspaceSyncedSessionIDs.Store(userspaceSyncedSessionIDCounterMask - 1)

	const mints = 4 // last-before-wrap, the wrap itself, and two past it
	ids := make([]uint64, 0, mints)
	seen := make(map[uint64]int, mints)
	for i := 0; i < mints; i++ {
		id := nextUserspaceSyncedSessionID()
		if prev, dup := seen[id]; dup {
			t.Fatalf("mints %d and %d across the 48-bit wrap both returned %#x — "+
				"the zero-correction was applied to the returned copy but never "+
				"committed to the atomic, so the id after the wrap repeats",
				prev, i, id)
		}
		seen[id] = i
		ids = append(ids, id)
	}

	for i, id := range ids {
		if id == userspaceSyncedSessionIDNamespace {
			t.Fatalf("mint %d returned the reserved 0 counter (%#x)", i, id)
		}
		if id>>48 != 0xFFFF {
			t.Fatalf("mint %d left the namespace: %#x", i, id)
		}
	}

	// The wrap must land on 1 and then keep climbing, not stall or repeat.
	if got := ids[1] &^ userspaceSyncedSessionIDNamespace; got != 1 {
		t.Fatalf("counter after the wrap = %d, want 1", got)
	}
	if got := ids[2] &^ userspaceSyncedSessionIDNamespace; got != 2 {
		t.Fatalf("counter after the wrap+1 = %d, want 2 — the atomic did not "+
			"retain the corrected value", got)
	}
}

// TestUserspaceSyncedSessionIDDistinctAwayFromWrap6198 is the NEGATIVE CONTROL
// for the wrap test: consecutive mints far from the boundary are distinct under
// BOTH the CAS advance and the old Add-and-correct, because the correction branch
// never runs there. A control that also reds would be a co-signer.
func TestUserspaceSyncedSessionIDDistinctAwayFromWrap6198(t *testing.T) {
	_ = nextUserspaceSyncedSessionID()
	saved := userspaceSyncedSessionIDs.Load()
	t.Cleanup(func() { userspaceSyncedSessionIDs.Store(saved) })

	// Same distance-from-a-boundary shape as the wrap test, but at a point the
	// counter merely passes through.
	userspaceSyncedSessionIDs.Store(userspaceSyncedSessionIDCounterMask >> 1)

	seen := make(map[uint64]int, 4)
	for i := 0; i < 4; i++ {
		id := nextUserspaceSyncedSessionID()
		if prev, dup := seen[id]; dup {
			t.Fatalf("mints %d and %d away from the wrap both returned %#x", prev, i, id)
		}
		seen[id] = i
	}
}

// TestUserspaceForwardWireAliasSharesBaseSessionID6198 pins that the
// fabric-redirect forward-wire alias entry carries the SAME SessionID as its
// base entry: they are two conntrack keys for ONE logical session. Re-converting
// the delta for the alias (the pre-#6198 shape) would mint a second id.
func TestUserspaceForwardWireAliasSharesBaseSessionID6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}

	deltaV4 := sessionDeltaV4ForSessionID(39906, 0)
	deltaV4.NATSrcIP = "172.16.80.8"
	deltaV4.NATSrcPort = 39906
	baseKeyV4, baseValV4, ok := userspaceSessionFromDeltaV4(deltaV4, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	_, aliasValV4, ok := userspaceForwardWireAliasV4(baseKeyV4, baseValV4)
	if !ok {
		t.Fatal("expected v4 forward-wire alias")
	}
	if aliasValV4.SessionID != baseValV4.SessionID {
		t.Fatalf("v4 alias SessionID %#x != base %#x", aliasValV4.SessionID, baseValV4.SessionID)
	}

	deltaV6 := sessionDeltaV6ForSessionID(50952, 0)
	deltaV6.NATSrcIP = "2001:559:8585:80::8"
	deltaV6.NATSrcPort = 50952
	baseKeyV6, baseValV6, ok := userspaceSessionFromDeltaV6(deltaV6, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	_, aliasValV6, ok := userspaceForwardWireAliasV6(baseKeyV6, baseValV6)
	if !ok {
		t.Fatal("expected v6 forward-wire alias")
	}
	if aliasValV6.SessionID != baseValV6.SessionID {
		t.Fatalf("v6 alias SessionID %#x != base %#x", aliasValV6.SessionID, baseValV6.SessionID)
	}
}
