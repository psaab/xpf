package cluster

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #19140: the heartbeat's optional "XPFR" readiness section carries the data
// RGs whose takeover readiness (rg.Ready) is false on the sender. The RETH
// member-shim yield goes only to a peer that does not flag the RG; the #12164
// arm-debt yield ignores it. These cells pin the wire contract (round trip,
// invisible to a pre-section decoder, MAC-covered, fits the frame) and the
// receiver contract (per frame, RG0 ignored, dropped with the peer).

func readinessPacket19140(notReady []uint8) *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         1,
		Groups:            []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: 0}, {GroupID: 1, Priority: 100, Weight: 255, State: 0}},
		Monitors:          []HeartbeatMonitor{{RGID: 1, Weight: 255, Up: true, Interface: "ge-7-0-2"}},
		SoftwareVersion:   "xpf-19140",
		HAProtocolVersion: CurrentHAProtocolVersion,
		HeartbeatSession:  7,
		HeartbeatSequence: 9,
		WallClockUnixNano: 1_800_000_000_000_000_000,
		TakeoverNotReady:  notReady,
	}
}

func TestReadinessSectionRoundTrip19140(t *testing.T) {
	for _, ids := range [][]uint8{{1}, {1, 3, 255}, {2, 9, 64, 128, 200}} {
		got, err := UnmarshalHeartbeat(MarshalHeartbeat(readinessPacket19140(ids)))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.TakeoverNotReady, ids) {
			t.Fatalf("round trip %v -> %v", ids, got.TakeoverNotReady)
		}
	}
	// No not-ready RG: no section at all, byte-identical to the pre-#19140 frame.
	with, without := MarshalHeartbeat(readinessPacket19140(nil)), MarshalHeartbeat(readinessPacket19140([]uint8{}))
	if len(with) != len(without) {
		t.Fatal("an empty not-ready set changed the frame")
	}
	if got, _ := UnmarshalHeartbeat(with); len(got.TakeoverNotReady) != 0 {
		t.Fatalf("an all-ready frame decoded not-ready RGs %v", got.TakeoverNotReady)
	}
}

// The real pre-section decoder (a verbatim copy of UnmarshalHeartbeat before
// #19140) decodes a frame WITH the section exactly as the same frame without
// it, on a plain frame and on a keyed one (whose auth trailer it locates at the
// fixed tail and whose MAC still verifies).
func TestReadinessSectionInvisibleToPreSectionReaders19140(t *testing.T) {
	key := []byte("test-cluster-psk-19140")
	for _, keyed := range []bool{false, true} {
		t.Run(fmt.Sprintf("keyed=%v", keyed), func(t *testing.T) {
			enc := func(p *HeartbeatPacket) []byte {
				if keyed {
					return MarshalHeartbeatAuth(p, key, 11, 12)
				}
				return MarshalHeartbeat(p)
			}
			withSec, noSec := enc(readinessPacket19140([]uint8{1, 5})), enc(readinessPacket19140(nil))
			a, err := unmarshalHeartbeatPre19140(withSec)
			if err != nil {
				t.Fatal(err)
			}
			b, err := unmarshalHeartbeatPre19140(noSec)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("an old reader decoded the frame differently with the section:\n with %+v\n without %+v", a, b)
			}
			if keyed {
				if _, _, present := heartbeatAuthTrailer(withSec); !present || !verifyHeartbeatMAC(withSec, key) {
					t.Fatal("an old reader cannot locate or verify the auth trailer of a frame carrying the section")
				}
			}
		})
	}
}

// The section is inside the MAC-covered body: a keyed frame with it verifies,
// and flipping one bitmap bit fails verification, so an on-path writer can
// neither forge "not ready" nor clear it.
func TestReadinessSectionIsMACCovered19140(t *testing.T) {
	key := []byte("test-cluster-psk-19140")
	frame := MarshalHeartbeatAuth(readinessPacket19140([]uint8{1}), key, 11, 12)
	if !verifyHeartbeatMAC(frame, key) {
		t.Fatal("a keyed frame with the readiness section does not verify")
	}
	got, err := UnmarshalHeartbeat(frame)
	if err != nil || !slices.Equal(got.TakeoverNotReady, []uint8{1}) {
		t.Fatalf("decode of a keyed frame: %v %v", got, err)
	}
	at := -1
	for i := 0; i+4 <= len(frame); i++ {
		if string(frame[i:i+4]) == heartbeatReadinessMagic {
			at = i
		}
	}
	if at < 0 {
		t.Fatal("no readiness section in the keyed frame")
	}
	for _, bit := range []int{0, 1, 2} { // clear RG1, set RG0, set RG2
		tampered := append([]byte(nil), frame...)
		tampered[at+4] ^= 1 << bit
		if verifyHeartbeatMAC(tampered, key) {
			t.Fatalf("flipping readiness bit %d still verifies: the section is outside the MAC", bit)
		}
	}
}

// At the largest group count and with every data RG not ready, the section
// still fits the frame (it is reserved ahead of the best-effort monitors) and
// the keyed frame stays within maxHeartbeatSize.
func TestReadinessSectionFitsTheMaximalFrame19140(t *testing.T) {
	pkt := readinessPacket19140(nil)
	pkt.Groups = nil
	for id := 0; id < maxHeartbeatGroups; id++ {
		pkt.Groups = append(pkt.Groups, HeartbeatGroup{GroupID: uint8(id), Priority: 100, Weight: 255})
		if id != 0 {
			pkt.TakeoverNotReady = append(pkt.TakeoverNotReady, uint8(id))
		}
	}
	for i := range 300 {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{RGID: 1, Weight: 1, Up: true, Interface: fmt.Sprintf("ge-0-0-%d", i)})
	}
	frame := marshalHeartbeatAuthEpoch(pkt, []byte("k"), 1, 1, 42)
	if len(frame) > maxHeartbeatSize {
		t.Fatalf("maximal keyed frame is %d bytes, over the %d-byte bound", len(frame), maxHeartbeatSize)
	}
	got, err := UnmarshalHeartbeat(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.TakeoverNotReady) != maxHeartbeatGroups-1 || len(got.Groups) != maxHeartbeatGroups {
		t.Fatalf("maximal frame decoded %d not-ready RGs and %d groups, want %d and %d",
			len(got.TakeoverNotReady), len(got.Groups), maxHeartbeatGroups-1, maxHeartbeatGroups)
	}
	t.Logf("maximal keyed frame: %d of %d bytes, %d monitors carried", len(frame), maxHeartbeatSize, len(got.Monitors))
}

// The sender flags every data RG whose rg.Ready is false, never RG0.
func TestHeartbeatFlagsNotReadyDataRGsOnly19140(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 200}},
		{ID: 1, NodePriorities: map[int]int{0: 200}},
		{ID: 2, NodePriorities: map[int]int{0: 200}},
	}})
	t.Cleanup(m.Stop)
	m.SetRGReady(0, false, []string{"rg0 never flagged"})
	m.SetRGReady(1, true, nil)
	m.SetRGReady(2, false, []string{"not ready"})
	if got := m.buildHeartbeat().TakeoverNotReady; !slices.Equal(got, []uint8{2}) {
		t.Fatalf("flagged %v, want [2] (RG0 never, a ready RG1 never)", got)
	}
}

// The receiver: per frame, RG0 ignored, dropped with the peer. Both nodes
// configure RG0, so the peer's frame carries an RG0 group and the RG0 check
// is reachable (without it peerGroups[0] never exists and the check is
// vacuous).
func TestReadinessBitIsPerFrameAndDataRGOnly19140(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
			{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	}
	owner, peer := NewManager(0, 1), NewManager(1, 1)
	owner.UpdateConfig(cfg)
	peer.UpdateConfig(cfg)
	t.Cleanup(func() { owner.Stop(); peer.Stop() })
	exchangeElection12164(owner, peer)
	frame := peer.buildHeartbeat()
	frame.TakeoverNotReady = []uint8{0, 1}
	owner.handlePeerHeartbeat(frame)
	owner.mu.RLock()
	pg1, pg0 := owner.peerGroups[1], owner.peerGroups[0]
	owner.mu.RUnlock()
	if !pg1.takeoverNotReady {
		t.Fatal("the peer's RG1 not-ready bit was not recorded")
	}
	if pg0.frame == 0 {
		t.Fatal("setup: the frame carried no RG0 group, so the RG0 check below would be vacuous")
	}
	if pg0.takeoverNotReady {
		t.Fatal("an RG0 bit was honoured; RG0 is never a member-shim yield target")
	}
	frame = peer.buildHeartbeat()
	frame.TakeoverNotReady = nil
	owner.handlePeerHeartbeat(frame)
	owner.mu.RLock()
	pg1 = owner.peerGroups[1]
	owner.mu.RUnlock()
	if pg1.takeoverNotReady {
		t.Fatal("a frame without the bit did not clear it: the marker outlived its frame")
	}
}

// E3 (with the section): a charged owner does NOT yield to a heavier peer that
// flags the RG not ready; it keeps the RG. E10: the same peer seen as an older
// build (no section on the wire) gets the inherited #12164 behaviour, and the
// RG is never stranded. E11: arm debt ignores the section (#12164). E12: once
// the peer becomes ready, its next frame clears the flag and the yield goes.
func TestMemberShimYieldRespectsPeerReadiness19140(t *testing.T) {
	type mode struct {
		name     string
		preempt  bool
		stripped bool // the peer is an older build: no readiness section
		arm      bool // charge arm debt instead of member-shim debt
		// staleAtCharge: the charge lands while the owner's latest peer frame
		// still predates the peer's not-ready edge.
		staleAtCharge bool
	}
	run := func(t *testing.T, owner, peer *Manager, stripped bool, rounds int) (dual int) {
		for range rounds {
			hb := peer.buildHeartbeat()
			if stripped {
				hb.TakeoverNotReady = nil
			}
			owner.handlePeerHeartbeat(hb)
			peer.handlePeerHeartbeat(owner.buildHeartbeat())
			if owner.IsLocalPrimary(1) && peer.IsLocalPrimary(1) {
				dual++
			}
		}
		return dual
	}
	for _, preempt := range []bool{true, false} {
		for _, m := range []mode{
			{name: "flagged-peer-keeps", preempt: preempt},
			{name: "stale-frame-at-charge-keeps", preempt: preempt, staleAtCharge: true},
			{name: "older-peer-inherits-12164", preempt: preempt, stripped: true},
			{name: "arm-debt-ignores-flag", preempt: preempt, arm: true},
		} {
			t.Run(fmt.Sprintf("%s/preempt=%v", m.name, m.preempt), func(t *testing.T) {
				owner, peer := memberShimPair19140(t, m.preempt, 200, 100)
				exchangeElection12164(owner, peer)
				peer.SetRGReady(1, false, []string{"userspace forwarding not armed"})
				if !m.staleAtCharge {
					// The owner has seen the peer's current readiness before
					// the charge: the producer's grace is 10 s of frames.
					run(t, owner, peer, m.stripped, 1)
				}
				if m.arm {
					owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
				} else {
					chargeMemberShim19140(owner, true)
				}
				if dual := run(t, owner, peer, m.stripped, 10); dual != 0 {
					t.Fatalf("%d dual-primary rounds", dual)
				}
				switch {
				case m.name == "flagged-peer-keeps" || m.staleAtCharge:
					if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
						t.Fatal("a member-shim owner yielded to a peer that flags the RG not ready")
					}
					// E12: the peer becomes ready; its next frames clear the
					// flag and the yield goes.
					peer.SetRGReady(1, true, nil)
					run(t, owner, peer, false, 10)
					if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
						t.Fatal("after the peer became ready the member-shim owner still kept the RG")
					}
				default:
					if !owner.IsLocalPrimary(1) && !peer.IsLocalPrimary(1) {
						t.Fatal("the yield stranded the RG")
					}
					if owner.IsLocalPrimary(1) {
						t.Fatal("the owner kept the RG: want the #12164 yield (older peer, or arm debt)")
					}
				}
			})
		}
	}
}
