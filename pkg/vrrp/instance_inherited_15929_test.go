package vrrp

import (
	"errors"
	"net"
	"testing"
	"time"
)

// Regression tests for #15929: inherited coalescing gaps surfaced by the
// Codex review of PR #15928 (ledger 15928-codex.md). Each defect is
// reproduced here BEFORE its fix; the two-instance harness (gap 1) drives
// the master's wire advert into a real peer BACKUP, while gaps 2 and 3
// are deterministic interleavings from the same ledger.

type advert15929 struct {
	priority int
	cs       int
}

// captureAdverts15929 records every wire advert (priority + MaxAdvertInt
// centiseconds) the re-pointed sendPacketFn would emit.
func captureAdverts15929(t *testing.T) chan advert15929 {
	t.Helper()
	adverts := make(chan advert15929, 64)
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		adverts <- advert15929{priority: int(pkt.Priority), cs: int(pkt.MaxAdvertInt)}
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })
	return adverts
}

func drainAdverts15929(adverts chan advert15929) []advert15929 {
	var out []advert15929
	for {
		select {
		case a := <-adverts:
			out = append(out, a)
		default:
			return out
		}
	}
}

// --- Gap 1: interval growth applied via a cfg-derived arm without ---
// --- telling the peer (two-instance harness). ---

// TestVRRPMasterTwoInstance_IntervalGrowthDuringSend_CorrectsPeerBeforePeerTimeout:
//
// MASTER at 100ms advertises; a manager commit grows its interval to
// 10000ms DURING that send (between sendAdvert's snapshot and the
// trailing armAdvertTimer). The arm applies the growth and, pre-fix,
// armIntervalAppliedLocked baselined oldAdvertiseMS to the grown cfg so
// the queued config token suppressed its correction advert: the peer
// BACKUP, having learned the 100ms MaxAdvertInt the wire actually
// carried, times the master out in ~0.34s — two owners long before the
// master's next 10s advert.
//
// Post-fix the wire baseline is the interval the advert actually
// carried (wireAdvertIntervalMS, tracked inside sendAdvert), never the
// armed cfg: the arm still re-times locally, but the pending record
// keeps old=100 (wire) vs new=10000 (cfg), so the config consumption
// emits the correction. This test carries the correction packet into a
// real BACKUP instance and proves it lands BEFORE that BACKUP's
// short learned master-down deadline — i.e. the peer does not expire
// into a second MASTER.
//
// Pre-fix deterministic RED: the pending record reads old==new==10000
// after the arm, the consumption sends no second advert, the peer's
// masterDownInterval stays ~0.34s, and the "wire grows before peer
// timeout" assertion fails.
func TestVRRPMasterTwoInstance_IntervalGrowthDuringSend_CorrectsPeerBeforePeerTimeout(t *testing.T) {
	master := newMaster15689(t, 100)
	// Peer BACKUP: priority 150 (strictly below master's 200 so its
	// master-down horizon at the learned cadence is short), local 100ms.
	peer := newMasterIntervalTestInstance(t, 150, 100)
	installFakeVIPNetlink(peer) // promotion would otherwise fail closed on eth0

	wire := captureAdverts15929(t)
	// Commit the growth right after the first (100ms) wire advert has
	// actually been emitted — sendPacketDone runs at the end of that
	// sendAdvert, before noteAdvertPriority and the trailing arm,
	// exactly the interleaving the ledger names (the arm then arms
	// 10000ms locally while the wire still says 100ms). A callback
	// inside sendPacketFn would fire mid-send instead.
	grown := false
	prevDone := sendPacketDone
	sendPacketDone = func(_ *vrrpInstance) {
		if !grown {
			grown = true
			master.updateConfig(Instance{
				Interface: "eth0", GroupID: 101, Priority: 200,
				Preempt: true, AdvertiseInterval: 10000,
			})
		}
	}
	t.Cleanup(func() { sendPacketDone = prevDone })

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(0)
	t.Cleanup(func() { advert.Stop() })
	time.Sleep(2 * time.Millisecond) // let advertTimer.C fire

	// Periodic step: sends the 100ms advert (10cs); the growth commits
	// mid-send; the trailing arm arms 10000ms locally.
	if stop := master.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on advert timer")
	}
	// Consume the queued config token. Post-fix this emits the
	// correction advert carrying 10000ms (1000cs); pre-fix it is silent.
	if stop := master.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}

	sent := drainAdverts15929(wire)
	if len(sent) != 2 {
		t.Fatalf("wire adverts = %v, want exactly [100ms advert, 10000ms correction]: "+
			"interval growth applied by the trailing arm was baselined into "+
			"silence, so a peer that learned 100ms stays on a ~0.34s horizon "+
			"while this MASTER is silent for 10s (dual-MASTER window)", sent)
	}
	if sent[0].cs != 10 || sent[1].cs != 1000 {
		t.Fatalf("wire adverts = %v cs, want [10 1000] (100ms then 10000ms correction)", sent)
	}

	// Two-instance leg: deliver the adverts the MASTER actually put on
	// the wire to the peer BACKUP, in order.
	peerMasterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { peerMasterDown.Stop() })
	peerHold := time.NewTimer(time.Hour)
	t.Cleanup(func() { peerHold.Stop() })
	for _, a := range sent {
		pkt := &VRRPPacket{
			VRID:         101,
			Priority:     uint8(a.priority),
			MaxAdvertInt: uint16(a.cs),
			SrcIP:        net.IPv4(10, 0, 0, 2),
		}
		peer.handleBackupRx(pkt, peerMasterDown, peerHold)
	}
	peer.mu.RLock()
	learned := peer.masterAdverInterval
	peer.mu.RUnlock()
	if learned != 10*time.Second {
		t.Fatalf("peer learned master interval = %v, want 10s: the correction advert never reached the peer's learned cadence, so its master-down horizon stays ~0.34s", learned)
	}
	// The peer must still be BACKUP with a horizon beyond the old
	// ~0.34s learned horizon (3*10s + skew at priority 150).
	if peer.getState() != StateBackup {
		t.Fatalf("peer state = %s, want BACKUP after correction advert", peer.getState())
	}
	if got := peer.masterDownInterval(); got <= time.Second {
		t.Fatalf("peer masterDownInterval = %v, want >1s after learning 10s cadence", got)
	}
}

// TestDecideMasterConfigAdvert_WireBaseline pins gap 1's decision unit:
// an arm-applied interval GROWTH corrects until the wire itself has
// carried the grown cadence; a shrink always corrects; a wire-matched
// growth stays silent. This is the deterministic counterpart of the
// two-instance harness above (whose integration leg exercises the same
// path through stepMaster).
func TestDecideMasterConfigAdvert_WireBaseline(t *testing.T) {
	change := func(oldMS, newMS, oldPrio, newPrio int) configChange15689 {
		return configChange15689{
			valid: true, oldAdvertiseMS: oldMS, newAdvertiseMS: newMS,
			oldEffectivePrio: oldPrio, newEffectivePrio: newPrio,
		}
	}
	cases := []struct {
		name   string
		change configChange15689
		wireMS int
		want   masterAdvertAction
	}{
		{"arm-applied growth, wire still short", change(10000, 10000, 200, 200), 100, masterAdvertSend},
		{"growth already on wire", change(10000, 10000, 200, 200), 10000, masterAdvertNone},
		{"growth arm-netted, no wire advert yet", change(10000, 10000, 200, 200), 0, masterAdvertSend},
		{"plain growth not yet armed", change(100, 10000, 200, 200), 100, masterAdvertSend},
		{"plain shrink sends", change(60000, 100, 200, 200), 40950, masterAdvertSend},
		{"shrink already announced on wire re-arms only", change(60000, 100, 200, 200), 100, masterAdvertRearm},
		{"change-then-revert netted, wire matches normalized", change(60000, 60000, 200, 200), 40950, masterAdvertNone},
		{"unchanged stays silent", change(1000, 1000, 200, 200), 1000, masterAdvertNone},
		{"priority delta sends", change(1000, 1000, 200, 100), 1000, masterAdvertSend},
		{"invalid record fails safe", configChange15689{}, 0, masterAdvertSend},
		// #15961 normalized-space cases: raw cfg vs normalized wire.
		{"tolerant 60000 with producible wire 40950 stays silent", change(60000, 60000, 200, 200), 40950, masterAdvertNone},
		{"inexact 15ms normalizes to wire 10ms", change(15, 15, 200, 200), 10, masterAdvertNone},
		{"raw values above ceiling equal after normalization", change(700000, 60000, 200, 200), 40950, masterAdvertNone},
	}
	for _, tc := range cases {
		if got := decideMasterConfigAdvert(tc.change, tc.wireMS); got != tc.want {
			t.Errorf("%s: decideMasterConfigAdvert(change=%+v, wire=%d) = %v, want %v", tc.name, tc.change, tc.wireMS, got, tc.want)
		}
	}
}

// TestVRRPMaster_Tolerant60000_GARPOnlyTokensStaySilent is the #15961
// GLM blocker regression, through the real stepMaster path: a MASTER
// at a tolerant AdvertiseInterval=60000 (admitted on tolerant load,
// capped to 40950ms/4095cs on the wire) must NOT emit a redundant
// correction advert + timer reset on every unrelated (GARP-only)
// config token. RED on the folded head that compared RAW cfg (60000)
// against the NORMALIZED wire record (40950): adverts [4095 4095
// 4095]. GREEN with normalized-space comparison: exactly the one
// periodic advert, timer untouched.
func TestVRRPMaster_Tolerant60000_GARPOnlyTokensStaySilent(t *testing.T) {
	vi := newMaster15689(t, 60000)
	adverts := captureAdverts15929(t)

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(0)
	t.Cleanup(func() { advert.Stop() })
	time.Sleep(2 * time.Millisecond)

	// Periodic step: one wire advert at the capped 4095cs cadence.
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on advert timer")
	}
	// The trailing arm set the 40950ms timer; Stop() must report it
	// still pending (it cannot have fired within this test).
	if !advert.Stop() {
		t.Fatal("advertTimer not pending after periodic step (already fired or drained)")
	}
	advert.Reset(40950 * time.Millisecond)
	for i := range 2 {
		vi.updateConfig(Instance{
			Interface: "eth0", GroupID: 101, Priority: 200,
			Preempt: true, AdvertiseInterval: 60000, GARPCount: 5 + i,
		})
		if stop := vi.stepMaster(masterDown, advert); stop {
			t.Fatal("stepMaster returned stop=true on GARP-only update")
		}
	}
	got := drainAdverts15929(adverts)
	if len(got) != 1 || got[0].cs != 4095 {
		t.Fatalf("wire adverts = %v, want exactly [{200 4095}]: a tolerant 60000ms cfg must not correct on every unrelated token (raw-vs-normalized comparison)", got)
	}
	// The timer armed by the periodic step (40950ms) must survive both
	// consumptions untouched: still pending, not drained/fired.
	if !advert.Stop() {
		select {
		case <-advert.C:
		default:
			t.Fatal("advertTimer disturbed by a GARP-only consumption at a wire-matched cadence")
		}
	}
}

// TestSendAdvert_FailedSendDoesNotAdvanceWireBaseline: a locally
// failed send must not record the cadence it never emitted (#15961
// Opus). With the wire baseline pinned at the old 100ms, a failed
// announce at 10000ms leaves wire!=new, so the MASTER consumer still
// sends the owed correction once sends recover. On the folded head
// the record advanced before the attempt and the consumer took the
// re-arm-only path — the correction was suppressed.
func TestSendAdvert_FailedSendDoesNotAdvanceWireBaseline(t *testing.T) {
	vi := newMaster15689(t, 100)
	vi.mu.Lock()
	vi.wireAdvertIntervalMS = 100 // last successful cadence
	vi.mu.Unlock()

	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, _ *VRRPPacket, _ bool) error {
		return errFakeSend15961
	}
	t.Cleanup(func() { sendPacketFn = prev })

	vi.mu.Lock()
	vi.cfg.AdvertiseInterval = 10000
	vi.mu.Unlock()
	vi.sendAdvert(200) // fails locally: must NOT advance the baseline

	vi.mu.RLock()
	wire := vi.wireAdvertIntervalMS
	seq := vi.sendSeq
	vi.mu.RUnlock()
	if wire != 100 || seq != 0 {
		t.Fatalf("after failed send: wire=%d seq=%d, want wire=100 seq=0 (a failed send claims nothing)", wire, seq)
	}
	// The consumer must still owe the growth correction.
	change := configChange15689{valid: true, oldAdvertiseMS: 10000, newAdvertiseMS: 10000, oldEffectivePrio: 200, newEffectivePrio: 200}
	if got := decideMasterConfigAdvert(change, wire); got != masterAdvertSend {
		t.Fatalf("decideMasterConfigAdvert after failed announce = %v, want masterAdvertSend", got)
	}
}

var errFakeSend15961 = errors.New("fake send failure")

// TestNoteAdvertPrioritySeq_StaleNoteDropped is the #15961 Codex #2
// ordering pin: a caller paused between send and note must not rewind
// the pending baseline past a newer send's basis. Promotion sends 100
// (seq snapshot S, then "pauses"); a VIP announce sends 200 and notes
// first (newer basis); promotion's late note(100) resumes and must be
// dropped, so the record keeps old==200 (the latest wire basis).
func TestNoteAdvertPrioritySeq_StaleNoteDropped(t *testing.T) {
	vi := newMaster15689(t, 1000)
	vi.mu.Lock()
	vi.pendingConfigChange = configChange15689{
		valid: true, oldAdvertiseMS: 1000, newAdvertiseMS: 1000,
		oldEffectivePrio: 200, newEffectivePrio: 200,
	}
	vi.sendSeq = 5 // five emitting sends already happened
	vi.mu.Unlock()

	promoSeq := vi.sendSeqNow() // promotion's snapshot: 5
	vi.mu.Lock()
	vi.sendSeq = 6 // the announce actually emitted (advances the count)
	vi.mu.Unlock()
	vi.noteAdvertPrioritySeq(vi.sendSeqNow(), 200) // announce notes first
	vi.noteAdvertPrioritySeq(promoSeq, 100)        // stale: must be dropped

	vi.mu.RLock()
	p := vi.pendingConfigChange
	vi.mu.RUnlock()
	if p.oldEffectivePrio != 200 {
		t.Fatalf("pending oldEffectivePrio = %d, want 200: the stale promotion note rewound the baseline past the newer announce", p.oldEffectivePrio)
	}
}

// --- Gap 2: priority-bearing sends that never baseline the pending ---
// --- priority record. ---

// TestUpdateVIPs_PriorityCoEditThenRevert_ConfigStillCorrects is the
// Codex Finding-B production sequence via the manager's ordering:
// commit A changes priority 200->100 together with a VIP-set change,
// updateVIPs' MASTER announce sends the 100 packet; before the queued
// token is consumed, commit B reverts priority to 200 with no VIP edit.
// Pre-fix the announce never called noteAdvertPriority, so the
// accumulated record netted 200->200 and stepMaster's consumer sent
// nothing: the peer retained the stale 100 until the next periodic
// advert. Post-fix the announce baselines oldEffectivePrio to the SENT
// 100, the record reads 100->200, and the consumer emits the correction
// — without falsely baselining the (unchanged) interval the announce
// did not re-arm.
func TestUpdateVIPs_PriorityCoEditThenRevert_ConfigStillCorrects(t *testing.T) {
	vi := newMaster15689(t, 1000)
	vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }
	adverts := captureAdverts15929(t)

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })

	// Commit A: priority 200->100 (VIP edit follows, as in manager.go).
	vi.updateConfig(Instance{
		Interface: "eth0", GroupID: 101, Priority: 100,
		Preempt: true, AdvertiseInterval: 1000,
	})
	if err := vi.updateVIPs([]string{"10.0.0.10/24", "10.0.0.11/24"}); err != nil {
		t.Fatalf("updateVIPs: %v", err)
	}
	announced := drainAdverts15929(adverts)
	if len(announced) != 1 || announced[0].priority != 100 {
		t.Fatalf("VIP announce adverts = %v, want exactly one priority-100 advert", announced)
	}

	// Commit B: revert priority to 200, no VIP edit, before consumption.
	vi.updateConfig(Instance{
		Interface: "eth0", GroupID: 101, Priority: 200,
		Preempt: true, AdvertiseInterval: 1000,
	})

	vi.mu.RLock()
	mid := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !mid.valid || mid.oldEffectivePrio != 100 || mid.newEffectivePrio != 200 {
		t.Fatalf("pending priority after VIP announce + revert = %d->%d (valid=%v), want 100->200: "+
			"the announce's priority-100 packet was never baselined, so the revert netted the record to no-change", mid.oldEffectivePrio, mid.newEffectivePrio, mid.valid)
	}

	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	got := drainAdverts15929(adverts)
	if len(got) != 1 || got[0].priority != 200 {
		t.Fatalf("correction adverts = %v, want exactly one priority-200 advert: the peer would otherwise retain stale priority 100", got)
	}
}

// TestBecomeMaster_PendingPriorityCommit_CorrectedByConsumer: promotion
// sends `pri` (instance_transition.go) without (pre-fix) baselining the
// pending record. A priority commit queued before a BACKUP->MASTER
// promotion, followed by a revert before the MASTER consumer runs,
// netted to no-change pre-fix and the consumer sent nothing — the
// promotion packet's priority was the last word until the periodic
// timer. Post-fix becomeMaster notes the priority it actually sent.
//
// The promotion is driven by calling becomeMaster directly (the
// transition the run loop invokes) so the config token does not race
// the masterDown/configUpdated select inside the test itself;
// becomeMaster's own send is the unit under test.
func TestBecomeMaster_PendingPriorityCommit_CorrectedByConsumer(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0)
	vi.mu.Lock()
	vi.cfg.AdvertiseInterval = 1000
	vi.cfg.VirtualAddresses = []string{"10.0.0.10/24"}
	vi.mu.Unlock()
	adverts := captureAdverts15929(t)

	// Commit A before promotion: priority 200->100.
	vi.updateConfig(Instance{
		Interface: "eth0", GroupID: 101, Priority: 100,
		Preempt: true, AdvertiseInterval: 1000,
	})

	// Promotion: becomeMaster sends the committed priority 100.
	if !vi.becomeMaster() {
		t.Fatal("becomeMaster returned false")
	}
	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER after promotion", vi.getState())
	}
	promo := drainAdverts15929(adverts)
	if len(promo) != 1 || promo[0].priority != 100 {
		t.Fatalf("promotion adverts = %v, want exactly one priority-100 advert", promo)
	}

	// Commit B: revert to 200 before the MASTER consumer runs.
	vi.updateConfig(Instance{
		Interface: "eth0", GroupID: 101, Priority: 200,
		Preempt: true, AdvertiseInterval: 1000,
	})
	vi.mu.RLock()
	mid := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !mid.valid || mid.oldEffectivePrio != 100 || mid.newEffectivePrio != 200 {
		t.Fatalf("pending priority after promotion + revert = %d->%d (valid=%v), want 100->200: "+
			"the promotion's priority-100 packet was never baselined", mid.oldEffectivePrio, mid.newEffectivePrio, mid.valid)
	}

	masterDown2 := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown2.Stop() })
	advert2 := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert2.Stop() })
	if stop := vi.stepMaster(masterDown2, advert2); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	got := drainAdverts15929(adverts)
	if len(got) != 1 || got[0].priority != 200 {
		t.Fatalf("correction adverts = %v, want exactly one priority-200 advert", got)
	}
}

// TestBecomeMaster_PendingPriorityCommit_NoRevert_NoCorrection is the
// negative control for the promotion note: the promotion advert already
// carried the committed (final) priority and nothing reverts, so the
// consumer must stay silent — baselining must not fabricate a spurious
// correction advert.
func TestBecomeMaster_PendingPriorityCommit_NoRevert_NoCorrection(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0)
	vi.mu.Lock()
	vi.cfg.AdvertiseInterval = 1000
	vi.cfg.VirtualAddresses = []string{"10.0.0.10/24"}
	vi.mu.Unlock()
	adverts := captureAdverts15929(t)

	vi.updateConfig(Instance{
		Interface: "eth0", GroupID: 101, Priority: 100,
		Preempt: true, AdvertiseInterval: 1000,
	})
	if !vi.becomeMaster() {
		t.Fatal("becomeMaster returned false")
	}
	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER", vi.getState())
	}
	_ = drainAdverts15929(adverts)

	masterDown2 := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown2.Stop() })
	advert2 := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert2.Stop() })
	if stop := vi.stepMaster(masterDown2, advert2); stop {
		t.Fatal("stepMaster returned stop=true")
	}
	if got := drainAdverts15929(adverts); len(got) != 0 {
		t.Fatalf("adverts = %v, want none: promotion already carried the final priority", got)
	}
}

// TestResignZeroBurst_DoesNotBaselineLivePriority: the forced-resign
// and shutdown priority-0 bursts put 0 on the wire AFTER the instance
// has published BACKUP (becomeBackup applied the stashed resign
// priority). Baselining that 0 into the pending record would fabricate
// a 0->live priority delta and a spurious correction advert in the new
// BACKUP tenure's consumer. This pins the current (correct) refusal to
// note the 0-burst, so a later "note every send" refactor cannot
// quietly break it.
func TestResignZeroBurst_DoesNotBaselineLivePriority(t *testing.T) {
	vi := newMaster15689(t, 100)
	adverts := captureAdverts15929(t)
	// Seed a LIVE pending record (GLM fold): without one,
	// noteAdvertPriority* no-ops on invalid records and the pin below
	// is vacuous — an erroneous note(0) on the burst would pass.
	vi.updateConfig(Instance{
		Interface: "eth0", GroupID: 101, Priority: 150,
		Preempt: true, AdvertiseInterval: 100,
	})
	vi.mu.RLock()
	seeded := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !seeded.valid || seeded.oldEffectivePrio != 200 || seeded.newEffectivePrio != 150 {
		t.Fatalf("seeded pending = %+v, want valid 200->150", seeded)
	}
	if !vi.beginResign() {
		t.Fatal("beginResign did not queue forced resignation")
	}
	vi.triggerResign()

	down := time.NewTimer(time.Hour)
	t.Cleanup(func() { down.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	// resignCh and configUpdatedCh are both queued; stepMaster may take
	// either first. Drive until BACKUP (the resign step ran), at most
	// a few steps.
	for range 4 {
		if vi.getState() == StateBackup {
			break
		}
		if stop := vi.stepMaster(down, advert); stop {
			t.Fatal("stepMaster returned stop=true during resign drive")
		}
	}
	got := drainAdverts15929(adverts)
	zeros := 0
	for _, a := range got {
		if a.priority == 0 {
			zeros++
		}
	}
	if zeros != 3 {
		t.Fatalf("priority-zero adverts = %d (all %v), want 3", zeros, got)
	}
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP after resign", vi.getState())
	}
	// The burst must not have baselined the live record to 0, and the
	// recorded pending delta must be exactly what the two updateConfig
	// calls left (200->150 from the seed; beginResign stashes, it does
	// not rewrite the record).
	vi.mu.RLock()
	p := vi.pendingConfigChange
	vi.mu.RUnlock()
	if p.valid && p.oldEffectivePrio == 0 {
		t.Fatalf("pending record baselined to the priority-0 resign burst (%+v): "+
			"a later 0->live delta would fabricate a correction advert", p)
	}
}

// --- Gap 3: hold-expiry select race. ---

// TestHoldExpiry_PendingHoldTimeGrowth_DoesNotPromote: the
// [INFERENCE] race from the ledger, made deterministic. The run loop is
// blocked until BOTH preemptHoldTimer.C (1s hold, armed) and
// configUpdatedCh (hold-time grown 1->60, token queued) are ready, and
// select picks the hold expiry first. Pre-fix the expiry case only
// re-ran shouldPreemptObservedMaster (preempt/priority/staleness) and
// promoted immediately against the still-live lower master — the 60s
// hold was never honoured. Post-fix the expiry re-checks the pending
// hold-time change BEFORE promoting and, on a change, defers to the
// config consumer's disarm/revalidation instead of promoting.
//
// Go's select picks pseudo-randomly among ready cases, so the test
// re-drives fresh instances until the expiry case wins (bounded tries);
// a win pre-fix yields MASTER (fail), a win post-fix must yield BACKUP
// with the hold disarmed and the pending record still queued for the
// consumer. If the config case wins first, the consumer disarms and no
// promotion occurs either — that is also a correct outcome, retried
// only to observe the expiry-first branch at least once.
func TestHoldExpiry_PendingHoldTimeGrowth_DoesNotPromote(t *testing.T) {
	expiryFirstSeen := false
	for attempt := 0; attempt < 64 && !expiryFirstSeen; attempt++ {
		vi := newHoldTestInstance(t, 200, 1)
		vi.mu.Lock()
		vi.lastMasterPriority = 100 // live lower-priority master
		vi.lastMasterSeen = time.Now()
		vi.mu.Unlock()

		masterDown := time.NewTimer(time.Hour)
		advert := time.NewTimer(time.Hour)
		preemptHold := time.NewTimer(0)
		time.Sleep(2 * time.Millisecond) // hold timer genuinely fired

		// Arm the bookkeeping exactly as armPreemptHold would have
		// (the test drives a synthetic fired timer, not the arm path).
		vi.mu.Lock()
		vi.preemptHoldArmed = true
		vi.preemptHoldArmedAt = time.Now().Add(-time.Second)
		vi.mu.Unlock()

		// Grow the hold-time 1->60; token coalesces pending. The peer
		// stays fresh so only the hold-time delta discriminates.
		vi.updateConfig(Instance{
			Interface: "eth0", GroupID: 101, Priority: 200,
			Preempt: true, PreemptHoldTime: 60, AdvertiseInterval: 30,
		})
		vi.mu.Lock()
		vi.lastMasterSeen = time.Now()
		vi.mu.Unlock()

		// Detect which case the select took: the config consumer
		// CONSUMES the pending record (takePendingConfigChange clears
		// it); the expiry case (fixed) defers with the record intact.
		vi.stepBackup(masterDown, advert, preemptHold)
		vi.mu.RLock()
		pendingIntact := vi.pendingConfigChange.valid
		armed := vi.preemptHoldArmed
		vi.mu.RUnlock()

		if vi.getState() == StateMaster {
			t.Fatalf("attempt %d: promoted to MASTER on hold expiry with a pending 1->60 hold-time growth (pendingIntact=%v armed=%v): "+
				"the hold-expiry case never rechecked PreemptHoldTime", attempt, pendingIntact, armed)
		}
		if pendingIntact {
			// Expiry-first branch taken and (post-fix) deferred
			// without promoting or consuming.
			expiryFirstSeen = true
			if armed {
				t.Fatal("hold still marked armed after expiry-first deferral")
			}
		}
		masterDown.Stop()
		advert.Stop()
		preemptHold.Stop()
		// If config-first won every time this instance is spent;
		// retry with a fresh one. The state must be BACKUP either way.
		if vi.getState() != StateBackup {
			t.Fatalf("state = %s, want BACKUP", vi.getState())
		}
	}
	if !expiryFirstSeen {
		t.Fatal("hold-expiry case never won the select in 64 tries; race branch unexercised")
	}
}
