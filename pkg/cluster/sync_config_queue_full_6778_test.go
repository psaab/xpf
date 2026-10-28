package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// #6778 — a full config-apply queue strands the NEWEST generation.
//
// The non-blocking enqueue in handleConfigPayload discards the INCOMING
// payload, which is the newest generation the peer has sent, while the queue
// retains older ones. recordRecvConfigGen has already raised the received
// high-water for it, so the node reads config-stale (and #5563 refuses
// manual-failover promotion) with nothing driving the missing generation back:
// the sender's #5863 (epoch x generation) marker was claimed before the push
// and only a nack clears it. That is a wedge, not a blip.
//
// These tests pin the three halves of the repair on the DROP path:
//   - the drop is COUNTED on its own counter and rendered in cluster status,
//   - it accrues HEALTH DEBT (the #6387 grace timer), and that debt is not
//     cancelled by the apply of an older generation still in the queue, and
//   - it NACKS, re-arming the sender's push marker so the existing periodic
//     reconcile re-pushes.

// fillConfigApplyQueue6778 saturates the ordered apply queue with placeholder
// items so the next enqueue must take the non-blocking send's default arm. No
// consumer is running, so the queue stays full for the duration of the test.
func fillConfigApplyQueue6778(t *testing.T, s *SessionSync) {
	t.Helper()
	for i := 0; i < cap(s.configApplyCh); i++ {
		select {
		case s.configApplyCh <- configApplyItem{gen: uint64(i + 1), text: "backlog"}:
		default:
			t.Fatalf("setup: could not fill the apply queue, stalled at %d of %d", i, cap(s.configApplyCh))
		}
	}
	if len(s.configApplyCh) != cap(s.configApplyCh) {
		t.Fatalf("setup: queue must be full, got len=%d cap=%d", len(s.configApplyCh), cap(s.configApplyCh))
	}
}

// readOneFrame6778 reads a single length-prefixed sync frame off peer, or
// reports ok=false if none arrives before the deadline.
func readOneFrame6778(peer net.Conn, timeout time.Duration) (typ uint8, gen uint64, ok bool) {
	type frame struct {
		typ uint8
		gen uint64
		ok  bool
	}
	got := make(chan frame, 1)
	go func() {
		hdr := make([]byte, 12)
		if _, err := io.ReadFull(peer, hdr); err != nil {
			got <- frame{}
			return
		}
		length := binary.LittleEndian.Uint32(hdr[8:12])
		body := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(peer, body); err != nil {
				got <- frame{}
				return
			}
		}
		f := frame{typ: hdr[4], ok: true}
		if len(body) >= 8 {
			f.gen = binary.LittleEndian.Uint64(body[:8])
		}
		got <- f
	}()
	select {
	case f := <-got:
		return f.typ, f.gen, f.ok
	case <-time.After(timeout):
		return 0, 0, false
	}
}

// TestConfigQueueFullDropCountsNacksAndArmsDebt6778 binds the production
// WIRING at the drop site, not the functions it calls.
//
// It drives a real config payload through handleMessage into a SATURATED
// queue over a real connection and asserts all three repairs at once, plus the
// pre-existing property the repair must not disturb (the received high-water is
// still raised, so the node honestly reads config-stale).
//
// The fixture is the smallest shape where removing any one of the three lines
// changes an OUTCOME: the queue must be full (otherwise the enqueue succeeds
// and the default arm is never entered), and a connection must be installed
// (otherwise sendConfigApplyNack returns before writing and the nack assertion
// could not distinguish "not called" from "no peer").
//
// FAIL-ON-REVERT, one line each:
//   - delete s.stats.ConfigsQueueFullDropped.Add(1)   -> the counter leg reds
//   - delete s.noteConfigApplyFailure(...)            -> the armed-timer leg reds
//   - delete s.sendConfigApplyNack(gen)               -> the nack leg reds on the deadline
//   - delete s.recordRecvConfigGen(gen) above the enqueue -> the config-stale leg reds
func TestConfigQueueFullDropCountsNacksAndArmsDebt6778(t *testing.T) {
	const droppedGen = 9_001

	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	af := &fakeAfterFunc{}
	s.afterFuncFn = af.schedule

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	s.mu.Lock()
	s.conn0 = local
	s.stats.Connected.Store(true)
	s.mu.Unlock()

	fillConfigApplyQueue6778(t, s)

	// Deliver the newest generation through the REAL receive-side entry point.
	// The read must be concurrent with the delivery: net.Pipe is unbuffered, so
	// the nack write inside handleMessage blocks until the peer reads it.
	frames := make(chan [3]uint64, 1)
	go func() {
		typ, gen, ok := readOneFrame6778(peer, 2*time.Second)
		okv := uint64(0)
		if ok {
			okv = 1
		}
		frames <- [3]uint64{uint64(typ), gen, okv}
	}()
	s.handleMessage(local, syncMsgConfig, encodeConfigPayload("newest-config", droppedGen))

	// (1) Counted on its OWN counter. ConfigsApplyFailed must stay at zero —
	// the apply never ran, and folding the two together would tell an operator
	// to go read a compile error that does not exist.
	if got := s.stats.ConfigsQueueFullDropped.Load(); got != 1 {
		t.Fatalf("a queue-full drop must be counted on ConfigsQueueFullDropped; got %d", got)
	}
	if got := s.stats.ConfigsApplyFailed.Load(); got != 0 {
		t.Fatalf("a queue-full drop is not an apply failure — the apply never ran; "+
			"ConfigsApplyFailed=%d", got)
	}

	// (2) The received high-water is still raised, so the node reads
	// config-stale rather than silently healthy on a superseded config.
	if got := s.lastRecvConfigGen.Load(); got != droppedGen {
		t.Fatalf("the received high-water must be raised for a dropped generation so the node "+
			"reads config-stale (#5563); got %d want %d", got, droppedGen)
	}
	snap := TransferReadinessSnapshot{
		PeerConfigGen:    s.lastRecvConfigGen.Load(),
		AppliedConfigGen: s.lastAppliedConfigGen.Load(),
	}
	if !snap.ConfigStale() {
		t.Fatal("a node that dropped the newest generation must report config-stale")
	}

	// (3) Health debt armed: the #6387 grace timer starts on this edge, so a
	// drop that never re-converges raises CF with no further delivery.
	if calls, d := af.armed(); calls != 1 || d != DefaultConfigApplyFailGrace {
		t.Fatalf("a queue-full drop must arm the config-apply grace timer exactly once with the "+
			"grace; got calls=%d d=%s", calls, d)
	}

	// (4) The sender is told, which is the ONLY thing that re-arms its #5863
	// push marker on a live connection.
	select {
	case f := <-frames:
		if f[2] != 1 {
			t.Fatal("a queue-full drop must send a config-apply nack — without it the sender's " +
				"#5863 marker suppresses every re-push of the dropped generation and the " +
				"standby stays behind the primary indefinitely (#6778)")
		}
		if uint8(f[0]) != syncMsgConfigApplyNack {
			t.Fatalf("expected a config-apply nack frame, got message type %d", f[0])
		}
		if f[1] != droppedGen {
			t.Fatalf("the nack must name the DROPPED generation so the sender's scope guard "+
				"matches it against the current config debt snapshot; got %d want %d", f[1], droppedGen)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no frame observed after a queue-full drop")
	}
}

// TestConfigEnqueueSuccessIsSilent6778 is the TIGHTENING control for the test
// above: it makes the code MORE aggressive than shipped rather than deleting a
// line.
//
// Hoisting any of the three drop-path calls out of the `default:` arm so it
// fires on every received config would count a drop that did not happen, arm
// health debt on a healthy node, and — worst — nack every successful push,
// re-arming the sender's marker on each one and reintroducing exactly the push
// storm #5863 exists to prevent. With room in the queue, none of the three may
// fire.
func TestConfigEnqueueSuccessIsSilent6778(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	af := &fakeAfterFunc{}
	s.afterFuncFn = af.schedule

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	s.mu.Lock()
	s.conn0 = local
	s.stats.Connected.Store(true)
	s.mu.Unlock()

	frames := make(chan bool, 1)
	go func() {
		_, _, ok := readOneFrame6778(peer, 750*time.Millisecond)
		frames <- ok
	}()

	// Queue deliberately NOT filled: the enqueue succeeds.
	s.handleMessage(local, syncMsgConfig, encodeConfigPayload("accepted-config", 4_242))

	if len(s.configApplyCh) != 1 {
		t.Fatalf("setup: the payload must have been enqueued; queue len=%d", len(s.configApplyCh))
	}
	if got := s.stats.ConfigsQueueFullDropped.Load(); got != 0 {
		t.Fatalf("an ACCEPTED config must not count a queue-full drop; got %d", got)
	}
	if calls, _ := af.armed(); calls != 0 {
		t.Fatalf("an ACCEPTED config must not arm config-apply health debt; armed %d times", calls)
	}
	if <-frames {
		t.Fatal("an ACCEPTED config must send NO nack — a nack on the success path re-arms the " +
			"sender's #5863 marker on every push and reintroduces the push storm")
	}
}

// TestQueueFullDebtSurvivesStaleBacklogApply6778 pins the #6778 narrowing of
// noteConfigApplySuccess: the health debt raised by a dropped generation must
// not be cancelled by the apply of an OLDER generation that was already sitting
// in the queue when the drop happened.
//
// This is the interaction the lone-drop fixture cannot see. A queue only fills
// because the consumer is behind, so the drop is ALWAYS followed within
// milliseconds by successful applies of the backlog. Under the pre-#6778
// unconditional clear those successes disarmed the grace timer, and the drop's
// debt evaporated long before the grace could raise CF — leaving a standby
// behind the primary with the health signal silent.
//
// It drives the REAL configApplyLoop, so it binds the `noteConfigApplySuccess(item.gen)`
// wiring and not just the function.
//
// FAIL-ON-REVERT:
//   - drop the `appliedGen < s.lastRecvConfigGen.Load()` gate (restore the
//     unconditional clear) -> the stale-backlog leg reds.
//   - pass a constant (e.g. 0) instead of item.gen at the call site -> the
//     caught-up leg reds, because the debt would never clear again.
func TestQueueFullDebtSurvivesStaleBacklogApply6778(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	af := &fakeAfterFunc{}
	s.afterFuncFn = af.schedule
	s.OnConfigReceived = func(string) error { return nil }

	// The peer's newest generation is 20; it was dropped at the receive edge,
	// so the received high-water sits at 20 and the debt is armed.
	s.recordRecvConfigGen(20)
	s.noteConfigApplyFailure(errConfigApplyQueueFull)
	if calls, _ := af.armed(); calls != 1 {
		t.Fatalf("setup: the drop must arm the grace timer once; armed %d times", calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// Gen 19 was already queued when 20 was dropped. It applies cleanly — and
	// must NOT clear the debt, because the node is still behind gen 20.
	s.configApplyCh <- configApplyItem{gen: 19, text: "backlog-19"}
	drainConfigApply(t, s)
	if got := s.lastAppliedConfigGen.Load(); got != 19 {
		t.Fatalf("setup: gen 19 must apply; high-water=%d", got)
	}
	s.configApplyMu.Lock()
	stillArmed := s.firstUnappliedFailNano != 0
	reason := s.configApplyFailReason
	s.configApplyMu.Unlock()
	if !stillArmed {
		t.Fatal("applying an OLDER queued generation must NOT clear the debt for the NEWER " +
			"generation the queue-full drop lost — the node is still behind the primary, and " +
			"disarming here is what let a stranded standby look healthy (#6778)")
	}
	if !strings.Contains(reason, "queue full") {
		t.Fatalf("the debt must retain the queue-full reason; got %q", reason)
	}

	// The re-push lands as a newer generation and the node catches up: NOW the
	// debt clears.
	s.configApplyCh <- configApplyItem{gen: 21, text: "re-pushed"}
	drainConfigApply(t, s)
	if got := s.lastAppliedConfigGen.Load(); got != 21 {
		t.Fatalf("gen 21 must apply; high-water=%d", got)
	}
	s.configApplyMu.Lock()
	cleared := s.firstUnappliedFailNano == 0
	s.configApplyMu.Unlock()
	if !cleared {
		t.Fatal("once the applied generation catches up with the received high-water the debt " +
			"must clear — a gate that never releases would pin CF raised forever")
	}
}

// TestQueueFullDebtRaisesHealthWithoutRedelivery6778 completes the debt half:
// a drop that never re-converges must raise the CF config-sync health
// annotation on the grace timer alone, with no second delivery. The sender
// pushes a generation at most once per connection/generation, so a drop on a
// STABLE connection whose nack was not actionable (a pre-#7328 peer, or a nack
// superseded by a newer push) gets no re-delivery edge at all.
func TestQueueFullDebtRaisesHealthWithoutRedelivery6778(t *testing.T) {
	const grace = 5 * time.Second
	clk := &healthClk{}
	clk.set(1_000_000_000)
	af := &fakeAfterFunc{}

	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	flushClusterEvents(m)

	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	s.nowMonoFn = clk.now
	s.configApplyFailGrace = grace
	s.afterFuncFn = af.schedule
	s.OnConfigApplyHealth = func(failing bool, reason string) { m.SetConfigSyncHealth(failing, reason) }

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	s.mu.Lock()
	s.conn0 = local
	s.stats.Connected.Store(true)
	s.mu.Unlock()
	go func() {
		// Drain whatever the drop path writes so the unbuffered pipe never
		// blocks the delivery under test.
		buf := make([]byte, 256)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()

	fillConfigApplyQueue6778(t, s)
	s.handleMessage(local, syncMsgConfig, encodeConfigPayload("newest-config", 9_100))

	if mgrConfigSyncFailing(m) {
		t.Fatal("CF must not raise before the grace elapses — a transient saturation that " +
			"re-converges must never flap the flag")
	}
	clk.advance(grace + time.Second)
	af.fire()
	if !mgrConfigSyncFailing(m) {
		t.Fatal("a queue-full drop that never re-converges must raise the config-sync health " +
			"annotation once the grace elapses, with no second delivery (#6778)")
	}
	info := m.FormatInformation()
	if !strings.Contains(info, "Config sync: failing") {
		t.Fatalf("the raised health must render for the operator:\n%s", info)
	}
}

// TestQueueFullDropRendersInStatus6778 binds the operator-visible half in both
// directions. A counter that is only ever asserted nonzero cannot tell a
// missing render from a working one, so the zero case is asserted too: the line
// must be ABSENT on a healthy node and PRESENT once a drop has happened.
func TestQueueFullDropRendersInStatus6778(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	m.SetSyncStats(s)

	const dropLine = "Configs queue-full-dropped:"
	const nackLine = "Config apply-nacks received:"

	if info := m.FormatInformation(); strings.Contains(info, dropLine) {
		t.Fatalf("a node that has dropped nothing must not render %q:\n%s", dropLine, info)
	}
	if info := m.FormatInformation(); strings.Contains(info, nackLine) {
		t.Fatalf("a node that has received no nacks must not render %q:\n%s", nackLine, info)
	}

	s.stats.ConfigsQueueFullDropped.Add(3)
	s.stats.ConfigApplyNacksReceived.Add(2)
	info := m.FormatInformation()
	if !strings.Contains(info, dropLine+" 3") {
		t.Fatalf("a queue-full drop must be operator-visible in cluster status:\n%s", info)
	}
	if !strings.Contains(info, nackLine+" 2") {
		t.Fatalf("the sender-side half of the recovery loop must be operator-visible — a peer "+
			"whose drops climb while nacks stay at zero has no working re-push driver:\n%s", info)
	}
}

// TestQueueFullDropReasonIsDistinctFromApplyFailure6778 pins that the health
// debt carries a reason an operator can act on. An apply failure points at the
// config or the store; a queue-full drop points at a saturated receive path.
// Both raise the same annotation, so the reason string is the only thing that
// separates them.
func TestQueueFullDropReasonIsDistinctFromApplyFailure6778(t *testing.T) {
	if errConfigApplyQueueFull == nil {
		t.Fatal("the queue-full health-debt reason must exist")
	}
	got := errConfigApplyQueueFull.Error()
	if !strings.Contains(got, "queue full") {
		t.Fatalf("the queue-full reason must name the saturated queue; got %q", got)
	}
	other := errors.New("host-inbound apply failed: dependency missing")
	if got == other.Error() {
		t.Fatal("the queue-full reason must be distinguishable from an apply-failure reason")
	}
}
