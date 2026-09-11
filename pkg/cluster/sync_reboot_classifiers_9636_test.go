package cluster

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// #9636: a peer reboot has two classifiers. installConn retires the prior
// incarnation on a raised heartbeat boot EPOCH (#7762), and the BulkStart arm
// retires it on a changed boot ID (#6910). Each used to act on its own evidence
// without learning that the other had already retired the same reboot, so the
// one that ran second advanced the incarnation again and evicted the peer's
// healthy second fabric, and a boot-id-first reboot never reached
// OnPeerConnected.
//
// Every cell asserts the four things the issue names, per ordering: how many
// times the incarnation advanced, which connections are installed, whether a
// cold prime is owed (with the number of arms), and how many times
// OnPeerConnected was dispatched.
//
// The cells drive handleNewConnection and send every later frame on the
// connection it STORED. handleNewConnection wraps the socket, so a frame handed
// the raw socket never matches fabricIdxForConnLocked and silently skips the
// classification under test.

var (
	incA9636 = bootIncarnation{0xa9, 0x36, 0x0a}
	incB9636 = bootIncarnation{0xb9, 0x36, 0x0b}
)

type rebootEnv9636 struct {
	t          *testing.T
	s          *SessionSync
	src        *epochSource
	ctx        context.Context
	dispatches atomic.Int32
	names      map[net.Conn]string
	bulkEpoch  uint64
	inc0       uint64
	gen0       uint64
}

func newRebootEnv9636(t *testing.T) *rebootEnv9636 {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	e := &rebootEnv9636{t: t, s: s, src: &epochSource{epoch: 100, latched: true}, names: map[net.Conn]string{nil: "nothing"}}
	s.PeerBootEpochFn = e.src.fn
	s.OnPeerConnected = func() { e.dispatches.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx = ctx
	t.Cleanup(cancel)
	return e
}

// connect runs the production handleNewConnection for a new peer socket on
// fabric idx and returns the connection it stored.
func (e *rebootEnv9636) connect(idx int, name string) net.Conn {
	e.t.Helper()
	raw := newBulkCaptureConn()
	e.t.Cleanup(func() { raw.Close() })
	e.s.handleNewConnection(e.ctx, idx, raw, true)
	e.s.mu.Lock()
	stored := e.s.conn0
	if idx == 1 {
		stored = e.s.conn1
	}
	e.s.mu.Unlock()
	if ac, ok := stored.(*authConn); !ok || ac.Conn != raw {
		e.t.Fatalf("setup: fabric %d does not hold the connection handleNewConnection was given", idx)
	}
	e.names[stored] = name
	return stored
}

// prime delivers a BulkStart carrying inc on conn. Bulk epochs only increase, so
// no prime is refused as a stale restart of the previous bulk.
func (e *rebootEnv9636) prime(conn net.Conn, inc bootIncarnation) {
	e.bulkEpoch++
	e.s.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(e.bulkEpoch, &inc))
}

// settleDispatches returns the OnPeerConnected count once it has stopped
// moving. Every dispatch under test is spawned before this is called; the
// callback runs on its own goroutine.
func (e *rebootEnv9636) settleDispatches() int32 {
	last := e.dispatches.Load()
	stable := time.Now()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		if n := e.dispatches.Load(); n != last {
			last, stable = n, time.Now()
		}
		if time.Since(stable) >= 250*time.Millisecond {
			break
		}
	}
	return last
}

// primedA is an established pair: peer boot A connected on fabric idx and
// primed with its boot id. With acked, the cold prime A was owed has been
// acknowledged; without it, A died with that debt outstanding. Every count a
// cell asserts starts from here.
func (e *rebootEnv9636) primedA(idx int, acked bool) net.Conn {
	e.t.Helper()
	a := e.connect(idx, "A (the corpse)")
	e.prime(a, incA9636)
	if acked {
		e.s.dischargeColdPrime(e.s.coldPrimeOwedGen())
		e.s.outboundBulkAcked.Store(true)
	}
	if n := e.settleDispatches(); n != 1 {
		e.t.Fatalf("setup: the first connection dispatched OnPeerConnected %d times, want 1", n)
	}
	e.dispatches.Store(0)
	e.s.mu.Lock()
	e.inc0 = e.s.peerIncarnation
	e.s.mu.Unlock()
	e.gen0 = e.s.coldPrimeGen.Load()
	return a
}

type rebootWant9636 struct {
	advances   uint64
	conn0      net.Conn
	conn1      net.Conn
	owed       bool
	arms       uint64
	dispatches int32
}

func (e *rebootEnv9636) check(w rebootWant9636) {
	e.t.Helper()
	n := e.settleDispatches()
	e.s.mu.Lock()
	inc, c0, c1 := e.s.peerIncarnation, e.s.conn0, e.s.conn1
	e.s.mu.Unlock()
	if got := inc - e.inc0; got != w.advances {
		e.t.Errorf("the peer incarnation advanced %d times, want %d", got, w.advances)
	}
	if c0 != w.conn0 {
		e.t.Errorf("fabric 0 holds %s, want %s", e.names[c0], e.names[w.conn0])
	}
	if c1 != w.conn1 {
		e.t.Errorf("fabric 1 holds %s, want %s", e.names[c1], e.names[w.conn1])
	}
	if got := e.s.needColdPrime.Load(); got != w.owed {
		e.t.Errorf("needColdPrime = %v, want %v", got, w.owed)
	}
	if got := e.s.coldPrimeGen.Load() - e.gen0; got != w.arms {
		e.t.Errorf("the cold prime was armed %d times, want %d", got, w.arms)
	}
	if n != w.dispatches {
		e.t.Errorf("OnPeerConnected was dispatched %d times, want %d", n, w.dispatches)
	}
}

// Boot-id first: the replacement dials the empty alternate slot before its
// heartbeat raised the epoch, so installConn has nothing to classify, and the
// BulkStart switch is the only classifier that sees the reboot. It retires the
// incarnation and must also announce the new peer process.
func TestBootIDFirstRebootIsRetiredAndAnnounced_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	b1 := e.connect(1, "B's fabric 1")
	e.prime(b1, incB9636)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Epoch first, then BulkStart: installConn retires A on the raised epoch and
// announces B. B's BulkStart then reports the same reboot by its boot id, and
// must not retire it a second time or arm again.
func TestEpochFirstRebootIsNotRetiredAgainByItsBulkStart_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	e.src.epoch = 101
	b1 := e.connect(1, "B's fabric 1")
	e.prime(b1, incB9636)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Epoch first, then B's second fabric, then BulkStart: the issue's executed
// failure. A second advance on the boot id left B's fabric 0 one incarnation
// behind, and evictStaleIncarnationConnsLocked dropped it as a corpse.
//
// Two dispatches is the existing #4962 behaviour: fabric 0 is preferred, so its
// install is the active one while the cold prime is still owed, and it drives
// the owed prime again. Neither dispatch comes from the BulkStart.
func TestEpochFirstRebootKeepsTheSiblingThatInstalledBeforeBulkStart_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	e.src.epoch = 101
	b1 := e.connect(1, "B's fabric 1")
	b0 := e.connect(0, "B's fabric 0")
	e.prime(b1, incB9636)
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 2})
}

// The corpse leaves on its own after the replacement installed. The switch that
// finally sees the reboot evicts nothing, and must still arm and announce.
func TestBootIDRebootAfterTheCorpseLeftIsStillAnnounced_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	a := e.primedA(0, true)
	b1 := e.connect(1, "B's fabric 1")
	e.s.handleDisconnect(a)
	e.prime(b1, incB9636)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Control: the same boot bringing up its second fabric and priming on it.
func TestSameBootSecondFabricIsNotAReboot_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	a0 := e.primedA(0, true)
	a1 := e.connect(1, "A's fabric 1")
	e.prime(a1, incA9636)
	e.check(rebootWant9636{conn0: a0, conn1: a1})
}

// Control: zero -> X is the first incarnated prime, not a reboot. The one arm
// and the one dispatch are the first connection's.
func TestFirstIncarnatedPrimeIsNotAReboot_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	a0 := e.connect(0, "A's fabric 0")
	e.prime(a0, incA9636)
	e.check(rebootWant9636{conn0: a0, owed: true, arms: 1, dispatches: 1})
}

// The mirror of the executed failure. The boot id retires A first; B's
// heartbeat lands only afterwards, and B's second fabric is the first install
// to observe the raised epoch. That raise belongs to the reboot the switch
// already retired, so it must not advance again and evict the fabric B primed
// on.
func TestBootIDFirstRebootKeepsTheSiblingThatInstalledAfterTheEpochLanded_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	b1 := e.connect(1, "B's fabric 1")
	e.prime(b1, incB9636)
	e.src.epoch = 101
	b0 := e.connect(0, "B's fabric 0")
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 2})
}

// A daemon restart raises the epoch and KEEPS the boot id (the boot id changes
// only on an OS boot). The restarted process primes with the same boot id,
// which settles the epoch retirement: there was no boot-id change to come. A
// later OS reboot seen only by its boot id is a new reboot and must be retired.
func TestDaemonRestartDoesNotSwallowALaterBootIDReboot_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	e.src.epoch = 101
	a1 := e.connect(1, "A restarted, fabric 1")
	e.prime(a1, incA9636)
	e.s.dischargeColdPrime(e.s.coldPrimeOwedGen())
	b0 := e.connect(0, "B's fabric 0")
	e.prime(b0, incB9636)
	e.check(rebootWant9636{advances: 2, conn0: b0, owed: true, arms: 2, dispatches: 2})
}

// An epoch retirement is still waiting for its boot id (the restarted process
// never primed) when the peer reboots again. The new boot's heartbeat raises the
// epoch after its install and before its BulkStart. The boot-id change is then
// evidence of a NEW reboot, not of the one already retired.
func TestEpochRaisedAgainMeansTheBootIDChangeIsANewReboot_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	e.src.epoch = 101
	e.connect(1, "A restarted, fabric 1")
	b0 := e.connect(0, "B's fabric 0")
	e.src.epoch = 102
	e.prime(b0, incB9636)
	e.check(rebootWant9636{advances: 2, conn0: b0, owed: true, arms: 2, dispatches: 2})
}

// A died with its cold prime unacknowledged, so the replacement's own install on
// the preferred fabric drove the owed prime and dispatched OnPeerConnected for
// it. The switch that then retires A must not dispatch a second time for the
// same connection: the callback is not idempotent.
func TestSwitchDoesNotAnnounceAConnectionItsInstallAlreadyAnnounced_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(1, false)
	b0 := e.connect(0, "B's fabric 0")
	e.prime(b0, incB9636)
	e.check(rebootWant9636{advances: 1, conn0: b0, owed: true, arms: 1, dispatches: 1})
}

// The evicted corpse can still deliver a BulkStart it had already read, carrying
// the OLD boot id. That is not the new process priming with an unchanged boot
// id, and must not settle the epoch retirement, or B's own BulkStart is
// retired a second time and evicts B's second fabric.
func TestEvictedCorpsesPrimeDoesNotSettleTheRetirement_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	a := e.primedA(0, true)
	e.src.epoch = 101
	b1 := e.connect(1, "B's fabric 1")
	e.prime(a, incA9636)
	b0 := e.connect(0, "B's fabric 0")
	e.prime(b1, incB9636)
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 2})
}

// The common shape: A's sockets are gone before the replacement connects, so B
// installs into an empty registry. That install announces B and owes the cold
// prime. The BulkStart that then retires A must not announce the same connection
// again. Its second arm is the pre-existing full-disconnect-plus-switch cost: one
// redundant, idempotent bulk.
func TestRebootAfterAFullDisconnectIsAnnouncedOnce_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	a := e.primedA(0, true)
	e.s.handleDisconnect(a)
	b1 := e.connect(1, "B's fabric 1")
	e.prime(b1, incB9636)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 2, dispatches: 1})
}

// A boot-id switch that already sees the raised epoch accounts for it, so it
// leaves nothing for installConn to consume. A later daemon restart of B raises
// the epoch again, and its install must retire B's stale fabric.
func TestBootIDSwitchThatSawTheEpochLeavesNothingToConsume_9636(t *testing.T) {
	e := newRebootEnv9636(t)
	e.primedA(0, true)
	b1 := e.connect(1, "B's fabric 1")
	e.src.epoch = 101
	e.prime(b1, incB9636)
	e.src.epoch = 102
	b0 := e.connect(0, "B restarted, fabric 0")
	e.check(rebootWant9636{advances: 2, conn0: b0, owed: true, arms: 2, dispatches: 2})
}
