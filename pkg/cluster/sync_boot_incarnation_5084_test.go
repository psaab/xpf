package cluster

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	incA = bootIncarnation{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}
	incB = bootIncarnation{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf}
)

// bulkStartPayload builds a BulkStart body: the 8-byte epoch, plus the 16-byte
// incarnation when one is given. The no-incarnation form is byte-identical to
// what a pre-#5084 sender emits.
func bulkStartPayload(epoch uint64, inc *bootIncarnation) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, epoch)
	if inc != nil {
		buf = append(buf, inc[:]...)
	}
	return buf
}

// incEnv drives the real receive and apply paths over installed connections.
//
// The apply handler can be made to BLOCK for exactly one payload (holdNext), so
// a test can leave a second payload sitting in configApplyCh across a re-prime.
// That is the shape #5084 is about — "resetRecvGen does not drain items already
// queued from the prior boot" — and it is reproduced here without reaching into
// any connection's incarnation stamp by hand: every payload is stamped by the
// production enqueue from the connection that carried it.
type incEnv struct {
	s       *SessionSync
	conns   []*authConn
	applied chan string
	entered chan string

	mu   sync.Mutex
	hold chan struct{}
}

func newIncEnv(t *testing.T, fabrics int) *incEnv {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	// Bulk completion now requires an authoritative snapshot; an explicit empty
	// map is a valid all-unmapped snapshot for these session-free fixtures.
	s.SetZoneRGMap(map[uint16]int{})
	e := &incEnv{s: s, applied: make(chan string, 16), entered: make(chan string, 16)}
	s.OnConfigReceived = func(text string) error {
		e.mu.Lock()
		h := e.hold
		e.hold = nil
		e.mu.Unlock()
		if h != nil {
			// Announce that this payload cleared EVERY gate and is now inside
			// the apply. Without this the test could push the next payload
			// while the loop had merely dequeued this one and not yet run the
			// incarnation check — a fixture race, not a production one.
			e.entered <- text
			<-h
		}
		e.applied <- text
		return nil
	}
	for i := 0; i < fabrics; i++ {
		local, remote := net.Pipe()
		t.Cleanup(func() { local.Close(); remote.Close() })
		ac := &authConn{Conn: local}
		s.mu.Lock()
		if i == 0 {
			s.conn0 = ac
		} else {
			s.conn1 = ac
		}
		s.mu.Unlock()
		e.conns = append(e.conns, ac)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.configApplyLoop(ctx)
	return e
}

// holdNext makes the NEXT apply block until the returned channel is closed.
func (e *incEnv) holdNext() chan struct{} {
	h := make(chan struct{})
	e.mu.Lock()
	e.hold = h
	e.mu.Unlock()
	return h
}

// waitEntered blocks until the held payload is INSIDE OnConfigReceived, so the
// apply loop is provably occupied and anything pushed next stays queued.
func (e *incEnv) waitEntered(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-e.entered:
		if got != want {
			t.Fatalf("setup: apply loop entered with %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("setup: the apply loop never entered the handler for %q", want)
	}
}

func (e *incEnv) prime(idx int, epoch uint64, inc *bootIncarnation) {
	e.s.handleMessage(e.conns[idx], syncMsgBulkStart, bulkStartPayload(epoch, inc))
}

func (e *incEnv) pushConfig(idx int, text string, gen uint64) {
	e.s.handleMessage(e.conns[idx], syncMsgConfig, encodeConfigPayload(text, gen))
}

// waitApplied returns the next applied config text, or "" if none arrives.
func (e *incEnv) waitApplied(d time.Duration) string {
	select {
	case text := <-e.applied:
		return text
	case <-time.After(d):
		return ""
	}
}

// waitQueued asserts that n payloads are sitting in configApplyCh. It is only
// meaningful once waitEntered has proved the apply loop is blocked inside the
// handler, which is what makes the count stable.
func (e *incEnv) waitQueued(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(e.s.configApplyCh) == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("setup: %d payload(s) never reached the apply queue (len=%d)", n, len(e.s.configApplyCh))
}

// TestQueuedPriorIncarnationConfigNeverApplies5084 is the binder the plan's §8
// names first: it must RED as an ASSERTION when the incarnation comparison is
// removed, showing a prior-incarnation config applying.
//
// It is the reported defect end to end, driven entirely through production
// paths:
//
//  1. Boot A primes and a config applies (gen 5). The apply is HELD inside
//     OnConfigReceived, so the apply loop is busy.
//  2. Boot A pushes a second config at a LARGE generation — its
//     monotonic-seeded counter has been climbing all boot. It sits in
//     configApplyCh, stamped by the production enqueue with boot A.
//  3. The peer REBOOTS and re-primes as boot B. resetRecvGen zeroes the
//     generation high-waters — and does NOT drain the queue. That undrained
//     item is the whole issue.
//  4. The held apply is released. The queued boot-A payload reaches the front.
//
// Before the fence it applied and recorded its large generation as the
// high-water, after which boot B's LOWER-generation current config was refused
// as stale — permanently, because the mark is monotone-max. Both halves are
// asserted: the stale payload must not apply, AND boot B's current config must.
func TestQueuedPriorIncarnationConfigNeverApplies5084(t *testing.T) {
	e := newIncEnv(t, 1)

	// (1) Boot A primes and applies a config; the apply blocks in the handler.
	e.prime(0, 1, &incA)
	hold := e.holdNext()
	e.pushConfig(0, "config-from-boot-A", 5)
	e.waitEntered(t, "config-from-boot-A")

	// (2) A second boot-A config queues behind it at a large generation.
	e.pushConfig(0, "stale-from-boot-A", 9_000_001)
	e.waitQueued(t, 1)

	// (3) The peer reboots and re-primes. The queue is NOT drained.
	e.prime(0, 2, &incB)

	// (4) Release.
	close(hold)
	if got := e.waitApplied(3 * time.Second); got != "config-from-boot-A" {
		t.Fatalf("setup: boot A's first config must apply normally; got %q", got)
	}
	if got := e.waitApplied(1500 * time.Millisecond); got != "" {
		t.Fatalf("a config QUEUED from a REPLACED peer boot incarnation must never apply; it "+
			"applied as %q. Applying it records a high-water drawn from a dead incarnation, "+
			"after which the rebooted peer's lower-generation CURRENT config is refused as "+
			"stale permanently — the #5084 divergence", got)
	}
	if n := e.s.stats.ConfigsDeadIncarnationDropped.Load(); n != 1 {
		t.Fatalf("the drop must be counted (a fail-open fence is silent by construction); got %d", n)
	}

	// And the point of the whole fix: boot B's own config, at a generation far
	// LOWER than boot A ever reached, still applies.
	e.pushConfig(0, "current-from-boot-B", 42)
	if got := e.waitApplied(3 * time.Second); got != "current-from-boot-B" {
		t.Fatalf("the rebooted peer's current config must apply even though its generation is "+
			"far LOWER than the dead incarnation's; got %q. If the queued boot-A payload "+
			"applied above, its generation is now the high-water and every generation boot B "+
			"can produce is refused", got)
	}
}

// TestIncarnationIsComparedByEqualityNotOrder5084 binds the central finding of
// the #6900 post-mortem: the predicate is an EQUIVALENCE, never a ranking.
//
// Same sequence as the binder above with the two boot ids REVERSED, so the dead
// incarnation sorts ABOVE the live one. Any implementation that reaches for a
// comparison — `<`, `>`, a floor, a high-water over incarnations — passes when
// the ids happen to ascend and fails here, silently admitting a dead boot's
// config. The sibling binder alone cannot see it, because there `incA < incB`
// and an ordering test gives the right answer for the wrong reason.
func TestIncarnationIsComparedByEqualityNotOrder5084(t *testing.T) {
	e := newIncEnv(t, 1)

	// The peer's FIRST boot sorts HIGHER than the boot that replaces it.
	e.prime(0, 1, &incB)
	hold := e.holdNext()
	e.pushConfig(0, "config-from-the-higher-sorting-boot", 5)
	e.waitEntered(t, "config-from-the-higher-sorting-boot")
	e.pushConfig(0, "stale-from-the-higher-sorting-boot", 9_000_001)
	e.waitQueued(t, 1)

	// Reboot into an incarnation that sorts LOWER.
	e.prime(0, 2, &incA)
	close(hold)

	if got := e.waitApplied(3 * time.Second); got != "config-from-the-higher-sorting-boot" {
		t.Fatalf("setup: the first boot's config must apply normally; got %q", got)
	}
	if got := e.waitApplied(1500 * time.Millisecond); got != "" {
		t.Fatalf("a config from a replaced boot must be dropped whatever the two ids sort "+
			"like; it applied as %q. A ranking cannot express \"same peer boot?\" — that is "+
			"the finding seven review rounds of #6900 converged on, and this is the case "+
			"that catches an implementation which reached for a comparison anyway", got)
	}
}

// TestSameIncarnationRePrimeKeepsQueuedConfig5084 is the plan's over-reach
// guard, and it must stay GREEN under the revert above. A mid-connection
// re-prime (the #5450 forced resync) carries the SAME incarnation, so
// generations remain comparable and nothing queued may be discarded.
//
// The payload is genuinely queued ACROSS the re-prime, matching the binder's
// shape exactly, so the two differ only in whether the boot id changed. A guard
// that over-rejects — dropping on any re-prime, or on a connection-establishment
// ranking — reds here while the binder stays green.
func TestSameIncarnationRePrimeKeepsQueuedConfig5084(t *testing.T) {
	e := newIncEnv(t, 1)
	e.prime(0, 1, &incA)
	hold := e.holdNext()
	e.pushConfig(0, "first-config", 5)
	e.waitEntered(t, "first-config")
	e.pushConfig(0, "config-across-a-re-prime", 7)
	e.waitQueued(t, 1)

	e.prime(0, 2, &incA) // forced resync, SAME boot
	close(hold)

	if got := e.waitApplied(3 * time.Second); got != "first-config" {
		t.Fatalf("setup: the first config must apply; got %q", got)
	}
	if got := e.waitApplied(3 * time.Second); got != "config-across-a-re-prime" {
		t.Fatalf("a SAME-incarnation re-prime must not invalidate a queued payload — the "+
			"generations are comparable and the peer did not reboot; got %q", got)
	}
	if n := e.s.stats.ConfigsDeadIncarnationDropped.Load(); n != 0 {
		t.Fatalf("a same-incarnation re-prime must drop nothing; dropped %d", n)
	}
}

// TestSurvivingFabricSameIncarnationIsNeverFenced5084 is the two-fabric case
// that defeated #6900, and the plan requires it to be green BY CONSTRUCTION
// rather than by a floor that descends.
//
// Fabric 0 primes first (it would hold the LOWER syncConnID under the old
// ranking design). Fabric 1 then primes with the SAME incarnation — the same
// peer boot, reached over the redundant link. A config arriving on fabric 0
// must still apply: under a floor over connection ids, fabric 0 sits below the
// floor fabric 1 raised and is fenced out, which is the live-sibling lockout
// that killed the previous attempt.
func TestSurvivingFabricSameIncarnationIsNeverFenced5084(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 1, &incA) // earlier connection, same boot
	e.prime(1, 2, &incA) // later connection, SAME boot

	e.pushConfig(0, "config-on-the-earlier-fabric", 11)
	if got := e.waitApplied(3 * time.Second); got != "config-on-the-earlier-fabric" {
		t.Fatalf("a config on the EARLIER fabric of the SAME peer boot must never be fenced "+
			"out; got %q. This is the exact live-sibling lockout that defeated #6900: a "+
			"ranking over connections cannot express \"same boot?\"", got)
	}
	if n := e.s.stats.ConfigsDeadIncarnationDropped.Load(); n != 0 {
		t.Fatalf("no drop is legitimate here; dropped %d", n)
	}
}

// TestUnincarnatedPeerBehavesExactlyAsBefore5084 is the mixed-version cell, and
// the one that binds the FAIL-OPEN decision rather than merely documenting it:
// an 8-byte BulkStart from an old peer must produce today's generation-only
// ordering, with nothing dropped on incarnation grounds (plan §6 rule 4).
//
// A guard TIGHTENED to refuse an absent incarnation — the plausible "be safe,
// reject what you cannot verify" edit — reds here and only here. Failing closed
// would refuse ALL config from a not-yet-upgraded peer for the whole
// rolling-upgrade window, stranding the standby: strictly worse than the bug
// being fixed.
//
// The queued-across-a-re-prime shape is used deliberately, so this exercises
// the same code path the binder does and differs only in the absent field.
func TestUnincarnatedPeerBehavesExactlyAsBefore5084(t *testing.T) {
	e := newIncEnv(t, 1)
	e.prime(0, 1, nil) // legacy 8-byte BulkStart

	if n := e.s.stats.BulkPrimesWithoutIncarnation.Load(); n != 1 {
		t.Fatalf("an un-incarnated prime must be COUNTED — a silent fallback is how a "+
			"half-upgraded cluster hides; got %d", n)
	}
	hold := e.holdNext()
	e.pushConfig(0, "config-from-an-old-peer", 5)
	e.waitEntered(t, "config-from-an-old-peer")
	e.pushConfig(0, "queued-config-from-an-old-peer", 6)
	e.waitQueued(t, 1)

	// A second prime from the same old peer must not look like a reboot, and
	// must not invalidate the payload queued behind it.
	e.prime(0, 2, nil)
	close(hold)

	if got := e.waitApplied(3 * time.Second); got != "config-from-an-old-peer" {
		t.Fatalf("an un-incarnated payload must never be dropped on incarnation grounds; got %q", got)
	}
	if got := e.waitApplied(3 * time.Second); got != "queued-config-from-an-old-peer" {
		t.Fatalf("a second un-incarnated prime is not a namespace switch, and must not "+
			"invalidate a queued payload; got %q. Failing CLOSED here refuses every config "+
			"a not-yet-upgraded peer sends for the whole rolling-upgrade window", got)
	}
	if n := e.s.stats.ConfigsDeadIncarnationDropped.Load(); n != 0 {
		t.Fatalf("nothing may be dropped against an un-incarnated peer; dropped %d", n)
	}
	if n := e.s.stats.BulkPrimesWithoutIncarnation.Load(); n != 2 {
		t.Fatalf("both un-incarnated primes must be counted; got %d", n)
	}
}

// TestIncarnatedPeerThenUnincarnatedPrimeKeepsTheFence5084 pins the asymmetry
// in the absent-field rule: "no incarnation" means NO INFORMATION, not "a
// different boot". A prime that carries nothing must leave an incarnation
// already learned in place, so a peer that primes once with one and once
// without does not silently lose the fence.
func TestIncarnatedPeerThenUnincarnatedPrimeKeepsTheFence5084(t *testing.T) {
	e := newIncEnv(t, 1)
	e.prime(0, 1, &incA)
	e.prime(0, 2, nil)
	if got := e.s.PeerBootIncarnation(); got != incA {
		t.Fatalf("an un-incarnated prime must not CLEAR a learned incarnation; got %s", got)
	}
}

// TestBulkStartCarriesTheLocalBootIncarnationOnTheWire5084 binds the SENDER
// wiring, not the helper it calls. Deleting `appendBootIncarnation` from
// bulkSyncWindow leaves every receiver-side test above green — they inject
// their own payloads — and ships a build that never emits the field at all.
//
// The frame is read off a real connection through the production write path.
func TestBulkStartCarriesTheLocalBootIncarnationOnTheWire5084(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", &mockSweepDP{})
	s.mu.Lock()
	s.conn0 = local
	s.mu.Unlock()
	s.stats.Connected.Store(true)

	frames := make(chan syncFrame, 8)
	readFramesInto(peer, frames)
	go func() { _ = s.BulkSyncSnapshot(BulkSnapshot{}) }()

	var start syncFrame
	select {
	case start = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("no BulkStart frame was written")
	}
	if start.typ != syncMsgBulkStart {
		t.Fatalf("first frame type = %d, want BulkStart %d", start.typ, syncMsgBulkStart)
	}

	want := localBootIncarnation()
	if !want.known() {
		t.Fatalf("this node's %s could not be read, so the sender has nothing to advertise "+
			"and the #5084 fence is inert on it. On Linux this file always exists; a build "+
			"or sandbox that hides it silently disables the guard", bootIDPath)
	}
	if len(start.payload) != 8+bootIncarnationLen {
		t.Fatalf("BulkStart payload = %d bytes, want %d (8B epoch + 16B boot incarnation). "+
			"An 8-byte payload means the sender never appends the field, so an upgraded "+
			"receiver sees an un-incarnated peer forever and the fence never engages",
			len(start.payload), 8+bootIncarnationLen)
	}
	if !bytes.Equal(start.payload[8:], want[:]) {
		t.Fatalf("BulkStart tail = %x, want this node's boot incarnation %s",
			start.payload[8:], want)
	}
	// The receiver's parse of the frame this sender actually produced must
	// agree with the sender's own value — the two spellings are asserted
	// against each other rather than either being pinned to a literal.
	if got := parseBootIncarnation(start.payload); got != want {
		t.Fatalf("the receiver parses %s out of the frame the sender wrote for %s — the two "+
			"halves of the wire contract disagree", got, want)
	}
}

// TestUnreadableLocalBootIdEmitsTheLegacyPayload5084 pins the sender's own
// fail-open. A node that cannot read its boot id appends NOTHING rather than 16
// zero bytes: an explicit zero would be indistinguishable on the wire from a
// real incarnation the receiver must compare against, and would fence every
// payload against a namespace that does not exist.
func TestUnreadableLocalBootIdEmitsTheLegacyPayload5084(t *testing.T) {
	epoch := make([]byte, 8)
	binary.LittleEndian.PutUint64(epoch, 0x1122334455667788)

	legacy := appendBootIncarnation(append([]byte(nil), epoch...), bootIncarnation{})
	if len(legacy) != 8 || !bytes.Equal(legacy, epoch) {
		t.Fatalf("an unreadable boot id must emit the legacy 8-byte payload unchanged; got %x", legacy)
	}
	if parseBootIncarnation(legacy).known() {
		t.Fatal("the legacy payload must read back as un-incarnated")
	}

	extended := appendBootIncarnation(append([]byte(nil), epoch...), incA)
	if len(extended) != 8+bootIncarnationLen {
		t.Fatalf("a known boot id must extend the payload to %d bytes; got %d", 8+bootIncarnationLen, len(extended))
	}
	if !bytes.Equal(extended[:8], epoch) {
		t.Fatalf("the extension must not disturb the leading epoch; got %x", extended[:8])
	}
	if got := parseBootIncarnation(extended); got != incA {
		t.Fatalf("round-trip: parsed %s, want %s", got, incA)
	}
}

// TestExtendedBulkStartDecodesTheEpochUnchanged5084 is the wire-compatibility
// cell the plan says must NOT be established by inspection.
//
// The claim under test is the one the whole design rests on: extending the
// BulkStart payload from 8 to 24 bytes leaves the existing 8-byte field
// readable exactly as before. It is asserted against the ACTUAL decode path —
// the real `syncMsgBulkStart` arm, observed through the state it writes —
// rather than by re-reading the bytes in the test, because a wire-compat claim
// verified by reading is the shape that has failed repeatedly.
func TestExtendedBulkStartDecodesTheEpochUnchanged5084(t *testing.T) {
	const epoch = uint64(0x0102_0304_0506_0708)

	legacy := newIncEnv(t, 1)
	legacy.prime(0, epoch, nil)
	legacy.s.bulkMu.Lock()
	legacyEpoch := legacy.s.bulkRecvEpoch
	legacy.s.bulkMu.Unlock()

	extended := newIncEnv(t, 1)
	extended.prime(0, epoch, &incA)
	extended.s.bulkMu.Lock()
	extendedEpoch := extended.s.bulkRecvEpoch
	extended.s.bulkMu.Unlock()

	if legacyEpoch != epoch {
		t.Fatalf("precondition: the 8-byte form must decode the epoch (got %#x); without this "+
			"the comparison below is between two wrong answers", legacyEpoch)
	}
	if extendedEpoch != legacyEpoch {
		t.Fatalf("the 24-byte payload must decode the SAME epoch as the 8-byte one through the "+
			"real receive arm: got %#x, want %#x. If the tail disturbs the leading field, "+
			"every old receiver misreads a new sender's bulk epoch and bulk-ack matching "+
			"breaks across the whole rolling upgrade", extendedEpoch, legacyEpoch)
	}
	if got := extended.s.PeerBootIncarnation(); got != incA {
		t.Fatalf("the extended form must also yield the incarnation; got %s", got)
	}
	if got := legacy.s.PeerBootIncarnation(); got.known() {
		t.Fatalf("the legacy form must yield NO incarnation; got %s", got)
	}
}

// TestBootIncarnationParsingIsTotal5084 pins the parse boundaries. A short or
// absent tail is "no information" and must never be mistaken for a real
// incarnation, because a zero incarnation compared as a value would fence every
// payload against a namespace that does not exist.
func TestBootIncarnationParsingIsTotal5084(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", nil, false},
		{"epoch only", make([]byte, 8), false},
		{"one byte short", make([]byte, 8+bootIncarnationLen-1), false},
		{"exact", append(make([]byte, 8), incA[:]...), true},
	} {
		got := parseBootIncarnation(tc.in)
		if got.known() != tc.want {
			t.Fatalf("%s: known()=%v want %v", tc.name, got.known(), tc.want)
		}
	}
	// An all-zero tail is indistinguishable from absence, and must be treated
	// as absence: the sender never emits one (appendBootIncarnation appends
	// nothing when the local read failed) precisely so this case cannot arise
	// as a real value.
	zeroTail := make([]byte, 8+bootIncarnationLen)
	if parseBootIncarnation(zeroTail).known() {
		t.Fatal("an all-zero incarnation must read as absent, not as a distinct boot")
	}
}

// TestLocalBootIncarnationParsesTheKernelFormat5084 drives the real reader
// against the kernel's actual rendering — a dashed UUID with a trailing
// newline — rather than a hand-rolled hex string.
func TestLocalBootIncarnationParsesTheKernelFormat5084(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/boot_id"
	if err := os.WriteFile(path, []byte("550e8400-e29b-41d4-a716-446655440000\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readBootIncarnation(path)
	want := bootIncarnation{0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00}
	if got != want {
		t.Fatalf("kernel boot_id parse: got %s want %s", got, want)
	}
	// Every failure mode yields the un-incarnated sentinel, never a partial or
	// synthesised value: a substitute that changes when it must not would make
	// every reconnect look like a reboot and clear the peer's high-water on a
	// node that never rebooted.
	if readBootIncarnation(dir + "/missing").known() {
		t.Fatal("a missing boot_id must read as un-incarnated")
	}
	if err := os.WriteFile(path, []byte("not-a-uuid\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if readBootIncarnation(path).known() {
		t.Fatal("an unparseable boot_id must read as un-incarnated")
	}
	// The real kernel file must parse too — the fixture above proves the
	// FORMAT, this proves the deployed node actually yields an incarnation.
	if !readBootIncarnation("/proc/sys/kernel/random/boot_id").known() {
		t.Fatalf("%s did not yield an incarnation on this host; the sender would silently "+
			"advertise nothing and the #5084 fence would be inert", bootIDPath)
	}
}

// TestIncarnationSurfacesAsStatusNotHealth5084 binds the third design decision:
// a stale-incarnation discard and an un-incarnated peer are EXPECTED events —
// a peer reboot and a rolling upgrade — so they are surfaced as a status field
// plus counters and must NOT raise a cluster health / alarm state.
//
// #6387 set the precedent in the other direction by making a config-sync APPLY
// FAILURE diagnostic-only so it never gates failover; a strictly less severe
// condition must not be louder. Raising health on an un-incarnated peer would
// make every rolling upgrade render as degraded.
func TestIncarnationSurfacesAsStatusNotHealth5084(t *testing.T) {
	e := newIncEnv(t, 1)
	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	m.SetSyncStats(e.s)

	// (1) Nothing has primed. The line must render ANYWAY, carrying "none" —
	// the operationally interesting value is exactly the one a
	// render-only-when-set line would hide.
	info := m.FormatInformation()
	if !strings.Contains(info, "Peer boot incarnation: none") {
		t.Fatalf("status must always render the peer boot incarnation, including \"none\":\n%s", info)
	}
	assertNoHealthEscalation5084(t, m, "before any prime")

	// (2) An un-incarnated (old-build) peer primes: counted and rendered, and
	// still not a fault.
	e.prime(0, 1, nil)
	info = m.FormatInformation()
	if !strings.Contains(info, "Primes without incarnation: 1") {
		t.Fatalf("an un-incarnated prime must be rendered:\n%s", info)
	}
	if !strings.Contains(info, "Peer boot incarnation: none") {
		t.Fatalf("an un-incarnated peer must still render \"none\":\n%s", info)
	}
	assertNoHealthEscalation5084(t, m, "against an un-incarnated peer")

	// (3) A real incarnation primes, a payload queued from it survives a reboot
	// into another incarnation, and the fence drops it.
	e.prime(0, 2, &incA)
	hold := e.holdNext()
	e.pushConfig(0, "first", 5)
	e.waitEntered(t, "first")
	e.pushConfig(0, "queued-from-the-dead-boot", 9_000_001)
	e.waitQueued(t, 1)
	e.prime(0, 3, &incB)
	close(hold)
	if got := e.waitApplied(3 * time.Second); got != "first" {
		t.Fatalf("setup: the first config must apply; got %q", got)
	}
	if got := e.waitApplied(1500 * time.Millisecond); got != "" {
		t.Fatalf("setup: the dead-boot payload must be dropped; it applied as %q", got)
	}

	info = m.FormatInformation()
	if !strings.Contains(info, "Peer boot incarnation: "+incB.String()) {
		t.Fatalf("status must render the CURRENT incarnation (%s):\n%s", incB, info)
	}
	if !strings.Contains(info, "Configs dead-incarnation-dropped: 1") {
		t.Fatalf("the fence's drop must be rendered as a counter:\n%s", info)
	}
	assertNoHealthEscalation5084(t, m, "after a dead-incarnation drop")
}

// assertNoHealthEscalation5084 checks the two node-health surfaces #6387 uses.
// "Local node: degraded" is the FormatInformation health line, and a second
// "CF" occurrence in FormatStatus means a redundancy-group row picked up a
// config-sync monitor failure (the legend line always contributes one).
func assertNoHealthEscalation5084(t *testing.T, m *Manager, when string) {
	t.Helper()
	info := m.FormatInformation()
	if strings.Contains(info, "Local node: degraded") {
		t.Fatalf("%s: the incarnation fence must not degrade node health — an un-incarnated "+
			"peer is a rolling upgrade and a stale-incarnation discard is a peer reboot, "+
			"neither is a fault:\n%s", when, info)
	}
	if strings.Contains(info, "Config sync: failing") {
		t.Fatalf("%s: the incarnation fence must not raise the #6387 config-sync health "+
			"signal:\n%s", when, info)
	}
	if n := strings.Count(m.FormatStatus(), "CF"); n != 1 {
		t.Fatalf("%s: FormatStatus must carry only the legend's CF (count=%d) — the fence "+
			"must never raise a monitor failure:\n%s", when, n, m.FormatStatus())
	}
}

// TestUnkeyedConnectionStampsTheIncarnation5084 binds the INSTALL wiring on the
// posture the plan singles out: an UNKEYED cluster.
//
// `performSyncHandshake` returns immediately with syncAuthUnauthenticated when
// `len(key) == 0`, which is exactly why the auth HELLO was rejected as the
// carrier — a HELLO-borne incarnation would be silently absent there, making
// the whole guard configuration-dependent. Carrying it on BulkStart is only
// correct if the connection-install path still produces a per-connection
// carrier on that path, and it does: handleNewConnection wraps EVERY connection
// in an *authConn regardless of mode, and connBootIncarnation keys off that
// wrapper.
//
// This drives the real thing: an unkeyed install, a BulkStart written onto the
// wire, and the receiveLoop's own decode. Every other cell in this file injects
// through handleMessage directly, so all of them stay green if the wrap is
// dropped from handleNewConnection — and then connBootIncarnation returns the
// zero value forever, every payload lands in the never-dropped class, and the
// fence is silently inert on exactly the clusters that cannot authenticate.
func TestUnkeyedConnectionStampsTheIncarnation5084(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	if !s.beginSetup(srv, true) {
		t.Fatal("setup: beginSetup should admit the first inbound connection")
	}
	// The install path emits advisory frames (clock sync, capabilities, key
	// exchange). net.Pipe is unbuffered, so drain them or the install blocks.
	drain := make(chan syncFrame, 32)
	readFramesInto(cli, drain)
	go s.handleNewConnection(context.Background(), 0, srv, true)

	if err := writeMsg(cli, syncMsgBulkStart, bulkStartPayload(7, &incA)); err != nil {
		t.Fatalf("write BulkStart: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.PeerBootIncarnation() == incA {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := s.PeerBootIncarnation(); got != incA {
		t.Fatalf("an UNKEYED connection must still learn the peer boot incarnation; got %s. "+
			"That posture performs no auth handshake at all, which is precisely why the "+
			"incarnation rides on BulkStart rather than the HELLO", got)
	}
	s.mu.Lock()
	installed := s.conn0
	s.mu.Unlock()
	if installed == nil {
		t.Fatal("setup: the connection was never installed in fabric slot 0")
	}
	if got := s.connBootIncarnation(installed); got != incA {
		t.Fatalf("the INSTALLED connection must carry the stamp (%s), so every config payload "+
			"it delivers is enqueued with it; got %s. A connection the install path did not "+
			"wrap yields the zero value and lands every payload in the never-dropped class",
			incA, got)
	}
}

// TestDeadIncarnationConfigNeverRaisesTheReceivedHighWater5084 covers the OTHER
// drop site, and the fail state that made it necessary.
//
// `recordRecvConfigGen` runs at RECEIVE time and is a monotone max. #5563 gates
// manual-failover readiness on it: `ReadyForManualFailover` refuses promotion
// while `PeerConfigGen > AppliedConfigGen`. A dead incarnation's generation is
// drawn from the peer's PRE-reboot counter, so it is far higher than anything
// the live incarnation can produce. Dropping such a payload only at APPLY time
// would leave the received mark inflated with nothing able to close the gap
// short of another re-prime: the standby reads config-stale and refuses
// promotion indefinitely — the #5084 divergence traded for a different silent
// wedge, which is precisely the failure mode that killed #6900.
//
// The shape is the surviving-fabric one: fabric 0 primed under the dead boot,
// the peer rebooted and re-primed over fabric 1, and a buffered payload from
// the dead boot then arrives on fabric 0.
//
// FAIL-ON-REVERT: delete the receive-time check in handleConfigPayload and the
// high-water assertion below reds while every apply-time cell stays green.
func TestDeadIncarnationConfigNeverRaisesTheReceivedHighWater5084(t *testing.T) {
	e := newIncEnv(t, 2)
	e.prime(0, 1, &incA) // fabric 0 primed under boot A
	e.prime(1, 2, &incB) // the peer rebooted; its re-prime arrives over fabric 1

	e.pushConfig(0, "buffered-from-the-dead-boot", 9_000_001)
	if got := e.waitApplied(1500 * time.Millisecond); got != "" {
		t.Fatalf("a payload arriving under a replaced incarnation must not apply; got %q", got)
	}
	if n := e.s.stats.ConfigsDeadIncarnationDropped.Load(); n != 1 {
		t.Fatalf("the receive-time drop must be counted exactly once; got %d", n)
	}
	if got := e.s.lastRecvConfigGen.Load(); got != 0 {
		t.Fatalf("the received-config high-water rose to %d for a payload from a DEAD peer "+
			"boot. #5563 refuses manual failover while PeerConfigGen > AppliedConfigGen, and "+
			"no generation the live incarnation can produce will ever exceed a pre-reboot "+
			"one — the standby would read config-stale and refuse promotion until the next "+
			"re-prime", got)
	}

	// The live incarnation's own lower-generation config still applies, and
	// leaves readiness clean (received == applied).
	e.pushConfig(1, "current-on-the-live-fabric", 42)
	if got := e.waitApplied(3 * time.Second); got != "current-on-the-live-fabric" {
		t.Fatalf("the live incarnation's config must apply; got %q", got)
	}
	// recordAppliedConfigGen runs AFTER OnConfigReceived returns, so poll
	// rather than read the mark the instant the text lands.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && e.s.lastAppliedConfigGen.Load() != 42 {
		time.Sleep(time.Millisecond)
	}
	if r, a := e.s.lastRecvConfigGen.Load(), e.s.lastAppliedConfigGen.Load(); r != 42 || a != 42 {
		t.Fatalf("received/applied marks = %d/%d, want 42/42 — a standby whose received mark "+
			"exceeds its applied mark refuses manual failover (#5563)", r, a)
	}
}
