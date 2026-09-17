package cluster

import (
	"encoding/binary"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// STEP-0 RED cells for psaab/xpf#9915 (cluster/HA sync-guard cohort). Each cell
// asserts the intended invariant and FAILS on the base revision; the fix turns
// each GREEN. Kept as permanent regression coverage.

// F-043: a node id outside {0,1} must fail the keyed handshake LOUD, naming the
// identity — never derive a divergent Noise prologue that bricks the sync plane
// while the cluster looks alive.
func TestSyncNoiseIdentityRejectsNodeIdOutside01_9915(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	for _, node := range []int{2, 5, -1, 256} {
		s := newAuthSyncNode(t, key, node)
		_, err := s.newSyncNoiseState(key, true, syncNoisePhaseConnect, 0)
		if err == nil {
			t.Errorf("node id %d: newSyncNoiseState succeeded, want a loud identity error; "+
				"1-localNode derives a prologue the peer cannot match (F-043)", node)
			continue
		}
		if !strings.Contains(err.Error(), "node") {
			t.Errorf("node id %d: error %q does not name the node identity", node, err)
		}
	}
	for _, node := range []int{0, 1} {
		s := newAuthSyncNode(t, key, node)
		if _, err := s.newSyncNoiseState(key, true, syncNoisePhaseConnect, 0); err != nil {
			t.Errorf("CONTROL: node id %d must still handshake, got %v", node, err)
		}
	}
}

// F-044 (sizing half): the generation-guard cap must cover the maximum possible
// live-session key count — forward entries, i.e. half of conntrack.MaxSessions
// (which counts forward+reverse). A static 200k cap at 2% of the table leaves a
// full-of-LIVE skip-record degradation for any table past 200k sessions.
func TestGenGuardCapCoversMaxLiveSessions_9915(t *testing.T) {
	// Behavioral (spark-MINOR-13): with a full table's sessions wired, the
	// effective ceiling must bind at the forward-entries count — asserted
	// through the setter→maxCap path, not by restating the constant.
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetGenGuardSessionCap(uint64(conntrack.MaxSessions))
	if got, want := ss.maxCap(), conntrack.MaxSessions/2; got != want {
		t.Fatalf("maxCap with a full table wired = %d, want %d forward entries (F-044)", got, want)
	}
}

// F-044 (observability half): guard-map saturation must be operator-visible in
// cluster status, not only a counter — the #9653 ClockSyncsRefused posture.
func TestGenGuardSaturationRenderedInStatus_9915(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	m.SetSyncStats(s)

	const overflowLine = "Generation-guard map overflows:"
	const tombLine = "Generation-guard tombstones evicted:"
	if info := m.FormatInformation(); strings.Contains(info, overflowLine) || strings.Contains(info, tombLine) {
		t.Fatalf("a node at no saturation must render neither saturation line:\n%s", info)
	}

	s.stats.GenMapOverflow.Add(3)
	s.stats.GenTombstonesEvicted.Add(7)
	info := m.FormatInformation()
	if !strings.Contains(info, overflowLine+" 3") {
		t.Errorf("guard-map overflow must be operator-visible in cluster status (F-044):\n%s", info)
	}
	if !strings.Contains(info, tombLine+" 7") {
		t.Errorf("tombstone evictions must be operator-visible in cluster status (F-044):\n%s", info)
	}
}

// F-116: dropping an IDLE fabric must not abort a confirmed fence whose ack path
// is healthy. The fence goes out on the active conn; only that conn's drop may
// release the waiter. Driven via public API so the cell survives the fix.
func TestFenceSurvivesIdleFabricFlap_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	f0a, f0b := net.Pipe()
	defer f0a.Close()
	defer f0b.Close()
	f1a, f1b := net.Pipe()
	defer f1a.Close()
	defer f1b.Close()
	ss.installConn(0, f0a)
	ss.installConn(1, f1a)
	if ss.getActiveConn() == nil {
		t.Fatal("FIXTURE: no active conn after installing both fabrics")
	}
	ss.peerCapabilityFlags.Store(uint32(capFlagFenceAck))

	type fenceOutcome struct {
		ack FenceAck
		err error
	}
	out := make(chan fenceOutcome, 1)
	go func() {
		ack, err := ss.SendFenceAwait(3 * time.Second)
		out <- fenceOutcome{ack: ack, err: err}
	}()

	// Wait for the fence frame itself on the peer end: registration precedes
	// the write, so an observed frame proves the waiter exists.
	_, fencePayload := waitForFenceFrame9915(t, f0b)
	if len(fencePayload) < 8 {
		t.Fatalf("FIXTURE: fence payload is %d bytes, want >= 8 (seq)", len(fencePayload))
	}
	seq := binary.LittleEndian.Uint64(fencePayload[:8])

	// The idle fabric flaps while the fence is outstanding on fab0.
	ss.handleDisconnect(f1a)

	select {
	case got := <-out:
		t.Fatalf("an idle-fabric flap aborted the confirmed fence (err=%v); "+
			"the ack path is healthy and the fence must survive (F-116)", got.err)
	case <-time.After(150 * time.Millisecond):
	}

	// The peer answers on the healthy path; the fence must confirm.
	ss.completeFenceAckWait(FenceAck{Seq: seq, Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1})
	select {
	case got := <-out:
		if got.err != nil {
			t.Fatalf("fence failed after idle flap + healthy ack: %v (F-116)", got.err)
		}
		if got.ack.Seq != seq {
			t.Fatalf("fence ack seq = %d, want %d", got.ack.Seq, seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fence never completed after the ack arrived")
	}
}

// F-116 control: dropping the fence's OWN fabric still releases the waiter
// immediately with a disconnect error (no full-timeout burn).
func TestFenceAbortsWhenItsOwnFabricDrops_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	f0a, f0b := net.Pipe()
	defer f0a.Close()
	defer f0b.Close()
	f1a, f1b := net.Pipe()
	defer f1a.Close()
	defer f1b.Close()
	ss.installConn(0, f0a)
	ss.installConn(1, f1a)
	if ss.getActiveConn() != f0a {
		t.Fatal("FIXTURE: fab0 must be the active conn")
	}
	ss.peerCapabilityFlags.Store(uint32(capFlagFenceAck))

	out := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(3 * time.Second)
		out <- err
	}()
	// Wait for the fence frame itself: proves the waiter is registered
	// (registration precedes the write); see the survive cell.
	waitForFenceFrame9915(t, f0b)

	ss.handleDisconnect(f0a)
	select {
	case err := <-out:
		if err == nil {
			t.Fatal("dropping the fence fabric must release the waiter with an error, got ack")
		}
		if !strings.Contains(err.Error(), "disconnected") {
			t.Fatalf("waiter released with %q, want a disconnect error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dropping the fence fabric did not release the waiter promptly")
	}
}

// F-117: a DHCP lease record without minimal identity for the OUTER message
// family must be dropped (with a counter), not installed as a partial lease.
// Only the violating member drops; the rest of the set still applies.
func TestDHCPLeaseWithoutFamilyIdentityDropped_9915(t *testing.T) {
	good := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:05",
		SubnetID: 1, ValidLife: 3600, Remaining: 1800}
	noIdentity := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.9",
		SubnetID: 1, ValidLife: 3600, Remaining: 1800}
	crossFamily := dhcpserver.SyncLease{Family: 6, Address: "2001:db8::9", DUID: "00:01:xx",
		LeaseType: "IA_NA", SubnetID: 2, ValidLife: 3600, Remaining: 1800}

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var got []dhcpserver.SyncLease
	ss.OnDHCPLeasesReceived = func(family int, leases []dhcpserver.SyncLease) {
		if family != 4 {
			t.Errorf("callback family = %d, want 4", family)
		}
		got = leases
	}
	payload := encodeDHCPLeasePayload([]dhcpserver.SyncLease{good, noIdentity, crossFamily})
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, payload)
	if len(got) != 1 || got[0].Address != "10.0.0.5" {
		t.Fatalf("received %d leases (%v), want only the identity-carrying 10.0.0.5; "+
			"the identity-less record and the cross-family record must drop (F-117)", len(got), got)
	}

	// Adjudicated (scope P0): production flows via the held set, not the
	// callback — assert the aged held set carries only the survivor too.
	held := ss.PeerDHCPLeases4()
	if len(held) != 1 || held[0].Address != "10.0.0.5" {
		t.Fatalf("held v4 set has %d leases (%v), want only 10.0.0.5 (F-117)", len(held), held)
	}
	if got := ss.Stats().DHCPLeasesDroppedNoIdentity; got != 2 {
		t.Fatalf("DHCPLeasesDroppedNoIdentity = %d, want 2 (F-117)", got)
	}

	// Control: a clean set still applies whole.
	ss2 := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var got2 []dhcpserver.SyncLease
	ss2.OnDHCPLeasesReceived = func(_ int, leases []dhcpserver.SyncLease) { got2 = leases }
	ss2.handleMessage(nil, syncMsgDHCPLeaseV4, encodeDHCPLeasePayload([]dhcpserver.SyncLease{good}))
	if len(got2) != 1 {
		t.Fatalf("CONTROL: clean single-lease set applied %d leases, want 1", len(got2))
	}

	// Retain-on-empty (adjudicated #7175 posture): a non-empty push that
	// filters to zero survivors must retain the prior set, not wipe it.
	ss3 := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss3.handleMessage(nil, syncMsgDHCPLeaseV4, encodeDHCPLeasePayload([]dhcpserver.SyncLease{good}))
	if held3 := ss3.PeerDHCPLeases4(); len(held3) != 1 {
		t.Fatalf("FIXTURE: clean push held %d leases, want 1", len(held3))
	}
	ss3.handleMessage(nil, syncMsgDHCPLeaseV4, encodeDHCPLeasePayload([]dhcpserver.SyncLease{noIdentity, crossFamily}))
	if held3 := ss3.PeerDHCPLeases4(); len(held3) != 1 || held3[0].Address != "10.0.0.5" {
		t.Fatalf("all-dropped push left held set %v, want prior set retained (F-117)", held3)
	}
	if got := ss3.Stats().DHCPLeasesDroppedNoIdentity; got != 2 {
		t.Fatalf("ss3 DHCPLeasesDroppedNoIdentity = %d, want 2 (F-117)", got)
	}
}

// F-118 (rebase half): a huge peer timestamp must never wrap to a near-epoch
// value that lands the install in the past (instant reap).
func TestRebaseTimestampNeverWrapsToPast_9915(t *testing.T) {
	if got := rebaseTimestamp(math.MaxUint64, 100); got <= 1<<62 {
		t.Fatalf("rebaseTimestamp(maxUint64, 100) = %d, want a saturated far-future value; "+
			"the wrap lands the deadline in the past (F-118)", got)
	}
	if got := rebaseTimestamp(100, 50); got != 150 {
		t.Fatalf("CONTROL: rebaseTimestamp(100, 50) = %d, want 150", got)
	}
	if got := rebaseTimestamp(10, -20); got != 0 {
		t.Fatalf("CONTROL: rebaseTimestamp(10, -20) = %d, want 0 (negative clamps)", got)
	}
}

// F-118 (offset half): a full disconnect ends the peer incarnation, so the
// stored clock offset must reset — a reconnect-window install must not carry
// the DEAD incarnation's offset.
func TestClockOffsetResetOnFullDisconnect_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	c0 := pipeConn(t)
	ss.installConn(0, c0)
	ss.testClockNow = func() uint64 { return 1000000 }
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 500000) // offset +500000, deterministic
	ss.handleMessage(nil, syncMsgClockSync, buf[:])
	before := ss.peerClockOffset.Load()
	if before == 0 {
		t.Fatal("FIXTURE: the honest clock sync was not stored")
	}
	ss.handleDisconnect(c0)
	if got := ss.peerClockOffset.Load(); got != 0 {
		t.Fatalf("peerClockOffset = %d after a full disconnect, want 0; the dead "+
			"incarnation's offset survives into the reconnect window (F-118)", got)
	}
}

var _ = dataplane.SessionKey{}

// F-118 control: a PARTIAL disconnect keeps the stored offset — the surviving
// fabric belongs to the same peer process, and not-yet-synced conns fall back
// to it. Passes on base and post-fix (full reset is pinned separately).
func TestClockOffsetKeepsOnPartialDisconnect_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	c0 := pipeConn(t)
	c1 := pipeConn(t)
	ss.installConn(0, c0)
	ss.installConn(1, c1)
	ss.testClockNow = func() uint64 { return 1000000 }
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 500000) // offset +500000, deterministic
	ss.handleMessage(nil, syncMsgClockSync, buf[:])
	before := ss.peerClockOffset.Load()
	if before == 0 {
		t.Fatal("FIXTURE: the honest clock sync was not stored")
	}
	ss.handleDisconnect(c0)
	if got := ss.peerClockOffset.Load(); got != before {
		t.Fatalf("peerClockOffset = %d after a partial disconnect, want %d (same peer process) (F-118)", got, before)
	}
}

// F-044 (demand-growth half): with helper capacity wired, a full-of-LIVE map
// grows the cap instead of skip-recording the new key. Base-RED evidence for
// the member (static-200k skip) was captured pre-fix and is preserved in
// docs/log/9915.md; this cell pins the wired behavior (setter is new API).
func TestGenGuardCapGrowsOnLiveDemand_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetGenGuardSessionCap(600000)
	live := gen2170KeyV4()
	ss.recordInstalledGenV4(live, 2)
	fillRecvGenV4ToCount(ss, live, genGuardMapDefaultCap)
	newKey := dataplane.SessionKey{Protocol: 6, SrcPort: 0xBEEF, DstPort: 0xCAFE}
	ss.recordInstalledGenV4(newKey, 1)
	ss.recvGenMu.Lock()
	_, stored := ss.recvGenV4[newKey]
	grown := ss.recvCap()
	ss.recvGenMu.Unlock()
	if !stored {
		t.Fatal("full-of-live map skip-recorded the new key instead of growing the cap (F-044)")
	}
	if grown != 400000 {
		t.Fatalf("recvGenGuardCap = %d, want 400000 (one doubling from default 200000)", grown)
	}
	if got := ss.stats.GenCapGrown.Load(); got != 1 {
		t.Fatalf("GenCapGrown = %d, want 1", got)
	}
}

// F-044 (unwired default): without provisioned capacity the default holds —
// no growth past status quo, skip + overflow exactly as before. Pins
// no-change for unwired (kernel/legacy/test) paths.
func TestGenGuardCapStaysDefaultWhenUnwired_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	live := gen2170KeyV4()
	ss.recordInstalledGenV4(live, 2)
	fillRecvGenV4ToCount(ss, live, genGuardMapDefaultCap)
	newKey := dataplane.SessionKey{Protocol: 6, SrcPort: 0xBEEF, DstPort: 0xCAFE}
	ss.recordInstalledGenV4(newKey, 1)
	ss.recvGenMu.Lock()
	_, stored := ss.recvGenV4[newKey]
	ss.recvGenMu.Unlock()
	if stored {
		t.Fatal("unwired map recorded past the default without provisioned capacity (F-044)")
	}
	if got := ss.stats.GenMapOverflow.Load(); got != 1 {
		t.Fatalf("GenMapOverflow = %d, want 1 (F-044)", got)
	}
	if got := ss.stats.GenCapGrown.Load(); got != 0 {
		t.Fatalf("GenCapGrown = %d, want 0 unwired (F-044)", got)
	}
}

// F-044 (setter semantics): unknown retains, values clamp to
// [default, absolute], each report tracks current (a replacement reporting
// fewer workers shrinks honestly). GREEN-only (new API).
func TestGenGuardSessionCapClampAndTrack_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if got := ss.maxCap(); got != genGuardMapDefaultCap {
		t.Fatalf("unwired maxCap = %d, want default %d", got, genGuardMapDefaultCap)
	}
	ss.SetGenGuardSessionCap(0)
	if got := ss.maxCap(); got != genGuardMapDefaultCap {
		t.Fatalf("maxCap after Set(0) = %d, want default %d (unknown retains)", got, genGuardMapDefaultCap)
	}
	ss.SetGenGuardSessionCap(600000)
	if got := ss.maxCap(); got != 600000 {
		t.Fatalf("maxCap after Set(600000) = %d, want 600000", got)
	}
	ss.SetGenGuardSessionCap(500000)
	if got := ss.maxCap(); got != 500000 {
		t.Fatalf("maxCap after Set(500000) = %d, want 500000 (tracks current, not max-so-far)", got)
	}
	fresh := NewSessionSync(":0", "10.0.0.2:4785", nil)
	fresh.SetGenGuardSessionCap(100)
	if got := fresh.maxCap(); got != genGuardMapDefaultCap {
		t.Fatalf("maxCap after Set(100) = %d, want default %d (clamp up)", got, genGuardMapDefaultCap)
	}
	fresh.SetGenGuardSessionCap(100000000)
	if got := fresh.maxCap(); got != genGuardMapCap {
		t.Fatalf("maxCap after Set(100M) = %d, want absolute ceiling %d (clamp down)", got, genGuardMapCap)
	}
}

// F-118 (saturation-count half): an install whose rebase ACTUALLY overflows
// (positive offset + huge timestamp) counts RebaseSaturations and lands
// clamped at MaxUint64; a huge timestamp with a negative offset neither
// saturates nor counts. GREEN-only: the counter is new API (the wrap itself
// is RED-pinned by TestRebaseTimestampNeverWrapsToPast_9915).
func TestRebaseSaturationCountedAtInstall_9915(t *testing.T) {
	newTestSync := func() (*SessionSync, *mockSweepDP) {
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		return NewSessionSync(":0", "10.0.0.2:4785", dp), dp
	}
	keyFor := func(port uint16) dataplane.SessionKey {
		key := dataplane.SessionKey{Protocol: 6, SrcPort: port, DstPort: 80}
		key.SrcIP = [4]byte{192, 0, 2, 118}
		return key
	}
	clockSync := func(ss *SessionSync, peerMono uint64) {
		t.Helper()
		ss.testClockNow = func() uint64 { return 1000000 }
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], peerMono)
		ss.handleMessage(nil, syncMsgClockSync, buf[:])
	}
	local := uint64(1000000)

	// Positive offset + huge timestamp: the rebase overflows, saturates, counts.
	ss, dp := newTestSync()
	clockSync(ss, local-100) // offset +100; plausible uptime-scale peer clock
	if got := ss.peerClockOffset.Load(); got != 100 {
		t.Fatalf("FIXTURE: offset = %d, want +100", got)
	}
	key := keyFor(0x9915)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		Created: math.MaxUint64 - 10, LastSeen: math.MaxUint64 - 10}
	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val))
	if got := ss.stats.RebaseSaturations.Load(); got != 1 {
		t.Fatalf("RebaseSaturations = %d, want 1 for an overflowing rebase (F-118)", got)
	}
	got, ok := dp.v4sessions[key]
	if !ok {
		t.Fatal("saturated install did not land")
	}
	if got.Created != math.MaxUint64 || got.LastSeen != math.MaxUint64 {
		t.Fatalf("installed Created/LastSeen = %d/%d, want saturated MaxUint64 (F-118)", got.Created, got.LastSeen)
	}

	// Control: huge timestamp with a NEGATIVE offset neither saturates nor counts.
	ss2, dp2 := newTestSync()
	clockSync(ss2, local+100) // offset -100
	if got := ss2.peerClockOffset.Load(); got != -100 {
		t.Fatalf("FIXTURE: offset = %d, want -100", got)
	}
	key2 := keyFor(0x9916)
	huge := (uint64(1) << 63) + 5
	val2 := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		Created: huge, LastSeen: huge}
	ss2.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key2, val2))
	if got := ss2.stats.RebaseSaturations.Load(); got != 0 {
		t.Fatalf("RebaseSaturations = %d, want 0 for a non-saturating rebase (F-118)", got)
	}
	got2, ok := dp2.v4sessions[key2]
	if !ok {
		t.Fatal("control install did not land")
	}
	if got2.LastSeen != huge-100 {
		t.Fatalf("installed LastSeen = %d, want exact %d (F-118)", got2.LastSeen, huge-100)
	}
}

// F-116 (supersede half): a waiter tagged with a conn that is SUPERSEDED
// (replaced without any disconnect) must release promptly — its ack path is
// gone. RED on base (survives to timeout); GREEN via installConn-tail abort.
func TestFenceAbortsWhenItsFabricIsSuperseded_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	f0a, f0b := net.Pipe()
	defer f0a.Close()
	defer f0b.Close()
	f1a, f1b := net.Pipe()
	defer f1a.Close()
	defer f1b.Close()
	ss.installConn(0, f0a)
	ss.installConn(1, f1a)
	if ss.getActiveConn() != f0a {
		t.Fatal("FIXTURE: fab0 must be the active conn")
	}
	ss.peerCapabilityFlags.Store(uint32(capFlagFenceAck))
	out := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(3 * time.Second)
		out <- err
	}()
	// Wait for the fence frame itself: proves the waiter is registered;
	// see the survive cell.
	waitForFenceFrame9915(t, f0b)

	// Supersede fab0: the replacement lands without any disconnect.
	f0c, f0d := net.Pipe()
	defer f0c.Close()
	defer f0d.Close()
	ss.installConn(0, f0c)
	select {
	case err := <-out:
		if err == nil {
			t.Fatal("superseded fence waiter returned an ack for a dead fabric")
		}
		if !strings.Contains(err.Error(), "disconnected") {
			t.Fatalf("waiter released with %q, want a disconnect error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("superseding the fence fabric did not release the waiter promptly (F-116)")
	}
}

// F-116 (evict half): a waiter tagged with a conn retired by incarnation
// eviction must release promptly. RED on base; GREEN via evict-tail abort.
func TestFenceAbortsWhenItsFabricIsEvicted_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	f0a, f0b := net.Pipe()
	defer f0a.Close()
	defer f0b.Close()
	f1a, f1b := net.Pipe()
	defer f1a.Close()
	defer f1b.Close()
	ss.installConn(0, f0a)
	ss.installConn(1, f1a)
	if ss.getActiveConn() != f0a {
		t.Fatal("FIXTURE: fab0 must be the active conn")
	}
	ss.peerCapabilityFlags.Store(uint32(capFlagFenceAck))
	out := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(3 * time.Second)
		out <- err
	}()
	// Wait for the fence frame itself: proves the waiter is registered;
	// see the survive cell.
	waitForFenceFrame9915(t, f0b)

	// Advance the incarnation and evict the retired fabric-0 conn.
	ss.mu.Lock()
	ss.peerIncarnation++
	evicted := ss.evictStaleIncarnationConnsLocked(1)
	ss.mu.Unlock()
	if !evicted {
		t.Fatal("FIXTURE: fabric 0 was not evicted")
	}
	select {
	case err := <-out:
		if err == nil {
			t.Fatal("evicted fence waiter returned an ack for a dead fabric")
		}
		if !strings.Contains(err.Error(), "disconnected") {
			t.Fatalf("waiter released with %q, want a disconnect error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("evicting the fence fabric did not release the waiter promptly (F-116)")
	}
}

// F-044 review (spark-MAJOR-2/gpt-Medium-2): the installing-table sender memo
// is a guard map like the rest — unwired it refuses past the default, with no
// growth and no provisioning proof. Pins the unwired boundary for the memo
// family, not only recvGenV4.
func TestInstallTableMemoUnwiredBoundary_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.genSentMu.Lock()
	ss.installTableSentV4 = make(map[dataplane.SessionKey]sentInstallTable, genGuardMapDefaultCap)
	for i := 0; len(ss.installTableSentV4) < genGuardMapDefaultCap; i++ {
		k := synthKeyV4(0x500000 + i)
		ss.installTableSentV4[k] = sentInstallTable{sessionID: uint64(i + 1), domain: 1, check: 2}
	}
	ss.genSentMu.Unlock()
	newKey := dataplane.SessionKey{Protocol: 6, SrcPort: 0xBEEF, DstPort: 0xCAFE}
	val := dataplane.SessionValue{SessionID: 0x9915}
	ss.stampInstallGenV4(newKey, &val)
	ss.genSentMu.Lock()
	_, stored := ss.installTableSentV4[newKey]
	ss.genSentMu.Unlock()
	if stored {
		t.Fatal("unwired sender memo recorded past the default without provisioned capacity (F-044 review)")
	}
	if got := ss.stats.GenCapGrown.Load(); got != 0 {
		t.Fatalf("GenCapGrown = %d, want 0 unwired (F-044 review)", got)
	}
	if got := ss.sentCap(); got != genGuardMapDefaultCap {
		t.Fatalf("sentCap = %d, want default %d unwired", got, genGuardMapDefaultCap)
	}
}

// F-044 review (spark-MAJOR-3): a wired ceiling that shrinks below a grown cap
// clamps the stored cap down — the sender never outruns provisioned RAM
// forever. Clamp-at-read makes the effective cap follow immediately; the grow
// path persists the clamp and counts it.
func TestGenGuardCapClampsOnShrink_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.genSentMu.Lock()
	ss.sentGenGuardCap = 800000 // as if demand-grown under a larger ceiling
	ss.genSentMu.Unlock()
	ss.SetGenGuardSessionCap(200000) // replacement reports fewer workers
	ss.genSentMu.Lock()
	if got := ss.sentCap(); got != 200000 {
		ss.genSentMu.Unlock()
		t.Fatalf("sentCap = %d, want 200000 clamped-at-read to the shrunken ceiling (F-044 review)", got)
	}
	grew := ss.growSentCap()
	stored := ss.sentGenGuardCap
	ss.genSentMu.Unlock()
	if grew {
		t.Fatal("grow reported growth while clamping down (F-044 review)")
	}
	if stored != 200000 {
		t.Fatalf("stored sent cap = %d, want 200000 clamped down (F-044 review)", stored)
	}
	if got := ss.Stats().GenCapShrunk; got != 1 {
		t.Fatalf("Stats().GenCapShrunk = %d, want 1 (F-044 review)", got)
	}
}

// F-044 review (spark-MINOR-16): reconciled contract — nonzero always tracks
// current (up AND down); zero means "unknown" (missed report), retaining
// last-known-good so a telemetry gap never shrinks live guards.
func TestGenGuardSessionCapZeroRetainsAfterWired_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetGenGuardSessionCap(600000)
	ss.SetGenGuardSessionCap(0)
	if got := ss.maxCap(); got != 600000 {
		t.Fatalf("maxCap after Set(0) = %d, want 600000 retained (unknown retains last-known, F-044 review)", got)
	}
	ss.SetGenGuardSessionCap(500000)
	if got := ss.maxCap(); got != 500000 {
		t.Fatalf("maxCap after Set(500000) = %d, want 500000 (nonzero tracks current down)", got)
	}
}

// F-044 review (spark-MINOR-17): grow is nil-safe like its sentCap/recvCap/
// maxCap siblings.
func TestGrowGuardCapSideNilSafe_9915(t *testing.T) {
	var ss *SessionSync
	if ss.growSentCap() || ss.growRecvCap() {
		t.Fatal("nil SessionSync grow reported growth (F-044 review)")
	}
}

// F-118 review (spark-MAJOR-8): the spec counts installs "outside int64
// range" — the predicate and clamp agree with it, including the offset-0
// case the uint64-overflow-only predicate missed.
func TestRebaseSaturateBeyondInt64_9915(t *testing.T) {
	huge := uint64(math.MaxInt64) + 1 // 2^63+1
	if !rebaseSaturates(huge, 0) {
		t.Fatal("rebaseSaturates(2^63+1, 0) = false, want true: outside int64 range (F-118 review)")
	}
	if got := rebaseTimestamp(huge, 0); got != math.MaxUint64 {
		t.Fatalf("rebaseTimestamp(2^63+1, 0) = %d, want saturated MaxUint64 (F-118 review)", got)
	}
	if rebaseSaturates(uint64(math.MaxInt64), 0) {
		t.Fatal("rebaseSaturates(MaxInt64, 0) = true, want false: in range (F-118 review)")
	}
	if got := rebaseTimestamp(100, 50); got != 150 {
		t.Fatalf("CONTROL: rebaseTimestamp(100, 50) = %d, want 150", got)
	}
}

// F-118 review (spark-MAJOR-8): the counter counts LANDED applies — a
// saturated install refused by the ordering guard must not count.
func TestRebaseSaturationCountsLandedOnly_9915(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 0x9918, DstPort: 80}
	key.SrcIP = [4]byte{192, 0, 2, 118}
	// Generation 9 lands first (small timestamps, no saturation).
	fresh := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		Created: 100, LastSeen: 100, Generation: 9}
	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, fresh))
	// Saturated (2^63+1, offset 0) but generation-stale: refused, uncounted.
	stale := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		Created: (uint64(1) << 63) + 1, LastSeen: (uint64(1) << 63) + 1, Generation: 1}
	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, stale))
	if got := ss.stats.RebaseSaturations.Load(); got != 0 {
		t.Fatalf("RebaseSaturations = %d, want 0: the saturated install was refused stale, never landed (F-118 review)", got)
	}
	if got := ss.stats.InstallsStaleIgnored.Load(); got != 1 {
		t.Fatalf("InstallsStaleIgnored = %d, want 1 (fixture: saturated install must refuse stale)", got)
	}
	got, ok := dp.v4sessions[key]
	if !ok {
		t.Fatal("fixture: the gen-9 install did not land")
	}
	if got.Created != 100 {
		t.Fatalf("landed Created = %d, want 100 (stale install must not regress the row)", got.Created)
	}
}

// F-118 review (gpt-Medium-3): a ClockSync frame already read off a conn that
// retires before publication must not republish the dead incarnation's
// offset. Disconnect variant: sync, disconnect (clears), redeliver same bytes.
func TestClockSyncRetiredConnDisconnectRejected_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.testClockNow = func() uint64 { return 1000000 }
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	ac := &authConn{Conn: local}
	ss.installConn(0, ac)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 900000) // offset +100000
	ss.handleMessage(ac, syncMsgClockSync, buf[:])
	if got := ss.peerClockOffset.Load(); got != 100000 {
		t.Fatalf("FIXTURE: offset = %d, want +100000", got)
	}
	ss.handleDisconnect(ac)
	if got := ss.peerClockOffset.Load(); got != 0 {
		t.Fatalf("FIXTURE: offset = %d after disconnect, want 0", got)
	}
	// The already-read frame resumes after retirement: must drop.
	ss.handleMessage(ac, syncMsgClockSync, buf[:])
	if got := ss.peerClockOffset.Load(); got != 0 {
		t.Fatalf("peerClockOffset = %d after redelivering on a retired conn, want 0 (F-118 review)", got)
	}
	// A replacement conn falls back to the cleared global, not the retired value.
	local2, remote2 := net.Pipe()
	defer local2.Close()
	defer remote2.Close()
	ac2 := &authConn{Conn: local2}
	ss.installConn(0, ac2)
	if got := ss.clockOffsetFor(ac2); got != 0 {
		t.Fatalf("replacement clockOffsetFor = %d, want 0 (F-118 review)", got)
	}
}

// F-118 review (gpt-Medium-3): supersession variant — an incarnation switch
// evicts the conn; its in-flight ClockSync must not republish.
func TestClockSyncRetiredConnSwitchRejected_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.testClockNow = func() uint64 { return 1000000 }
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	ss.installConn(1, ac1)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 900000)
	ss.handleMessage(ac0, syncMsgClockSync, buf[:])
	if got := ss.peerClockOffset.Load(); got != 100000 {
		t.Fatalf("FIXTURE: offset = %d, want +100000", got)
	}
	// Incarnation switch keeping fabric 1: evicts fabric 0, clears global.
	ss.mu.Lock()
	ss.applyPeerIncarnationSwitchLocked(1)
	ss.mu.Unlock()
	if got := ss.peerClockOffset.Load(); got != 0 {
		t.Fatalf("FIXTURE: offset = %d after switch, want 0", got)
	}
	ss.handleMessage(ac0, syncMsgClockSync, buf[:])
	if got := ss.peerClockOffset.Load(); got != 0 {
		t.Fatalf("peerClockOffset = %d after redelivering on an evicted conn, want 0 (F-118 review)", got)
	}
}

// F-118 review (spark-MAJOR-7): incarnation advance clears the kept
// connection's per-conn offset too — clockOffsetFor must fall back to the
// cleared global, not the dead incarnation's offset. Asserts the replacement
// path, not just the global.
func TestClockOffsetPerConnClearedOnSwitch_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.testClockNow = func() uint64 { return 1000000 }
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	ss.installConn(1, ac1)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 900000)
	ss.handleMessage(ac1, syncMsgClockSync, buf[:])
	if off, synced := ac1.clockOffset.Load(), ac1.clockSynced.Load(); !synced || off != 100000 {
		t.Fatalf("FIXTURE: kept conn offset = %d synced=%v, want 100000 true", off, synced)
	}
	ss.mu.Lock()
	ss.applyPeerIncarnationSwitchLocked(1)
	ss.mu.Unlock()
	if ac1.clockSynced.Load() {
		t.Fatal("kept conn still synced after incarnation switch (F-118 review)")
	}
	if got := ss.clockOffsetFor(ac1); got != 0 {
		t.Fatalf("clockOffsetFor(kept) = %d, want 0 fallback to cleared global (F-118 review)", got)
	}
}

// F-043 review (spark-MAJOR-11): a corrupt cluster id diverges prologues
// exactly like a bad node id — rejected loud at identity resolution. The
// schema bounds cluster-id to 0..255 (one RETH MAC byte).
func TestSyncNoiseIdentityRejectsBadClusterId_9915(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	for _, cluster := range []int{-1, 256, 1 << 30} {
		s := NewSessionSync(":0", ":0", nil)
		s.SetAuthProvider(&fakeSyncAuthProvider{key: key, node: 0, cluster: cluster})
		if _, err := s.newSyncNoiseState(key, true, syncNoisePhaseConnect, 0); err == nil {
			t.Errorf("cluster id %d: newSyncNoiseState succeeded, want a loud identity error (F-043 review)", cluster)
		} else if !strings.Contains(err.Error(), "cluster") {
			t.Errorf("cluster id %d: error %q does not name the cluster identity", cluster, err)
		}
	}
	for _, cluster := range []int{0, 22, 255} {
		s := NewSessionSync(":0", ":0", nil)
		s.SetAuthProvider(&fakeSyncAuthProvider{key: key, node: 0, cluster: cluster})
		if _, err := s.newSyncNoiseState(key, true, syncNoisePhaseConnect, 0); err != nil {
			t.Errorf("CONTROL: cluster id %d must still handshake, got %v", cluster, err)
		}
	}
}

// F-043 review (spark-MAJOR-11): identity failures in the upgrade-role path
// are counted centrally (all three callers inherit), so a bad node/cluster id
// is operator-visible instead of silently leave-as-is.
func TestUpgradeRoleIdentityErrorCounted_9915(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	bad := newAuthSyncNode(t, key, 5)
	if _, err := bad.upgradeRoleIsInitiator(); err == nil {
		t.Fatal("bad node id: upgradeRoleIsInitiator succeeded, want an identity error")
	}
	if got := bad.Stats().AuthUpgradeIdentityErrors; got != 1 {
		t.Fatalf("Stats().AuthUpgradeIdentityErrors = %d, want 1 (F-043 review)", got)
	}
	good := newAuthSyncNode(t, key, 0)
	if _, err := good.upgradeRoleIsInitiator(); err != nil {
		t.Fatalf("CONTROL: valid identity must resolve role, got %v", err)
	}
	if got := good.Stats().AuthUpgradeIdentityErrors; got != 0 {
		t.Fatalf("CONTROL: counter = %d, want 0", got)
	}
}

// F-117 review (spark-MAJOR-12): an injected all-bad high-seq set is retained
// WITHOUT advancing the mark, so an honest lower-seq push still applies. No
// legacy bypass exists: every decoded set is filtered (see the F-117 drops
// test); the wedge closes via mark-after-apply.
func TestDHCPHighSeqAllBadDoesNotWedgeHonestPush_9915(t *testing.T) {
	good := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:05",
		SubnetID: 1, ValidLife: 3600, Remaining: 1800}
	bad1 := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.9",
		SubnetID: 1, ValidLife: 3600, Remaining: 1800}
	bad2 := dhcpserver.SyncLease{Family: 6, Address: "2001:db8::9", DUID: "00:01:xx",
		LeaseType: "IA_NA", SubnetID: 2, ValidLife: 3600, Remaining: 1800}
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var got []dhcpserver.SyncLease
	ss.OnDHCPLeasesReceived = func(_ int, leases []dhcpserver.SyncLease) { got = leases }
	// Injected: trailered all-bad set at a high seq. Retained, mark unmoved.
	ss.handleMessage(nil, syncMsgDHCPLeaseV4,
		appendFullSetSeq(encodeDHCPLeasePayload([]dhcpserver.SyncLease{bad1, bad2}), 7, 100))
	if held := ss.PeerDHCPLeases4(); len(held) != 0 {
		t.Fatalf("injected all-bad set held %d leases, want 0 retained-empty", len(held))
	}
	if got := ss.Stats().DHCPLeasesDroppedNoIdentity; got != 2 {
		t.Fatalf("DHCPLeasesDroppedNoIdentity = %d, want 2", got)
	}
	// Honest lower-seq push still applies: the mark never wedged.
	ss.handleMessage(nil, syncMsgDHCPLeaseV4,
		appendFullSetSeq(encodeDHCPLeasePayload([]dhcpserver.SyncLease{good}), 7, 50))
	if len(got) != 1 || got[0].Address != "10.0.0.5" {
		t.Fatalf("honest lower-seq push applied %d leases (%v), want the good lease: mark wedged (F-117 review)", len(got), got)
	}
	ss.recvSeqMu.Lock()
	inc, seq := ss.dhcpV4RecvSeq.incarnation, ss.dhcpV4RecvSeq.seq
	ss.recvSeqMu.Unlock()
	if inc != 7 || seq != 50 {
		t.Fatalf("guard mark = (%d,%d), want (7,50): the retained set must not advance it", inc, seq)
	}
}

// F-117 review (blocker advisory): duplicate-fabric twins racing through the
// atomic commit must converge on the higher-seq set in BOTH the held set and
// the callback order — never [B,A], never a stale held set. Probabilistic RED
// pre-commit (the interleaving must land); deterministic GREEN post-commit.
func TestDHCPConcurrentSetsConvergeOnNewer_9915(t *testing.T) {
	mkLease := func(addr string) dhcpserver.SyncLease {
		return dhcpserver.SyncLease{Family: 4, Address: addr, HWAddress: "aa:bb:cc:dd:ee:01",
			SubnetID: 1, ValidLife: 3600, Remaining: 1800}
	}
	for i := 0; i < 50; i++ {
		ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
		var mu sync.Mutex
		var calls []string
		ss.OnDHCPLeasesReceived = func(_ int, leases []dhcpserver.SyncLease) {
			mu.Lock()
			defer mu.Unlock()
			if len(leases) == 1 {
				calls = append(calls, leases[0].Address)
			} else {
				calls = append(calls, "BADLEN")
			}
		}
		payloadA := appendFullSetSeq(encodeDHCPLeasePayload([]dhcpserver.SyncLease{mkLease("10.0.0.10")}), 9, 20)
		payloadB := appendFullSetSeq(encodeDHCPLeasePayload([]dhcpserver.SyncLease{mkLease("10.0.0.11")}), 9, 21)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; ss.handleMessage(nil, syncMsgDHCPLeaseV4, payloadA) }()
		go func() { defer wg.Done(); <-start; ss.handleMessage(nil, syncMsgDHCPLeaseV4, payloadB) }()
		close(start)
		wg.Wait()
		held := ss.PeerDHCPLeases4()
		if len(held) != 1 || held[0].Address != "10.0.0.11" {
			t.Fatalf("iter %d: held set = %v, want the seq-21 set (regressed)", i, held)
		}
		mu.Lock()
		got := append([]string(nil), calls...)
		mu.Unlock()
		if len(got) == 1 && got[0] == "10.0.0.11" {
			continue // B committed first; A lost advanceIfNewer. Correct.
		}
		if len(got) == 2 && got[0] == "10.0.0.10" && got[1] == "10.0.0.11" {
			continue // A committed first, B superseded. Correct.
		}
		t.Fatalf("iter %d: callback sequence = %v, want [B] or [A B] (never stale-after-fresh)", i, got)
	}
}

// F-118 review (spark-MAJOR-6): a saturated Created (MaxUint64) must not
// re-queue every sweep — it was installed once via its delta and never ages
// into the window. Honest-queues direction is pinned by the 9752 sweep tests.
func TestSweepSkipsSaturatedCreated_9915(t *testing.T) {
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 9, 9}, DstIP: [4]byte{10, 0, 9, 10},
		Protocol: 6, SrcPort: 9000, DstPort: 80}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {State: dataplane.SessStateEstablished, Created: math.MaxUint64, SessionID: 9915, RTFlowSessionID: 9915},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = 0 // threshold 0: recency alone would queue everything
	ss.syncSweep()
	if got := len(ss.sendCh); got != 0 {
		t.Fatalf("sweep queued %d frames for a saturated-Created session; MaxUint64 must never re-queue (F-118 review)", got)
	}
}

// waitForFenceFrame9915 blocks until the peer end observes the fence frame
// SendFenceAwait wrote — which proves the waiter is registered (registration
// precedes the write), unlike polling fenceSeq (allocated before
// registration). A pre-registration disruption aborts nothing even on broken
// code and fakes green (gpt-Medium-4a); the observed frame closes the escape.
func waitForFenceFrame9915(t *testing.T, peer net.Conn) (uint8, []byte) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("FIXTURE: set read deadline: %v", err)
	}
	typ, payload, err := readSyncFrameRaw(peer)
	if err != nil {
		t.Fatalf("FIXTURE: SendFenceAwait never wrote its fence frame: %v", err)
	}
	if typ != syncMsgFence {
		t.Fatalf("FIXTURE: first frame type = %d, want syncMsgFence (%d)", typ, syncMsgFence)
	}
	return typ, payload
}

// F-116 review (spark-MAJOR-9): the scoping premise, pinned behaviorally —
// the fence-receive arm answers with sendFenceAck on the conn that carried
// the fence, so a waiter's ack path is exactly its own fabric.
func TestFenceAckAnswersOnReceivingConn_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	f0a, f0b := net.Pipe()
	defer f0a.Close()
	defer f0b.Close()
	f1a, f1b := net.Pipe()
	defer f1a.Close()
	defer f1b.Close()
	ss.installConn(0, f0a)
	ss.installConn(1, f1a)
	ss.OnFenceReceived = func() FenceResult { return FenceResult{} }
	const wantSeq = 77
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], wantSeq)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ss.handleMessage(f0a, syncMsgFence, payload[:])
	}()
	if err := f0b.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("FIXTURE: set read deadline: %v", err)
	}
	typ, ackPayload, err := readSyncFrameRaw(f0b)
	if err != nil {
		t.Fatalf("fence received on fab0 was not answered on fab0: %v (F-116)", err)
	}
	if typ != syncMsgFenceAck {
		t.Fatalf("answer frame type = %d, want syncMsgFenceAck (%d) (F-116)", typ, syncMsgFenceAck)
	}
	ack, ok := decodeFenceAckPayload(ackPayload)
	if !ok {
		t.Fatal("answer frame did not decode as a fence ack (F-116)")
	}
	if ack.Seq != wantSeq {
		t.Fatalf("answer seq = %d, want %d (F-116)", ack.Seq, wantSeq)
	}
	<-done
}

// Fold-2 HIGH-1: production order ClockSync → changed-BulkStart → session
// preserves the kept conn's offset. handleNewConnection sends ClockSync
// BEFORE the cold-prime bulk, and ClockSync is never re-sent — so a
// replacement installed pre-evidence gets its ClockSync ACCEPTED, and when
// its BulkStart triggers the switch that offset is new-boot truth learned
// seconds ago, not dead-boot state. Erasing it rebases new-boot sessions
// with 0 unboundedly (no re-sync trigger exists). RED against blanket
// clearing; GREEN via provenance-preserving switch.
func TestClockOffsetPreservedOnPrimedSwitch_9915(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.testClockNow = func() uint64 { return 1000000 }
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	// Old boot A primes on the OLD conn first (production order: the recorded
	// boot predates the replacement's arrival, so its BulkStart is what makes
	// the replacement's prime a *changed* boot id).
	incA := incarnation6910(0xA1)
	ss.handleMessage(ac0, syncMsgBulkStart, bulkStartPayload6910(1, incA))
	// Replacement installed pre-evidence (empty slot, no advance), then its
	// ClockSync is ACCEPTED — offset +100000 from the NEW boot.
	ss.installConn(1, ac1)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 900000)
	ss.handleMessage(ac1, syncMsgClockSync, buf[:])
	if got := ss.peerClockOffset.Load(); got != 100000 {
		t.Fatalf("FIXTURE: offset = %d, want +100000", got)
	}
	// The replacement's FIRST BulkStart carries the new boot id and triggers
	// the switch keeping fabric 1.
	incB := incarnation6910(0xB2)
	if incB == incA {
		t.Fatal("FIXTURE: boot ids must differ")
	}
	ss.handleMessage(ac1, syncMsgBulkStart, bulkStartPayload6910(2, incB))
	// Prove the switch fired (else preservation below is vacuous).
	ss.mu.Lock()
	inc, c0, c1 := ss.peerIncarnation, ss.conn0, ss.conn1
	ss.mu.Unlock()
	if inc != 1 {
		t.Fatalf("FIXTURE: peerIncarnation = %d, want 1 (switch did not fire)", inc)
	}
	if c0 != nil {
		t.Fatal("FIXTURE: fabric 0 not evicted by the switch")
	}
	if c1 != ac1 {
		t.Fatal("FIXTURE: fabric 1 does not hold the priming conn")
	}
	// The fresh offset survives: per-conn, global fallback, and the session.
	if got := ss.clockOffsetFor(ac1); got != 100000 {
		t.Fatalf("clockOffsetFor(kept) = %d, want preserved +100000 (HIGH-1)", got)
	}
	if got := ss.peerClockOffset.Load(); got != 100000 {
		t.Fatalf("peerClockOffset = %d, want preserved +100000 (HIGH-1)", got)
	}
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 0x9917, DstPort: 80}
	key.SrcIP = [4]byte{192, 0, 2, 118}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		Created: 100, LastSeen: 100}
	ss.handleMessage(ac1, syncMsgSessionV4, encodeSessionV4Payload(key, val))
	got, ok := dp.v4sessions[key]
	if !ok {
		t.Fatal("session on kept conn did not land after switch")
	}
	if got.Created != 100100 || got.LastSeen != 100100 {
		t.Fatalf("installed Created/LastSeen = %d/%d, want 100100/100100 (offset erased — HIGH-1)", got.Created, got.LastSeen)
	}
}

// Fold-2 HIGH-2: a DHCP commit spanning a receiver reset must die, not
// resurrect the dead boot's high-water over the replacement's. Deterministic
// interleave via testDHCPPreCommit: old-boot set pauses pre-commit, the main
// goroutine resets + applies the replacement, the old handler resumes into
// an epoch mismatch. No sleeps; channel-orchestrated (the hook rendezvous
// also gives -race its happens-before edges).
func TestDHCPCommitSpanningResetIsDropped_9915(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	mkLease := func(addr string) dhcpserver.SyncLease {
		return dhcpserver.SyncLease{Family: 4, Address: addr, HWAddress: "aa:bb:cc:dd:ee:01",
			SubnetID: 1, ValidLife: 3600, Remaining: 1800}
	}
	oldPayload := appendFullSetSeq(encodeDHCPLeasePayload([]dhcpserver.SyncLease{mkLease("10.0.0.10")}), 9000, 20)
	newPayload := appendFullSetSeq(encodeDHCPLeasePayload([]dhcpserver.SyncLease{mkLease("10.0.0.11")}), 100, 1)
	reached := make(chan struct{}, 1)
	resume := make(chan struct{})
	ss.testDHCPPreCommit = func() {
		select {
		case reached <- struct{}{}:
		default: // single-fire: only the first commit attempt pauses
		}
		<-resume
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ss.handleMessage(nil, syncMsgDHCPLeaseV4, oldPayload)
	}()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("old-boot handler never reached pre-commit")
	}
	// Interleaving: reset + replacement apply fully while old handler waits.
	// Nil-ing the hook past first fire keeps the replacement synchronous.
	ss.resetRecvGen()
	ss.testDHCPPreCommit = nil
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, newPayload)
	if held := ss.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != "10.0.0.11" {
		t.Fatalf("FIXTURE: replacement did not apply cleanly: %v", held)
	}
	close(resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("old-boot handler never resumed")
	}
	// Old commit must have died on the epoch fence: held set + mark intact.
	if held := ss.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != "10.0.0.11" {
		t.Fatalf("held set = %v, want replacement: old-boot commit resurrected across reset (HIGH-2)", held)
	}
	ss.recvSeqMu.Lock()
	inc, seq := ss.dhcpV4RecvSeq.incarnation, ss.dhcpV4RecvSeq.seq
	ss.recvSeqMu.Unlock()
	if inc != 100 || seq != 1 {
		t.Fatalf("guard mark = (%d,%d), want (100,1): dead high-water restored (HIGH-2)", inc, seq)
	}
	if got := ss.Stats().DHCPLeasesStaleIgnored; got != 1 {
		t.Fatalf("DHCPLeasesStaleIgnored = %d, want 1 (fenced commit must count as stale)", got)
	}
}
