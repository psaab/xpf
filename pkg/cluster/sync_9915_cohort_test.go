package cluster

import (
	"encoding/binary"
	"math"
	"net"
	"strings"
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
	want := conntrack.MaxSessions / 2
	if genGuardMapCap < want {
		t.Fatalf("genGuardMapCap = %d, want >= %d (conntrack.MaxSessions/2 forward entries); "+
			"a table past the cap degrades every new session to gen-0 (F-044)", genGuardMapCap, want)
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

	// Drain the fence frame the SENd path writes on fab0.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, _, err := readSyncFrameRaw(f0b); err != nil {
				return
			}
		}
	}()

	type fenceOutcome struct {
		ack FenceAck
		err error
	}
	out := make(chan fenceOutcome, 1)
	go func() {
		ack, err := ss.SendFenceAwait(3 * time.Second)
		out <- fenceOutcome{ack: ack, err: err}
	}()

	dl := time.Now().Add(2 * time.Second)
	for ss.fenceSeq.Load() == 0 {
		if time.Now().After(dl) {
			t.Fatal("FIXTURE: SendFenceAwait never registered its waiter")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The idle fabric flaps while the fence is outstanding on fab0.
	ss.handleDisconnect(f1a)

	select {
	case got := <-out:
		t.Fatalf("an idle-fabric flap aborted the confirmed fence (err=%v); "+
			"the ack path is healthy and the fence must survive (F-116)", got.err)
	case <-time.After(150 * time.Millisecond):
	}

	// The peer answers on the healthy path; the fence must confirm.
	seq := ss.fenceSeq.Load()
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
	go func() {
		for {
			if _, _, err := readSyncFrameRaw(f0b); err != nil {
				return
			}
		}
	}()

	out := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(3 * time.Second)
		out <- err
	}()
	dl := time.Now().Add(2 * time.Second)
	for ss.fenceSeq.Load() == 0 {
		if time.Now().After(dl) {
			t.Fatal("FIXTURE: SendFenceAwait never registered its waiter")
		}
		time.Sleep(5 * time.Millisecond)
	}

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
	peerMono := monotonicSeconds() / 2
	if peerMono < 1 {
		peerMono = 1
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], peerMono)
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
	peerMono := monotonicSeconds() / 2
	if peerMono < 1 {
		peerMono = 1
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], peerMono)
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
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], peerMono)
		ss.handleMessage(nil, syncMsgClockSync, buf[:])
	}
	local := monotonicSeconds()

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
	go func() {
		for {
			if _, _, err := readSyncFrameRaw(f0b); err != nil {
				return
			}
		}
	}()
	out := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(3 * time.Second)
		out <- err
	}()
	dl := time.Now().Add(2 * time.Second)
	for ss.fenceSeq.Load() == 0 {
		if time.Now().After(dl) {
			t.Fatal("FIXTURE: SendFenceAwait never registered its waiter")
		}
		time.Sleep(5 * time.Millisecond)
	}

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
	go func() {
		for {
			if _, _, err := readSyncFrameRaw(f0b); err != nil {
				return
			}
		}
	}()
	out := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(3 * time.Second)
		out <- err
	}()
	dl := time.Now().Add(2 * time.Second)
	for ss.fenceSeq.Load() == 0 {
		if time.Now().After(dl) {
			t.Fatal("FIXTURE: SendFenceAwait never registered its waiter")
		}
		time.Sleep(5 * time.Millisecond)
	}

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
