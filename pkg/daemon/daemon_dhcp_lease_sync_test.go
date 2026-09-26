package daemon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #2239 daemon-level tests: the node-level MASTER gate, the takeover-seed
// orchestration (standby-hold → lease{4,6}-add), the config knob gate, and the
// change-detect (on-grant) push fingerprint.

// stubKeaServer is a minimal Kea control-socket server for the seed test: it
// records lease{4,6}-add commands and answers success.
type stubKeaServer struct {
	mu  sync.Mutex
	cmd []string
	add []map[string]any
}

func (s *stubKeaServer) start(t *testing.T, path string) func() {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req struct {
					Command   string         `json:"command"`
					Arguments map[string]any `json:"arguments"`
				}
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				s.mu.Lock()
				s.cmd = append(s.cmd, req.Command)
				if req.Command == "lease4-add" || req.Command == "lease6-add" {
					s.add = append(s.add, req.Arguments)
				}
				s.mu.Unlock()
				_, _ = c.Write([]byte(`{"result":0,"text":"ok"}`))
			}(c)
		}
	}()
	return func() { ln.Close() }
}

func (s *stubKeaServer) adds() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, len(s.add))
	copy(out, s.add)
	return out
}

func shortTmpSocket(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func unixDialer() func(ctx context.Context, path string) (net.Conn, error) {
	return func(ctx context.Context, path string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
}

// leaseSyncTestDaemon builds a cluster daemon committing a DHCP-server config
// with the dhcp-lease-synchronization knob, a dhcpServer pointed at a stub Kea
// socket, and a SessionSync.
func leaseSyncTestDaemon(t *testing.T, sock4, sock6 string, withKnob bool) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	set := "set chassis cluster cluster-id 1\n" +
		"set chassis cluster node 0\n" +
		"set chassis cluster authentication-key test-cluster-psk-6611\n" +
		"set system services dhcp-local-server group g1 interface ge-0/0/1.0\n" +
		"set system services dhcp-local-server group g1 dhcp-attributes subnet 10.0.61.0/24\n" +
		"set system services dhcpv6-local-server group g6 interface ge-0/0/1.0\n"
	if withKnob {
		set += "set chassis cluster dhcp-lease-synchronization\n"
	}
	if _, err := s.LoadSet(set); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	mgr := dhcpserver.New()
	mgr.SetLeaseSyncSeamsForTesting(unixDialer(), sock4, sock6, "", "")
	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)

	d := &Daemon{
		store:         s,
		applySem:      semaphore.NewWeighted(1),
		rgStates:      make(map[int]*rgStateMachine),
		cluster:       cluster.NewManager(0, 1),
		dhcpServer:    mgr,
		sessionSync:   ss,
		dhcpLeaseSync: dhcpLeaseSyncState{nowCh: make(chan struct{}, 1)},
	}
	return d
}

func TestDHCPLeaseSyncGateStandaloneClosed(t *testing.T) {
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	if d.dhcpLeaseSyncGateOpen() {
		t.Fatal("standalone node must never push leases (gate closed)")
	}
}

func TestDHCPLeaseSyncGateMasterOpen(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	d.getOrCreateRGState(1).SetCluster(false)
	d.getOrCreateRGState(2).SetCluster(true)
	if !d.dhcpLeaseSyncGateOpen() {
		t.Fatal("a node MASTER for >=1 RG must push (gate open)")
	}
}

func TestDHCPLeaseSyncGateBackupClosed(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	d.getOrCreateRGState(1).SetCluster(false)
	if d.dhcpLeaseSyncGateOpen() {
		t.Fatal("BACKUP-for-all node must not push (gate closed)")
	}
}

// Config-knob gate: dhcpLeaseSyncEnabled true only when the knob is set.
func TestDHCPLeaseSyncEnabledKnobGate(t *testing.T) {
	withKnob := leaseSyncTestDaemon(t, "/tmp/x4", "/tmp/x6", true)
	if !withKnob.dhcpLeaseSyncEnabled(withKnob.store.ActiveConfig()) {
		t.Error("knob set → lease sync enabled")
	}
	without := leaseSyncTestDaemon(t, "/tmp/x4", "/tmp/x6", false)
	if without.dhcpLeaseSyncEnabled(without.store.ActiveConfig()) {
		t.Error("knob absent → lease sync disabled")
	}
	// Standalone (no cluster manager) → always disabled.
	without.cluster = nil
	if without.dhcpLeaseSyncEnabled(without.store.ActiveConfig()) {
		t.Error("standalone → lease sync disabled regardless of knob")
	}
}

// Takeover seed: the standby holds peer leases; seedDHCPLeasesFromPeer writes
// the right lease4-add/lease6-add with a local-clock re-anchored expiry.
func TestSeedDHCPLeasesFromPeer(t *testing.T) {
	sock4 := shortTmpSocket(t, "k4.sock")
	sock6 := shortTmpSocket(t, "k6.sock")
	stub := &stubKeaServer{}
	stop4 := stub.start(t, sock4)
	defer stop4()
	stop6 := stub.start(t, sock6)
	defer stop6()

	d := leaseSyncTestDaemon(t, sock4, sock6, true)

	// Standby holds peer leases (would arrive over the sync channel).
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.61.50", HWAddress: "aa:bb:cc:dd:ee:01",
			SubnetID: 1, Remaining: 1800, PreferredRemaining: 1800, State: 0},
	})
	d.sessionSync.SetPeerDHCPLeasesForTesting(6, []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8::100", DUID: "00:01:00:01", IAID: 9,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 2400, PreferredRemaining: 2400, State: 0},
	})

	d.seedDHCPLeasesFromPeer(context.Background())

	adds := stub.adds()
	if len(adds) != 2 {
		t.Fatalf("expected 2 lease-add (v4+v6), got %d: %+v", len(adds), adds)
	}
	// Seeded counter incremented.
	if got := d.sessionSync.Stats().DHCPLeasesSeeded; got != 2 {
		t.Errorf("DHCPLeasesSeeded = %d, want 2", got)
	}
	// Find the v4 add and check the re-anchored fields.
	var v4 map[string]any
	for _, a := range adds {
		if a["ip-address"] == "10.0.61.50" {
			v4 = a
		}
	}
	if v4 == nil {
		t.Fatalf("v4 lease-add not seen: %+v", adds)
	}
	if vl, _ := v4["valid-lft"].(float64); int(vl) != 1800 {
		t.Errorf("v4 valid-lft = %v, want 1800 (remaining)", v4["valid-lft"])
	}
	// expire must be ~now+1800 on the LOCAL clock (within a few seconds).
	exp, _ := v4["expire"].(float64)
	want := time.Now().Unix() + 1800
	if d := int64(exp) - want; d < -5 || d > 5 {
		t.Errorf("v4 expire = %d, want ~%d (local re-anchor)", int64(exp), want)
	}
}

// Takeover seed is a no-op when the knob is off (standby holds nothing useful
// and the feature is disabled).
func TestSeedDHCPLeasesFromPeer_KnobOff(t *testing.T) {
	sock4 := shortTmpSocket(t, "k4.sock")
	stub := &stubKeaServer{}
	defer stub.start(t, sock4)()
	d := leaseSyncTestDaemon(t, sock4, sock4, false /* no knob */)
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.61.50", HWAddress: "a", SubnetID: 1, Remaining: 60},
	})
	d.seedDHCPLeasesFromPeer(context.Background())
	if len(stub.adds()) != 0 {
		t.Fatalf("knob off must not seed: %+v", stub.adds())
	}
}

// pushDHCPLeasesOnce is gated: a BACKUP-for-all node reads and pushes nothing.
func TestPushDHCPLeasesGatedBackup(t *testing.T) {
	sock4 := shortTmpSocket(t, "k4.sock")
	stub := &stubKeaServer{}
	defer stub.start(t, sock4)()
	d := leaseSyncTestDaemon(t, sock4, sock4, true)
	d.getOrCreateRGState(1).SetCluster(false) // BACKUP
	d.pushDHCPLeasesOnce(context.Background(), true)
	// Gate closed → no Kea read at all (no get-all command).
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.cmd {
		if c == "lease4-get-all" {
			t.Fatal("BACKUP node must not read/push leases")
		}
	}
}

// Change-detect fingerprint: identical sets (ignoring the per-second Remaining
// countdown) produce equal fingerprints; an added lease changes it.
func TestDHCPLeaseSetFingerprint(t *testing.T) {
	a := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.1", HWAddress: "m", ValidLife: 3600, Remaining: 3000, Hostname: "h"},
	}
	b := []dhcpserver.SyncLease{
		// same lease, lower Remaining (countdown) → SAME fingerprint.
		{Family: 4, Address: "10.0.0.1", HWAddress: "m", ValidLife: 3600, Remaining: 2999, Hostname: "h"},
	}
	if dhcpLeaseSetFingerprint(a) != dhcpLeaseSetFingerprint(b) {
		t.Error("Remaining countdown must NOT change the fingerprint")
	}
	c := append([]dhcpserver.SyncLease{}, a...)
	c = append(c, dhcpserver.SyncLease{Family: 4, Address: "10.0.0.2", HWAddress: "n", ValidLife: 3600, Remaining: 3600})
	if dhcpLeaseSetFingerprint(a) == dhcpLeaseSetFingerprint(c) {
		t.Error("a new lease MUST change the fingerprint (on-grant push trigger)")
	}
	if dhcpLeaseSetFingerprint(nil) != "" {
		t.Error("empty set fingerprint must be empty")
	}
}

// TestDHCPLeaseSetFingerprintSeedConsumedFields10894 pins #10894: the change
// fingerprint covered IdentityKey+ValidLife+Hostname only, so seed-consumed
// field changes (SubnetID, PrefixLen, FQDN flags, a v4 HWAddress move under a
// stable ClientID) produced identical fingerprints and the ~2s change push
// never fired — the standby held stale bindings until the 30s forced
// heartbeat, and a failover inside that window seeded them. Every
// seed-consumed field flip MUST change the fingerprint (triggering the push);
// the per-second countdowns MUST NOT (else every poll looks like a change).
func TestDHCPLeaseSetFingerprintSeedConsumedFields10894(t *testing.T) {
	baseV4 := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.1", SubnetID: 1,
		HWAddress: "aa:bb:cc:dd:ee:01", ClientID: "01:aa:bb:cc:dd:ee:01",
		Hostname: "h", ValidLife: 3600, Remaining: 3000, PreferredRemaining: 3000}
	baseV6 := dhcpserver.SyncLease{Family: 6, Address: "2001:db8::1", SubnetID: 2,
		DUID: "00:01:02:03", IAID: 7, LeaseType: "IA_PD", PrefixLen: 56,
		HWAddress: "aa:bb:cc:dd:ee:02", Hostname: "h6",
		ValidLife: 3600, Remaining: 3000, PreferredRemaining: 3000}

	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	changePushTriggered := func(base, mutated dhcpserver.SyncLease) bool {
		d := &Daemon{sessionSync: ss, dhcpLeaseSync: dhcpLeaseSyncState{}}
		family := base.Family
		snapshot := func(lease dhcpserver.SyncLease) dhcpserver.LeaseSyncSnapshot {
			return dhcpserver.LeaseSyncSnapshot{Leases: []dhcpserver.SyncLease{lease}, Received: true}
		}
		d.maybePushFamily(family, snapshot(base), false)
		lastBefore := d.dhcpLeaseSync.lastSent4
		if family == 6 {
			lastBefore = d.dhcpLeaseSync.lastSent6
		}
		d.maybePushFamily(family, snapshot(mutated), false)
		lastAfter := d.dhcpLeaseSync.lastSent4
		if family == 6 {
			lastAfter = d.dhcpLeaseSync.lastSent6
		}
		return lastBefore != lastAfter
	}

	mustChange := []struct {
		name   string
		v6     bool
		mutate func(*dhcpserver.SyncLease)
	}{
		{"Family", false, func(l *dhcpserver.SyncLease) { l.Family = 6 }},
		{"v4 Address", false, func(l *dhcpserver.SyncLease) { l.Address = "10.0.0.2" }},
		{"v4 SubnetID", false, func(l *dhcpserver.SyncLease) { l.SubnetID = 2 }},
		{"v4 HWAddress under stable ClientID", false, func(l *dhcpserver.SyncLease) {
			l.HWAddress = "aa:bb:cc:dd:ee:ff"
		}},
		{"v4 ClientID under stable HWAddress", false, func(l *dhcpserver.SyncLease) {
			l.ClientID = "01:aa:bb:cc:dd:ee:ff"
		}},
		{"v4 Hostname", false, func(l *dhcpserver.SyncLease) { l.Hostname = "h2" }},
		{"v4 FQDNFwd", false, func(l *dhcpserver.SyncLease) { l.FQDNFwd = true }},
		{"v4 FQDNRev", false, func(l *dhcpserver.SyncLease) { l.FQDNRev = true }},
		{"v4 ValidLife", false, func(l *dhcpserver.SyncLease) { l.ValidLife = 7200 }},
		{"v6 Address", true, func(l *dhcpserver.SyncLease) { l.Address = "2001:db8::2" }},
		{"v6 SubnetID", true, func(l *dhcpserver.SyncLease) { l.SubnetID = 3 }},
		{"v6 HWAddress", true, func(l *dhcpserver.SyncLease) {
			l.HWAddress = "aa:bb:cc:dd:ee:ff"
		}},
		{"v6 DUID", true, func(l *dhcpserver.SyncLease) { l.DUID = "00:01:02:04" }},
		{"v6 IAID", true, func(l *dhcpserver.SyncLease) { l.IAID = 8 }},
		{"v6 LeaseType", true, func(l *dhcpserver.SyncLease) { l.LeaseType = "IA_NA" }},
		{"v6 PrefixLen", true, func(l *dhcpserver.SyncLease) { l.PrefixLen = 60 }},
		{"v6 Hostname", true, func(l *dhcpserver.SyncLease) { l.Hostname = "h6-2" }},
		{"v6 FQDNFwd", true, func(l *dhcpserver.SyncLease) { l.FQDNFwd = true }},
		{"v6 FQDNRev", true, func(l *dhcpserver.SyncLease) { l.FQDNRev = true }},
		{"v6 ValidLife", true, func(l *dhcpserver.SyncLease) { l.ValidLife = 7200 }},
	}
	for _, tc := range mustChange {
		base := baseV4
		if tc.v6 {
			base = baseV6
		}
		mutated := base
		tc.mutate(&mutated)
		if !changePushTriggered(base, mutated) {
			t.Errorf("%s flip MUST trigger the change-push decision", tc.name)
		}
	}

	mustNotChange := []struct {
		name   string
		mutate func(*dhcpserver.SyncLease)
	}{
		{"Remaining countdown", func(l *dhcpserver.SyncLease) { l.Remaining = 2999 }},
		{"PreferredRemaining countdown", func(l *dhcpserver.SyncLease) { l.PreferredRemaining = 2999 }},
		// State is not seed-consumed: the read path only yields active leases
		// and the seed always writes default, so it stays out of the fingerprint.
		{"State", func(l *dhcpserver.SyncLease) { l.State = 1 }},
	}
	for _, tc := range mustNotChange {
		for _, base := range []dhcpserver.SyncLease{baseV4, baseV6} {
			mutated := base
			tc.mutate(&mutated)
			if changePushTriggered(base, mutated) {
				t.Errorf("%s MUST NOT trigger a change push (family %d)", tc.name, base.Family)
			}
		}
	}

	// Order-stability control: the fingerprint is a SET digest, so row order
	// must not matter (else a Kea get-all reorder would fake a change).
	fwd := dhcpLeaseSetFingerprint([]dhcpserver.SyncLease{baseV4, baseV6})
	rev := dhcpLeaseSetFingerprint([]dhcpserver.SyncLease{baseV6, baseV4})
	if fwd != rev {
		t.Error("lease order MUST NOT change the fingerprint")
	}
}
