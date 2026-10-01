package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/snmp"
	"github.com/psaab/xpf/pkg/vrrp"
)

// snmpDowngradeConfig returns a compiled config whose only SNMP community is
// authorized read-only. Reconciling the running agent onto it must flip the
// live SET access-control gate from read-write to read-only.
func snmpDowngradeConfig() *config.Config {
	return &config.Config{
		System: config.SystemConfig{
			SNMP: &config.SNMPConfig{
				Communities: map[string]*config.SNMPCommunity{
					"private": {Name: "private", Authorization: "read-only"},
				},
			},
		},
	}
}

// TestApplyConfigLockedReconcilesSNMPAuthorization proves the daemon WIRING:
// applyConfigLocked must call snmpAgent.UpdateConfig so a committed community
// downgrade (read-write -> read-only) reaches the live agent. This drives the
// REAL applyConfigLocked body (not the applyBodyForTest seam), so it fails if
// the UpdateConfig call is removed from applyConfigLocked — the package-level
// snmp tests exercise UpdateConfig directly and would NOT catch that.
//
// Mutation check: delete the `d.snmpAgent.UpdateConfig(...)` line from
// applyConfigLocked and this test fails — the agent keeps its read-write gate
// and SETAuthorized("private") stays true after the apply.
func TestApplyConfigLockedReconcilesSNMPAuthorization(t *testing.T) {
	agent := snmp.NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})
	if !agent.SETAuthorized("private") {
		t.Fatal("precondition: agent should start read-write")
	}

	installFakeNetworkctl(t)
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		snmpAgent: agent,
		vrrpMgr:   vrrp.NewManager(),
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:      Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	if err := d.applyConfigLocked(context.Background(), snmpDowngradeConfig()); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	if agent.SETAuthorized("private") {
		t.Fatal("applyConfigLocked did not reconcile SNMP authorization: " +
			"community is still read-write after a read-only commit " +
			"(missing snmpAgent.UpdateConfig wiring)")
	}
}

// TestApplyConfigLockedReconcilesSNMPBeforeDataplaneAbort is the Codex r2
// regression: the SNMP reconcile must run BEFORE the dataplane apply, which
// aborts applyConfigLocked early on any required userspace protocol-gate error
// (compileErrorMustAbortApply — this test uses the policy-scheduler sentinel
// as the abort vector; the persistent-source-NAT gate, #2138, aborts
// identically). Store.Commit() has already promoted/persisted
// the compiled config, so the committed authorization is live regardless of
// whether the dataplane apply later fails. If the reconcile is placed AFTER the
// abort (the original step-16b position), an early-aborting apply leaves the
// downgraded community still serving the stale read-write gate.
//
// The fake dataplane returns the aborting sentinel from ApplyConfig, so the
// call returns that error (proving the early-return fired). The assertion is
// that despite the abort the live SNMP gate reflects the downgrade.
//
// Mutation check: move the snmpAgent.UpdateConfig call back below the dataplane
// apply (step 16b) and this test fails — the early return skips it and the gate
// stays read-write.
func TestApplyConfigLockedReconcilesSNMPBeforeDataplaneAbort(t *testing.T) {
	agent := snmp.NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})
	if !agent.SETAuthorized("private") {
		t.Fatal("precondition: agent should start read-write")
	}

	dp := &runtimeOnlyApplyTestDP{
		applyErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		snmpAgent: agent,
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:      Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	err := d.applyConfigLocked(context.Background(), snmpDowngradeConfig())
	if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want early abort on "+
			"ErrPolicySchedulerProtocolIncompatible (the early-return path "+
			"this test exercises)", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("dataplane ApplyConfig calls = %d, want 1 (abort path not reached)", dp.applyCalls)
	}

	if agent.SETAuthorized("private") {
		t.Fatal("SNMP authorization was NOT reconciled before the dataplane " +
			"abort: a committed read-write -> read-only downgrade is still " +
			"serving the stale read-write gate because applyConfigLocked " +
			"aborted early before reaching the SNMP reconcile")
	}
}

// snmpServeRecorder is a snmpServe seam that counts how many times the SNMP
// UDP listener was (re)started and blocks until its context is cancelled,
// mirroring the real agent.Start blocking contract so teardownSNMP's wg.Wait
// joins cleanly. A listener "bounce" (stop+restart) increments the count; an
// idempotent reconcile must not.
type snmpServeRecorder struct {
	mu    sync.Mutex
	calls int
}

func (r *snmpServeRecorder) serve(ctx context.Context, _ *snmp.Agent, ready chan<- error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	ready <- nil // simulate a successful bind
	<-ctx.Done()
}

func (r *snmpServeRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// newSNMPReconcileDaemon builds a daemon wired to drive the REAL
// applyConfigLocked -> reconcileSNMP lifecycle path (#3967) without binding
// UDP/161 or touching real netlink: the listener runs on the injected serve
// seam, the link-state monitor on hermetic subscribe/list seams, and the
// SNMPv3 engineBoots file on a temp path. snmpBootReady=true simulates the
// post-boot state in which day-2 commits own the SNMP lifecycle.
func newSNMPReconcileDaemon(t *testing.T, serve func(context.Context, *snmp.Agent, chan<- error)) *Daemon {
	t.Helper()
	installFakeNetworkctl(t)
	d := &Daemon{
		applySem:         semaphore.NewWeighted(1),
		vrrpMgr:          vrrp.NewManager(),
		store:            newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:             Options{NoDataplane: true},
		daemonCtx:        context.Background(),
		snmpBootReady:    true,
		snmpServe:        serve,
		snmpBootsPath:    filepath.Join(t.TempDir(), "engineboots"),
		snmpEngineIDPath: filepath.Join(t.TempDir(), "snmp-engine-id"),
		// Keep the link-state monitor hermetic: return an established
		// subscription that streams nothing and exits on ctx cancel, and an
		// empty link list for the boot seed.
		linkStateSubscribe: func(_ chan<- netlink.LinkUpdate, done <-chan struct{}, _ func(error)) error {
			go func() { <-done }()
			return nil
		},
		linkStateList: func() ([]netlink.Link, error) { return nil, nil },
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell
	t.Cleanup(d.teardownSNMP)
	return d
}

// snmpEnabledConfig is a minimal SNMP-enabled config (one read-only community).
func snmpEnabledConfig() *config.Config {
	return &config.Config{
		System: config.SystemConfig{
			SNMP: &config.SNMPConfig{
				Communities: map[string]*config.SNMPCommunity{
					"public": {Name: "public", Authorization: "read-only"},
				},
			},
		},
	}
}

func TestSNMPVRFDeviceForConfig11427(t *testing.T) {
	if got := snmpVRFDeviceForConfig(nil); got != "" {
		t.Fatalf("VRF device without management interfaces = %q, want empty", got)
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0"},
	}
	if got := snmpVRFDeviceForConfig(cfg); got != config.ManagementVRFDeviceName {
		t.Fatalf("VRF device with management interfaces = %q, want %q", got, config.ManagementVRFDeviceName)
	}
}

func snmpTestTLV11427(tag byte, body []byte) []byte {
	out := []byte{tag, byte(len(body))}
	return append(out, body...)
}

func snmpIfDescrGetRequest11427() []byte {
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x07}
	oidValue := snmpTestTLV11427(0x06, oid)
	varBindBody := append(append([]byte{}, oidValue...), 0x05, 0x00)
	varBind := snmpTestTLV11427(0x30, varBindBody)
	varBindList := snmpTestTLV11427(0x30, varBind)
	pduBody := append([]byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}, varBindList...)
	pdu := snmpTestTLV11427(0xa0, pduBody)
	messageBody := append([]byte{0x02, 0x01, 0x01}, snmpTestTLV11427(0x04, []byte("public"))...)
	messageBody = append(messageBody, pdu...)
	return snmpTestTLV11427(0x30, messageBody)
}

// TestSNMPWithoutManagementVRFServesIfTableOnMain11427 exercises the daemon's
// real listener path on a box with no configured management interfaces. The
// test SNMP manager polls ifDescr.7 over loopback; a live response proves both
// main-table service and the daemon's interface-table callback wiring.
func TestSNMPWithoutManagementVRFServesIfTableOnMain11427(t *testing.T) {
	previousLister := snmpLinkLister
	snmpLinkLister = func() ([]netlink.Link, error) {
		return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Index: 7, Name: "test0", Flags: net.FlagUp,
		}}}, nil
	}
	defer func() { snmpLinkLister = previousLister }()

	rec := &recordingSlogHandler{level: slog.LevelWarn}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(previousLogger)

	d := &Daemon{
		daemonCtx:        context.Background(),
		snmpBootsPath:    filepath.Join(t.TempDir(), "engineboots"),
		snmpEngineIDPath: filepath.Join(t.TempDir(), "engine-id"),
	}
	d.snmpReconMu.Lock()
	err := d.startSNMPLocked(snmpEnabledConfig())
	d.snmpReconMu.Unlock()
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EADDRINUSE) {
			t.Skipf("cannot bind the real SNMP listener in this environment: %v", err)
		}
		t.Fatalf("start SNMP without a management VRF: %v", err)
	}
	t.Cleanup(d.teardownSNMP)

	manager, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen as local SNMP manager: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 161}
	if _, err := manager.WriteToUDP(snmpIfDescrGetRequest11427(), server); err != nil {
		t.Fatalf("send ifDescr.7 poll: %v", err)
	}
	reply := make([]byte, 2048)
	n, peer, err := manager.ReadFromUDP(reply)
	if err != nil {
		t.Fatalf("SNMP manager did not receive a main-routing-context reply: %v", err)
	}
	if !peer.IP.Equal(net.ParseIP("127.0.0.1")) || peer.Port != 161 {
		t.Fatalf("SNMP reply source = %v, want 127.0.0.1:161", peer)
	}
	wantOID := snmpTestTLV11427(0x06, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x07})
	wantValue := snmpTestTLV11427(0x04, []byte("test0"))
	wantVarBind := snmpTestTLV11427(0x30, append(wantOID, wantValue...))
	if !bytes.Contains(reply[:n], wantVarBind) {
		t.Fatalf("ifTable response does not contain ifDescr.7 = test0: %x", reply[:n])
	}
	if got := rec.count("SNMP management VRF is not configured; serving from main routing table"); got != 1 {
		t.Fatalf("SNMP main-table fallback warning count = %d, want 1", got)
	}
}

// snmpEnabledWithTrapConfig adds a trap group to snmpEnabledConfig so a day-2
// commit that introduces trap targets must bring up the link-state monitor.
func snmpEnabledWithTrapConfig() *config.Config {
	return &config.Config{
		System: config.SystemConfig{
			SNMP: &config.SNMPConfig{
				Communities: map[string]*config.SNMPCommunity{
					"public": {Name: "public", Authorization: "read-only"},
				},
				TrapGroups: map[string]*config.SNMPTrapGroup{
					"managers": {Name: "managers", Targets: []string{"192.0.2.1"}, Version: "v2"},
				},
			},
		},
	}
}

// TestApplyConfigLockedStartsSNMPWhenEnabledDay2 is the #3967 RED-on-revert
// test for the primary defect: enabling SNMP on a running daemon must start the
// agent listener via the apply path, not sit inert until a restart. It drives
// the REAL applyConfigLocked so it fails if reconcileSNMP's start wiring is
// removed from the apply body.
//
// Mutation check: delete the d.reconcileSNMP(cfg) call from applyConfigLocked
// (or revert its start branch) and this test fails — d.snmpAgent stays nil and
// the listener never starts after a day-2 enable.
func TestApplyConfigLockedStartsSNMPWhenEnabledDay2(t *testing.T) {
	rec := &snmpServeRecorder{}
	d := newSNMPReconcileDaemon(t, rec.serve)

	if d.snmpAgent != nil {
		t.Fatal("precondition: no SNMP agent should be running before the enable commit")
	}

	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable): %v", err)
	}

	if d.snmpAgent == nil {
		t.Fatal("day-2 SNMP enable was NOT reconciled into the running subsystem: " +
			"the agent is still nil after the commit (inert until restart)")
	}
	if !waitUntil(t, time.Second, func() bool { return rec.count() == 1 }) {
		t.Fatalf("SNMP listener did not start on a day-2 enable: serve invocations = %d, want 1", rec.count())
	}
}

// TestApplyConfigLockedStopsSNMPWhenDisabledDay2 proves the enable->disable
// half: a commit that removes SNMP stops the running listener rather than
// leaving it bound until a restart.
func TestApplyConfigLockedStopsSNMPWhenDisabledDay2(t *testing.T) {
	rec := &snmpServeRecorder{}
	d := newSNMPReconcileDaemon(t, rec.serve)

	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable): %v", err)
	}
	if d.snmpAgent == nil {
		t.Fatal("precondition: agent should be running after the enable commit")
	}

	if err := d.applyConfigLocked(context.Background(), snmpDowngradeDisabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(disable): %v", err)
	}
	if d.snmpAgent != nil {
		t.Fatal("day-2 SNMP disable was NOT reconciled: the agent is still running after the commit")
	}
}

// snmpDowngradeDisabledConfig is an SNMP-absent config (the disable target).
func snmpDowngradeDisabledConfig() *config.Config { return &config.Config{} }

// TestReconcileSNMPUnchangedIsNoOp proves idempotence: re-committing an
// identical SNMP stanza must NOT bounce the UDP listener — the serve seam is
// invoked exactly once across two identical enable commits and the agent
// pointer is preserved.
func TestReconcileSNMPUnchangedIsNoOp(t *testing.T) {
	rec := &snmpServeRecorder{}
	d := newSNMPReconcileDaemon(t, rec.serve)

	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable #1): %v", err)
	}
	if !waitUntil(t, time.Second, func() bool { return rec.count() == 1 }) {
		t.Fatalf("listener not started on first enable: serve = %d", rec.count())
	}
	first := d.snmpAgent

	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable #2, unchanged): %v", err)
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("unchanged SNMP commit bounced the listener: serve invocations = %d, want 1", got)
	}
	if d.snmpAgent != first {
		t.Fatal("unchanged SNMP commit replaced the running agent (listener bounce)")
	}
}

// TestReconcileSNMPStartsMonitorOnTrapGroupAddedDay2 proves the trap-group half
// of the defect: an agent already running WITHOUT trap groups must bring up the
// link-state trap monitor when a commit adds a trap group — without bouncing
// the UDP listener.
func TestReconcileSNMPStartsMonitorOnTrapGroupAddedDay2(t *testing.T) {
	rec := &snmpServeRecorder{}
	d := newSNMPReconcileDaemon(t, rec.serve)

	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable, no trap groups): %v", err)
	}
	if d.snmpMonitorRunning {
		t.Fatal("precondition: link-state monitor should not run without trap groups")
	}

	if err := d.applyConfigLocked(context.Background(), snmpEnabledWithTrapConfig()); err != nil {
		t.Fatalf("applyConfigLocked(add trap group): %v", err)
	}
	if !d.snmpMonitorRunning {
		t.Fatal("adding a trap group day-2 did NOT start the SNMP link-state monitor " +
			"(link traps would never flow to the new target until a restart)")
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("adding a trap group bounced the UDP listener: serve invocations = %d, want 1", got)
	}
}

// snmpServeBindOutcome is a snmpServe seam whose bind result is scripted per
// attempt: the first failN attempts report a bind failure on the readiness
// channel and return WITHOUT serving (mirroring Agent.Bind failing before
// Agent.Serve); every later attempt reports a successful bind and blocks until
// ctx cancel (mirroring a clean Bind+Serve). It counts attempts so a test can
// prove a failed start is retried on the next apply.
type snmpServeBindOutcome struct {
	mu       sync.Mutex
	attempts int
	failN    int
}

func (s *snmpServeBindOutcome) serve(ctx context.Context, _ *snmp.Agent, ready chan<- error) {
	s.mu.Lock()
	s.attempts++
	n := s.attempts
	s.mu.Unlock()
	if n <= s.failN {
		ready <- errors.New("snmp: listen: listen udp :161: bind: address already in use")
		return
	}
	ready <- nil
	<-ctx.Done()
}

func (s *snmpServeBindOutcome) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// TestReconcileSNMPBindFailureLeavesHashUnrecordedAndRetries is the #5110
// RED-on-revert test: a listener bind failure must NOT publish the running
// SNMP hash, and the half-started agent must be torn down, so the NEXT
// identical apply retries the bind (self-healing a transient UDP/161 failure)
// instead of no-oping forever with SNMP silently down.
//
// Mutation check: record d.snmpHash on the failed start (or leave the zombie
// agent non-nil / drop the teardown), and the retry apply sees a running agent
// with a matching hash, takes the idempotent no-op path, and never re-attempts
// the bind — seam attempts stay at 1 and d.snmpAgent stays nil, failing the
// retry assertions below.
func TestReconcileSNMPBindFailureLeavesHashUnrecordedAndRetries(t *testing.T) {
	seam := &snmpServeBindOutcome{failN: 1} // fail the first bind, then succeed
	d := newSNMPReconcileDaemon(t, seam.serve)

	// First enable: the listener bind FAILS.
	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable, bind fails): %v", err)
	}
	if got := seam.count(); got != 1 {
		t.Fatalf("bind was not attempted exactly once: attempts = %d, want 1", got)
	}
	if d.snmpAgent != nil {
		t.Fatal("bind failure left a zombie SNMP agent: d.snmpAgent must be nil " +
			"after a failed start so the next apply retries (#5110)")
	}
	d.snmpReconMu.Lock()
	hashSet := d.snmpHashSet
	d.snmpReconMu.Unlock()
	if hashSet {
		t.Fatal("bind failure recorded the desired SNMP hash: a subsequent " +
			"identical apply will no-op and SNMP stays silently down (#5110)")
	}

	// Second identical enable: because the hash was NOT recorded and the zombie
	// was torn down, the apply RETRIES the bind, which now succeeds.
	if err := d.applyConfigLocked(context.Background(), snmpEnabledConfig()); err != nil {
		t.Fatalf("applyConfigLocked(enable retry): %v", err)
	}
	if got := seam.count(); got != 2 {
		t.Fatalf("failed SNMP start was NOT retried on the next identical apply: "+
			"bind attempts = %d, want 2 (#5110)", got)
	}
	if d.snmpAgent == nil {
		t.Fatal("SNMP did not self-heal: the retry apply did not bring the agent up")
	}
	if !waitUntil(t, time.Second, func() bool { return d.snmpAgent != nil }) {
		t.Fatal("SNMP agent not running after successful retry")
	}
	d.snmpReconMu.Lock()
	hashSet = d.snmpHashSet
	d.snmpReconMu.Unlock()
	if !hashSet {
		t.Fatal("successful retry did not record the desired SNMP hash")
	}
}

// TestDeriveIfCountersUnicastExcludesMulticast is the fail-on-revert guard for
// #5050. The SNMP IF-MIB unicast packet counters must carry only the unicast
// subset, never the Linux TOTAL RxPackets/TxPackets (which fold in
// multicast/broadcast). With RxPackets = unicast + multicast, ifHCInUcastPkts
// must equal the unicast value and ifInMulticastPkts the multicast value; if
// the counters overlapped (the pre-fix bug) HCInUcastPkts would equal the
// total and this test fails RED.
func TestDeriveIfCountersUnicastExcludesMulticast(t *testing.T) {
	const (
		inUnicast   = uint64(1_000_000)
		inMulticast = uint64(250_000)
		inTotal     = inUnicast + inMulticast // Linux RxPackets = all classes
		txTotal     = uint64(4_000_000)
		rxBytes     = uint64(9_000_000_000) // > 2^32 to exercise HC counters
		txBytes     = uint64(8_000_000_000)
	)
	stats := &netlink.LinkStatistics{
		RxPackets: inTotal,
		TxPackets: txTotal,
		RxBytes:   rxBytes,
		TxBytes:   txBytes,
		Multicast: inMulticast,
	}

	var entry snmp.IfData
	deriveIfCounters(&entry, stats)

	// The core invariant: IN unicast is the unicast subset, NOT the total.
	if entry.HCInUcastPkts != inUnicast {
		t.Errorf("ifHCInUcastPkts = %d, want %d (unicast subset, not total %d) — "+
			"multicast is being double-counted into unicast (#5050)",
			entry.HCInUcastPkts, inUnicast, inTotal)
	}
	if entry.HCInUcastPkts == inTotal {
		t.Errorf("ifHCInUcastPkts = %d equals Linux TOTAL RxPackets — the pre-fix "+
			"bug reappeared (#5050)", entry.HCInUcastPkts)
	}
	// Multicast must be reported under its own class column, so unicast +
	// multicast reconstructs the total with no overlap.
	if entry.InMulticastPkts != uint32(inMulticast) {
		t.Errorf("ifInMulticastPkts = %d, want %d", entry.InMulticastPkts, inMulticast)
	}
	if got := uint64(entry.HCInUcastPkts) + uint64(entry.InMulticastPkts); got != inTotal {
		t.Errorf("unicast(%d) + multicast(%d) = %d, want RxPackets total %d — "+
			"class columns overlap", entry.HCInUcastPkts, entry.InMulticastPkts, got, inTotal)
	}
	// OUT unicast tracks TxPackets (Linux exposes no TX class breakdown to
	// subtract) and the HC octet counters carry the full 64-bit byte totals.
	if entry.HCOutUcastPkts != txTotal {
		t.Errorf("ifHCOutUcastPkts = %d, want %d", entry.HCOutUcastPkts, txTotal)
	}
	if entry.HCInOctets != rxBytes {
		t.Errorf("ifHCInOctets = %d, want %d", entry.HCInOctets, rxBytes)
	}
	if entry.HCOutOctets != txBytes {
		t.Errorf("ifHCOutOctets = %d, want %d", entry.HCOutOctets, txBytes)
	}
}

// TestDeriveIfCountersClampsMulticastOverflow proves the racy-read guard: if a
// non-atomic stats sample observes Multicast > RxPackets, IN unicast clamps to
// 0 rather than underflowing to a huge uint64 (#5050).
func TestDeriveIfCountersClampsMulticastOverflow(t *testing.T) {
	stats := &netlink.LinkStatistics{RxPackets: 100, Multicast: 250}
	var entry snmp.IfData
	deriveIfCounters(&entry, stats)
	if entry.HCInUcastPkts != 0 {
		t.Errorf("ifHCInUcastPkts = %d, want 0 (clamped, no underflow)", entry.HCInUcastPkts)
	}
}
