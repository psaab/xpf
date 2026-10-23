package ddns

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestRFC2136RequireTSIGRefusesUnsigned15992 pins #15992's runtime backstop:
// a require-tsig updater with no key refuses a non-loopback UPDATE before
// sending, so a forged rcode can never record durable ownership.
// A keyed control publishes, and a loopback server is exempt (same
// predicate the strict commit gate applies).
func TestRFC2136RequireTSIGRefusesUnsigned15992(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", RequireTSIG: true,
	}, &ptr, &conf)
	// testUpdater points at a loopback fake; force a non-loopback server
	// string so the require-tsig refusal (not the loopback exemption) fires.
	u.server = "192.0.2.53:53"
	err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300))
	if err == nil {
		t.Fatal("require-tsig updater without a key published on an unsigned rcode (#15992)")
	}
	if !strings.Contains(err.Error(), "require-tsig") {
		t.Fatalf("refusal must name require-tsig, got: %v", err)
	}
	if got := len(srv.recorded()); got != 0 {
		t.Fatalf("refusal must happen before any wire UPDATE, server saw %d", got)
	}

	secret := map[string]string{"k1.": "c2VjcmV0"}
	srv2 := newFakeDNSServer(t, secret)
	var ptr2, conf2 int
	u2 := testUpdater(t, srv2, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", RequireTSIG: true,
		TSIGKeyName: "k1", TSIGAlgorithm: "hmac-sha256", TSIGSecret: config.NewSecret("c2VjcmV0"),
	}, &ptr2, &conf2)
	if err := u2.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("keyed require-tsig updater must publish: %v", err)
	}

	// Loopback exemption: require-tsig + no key + loopback server publishes
	// unsigned, exactly as the strict commit gate allows.
	srv3 := newFakeDNSServer(t, nil)
	var ptr3, conf3 int
	u3 := testUpdater(t, srv3, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", RequireTSIG: true,
	}, &ptr3, &conf3)
	if err := u3.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("loopback require-tsig updater must publish unsigned (commit-gate exemption): %v", err)
	}
}

// TestDDNSUnsignedNonLoopbackPosture15992 pins the live alarm predicate:
// non-loopback unsigned is active; loopback, keyed, and disabled are not.
func TestDDNSUnsignedNonLoopbackPosture15992(t *testing.T) {
	mk := func(server, key string, enabled bool) (ddnsPolicy, *config.DHCPDynamicDNSConfig) {
		c := &config.DHCPDynamicDNSConfig{Enabled: enabled, Domain: "example.com", UpdateServer: server, TSIGKeyName: key}
		if key != "" {
			c.TSIGSecret = config.NewSecret("c2VjcmV0")
		}
		return policyFromConfig(c), c
	}
	for _, tc := range []struct {
		name    string
		server  string
		key     string
		enabled bool
		want    bool
	}{
		{"non-loopback unsigned", "192.0.2.53", "", true, true},
		{"hostname unsigned (unprovable, fail-closed)", "ns1.example.com", "", true, true},
		{"loopback unsigned", "127.0.0.1", "", true, false},
		{"loopback v6 unsigned", "::1", "", true, false},
		{"keyed non-loopback", "192.0.2.53", "k1", true, false},
		{"disabled", "192.0.2.53", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol, c := mk(tc.server, tc.key, tc.enabled)
			if got := ddnsUnsignedNonLoopback(pol, c); got != tc.want {
				t.Fatalf("ddnsUnsignedNonLoopback = %v, want %v", got, tc.want)
			}
		})
	}
	for server, want := range map[string]bool{
		"127.0.0.1:53": true, "[::1]:53": true, "localhost:53": true,
		"192.0.2.53:53": false, "ns1.example.com:53": false,
	} {
		if got := updateServerIsLoopback(server); got != want {
			t.Errorf("updateServerIsLoopback(%q) = %v, want %v", server, got, want)
		}
	}
}

// TestDDNSUnsignedGaugeViaReconcile15992 drives the gauge through real
// reconciliation wiring (Manager.ReconcileScoped + SurfaceAManager.Reconcile
// -> Stats), not preconstructed stats: the posture must appear while a
// non-loopback unsigned server is configured and clear when it is not.
func TestDDNSUnsignedGaugeViaReconcile15992(t *testing.T) {
	nowFn := func() time.Time { return time.Unix(1_700_000_000, 0) }

	// Surface B (DHCP lease DDNS): reconcile with a non-loopback unsigned
	// server, then with a loopback one.
	m := testDDNS(t, newFakeUpdater())
	unsignedCfg := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", TTLSeconds: 300, UpdateServer: "192.0.2.53",
	}}
	if err := m.ReconcileScoped(context.Background(), unsignedCfg, ReconcileOptions{}); err != nil {
		t.Fatalf("reconcile unsigned: %v", err)
	}
	if !m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("Stats().UnsignedNonLoopbackActive = false after reconcile with non-loopback unsigned server")
	}
	loopbackCfg := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", TTLSeconds: 300, UpdateServer: "127.0.0.1",
	}}
	if err := m.ReconcileScoped(context.Background(), loopbackCfg, ReconcileOptions{}); err != nil {
		t.Fatalf("reconcile loopback: %v", err)
	}
	if m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("Stats().UnsignedNonLoopbackActive = true after reconcile with loopback server; gauge must clear")
	}

	// Surface A: reconcile with a catalog carrying a non-loopback unsigned
	// provider, then with a keyed catalog.
	dir := t.TempDir()
	sa := newSurfaceAManagerForTesting(filepath.Join(dir, "iface.json"), newFakeUpdater(), nowFn)
	catalog := map[string]*config.DDNSProvider{
		"p1": {Backend: "rfc2136", UpdateServer: "192.0.2.53"},
	}
	if err := sa.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("surface-a reconcile unsigned: %v", err)
	}
	if !sa.Stats().UnsignedNonLoopbackActive {
		t.Fatal("SurfaceA Stats().UnsignedNonLoopbackActive = false with non-loopback unsigned provider")
	}
	keyed := map[string]*config.DDNSProvider{
		"p1": {Backend: "rfc2136", UpdateServer: "192.0.2.53", TSIGKeyName: "k1", TSIGSecret: config.NewSecret("c2VjcmV0")},
	}
	if err := sa.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, keyed); err != nil {
		t.Fatalf("surface-a reconcile keyed: %v", err)
	}
	if sa.Stats().UnsignedNonLoopbackActive {
		t.Fatal("SurfaceA Stats().UnsignedNonLoopbackActive = true with keyed provider; gauge must clear")
	}
}

// TestDDNSUnsignedGaugeCleanupAfterDisable15992 pins the cleanup-path half
// of the gauge: after a family/provider is disabled or removed, owned
// records pending cleanup still send unsigned UPDATEs to the old
// non-loopback server, so the gauge must stay 1 until the last such record
// is withdrawn — and clear then. Fail-on-revert: computing the gauge only
// from the current enabled config reports 0 in the disabled/removed pass.
func TestDDNSUnsignedGaugeCleanupAfterDisable15992(t *testing.T) {
	ctx := context.Background()
	nowFn := func() time.Time { return time.Unix(1_700_000_000, 0) }

	// --- Surface B (DHCP lease DDNS) ---
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	// The fake server is loopback; the retained cleanup endpoint must be
	// the non-loopback authored server, so the factory dials the fake
	// but reports the authored endpoint posture (postureUpdater15992).
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		authored := c.UpdateServer
		c2 := *c
		c2.UpdateServer = srv.addrUDP
		u, err := newRFC2136Updater(pol, &c2, nil,
			func() { m.skippedPTRNotAuth.Add(1) },
			func() { m.skippedConflict.Add(1) })
		if err != nil {
			return nil, err
		}
		// Gauge posture keys on the authored endpoint, wire on the fake.
		return &postureUpdater15992{inner: u, server: authored}, nil
	}
	cfg := ddnsCfg("192.0.2.53")
	src.v4 = laptopMacLease()
	if err := m.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("publish reconcile: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("owned records = %d, want 1 after publish", got)
	}
	if !m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("gauge 0 while enabled unsigned non-loopback (precondition)")
	}
	// Disable DDNS: cleanup UPDATEs still go out unsigned, but the record
	// is withdrawn this pass, so afterwards the gauge must clear.
	disabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{Enabled: false, Domain: "example.com", TTLSeconds: 300, Backend: "rfc2136", UpdateServer: "192.0.2.53"}}
	src.v4 = nil
	if err := m.Reconcile(ctx, disabled); err != nil {
		t.Fatalf("disabled reconcile: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("owned records = %d, want 0 after disabled cleanup", got)
	}
	if m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("gauge stuck at 1 after cleanup completed (no owned records)")
	}

	// Republish, then make cleanup FAIL so ownership is retained across a
	// disabled pass: the gauge must stay 1 while cleanup is pending, even
	// though the current config is disabled.
	src.v4 = laptopMacLease()
	if err := m.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("republish reconcile: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("owned records = %d, want 1 after republish", got)
	}
	// Force withdraw failure via a failing factory on the disabled pass.
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		return &postureUpdater15992{inner: &failDeleteUpdater15992{}, server: "192.0.2.53"}, nil
	}
	if err := m.Reconcile(ctx, disabled); err == nil {
		// A delete failure surfaces as a reconcile error; either way
		// ownership must be retained.
		t.Logf("disabled failing-cleanup reconcile returned nil (checked via ownership below)")
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("owned records = %d, want 1 retained after failed cleanup", got)
	}
	if !m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("gauge 0 while owned records pending unsigned non-loopback cleanup after disable")
	}

	// --- Surface A ---
	dir := t.TempDir()
	fu := newFakeUpdater()
	sa := newSurfaceAManagerForTesting(filepath.Join(dir, "iface.json"), fu, nowFn)
	prov := &config.DDNSProvider{Name: "p1", Backend: "rfc2136", UpdateServer: "192.0.2.53"}
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	sc.Key.PolicyID = "p1"
	sc.Provider = prov
	catalog := map[string]*config.DDNSProvider{"p1": prov}
	if err := sa.Reconcile(ctx, []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("surface-a publish: %v", err)
	}
	if got := sa.Stats().Scopes; got != 1 {
		t.Fatalf("surface-a scopes = %d, want 1 after publish", got)
	}
	if !sa.Stats().UnsignedNonLoopbackActive {
		t.Fatal("surface-a gauge 0 while unsigned non-loopback (precondition)")
	}
	// Remove binding AND provider, with withdraw failing: ownership is
	// retained, cleanup still implicates the old unsigned endpoint.
	fu.failDel["wan.example.net"] = true
	if err := sa.Reconcile(ctx, nil, fixedObserver("203.0.113.5"), nil, map[string]*config.DDNSProvider{}); err != nil {
		t.Logf("surface-a removed failing-cleanup reconcile: %v (checked via ownership below)", err)
	}
	if got := sa.Stats().Scopes; got != 1 {
		t.Fatalf("surface-a scopes = %d, want 1 retained after failed cleanup", got)
	}
	if !sa.Stats().UnsignedNonLoopbackActive {
		t.Fatal("surface-a gauge 0 while owned records pending unsigned cleanup after provider removal")
	}
	// Let cleanup succeed: gauge clears with the last owned record. The
	// failing withdraw armed a backoff window, so advance past it by
	// clearing the scope runtime backoff is not exposed — instead use a
	// fresh manager over the same persisted state (restart semantics:
	// ownership reloads, backoff does not).
	fu.failDel = map[string]bool{}
	sa = newSurfaceAManagerForTesting(filepath.Join(dir, "iface.json"), fu, nowFn)
	if err := sa.Reconcile(ctx, nil, fixedObserver("203.0.113.5"), nil, map[string]*config.DDNSProvider{"p1": prov}); err != nil {
		t.Fatalf("surface-a cleanup reconcile: %v", err)
	}
	if got := sa.Stats().Scopes; got != 0 {
		t.Fatalf("surface-a scopes = %d, want 0 after cleanup", got)
	}
	// One empty-catalog pass: no provider, no owned records — the gauge
	// must now report 0 (the previous pass's catalog still carried p1).
	if err := sa.Reconcile(ctx, nil, fixedObserver("203.0.113.5"), nil, map[string]*config.DDNSProvider{}); err != nil {
		t.Fatalf("surface-a empty reconcile: %v", err)
	}
	if sa.Stats().UnsignedNonLoopbackActive {
		t.Fatal("surface-a gauge stuck at 1 after cleanup completed")
	}
}

// blockingUpdater15992 blocks inside DeleteLease until released, so a
// test can scrape Stats() while a cleanup UPDATE is in flight.
type blockingUpdater15992 struct {
	inner   DNSUpdater
	server  string
	entered chan struct{}
	release chan struct{}
	once    bool
}

func (b *blockingUpdater15992) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	return b.inner.UpsertLease(ctx, rec)
}
func (b *blockingUpdater15992) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	if !b.once {
		b.once = true
		close(b.entered)
		<-b.release
	}
	return b.inner.DeleteLease(ctx, rec)
}
func (b *blockingUpdater15992) DDNSUpdaterEndpoint() (string, bool) { return b.server, false }

// TestDDNSUnsignedGaugeInFlightHold15992 pins the in-flight hold: while a
// cleanup pass is blocked inside its withdraw UPDATE (config already
// disabled), Stats() must still report the previous posture (1), never a
// transient 0 from the opening reset. Fail-on-revert: drop the hold and
// the mid-cleanup scrape reads 0.
func TestDDNSUnsignedGaugeInFlightHold15992(t *testing.T) {
	ctx := context.Background()
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		authored := c.UpdateServer
		c2 := *c
		c2.UpdateServer = srv.addrUDP
		u, err := newRFC2136Updater(pol, &c2, nil,
			func() { m.skippedPTRNotAuth.Add(1) },
			func() { m.skippedConflict.Add(1) })
		if err != nil {
			return nil, err
		}
		return &postureUpdater15992{inner: u, server: authored}, nil
	}
	cfg := ddnsCfg("192.0.2.53")
	src.v4 = laptopMacLease()
	if err := m.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("precondition: gauge must be 1 while enabled unsigned")
	}
	// Disabled pass whose withdraw blocks mid-flight.
	bu := &blockingUpdater15992{inner: &fakeUpdater{failUpd: map[string]bool{}, failDel: map[string]bool{}}, server: "192.0.2.53", entered: make(chan struct{}), release: make(chan struct{})}
	// The blocking updater must actually delete on release; give it the
	// real backend as inner via the posture path: use a fake that succeeds.
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		return bu, nil
	}
	disabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{Enabled: false, Domain: "example.com", TTLSeconds: 300, Backend: "rfc2136", UpdateServer: "192.0.2.53"}}
	src.v4 = nil
	done := make(chan error, 1)
	go func() { done <- m.Reconcile(ctx, disabled) }()
	<-bu.entered // cleanup UPDATE in flight, lock released by providerIO
	if !m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("gauge dipped to 0 during in-progress cleanup (in-flight hold missing)")
	}
	close(bu.release)
	if err := <-done; err != nil {
		t.Fatalf("disabled cleanup reconcile: %v", err)
	}
	if m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("gauge stuck at 1 after cleanup completed")
	}
}

// TestDDNSUnsignedGaugeKeyedTransition15992 pins the transition capture:
// config transitions unsigned -> keyed (new endpoint keyed, old records
// withdraw via the PREVIOUS unsigned updater). The gauge must reflect
// the previous updater's unsigned posture while old records are pending.
// Fail-on-revert: capture only from current config/updater and the gauge
// reads the keyed endpoint (0) during the transition cleanup.
func TestDDNSUnsignedGaugeKeyedTransition15992(t *testing.T) {
	ctx := context.Background()
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	factory := func(keyed bool) func(ddnsPolicy, *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		return func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
			if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
				return nopUpdater{}, nil
			}
			authored := c.UpdateServer
			c2 := *c
			c2.UpdateServer = srv.addrUDP
			if keyed {
				c2.TSIGKeyName = "k1"
				c2.TSIGAlgorithm = "hmac-sha256"
				c2.TSIGSecret = config.NewSecret("c2VjcmV0")
			}
			u, err := newRFC2136Updater(policyFromConfig(&c2), &c2, nil,
				func() { m.skippedPTRNotAuth.Add(1) },
				func() { m.skippedConflict.Add(1) })
			if err != nil {
				return nil, err
			}
			return &keyedPostureUpdater15992{inner: u, server: authored, keyed: keyed}, nil
		}
	}
	m.newUpdater = factory(false)
	src.v4 = laptopMacLease()
	if err := m.Reconcile(ctx, ddnsCfg("192.0.2.53")); err != nil {
		t.Fatalf("publish unsigned: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("owned = %d, want 1", got)
	}
	// Transition to a keyed endpoint (different server so the fingerprint
	// changes and old records withdraw via prevUpdater) with withdraw
	// FAILING, so old ownership is retained through the transition pass.
	keyedCfg := ddnsCfg("198.51.100.53")
	keyedCfg.DynamicDNS.TSIGKeyName = "k1"
	keyedCfg.DynamicDNS.TSIGAlgorithm = "hmac-sha256"
	keyedCfg.DynamicDNS.TSIGSecret = config.NewSecret("c2VjcmV0")
	m.newUpdater = factory(true)
	// Make the previous updater's delete fail by swapping prev anchor's
	// inner failure: the prev updater is the one retained from pass 1.
	if pu, ok := m.lastLiveUpdater[0].(*keyedPostureUpdater15992); ok {
		pu.inner = &failDeleteUpdater15992{}
	}
	src.v4 = laptopMacLease()
	_ = m.Reconcile(ctx, keyedCfg) // transition delete may error; ownership retained is the check
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("owned = %d, want 1 retained through keyed transition", got)
	}
	if !m.Stats().UnsignedNonLoopbackActive {
		t.Fatal("gauge 0 during keyed transition while old records withdraw via previous unsigned updater")
	}
}

// keyedPostureUpdater15992 reports an explicit keyed flag for the gauge.
type keyedPostureUpdater15992 struct {
	inner  DNSUpdater
	server string
	keyed  bool
}

func (k *keyedPostureUpdater15992) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	return k.inner.UpsertLease(ctx, rec)
}
func (k *keyedPostureUpdater15992) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	return k.inner.DeleteLease(ctx, rec)
}
func (k *keyedPostureUpdater15992) DDNSUpdaterEndpoint() (string, bool) {
	return k.server, k.keyed
}

// postureUpdater15992 wraps a resolved updater and reports a fixed
// authored server for gauge-posture purposes in tests. The wire behaviour
// is the inner updater's.
type postureUpdater15992 struct {
	inner  DNSUpdater
	server string
}

func (p *postureUpdater15992) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	return p.inner.UpsertLease(ctx, rec)
}
func (p *postureUpdater15992) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	return p.inner.DeleteLease(ctx, rec)
}

// DDNSUpdaterEndpoint reports the authored endpoint posture for the gauge.
func (p *postureUpdater15992) DDNSUpdaterEndpoint() (string, bool) { return p.server, false }

type failDeleteUpdater15992 struct{ fakeUpdater }

func (f *failDeleteUpdater15992) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	return errFailDelete15992
}

// DDNSUpdaterEndpoint reports the authored endpoint posture for the gauge.
func (f *failDeleteUpdater15992) DDNSUpdaterEndpoint() (string, bool) {
	return "192.0.2.53", false
}

var errFailDelete15992 = errString15992("fake: delete failed (cleanup pending)")

type errString15992 string

func (e errString15992) Error() string { return string(e) }
