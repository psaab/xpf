package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #5814 — the DHCP-lease (Surface B) reconciler must treat an update-server /
// TSIG-key / zone identity change as a real transition: withdraw the record
// through the OLD endpoint that published it and republish on the NEW one, even
// when the DNS content (name / type / address / TTL) is byte-for-byte unchanged.
// Before the fix, the content-only recordsEqual shortcut marked such a record
// "settled" (no publish on the new server, old server's record left live), and a
// forced delete would have been routed to the NEW (wrong) endpoint.

// backendFPOf returns the stored backend fingerprint for the single owned record
// whose address matches (test-only helper; the package owns the state store).
func backendFPOf(t *testing.T, m *Manager, address string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.state.all() {
		if r.Address == address {
			return r.BackendFingerprint
		}
	}
	t.Fatalf("no owned record for address %s", address)
	return ""
}

func driveReconcile(t *testing.T, m *Manager, env *reconcileEnv, leases []Lease) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.reconcileOnceLocked(context.Background(), env, leases, nil, nil); err != nil {
		t.Fatalf("reconcileOnceLocked: %v", err)
	}
}

// TestReconcileBackendChangeWithdrawsOldPublishesNew_5814 is the primary
// fail-on-revert guard: publish through backend A, then reconcile the SAME
// desired tuple through backend B (a server/zone/credential change). The old
// endpoint A must receive the withdraw (cleanup authority preserved) and the new
// endpoint B must receive the publish. Reverting EITHER half of the fix (the
// settled-shortcut backend check OR the old-endpoint delete routing) turns this
// test red.
func TestReconcileBackendChangeWithdrawsOldPublishesNew_5814(t *testing.T) {
	updA := newFakeUpdater()
	updB := newFakeUpdater()
	m := testDDNS(t, nopUpdater{})
	pol := enabledPolicy()
	lease := leaseV4("10.0.1.5", "cid:aa", "laptop")

	// Pass 1 — publish through backend A (fingerprint "fpA").
	driveReconcile(t, m, &reconcileEnv{
		pol:       [2]ddnsPolicy{pol, pol},
		updater:   [2]DNSUpdater{updA, updA},
		backendFP: [2]string{"fpA", "fpA"},
	}, []Lease{lease})

	if got := updA.upsertNames(); len(got) != 1 {
		t.Fatalf("pass 1: publish on backend A = %v, want exactly 1", got)
	}
	if fp := backendFPOf(t, m, "10.0.1.5"); fp != "fpA" {
		t.Fatalf("pass 1: owned record fingerprint = %q, want %q", fp, "fpA")
	}

	// Pass 2 — SAME desired tuple, backend B (fingerprint "fpB"); the previous
	// live backend (A) is retained as the per-family withdraw anchor, tagged with
	// its own fingerprint "fpA" so the identity gate proves it published the
	// owned record before withdrawing through it (#5814 review).
	driveReconcile(t, m, &reconcileEnv{
		pol:         [2]ddnsPolicy{pol, pol},
		updater:     [2]DNSUpdater{updB, updB},
		backendFP:   [2]string{"fpB", "fpB"},
		prevUpdater: [2]DNSUpdater{updA, updA},
		prevFP:      [2]string{"fpA", "fpA"},
	}, []Lease{lease})

	// (a) the NEW endpoint B received the publish.
	if got := updB.upsertNames(); len(got) != 1 {
		t.Errorf("backend change: publish on NEW backend B = %v, want exactly 1 "+
			"(the content-only settled shortcut ignored the endpoint change)", got)
	}
	// (b) the OLD endpoint A received the withdraw — cleanup authority preserved.
	if got := updA.deleteNames(); len(got) != 1 {
		t.Errorf("backend change: withdraw on OLD backend A = %v, want exactly 1 "+
			"(the old server's record was orphaned)", got)
	}
	// The withdraw must NOT be routed to the new/wrong endpoint.
	if got := updB.deleteNames(); len(got) != 0 {
		t.Errorf("backend change: withdraw wrongly routed to NEW backend B: %v", got)
	}
	// The new publish must NOT be routed to the old endpoint.
	if got := updA.upsertNames(); len(got) != 1 { // only the pass-1 publish
		t.Errorf("backend change: unexpected extra publish on OLD backend A: %v", got)
	}
	// Ownership converges onto the new endpoint's fingerprint.
	if fp := backendFPOf(t, m, "10.0.1.5"); fp != "fpB" {
		t.Errorf("backend change: owned record fingerprint = %q, want %q (not converged)", fp, "fpB")
	}
}

// TestReconcileBackendChangeIsPerFamily_5814 proves the transition is per-family
// (#2663 independence, #5814 design pt 7): a v4 endpoint change must not withdraw
// or re-publish any v6 record, and the v4 withdraw must NOT be routed through
// v6's backend.
func TestReconcileBackendChangeIsPerFamily_5814(t *testing.T) {
	updA4 := newFakeUpdater() // v4 old endpoint
	updB4 := newFakeUpdater() // v4 new endpoint
	updC6 := newFakeUpdater() // v6 endpoint (unchanged across both passes)
	m := testDDNS(t, nopUpdater{})
	pol := enabledPolicy()
	l4 := leaseV4("10.0.1.5", "cid:aa", "laptop")
	l6 := Lease{Family: 6, Address: "2001:db8::5", Identity: "duid:bb", HostName: "laptop6", SubnetID: "1"}

	// Pass 1 — v4 on A4 (fpA4), v6 on C6 (fpC6).
	driveReconcile(t, m, &reconcileEnv{
		pol:       [2]ddnsPolicy{pol, pol},
		updater:   [2]DNSUpdater{updA4, updC6},
		backendFP: [2]string{"fpA4", "fpC6"},
	}, []Lease{l4, l6})

	if got := updA4.upsertNames(); len(got) != 1 {
		t.Fatalf("pass 1: v4 publish = %v, want 1", got)
	}
	if got := updC6.upsertNames(); len(got) != 1 {
		t.Fatalf("pass 1: v6 publish = %v, want 1", got)
	}

	// Pass 2 — ONLY the v4 backend changes (A4 -> B4); v6 stays on C6. Each
	// family's retained anchor carries its own fingerprint so the identity gate
	// admits the v4 withdraw through A4 (fpA4 matches) and never disturbs v6.
	driveReconcile(t, m, &reconcileEnv{
		pol:         [2]ddnsPolicy{pol, pol},
		updater:     [2]DNSUpdater{updB4, updC6},
		backendFP:   [2]string{"fpB4", "fpC6"},
		prevUpdater: [2]DNSUpdater{updA4, updC6},
		prevFP:      [2]string{"fpA4", "fpC6"},
	}, []Lease{l4, l6})

	// v4 transitioned: withdraw on A4, publish on B4.
	if got := updA4.deleteNames(); len(got) != 1 {
		t.Errorf("v4 withdraw on OLD backend A4 = %v, want 1", got)
	}
	if got := updB4.upsertNames(); len(got) != 1 {
		t.Errorf("v4 publish on NEW backend B4 = %v, want 1", got)
	}
	// v6 UNTOUCHED: no withdraw, and no re-publish (the pass-1 publish stands).
	if got := updC6.deleteNames(); len(got) != 0 {
		t.Errorf("v6 was withdrawn by a v4-only backend change: %v", got)
	}
	if got := updC6.upsertNames(); len(got) != 1 {
		t.Errorf("v6 was re-published by a v4-only backend change: %v (want the single pass-1 publish)", got)
	}
	// The v4 withdraw must not have been routed through v6's backend.
	if got := updC6.deleteNames(); len(got) != 0 {
		t.Errorf("v4 cleanup wrongly routed through v6 backend C6: %v", got)
	}
}

// TestReconcileBackendChangeOrphansWhenOldEndpointUnreachable_5814 covers the
// restart / lost-anchor case: an endpoint change is detected but the OLD backend
// is not reachable in-process (prevUpdater nil). The record must NOT be deleted
// at the new/wrong endpoint, must NOT be re-published (which would clobber the
// old cleanup key), ownership is KEPT, and the orphan alarm counter increments.
func TestReconcileBackendChangeOrphansWhenOldEndpointUnreachable_5814(t *testing.T) {
	updA := newFakeUpdater()
	updB := newFakeUpdater()
	m := testDDNS(t, nopUpdater{})
	pol := enabledPolicy()
	lease := leaseV4("10.0.1.5", "cid:aa", "laptop")

	// Pass 1 — publish through backend A.
	driveReconcile(t, m, &reconcileEnv{
		pol:       [2]ddnsPolicy{pol, pol},
		updater:   [2]DNSUpdater{updA, updA},
		backendFP: [2]string{"fpA", "fpA"},
	}, []Lease{lease})

	// Pass 2 — backend changed to B but NO previous anchor is available
	// (prevUpdater nil, as after a daemon restart).
	driveReconcile(t, m, &reconcileEnv{
		pol:       [2]ddnsPolicy{pol, pol},
		updater:   [2]DNSUpdater{updB, updB},
		backendFP: [2]string{"fpB", "fpB"},
		// prevUpdater deliberately left nil.
	}, []Lease{lease})

	if got := updB.deleteNames(); len(got) != 0 {
		t.Errorf("unreachable old endpoint: delete wrongly issued to NEW backend B: %v", got)
	}
	if got := updB.upsertNames(); len(got) != 0 {
		t.Errorf("unreachable old endpoint: republish wrongly issued (would clobber old cleanup key): %v", got)
	}
	// Ownership is retained (with the OLD fingerprint) so cleanup authority survives.
	if fp := backendFPOf(t, m, "10.0.1.5"); fp != "fpA" {
		t.Errorf("unreachable old endpoint: fingerprint = %q, want retained %q", fp, "fpA")
	}
	if n := m.Stats().OrphanedBackendChange; n != 1 {
		t.Errorf("OrphanedBackendChange = %d, want 1 (orphan alarm not raised)", n)
	}
}

// TestReconcileScopedBackendChangeEndToEnd_5814 drives the full resolve-per-
// Reconcile path (ReconcileScoped -> dhcpBackendFingerprint -> per-family anchor
// capture -> reconcile) with a factory that hands out a distinct fake updater per
// update-server. It proves the plumbing computes the fingerprint from the
// committed config, retains the previous backend, and routes the transition
// correctly — end to end, not just the inner reconcile.
func TestReconcileScopedBackendChangeEndToEnd_5814(t *testing.T) {
	updA := newFakeUpdater()
	updB := newFakeUpdater()
	dir := t.TempDir()
	src := &fakeLeaseSource{}
	m := newManagerForTesting(
		src.parser(),
		nopUpdater{},
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		switch c.UpdateServer {
		case "serverA":
			return updA, nil
		case "serverB":
			return updB, nil
		}
		return nopUpdater{}, nil
	}
	src.v4 = laptopMacLease()

	// Cycle 1 — publish through serverA.
	if err := m.Reconcile(context.Background(), ddnsCfg("serverA")); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if len(updA.upsertNames()) == 0 {
		t.Fatalf("cycle 1: nothing published on serverA")
	}

	// Cycle 2 — identical lease, update-server moved to serverB.
	if err := m.Reconcile(context.Background(), ddnsCfg("serverB")); err != nil {
		t.Fatalf("cycle 2 reconcile: %v", err)
	}
	if got := updB.upsertNames(); len(got) == 0 {
		t.Errorf("endpoint change: expected publish on serverB, got none")
	}
	if got := updA.deleteNames(); len(got) == 0 {
		t.Errorf("endpoint change: expected withdraw on serverA, got none (old endpoint orphaned)")
	}
	if got := updB.deleteNames(); len(got) != 0 {
		t.Errorf("endpoint change: withdraw wrongly routed to serverB: %v", got)
	}

	// Cycle 3 — steady state on serverB is settled (no further wire ops).
	beforeUp := len(updB.upsertNames())
	beforeDel := len(updB.deleteNames())
	if err := m.Reconcile(context.Background(), ddnsCfg("serverB")); err != nil {
		t.Fatalf("cycle 3 reconcile: %v", err)
	}
	if len(updB.upsertNames()) != beforeUp || len(updB.deleteNames()) != beforeDel {
		t.Errorf("cycle 3: steady state on serverB was not settled (extra wire ops)")
	}
}

// TestReconcileScopedBackendChangeAfterRestartOrphans_5814 is the post-restart
// fail-on-revert guard (the #5814 review defect). After a daemon restart the
// per-family anchor is lost, so the FIRST post-restart cycle correctly orphans.
// But the anchor then re-seeds to the NEW endpoint, so a SECOND post-restart
// cycle finds a non-nil anchor pointing at the WRONG server. Without the
// prevFP==owned-fingerprint identity gate it would misroute the withdraw of the
// OLD-endpoint record through the new server — orphaning the old server's record
// and dropping ownership while OrphanedBackendChange froze at 1. The gate must
// keep BOTH post-restart cycles on the orphan path: no delete to the new server,
// ownership retained with the OLD fingerprint, and the alarm incrementing every
// cycle. Reverting the gate (using prev whenever it is merely non-nil) misroutes
// the cycle-2 delete to serverB, flipping the updB.del==empty assertion RED.
func TestReconcileScopedBackendChangeAfterRestartOrphans_5814(t *testing.T) {
	updA := newFakeUpdater()
	updB := newFakeUpdater()
	dir := t.TempDir()
	src := &fakeLeaseSource{}
	m := newManagerForTesting(
		src.parser(),
		nopUpdater{},
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		switch c.UpdateServer {
		case "serverA":
			return updA, nil
		case "serverB":
			return updB, nil
		}
		return nopUpdater{}, nil
	}
	src.v4 = laptopMacLease()

	// Cycle 0 — publish on serverA (ownership stored with serverA's fingerprint).
	if err := m.Reconcile(context.Background(), ddnsCfg("serverA")); err != nil {
		t.Fatalf("cycle 0 reconcile: %v", err)
	}
	if len(updA.upsertNames()) == 0 {
		t.Fatalf("cycle 0: nothing published on serverA")
	}
	fpA := backendFPOf(t, m, "10.0.1.5")
	if fpA == "" {
		t.Fatalf("cycle 0: owned record has no fingerprint")
	}

	// Simulate a daemon RESTART: the in-process per-family anchor AND its
	// fingerprint are lost (a fresh Manager zeroes them), but the ownership store
	// persists the serverA fingerprint.
	m.mu.Lock()
	m.lastLiveUpdater = [2]DNSUpdater{}
	m.lastLiveFP = [2]string{}
	m.mu.Unlock()

	// Post-restart cycle 1 (resolve serverB): the old endpoint is unreachable
	// (anchor nil) → orphan + alarm=1. Nothing sent to serverB.
	if err := m.Reconcile(context.Background(), ddnsCfg("serverB")); err != nil {
		t.Fatalf("post-restart cycle 1 reconcile: %v", err)
	}
	if n := m.Stats().OrphanedBackendChange; n != 1 {
		t.Errorf("post-restart cycle 1: alarm = %d, want 1", n)
	}
	if got := updB.deleteNames(); len(got) != 0 {
		t.Errorf("post-restart cycle 1: misrouted delete to serverB: %v", got)
	}
	if got := updB.upsertNames(); len(got) != 0 {
		t.Errorf("post-restart cycle 1: republish on serverB clobbering the old cleanup key: %v", got)
	}

	// Post-restart cycle 2 (resolve serverB again): the anchor is now RE-SEEDED to
	// serverB, but the owned record's fingerprint is still serverA's. The identity
	// gate must STILL treat the old endpoint as unreachable — the smoking gun the
	// reviewer reproduced. No delete may reach serverB; ownership stays retained
	// with the serverA fingerprint; the alarm increments (never freezes at 1).
	if err := m.Reconcile(context.Background(), ddnsCfg("serverB")); err != nil {
		t.Fatalf("post-restart cycle 2 reconcile: %v", err)
	}
	if got := updB.deleteNames(); len(got) != 0 {
		t.Errorf("post-restart cycle 2: withdraw MISROUTED to serverB (wrong-endpoint delete): %v", got)
	}
	if got := updB.upsertNames(); len(got) != 0 {
		t.Errorf("post-restart cycle 2: republish on serverB clobbering the old cleanup key: %v", got)
	}
	if n := m.Stats().OrphanedBackendChange; n != 2 {
		t.Errorf("post-restart cycle 2: alarm = %d, want 2 (must fire every cycle, not freeze at 1)", n)
	}
	if !m.OwnedForTesting("mac:aa", "10.0.1.5") {
		t.Errorf("post-restart cycle 2: ownership was dropped (cleanup authority lost)")
	}
	if fp := backendFPOf(t, m, "10.0.1.5"); fp != fpA {
		t.Errorf("post-restart cycle 2: fingerprint = %q, want retained %q (never converged to the wrong endpoint)", fp, fpA)
	}
	// serverA never received a spurious extra op across the restart cycles.
	if got := updA.deleteNames(); len(got) != 0 {
		t.Errorf("serverA received a delete it should not have (old endpoint was unreachable): %v", got)
	}
}

// TestDHCPBackendFingerprintIdentity_5814 pins the fingerprint contract: it
// distinguishes server / TSIG-key / algorithm / transport-bind changes, is
// stable for an unchanged endpoint, EXCLUDES the TSIG secret (no secret ever
// hashed in), and returns "" (unknown) for a non-live family.
func TestDHCPBackendFingerprintIdentity_5814(t *testing.T) {
	base := &config.DHCPDynamicDNSConfig{
		Enabled: true, Backend: "rfc2136",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "ns1.example.com:53",
			TSIGKeyName:   "k1",
			TSIGAlgorithm: "hmac-sha256",
		},
	}
	fp := func(c *config.DHCPDynamicDNSConfig) string {
		return dhcpBackendFingerprint(policyFromConfig(c), c)
	}
	fpBase := fp(base)
	if fpBase == "" {
		t.Fatalf("live endpoint fingerprint is empty")
	}

	// Stable for an identical endpoint.
	if got := fp(&config.DHCPDynamicDNSConfig{
		Enabled: true, Backend: "rfc2136",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "ns1.example.com:53",
			TSIGKeyName:   "k1",
			TSIGAlgorithm: "hmac-sha256",
		},
	}); got != fpBase {
		t.Errorf("fingerprint not stable for identical endpoint: %q vs %q", got, fpBase)
	}

	// The TSIG SECRET is excluded — a different secret, same identity, same fp.
	withSecret := *base
	withSecret.TSIGSecret = config.NewSecret("super-secret-key-material")
	if got := fp(&withSecret); got != fpBase {
		t.Errorf("fingerprint changed when only the TSIG secret differs: %q vs %q "+
			"(secret must never be hashed in)", got, fpBase)
	}

	// Each identity field changes the fingerprint.
	for name, mut := range map[string]func(c *config.DHCPDynamicDNSConfig){
		"server":     func(c *config.DHCPDynamicDNSConfig) { c.UpdateServer = "ns2.example.com:53" },
		"tsig-key":   func(c *config.DHCPDynamicDNSConfig) { c.TSIGKeyName = "k2" },
		"tsig-alg":   func(c *config.DHCPDynamicDNSConfig) { c.TSIGAlgorithm = "hmac-sha512" },
		"source":     func(c *config.DHCPDynamicDNSConfig) { c.SourceAddress = "192.0.2.1" },
		"dest-iface": func(c *config.DHCPDynamicDNSConfig) { c.DestinationInterface = "ge-0-0-0" },
		"vrf":        func(c *config.DHCPDynamicDNSConfig) { c.RoutingInstance = "wan-vr" },
	} {
		c := *base
		mut(&c)
		if got := fp(&c); got == fpBase {
			t.Errorf("fingerprint unchanged after %s change (endpoint identity not tracked)", name)
		}
	}

	// Non-live families are "unknown" (empty).
	for name, c := range map[string]*config.DHCPDynamicDNSConfig{
		"disabled":       {Enabled: false, Backend: "rfc2136", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: "ns1.example.com:53"}},
		"no-server":      {Enabled: true, Backend: "rfc2136", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: ""}},
		"kea-d2-backend": {Enabled: true, Backend: "kea-d2", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: "ns1.example.com:53"}},
		"nil-config":     nil,
	} {
		if got := fp(c); got != "" {
			t.Errorf("%s: fingerprint = %q, want \"\" (unknown / no false transition)", name, got)
		}
	}
}
