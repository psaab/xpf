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
// a require-tsig updater with no key refuses a non-loopback exchange before
// any byte is sent, so a forged rcode can never record durable ownership.
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
