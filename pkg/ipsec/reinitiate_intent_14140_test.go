package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14140: reinitiateChangedConnections initiated EVERY child of a changed
// connection whose live SA terminated, without inspecting responder-only
// or on-traffic intent. policy.go deliberately renders no start_action
// for a ResponderOnly gateway and trap (not start) for on-traffic, so the
// post-change reinitiation contradicted the rendered policy: a live
// responder-only VPN whose config changed was eagerly dialed with
// `swanctl --initiate --child <name>` against remote_addrs = %any, and
// the initiate error propagated out of Apply (manager.go errors.Join),
// turning an unrelated config change into a failed commit. The decisive
// check from the issue: a changed+terminated responder-only VPN must not
// be initiated and Apply must succeed, settled by the fake's argv.

// eagerCfg builds a one-VPN config through a defined gateway so the test
// can flip ResponderOnly / EstablishTunnels / the gateway address shape.
func eagerCfg(gw *config.IPsecGateway, vpn *config.IPsecVPN) *config.IPsecConfig {
	vpn.Gateway = gw.Name
	return &config.IPsecConfig{
		Gateways:  map[string]*config.IPsecGateway{gw.Name: gw},
		VPNs:      map[string]*config.IPsecVPN{"site-a": vpn},
		Proposals: map[string]*config.IPsecProposal{},
	}
}

// applyChange14140 drives the #3941-style two-Apply flow: a first Apply
// loads the old config, then a second Apply with a rotated PSK (a
// security-effective rendered change) while the old SA is live. It
// returns the second Apply's error.
func applyChange14140(t *testing.T, rec *swanctlRecorder, m *Manager, oldCfg, newCfg *config.IPsecConfig) error {
	t.Helper()
	if err := m.Apply(oldCfg); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")
	return m.Apply(newCfg)
}

func TestChangedResponderOnlyVPNIsNotReinitiated14140(t *testing.T) {
	for _, mode := range []string{"immediately", "on-traffic", "responder-only", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			rec := &swanctlRecorder{}
			m := newRecordingManager(t, rec)
			mk := func(psk string) *config.IPsecConfig {
				return eagerCfg(
					&config.IPsecGateway{Name: "dial-in", ResponderOnly: true, RemoteIDType: "hostname", RemoteIDValue: "dialin.example.com", LocalAddress: "203.0.113.5"},
					&config.IPsecVPN{PSK: config.Secret(psk), EstablishTunnels: mode},
				)
			}
			if err := applyChange14140(t, rec, m, mk("old-secret"), mk("rotated-secret")); err != nil {
				t.Fatalf("changed responder-only Apply must succeed, got %v (calls %v)", err, rec.calls)
			}
			if got := rec.terminateCalls(); len(got) != 1 || got[0] != "site-a" {
				t.Fatalf("stale SA must still be terminated, got %v", got)
			}
			if got := rec.initiateCalls(); len(got) != 0 {
				t.Fatalf("responder-only VPN must not be reinitiated, got initiate %v (calls %v)", got, rec.calls)
			}
		})
	}
}

func TestChangedNonEagerModesAreNotReinitiated14140(t *testing.T) {
	// A fixed-address gateway isolates EstablishTunnels as the only
	// variable: on-traffic renders trap, the absent Junos default also
	// renders trap (#14592), responder-only mode renders no start_action
	// — none may be eagerly initiated after a change.
	for _, mode := range []string{"on-traffic", "responder-only", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			rec := &swanctlRecorder{}
			m := newRecordingManager(t, rec)
			mk := func(psk string) *config.IPsecConfig {
				return eagerCfg(
					&config.IPsecGateway{Name: "gw", Address: "10.0.2.1"},
					&config.IPsecVPN{PSK: config.Secret(psk), EstablishTunnels: mode},
				)
			}
			if err := applyChange14140(t, rec, m, mk("old-secret"), mk("rotated-secret")); err != nil {
				t.Fatalf("changed %q Apply must succeed, got %v", mode, err)
			}
			if got := rec.terminateCalls(); len(got) != 1 || got[0] != "site-a" {
				t.Fatalf("stale SA must still be terminated, got %v", got)
			}
			if got := rec.initiateCalls(); len(got) != 0 {
				t.Fatalf("establish-tunnels=%q must not be eagerly reinitiated, got %v", mode, got)
			}
		})
	}
}

// TestChangedImmediatelyVPNIsStillReinitiated14140 is the control: the
// gate must not suppress the reinitiation that #10878 exists for. Both a
// defined fixed-address gateway and a legacy inline endpoint (no
// Gateways entry) with establish-tunnels=immediately reinitiate.
func TestChangedImmediatelyVPNIsStillReinitiated14140(t *testing.T) {
	t.Run("defined gateway", func(t *testing.T) {
		rec := &swanctlRecorder{}
		m := newRecordingManager(t, rec)
		mk := func(psk string) *config.IPsecConfig {
			return eagerCfg(
				&config.IPsecGateway{Name: "gw", Address: "10.0.2.1"},
				&config.IPsecVPN{PSK: config.Secret(psk), EstablishTunnels: "immediately"},
			)
		}
		if err := applyChange14140(t, rec, m, mk("old-secret"), mk("rotated-secret")); err != nil {
			t.Fatalf("changed immediately Apply: %v", err)
		}
		if got := rec.initiateCalls(); len(got) != 1 || got[0] != "site-a" {
			t.Fatalf("immediately VPN must be reinitiated, got %v", got)
		}
	})

	t.Run("inline endpoint", func(t *testing.T) {
		rec := &swanctlRecorder{}
		m := newRecordingManager(t, rec)
		mk := func(psk string) *config.IPsecConfig {
			cfg := vpnCfg("site-a")
			cfg.VPNs["site-a"].PSK = config.Secret(psk)
			cfg.VPNs["site-a"].EstablishTunnels = "immediately"
			return cfg
		}
		if err := applyChange14140(t, rec, m, mk("old-secret"), mk("rotated-secret")); err != nil {
			t.Fatalf("changed immediately Apply: %v", err)
		}
		if got := rec.initiateCalls(); len(got) != 1 || got[0] != "site-a" {
			t.Fatalf("inline-endpoint immediately VPN must be reinitiated, got %v", got)
		}
	})

	// #14590: a dynamic-hostname gateway is responder-only, so even an
	// immediately VPN through it is never reinitiated (nothing to dial).
	t.Run("dynamic hostname gateway is responder-only", func(t *testing.T) {
		rec := &swanctlRecorder{}
		m := newRecordingManager(t, rec)
		mk := func(psk string) *config.IPsecConfig {
			return eagerCfg(
				&config.IPsecGateway{Name: "gw", DynamicHostname: "peer.example.com", ResponderOnly: true},
				&config.IPsecVPN{PSK: config.Secret(psk), EstablishTunnels: "immediately"},
			)
		}
		if err := applyChange14140(t, rec, m, mk("old-secret"), mk("rotated-secret")); err != nil {
			t.Fatalf("changed dynamic-hostname Apply: %v", err)
		}
		if got := rec.initiateCalls(); len(got) != 0 {
			t.Fatalf("dynamic-hostname (responder) VPN must not be reinitiated, got %v", got)
		}
	})
}

// TestChangedModeTransitionToNonEagerIsNotReinitiated14140 pins that the
// NEW config's mode governs: flipping immediately -> on-traffic (itself
// a rendered change) must not eagerly initiate under the new trap policy.
func TestChangedModeTransitionToNonEagerIsNotReinitiated14140(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	mk := func(psk, mode string) *config.IPsecConfig {
		return eagerCfg(
			&config.IPsecGateway{Name: "gw", Address: "10.0.2.1"},
			&config.IPsecVPN{PSK: config.Secret(psk), EstablishTunnels: mode},
		)
	}
	if err := applyChange14140(t, rec, m, mk("old-secret", "immediately"), mk("old-secret", "on-traffic")); err != nil {
		t.Fatalf("mode-transition Apply must succeed, got %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("mode change must terminate the stale SA, got %v", got)
	}
	if got := rec.initiateCalls(); len(got) != 0 {
		t.Fatalf("transition to on-traffic must not eagerly reinitiate, got %v", got)
	}
}
