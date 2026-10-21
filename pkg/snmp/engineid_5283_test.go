package snmp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5283: the SNMPv3 authoritative EngineID must carry a PER-DEVICE unique
// component so two same-hostname clones (HA pair, factory default, lab image,
// config restore) derive DIFFERENT EngineIDs — and therefore DIFFERENT localized
// USM keys — closing the cross-device auth bypass where an authenticated request
// captured from firewall A was accepted by firewall B.

func newAgentWithEngineIDPath(t *testing.T, cfg *config.SNMPConfig, engineIDPath string) *Agent {
	t.Helper()
	// Redirect BOTH persisted paths into the test tempdir so the agent never
	// touches /var/lib/xpf.
	bootsPath := filepath.Join(t.TempDir(), "engineboots")
	return NewAgentWithPaths(cfg, bootsPath, engineIDPath)
}

// TestEngineID_CloneUniqueness is the core anti-clone property: two agents on
// the SAME host (same os.Hostname, same /etc/machine-id) with DIFFERENT
// persisted per-device components derive DIFFERENT EngineIDs.
//
// RED-on-revert: revert buildEngineID to hostname-only (ignore the device
// component) and both agents collapse to the identical hostname-derived
// EngineID — exactly the #5283 bypass precondition — failing this test.
func TestEngineID_CloneUniqueness(t *testing.T) {
	dir := t.TempDir()
	a := newAgentWithEngineIDPath(t, nil, filepath.Join(dir, "dev-a"))
	b := newAgentWithEngineIDPath(t, nil, filepath.Join(dir, "dev-b"))

	if bytes.Equal(a.engineID, b.engineID) {
		t.Fatalf("two same-hostname clones derived IDENTICAL EngineIDs %x — cross-device USM key collision (the #5283 bypass)", a.engineID)
	}
}

// TestEngineID_RebootStable verifies the SAME device (same persisted component
// file) derives a STABLE EngineID across re-inits — a manager that cached our
// (engineBoots, engineTime) and localized its keys keeps working over a reboot.
func TestEngineID_RebootStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev")
	first := newAgentWithEngineIDPath(t, nil, path)
	// Second init reuses the component persisted by the first (simulated reboot).
	second := newAgentWithEngineIDPath(t, nil, path)

	if !bytes.Equal(first.engineID, second.engineID) {
		t.Fatalf("EngineID not stable across re-init: %x vs %x (persisted component not reused)", first.engineID, second.engineID)
	}
}

// TestEngineID_LengthCap keeps the #4917/#5264 RFC 3411 5..32-octet invariant at
// the agent level: the per-device component must not push the EngineID out of
// range.
func TestEngineID_LengthCap(t *testing.T) {
	a := newAgentWithEngineIDPath(t, nil, filepath.Join(t.TempDir(), "dev"))
	if len(a.engineID) < 5 || len(a.engineID) > snmpEngineIDMaxLen {
		t.Fatalf("EngineID length %d out of RFC 3411 range 5..32", len(a.engineID))
	}
}

// TestEngineID_USMKeysDivergeAcrossClones is the direct proof the bypass is
// closed: two agents with the SAME v3 user (identical username/password/proto)
// but DIFFERENT per-device components localize DIFFERENT auth AND priv keys, so
// clone A's authenticated packet can never validate against clone B.
func TestEngineID_USMKeysDivergeAcrossClones(t *testing.T) {
	mkCfg := func() *config.SNMPConfig {
		return &config.SNMPConfig{
			V3Users: map[string]*config.SNMPv3User{
				"monitor": {
					Name:         "monitor",
					AuthProtocol: "sha256",
					AuthPassword: config.NewSecret("auth-password-123"),
					PrivProtocol: "aes128",
					PrivPassword: config.NewSecret("priv-password-456"),
				},
			},
		}
	}
	dir := t.TempDir()
	a := newAgentWithEngineIDPath(t, mkCfg(), filepath.Join(dir, "dev-a"))
	b := newAgentWithEngineIDPath(t, mkCfg(), filepath.Join(dir, "dev-b"))

	ua := a.snapshotV3User("monitor")
	ub := b.snapshotV3User("monitor")
	if ua == nil || ub == nil {
		t.Fatal("monitor user missing on one of the agents")
	}
	if len(ua.authKey) == 0 || len(ub.authKey) == 0 {
		t.Fatal("auth key not localized")
	}
	if bytes.Equal(ua.authKey, ub.authKey) {
		t.Fatal("same-password clones localized IDENTICAL auth keys — cross-device auth bypass NOT closed")
	}
	if len(ua.privKey) == 0 || len(ub.privKey) == 0 {
		t.Fatal("priv key not localized")
	}
	if bytes.Equal(ua.privKey, ub.privKey) {
		t.Fatal("same-password clones localized IDENTICAL priv keys — cross-device priv bypass NOT closed")
	}
}

// TestPersistedComponent_FormatAndPerms verifies the persisted component is a
// 16-byte value stored as hex text with 0600 perms, and is regenerated when the
// file is corrupted.
func TestPersistedComponent_FormatAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev")
	first := newAgentWithEngineIDPath(t, nil, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("persisted component not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("persisted component perms %o, want 0600", perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted component: %v", err)
	}
	// 16 bytes -> 32 hex chars + trailing newline.
	if n := len(string(data)); n != deviceComponentLen*2+1 {
		t.Fatalf("persisted component encoded length %d, want %d", n, deviceComponentLen*2+1)
	}

	// Corrupt the file -> next init regenerates a valid component and a NEW
	// EngineID (the corrupt bytes are not silently reused).
	if err := os.WriteFile(path, []byte("not-hex!!"), 0o600); err != nil {
		t.Fatalf("corrupt persisted component: %v", err)
	}
	regen := newAgentWithEngineIDPath(t, nil, path)
	if len(regen.engineID) < 5 || len(regen.engineID) > snmpEngineIDMaxLen {
		t.Fatalf("regenerated EngineID length %d out of range", len(regen.engineID))
	}
	if bytes.Equal(first.engineID, regen.engineID) {
		t.Fatal("regenerated EngineID equals the pre-corruption one despite a corrupt component file")
	}
	// And the corrupt file was replaced with a well-formed hex component.
	data2, _ := os.ReadFile(path)
	if n := len(string(data2)); n != deviceComponentLen*2+1 {
		t.Fatalf("regenerated component encoded length %d, want %d", n, deviceComponentLen*2+1)
	}
}
