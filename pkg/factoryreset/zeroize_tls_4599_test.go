package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

// TestZeroizeConfigDirWipesTLSKey pins #4599: a factory-reset wipe must remove
// the self-signed REST-API TLS pair under /etc/xpf/tls (key.pem — the
// device-generated localhost HTTPS private key — and cert.pem) so the prior
// tenant's key is not handed to the next owner. The pair is xpf-generated and
// regenerated on absence (generateSelfSignedCertAt), so removing it is safe.
//
// RED on revert: before this fix, wipeConfigDir removed only the .configdb
// SSOT + top-level .conf/rollback/journal artifacts and never recursed into the
// tls/ subdir (the top-level ReadDir loop uses os.Remove, which cannot delete a
// non-empty directory and never matched the "tls" name anyway), so tls/key.pem
// and tls/cert.pem SURVIVED — the two assertAbsent calls on them fail.
func TestZeroizeConfigDirWipesTLSKey(t *testing.T) {
	dir := t.TempDir()
	configBase := "xpf.conf"
	configPath := filepath.Join(dir, configBase)
	marker := []byte(wipeMarker)

	// The self-signed REST-API TLS pair (#4599 target).
	tlsDir := filepath.Join(dir, "tls")
	tlsKey := filepath.Join(tlsDir, "key.pem")
	tlsCert := filepath.Join(tlsDir, "cert.pem")
	mustWriteFile(t, tlsKey, []byte("-----BEGIN EC PRIVATE KEY-----\n"))
	mustWriteFile(t, tlsCert, []byte("-----BEGIN CERTIFICATE-----\n"))

	// Regression guard: the existing SSOT/rollback/journal removals must still
	// hold with the tls/ removal in place.
	masterKey := filepath.Join(dir, ".configdb", "master.key")
	activeJSON := filepath.Join(dir, ".configdb", "active.json")
	journalPath := filepath.Join(dir, ".config.journal")
	textRollback := configPath + ".1"
	mustWriteFile(t, masterKey, make([]byte, 32))
	mustWriteFile(t, activeJSON, marker)
	mustWriteFile(t, journalPath, marker)
	mustWriteFile(t, configPath, marker)
	mustWriteFile(t, textRollback, marker)

	// A non-xpf file in the same dir must be LEFT ALONE.
	bystander := filepath.Join(dir, "node-id")
	mustWriteFile(t, bystander, []byte("0"))

	if err := wipeConfigDir(dir, configBase); err != nil {
		t.Fatalf("wipeConfigDir returned error: %v", err)
	}

	// The TLS pair AND its directory are gone (the #4599 fix; RED on revert).
	for _, p := range []string{tlsKey, tlsCert, tlsDir} {
		assertAbsent(t, p)
	}

	// The pre-existing removals still hold.
	for _, p := range []string{
		filepath.Join(dir, ".configdb"), masterKey, activeJSON,
		journalPath, configPath, textRollback,
	} {
		assertAbsent(t, p)
	}

	// Scope guard: the non-xpf file survives.
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("zeroize removed a non-xpf file %s: %v", bystander, err)
	}
}
