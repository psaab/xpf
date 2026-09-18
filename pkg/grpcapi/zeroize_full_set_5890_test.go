package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestPerformZeroizeWipeErasesFullSecretSet_5890 pins that the SHARED
// factory-reset primitive PerformZeroizeWipe — the exact function BOTH the gRPC
// runZeroize AND the interactive console (cli.performConsoleZeroize, #5890) now
// delegate to — erases the COMPLETE owned secret set in one pass: the config
// state (.configdb SSOT + master.key), the REST-API tls/ private key, the
// rendered service configs (frr managed section + swanctl IKE-PSK + kea), the
// provisioned OS login accounts (userdel + authorized_keys + sudoers.d/xpf-*),
// and the config archive. Every leg is seamed onto a throwaway tree, so the test
// never touches the real /etc, /sys/fs/bpf, or /etc/systemd/network.
//
// It is the security backstop for the #5890 console fix: the interactive console
// delegates here, so whatever this primitive erases, the console erases too —
// the two paths cannot present a divergent (partial) secret set.
//
// RED on revert: dropping any leg from performZeroizeWipe leaves the matching
// secret behind — the corresponding assertion fails. (The console's own #5890
// revert — reverting it to the partial zeroizeConfigState — is caught in
// pkg/cli.)
func TestPerformZeroizeWipeErasesFullSecretSet_5890(t *testing.T) {
	root := t.TempDir()

	// --- Config root (the PerformZeroizeWipe parameter): .configdb + master.key
	// + tls/ private key + the live config text. ---
	configDir := filepath.Join(root, "etc-xpf")
	if err := os.MkdirAll(filepath.Join(configDir, ".configdb"), 0o700); err != nil {
		t.Fatal(err)
	}
	masterKey := filepath.Join(configDir, ".configdb", "master.key")
	mustWriteFile(t, masterKey, []byte("AES-GCM-KEY"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	configBase := "xpf.conf"
	configFile := filepath.Join(configDir, configBase)
	mustWriteFile(t, configFile, []byte("system { host-name fw; }\n"))
	tlsKey := filepath.Join(configDir, "tls", "key.pem")
	mustWriteFile(t, tlsKey, []byte("-----BEGIN PRIVATE KEY-----\n"))

	// --- Rendered service configs (seamed off /etc via the #5890 vars). ---
	const secret = "MARKER-SECRET-5890"
	frrConf := filepath.Join(root, "frr", "frr.conf")
	const operatorFRR = "hostname r1\nrouter bgp 65000\n ! operator-managed, must survive\n"
	mustWriteFile(t, frrConf, []byte(operatorFRR+
		"! BEGIN BPFRX MANAGED CONFIG - do not edit this section\n"+
		" ip ospf message-digest-key 1 md5 "+secret+"\n"+
		"! END BPFRX MANAGED CONFIG\n"))
	swanctl := filepath.Join(root, "swanctl", "xpf.conf")
	kea4 := filepath.Join(root, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(root, "kea", "kea-dhcp6.conf")
	mustWriteFile(t, swanctl, []byte("secrets { ike { secret = "+secret+" } }\n"))
	mustWriteFile(t, kea4, []byte(secret))
	mustWriteFile(t, kea6, []byte(secret))

	origFRR, origSwan, origK4, origK6 := zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf
	origBPF, origND := zeroizeBPFPinDir, zeroizeNetworkdDir
	t.Cleanup(func() {
		zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf = origFRR, origSwan, origK4, origK6
		zeroizeBPFPinDir, zeroizeNetworkdDir = origBPF, origND
	})
	zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf = frrConf, swanctl, kea4, kea6
	// Non-secret best-effort legs onto a throwaway tree so nothing real is touched.
	zeroizeBPFPinDir = filepath.Join(root, "bpf-pins")
	zeroizeNetworkdDir = filepath.Join(root, "networkd")
	mustWriteFile(t, filepath.Join(zeroizeNetworkdDir, "10-xpf-ge-0-0-0.link"), []byte("x"))
	operatorND := filepath.Join(zeroizeNetworkdDir, "20-operator.network")
	mustWriteFile(t, operatorND, []byte("operator"))

	// --- Provisioned login accounts (seamed via the #4598 helper). ---
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")
	mustWriteFile(t, passwdPath, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"alice:x:1001:1001:alice:/home/alice:/bin/bash\n"))
	mustWriteFile(t, filepath.Join(provDir, "alice"), []byte("1001"))
	xpfAliceSudo := filepath.Join(sudoersDir, "xpf-alice")
	operatorSudo := filepath.Join(sudoersDir, "90-cloud-init")
	mustWriteFile(t, xpfAliceSudo, []byte("alice ALL=(ALL) NOPASSWD: ALL\n"))
	mustWriteFile(t, operatorSudo, []byte("operator ALL=(ALL) ALL\n"))
	aliceKeys := filepath.Join(homeBase, "alice", ".ssh", "authorized_keys")
	mustWriteFile(t, aliceKeys, []byte("ssh-ed25519 AAAAxpf alice\n"))
	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	// --- Config archive (seamed via configstore.DefaultArchiveDir; the wipe's
	// ownership guard requires the arg to equal DefaultArchiveDir). ---
	archiveDir := filepath.Join(root, "archive")
	origArchive := configstore.DefaultArchiveDir
	configstore.DefaultArchiveDir = archiveDir
	t.Cleanup(func() { configstore.DefaultArchiveDir = origArchive })
	archiveSnap := filepath.Join(archiveDir, "config-20260101.1.conf")
	mustWriteFile(t, archiveSnap, []byte("system { services { ssh; } }\n"+secret))

	// === Drive the SHARED primitive the console delegates to. ===
	// #7173: the archive dir is now a PARAMETER, not read from the package
	// default. Passing "" here would mean "archival disabled" and silently skip
	// the archive leg this test exists to assert — the erasure would not be
	// tested and the test would still pass its other legs.
	if err := PerformZeroizeWipe(configDir, configBase, archiveDir); err != nil {
		t.Fatalf("PerformZeroizeWipe returned error (reset reported incomplete): %v", err)
	}

	// Config state + tls key gone.
	assertAbsent(t, masterKey)
	assertAbsent(t, filepath.Join(configDir, ".configdb"))
	assertAbsent(t, configFile)
	assertAbsent(t, tlsKey)

	// Rendered secrets gone; operator FRR content survives.
	if b, err := os.ReadFile(frrConf); err != nil {
		t.Fatalf("read frr.conf: %v", err)
	} else if strings.Contains(string(b), secret) || strings.Contains(string(b), "BPFRX MANAGED CONFIG") {
		t.Errorf("frr.conf still carries the xpf managed section / secret after zeroize:\n%s", b)
	} else if !strings.Contains(string(b), "router bgp 65000") {
		t.Errorf("zeroize removed operator FRR content:\n%s", b)
	}
	assertAbsent(t, swanctl)
	assertAbsent(t, kea4)
	assertAbsent(t, kea6)

	// Login accounts torn down; operator artifacts survive.
	if len(*deleted) != 1 || (*deleted)[0] != "alice" {
		t.Errorf("userdel invoked for %v, want exactly [alice]", *deleted)
	}
	assertAbsent(t, xpfAliceSudo)
	assertAbsent(t, aliceKeys)
	assertPresent(t, operatorSudo)

	// Archive snapshot (cleartext secret leaves) gone.
	assertAbsent(t, archiveSnap)

	// Non-secret legs: xpf-owned networkd file gone, operator networkd survives.
	assertAbsent(t, filepath.Join(zeroizeNetworkdDir, "10-xpf-ge-0-0-0.link"))
	assertPresent(t, operatorND)
}
