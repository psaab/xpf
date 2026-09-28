package grpcapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// isolateZeroizeSealPaths redirects every F6 system-path leg, including the
// DDNS ownership files and the pre-existing /var/log seam, into root.
func isolateZeroizeSealPaths(t *testing.T, root string) {
	t.Helper()
	oldMachine, oldSSH, oldRootSSH, oldHistory := zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory
	oldEngineID, oldBoots, oldSeed := zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed
	oldAptLists, oldAptArchive, oldUtmp := zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath
	oldDay0Reject, oldRootGrown := zeroizeDay0RejectedPath, zeroizeRootGrownPath
	oldDDNSLease, oldDDNSSurface := zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath
	oldPasswdBackups, oldHostKeys := zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath
	oldDropins, oldVarLog := zeroizeManagedDropins, zeroizeVarLogDir
	oldHostname, oldResolv, oldIPsec := zeroizeHostnamePath, zeroizeResolvConfPath, zeroizeIPsecStatePath
	oldKeaPaths, oldStopKea := zeroizeKeaLeasePaths, zeroizeStopKeaUnits
	t.Cleanup(func() {
		zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory = oldMachine, oldSSH, oldRootSSH, oldHistory
		zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed = oldEngineID, oldBoots, oldSeed
		zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath = oldAptLists, oldAptArchive, oldUtmp
		zeroizeDay0RejectedPath, zeroizeRootGrownPath = oldDay0Reject, oldRootGrown
		zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath = oldDDNSLease, oldDDNSSurface
		zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath = oldPasswdBackups, oldHostKeys
		zeroizeManagedDropins, zeroizeVarLogDir = oldDropins, oldVarLog
		zeroizeHostnamePath, zeroizeResolvConfPath, zeroizeIPsecStatePath = oldHostname, oldResolv, oldIPsec
		zeroizeKeaLeasePaths, zeroizeStopKeaUnits = oldKeaPaths, oldStopKea
	})

	zeroizeMachineIDPath = filepath.Join(root, "etc", "machine-id")
	zeroizeSSHHostKeyDir = filepath.Join(root, "etc", "ssh")
	zeroizeRootSSHUserDir = filepath.Join(root, "root", ".ssh")
	zeroizeRootBashHistory = filepath.Join(root, "root", ".bash_history")
	zeroizeSNMPEngineIDPath = filepath.Join(root, "var", "lib", "xpf", "snmp-engine-id")
	zeroizeSNMPEngineBootsPath = filepath.Join(root, "var", "lib", "xpf", "snmp-engineboots")
	zeroizeSystemdRandomSeed = filepath.Join(root, "var", "lib", "systemd", "random-seed")
	zeroizeAptListsDir = filepath.Join(root, "var", "lib", "apt", "lists")
	zeroizeAptArchiveDir = filepath.Join(root, "var", "cache", "apt", "archives")
	zeroizeRunUtmpPath = filepath.Join(root, "run", "utmp")
	zeroizeDay0RejectedPath = filepath.Join(root, "etc", "xpf", ".day0-config-rejected")
	zeroizeRootGrownPath = filepath.Join(root, "etc", "xpf", ".root-grown")
	zeroizeDDNSLeaseStatePath = filepath.Join(root, "var", "lib", "xpf", "dhcp-ddns-state.json")
	zeroizeDDNSSurfaceAPath = filepath.Join(root, "var", "lib", "xpf", "interface-ddns-state.json")
	zeroizePasswdBackupPaths = []string{
		filepath.Join(root, "etc", "passwd-"), filepath.Join(root, "etc", "shadow-"),
		filepath.Join(root, "etc", "group-"), filepath.Join(root, "etc", "gshadow-"),
	}
	zeroizeManagedHostKeysPath = filepath.Join(root, "etc", "ssh", "ssh_known_hosts")
	zeroizeManagedDropins = []string{
		filepath.Join(root, "etc", "ssh", "sshd_config.d", "00-xpf.conf"),
		filepath.Join(root, "etc", "ssh", "sshd_config.d", "xpf.conf"),
		filepath.Join(root, "etc", "chrony", "sources.d", "xpf.sources"),
		filepath.Join(root, "etc", "chrony", "conf.d", "xpf-threshold.conf"),
		filepath.Join(root, "etc", "systemd", "resolved.conf.d", "xpf.conf"),
		filepath.Join(root, "etc", "systemd", "resolved.conf.d", "bpfrx.conf"),
	}
	zeroizeHostnamePath = filepath.Join(root, "etc", "hostname")
	zeroizeResolvConfPath = filepath.Join(root, "etc", "resolv.conf")
	zeroizeIPsecStatePath = filepath.Join(root, "var", "lib", "xpf", "ipsec-conn-state.json")
	zeroizeKeaLeasePaths = []string{
		filepath.Join(root, "var", "lib", "kea", "kea-leases4.csv"),
		filepath.Join(root, "var", "lib", "kea", "kea-leases6.csv"),
	}
	zeroizeStopKeaUnits = func() error { return nil }
	zeroizeVarLogDir = filepath.Join(root, "var", "log")
}

// RED on revert: dropping zeroizeImageSealResidue from performZeroizeWipe
// leaves prior-tenant machine identity, leases, keys, trust, resolver, and logs.
func TestPerformZeroizeErasesSafeImageSealResidue10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	if err := os.MkdirAll(filepath.Join(configDir, ".configdb"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".configdb", "master.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	machineID := zeroizeMachineIDPath
	hostname, resolver := zeroizeHostnamePath, zeroizeResolvConfPath
	keaLease4, keaLease6 := zeroizeKeaLeasePaths[0], zeroizeKeaLeasePaths[1]
	ipsecState := zeroizeIPsecStatePath
	sshHostKey := filepath.Join(zeroizeSSHHostKeyDir, "ssh_host_ed25519_key")
	sshHostPub := sshHostKey + ".pub"
	foreignSSH := filepath.Join(zeroizeSSHHostKeyDir, "sshd_config")
	rootSSHKey := filepath.Join(zeroizeRootSSHUserDir, "id_ed25519")
	history := zeroizeRootBashHistory
	engineID, engineBoots, randomSeed := zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed
	for path, body := range map[string]string{
		machineID: "machine-id-secret\n", hostname: "prior-tenant.example\n",
		resolver: zeroizeManagedResolvConfHeader + "nameserver 192.0.2.53\n",
		keaLease4: "prior client lease v4", keaLease6: "prior client lease v6",
		ipsecState: `{"loaded":[],"pending_terminate":[]}`,
		sshHostKey: "private host key", sshHostPub: "public host key",
		foreignSSH: "unmanaged ssh config", rootSSHKey: "root private key", history: "old shell commands\n",
		engineID: "snmp-engine-identity", engineBoots: "17\n", randomSeed: "old entropy",
		zeroizeRunUtmpPath: "login records", zeroizeDay0RejectedPath: "reject marker", zeroizeRootGrownPath: "grown",
		zeroizeManagedHostKeysPath:  zeroizeManagedHostKeysHeader + "old.example ssh-ed25519 AAAA\n",
		zeroizePasswdBackupPaths[0]: "old passwd", zeroizePasswdBackupPaths[1]: "old shadow",
		zeroizePasswdBackupPaths[2]: "old group", zeroizePasswdBackupPaths[3]: "old gshadow",
		zeroizeManagedDropins[0]: "old sshd policy", zeroizeManagedDropins[1]: "legacy sshd policy",
		zeroizeManagedDropins[2]: "old chrony sources", zeroizeManagedDropins[3]: "old chrony threshold",
		zeroizeManagedDropins[4]: "old resolved config", zeroizeManagedDropins[5]: "legacy resolved config",
		filepath.Join(zeroizeAptListsDir, "example_Packages"):     "package list",
		filepath.Join(zeroizeAptArchiveDir, "old.deb"):            "package archive",
		filepath.Join(zeroizeVarLogDir, "journal", "old.journal"): "prior tenant journal",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keaStopped := false
	zeroizeStopKeaUnits = func() error {
		for _, path := range []string{keaLease4, keaLease6} {
			if _, err := os.Lstat(path); err != nil {
				return fmt.Errorf("Kea lease file %s missing before stop: %w", path, err)
			}
		}
		keaStopped = true
		return nil
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if !keaStopped {
		t.Fatal("Kea must be stopped before its lease files are erased")
	}
	if body, err := os.ReadFile(machineID); err != nil || len(body) != 0 {
		t.Fatalf("machine-id should remain present but empty for systemd regeneration; body=%q err=%v", body, err)
	}
	if body, err := os.ReadFile(hostname); err != nil || string(body) != "xpf\n" {
		t.Fatalf("hostname should reset to the appliance default: body=%q err=%v", body, err)
	}
	for _, path := range []string{
		sshHostKey, sshHostPub, rootSSHKey, history, engineID, engineBoots, randomSeed,
		keaLease4, keaLease6, ipsecState, resolver,
		zeroizeRunUtmpPath, zeroizeDay0RejectedPath, zeroizeRootGrownPath,
		zeroizeManagedHostKeysPath, zeroizePasswdBackupPaths[0], zeroizePasswdBackupPaths[1],
		zeroizePasswdBackupPaths[2], zeroizePasswdBackupPaths[3],
		zeroizeManagedDropins[0], zeroizeManagedDropins[1], zeroizeManagedDropins[2],
		zeroizeManagedDropins[3], zeroizeManagedDropins[4], zeroizeManagedDropins[5],
		filepath.Join(zeroizeAptListsDir, "example_Packages"), filepath.Join(zeroizeAptArchiveDir, "old.deb"),
		filepath.Join(zeroizeVarLogDir, "journal", "old.journal"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("sealed prior-tenant artifact %s survived: %v", path, err)
		}
	}
	if body, err := os.ReadFile(foreignSSH); err != nil || string(body) != "unmanaged ssh config" {
		t.Errorf("unrelated SSH config changed: body=%q err=%v", body, err)
	}
}

func TestZeroizePreservesUnownedKnownHosts10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	if err := os.MkdirAll(filepath.Dir(zeroizeManagedHostKeysPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := "operator-owned known hosts\n"
	if err := os.WriteFile(zeroizeManagedHostKeysPath, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := zeroizeRemoveManagedHostKeys(zeroizeManagedHostKeysPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(zeroizeManagedHostKeysPath)
	if err != nil || string(got) != want {
		t.Fatalf("unowned SSH known-hosts file was not preserved: body=%q err=%v", got, err)
	}
}

func TestZeroizeDoesNotEraseDDNSDeleteAuthority10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	state := `{"version":1,"records":[{"family":4,"identity":"client","address":"192.0.2.8","fqdn":"client.example.test","forward_type":"A","ptr_name":"8.2.0.192.in-addr.arpa","ttl":300,"backend_fingerprint":"fp1-test"}]}`
	if err := os.MkdirAll(filepath.Dir(zeroizeDDNSLeaseStatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeroizeDDNSLeaseStatePath, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := zeroizeEraseDDNSState(); err == nil || !strings.Contains(err.Error(), "still has 1 record") {
		t.Fatalf("non-empty DDNS ownership store must block erase, got %v", err)
	}
	if got, err := os.ReadFile(zeroizeDDNSLeaseStatePath); err != nil || string(got) != state {
		t.Fatalf("failed ownership check must preserve DDNS delete authority: body=%q err=%v", got, err)
	}
}

func TestPerformZeroizeKeepsConfigWhenDDNSWithdrawalIsUnresolved10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc", "xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("tenant config"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { secret tenant; }\n"))
	state := `{"version":1,"records":[{"family":4,"identity":"client","address":"192.0.2.8","fqdn":"client.example.test","forward_type":"A","ptr_name":"8.2.0.192.in-addr.arpa","ttl":300,"backend_fingerprint":"fp1-test"}]}`
	if err := os.MkdirAll(filepath.Dir(zeroizeDDNSLeaseStatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeroizeDDNSLeaseStatePath, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil {
		t.Fatal("unresolved DDNS ownership must fail the reset before any wipe leg")
	}
	for _, path := range []string{
		filepath.Join(configDir, ".configdb", "master.key"),
		filepath.Join(configDir, ".configdb", "active.json"),
		filepath.Join(configDir, "xpf.conf"),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("config credential %s must survive failed DDNS preflight: %v", path, err)
		}
	}
	if got, err := os.ReadFile(zeroizeDDNSLeaseStatePath); err != nil || string(got) != state {
		t.Fatalf("DDNS deletion authority must survive failed preflight: body=%q err=%v", got, err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Fatalf("DDNS preflight must run before pending marker creation, got %v", err)
	}
}

func TestZeroizePreservesForeignResolver10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	if err := os.MkdirAll(filepath.Dir(zeroizeResolvConfPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := "nameserver 192.0.2.1\n"
	if err := os.WriteFile(zeroizeResolvConfPath, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := zeroizeRemoveManagedResolvConf(zeroizeResolvConfPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(zeroizeResolvConfPath)
	if err != nil || string(got) != want {
		t.Fatalf("unowned resolver file was not preserved: body=%q err=%v", got, err)
	}
}

func TestZeroizePreservesForeignResolverSymlink10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	if err := os.MkdirAll(filepath.Dir(zeroizeResolvConfPath), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "run", "systemd", "resolve", "stub-resolv.conf")
	mustWriteFile(t, target, []byte("nameserver 127.0.0.53\n"))
	if err := os.Symlink(target, zeroizeResolvConfPath); err != nil {
		t.Fatal(err)
	}
	if err := zeroizeRemoveManagedResolvConf(zeroizeResolvConfPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(zeroizeResolvConfPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("foreign resolver symlink was not preserved: info=%v err=%v", info, err)
	}
}

func TestPerformZeroizeKeepsConfigWhenIPsecTeardownIsUnresolved10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc", "xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("tenant config"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { secret tenant; }\n"))
	state := `{"loaded":["site-a"],"fingerprints":{"site-a":"fp1"}}`
	mustWriteFile(t, zeroizeIPsecStatePath, []byte(state))
	stopCalled := false
	zeroizeStopKeaUnits = func() error {
		stopCalled = true
		return nil
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil {
		t.Fatal("unresolved IPsec teardown must fail the reset before any wipe leg")
	}
	if stopCalled {
		t.Fatal("IPsec preflight must run before stopping Kea")
	}
	for _, path := range []string{
		filepath.Join(configDir, ".configdb", "master.key"),
		filepath.Join(configDir, ".configdb", "active.json"),
		filepath.Join(configDir, "xpf.conf"),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("config credential %s must survive failed IPsec preflight: %v", path, err)
		}
	}
	if got, err := os.ReadFile(zeroizeIPsecStatePath); err != nil || string(got) != state {
		t.Fatalf("IPsec teardown authority must survive failed preflight: body=%q err=%v", got, err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Fatalf("IPsec preflight must run before pending marker creation, got %v", err)
	}
}

func TestPerformZeroizeKeepsConfigWhenKeaCannotStop10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc", "xpf")
	masterKey := filepath.Join(configDir, ".configdb", "master.key")
	mustWriteFile(t, masterKey, []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("tenant config"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { secret tenant; }\n"))
	lease := zeroizeKeaLeasePaths[0]
	mustWriteFile(t, lease, []byte("prior tenant lease"))
	zeroizeStopKeaUnits = func() error { return fmt.Errorf("systemctl unavailable") }

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil || !strings.Contains(err.Error(), "systemctl unavailable") {
		t.Fatalf("Kea stop failure must abort the wipe, got %v", err)
	}
	for _, path := range []string{masterKey, filepath.Join(configDir, "xpf.conf"), lease} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("Kea stop failure must preserve %s: %v", path, err)
		}
	}
}

func TestZeroizeRemovePathSyncsParent10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	var synced []string
	zeroizeSyncDir = func(dir string) error {
		synced = append(synced, filepath.Clean(dir))
		return orig(dir)
	}
	victim := filepath.Join(root, "nested", "dir", "leaf")
	mustWriteFile(t, victim, []byte("x"))
	if err := zeroizeRemovePath(victim); err != nil {
		t.Fatalf("zeroizeRemovePath: %v", err)
	}
	want := filepath.Join(root, "nested", "dir")
	found := false
	for _, dir := range synced {
		if dir == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("parent %s was not synced after removal (synced=%v)", want, synced)
	}
	synced = nil
	boom := fmt.Errorf("injected fsync failure")
	zeroizeSyncDir = func(dir string) error {
		if filepath.Clean(dir) == want {
			return boom
		}
		return orig(dir)
	}
	mustWriteFile(t, victim, []byte("x"))
	if err := zeroizeRemovePath(victim); !errors.Is(err, boom) {
		t.Fatalf("parent sync failure must propagate, got %v", err)
	}
}

func TestPerformZeroizeSyncsEverySealParent10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	// One planted file per seal parent directory; the wipe must sync every
	// containing dir before the pending marker can clear.
	planted := []string{
		zeroizeMachineIDPath,
		filepath.Join(zeroizeSSHHostKeyDir, "ssh_host_ed25519_key"),
		filepath.Join(zeroizeRootSSHUserDir, "id_ed25519"),
		zeroizeRootBashHistory,
		zeroizeSNMPEngineIDPath,
		zeroizeSystemdRandomSeed,
		filepath.Join(zeroizeAptListsDir, "example_Packages"),
		zeroizeRunUtmpPath,
		zeroizeDay0RejectedPath,
		zeroizePasswdBackupPaths[0],
		zeroizeManagedHostKeysPath,
		zeroizeManagedDropins[0],
		zeroizeManagedDropins[2],
		zeroizeManagedDropins[3],
		zeroizeManagedDropins[4],
		zeroizeResolvConfPath,
		zeroizeKeaLeasePaths[0],
		filepath.Join(zeroizeVarLogDir, "old.log"),
	}
	for _, path := range planted {
		body := "prior tenant residue"
		if path == zeroizeManagedHostKeysPath {
			body = zeroizeManagedHostKeysHeader + "old.example ssh-ed25519 AAAA\n"
		}
		if path == zeroizeResolvConfPath {
			body = zeroizeManagedResolvConfHeader + "nameserver 192.0.2.53\n"
		}
		mustWriteFile(t, path, []byte(body))
	}
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	synced := map[string]bool{}
	zeroizeSyncDir = func(dir string) error {
		synced[filepath.Clean(dir)] = true
		return orig(dir)
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	wantParents := map[string]bool{}
	for _, path := range planted {
		wantParents[filepath.Clean(filepath.Dir(path))] = true
	}
	// The wipe removes the whole root .ssh directory (not the planted key
	// inside it), so its barrier lands on the parent of that directory.
	delete(wantParents, filepath.Clean(zeroizeRootSSHUserDir))
	wantParents[filepath.Clean(filepath.Dir(zeroizeRootSSHUserDir))] = true
	for dir := range wantParents {
		if !synced[dir] {
			t.Errorf("seal removal in %s left no durability barrier (synced=%v)", dir, synced)
		}
	}
}

func TestPerformZeroizeRetainsMarkerOnSealSyncFailure10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	mustWriteFile(t, zeroizeKeaLeasePaths[0], []byte("lease"))
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	boom := fmt.Errorf("injected seal parent fsync failure")
	keaDir := filepath.Clean(filepath.Dir(zeroizeKeaLeasePaths[0]))
	zeroizeSyncDir = func(dir string) error {
		if filepath.Clean(dir) == keaDir {
			return boom
		}
		return orig(dir)
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); !errors.Is(err, boom) {
		t.Fatalf("seal sync failure must fail the wipe, got %v", err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
		t.Fatalf("failed wipe must retain the pending marker: %v", err)
	}
}
