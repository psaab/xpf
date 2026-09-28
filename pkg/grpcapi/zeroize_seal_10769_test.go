package grpcapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
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
	oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec := zeroizeHostnamePath, zeroizeHostsPath, zeroizeResolvConfPath, zeroizeDBusMachineIDPath, zeroizeIPsecStatePath
	oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldDHCPClient, oldTmp, oldShm, oldEtc := zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir
	t.Cleanup(func() {
		zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory = oldMachine, oldSSH, oldRootSSH, oldHistory
		zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed = oldEngineID, oldBoots, oldSeed
		zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath = oldAptLists, oldAptArchive, oldUtmp
		zeroizeDay0RejectedPath, zeroizeRootGrownPath = oldDay0Reject, oldRootGrown
		zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath = oldDDNSLease, oldDDNSSurface
		zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath = oldPasswdBackups, oldHostKeys
		zeroizeManagedDropins, zeroizeVarLogDir = oldDropins, oldVarLog
		zeroizeHostnamePath, zeroizeHostsPath, zeroizeResolvConfPath, zeroizeDBusMachineIDPath, zeroizeIPsecStatePath = oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec
		zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir = oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldDHCPClient, oldTmp, oldShm, oldEtc
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
	zeroizeHostsPath = filepath.Join(root, "etc", "hosts")
	zeroizeResolvConfPath = filepath.Join(root, "etc", "resolv.conf")
	zeroizeDBusMachineIDPath = filepath.Join(root, "var", "lib", "dbus", "machine-id")
	zeroizeIPsecStatePath = filepath.Join(root, "var", "lib", "xpf", "ipsec-conn-state.json")
	zeroizeKeaLeasePaths = []string{
		filepath.Join(root, "var", "lib", "kea", "kea-leases4.csv"),
		filepath.Join(root, "var", "lib", "kea", "kea-leases6.csv"),
	}
	zeroizeStopKeaUnits = func() error { return nil }
	zeroizeVerifyKeaStopped = func() error { return nil }
	zeroizeVarBackupsDir = filepath.Join(root, "var", "backups")
	zeroizeNetworkdLeaseDir = filepath.Join(root, "var", "lib", "systemd", "network")
	zeroizeDHCPClientStateDirs = []string{filepath.Join(root, "var", "lib", "dhcp"), filepath.Join(root, "var", "lib", "dhclient")}
	zeroizeTmpDirs = []string{filepath.Join(root, "tmp"), filepath.Join(root, "var", "tmp")}
	zeroizeShmDir = filepath.Join(root, "dev", "shm")
	zeroizeEtcDir = filepath.Join(root, "etc")
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
	hosts, dbusID := zeroizeHostsPath, zeroizeDBusMachineIDPath
	var keaWipeSet []string
	for _, current := range zeroizeKeaLeasePaths {
		keaWipeSet = append(keaWipeSet, dhcpserver.KeaLeaseWipePaths(current)...)
	}
	ipsecState := zeroizeIPsecStatePath
	sshHostKey := filepath.Join(zeroizeSSHHostKeyDir, "ssh_host_ed25519_key")
	sshHostPub := sshHostKey + ".pub"
	foreignSSH := filepath.Join(zeroizeSSHHostKeyDir, "sshd_config")
	rootSSHKey := filepath.Join(zeroizeRootSSHUserDir, "id_ed25519")
	history := zeroizeRootBashHistory
	engineID, engineBoots, randomSeed := zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed
	plant := map[string]string{
		machineID: "machine-id-secret\n", hostname: "prior-tenant.example\n",
		resolver: zeroizeManagedResolvConfHeader + "nameserver 192.0.2.53\n",
		hosts:    "127.0.0.1 localhost\n10.9.9.9 tenant-internal.example\n",
		dbusID:   "dbus-machine-id-secret\n",
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
	}
	for _, path := range keaWipeSet {
		plant[path] = "prior client lease"
	}
	for path, body := range plant {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keaStopped, keaVerified := false, false
	zeroizeStopKeaUnits = func() error {
		for _, path := range keaWipeSet {
			if _, err := os.Lstat(path); err != nil {
				return fmt.Errorf("Kea lease file %s missing before stop: %w", path, err)
			}
		}
		keaStopped = true
		return nil
	}
	zeroizeVerifyKeaStopped = func() error {
		if !keaStopped {
			return fmt.Errorf("Kea verified before stop")
		}
		for _, path := range keaWipeSet {
			if _, err := os.Lstat(path); err != nil {
				return fmt.Errorf("Kea lease file %s missing before unlink: %w", path, err)
			}
		}
		keaVerified = true
		return nil
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if !keaStopped {
		t.Fatal("Kea must be stopped before its lease files are erased")
	}
	if !keaVerified {
		t.Fatal("Kea must verify inactive between stop and lease unlink")
	}
	if body, err := os.ReadFile(machineID); err != nil || len(body) != 0 {
		t.Fatalf("machine-id should remain present but empty for systemd regeneration; body=%q err=%v", body, err)
	}
	if body, err := os.ReadFile(hostname); err != nil || string(body) != "xpf\n" {
		t.Fatalf("hostname should reset to the appliance default: body=%q err=%v", body, err)
	}
	if body, err := os.ReadFile(resolver); err != nil || string(body) != zeroizeManagedResolvConfHeader {
		t.Fatalf("resolver should reset to the header-only empty default: body=%q err=%v", body, err)
	}
	if body, err := os.ReadFile(hosts); err != nil || string(body) != zeroizeDefaultHosts {
		t.Fatalf("hosts should reset to the factory default: body=%q err=%v", body, err)
	}
	absent := []string{
		sshHostKey, sshHostPub, rootSSHKey, history, engineID, engineBoots, randomSeed,
		dbusID, ipsecState,
		zeroizeRunUtmpPath, zeroizeDay0RejectedPath, zeroizeRootGrownPath,
		zeroizeManagedHostKeysPath, zeroizePasswdBackupPaths[0], zeroizePasswdBackupPaths[1],
		zeroizePasswdBackupPaths[2], zeroizePasswdBackupPaths[3],
		zeroizeManagedDropins[0], zeroizeManagedDropins[1], zeroizeManagedDropins[2],
		zeroizeManagedDropins[3], zeroizeManagedDropins[4], zeroizeManagedDropins[5],
		filepath.Join(zeroizeAptListsDir, "example_Packages"), filepath.Join(zeroizeAptArchiveDir, "old.deb"),
		filepath.Join(zeroizeVarLogDir, "journal", "old.journal"),
	}
	// No lease-bearing generation may survive: absence of every LFC source
	// is the stronger assertion (there is no hermetic exported lease reader
	// to call instead — no files means no readable leases).
	absent = append(absent, keaWipeSet...)
	for _, path := range absent {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("sealed prior-tenant artifact %s survived: %v", path, err)
		}
	}
	if body, err := os.ReadFile(foreignSSH); err != nil || string(body) != "unmanaged ssh config" {
		t.Errorf("unrelated SSH config changed: body=%q err=%v", body, err)
	}
}

func TestZeroizeErasesForeignKnownHosts10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	if err := os.MkdirAll(filepath.Dir(zeroizeManagedHostKeysPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// No xpfd header: a prior root could strip the header to preserve
	// hostile trust anchors, so headerless trust is erased, not kept.
	if err := os.WriteFile(zeroizeManagedHostKeysPath, []byte("evil.example ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := zeroizeEraseKnownHosts(zeroizeManagedHostKeysPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(zeroizeManagedHostKeysPath); !os.IsNotExist(err) {
		t.Fatalf("foreign SSH known-hosts file survived: %v", err)
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

func TestZeroizeResetsForeignResolver10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	if err := os.MkdirAll(filepath.Dir(zeroizeResolvConfPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeroizeResolvConfPath, []byte("nameserver 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := zeroizeResetResolvConf(zeroizeResolvConfPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(zeroizeResolvConfPath)
	if err != nil || string(got) != zeroizeManagedResolvConfHeader {
		t.Fatalf("foreign resolver was not reset to the empty default: body=%q err=%v", got, err)
	}
}

func TestZeroizeResetsForeignResolverSymlink10769(t *testing.T) {
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
	if err := zeroizeResetResolvConf(zeroizeResolvConfPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(zeroizeResolvConfPath)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("resolver symlink was not replaced by a regular file: info=%v err=%v", info, err)
	}
	got, err := os.ReadFile(zeroizeResolvConfPath)
	if err != nil || string(got) != zeroizeManagedResolvConfHeader {
		t.Fatalf("replaced resolver has wrong content: body=%q err=%v", got, err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("symlink target must be untouched: %v", err)
	}
}

func TestZeroizeResetsHosts10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	mustWriteFile(t, zeroizeHostsPath, []byte("127.0.0.1 localhost\n10.9.9.9 tenant-internal.example\n"))
	if err := zeroizeResetHosts(zeroizeHostsPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(zeroizeHostsPath)
	if err != nil || string(got) != zeroizeDefaultHosts {
		t.Fatalf("hosts was not reset to the factory default: body=%q err=%v", got, err)
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
		zeroizeHostsPath,
		zeroizeDBusMachineIDPath,
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

func TestPerformZeroizeErasesCompletedOnlyLeaseResidue10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	// A crash between LFC rotation steps can leave leases ONLY in .completed
	// while the canonical file is fresh/empty; Kea startup prefers it.
	completed := zeroizeKeaLeasePaths[0] + ".completed"
	mustWriteFile(t, completed, []byte("orphaned compacted leases"))
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if _, err := os.Lstat(completed); !os.IsNotExist(err) {
		t.Fatalf(".completed lease residue survived: %v", err)
	}
}

func TestPerformZeroizeAbortsWhenKeaVerifyFails10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	masterKey := filepath.Join(configDir, ".configdb", "master.key")
	mustWriteFile(t, masterKey, []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("tenant config"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { secret tenant; }\n"))
	lease := zeroizeKeaLeasePaths[0]
	mustWriteFile(t, lease, []byte("prior tenant lease"))
	zeroizeVerifyKeaStopped = func() error { return fmt.Errorf("kea-dhcp4-server still active") }

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("Kea verify failure must abort the wipe, got %v", err)
	}
	for _, path := range []string{masterKey, filepath.Join(configDir, "xpf.conf"), lease} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("Kea verify failure must preserve %s: %v", path, err)
		}
	}
}

func TestPerformZeroizeErasesRecreatedAccountBackups10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))

	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")
	mustWriteFile(t, passwdPath, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"alice:x:1001:1001:alice:/home/alice:/bin/bash\n"))
	mustWriteFile(t, filepath.Join(provDir, "alice"), []byte("1001"))
	mustWriteFile(t, filepath.Join(homeBase, "alice", ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAA alice\n"))
	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)
	// Simulate the shadow-tools backup contract (man shadow: /etc/shadow-
	// is the backup of the password database; Debian also keeps
	// /var/backups/shadow.bak): every userdel recreates these with
	// pre-modification account data. The wipe's backup sweep must run
	// after this teardown, not in the early seal legs.
	innerUserdel := zeroizeUserdel
	zeroizeUserdel = func(name string) ([]byte, error) {
		out, err := innerUserdel(name)
		for _, path := range zeroizePasswdBackupPaths {
			mustWriteFile(t, path, []byte("pre-modification account data"))
		}
		mustWriteFile(t, filepath.Join(zeroizeVarBackupsDir, "shadow.bak"), []byte("pre-modification shadow"))
		mustWriteFile(t, filepath.Join(zeroizeVarBackupsDir, "passwd.bak"), []byte("pre-modification passwd"))
		return out, err
	}
	bystander := filepath.Join(zeroizeVarBackupsDir, "unrelated.txt")
	mustWriteFile(t, bystander, []byte("not an account backup"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if len(*deleted) != 1 || (*deleted)[0] != "alice" {
		t.Fatalf("userdel invoked for %v, want exactly [alice]", *deleted)
	}
	for _, path := range append(append([]string{}, zeroizePasswdBackupPaths...),
		filepath.Join(zeroizeVarBackupsDir, "shadow.bak"),
		filepath.Join(zeroizeVarBackupsDir, "passwd.bak")) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("recreated account backup %s survived: %v", path, err)
		}
	}
	if _, err := os.Lstat(bystander); err != nil {
		t.Errorf("non-backup bystander %s must survive: %v", bystander, err)
	}
}

func TestPerformZeroizeErasesDHCPClientIdentity10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	duid := filepath.Join(configDir, "dhcpv6-duid-ge-0-0-1")
	mustWriteFile(t, duid, []byte("persistent client DUID"))
	v4lease := filepath.Join(zeroizeNetworkdLeaseDir, "2-ens3.lease")
	mustWriteFile(t, v4lease, []byte("ADDRESS=192.0.2.10\nDUID=duid-bytes\n"))
	dhclientLease := filepath.Join(zeroizeDHCPClientStateDirs[0], "dhclient.leases")
	mustWriteFile(t, dhclientLease, []byte("lease { address 192.0.2.11; }"))
	dhclient6Lease := filepath.Join(zeroizeDHCPClientStateDirs[1], "dhclient6.leases")
	mustWriteFile(t, dhclient6Lease, []byte("lease6 { ia-na {...} }"))
	// Non-lease state beside networkd leases is out of scope and survives.
	bystander := filepath.Join(zeroizeNetworkdLeaseDir, "other.state")
	mustWriteFile(t, bystander, []byte("not a lease"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range []string{duid, v4lease, dhclientLease, dhclient6Lease} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("DHCP client identity %s survived: %v", path, err)
		}
	}
	if _, err := os.Lstat(bystander); err != nil {
		t.Errorf("non-lease networkd state must survive: %v", err)
	}
}

func TestPerformZeroizeClearsTmpAndShm10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	tmpFile := filepath.Join(zeroizeTmpDirs[0], "tenant-secret.txt")
	mustWriteFile(t, tmpFile, []byte("prior tenant tmp data"))
	tmpNested := filepath.Join(zeroizeTmpDirs[1], "nested", "deep.txt")
	mustWriteFile(t, tmpNested, []byte("nested tmp data"))
	// A symlink inside tmp: the link goes, its outside target stays.
	linkTarget := filepath.Join(root, "elsewhere", "victim.txt")
	mustWriteFile(t, linkTarget, []byte("not in tmp"))
	link := filepath.Join(zeroizeTmpDirs[0], "evil-link")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}
	// Service-infrastructure tmp survives.
	preserved := filepath.Join(zeroizeTmpDirs[0], "systemd-private-abc", "keep")
	mustWriteFile(t, preserved, []byte("service infra"))
	shmXPF := filepath.Join(zeroizeShmDir, "xpf-segment")
	mustWriteFile(t, shmXPF, []byte("xpf shm"))
	shmKea := filepath.Join(zeroizeShmDir, "kea-mem")
	mustWriteFile(t, shmKea, []byte("kea shm"))
	shmOther := filepath.Join(zeroizeShmDir, "unrelated-service")
	mustWriteFile(t, shmOther, []byte("live service shm"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range []string{tmpFile, tmpNested, link, shmXPF, shmKea} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("tmp/shm residue %s survived: %v", path, err)
		}
	}
	for _, path := range []string{linkTarget, preserved, shmOther} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("bystander %s must survive: %v", path, err)
		}
	}
}

func TestPerformZeroizeSweepsEditorBackups10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	// Backups OF owned config-root artifacts are erased; a backup of an
	// unowned sibling survives (stem-gated, #5768).
	ownedBackups := []string{
		filepath.Join(configDir, "xpf.conf~"),
		filepath.Join(configDir, "xpf.conf.bak"),
		filepath.Join(configDir, "rescue.conf.orig"),
		filepath.Join(configDir, "xpf.conf.1~"),
	}
	for _, path := range ownedBackups {
		mustWriteFile(t, path, []byte("prior config text with secrets"))
	}
	unownedBackup := filepath.Join(configDir, "notes.txt.bak")
	mustWriteFile(t, unownedBackup, []byte("not ours"))
	// /etc top level: owned-identity backups erased, others kept.
	etcOwned := []string{
		filepath.Join(zeroizeEtcDir, "hostname.bak"),
		filepath.Join(zeroizeEtcDir, "hosts~"),
		filepath.Join(zeroizeEtcDir, "resolv.conf.orig"),
	}
	for _, path := range etcOwned {
		mustWriteFile(t, path, []byte("prior identity backup"))
	}
	etcOther := filepath.Join(zeroizeEtcDir, "motd.bak")
	mustWriteFile(t, etcOther, []byte("not reset-owned"))
	// Service-owned dirs: any editor backup erased, live files kept.
	swanctlBackup := filepath.Join(filepath.Dir(zeroizeSwanctlSnippet), "xpf.conf.bak")
	mustWriteFile(t, swanctlBackup, []byte("prior IKE PSK backup"))
	sshdBackup := filepath.Join(filepath.Dir(zeroizeManagedDropins[0]), "00-xpf.conf~")
	mustWriteFile(t, sshdBackup, []byte("prior sshd policy backup"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range append(append(append([]string{}, ownedBackups...), etcOwned...), swanctlBackup, sshdBackup) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("editor backup %s survived: %v", path, err)
		}
	}
	for _, path := range []string{unownedBackup, etcOther} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("unowned backup %s must survive: %v", path, err)
		}
	}
}
