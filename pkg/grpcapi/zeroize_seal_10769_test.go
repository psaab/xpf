package grpcapi

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname := zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeNetifLeaseDir, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir, zeroizeRunXPFDir, zeroizeRunJournalDir, zeroizeSethostname
	t.Cleanup(func() {
		zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory = oldMachine, oldSSH, oldRootSSH, oldHistory
		zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed = oldEngineID, oldBoots, oldSeed
		zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath = oldAptLists, oldAptArchive, oldUtmp
		zeroizeDay0RejectedPath, zeroizeRootGrownPath = oldDay0Reject, oldRootGrown
		zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath = oldDDNSLease, oldDDNSSurface
		zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath = oldPasswdBackups, oldHostKeys
		zeroizeManagedDropins, zeroizeVarLogDir = oldDropins, oldVarLog
		zeroizeHostnamePath, zeroizeHostsPath, zeroizeResolvConfPath, zeroizeDBusMachineIDPath, zeroizeIPsecStatePath = oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec
		zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeNetifLeaseDir, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir, zeroizeRunXPFDir, zeroizeRunJournalDir, zeroizeSethostname = oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname
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
	zeroizeSethostname = func([]byte) error { return nil }
	zeroizeVarBackupsDir = filepath.Join(root, "var", "backups")
	zeroizeNetworkdLeaseDir = filepath.Join(root, "var", "lib", "systemd", "network")
	zeroizeNetifLeaseDir = filepath.Join(root, "run", "systemd", "netif", "leases")
	zeroizeDHCPClientStateDirs = []string{filepath.Join(root, "var", "lib", "dhcp"), filepath.Join(root, "var", "lib", "dhclient")}
	zeroizeTmpDirs = []string{filepath.Join(root, "tmp"), filepath.Join(root, "var", "tmp")}
	zeroizeShmDir = filepath.Join(root, "dev", "shm")
	zeroizeEtcDir = filepath.Join(root, "etc")
	zeroizeRunXPFDir = filepath.Join(root, "run", "xpf")
	zeroizeRunJournalDir = filepath.Join(root, "run", "log", "journal")
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
		resolver:   zeroizeManagedResolvConfHeader + "nameserver 192.0.2.53\n",
		hosts:      "127.0.0.1 localhost\n10.9.9.9 tenant-internal.example\n",
		dbusID:     "dbus-machine-id-secret\n",
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
	var liveNames []string
	zeroizeSethostname = func(name []byte) error {
		liveNames = append(liveNames, string(name))
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
	if len(liveNames) != 1 || liveNames[0] != "xpf" {
		t.Fatalf("live kernel hostname calls = %q, want exactly [xpf]", liveNames)
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
	} else if !errors.Is(err, errZeroizeDDNSOwnership) {
		t.Fatalf("outer DDNS preflight must carry the ownership sentinel, got %v", err)
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
	} else if !errors.Is(err, errZeroizeIPsecOwnership) {
		t.Fatalf("outer IPsec preflight must carry the ownership sentinel, got %v", err)
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
	otherTilde := filepath.Join(zeroizeVarBackupsDir, "other-app~")
	mustWriteFile(t, otherTilde, []byte("another application's backup"))
	shadowTilde := filepath.Join(zeroizeVarBackupsDir, "shadow~")
	mustWriteFile(t, shadowTilde, []byte("account-db tilde backup"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if len(*deleted) != 1 || (*deleted)[0] != "alice" {
		t.Fatalf("userdel invoked for %v, want exactly [alice]", *deleted)
	}
	for _, path := range append(append([]string{}, zeroizePasswdBackupPaths...),
		filepath.Join(zeroizeVarBackupsDir, "shadow.bak"),
		filepath.Join(zeroizeVarBackupsDir, "passwd.bak"),
		shadowTilde) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("recreated account backup %s survived: %v", path, err)
		}
	}
	for _, path := range []string{bystander, otherTilde} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("unrelated backup %s must survive: %v", path, err)
		}
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
	// networkd's runtime per-ifindex lease (no extension).
	netifLease := filepath.Join(zeroizeNetifLeaseDir, "2")
	mustWriteFile(t, netifLease, []byte("ADDRESS=192.0.2.10\nROUTER=192.0.2.1\n"))
	dhclientLease := filepath.Join(zeroizeDHCPClientStateDirs[0], "dhclient.leases")
	mustWriteFile(t, dhclientLease, []byte("lease { address 192.0.2.11; }"))
	dhclient6Lease := filepath.Join(zeroizeDHCPClientStateDirs[1], "dhclient6.leases")
	mustWriteFile(t, dhclient6Lease, []byte("lease6 { ia-na {...} }"))
	// Anything else in the networkd-exclusive dir goes with the leases.
	extra := filepath.Join(zeroizeNetworkdLeaseDir, "other.state")
	mustWriteFile(t, extra, []byte("networkd state"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range []string{duid, v4lease, netifLease, dhclientLease, dhclient6Lease, extra} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("DHCP client identity %s survived: %v", path, err)
		}
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
	// Service dirs: backups OF xpf-rendered basenames erased; backups of
	// operator files in the same shared dirs survive.
	swanctlBackup := filepath.Join(filepath.Dir(zeroizeSwanctlSnippet), "xpf.conf.bak")
	mustWriteFile(t, swanctlBackup, []byte("prior IKE PSK backup"))
	sshdBackup := filepath.Join(filepath.Dir(zeroizeManagedDropins[0]), "00-xpf.conf~")
	mustWriteFile(t, sshdBackup, []byte("prior sshd policy backup"))
	operatorDropinBackup := filepath.Join(filepath.Dir(zeroizeManagedDropins[0]), "50-operator.conf.bak")
	mustWriteFile(t, operatorDropinBackup, []byte("operator sshd policy backup"))
	operatorSSHBackup := filepath.Join(zeroizeSSHHostKeyDir, "sshd_config.bak")
	mustWriteFile(t, operatorSSHBackup, []byte("operator sshd config backup"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range append(append(append([]string{}, ownedBackups...), etcOwned...), swanctlBackup, sshdBackup) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("editor backup %s survived: %v", path, err)
		}
	}
	for _, path := range []string{unownedBackup, etcOther, operatorDropinBackup, operatorSSHBackup} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("unowned backup %s must survive: %v", path, err)
		}
	}
}

func TestPerformZeroizeClearsRunState10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	helperState := filepath.Join(zeroizeRunXPFDir, "userspace-dp.json")
	mustWriteFile(t, helperState, []byte("tenant flow state"))
	helperSock := filepath.Join(zeroizeRunXPFDir, "userspace-dp.sock")
	mustWriteFile(t, helperSock, []byte("socket name stand-in"))
	lock := filepath.Join(zeroizeRunXPFDir, "upgrade.lock")
	mustWriteFile(t, lock, []byte("held by nobody in this test"))
	journal := filepath.Join(zeroizeRunJournalDir, "machine-id", "system.journal")
	mustWriteFile(t, journal, []byte("volatile tenant logs"))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range []string{helperState, helperSock, journal} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("volatile run state %s survived: %v", path, err)
		}
	}
	if _, err := os.Lstat(lock); err != nil {
		t.Errorf("upgrade lock must survive the run clear (later leg needs it): %v", err)
	}
}

func TestPerformZeroizeSyncsAbsentParentOnRetry10769(t *testing.T) {
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
	failBarrier := true
	zeroizeSyncDir = func(dir string) error {
		if failBarrier && filepath.Clean(dir) == keaDir {
			return boom
		}
		return orig(dir)
	}
	// First attempt: the unlink lands but its barrier fails, so the wipe
	// reports incomplete and retains the pending marker.
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); !errors.Is(err, boom) {
		t.Fatalf("first attempt must fail on the injected barrier: %v", err)
	}
	if _, err := os.Lstat(zeroizeKeaLeasePaths[0]); !os.IsNotExist(err) {
		t.Fatalf("lease file should be unlinked even though its barrier failed: %v", err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
		t.Fatalf("failed wipe must retain the pending marker: %v", err)
	}
	// Retry with a healthy barrier: the lease path is already absent, but
	// its parent must still be synced before the marker may complete.
	failBarrier = false
	var retrySynced []string
	zeroizeSyncDir = func(dir string) error {
		retrySynced = append(retrySynced, filepath.Clean(dir))
		return orig(dir)
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("retry must converge: %v", err)
	}
	found := false
	for _, dir := range retrySynced {
		if dir == keaDir {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("retry never synced the absent lease path's parent %s (synced=%v)", keaDir, retrySynced)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Fatalf("converged retry must clear the pending marker: %v", err)
	}
}

func TestPerformZeroizeErasesStateCrashTemps10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	// Crash-orphaned fsatomic temps beside trusted-empty canonicals: full
	// state JSON from a save that never renamed.
	mustWriteFile(t, zeroizeDDNSLeaseStatePath, []byte(`{"version":1,"records":[]}`))
	ddnsTemp := filepath.Join(filepath.Dir(zeroizeDDNSLeaseStatePath), ".dhcp-ddns-state.json.tmp-999")
	mustWriteFile(t, ddnsTemp, []byte(`{"version":1,"records":[{"fqdn":"tenant.example"}]}`))
	mustWriteFile(t, zeroizeIPsecStatePath, []byte(`{"loaded":[],"pending_terminate":[]}`))
	ipsecTemp := filepath.Join(filepath.Dir(zeroizeIPsecStatePath), ".ipsec-conn-state.json.tmp-999")
	mustWriteFile(t, ipsecTemp, []byte(`{"loaded":["site-a"]}`))

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	for _, path := range []string{ddnsTemp, ipsecTemp} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("crash temp %s survived a reported-success reset: %v", path, err)
		}
	}
}

func TestZeroizeLeavesLiveHostnameOnSealFailure10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	mustWriteFile(t, zeroizeHostnamePath, []byte("prior-tenant.example\n"))
	// Force an earlier seal-leg failure: machine-id as a directory is
	// refused by the truncate leg, so the hostname leg (file + live) must
	// not run at all.
	if err := os.MkdirAll(zeroizeMachineIDPath, 0o700); err != nil {
		t.Fatal(err)
	}
	var liveNames []string
	zeroizeSethostname = func(name []byte) error {
		liveNames = append(liveNames, string(name))
		return nil
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil {
		t.Fatal("seal failure must fail the wipe")
	}
	if len(liveNames) != 0 {
		t.Fatalf("live hostname must stay untouched on seal failure, got %q", liveNames)
	}
	if body, err := os.ReadFile(zeroizeHostnamePath); err != nil || string(body) != "prior-tenant.example\n" {
		t.Fatalf("hostname file must stay untouched on seal failure: body=%q err=%v", body, err)
	}
}

func TestPerformZeroizeWarnsOnEscapingInteriorSymlink10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	// An interior link inside an owned directory that escapes it: the wipe
	// removes the link (inside the erased tree) but must neither follow it
	// nor silently imply the outside target was removed.
	target := filepath.Join(root, "elsewhere", "secret.txt")
	mustWriteFile(t, target, []byte("outside the erased tree"))
	link := filepath.Join(zeroizeRootSSHUserDir, "keys-link")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("interior link %s survived: %v", link, err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("out-of-tree link target must be preserved, never followed: %v", err)
	}
	if !strings.Contains(logs.String(), "outside the erased tree") {
		t.Fatalf("wipe must log the escaping target; logs:\n%s", logs.String())
	}
}

func TestPerformZeroizeSyncsEmptiedDirsOnRetry10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	aptFile := filepath.Join(zeroizeAptListsDir, "example_Packages")
	mustWriteFile(t, aptFile, []byte("package list"))
	tmpFile := filepath.Join(zeroizeTmpDirs[0], "tenant-tmp.txt")
	mustWriteFile(t, tmpFile, []byte("tmp data"))
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	boom := fmt.Errorf("injected dir-clear barrier failure")
	aptDir := filepath.Clean(zeroizeAptListsDir)
	tmpDir := filepath.Clean(zeroizeTmpDirs[0])
	failBarrier := true
	zeroizeSyncDir = func(dir string) error {
		clean := filepath.Clean(dir)
		if failBarrier && (clean == aptDir || clean == tmpDir) {
			return boom
		}
		return orig(dir)
	}
	// First attempt unlinks both entries but fails both barriers.
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); !errors.Is(err, boom) {
		t.Fatalf("first attempt must fail on the injected barriers: %v", err)
	}
	for _, path := range []string{aptFile, tmpFile} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("entry %s should be unlinked even though its barrier failed: %v", path, err)
		}
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
		t.Fatalf("failed wipe must retain the pending marker: %v", err)
	}
	// Retry reads both directories EMPTY and must still sync each before
	// the marker may complete.
	failBarrier = false
	synced := map[string]bool{}
	zeroizeSyncDir = func(dir string) error {
		synced[filepath.Clean(dir)] = true
		return orig(dir)
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("retry must converge: %v", err)
	}
	for _, dir := range []string{aptDir, tmpDir} {
		if !synced[dir] {
			t.Fatalf("retry never synced emptied directory %s (synced=%v)", dir, synced)
		}
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Fatalf("converged retry must clear the pending marker: %v", err)
	}
}

func TestZeroizeRemovePathSyncsSurvivingAncestor10769(t *testing.T) {
	root := t.TempDir()
	grandparent := filepath.Join(root, "gp")
	parent := filepath.Join(grandparent, "p")
	file := filepath.Join(parent, "leaf")
	mustWriteFile(t, file, []byte("x"))
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	boom := fmt.Errorf("injected parent barrier failure")
	zeroizeSyncDir = func(dir string) error {
		if filepath.Clean(dir) == filepath.Clean(parent) {
			return boom
		}
		return orig(dir)
	}
	if err := zeroizeRemovePath(file); !errors.Is(err, boom) {
		t.Fatalf("removal must surface the parent barrier failure, got %v", err)
	}
	// The parent itself disappears between attempts; the retry finds
	// neither the file nor its parent.
	if err := os.RemoveAll(parent); err != nil {
		t.Fatal(err)
	}
	var synced []string
	zeroizeSyncDir = func(dir string) error {
		synced = append(synced, filepath.Clean(dir))
		return orig(dir)
	}
	if err := zeroizeRemovePath(file); err != nil {
		t.Fatalf("retry: %v", err)
	}
	found := false
	for _, dir := range synced {
		if dir == filepath.Clean(grandparent) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("retry never synced surviving ancestor %s (synced=%v)", grandparent, synced)
	}
}

func TestPerformZeroizeWritesHandoffFlag10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	boot, dirty, present, err := configstore.ReadResetHandoff()
	if err != nil || !present {
		t.Fatalf("successful wipe must write the handoff flag: present=%v err=%v", present, err)
	}
	current, err := configstore.CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	if boot != current || dirty != "" {
		t.Fatalf("handoff = boot %q dirty %q, want current boot and clean", boot, dirty)
	}
}

func stubStopMonitor(t *testing.T, stopErr error, activeSeq []bool) {
	t.Helper()
	oldGrace, oldBudget, oldPoll := zeroizeStopGrace, zeroizeStopVerifyBudget, zeroizeStopVerifyPoll
	oldStop, oldActive := zeroizeStopDaemonUnit, zeroizeDaemonUnitActive
	oldFlag := configstore.ResetHandoffPath
	t.Cleanup(func() {
		zeroizeStopGrace, zeroizeStopVerifyBudget, zeroizeStopVerifyPoll = oldGrace, oldBudget, oldPoll
		zeroizeStopDaemonUnit, zeroizeDaemonUnitActive = oldStop, oldActive
		configstore.ResetHandoffPath = oldFlag
	})
	zeroizeStopGrace = 0
	zeroizeStopVerifyBudget = 50 * time.Millisecond
	zeroizeStopVerifyPoll = time.Millisecond
	zeroizeStopDaemonUnit = func() error { return stopErr }
	calls := 0
	zeroizeDaemonUnitActive = func() bool {
		if calls < len(activeSeq) {
			active := activeSeq[calls]
			calls++
			return active
		}
		return activeSeq[len(activeSeq)-1]
	}
	configstore.ResetHandoffPath = filepath.Join(t.TempDir(), ".reset-handoff")
}

func TestResetStopMonitorVerifiesStop10769(t *testing.T) {
	stubStopMonitor(t, nil, []bool{true, false})
	if err := resetStopMonitor(); err != nil {
		t.Fatalf("verified stop must be clean: %v", err)
	}
	if _, _, present, _ := configstore.ReadResetHandoff(); present {
		t.Fatal("verified stop must not write the handoff flag")
	}
}

func TestResetStopMonitorFlagsUnverifiedStop10769(t *testing.T) {
	t.Run("stop error", func(t *testing.T) {
		stubStopMonitor(t, errors.New("systemctl: connection refused"), []bool{false})
		// A nil return means the dirty condition was recorded, not that
		// the stop succeeded: the flag below is the signal.
		if err := resetStopMonitor(); err != nil {
			t.Fatalf("dirty marking must succeed: %v", err)
		}
		_, dirty, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || !strings.Contains(dirty, "stop failed") {
			t.Fatalf("stop error must mark dirty: present=%v dirty=%q err=%v", present, dirty, err)
		}
	})
	t.Run("still active past budget", func(t *testing.T) {
		stubStopMonitor(t, nil, []bool{true})
		if err := resetStopMonitor(); err != nil {
			t.Fatalf("dirty marking must succeed: %v", err)
		}
		_, dirty, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || !strings.Contains(dirty, "still active") {
			t.Fatalf("unverified stop must mark dirty: present=%v dirty=%q err=%v", present, dirty, err)
		}
	})
}

func TestPerformZeroizeFinalVerificationCatchesBypassedLeg10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	lease := zeroizeKeaLeasePaths[0]
	mustWriteFile(t, lease, []byte("escaper lease"))
	// Bypass the Kea leg entirely (a fence escaper re-creating faster than
	// the early check): only the pre-completion verification can catch it.
	origLeg := zeroizeStopKeaAndEraseLeases
	t.Cleanup(func() { zeroizeStopKeaAndEraseLeases = origLeg })
	zeroizeStopKeaAndEraseLeases = func() error { return nil }
	stopCalled := false
	zeroizeStopKeaUnits = func() error {
		stopCalled = true
		return nil
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil || !strings.Contains(err.Error(), "final verification") {
		t.Fatalf("bypassed erase must fail at final verification, got %v", err)
	}
	if stopCalled {
		t.Fatal("Kea leg must stay bypassed so the catch proves the final check")
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
		t.Fatalf("failed final verification must retain the pending marker: %v", err)
	}
}

func TestPerformZeroizeErasesRenderedNetworkd10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	rendered := filepath.Join(zeroizeNetworkdDir, "10-xpf-geo.network")
	mustWriteFile(t, rendered, []byte("[Match]\nName=ge-0\n"))
	foreign := filepath.Join(zeroizeNetworkdDir, "99-dhcp.network")
	mustWriteFile(t, foreign, []byte("[Match]\nName=en*\n"))
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}
	if _, err := os.Lstat(rendered); !os.IsNotExist(err) {
		t.Fatalf("rendered networkd file %s survived: %v", rendered, err)
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign networkd file %s must survive: %v", foreign, err)
	}
}

// RED on revert: restoring the warn-only networkd sweep reports success
// while the unlink failure (and the topology-resurrecting file) survives.
func TestPerformZeroizeFailsClosedOnNetworkdUnlinkFailure10769(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions; unlink would not fail")
	}
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	rendered := filepath.Join(zeroizeNetworkdDir, "10-xpf-geo.network")
	mustWriteFile(t, rendered, []byte("[Match]\nName=ge-0\n"))
	if err := os.Chmod(zeroizeNetworkdDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(zeroizeNetworkdDir, 0o755) })
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil {
		t.Fatal("networkd unlink failure must fail the wipe, got success")
	} else if !strings.Contains(err.Error(), "networkd") {
		t.Fatalf("wipe error must name the networkd leg, got %v", err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
		t.Fatalf("failed wipe must retain the pending marker: %v", err)
	}
}

// A prior-root immutable plant is the concrete topology-residue shape: the
// wipe must fail loudly, never report success over the surviving file.
// Skipped where the filesystem or privileges cannot set the immutable bit.
func TestPerformZeroizeFailsClosedOnImmutableNetworkdPlant10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	rendered := filepath.Join(zeroizeNetworkdDir, "10-xpf-geo.network")
	mustWriteFile(t, rendered, []byte("[Match]\nName=ge-0\n"))
	if err := exec.Command("chattr", "+i", rendered).Run(); err != nil {
		t.Skipf("immutable bit unsupported here: %v", err)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", rendered).Run() })
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err == nil {
		t.Fatal("immutable networkd plant must fail the wipe, got success")
	} else if !strings.Contains(err.Error(), "networkd") {
		t.Fatalf("wipe error must name the networkd leg, got %v", err)
	}
}

// RED on revert: dropping a selective loop's unconditional barrier lets a
// retry that finds zero matches complete the marker over undurable unlinks.
// Each case fails the first attempt's barrier after the unlink lands, then
// requires the empty retry to sync the affected directory pre-marker. Only
// the case's entry is seeded and no other leg references the directory, so
// the sync is attributable to the fixed loop. (The ssh, known-hosts, and
// backup sweeps share directories with helper-synced legs and are covered
// at leg level below instead.)
func TestPerformZeroizeSyncsSelectiveLoopsOnRetry10769(t *testing.T) {
	cases := []struct {
		name    string
		seed    func(t *testing.T) string
		syncDir func() string
	}{
		{"shadow backups",
			func(t *testing.T) string {
				p := filepath.Join(zeroizeVarBackupsDir, "shadow.bak")
				mustWriteFile(t, p, []byte("backup"))
				return p
			},
			func() string { return zeroizeVarBackupsDir }},
		{"shm entries",
			func(t *testing.T) string {
				p := filepath.Join(zeroizeShmDir, "xpf-test-seg")
				mustWriteFile(t, p, []byte("segment"))
				return p
			},
			func() string { return zeroizeShmDir }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			hermeticWipe10100(t, root)
			configDir := filepath.Join(root, "etc-xpf")
			mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
			mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
			mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
			seeded := tc.seed(t)
			orig := zeroizeSyncDir
			t.Cleanup(func() { zeroizeSyncDir = orig })
			boom := fmt.Errorf("injected %s barrier failure", tc.name)
			target := filepath.Clean(tc.syncDir())
			failBarrier := true
			zeroizeSyncDir = func(dir string) error {
				if failBarrier && filepath.Clean(dir) == target {
					return boom
				}
				return orig(dir)
			}
			if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); !errors.Is(err, boom) {
				t.Fatalf("first attempt must fail on the injected barrier: %v", err)
			}
			if _, err := os.Lstat(seeded); !os.IsNotExist(err) {
				t.Fatalf("seeded entry should be unlinked even though its barrier failed: %v", err)
			}
			if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
				t.Fatalf("failed wipe must retain the pending marker: %v", err)
			}
			failBarrier = false
			var retrySynced []string
			zeroizeSyncDir = func(dir string) error {
				retrySynced = append(retrySynced, filepath.Clean(dir))
				return orig(dir)
			}
			if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
				t.Fatalf("retry must converge: %v", err)
			}
			found := false
			for _, dir := range retrySynced {
				if dir == target {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("empty retry never synced %s (synced=%v)", target, retrySynced)
			}
			if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
				t.Fatalf("converged retry must clear the pending marker: %v", err)
			}
		})
	}
}

// The backup sweeps share their directories with removal legs that sync via
// the common helper, so wipe-level attribution is impossible: exercise the
// retry barrier at leg level on a private dir instead.
func TestBackupSweepsSyncEmptyDirOnRetry10769(t *testing.T) {
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	boom := errors.New("injected backup barrier failure")
	t.Run("service sweep", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteFile(t, filepath.Join(dir, "xpf.conf~"), []byte("backup"))
		owned := func(stem string) bool { return stem == "xpf.conf" }
		failBarrier := true
		zeroizeSyncDir = func(d string) error {
			if failBarrier && filepath.Clean(d) == filepath.Clean(dir) {
				return boom
			}
			return orig(d)
		}
		if err := zeroizeSweepOwnedBackups(dir, owned); !errors.Is(err, boom) {
			t.Fatalf("first sweep must fail on the injected barrier: %v", err)
		}
		failBarrier = false
		synced := false
		zeroizeSyncDir = func(d string) error {
			if filepath.Clean(d) == filepath.Clean(dir) {
				synced = true
			}
			return orig(d)
		}
		if err := zeroizeSweepOwnedBackups(dir, owned); err != nil {
			t.Fatalf("empty retry must converge: %v", err)
		}
		if !synced {
			t.Fatal("empty retry never synced the swept directory")
		}
	})
	t.Run("etc sweep", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteFile(t, filepath.Join(dir, "hosts~"), []byte("backup"))
		failBarrier := true
		zeroizeSyncDir = func(d string) error {
			if failBarrier && filepath.Clean(d) == filepath.Clean(dir) {
				return boom
			}
			return orig(d)
		}
		if err := zeroizeSweepOwnedEtcBackups(dir); !errors.Is(err, boom) {
			t.Fatalf("first sweep must fail on the injected barrier: %v", err)
		}
		failBarrier = false
		synced := false
		zeroizeSyncDir = func(d string) error {
			if filepath.Clean(d) == filepath.Clean(dir) {
				synced = true
			}
			return orig(d)
		}
		if err := zeroizeSweepOwnedEtcBackups(dir); err != nil {
			t.Fatalf("empty retry must converge: %v", err)
		}
		if !synced {
			t.Fatal("empty retry never synced the swept directory")
		}
	})
}

// The ssh-key and known-hosts legs share /etc/ssh with helper-synced legs
// (whose absent-path ancestor climb syncs the parent), so wipe-level
// attribution is impossible: exercise the retry barrier at leg level on a
// private dir instead.
func TestIdentityLegsSyncEmptyDirOnRetry10769(t *testing.T) {
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	boom := errors.New("injected identity barrier failure")
	t.Run("ssh host keys", func(t *testing.T) {
		dir := t.TempDir()
		oldSSH := zeroizeSSHHostKeyDir
		t.Cleanup(func() { zeroizeSSHHostKeyDir = oldSSH })
		zeroizeSSHHostKeyDir = dir
		mustWriteFile(t, filepath.Join(dir, "ssh_host_ed25519_key"), []byte("private"))
		failBarrier := true
		zeroizeSyncDir = func(d string) error {
			if failBarrier && filepath.Clean(d) == filepath.Clean(dir) {
				return boom
			}
			return orig(d)
		}
		if err := zeroizeEraseSSHHostKeys(); !errors.Is(err, boom) {
			t.Fatalf("first sweep must fail on the injected barrier: %v", err)
		}
		failBarrier = false
		synced := false
		zeroizeSyncDir = func(d string) error {
			if filepath.Clean(d) == filepath.Clean(dir) {
				synced = true
			}
			return orig(d)
		}
		if err := zeroizeEraseSSHHostKeys(); err != nil {
			t.Fatalf("empty retry must converge: %v", err)
		}
		if !synced {
			t.Fatal("empty retry never synced the key directory")
		}
	})
	t.Run("known hosts", func(t *testing.T) {
		dir := t.TempDir()
		knownHosts := filepath.Join(dir, "ssh_known_hosts")
		mustWriteFile(t, knownHosts, []byte("hostkey"))
		failBarrier := true
		zeroizeSyncDir = func(d string) error {
			if failBarrier && filepath.Clean(d) == filepath.Clean(dir) {
				return boom
			}
			return orig(d)
		}
		if err := zeroizeEraseKnownHosts(knownHosts); !errors.Is(err, boom) {
			t.Fatalf("first erase must fail on the injected barrier: %v", err)
		}
		failBarrier = false
		synced := false
		zeroizeSyncDir = func(d string) error {
			if filepath.Clean(d) == filepath.Clean(dir) {
				synced = true
			}
			return orig(d)
		}
		if err := zeroizeEraseKnownHosts(knownHosts); err != nil {
			t.Fatalf("absent retry must converge: %v", err)
		}
		if !synced {
			t.Fatal("absent retry never synced the parent directory")
		}
	})
}
