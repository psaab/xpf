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
	oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldNetifLinks, oldNetifServer, oldNetifState, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname := zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeNetifLeaseDir, zeroizeNetifLinksDir, zeroizeNetifServerLeaseDir, zeroizeNetifStatePath, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir, zeroizeRunXPFDir, zeroizeRunJournalDir, zeroizeSethostname
	t.Cleanup(func() {
		zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory = oldMachine, oldSSH, oldRootSSH, oldHistory
		zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed = oldEngineID, oldBoots, oldSeed
		zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath = oldAptLists, oldAptArchive, oldUtmp
		zeroizeDay0RejectedPath, zeroizeRootGrownPath = oldDay0Reject, oldRootGrown
		zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath = oldDDNSLease, oldDDNSSurface
		zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath = oldPasswdBackups, oldHostKeys
		zeroizeManagedDropins, zeroizeVarLogDir = oldDropins, oldVarLog
		zeroizeHostnamePath, zeroizeHostsPath, zeroizeResolvConfPath, zeroizeDBusMachineIDPath, zeroizeIPsecStatePath = oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec
		zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeNetifLeaseDir, zeroizeNetifLinksDir, zeroizeNetifServerLeaseDir, zeroizeNetifStatePath, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir, zeroizeRunXPFDir, zeroizeRunJournalDir, zeroizeSethostname = oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldNetifLinks, oldNetifServer, oldNetifState, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname
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
	zeroizeNetifLinksDir = filepath.Join(root, "run", "systemd", "netif", "links")
	zeroizeNetifServerLeaseDir = filepath.Join(root, "run", "systemd", "netif", "dhcp-server-lease")
	zeroizeNetifStatePath = filepath.Join(root, "run", "systemd", "netif", "state")
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
		machineID: "0123456789abcdef0123456789abcdef\n", hostname: "prior-tenant.example\n",
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
	if body, err := os.ReadFile(machineID); err != nil {
		t.Fatalf("machine-id must be present after reset: %v", err)
	} else if id := strings.TrimSpace(string(body)); len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("machine-id must be fresh 32-hex identity, got %q", body)
	} else if id == "0123456789abcdef0123456789abcdef" || !strings.HasSuffix(string(body), "\n") {
		t.Fatalf("machine-id must rotate away from the seeded prior identity with a trailing newline, got %q", body)
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

// Fixture paths/keys below are sourced from the image's systemd generation
// (Debian 261.x source: networkd-state-file.c link_save/manager_save,
// networkd-dhcp6.c link_serialize_dhcp6_client,
// networkd-dhcp-server.c link_get_dhcp_server_lease_file), not guessed:
// v261 keeps client leases in memory and serializes the derived state
// into links/<ifindex> + state; leases/<ifindex> has no v261 writer
// (seeded as legacy/foreign shape to pin the wholesale clear).
func TestPerformZeroizeErasesDHCPClientIdentity10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	duid := filepath.Join(configDir, "dhcpv6-duid-ge-0-0-1")
	mustWriteFile(t, duid, []byte("persistent client DUID"))
	// Per-link runtime serialization incl. DHCP-derived DNS and the
	// DHCPv6 client IAID/DUID lines.
	linkState := filepath.Join(zeroizeNetifLinksDir, "2")
	mustWriteFile(t, linkState, []byte("# This is private data. Do not parse.\nADMIN_STATE=configured\nOPER_STATE=routable\nDNS=192.0.2.53\nDHCP6_CLIENT_IAID=0x1a2b3c4d\nDHCP6_CLIENT_DUID=DUID-EN:0000ab9f8a9c8e5d4c3b2a1\n"))
	// Aggregate manager state with DHCP-derived DNS.
	managerState := zeroizeNetifStatePath
	mustWriteFile(t, managerState, []byte("# This is private data. Do not parse.\nOPER_STATE=routable\nDNS=192.0.2.53\n"))
	// Legacy per-ifindex lease shape (no v261 writer; wholesale clear).
	legacyLease := filepath.Join(zeroizeNetifLeaseDir, "2")
	mustWriteFile(t, legacyLease, []byte("# This is private data. Do not parse.\nADDRESS=192.0.2.10\nROUTER=192.0.2.1\n"))
	// DHCP server leases, runtime + persistent (xpf never renders
	// [DHCPServer], but the wholesale clear owns both regardless).
	serverRuntime := filepath.Join(zeroizeNetifServerLeaseDir, "ge-0")
	mustWriteFile(t, serverRuntime, []byte(`{"Leases":[{"Address":"192.0.2.10","Hostname":"tenant-client"}]}`))
	serverPersist := filepath.Join(zeroizeNetworkdLeaseDir, "dhcp-server-lease", "ge-0")
	mustWriteFile(t, serverPersist, []byte(`{"Leases":[{"Address":"192.0.2.10","Hostname":"tenant-client"}]}`))
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
	for _, path := range []string{duid, linkState, managerState, legacyLease, serverRuntime, serverPersist, dhclientLease, dhclient6Lease, extra} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("DHCP client identity %s survived: %v", path, err)
		}
	}
	// Entries are cleared with their directories kept: the running
	// networkd creates the subdirs at startup only.
	for _, dir := range []string{zeroizeNetifLinksDir, zeroizeNetifServerLeaseDir, zeroizeNetifLeaseDir} {
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
			t.Errorf("networkd runtime dir %s must survive as a directory: %v", dir, err)
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
	boot, dirty, _, present, err := configstore.ReadResetHandoff()
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
	if _, _, _, present, _ := configstore.ReadResetHandoff(); present {
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
		_, dirty, _, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || !strings.Contains(dirty, "stop failed") {
			t.Fatalf("stop error must mark dirty: present=%v dirty=%q err=%v", present, dirty, err)
		}
	})
	t.Run("still active past budget", func(t *testing.T) {
		stubStopMonitor(t, nil, []bool{true})
		if err := resetStopMonitor(); err != nil {
			t.Fatalf("dirty marking must succeed: %v", err)
		}
		_, dirty, _, present, err := configstore.ReadResetHandoff()
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

func TestPerformZeroizeWipePendingRecordsPending10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	helperPath := filepath.Join(root, "custom", "userspace-dp.json")
	if err := PerformZeroizeWipePending(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperPath); err != nil {
		t.Fatalf("PerformZeroizeWipePending: %v", err)
	}
	boot, dirty, gotPath, present, err := configstore.ReadResetHandoff()
	if err != nil || !present {
		t.Fatalf("pending wipe must write the handoff flag: present=%v err=%v", present, err)
	}
	current, err := configstore.CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	if boot != current || dirty != configstore.ResetHandoffPending || gotPath != helperPath {
		t.Fatalf("handoff = boot %q dirty %q path %q, want current boot, pending, %q", boot, dirty, gotPath, helperPath)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Fatalf("completed wipe must clear the pending marker: %v", err)
	}
}

// RED on revert: temps-only final verification clears the markers over a
// canonical state file whose writer completed a full save (no temp left).
func TestFinalEraseVerificationCatchesReappearedCanonical10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	mustWriteFile(t, zeroizeDDNSLeaseStatePath, []byte(`{"version":1,"records":[]}`))
	mustWriteFile(t, zeroizeIPsecStatePath, []byte(`{"loaded":[],"pending_terminate":[]}`))
	if err := zeroizeFinalEraseVerification(zeroizeComplete); err == nil {
		t.Fatal("canonical-only reappearance must fail final verification")
	} else if !strings.Contains(err.Error(), "present at final verification") {
		t.Fatalf("final verification error must name the reappeared canonicals, got %v", err)
	}
}

// The helper class is verified only for ungated completions with a known
// path: gated wipes skip it (live helper; the daemon sweep owns the path).
func TestFinalEraseVerificationCoversHelperOnUngated10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	helperFile := filepath.Join(root, "custom", "userspace-dp.json")
	mustWriteFile(t, helperFile, []byte(`{"flows":["prior"]}`))
	mustWriteFile(t, helperFile+".4250000000.1.tmp", []byte(`{"flows":["prior-temp"]}`))
	if err := zeroizeFinalEraseVerification(zeroizeCompletion{pending: false, helperPath: helperFile}); err == nil {
		t.Fatal("helper residue must fail ungated final verification")
	} else if !strings.Contains(err.Error(), "helper state") {
		t.Fatalf("final verification error must name helper residue, got %v", err)
	}
	if err := zeroizeFinalEraseVerification(zeroizeCompletion{pending: true, helperPath: helperFile}); err != nil {
		t.Fatalf("gated final verification must skip the live helper class: %v", err)
	}
	if err := zeroizeFinalEraseVerification(zeroizeComplete); err != nil {
		t.Fatalf("pathless completion must skip the helper class it cannot name: %v", err)
	}
}

// RED on revert: final verification that treats a reserved helper
// canonical as expected-present completes the wipe with helper residue
// unproven. A reserved alias with clean temps must fail.
func TestFinalEraseVerificationRefusesReservedHelper10769(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	helperFile := filepath.Join(root, "custom", ".reset-handoff")
	mustWriteFile(t, helperFile, []byte("gate bytes must survive"))
	if err := zeroizeFinalEraseVerification(zeroizeCompletion{pending: false, helperPath: helperFile}); err == nil {
		t.Fatal("reserved helper alias with clean temps must fail final verification, got nil")
	} else if !strings.Contains(err.Error(), "cannot be verified") || !strings.Contains(err.Error(), helperFile) {
		t.Fatalf("final verification error must name the unverifiable alias, got %v", err)
	}
	if got, err := os.ReadFile(helperFile); err != nil || string(got) != "gate bytes must survive" {
		t.Fatalf("verification must remove nothing: %q err=%v", got, err)
	}
}

// ownProcStartTuple reads this test process's pid + start time (field 22
// of /proc/self/stat) so a temp can be staged as a LIVE writer's
// in-flight file. ok is false without /proc.
func ownProcStartTuple(t *testing.T) (pid, start string, ok bool) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", "", false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 22 {
		return "", "", false
	}
	return fields[0], fields[21], true
}

// RED on revert: an ungated (offline/no-daemon) wipe that neither erases
// nor verifies a custom helper state file records clean over surviving
// tenant state, and boot repair re-derives the default instead.
func TestUngatedWipeErasesCustomHelperState10769(t *testing.T) {
	setup := func(t *testing.T) (root, configDir string) {
		t.Helper()
		root = t.TempDir()
		hermeticWipe10100(t, root)
		configDir = filepath.Join(root, "etc-xpf")
		mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
		mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
		mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
		return root, configDir
	}
	t.Run("custom state-file leaf", func(t *testing.T) {
		root, configDir := setup(t)
		helperFile := filepath.Join(root, "custom", "userspace-dp.json")
		mustWriteFile(t, helperFile, []byte(`{"flows":["prior"]}`))
		mustWriteFile(t, helperFile+".4250000000.1.tmp", []byte(`{"flows":["prior-temp"]}`))
		if err := PerformZeroizeWipeUngated(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperFile); err != nil {
			t.Fatalf("PerformZeroizeWipeUngated: %v", err)
		}
		for _, path := range []string{helperFile, helperFile + ".4250000000.1.tmp"} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Errorf("helper residue %s survived the ungated wipe: %v", path, err)
			}
		}
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty != "" || gotPath != helperFile {
			t.Fatalf("ungated handoff = dirty %q path %q present %v err %v, want clean with the recorded path", dirty, gotPath, present, err)
		}
	})
	t.Run("live temp fails closed", func(t *testing.T) {
		root, configDir := setup(t)
		pid, start, ok := ownProcStartTuple(t)
		if !ok {
			t.Skip("no /proc in test environment")
		}
		helperFile := filepath.Join(root, "custom", "userspace-dp.json")
		mustWriteFile(t, helperFile+"."+pid+"_"+start+".1.tmp", []byte(`{"inflight":true}`))
		if err := PerformZeroizeWipeUngated(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperFile); err == nil {
			t.Fatal("live helper temp must fail the ungated wipe, got success")
		}
		if _, err := os.Lstat(configstore.FactoryResetPendingPath); err != nil {
			t.Fatalf("failed wipe must retain the pending marker: %v", err)
		}
	})
}

func TestZeroizeRotateMachineIDCreatesAndRefusesLink10769(t *testing.T) {
	valid := func(t *testing.T, path string) string {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSpace(string(body))
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || !strings.HasSuffix(string(body), "\n") {
			t.Fatalf("machine-id must be 32-hex + newline, got %q", body)
		}
		return id
	}
	t.Run("missing is created fresh", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "machine-id")
		if err := zeroizeRotateMachineID(path); err != nil {
			t.Fatalf("rotate missing: %v", err)
		}
		first := valid(t, path)
		if err := zeroizeRotateMachineID(path); err != nil {
			t.Fatalf("rotate again: %v", err)
		}
		if second := valid(t, path); second == first {
			t.Fatal("rotation must install a differing identity")
		}
	})
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-id")
		mustWriteFile(t, target, []byte("0123456789abcdef0123456789abcdef\n"))
		link := filepath.Join(dir, "machine-id")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := zeroizeRotateMachineID(link); err == nil {
			t.Fatal("symlinked machine-id must fail closed")
		}
	})
	t.Run("hardlink refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "machine-id")
		mustWriteFile(t, path, []byte("0123456789abcdef0123456789abcdef\n"))
		sibling := filepath.Join(dir, "sibling-id")
		if err := os.Link(path, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		var linkErr *configstore.FactoryResetHardlinkError
		if err := zeroizeRotateMachineID(path); !errors.As(err, &linkErr) {
			t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
		}
		for _, p := range []string{path, sibling} {
			if body, serr := os.ReadFile(p); serr != nil || string(body) != "0123456789abcdef0123456789abcdef\n" {
				t.Fatalf("refusal must leave original bytes intact, %s body=%q err=%v", p, body, serr)
			}
		}
	})
}

// RED on revert: unlinking before the census destroys the nlink evidence,
// so a retry reports success while the sibling retains the bytes. The
// refusal must precede any removal and persist across retries, with the
// established inode-scan operator action.
func TestZeroizeRemovePathRefusesHardlinkBeforeUnlink10769(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "secret")
	mustWriteFile(t, managed, []byte("secret bytes"))
	sibling := filepath.Join(dir, "sibling")
	if err := os.Link(managed, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		err := zeroizeRemovePath(managed)
		var linkErr *configstore.FactoryResetHardlinkError
		if !errors.As(err, &linkErr) {
			t.Fatalf("attempt %d: expected FactoryResetHardlinkError, got %v", attempt, err)
		}
		if len(linkErr.Paths) != 1 || linkErr.Paths[0].Path != managed {
			t.Fatalf("attempt %d: error must name the managed path, got %+v", attempt, linkErr.Paths)
		}
		for _, path := range []string{managed, sibling} {
			if _, serr := os.Lstat(path); serr != nil {
				t.Fatalf("attempt %d: refusal must remove nothing, %s stat err=%v", attempt, path, serr)
			}
		}
	}
}

// The ungated helper sweep must never unlink a reserved alias (the wipe
// would delete its own gates/identity), but it must FAIL naming the
// alias: a skip that reports clean lets the wipe complete with helper
// residue unproven. Mirrors the daemon sweep contract.
func TestZeroizeEraseHelperStateRefusesReserved10769(t *testing.T) {
	for _, base := range []string{".reset-handoff", ".day0-config-applied"} {
		t.Run(base, func(t *testing.T) {
			dir := t.TempDir()
			canonical := filepath.Join(dir, base)
			body := []byte("gate bytes must survive")
			mustWriteFile(t, canonical, body)
			temp := canonical + ".4250000000.1.tmp"
			mustWriteFile(t, temp, []byte(`{"orphan":true}`))
			err := zeroizeEraseHelperState(canonical)
			if err == nil {
				t.Fatal("reserved-alias sweep must fail closed, got nil")
			}
			if !strings.Contains(err.Error(), "aliases reserved") || !strings.Contains(err.Error(), canonical) {
				t.Fatalf("sweep error must name the reserved alias, got %v", err)
			}
			if !strings.Contains(err.Error(), "delete /etc/xpf/.reset-handoff") || !strings.Contains(err.Error(), "restart xpfd") || !strings.Contains(err.Error(), "commit-confirmed") {
				t.Fatalf("sweep error must document the verify/delete/restart/commit-confirmed/rerun recovery, got %v", err)
			}
			if got, err := os.ReadFile(canonical); err != nil || string(got) != string(body) {
				t.Fatalf("reserved canonical must survive byte-identical: %q err=%v", got, err)
			}
			if _, err := os.Lstat(temp); !os.IsNotExist(err) {
				t.Fatalf("temps beside reserved canonical must still be swept: %v", err)
			}
		})
	}
	t.Run("clean temps still fail", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, ".reset-handoff")
		mustWriteFile(t, canonical, []byte("gate bytes must survive"))
		if err := zeroizeEraseHelperState(canonical); err == nil {
			t.Fatal("reserved alias with clean temps must fail the sweep, got nil")
		} else if !strings.Contains(err.Error(), "aliases reserved") {
			t.Fatalf("sweep error must name the reserved alias, got %v", err)
		}
	})
	t.Run("missing parent still fails", func(t *testing.T) {
		dir := t.TempDir()
		parent := filepath.Join(dir, "no-such-dir")
		canonical := filepath.Join(parent, ".reset-handoff")
		if err := zeroizeEraseHelperState(canonical); err == nil {
			t.Fatal("reserved alias with a missing parent must fail the sweep, got nil")
		} else if !strings.Contains(err.Error(), "aliases reserved") {
			t.Fatalf("sweep error must name the reserved alias, got %v", err)
		}
		if _, serr := os.Lstat(parent); !os.IsNotExist(serr) {
			t.Fatalf("failed sweep must create nothing: %v", serr)
		}
	})
	t.Run("missing parent non-reserved succeeds", func(t *testing.T) {
		dir := t.TempDir()
		parent := filepath.Join(dir, "no-such-dir")
		canonical := filepath.Join(parent, "userspace-dp.json")
		if err := zeroizeEraseHelperState(canonical); err != nil {
			t.Fatalf("missing parent with a non-reserved path must sweep nil, got %v", err)
		}
		if _, serr := os.Lstat(parent); !os.IsNotExist(serr) {
			t.Fatalf("nil sweep must create nothing: %v", serr)
		}
	})
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-state.json")
		mustWriteFile(t, target, []byte(`{"flows":[]}`))
		link := filepath.Join(dir, "state-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := zeroizeEraseHelperState(link); err == nil {
			t.Fatal("symlinked helper state must fail closed")
		}
		for _, path := range []string{link, target} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("refusal must remove nothing, %s stat err=%v", path, err)
			}
		}
	})
}

// RED on revert: unlinking before the census destroys the nlink evidence,
// so a retry succeeds while the sibling retains the bytes.
func TestZeroizeEraseHelperStateRefusesHardlinkedCanonical10769(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "userspace-dp.json")
	mustWriteFile(t, dest, []byte(`{"flows":[]}`))
	sibling := filepath.Join(dir, "sibling.json")
	if err := os.Link(dest, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		var linkErr *configstore.FactoryResetHardlinkError
		if err := zeroizeEraseHelperState(dest); !errors.As(err, &linkErr) {
			t.Fatalf("attempt %d: expected FactoryResetHardlinkError, got %v", attempt, err)
		}
		for _, path := range []string{dest, sibling} {
			if _, serr := os.Lstat(path); serr != nil {
				t.Fatalf("attempt %d: refusal must remove nothing, %s stat err=%v", attempt, path, serr)
			}
		}
	}
}

func TestZeroizeClearTmpDirRefusesHardlinkedEntry10769(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "tenant.tmp")
	mustWriteFile(t, entry, []byte("tenant bytes"))
	sibling := filepath.Join(dir, "sibling.tmp")
	if err := os.Link(entry, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	var linkErr *configstore.FactoryResetHardlinkError
	if err := zeroizeClearTmpDir(dir); !errors.As(err, &linkErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	for _, path := range []string{entry, sibling} {
		if _, serr := os.Lstat(path); serr != nil {
			t.Fatalf("refusal must remove nothing, %s stat err=%v", path, serr)
		}
	}
}

func TestZeroizeClearRunXPFDirRefusesHardlinkedEntry10769(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "state.json")
	mustWriteFile(t, entry, []byte("tenant bytes"))
	sibling := filepath.Join(dir, "sibling.json")
	if err := os.Link(entry, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	var linkErr *configstore.FactoryResetHardlinkError
	if err := zeroizeClearRunXPFDir(dir); !errors.As(err, &linkErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	for _, path := range []string{entry, sibling} {
		if _, serr := os.Lstat(path); serr != nil {
			t.Fatalf("refusal must remove nothing, %s stat err=%v", path, serr)
		}
	}
}

// Proves the load-bearing boot-ordering claim against the real
// systemd-machine-id-setup binary (same generation as the image):
// a VALID installed id is used verbatim at boot init, so the
// wipe-installed fresh id never consults firmware state and a
// stable-UUID fixture would be moot. There is no unit edge to pin:
// PID 1 runs machine-id setup before any unit starts. An empty id
// still regenerates (control leg). Hermetic via --root; skipped
// where systemd is absent.
func TestSystemdUsesInstalledMachineIDVerbatim10769(t *testing.T) {
	bin, err := exec.LookPath("systemd-machine-id-setup")
	if err != nil {
		t.Skip("systemd-machine-id-setup unavailable")
	}
	run := func(t *testing.T, root string) string {
		t.Helper()
		cmd := exec.Command(bin, "--root="+root, "--print")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("systemd-machine-id-setup --root: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	t.Run("valid installed id used verbatim", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		const installed = "f0e1d2c3b4a5968778695a4b3c2d1e0f"
		idPath := filepath.Join(root, "etc", "machine-id")
		if err := os.WriteFile(idPath, []byte(installed+"\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		if got := run(t, root); got != installed {
			t.Fatalf("boot init must use the installed id verbatim, got %q want %q", got, installed)
		}
		if body, err := os.ReadFile(idPath); err != nil || strings.TrimSpace(string(body)) != installed {
			t.Fatalf("boot init must leave the installed id untouched, body=%q err=%v", body, err)
		}
	})
	t.Run("empty id regenerates", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		idPath := filepath.Join(root, "etc", "machine-id")
		// 0644, not the production 0444: the tool must write the
		// regenerated id and the test does not run as root.
		if err := os.WriteFile(idPath, []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
		got := run(t, root)
		if len(got) != 32 || strings.Trim(got, "0123456789abcdef") != "" {
			t.Fatalf("empty id must regenerate to valid 32-hex, got %q", got)
		}
	})
}

// The sealed appliance carries /var/lib/dbus/machine-id as a tmpfiles
// symlink to /etc/machine-id (nothing stages the file; the L-line creates
// the link when absent). Refusing symlinks here would fail every reset
// on the target image; only the link goes, and rotation still applies.
func TestPerformZeroizeRemovesSymlinkedDBusMachineID10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	mustWriteFile(t, zeroizeMachineIDPath, []byte("0123456789abcdef0123456789abcdef\n"))
	if err := os.MkdirAll(filepath.Dir(zeroizeDBusMachineIDPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(zeroizeMachineIDPath, zeroizeDBusMachineIDPath); err != nil {
		t.Fatal(err)
	}
	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("symlinked dbus alias must not fail the wipe: %v", err)
	}
	if _, err := os.Lstat(zeroizeDBusMachineIDPath); !os.IsNotExist(err) {
		t.Fatalf("dbus symlink must be unlinked: %v", err)
	}
	body, err := os.ReadFile(zeroizeMachineIDPath)
	if err != nil {
		t.Fatalf("machine-id must survive link removal: %v", err)
	}
	if id := strings.TrimSpace(string(body)); len(id) != 32 || id == "0123456789abcdef0123456789abcdef" {
		t.Fatalf("machine-id must rotate despite the alias shape, got %q", body)
	}
}

// The identity-file legs must report hardlink hits with the established
// inode-scan error (errors.As), not %v: operators lose the dev/ino/find
// remediation otherwise. Refusal precedes any replacement.
func TestIdentityLegsReportHardlinkError10769(t *testing.T) {
	legs := []struct {
		name  string
		erase func(string) error
		body  string
	}{
		{"hostname", zeroizeResetHostname, "prior-tenant\n"},
		{"resolver", zeroizeResetResolvConf, "nameserver 10.0.0.1\n"},
		{"hosts", zeroizeResetHosts, "127.0.0.1 localhost\n"},
	}
	for _, leg := range legs {
		t.Run(leg.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "identity")
			mustWriteFile(t, path, []byte(leg.body))
			sibling := filepath.Join(dir, "sibling")
			if err := os.Link(path, sibling); err != nil {
				t.Fatalf("hardlink plant: %v", err)
			}
			var linkErr *configstore.FactoryResetHardlinkError
			if err := leg.erase(path); !errors.As(err, &linkErr) {
				t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
			}
			for _, p := range []string{path, sibling} {
				if body, serr := os.ReadFile(p); serr != nil || string(body) != leg.body {
					t.Fatalf("refusal must leave original bytes intact, %s body=%q err=%v", p, body, serr)
				}
			}
		})
	}
}
