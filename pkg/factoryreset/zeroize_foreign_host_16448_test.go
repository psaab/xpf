package factoryreset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantForeignHost16448 seeds host-owned and xpf-owned seal residue under
// root (already redirected by hermeticWipe10100) and returns the paths whose
// fate the twin cells assert.
func plantForeignHost16448(t *testing.T, root string) (hostOwned, xpfOwned map[string]string) {
	t.Helper()
	hostOwned = map[string]string{
		filepath.Join(wipeRootSSHUserDir, "authorized_keys"): "operator root key\n",
		filepath.Join(wipeRootSSHUserDir, "id_ed25519"):      "operator root private key\n",
		filepath.Join(wipeRootSSHUserDir, "known_hosts"):     "host.example ssh-ed25519 AAAA\n",
		wipeRootBashHistory:                                      "operator shell history\n",
		filepath.Join(wipeVarLogDir, "syslog"):                   "host log line\n",
		filepath.Join(wipeTmpDirs[0], "scratch.txt"):             "host tmp scratch\n",
		filepath.Join(wipeTmpDirs[1], "host-build", "data"):      "host build data\n",
		filepath.Join(wipeAptListsDir, "example_Packages"):       "host package list\n",
		filepath.Join(wipeAptArchiveDir, "old.deb"):              "host package archive\n",
		filepath.Join(wipeSSHHostKeyDir, "ssh_host_ed25519_key"): "host ssh host key\n",
		wipeSystemdRandomSeed:                                    "host random seed\n",
		wipeRunUtmpPath:                                          "host login records\n",
	}
	xpfOwned = map[string]string{
		wipeSNMPEngineIDPath:                              "xpf snmp engine id\n",
		wipeDay0RejectedPath:                              "xpf day0 rejected\n",
		wipeManagedDropins[0]:                             "xpf sshd drop-in\n",
		filepath.Join(wipeRunXPFDir, "helper-state"):      "xpf helper state\n",
		filepath.Join(wipeSecurityLogDir, "security.log"): "xpf security log\n",
	}
	for path, body := range hostOwned {
		mustWriteFile(t, path, []byte(body))
	}
	for path, body := range xpfOwned {
		mustWriteFile(t, path, []byte(body))
	}
	// Host identity files whose exact bytes must survive on a foreign host.
	mustWriteFile(t, wipeMachineIDPath, []byte("0123456789abcdef0123456789abcdef\n"))
	mustWriteFile(t, wipeDBusMachineIDPath, []byte("host dbus id\n"))
	mustWriteFile(t, wipeHostnamePath, []byte("operator-host.example\n"))
	mustWriteFile(t, wipeHostsPath, []byte("127.0.0.1 localhost\n10.9.9.9 operator-internal.example\n"))
	mustWriteFile(t, wipeManagedHostKeysPath, []byte("operator-trusted.example ssh-ed25519 AAAA\n"))
	mustWriteFile(t, wipeResolvConfPath, []byte("nameserver 192.0.2.53\n"))
	return hostOwned, xpfOwned
}

func assertPresent16448(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("host-owned %s must survive foreign-host zeroize: %v", path, err)
		return
	}
	if string(body) != want {
		t.Errorf("host-owned %s changed: got %q want %q", path, body, want)
	}
}

func assertAbsent16448(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("%s must be erased: %v", path, err)
	}
}

// Foreign-host twin (#16448): no /etc/xpf/appliance marker, so the
// image-seal legs must not delete host-owned root SSH material, /var/log,
// /tmp, /var/tmp, bash history, apt caches or machine-id. xpf-owned state
// is still erased and the wipe still completes (PerformZeroizeWipe drives
// the marker-aware login teardown, which preserves unmarked root keys).
//
// RED on revert: ungating wipeImageSealResidue deletes every hostOwned
// entry and rotates machine-id.
func TestPerformZeroizeForeignHostPreservesHostOwned16448(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	if err := os.Remove(wipeApplianceMarkerPath); err != nil {
		t.Fatalf("fixture must start foreign (no appliance marker): %v", err)
	}
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))

	hostOwned, xpfOwned := plantForeignHost16448(t, root)
	var liveNames []string
	wipeSethostname = func(name []byte) error {
		liveNames = append(liveNames, string(name))
		return nil
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("foreign-host PerformZeroizeWipe: %v", err)
	}
	if len(liveNames) != 0 {
		t.Errorf("foreign-host zeroize must not rename the live host, got %q", liveNames)
	}
	for path, body := range hostOwned {
		assertPresent16448(t, path, body)
	}
	assertPresent16448(t, wipeMachineIDPath, "0123456789abcdef0123456789abcdef\n")
	assertPresent16448(t, wipeDBusMachineIDPath, "host dbus id\n")
	assertPresent16448(t, wipeHostnamePath, "operator-host.example\n")
	if body, err := os.ReadFile(wipeHostsPath); err != nil || !strings.Contains(string(body), "operator-internal.example") {
		t.Errorf("foreign /etc/hosts must survive: body=%q err=%v", body, err)
	}
	assertPresent16448(t, wipeManagedHostKeysPath, "operator-trusted.example ssh-ed25519 AAAA\n")
	// /etc/resolv.conf is xpf-owned on every host: it resets to the
	// header-only default even here.
	if body, err := os.ReadFile(wipeResolvConfPath); err != nil || string(body) != wipeManagedResolvConfHeader {
		t.Errorf("resolver should reset to the xpf header-only default: body=%q err=%v", body, err)
	}
	for path := range xpfOwned {
		assertAbsent16448(t, path)
	}
	// The config root itself is xpf-owned and still erased.
	assertAbsent16448(t, filepath.Join(configDir, "xpf.conf"))
}

// Appliance twin (#16448): with the bake marker present the seal keeps
// today's behaviour — host-shaped residue is erased/rotated exactly as
// TestPerformZeroizeErasesSafeImageSealResidue10769 pins.
func TestPerformZeroizeApplianceHostSealUnchanged16448(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	if _, err := os.Stat(wipeApplianceMarkerPath); err != nil {
		t.Fatalf("redirected fixture must default to appliance: %v", err)
	}
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))

	hostOwned, _ := plantForeignHost16448(t, root)
	var liveNames []string
	wipeSethostname = func(name []byte) error {
		liveNames = append(liveNames, string(name))
		return nil
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("appliance PerformZeroizeWipe: %v", err)
	}
	if len(liveNames) != 1 || liveNames[0] != "xpf" {
		t.Errorf("appliance zeroize must reset the live hostname to xpf, got %q", liveNames)
	}
	for path := range hostOwned {
		assertAbsent16448(t, path)
	}
	if body, err := os.ReadFile(wipeMachineIDPath); err != nil {
		t.Errorf("appliance machine-id must be present after rotation: %v", err)
	} else if id := strings.TrimSpace(string(body)); len(id) != 32 || id == "0123456789abcdef0123456789abcdef" {
		t.Errorf("appliance machine-id must rotate to fresh 32-hex, got %q", body)
	}
	if body, err := os.ReadFile(wipeHostnamePath); err != nil || string(body) != "xpf\n" {
		t.Errorf("appliance hostname must reset: body=%q err=%v", body, err)
	}
	assertAbsent16448(t, wipeManagedHostKeysPath)
	// wipeResetHosts rewrites (not deletes) /etc/hosts; the tenant entry goes.
	if body, err := os.ReadFile(wipeHostsPath); err != nil || strings.Contains(string(body), "operator-internal") {
		t.Errorf("appliance /etc/hosts must be factory-reset: body=%q err=%v", body, err)
	}
}
