package factoryreset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #16443: zeroize from an xpf-provisioned account's own session could
// never complete — userdel -r refuses a busy account (exit 8) — but the
// wipe only discovered that AFTER the seal, login, networkd and config
// legs had erased host keys, login keys, sudoers and the config DB.
// These cells pin the fix: a busy provisioned account refuses the wipe
// BEFORE any destructive leg (naming the account, every surface intact),
// an idle account still completes, an account that becomes busy after
// the preflight is terminated + re-verified (toolless seam), and an
// account that stays busy is never userdel'd.
//
// RED on revert: drop the checkProvisionedAccountsIdle gate from
// performWipeWithLogInventory/performWipe and the busy cell's wipe
// proceeds, erases the planted surfaces and returns the userdel exit-8
// error (or, with the default hermetic userdel, a clean but fully-wiped
// result) — the intact-surface and named-account assertions fail.
// Drop terminateBusyProvisionedAccounts and the became-busy cell fires
// userdel at a busy UID.

// busyEnv16443 plants one provisioned account "admin" (UID 1001) plus the
// destructive surfaces the issue names, all under a hermetic tree.
type busyEnv16443 struct {
	configDir string
	hostKey   string
	adminKeys string
	sudo      string
	networkd  string
	marker    string
	deleted   *[]string
	killed    *[]int
}

func plantBusyEnv16443(t *testing.T) *busyEnv16443 {
	t.Helper()
	root := t.TempDir()
	hermeticWipe10100(t, root)
	env := &busyEnv16443{configDir: filepath.Join(root, "etc", "xpf")}

	mustWriteFile(t, filepath.Join(env.configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(env.configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(env.configDir, "xpf.conf"), []byte("system {}\n"))

	// SSH host key (seal leg).
	env.hostKey = filepath.Join(root, "etc", "ssh", "ssh_host_ed25519_key")
	mustWriteFile(t, env.hostKey, []byte("host-key"))

	// Provisioned account admin/1001: marker, passwd, keys, sudoers.
	login := filepath.Join(root, "login")
	mustWriteFile(t, filepath.Join(login, "passwd"), []byte(
		"root:x:0:0:root:/root:/bin/bash\nadmin:x:1001:1001:admin:/home/admin:/bin/bash\n"))
	env.marker = filepath.Join(login, "provisioned-users", "admin")
	mustWriteFile(t, env.marker, []byte("1001"))
	env.adminKeys = filepath.Join(login, "home", "admin", ".ssh", "authorized_keys")
	mustWriteFile(t, env.adminKeys, []byte("ssh-ed25519 AAAA admin\n"))
	env.sudo = filepath.Join(login, "sudoers.d", "xpf-admin")
	mustWriteFile(t, env.sudo, []byte("admin ALL=(ALL) NOPASSWD: ALL\n"))

	env.networkd = filepath.Join(root, "networkd", "10-xpf-fxp0.network")
	mustWriteFile(t, env.networkd, []byte("[Match]\n"))

	// Record userdel + kill invocations (Redirect installed no-ops).
	var deleted []string
	origUserdel := wipeUserdel
	wipeUserdel = func(name string) ([]byte, error) {
		deleted = append(deleted, name)
		return nil, nil
	}
	t.Cleanup(func() { wipeUserdel = origUserdel })
	env.deleted = &deleted
	var killed []int
	origKill := wipeKillAccountProcesses
	wipeKillAccountProcesses = func(uid int) ([]byte, error) {
		killed = append(killed, uid)
		return nil, nil
	}
	t.Cleanup(func() { wipeKillAccountProcesses = origKill })
	env.killed = &killed
	return env
}

func TestZeroizeBusyProvisionedAccountRefusesBeforeAnyWipe16443(t *testing.T) {
	env := plantBusyEnv16443(t)
	origBusy := wipeAccountHasLiveProcesses
	wipeAccountHasLiveProcesses = func(uid int) (bool, error) {
		return uid == 1001, nil // admin is busy (the operator's own session)
	}
	t.Cleanup(func() { wipeAccountHasLiveProcesses = origBusy })
	// Even the userdel seam reporting busy must never be reached.
	origUserdel := wipeUserdel
	wipeUserdel = func(string) ([]byte, error) {
		return []byte("userdel: user admin is currently used by process 1"), errors.New("exit status 8")
	}
	t.Cleanup(func() { wipeUserdel = origUserdel })

	err := PerformZeroizeWipe(env.configDir, "xpf.conf", "")
	if err == nil {
		t.Fatal("busy provisioned account: PerformZeroizeWipe returned nil; want a refusal naming the account")
	}
	if !strings.Contains(err.Error(), `"admin"`) {
		t.Errorf("refusal must name the busy account, got: %v", err)
	}
	if len(*env.deleted) != 0 {
		t.Errorf("userdel invoked %v on a refused wipe; want none", *env.deleted)
	}
	if len(*env.killed) != 0 {
		t.Errorf("processes terminated %v on a refused wipe; want none (refuse, do not kill the caller's session pre-marker)", *env.killed)
	}
	// Every surface intact: host key, login key, sudoers, networkd, config DB.
	for _, p := range []string{env.hostKey, env.adminKeys, env.sudo, env.networkd, env.marker,
		filepath.Join(env.configDir, ".configdb", "master.key"),
		filepath.Join(env.configDir, ".configdb", "active.json"),
		filepath.Join(env.configDir, "xpf.conf")} {
		assertPresent(t, p)
	}
	// No pending marker was written: a refused zeroize is retryable
	// against an intact box, not an interrupted reset.
	if _, serr := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(serr) {
		t.Errorf("pending marker exists after refusal (stat err=%v); want none", serr)
	}
	if _, serr := os.Lstat(filepath.Join(env.configDir, configstore.FactoryResetPendingBase)); !os.IsNotExist(serr) {
		t.Errorf("config-root pending marker exists after refusal (stat err=%v); want none", serr)
	}
}

// Twin of the busy cell: an idle provisioned account completes cleanly.
func TestZeroizeIdleProvisionedAccountStillCompletes16443(t *testing.T) {
	env := plantBusyEnv16443(t)
	// Hermetic default from RedirectWipePathsForTesting: idle (false,nil).

	if err := PerformZeroizeWipe(env.configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("idle provisioned account: PerformZeroizeWipe: %v", err)
	}
	if len(*env.deleted) != 1 || (*env.deleted)[0] != "admin" {
		t.Errorf("userdel invoked %v, want exactly [admin]", *env.deleted)
	}
	assertAbsent(t, env.adminKeys)
	assertAbsent(t, env.sudo)
	assertAbsent(t, env.hostKey)
	assertAbsent(t, env.networkd)
	assertAbsent(t, filepath.Join(env.configDir, ".configdb", "master.key"))
}

// An account idle at the preflight but busy by the time the login leg
// runs (new session in the check-to-use window) is terminated scoped to
// its UID and re-verified idle, then userdel proceeds: the wipe
// completes instead of hitting userdel exit 8 mid-wipe.
func TestZeroizeAccountBecameBusyIsTerminatedThenDeleted16443(t *testing.T) {
	env := plantBusyEnv16443(t)
	calls := 0
	origBusy := wipeAccountHasLiveProcesses
	wipeAccountHasLiveProcesses = func(uid int) (bool, error) {
		calls++
		// Call 1: wrapper preflight. Call 2: performWipe gate. Call 3:
		// in-wipe re-check (busy now). Call 4: post-kill verify (idle).
		return calls == 3 && uid == 1001, nil
	}
	t.Cleanup(func() { wipeAccountHasLiveProcesses = origBusy })

	if err := PerformZeroizeWipe(env.configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("became-busy account: PerformZeroizeWipe: %v", err)
	}
	if len(*env.killed) != 1 || (*env.killed)[0] != 1001 {
		t.Errorf("terminated UIDs %v, want exactly [1001]", *env.killed)
	}
	if len(*env.deleted) != 1 || (*env.deleted)[0] != "admin" {
		t.Errorf("userdel invoked %v, want exactly [admin]", *env.deleted)
	}
	assertAbsent(t, env.adminKeys)
}

// An account that stays busy after termination is never userdel'd and
// its markers survive for a retry; the wipe reports incomplete.
func TestZeroizeAccountStillBusyAfterTerminationIsNotDeleted16443(t *testing.T) {
	env := plantBusyEnv16443(t)
	calls := 0
	origBusy := wipeAccountHasLiveProcesses
	wipeAccountHasLiveProcesses = func(uid int) (bool, error) {
		calls++
		return calls >= 3 && uid == 1001, nil // idle at both preflights, busy in-wipe and after kill
	}
	t.Cleanup(func() { wipeAccountHasLiveProcesses = origBusy })

	err := PerformZeroizeWipe(env.configDir, "xpf.conf", "")
	if err == nil {
		t.Fatal("still-busy account: PerformZeroizeWipe returned nil; want incomplete")
	}
	if !strings.Contains(err.Error(), `"admin"`) {
		t.Errorf("error must name the still-busy account, got: %v", err)
	}
	if len(*env.deleted) != 0 {
		t.Errorf("userdel invoked %v at a proven-busy UID; want none", *env.deleted)
	}
	assertPresent(t, env.marker)    // retained for retry
	assertPresent(t, env.adminKeys) // not removed ahead of a userdel that cannot run
}

// A process-probe failure is UNKNOWN, never assumed idle: the wipe
// refuses before any leg rather than gambling on userdel.
func TestZeroizeBusyProbeFailureRefusesBeforeAnyWipe16443(t *testing.T) {
	env := plantBusyEnv16443(t)
	origBusy := wipeAccountHasLiveProcesses
	wipeAccountHasLiveProcesses = func(int) (bool, error) {
		return false, errors.New("pgrep unavailable")
	}
	t.Cleanup(func() { wipeAccountHasLiveProcesses = origBusy })

	err := PerformZeroizeWipe(env.configDir, "xpf.conf", "")
	if err == nil {
		t.Fatal("probe failure: PerformZeroizeWipe returned nil; want refusal")
	}
	if len(*env.deleted) != 0 {
		t.Errorf("userdel invoked %v on a refused wipe; want none", *env.deleted)
	}
	assertPresent(t, env.hostKey)
	assertPresent(t, env.adminKeys)
	assertPresent(t, filepath.Join(env.configDir, ".configdb", "master.key"))
}
