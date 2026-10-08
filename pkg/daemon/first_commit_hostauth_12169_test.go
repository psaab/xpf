package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// first_commit_hostauth_12169_test.go — #12169.
//
// The prevCfg==nil branch of executeConfirmedRollback (a FIRST commit
// confirmed on a fresh store timing out) runs enterBootstrapMode plus the
// web-only reconcileManagementAfterPromotion, then returns. The login,
// sudoers, absent-user, sshd, root-auth and nft owners run only from the
// apply tail (daemon_apply_tail.go) or the cancel closeout
// (daemon_apply_hostauth.go) — and a bootstrap boot suppresses the apply
// (daemon_run_bringup.go) — so the abandoned commit's xpf-owned host
// authorization (accounts, sudo grants, sshd drop-in, root keys, nft
// tables) stayed live with no reconciler ever revisiting them.
//
// This cell drives the REAL first-confirm-timeout path end to end:
// CommitConfirmed on a fresh store, seeded xpf-owned host-auth markers
// from the abandoned config's apply, then the rollback timer fires. The
// empty active config the store promotes must retire every xpf-owned
// marker while leaving foreign state untouched.
//
// Fail-on-revert: remove the host-auth owner run from the prevCfg==nil
// branch and every "retired" assertion below goes RED — the owned
// sudoers/sshd/account/key/root/nft markers survive the rollback — while
// the foreign-state assertions stay green.
func TestFirstCommitRollbackRetiresOwnedHostAuth12169(t *testing.T) {
	root := t.TempDir()

	// --- Hermetic identity + marker roots (never /etc, never /var/lib/xpf).
	origShadow, origPasswd := shadowPath, passwdPath
	origUsersDir, origHomeBase, origRootSSH := provisionedUsersDir, homeBaseDir, rootSSHDir
	shadowPath = filepath.Join(root, "shadow")
	passwdPath = filepath.Join(root, "passwd")
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	homeBaseDir = filepath.Join(root, "home")
	rootSSHDir = filepath.Join(root, "root-ssh")
	t.Cleanup(func() {
		shadowPath, passwdPath = origShadow, origPasswd
		provisionedUsersDir, homeBaseDir, rootSSHDir = origUsersDir, origHomeBase, origRootSSH
	})
	// alice is a live local account with an ACTIVE (unlocked) password;
	// mallory is an out-of-band operator account xpf never provisioned.
	passwdContent := "root:x:0:0::/root:/bin/bash\n" +
		"alice:x:1001:1001::/home/alice:/bin/bash\n" +
		"mallory:x:1002:1002::/home/mallory:/bin/bash\n"
	shadowContent := "root:!:19000:0:99999:7:::\n" +
		"alice:$6$salt$activehash:19000:0:99999:7:::\n" +
		"mallory:$6$salt$malloryhash:19000:0:99999:7:::\n"
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte(shadowContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// --- chpasswd runs a fake on PATH that records its stdin (the lock
	// command) and MUTATES the fixture shadow like the real tool, so the
	// lock is observable in the identity DB, not just in argv.
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "chpasswd-stdin")
	script := "#!/bin/sh\ncat > " + sentinel + "\n" +
		"while IFS=: read -r u h _; do " +
		"[ -n \"$u\" ] && [ -n \"$h\" ] && sed -i \"s/^$u:[^:]*/$u:$h/\" " + shadowPath + "; " +
		"done < " + sentinel + "\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	// --- sudoers at a throwaway dir: one xpf-owned grant the abandoned
	// commit wrote, one operator-authored file that must survive.
	sudoersTmp := t.TempDir()
	origSudoersDir, origValidate := sudoersDir, validateSudoersFile
	sudoersDir = sudoersTmp
	validateSudoersFile = func(string) error { return nil }
	t.Cleanup(func() { sudoersDir, validateSudoersFile = origSudoersDir, origValidate })
	if err := os.WriteFile(filepath.Join(sudoersTmp, "xpf-alice"), []byte("alice ALL=(ALL) NOPASSWD: ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	foreignSudoers := filepath.Join(sudoersTmp, "90-operator-custom")
	if err := os.WriteFile(foreignSudoers, []byte("mallory ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	// --- sshd drop-ins on a throwaway filesystem: the xpf-owned file must
	// be removed while an operator-authored file in the same directory stays.
	sshdDir := filepath.Join(root, "sshd_config.d")
	if err := os.MkdirAll(sshdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	origSSHDPath, origSSHDReload, origSSHDValidate := sshdConfPath, sshdReloadCmd, sshdValidateCmd
	sshdConfPath = filepath.Join(sshdDir, "00-xpf.conf")
	sshdReloads := 0
	sshdReloadCmd = func() ([]byte, error) { sshdReloads++; return nil, nil }
	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		sshdConfPath, sshdReloadCmd, sshdValidateCmd = origSSHDPath, origSSHDReload, origSSHDValidate
	})
	if err := os.WriteFile(sshdConfPath, []byte("# Managed by xpf\nPermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	foreignSSHD := filepath.Join(sshdDir, "99-operator.conf")
	if err := os.WriteFile(foreignSSHD, []byte("PermitRootLogin prohibit-password\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// --- nft: record every table teardown; the abandoned commit's
	// host-inbound + lo0 tables must both be deleted. Keep all kernel and
	// lifeline observation seams hermetic.
	origInstaller := nftInstaller
	var deleted, nftEvents []string
	nftFake := &fakeNftInstaller{
		del: func(name string) error {
			deleted = append(deleted, name)
			nftEvents = append(nftEvents, "delete:"+name)
			return nil
		},
		earlyInputBarrierLifelineInstall: func([]string) error {
			nftEvents = append(nftEvents, "lifeline-guard")
			return nil
		},
	}
	nftInstaller = nftFake
	t.Cleanup(func() { nftInstaller = origInstaller })
	origMarker := EarlyInputHandoffMarkerPath
	EarlyInputHandoffMarkerPath = filepath.Join(root, "early-input-handoff.done")
	t.Cleanup(func() { EarlyInputHandoffMarkerPath = origMarker })
	origSnapshots := sampleHostInboundSnapshots
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return nil }
	t.Cleanup(func() { sampleHostInboundSnapshots = origSnapshots })
	origDetect, origRecord := detectLifelineInterfaceFn, lifelineRecordNameFn
	detectLifelineInterfaceFn = func() (string, bool, error) { return "", false, nil }
	lifelineRecordNameFn = func() (string, bool) { return "", false }
	t.Cleanup(func() { detectLifelineInterfaceFn, lifelineRecordNameFn = origDetect, origRecord })

	// --- Store: a FIRST commit confirmed on a fresh store whose abandoned
	// config provisioned alice (super-user), an sshd policy, root keys,
	// and host-inbound/lo0 enforcement.
	s, err := configstore.New(filepath.Join(root, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(*config.Config) {}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	abandoned := "system { host-name abandoned; login { user alice { class super-user; } } " +
		"services { ssh { root-login deny; } } root-authentication { ssh-ed25519 \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI12169 root@xpf\"; } } " +
		"security { zones { security-zone trust { host-inbound-traffic { system-services ssh; } } } }"
	if err := s.LoadOverride(abandoned); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.ExitConfigure()

	// The abandoned commit's apply ran before the timeout: seed the
	// xpf-owned host-auth state it would have left behind.
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markPasswordProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	aliceKeys := managedAuthorizedKeysPath("alice")
	if err := os.MkdirAll(filepath.Dir(aliceKeys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aliceKeys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI12169 alice@xpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// mallory's key file is operator-installed (no marker): it must survive.
	malloryKeys := managedAuthorizedKeysPath("mallory")
	if err := os.MkdirAll(filepath.Dir(malloryKeys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malloryKeys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImallory mallory@xpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Root keys the abandoned commit provisioned (marker present).
	if err := markKeyProvisioned("root", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rootSSHDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootKeys := rootAuthorizedKeysPath()
	if err := os.WriteFile(rootKeys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIroot12169 root@xpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if d.inBootstrap() {
		t.Fatal("daemon should not be in bootstrap before the timeout")
	}

	// Fire the rollback timer's executor branch deterministically: the
	// first-commit timeout reverts the store to the empty tree and rolls
	// the daemon back to bootstrap mode.
	s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())

	if !d.inBootstrap() {
		t.Fatal("after first-commit rollback timeout, daemon must be in BOOTSTRAP mode")
	}
	if s.EverCommitted() {
		t.Fatal("after first-commit rollback, store must read never-committed")
	}

	// --- Owned state is retired.
	if _, err := os.Stat(filepath.Join(sudoersTmp, "xpf-alice")); !os.IsNotExist(err) {
		t.Error("abandoned commit's xpf-alice sudo grant survived the first-commit rollback")
	}
	if _, err := os.Stat(sshdConfPath); !os.IsNotExist(err) {
		t.Error("abandoned commit's xpf sshd drop-in survived the first-commit rollback")
	}
	if sshdReloads == 0 {
		t.Error("sshd was never reloaded after the rollback removed its drop-in")
	}
	shadowAfter, err := os.ReadFile(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	aliceLocked := false
	for _, line := range strings.Split(string(shadowAfter), "\n") {
		if strings.HasPrefix(line, "alice:") {
			aliceLocked = strings.HasPrefix(line, "alice:!")
		}
	}
	if !aliceLocked {
		t.Error("abandoned commit's alice password was not locked by the first-commit rollback")
	}
	if _, err := os.Stat(aliceKeys); !os.IsNotExist(err) {
		t.Error("abandoned commit's alice authorized_keys survived the first-commit rollback")
	}
	if _, err := os.Stat(rootKeys); !os.IsNotExist(err) {
		t.Error("abandoned commit's root authorized_keys survived the first-commit rollback")
	}
	for _, owned := range []struct{ dir, name string }{
		{provisionedUsersDir, "alice"},
		{provisionedPasswordsDir(), "alice"},
		{provisionedKeysDir(), "alice"},
		{provisionedKeysDir(), "root"},
	} {
		if _, err := os.Stat(filepath.Join(owned.dir, owned.name)); !os.IsNotExist(err) {
			t.Errorf("xpf ownership marker %s/%s survived the first-commit rollback", owned.dir, owned.name)
		}
	}
	for _, table := range []string{xnft.HostInboundTableName, xnft.HostInboundGapTableName, xnft.Lo0TableName} {
		found := false
		for _, name := range deleted {
			if name == table {
				found = true
			}
		}
		if !found {
			t.Errorf("nft table %q was not torn down by the first-commit rollback (deleted=%v)", table, deleted)
		}
	}
	firstDelete := -1
	firstGuard := -1
	for i, event := range nftEvents {
		if event == "lifeline-guard" && firstGuard == -1 {
			firstGuard = i
		}
		if strings.HasPrefix(event, "delete:") && firstDelete == -1 {
			firstDelete = i
		}
	}
	if firstGuard == -1 || firstDelete == -1 || firstGuard > firstDelete {
		t.Errorf("bootstrap lifeline guard must be installed before nft teardown: events=%v", nftEvents)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Error("bootstrap rollback marked early-input handoff complete; the lifeline guard must remain armed")
	}
	if EarlyInputHandoffMarked() {
		t.Error("bootstrap rollback persisted a completed handoff marker")
	}
	if len(nftFake.earlyInputBarrierLifelineSpecs) == 0 {
		t.Error("bootstrap rollback did not install the lifeline-admitting input guard")
	} else {
		foundFxp0 := false
		for _, name := range nftFake.earlyInputBarrierLifelineSpecs[len(nftFake.earlyInputBarrierLifelineSpecs)-1] {
			if name == defaultMgmtInterface {
				foundFxp0 = true
			}
		}
		if !foundFxp0 {
			t.Errorf("bootstrap input guard lifelines = %v, want %q exemption", nftFake.earlyInputBarrierLifelineSpecs[len(nftFake.earlyInputBarrierLifelineSpecs)-1], defaultMgmtInterface)
		}
	}
	for _, call := range nftFake.earlyInputBarrierCalls {
		if call == "remove" {
			t.Error("bootstrap rollback removed the early input guard instead of preserving the lifeline exemption")
			break
		}
	}

	// --- Foreign state is kept (provenance scoping + lifeline exemption).
	if _, err := os.Stat(foreignSudoers); err != nil {
		t.Errorf("operator-authored sudoers file was touched by the rollback: %v", err)
	}
	if _, err := os.Stat(malloryKeys); err != nil {
		t.Errorf("out-of-band mallory authorized_keys was touched by the rollback: %v", err)
	}
	if _, err := os.Stat(foreignSSHD); err != nil {
		t.Errorf("operator-authored sshd drop-in was touched by the rollback: %v", err)
	}
	malloryIntact := false
	for _, line := range strings.Split(string(shadowAfter), "\n") {
		if line == "mallory:$6$salt$malloryhash:19000:0:99999:7:::" {
			malloryIntact = true
		}
	}
	if !malloryIntact {
		t.Error("out-of-band mallory shadow entry was touched by the rollback")
	}
}

// isolateFirstCommitRollbackHostAuth12169 keeps the legacy first-commit
// rollback tests hermetic now that the rollback runs every host-auth owner.
// Unlike the issue regression above, those tests do not seed abandoned
// credentials, so an empty set of temp roots is sufficient.
func isolateFirstCommitRollbackHostAuth12169(t *testing.T) {
	t.Helper()
	root := t.TempDir()

	origShadow, origPasswd := shadowPath, passwdPath
	origUsers, origHome, origRootSSH := provisionedUsersDir, homeBaseDir, rootSSHDir
	origSudoers, origSudoersValidate := sudoersDir, validateSudoersFile
	origSSHDPath, origSSHDReload, origSSHDValidate := sshdConfPath, sshdReloadCmd, sshdValidateCmd
	origInstaller, origBarrierPath := nftInstaller, EarlyInputHandoffMarkerPath
	origSnapshots := sampleHostInboundSnapshots
	origDetect, origRecord := detectLifelineInterfaceFn, lifelineRecordNameFn

	shadowPath = filepath.Join(root, "shadow")
	passwdPath = filepath.Join(root, "passwd")
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	homeBaseDir = filepath.Join(root, "home")
	rootSSHDir = filepath.Join(root, "root-ssh")
	sudoersDir = filepath.Join(root, "sudoers.d")
	sshdConfPath = filepath.Join(root, "sshd_config.d", "00-xpf.conf")
	EarlyInputHandoffMarkerPath = filepath.Join(root, "early-input-handoff.done")
	nftInstaller = noopNftInstaller{}
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return nil }
	detectLifelineInterfaceFn = func() (string, bool, error) { return "", false, nil }
	lifelineRecordNameFn = func() (string, bool) { return "", false }
	validateSudoersFile = func(string) error { return nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, nil }
	sshdValidateCmd = func() ([]byte, error) { return nil, nil }

	for _, dir := range []string{
		provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir(),
		homeBaseDir, rootSSHDir, sudoersDir, filepath.Dir(sshdConfPath),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create isolated host-auth directory: %v", err)
		}
	}
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		shadowPath, passwdPath = origShadow, origPasswd
		provisionedUsersDir, homeBaseDir, rootSSHDir = origUsers, origHome, origRootSSH
		sudoersDir, validateSudoersFile = origSudoers, origSudoersValidate
		sshdConfPath, sshdReloadCmd, sshdValidateCmd = origSSHDPath, origSSHDReload, origSSHDValidate
		nftInstaller, EarlyInputHandoffMarkerPath = origInstaller, origBarrierPath
		sampleHostInboundSnapshots = origSnapshots
		detectLifelineInterfaceFn, lifelineRecordNameFn = origDetect, origRecord
	})
}
