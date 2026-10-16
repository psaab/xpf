package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

// #14112: the retained-user zero-key branch in applySystemLogin removed the
// xpf-managed authorized_keys (and its marker) without consulting the LIVE
// active config. A timed-out host-auth closeout owner (daemon_apply_hostauth.go
// abandons the goroutine at budget expiry) can resume after a newer commit has
// re-presented the same retained user WITH keys and installed them; the stale
// empty-keys pass then deletes the newer file — a management lockout. The
// sibling revocation paths (deprovisionLoginUser, applyRootAuth,
// reconcileSudoers) already fence on liveConfig12169(); this branch did not.
//
// Fail-on-revert: drop the liveDesiredLoginUser12169 fence in the emptied-key
// branch and this test REDS — the stale pass removes the live key file and its
// marker even though the live config desires keys for alice.
func TestStaleEmptiedKeysOwnerPreservesLiveKeys14112(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)

	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = oldRun })

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI14112 alice@xpf"
	root := filepath.Dir(passwdPath)
	store := newConfigStore(t, filepath.Join(root, "xpf.conf"))
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: store.ConfigPath()}}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	liveText := "system { host-name live; login { user alice { class operator; authentication { ssh-ed25519 \"" + key + "\"; } } } }"
	if err := store.LoadOverride(liveText); err != nil {
		t.Fatal(err)
	}
	d.applyBodyForTest = func(*config.Config) {}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if live, ok := d.liveDesiredLoginUser12169("alice"); !ok || len(live.SSHKeys) != 1 {
		t.Fatalf("premise: live config must desire one key for alice, got %+v desired=%v", live, ok)
	}

	// State a prior apply left: xpf owns alice's key file (marker + file with
	// exactly the live content, as the newer commit's apply installed).
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	keysFile := managedAuthorizedKeysPath("alice")
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The stale owner: an older config in which alice is retained but her key
	// list was emptied. On unfixed code this removes keysFile and its marker.
	stale := loginCfg(&config.LoginUser{Name: "alice", Class: "operator"})
	if err := d.applySystemLogin(stale); err != nil {
		t.Fatalf("stale emptied-keys owner: %v", err)
	}

	got, err := os.ReadFile(keysFile)
	if err != nil {
		t.Fatalf("stale owner removed the live authorized_keys (err=%v) — #14112 lockout", err)
	}
	if string(got) != key+"\n" {
		t.Fatalf("live authorized_keys content = %q, want %q", got, key+"\n")
	}
	if _, err := os.Stat(markerPathIn(provisionedKeysDir(), "alice")); err != nil {
		t.Fatalf("stale owner dropped the live key-provenance marker: %v", err)
	}

	// Control: when the live config no longer desires keys, the same branch
	// must still revoke. Retire alice's keys from the live config, then the
	// stale-shaped pass (now agreeing with live) removes file + marker.
	if err := store.LoadOverride("system { host-name live; login { user alice { class operator; } } }"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.liveDesiredLoginUser12169("alice"); !ok {
		t.Fatal("premise: alice must still be a live login user")
	}
	if live, _ := d.liveDesiredLoginUser12169("alice"); len(live.SSHKeys) != 0 {
		t.Fatalf("premise: live config must now desire no keys, got %v", live.SSHKeys)
	}
	if err := d.applySystemLogin(stale); err != nil {
		t.Fatalf("live-agreeing emptied-keys owner: %v", err)
	}
	if _, err := os.Stat(keysFile); !os.IsNotExist(err) {
		t.Fatalf("authorized_keys survived a live-agreeing revocation (err=%v)", err)
	}
	if _, err := os.Stat(markerPathIn(provisionedKeysDir(), "alice")); !os.IsNotExist(err) {
		t.Fatalf("key marker survived a live-agreeing revocation (err=%v)", err)
	}
}
