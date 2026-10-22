package factoryreset

import "testing"

// The shared wipe-path redirect must restore every global it moves,
// independently. The two root-SSH paths default to values that made a
// cross-wired restore invisible, so this plants distinct sentinels and
// nests two redirects: each restore must return its own entry values.
func TestRedirectZeroizeWipePathsRestoresIndependently(t *testing.T) {
	origUserDir, origSSHDir := wipeRootSSHUserDir, wipeRootSSHDir
	t.Cleanup(func() { wipeRootSSHUserDir, wipeRootSSHDir = origUserDir, origSSHDir })
	wipeRootSSHUserDir = "/sentinel/userdir"
	wipeRootSSHDir = "/sentinel/rootssh"
	outer := t.TempDir()
	restoreOuter := RedirectWipePathsForTesting(outer)
	if wipeRootSSHUserDir == "/sentinel/userdir" || wipeRootSSHDir == "/sentinel/rootssh" {
		t.Fatal("redirect must move both root-ssh paths")
	}
	outerUser, outerSSH := wipeRootSSHUserDir, wipeRootSSHDir
	inner := t.TempDir()
	restoreInner := RedirectWipePathsForTesting(inner)
	restoreInner()
	if wipeRootSSHUserDir != outerUser || wipeRootSSHDir != outerSSH {
		t.Fatalf("inner restore must return outer values, got %q and %q", wipeRootSSHUserDir, wipeRootSSHDir)
	}
	restoreOuter()
	if wipeRootSSHUserDir != "/sentinel/userdir" || wipeRootSSHDir != "/sentinel/rootssh" {
		t.Fatalf("outer restore must return entry values, got %q and %q", wipeRootSSHUserDir, wipeRootSSHDir)
	}
}
