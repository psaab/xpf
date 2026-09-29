package grpcapi

import "testing"

// The shared wipe-path redirect must restore every global it moves,
// independently. The two root-SSH paths default to values that made a
// cross-wired restore invisible, so this plants distinct sentinels and
// nests two redirects: each restore must return its own entry values.
func TestRedirectZeroizeWipePathsRestoresIndependently(t *testing.T) {
	origUserDir, origSSHDir := zeroizeRootSSHUserDir, zeroizeRootSSHDir
	t.Cleanup(func() { zeroizeRootSSHUserDir, zeroizeRootSSHDir = origUserDir, origSSHDir })
	zeroizeRootSSHUserDir = "/sentinel/userdir"
	zeroizeRootSSHDir = "/sentinel/rootssh"
	outer := t.TempDir()
	restoreOuter := RedirectZeroizeWipePathsForTesting(outer)
	if zeroizeRootSSHUserDir == "/sentinel/userdir" || zeroizeRootSSHDir == "/sentinel/rootssh" {
		t.Fatal("redirect must move both root-ssh paths")
	}
	outerUser, outerSSH := zeroizeRootSSHUserDir, zeroizeRootSSHDir
	inner := t.TempDir()
	restoreInner := RedirectZeroizeWipePathsForTesting(inner)
	restoreInner()
	if zeroizeRootSSHUserDir != outerUser || zeroizeRootSSHDir != outerSSH {
		t.Fatalf("inner restore must return outer values, got %q and %q", zeroizeRootSSHUserDir, zeroizeRootSSHDir)
	}
	restoreOuter()
	if zeroizeRootSSHUserDir != "/sentinel/userdir" || zeroizeRootSSHDir != "/sentinel/rootssh" {
		t.Fatalf("outer restore must return entry values, got %q and %q", zeroizeRootSSHUserDir, zeroizeRootSSHDir)
	}
}
