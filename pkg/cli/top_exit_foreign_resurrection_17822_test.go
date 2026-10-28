package cli

import (
	"strings"
	"testing"
)

// #17822: restoring top/up state is valid only while the calling local
// CLI session still owns the configuration lock. The Store edit cursor
// is global, so testing only one holder misses a handoff that can occur
// after the inner exit releases the lock and before the wrapper restores.
// These cells split those two legs deterministically and exercise the
// exact restore helper used by dispatchTopUp15082.
func TestLocalTopExitRestoreDoesNotResurrectIntoForeignSession17822(t *testing.T) {
	store := topUpStore15082(t)
	local := cliTopUp15082(t, store)
	local.setConfigOwned(true)

	stale := []string{"routing-instances", "RI1"}
	store.SetEditPath(stale)
	// Inner top-level `exit` releases this local session and clears its
	// cursor; a gRPC/REST session then enters at the root before the
	// outer top/up wrapper reaches its restore leg.
	if !store.ExitConfigureSession(localConfigSessionID) {
		t.Fatal("local session failed to release its own configuration lock (#17822)")
	}
	local.setConfigOwned(false)
	if got := store.GetEditPath(); len(got) != 0 {
		t.Fatalf("local exit left cursor %v (#17822)", got)
	}
	if err := store.EnterConfigureSession("grpc-peer-1"); err != nil {
		t.Fatalf("foreign EnterConfigureSession: %v (#17822)", err)
	}

	// On origin/master this helper is the former global-mode guard. It
	// restores `stale` because the foreign session made InConfigMode true.
	local.restoreTopUpCursor(stale)
	if holder, locked := store.ConfigHolder(); !locked || holder != "grpc-peer-1" {
		t.Fatalf("foreign holder = %q/%v, want grpc-peer-1/true (#17822)", holder, locked)
	}
	if got := store.GetEditPath(); len(got) != 0 {
		t.Fatalf("local top-exit resurrected %v into foreign session (#17822)", got)
	}
}

func TestForeignTopExitRestoreDoesNotResurrectIntoLocalSession17822(t *testing.T) {
	store := topUpStore15082(t)
	if !store.ExitConfigureSession(localConfigSessionID) {
		t.Fatal("local session failed to release setup lock (#17822 vice-versa)")
	}
	if err := store.EnterConfigureSession("grpc-peer-2"); err != nil {
		t.Fatalf("foreign EnterConfigureSession: %v (#17822 vice-versa)", err)
	}
	foreignStale := []string{"security", "policies"}
	store.SetEditPath(foreignStale)
	if !store.ExitConfigureSession("grpc-peer-2") {
		t.Fatal("foreign session failed to release its own configuration lock (#17822 vice-versa)")
	}
	if err := store.EnterConfigureSession(localConfigSessionID); err != nil {
		t.Fatalf("local EnterConfigureSession: %v (#17822 vice-versa)", err)
	}
	localCursor := []string{"interfaces", "ge-0/0/0"}
	store.SetEditPath(localCursor)

	// A foreign session's delayed restore is refused after ownership has
	// changed back to local. This is the symmetric session-identity
	// control for the same restore primitive used by the local CLI.
	if store.SetEditPathForSession("grpc-peer-2", foreignStale) {
		t.Fatal("foreign restore unexpectedly wrote into local session (#17822 vice-versa)")
	}
	if got := store.GetEditPath(); strings.Join(got, "\x00") != strings.Join(localCursor, "\x00") {
		t.Fatalf("foreign restore changed local cursor to %v, want %v (#17822 vice-versa)", got, localCursor)
	}
}

func TestTopExitRestoreStillWorksForOwnSession17822(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	c.setConfigOwned(true)
	want := []string{"security", "policies"}
	c.restoreTopUpCursor(want)
	if got := store.GetEditPath(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("own-session restore got %v, want %v (#17822 control)", got, want)
	}
}
