package cli

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #9013: the console wraps a wipe failure with %w before returning
// ("zeroize: factory reset did not fully complete: %w"). A caller that needs to
// tell "the secrets are still on disk, at THESE paths" apart from "the erasure
// failed" must still be able to reach the typed error through that wrapping —
// otherwise the operator gets a generic failure and never learns which paths
// survived.
//
// The success string is guarded structurally rather than by capturing stdout:
// handleRequestSystem returns on a non-nil performConsoleZeroize error BEFORE
// the fmt.Println("System zeroized. Configuration erased."), so a non-nil
// return IS the contract. #5890 already pins that an errored wipe does not stop
// the daemon; this pins that the #9013 detail survives to the operator.
func TestConsoleZeroizeSurfacesSymlinkSkip9013(t *testing.T) {
	c := consoleZeroizeStore(t)

	symErr := &configstore.FactoryResetSymlinkError{
		Skipped: []configstore.SymlinkedTarget{
			{Path: "/etc/xpf/.configdb", Target: "/mnt/big/configdb"},
		},
	}

	var stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { return symErr }
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	err := c.performConsoleZeroize()
	if err == nil {
		t.Fatal("console zeroize returned nil for a wipe that SKIPPED a symlinked target; " +
			"the caller would print \"System zeroized. Configuration erased.\"")
	}

	var got *configstore.FactoryResetSymlinkError
	if !errors.As(err, &got) {
		t.Fatalf("the symlink skip did not survive the console's %%w wrapping; the operator "+
			"cannot learn WHICH paths still hold secrets: %v", err)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Target != "/mnt/big/configdb" {
		t.Fatalf("skipped-path detail lost through the console: %+v", got.Skipped)
	}
	if stopped {
		t.Fatal("console zeroize stopped the daemon despite an incomplete wipe (it would " +
			"reboot into a reset that left secrets on disk)")
	}
}
