package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/configstore"
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

type promptCaptureWriter17822 struct{ output []byte }

func (w *promptCaptureWriter17822) Write(p []byte) (int, error) {
	w.output = append(w.output, p...)
	return len(p), nil
}

func promptCLI17822(t *testing.T, store *configstore.Store) (*CLI, *promptCaptureWriter17822) {
	t.Helper()
	output := &promptCaptureWriter17822{}
	rl, err := readline.NewEx(&readline.Config{
		Stdin:               io.NopCloser(strings.NewReader("")),
		Stdout:              output,
		Stderr:              io.Discard,
		ForceUseInteractive: true,
		FuncIsTerminal:      func() bool { return true },
		FuncMakeRaw:         func() error { return nil },
		FuncExitRaw:         func() error { return nil },
	})
	if err != nil {
		t.Fatalf("readline.NewEx: %v", err)
	}
	t.Cleanup(func() { rl.Close() })
	return &CLI{store: store, rl: rl, username: "operator"}, output
}

// TestRefreshPromptStaysOperationalWithForeignHolder17822 drives the
// runOneLine/refreshPrompt path with a foreign session in config mode. The
// local CLI never acquired that session, so its prompt must stay operational.
func TestRefreshPromptStaysOperationalWithForeignHolder17822(t *testing.T) {
	store := topUpStore15082(t)
	if !store.ExitConfigureSession(localConfigSessionID) {
		t.Fatal("local session failed to release setup lock (#17822 prompt)")
	}
	if err := store.EnterConfigureSession("grpc-peer-1"); err != nil {
		t.Fatalf("foreign EnterConfigureSession: %v (#17822 prompt)", err)
	}
	c, output := promptCLI17822(t, store)
	c.setConfigOwned(false)
	c.readLineFn = func() (string, error) { return "help", nil }
	done, err := c.runOneLine()
	if err != nil || done {
		t.Fatalf("runOneLine: done=%v err=%v (#17822 prompt)", done, err)
	}
	c.rl.Operation.SetBuffer("")
	paintedPrompt := string(output.output)
	if !strings.Contains(paintedPrompt, c.operationalPrompt()) {
		t.Fatalf("foreign holder painted %q, want operational prompt %q (#17822 prompt)", paintedPrompt, c.operationalPrompt())
	}
	if strings.Contains(paintedPrompt, c.configPrompt()) {
		t.Fatalf("foreign holder painted local config prompt %q: %q (#17822 prompt)", c.configPrompt(), paintedPrompt)
	}
}

// TestRefreshPromptOwnSessionControl17822 verifies the local holder still
// receives its config prompt through the same runOneLine/refreshPrompt path.
func TestRefreshPromptOwnSessionControl17822(t *testing.T) {
	store := topUpStore15082(t)
	c, output := promptCLI17822(t, store)
	c.setConfigOwned(true)
	c.readLineFn = func() (string, error) { return "help", nil }
	done, err := c.runOneLine()
	if err != nil || done {
		t.Fatalf("runOneLine: done=%v err=%v (#17822 control)", done, err)
	}
	c.rl.Operation.SetBuffer("")
	paintedPrompt := string(output.output)
	if !strings.Contains(paintedPrompt, c.configPrompt()) {
		t.Fatalf("own config holder painted %q, want config prompt %q (#17822 control)", paintedPrompt, c.configPrompt())
	}
}
