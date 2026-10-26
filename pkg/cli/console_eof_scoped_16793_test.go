package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// #16793 (R3-A53-05): the in-process console's Ctrl-D (io.EOF) and
// double Ctrl-C paths called the UNSCOPED store.ExitConfigure() on
// the store-GLOBAL InConfigMode() flag. The single configstore.Store
// is shared by every surface, so a console Ctrl-D while a gRPC peer
// (grpc-peer-1) held the config lock discarded that peer's candidate,
// freed its lock, printed a false "Exiting configuration mode", and
// #14986 gated dispatch on configOwned; these exit paths now share
// session-scoped cleanup.
//
// TestConsoleEOFArmPreservesForeignHolder17838 and the own-session control
// drive runOneLine, the exact per-iteration body Run executes, through its
// readLineFn seam. Run itself creates readline on os.Stdin, so it cannot be
// entered in a test without TTY/history side effects. The fixture keeps rl nil
// because all tested EOF paths are nil-safe and do not need readline.
//
// Run's double-interrupt loop is extracted into handleConsoleInterrupts,
// the exact method started by Run. TestConsoleDoubleInterruptArm17838 feeds
// that method synthetic SIGINTs rather than sending process-wide signals.

func consoleStore16793(t *testing.T, holder string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	// Seed + commit an ACTIVE config so a discarded candidate is
	// observable (host-name the peer stages below).
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(seed): %v", err)
	}
	if err := store.LoadMerge("system {\n    host-name base-16793;\n}\n"); err != nil {
		t.Fatalf("LoadMerge(seed): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(seed): %v", err)
	}
	store.ExitConfigure()
	if holder == "" {
		return store
	}
	if err := store.EnterConfigureSession(holder); err != nil {
		t.Fatalf("EnterConfigureSession(%q): %v", holder, err)
	}
	// The holder stages a candidate change that must survive.
	if err := store.LoadMergeAs(holder, "system {\n    host-name staged-peer;\n}\n"); err != nil {
		t.Fatalf("stage peer candidate: %v", err)
	}
	return store
}

func consoleCLI16793(t *testing.T, store *configstore.Store, owned bool) *CLI {
	t.Helper()
	c := &CLI{
		store: store,
		readLineFn: func() (string, error) {
			return "", io.EOF
		},
	}
	c.setConfigOwned(owned)
	return c
}

func TestConsoleEOFPreservesForeignHolder16793(t *testing.T) {
	store := consoleStore16793(t, "grpc-peer-1")
	// Console did NOT enter configure itself.
	c := consoleCLI16793(t, store, false)

	stay := false
	out := captureStdout(t, func() { stay = c.handleConsoleEOF() })
	if stay {
		t.Fatalf("EOF with foreign holder stayed in loop; want console exit (#16793)")
	}
	if strings.Contains(out, "Exiting configuration mode") {
		t.Fatalf("EOF printed false exit banner for foreign holder: %q (#16793)", out)
	}
	holder, locked := store.ConfigHolder()
	if !locked || holder != "grpc-peer-1" {
		t.Fatalf("ConfigHolder = %q/%v, want grpc-peer-1/true — foreign lock released (#16793 RED pre-fix)", holder, locked)
	}
	if !store.InConfigMode() {
		t.Fatalf("store left config mode after foreign EOF (#16793)")
	}
	if got := store.ShowCandidateSet(); !strings.Contains(got, "staged-peer") {
		t.Fatalf("peer candidate discarded by console EOF: %q (#16793)", got)
	}
}

func TestConsoleEOFExitsOwnConfigMode16793(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(seed): %v", err)
	}
	if err := store.LoadMerge("system {\n    host-name base-16793;\n}\n"); err != nil {
		t.Fatalf("LoadMerge(seed): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(seed): %v", err)
	}
	store.ExitConfigure()
	// Console enters configure itself through its gated verb identity.
	if err := store.EnterConfigureSession(localConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession(local): %v", err)
	}
	c := consoleCLI16793(t, store, true)

	done := true
	var err error
	out := captureStdout(t, func() { done, err = c.runOneLine() })
	if err != nil {
		t.Fatalf("runOneLine own-session EOF: %v", err)
	}
	if done {
		t.Fatalf("EOF in own config mode exited console; want stay in loop (#16793 control)")
	}
	if !strings.Contains(out, "Exiting configuration mode") {
		t.Fatalf("own EOF missing exit banner: %q (#16793 control)", out)
	}
	if store.InConfigMode() {
		t.Fatalf("own EOF left store in config mode (#16793 control)")
	}
	if c.configOwnedNow() {
		t.Fatalf("configOwned still set after own EOF release (#16793)")
	}
	if holder, locked := store.ConfigHolder(); locked {
		t.Fatalf("lock still held by %q after own EOF (#16793)", holder)
	}
}

func TestConsoleDoubleCtrlCPreservesForeignHolder16793(t *testing.T) {
	store := consoleStore16793(t, "grpc-peer-1")
	c := consoleCLI16793(t, store, false)
	c.releaseLocalConfigureOnInterrupt()
	holder, locked := store.ConfigHolder()
	if !locked || holder != "grpc-peer-1" {
		t.Fatalf("double Ctrl-C released foreign lock: %q/%v, want grpc-peer-1/true (#16793 RED pre-fix)", holder, locked)
	}
	if got := store.ShowCandidateSet(); !strings.Contains(got, "staged-peer") {
		t.Fatalf("double Ctrl-C discarded peer candidate: %q (#16793)", got)
	}
}

func TestConsoleDoubleCtrlCReleasesOwnLock16793(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigureSession(localConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession(local): %v", err)
	}
	c := consoleCLI16793(t, store, true)
	c.releaseLocalConfigureOnInterrupt()
	if store.InConfigMode() {
		t.Fatalf("double Ctrl-C left own config mode held (#16793 control)")
	}
	if c.configOwnedNow() {
		t.Fatalf("configOwned still set after double Ctrl-C (#16793)")
	}
}

// Stale-flag defense: configOwned set but the lock was reclaimed by
// another holder — the session-scoped release must refuse and the
// console exits instead of staying or freeing the new holder.
func TestConsoleEOFStaleOwnedForeignHolder16793(t *testing.T) {
	store := consoleStore16793(t, "grpc-peer-1")
	c := consoleCLI16793(t, store, true)
	stay := c.handleConsoleEOF()
	if stay {
		t.Fatalf("stale-owned EOF stayed; want exit (#16793)")
	}
	if c.configOwnedNow() {
		t.Fatalf("stale configOwned not cleared (#16793)")
	}
	if holder, locked := store.ConfigHolder(); !locked || holder != "grpc-peer-1" {
		t.Fatalf("stale-owned EOF freed foreign lock: %q/%v (#16793)", holder, locked)
	}
}

func TestConsoleEOFArmPreservesForeignHolder17838(t *testing.T) {
	store := consoleStore16793(t, "grpc-peer-1")
	c := consoleCLI16793(t, store, false)

	done := false
	var err error
	out := captureStdout(t, func() { done, err = c.runOneLine() })
	if err != nil {
		t.Fatalf("runOneLine foreign-holder EOF: %v", err)
	}
	if holder, locked := store.ConfigHolder(); !locked || holder != "grpc-peer-1" {
		t.Fatalf("EOF arm ConfigHolder = %q/%v, want grpc-peer-1/true (#17838 RED)", holder, locked)
	}
	if got := store.ShowCandidateSet(); !strings.Contains(got, "staged-peer") {
		t.Fatalf("EOF arm discarded peer candidate: %q (#17838)", got)
	}
	if !done {
		t.Fatalf("EOF arm with foreign holder stayed in loop; want exit (#17838)")
	}
	if strings.Contains(out, "Exiting configuration mode") {
		t.Fatalf("EOF arm printed false exit banner for foreign holder: %q (#17838)", out)
	}
}

func TestConsoleDoubleInterruptArm17838(t *testing.T) {
	store := consoleStore16793(t, "grpc-peer-1")
	c := &CLI{store: store}
	sigCh := make(chan os.Signal, 2)
	exitCh := make(chan struct{})
	runDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		c.handleConsoleInterrupts(sigCh, exitCh, runDone)
		close(done)
	}()

	sigCh <- os.Interrupt
	sigCh <- os.Interrupt
	close(sigCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		close(runDone)
		t.Fatal("handleConsoleInterrupts did not finish after two SIGINTs (#17838)")
	}
	select {
	case <-exitCh:
	default:
		t.Fatal("double SIGINT did not arm CLI exit (#17838)")
	}
	if holder, locked := store.ConfigHolder(); !locked || holder != "grpc-peer-1" {
		t.Fatalf("double SIGINT arm ConfigHolder = %q/%v, want grpc-peer-1/true (#17838)", holder, locked)
	}
	if got := store.ShowCandidateSet(); !strings.Contains(got, "staged-peer") {
		t.Fatalf("double SIGINT arm discarded peer candidate: %q (#17838)", got)
	}
}

func TestConsoleConfigOwnershipAccessRace17838(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10000 {
				c.setConfigOwned(true)
				c.setConfigOwned(false)
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10000 {
				c.releaseLocalConfigureOnInterrupt()
			}
		}()
	}
	wg.Wait()
}
