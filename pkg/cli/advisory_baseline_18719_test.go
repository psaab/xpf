package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestDelayedCLIApplyErrorDoesNotInvalidateLaterFabricBaseline18719(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"set chassis cluster fabric-interface fab0",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	applyPaused := make(chan struct{})
	releaseApply := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseApply) }) }
	defer release()
	var callsMu sync.Mutex
	calls := 0
	applyErr := errors.New("injected apply failure")
	c := &CLI{store: store}
	c.commitFn = func(context.Context, string) (*config.Config, error) {
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		compiled, err := store.Commit()
		if err != nil {
			return nil, err
		}
		if call == 1 {
			// Model the daemon-owned invalidation before its callback returns;
			// the handler must not invalidate again after a later commit.
			store.InvalidateScopedAdvisoryBaseline()
			close(applyPaused)
			<-releaseApply
			return compiled, applyErr
		}
		return compiled, nil
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- c.handleCommit(nil) }()
	select {
	case <-applyPaused:
	case <-time.After(5 * time.Second):
		t.Fatal("first promoted apply did not pause before returning")
	}
	if _, err := store.LoadSet("set system host-name later-success"); err != nil {
		t.Fatalf("stage later successful change: %v", err)
	}
	var secondErr error
	secondOutput := captureStdout(t, func() { secondErr = c.handleCommit(nil) })
	if secondErr != nil {
		t.Fatalf("later successful commit: %v", secondErr)
	}
	if !strings.Contains(secondOutput, "fabric zone stamp (#10105)") {
		t.Fatalf("later successful commit did not present the reopened reminder: %q", secondOutput)
	}
	release()
	if firstErr := <-firstDone; firstErr == nil || !strings.Contains(firstErr.Error(), "injected apply failure") {
		t.Fatalf("delayed first handler error = %v, want injected apply failure", firstErr)
	}

	if _, err := store.LoadSet("set system host-name after-delayed-error"); err != nil {
		t.Fatalf("stage third operator change: %v", err)
	}
	var thirdErr error
	thirdOutput := captureStdout(t, func() { thirdErr = c.handleCommit(nil) })
	if thirdErr != nil {
		t.Fatalf("third commit: %v", thirdErr)
	}
	if strings.Contains(thirdOutput, "fabric zone stamp (#10105)") {
		t.Fatalf("late apply-error handler invalidated the later successful baseline: %q", thirdOutput)
	}
}
