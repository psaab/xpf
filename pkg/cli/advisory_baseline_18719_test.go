package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCLIApplyErrorDoesNotHideFabricReminder18719(t *testing.T) {
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
	calls := 0
	c := &CLI{store: store}
	c.commitFn = func(context.Context, string) (*config.Config, error) {
		compiled, err := store.Commit()
		if err != nil {
			return nil, err
		}
		calls++
		if calls == 1 {
			return compiled, errors.New("injected apply failure")
		}
		return compiled, nil
	}

	var firstErr error
	firstOutput := captureStdout(t, func() { firstErr = c.handleCommit(nil) })
	if firstErr == nil || !strings.Contains(firstErr.Error(), "injected apply failure") {
		t.Fatalf("first commit error = %v, want injected apply failure", firstErr)
	}
	if strings.Contains(firstOutput, "fabric zone stamp (#10105)") {
		t.Fatalf("failed local apply unexpectedly printed a commit warning: %q", firstOutput)
	}
	if _, err := store.LoadSet("set system host-name after-apply-error"); err != nil {
		t.Fatalf("stage unrelated operator change: %v", err)
	}

	var secondErr error
	secondOutput := captureStdout(t, func() { secondErr = c.handleCommit(nil) })
	if secondErr != nil {
		t.Fatalf("retry commit: %v", secondErr)
	}
	if !strings.Contains(secondOutput, "fabric zone stamp (#10105)") {
		t.Fatalf("next operator commit hid the reminder not printed after apply error: %q", secondOutput)
	}
}
