package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14981: the on-box CLI must apply deny-configuration to groups /
// apply-groups expansion at Set-time and at Commit.

func cliStore14981(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"system login class limited permissions [ configure view ]",
		`system login class limited deny-configuration "system root-authentication"`,
		"system host-name base14981",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("seed %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("re-enter configure: %v", err)
	}
	return s
}

func TestCLICommitGroupInheritedDenied14981(t *testing.T) {
	store := cliStore14981(t)
	for _, line := range []string{
		"groups G system root-authentication plain-text-password hunter2",
		"apply-groups G",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("seed candidate %q: %v", line, err)
		}
	}
	c := &CLI{store: store, userClass: "limited"}
	if err := c.checkExpandedConfigRegex14981(); err == nil {
		t.Fatal("CLI commit gate allowed a group-inherited denied path (#14981)")
	}
	if err := c.handleCommit(nil); err == nil {
		t.Fatal("CLI handleCommit allowed a group-inherited denied path (#14981)")
	}
}

func TestCLICommitAllowedGroup14981(t *testing.T) {
	store := cliStore14981(t)
	for _, line := range []string{
		"groups G system host-name ok14981",
		"apply-groups G",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("seed candidate %q: %v", line, err)
		}
	}
	c := &CLI{store: store, userClass: "limited"}
	if err := c.checkExpandedConfigRegex14981(); err != nil {
		t.Fatalf("CLI commit gate refused an allowed group: %v", err)
	}
}

func TestCLISetApplyGroupsDenied14981(t *testing.T) {
	store := cliStore14981(t)
	if err := store.SetFromInput("groups G system root-authentication plain-text-password hunter2"); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	c := &CLI{store: store, userClass: "limited"}
	if err := c.checkConfigRegexGroups14981("set apply-groups G"); err == nil {
		t.Fatal("CLI set apply-groups with a denied group body was ALLOWED (#14981)")
	}
}
