package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

// #14152 sub-1: console reboot/halt/power-off/zeroize must journal BEFORE acting,
// like gRPC logSystemAction (#4108). Power action is stubbed; journal must exist.
func TestConsolePowerActionsJournalBeforeActing14152(t *testing.T) {
	for _, tc := range []struct{ verb, want string }{
		{"reboot", "reboot"}, {"halt", "halt"}, {"power-off", "power-off"},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "xpf.conf")
			store := newConfigStore(t, cfgPath)
			var acted string
			orig := consolePowerAction
			t.Cleanup(func() { consolePowerAction = orig })
			journalAtAct := ""
			consolePowerAction = func(arg string) error {
				acted = arg
				b, _ := os.ReadFile(filepath.Join(dir, ".config.journal"))
				journalAtAct = string(b)
				return nil
			}
			reader := &scriptedReader{lines: []string{"yes"}}
			c := &CLI{store: store, username: "alice", userClass: "super-user", readLineFn: reader.read}
			captureStdout(t, func() {
				if err := c.handleRequestSystem([]string{tc.verb}); err != nil {
					t.Fatalf("handleRequestSystem %s: %v", tc.verb, err)
				}
			})
			if acted == "" {
				t.Fatalf("power action not invoked for %s", tc.verb)
			}
			if !strings.Contains(journalAtAct, "system_action") || !strings.Contains(journalAtAct, tc.want) {
				t.Fatalf("journal before power action missing %q entry: %q", tc.want, journalAtAct)
			}
			if !strings.Contains(journalAtAct, "alice") {
				t.Fatalf("journal entry not attributable: %q", journalAtAct)
			}
		})
	}
}

func TestConsoleZeroizeJournalsBeforeWipe14152(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xpf.conf")
	store := newConfigStore(t, cfgPath)
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	journalAtWipe := ""
	zeroizeFullWipe = func(string, string, string, zeroizeLogInventory, string) error {
		b, _ := os.ReadFile(filepath.Join(dir, ".config.journal"))
		journalAtWipe = string(b)
		return nil
	}
	zeroizeStopDaemon = func() error { return nil }
	reader := &scriptedReader{lines: []string{"yes"}}
	c := &CLI{store: store, username: "alice", userClass: "super-user", readLineFn: reader.read}
	captureStdout(t, func() {
		if err := c.handleRequestSystem([]string{"zeroize"}); err != nil {
			t.Fatalf("zeroize: %v", err)
		}
	})
	if !strings.Contains(journalAtWipe, "zeroize") {
		t.Fatalf("journal before wipe missing zeroize entry: %q", journalAtWipe)
	}
}

// #14152 sub-2: reason with control chars must be rejected before feedsAckFn.
func TestLocalShrinkAckRejectsControlReason14152(t *testing.T) {
	hash := strings.Repeat("a", 64)
	base := strings.Repeat("b", 64)
	called := false
	c := &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{"f": {ShrinkRefused: true, ShrinkRefusalID: 7, ShrinkCandidateHash: hash, ShrinkBaselineHash: base, ShrinkCandidateOldCount: 10, ShrinkCandidateNewCount: 2}}
		},
		feedsAckFn: func(string, uint64, string, string, int, int, string, string) error {
			called = true
			return nil
		},
	}
	for _, reason := range []string{"ok\nforged log line", "ok\revil", "ok\x7f", "ok\x1b[31m"} {
		args := []string{"acknowledge-shrink", "f", "candidate-id", "7", "candidate-hash", hash, "baseline-hash", base, "old-count", "10", "new-count", "2", "reason", reason}
		err := c.handleRequestSecurityDynamicAddress(args)
		if err == nil || !strings.Contains(err.Error(), "control") {
		}
		if called {
			t.Fatalf("reason %q reached feedsAckFn", reason)
		}
	}
}

// #14152 sub-3: local-primary RG failover to self must short-circuit, not call RequestPeerFailover.
func TestLocalRGFailoverAlreadyPrimaryShortCircuits14152(t *testing.T) {
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
	}})
	mgr.SetGroupStateForTesting(1, cluster.StatePrimary)
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("setup: not local primary")
	}
	c := &CLI{cluster: mgr}
	out := captureStdout(t, func() {
		if err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node", "0"}); err != nil {
			t.Fatalf("failover: %v", err)
		}
	})
	if !strings.Contains(out, "already primary") {
		t.Fatalf("stdout=%q want already-primary short-circuit (pre-fix returns peer-transfer error)", out)
	}
}
