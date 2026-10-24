package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// refreshShell16071 is a userClassSetter + refresher-wire double that
// behaves like *cli.CLI: SetUserClass records, and the wired refresher
// is captured for the test to invoke as dispatch would.
type refreshShell16071 struct {
	calls     []string
	refresher func()
}

func (s *refreshShell16071) SetUserClass(class string) { s.calls = append(s.calls, class) }
func (s *refreshShell16071) SetRefreshUserClassFn(fn func()) {
	s.refresher = fn
}

// TestConsoleClassRefresher16071 is the decisive regression check for
// #16071: change a console user's class in config and apply → the
// console must enforce the new class without a daemon restart.
//
// It drives the production refresher (consoleClassRefresher) through
// the same sequence daemon_run.go performs: startup resolution from
// the initial active config, then refresher invocations (as dispatch
// does per command) against successive active configs.
//
// FAIL-ON-REVERT: revert to startup-only resolution (no refresher, or
// a refresher that never re-resolves) and the "revoked"/"re-classed"/
// "first stanza" rows keep the stale startup class and fail.
func TestConsoleClassRefresher16071(t *testing.T) {
	bob := osident.Identity{UID: 1001, Name: "bob"}

	startup := cfgWithLogin([2]string{"bob", "super-user"})
	revoked := cfgWithLogin([2]string{"alice", "super-user"}) // bob removed
	reclassed := cfgWithLogin([2]string{"bob", "read-only"})
	noLogin := &config.Config{}
	withLogin := cfgWithLogin([2]string{"bob", "read-only"})
	dropped := &config.Config{}
	dropped.System.LoginDroppedByPacking = true

	tests := []struct {
		name      string
		initial   *config.Config
		next      *config.Config
		wantCalls []string // SetUserClass calls after startup + one refresh
	}{
		{
			name:      "revoked user loses super-user without restart",
			initial:   startup,
			next:      revoked,
			wantCalls: []string{"super-user", cli.ClassUnidentified},
		},
		{
			name:      "re-classed user gets the new class without restart",
			initial:   startup,
			next:      reclassed,
			wantCalls: []string{"super-user", "read-only"},
		},
		{
			name:      "first login stanza appearing resolves the assignment",
			initial:   noLogin,
			next:      withLogin,
			wantCalls: []string{"read-only"},
		},
		{
			name:      "login stanza removed returns to unset legacy mode",
			initial:   withLogin,
			next:      noLogin,
			wantCalls: []string{"read-only", ""},
		},
		{
			name:      "dropped-by-packing stanza fails closed on refresh",
			initial:   noLogin,
			next:      dropped,
			wantCalls: []string{cli.ClassUnidentified},
		},
		{
			name:      "unrelated apply does not re-resolve or re-log",
			initial:   startup,
			next:      cfgWithLogin([2]string{"bob", "super-user"}),
			wantCalls: []string{"super-user"},
		},
		{
			name:      "no login stanza at startup or after: class never set",
			initial:   noLogin,
			next:      &config.Config{},
			wantCalls: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active := tt.initial
			shell := &refreshShell16071{}
			// Startup resolution, exactly as daemon_run.go does.
			applyCLILoginClass(shell, active, bob)
			refresh := consoleClassRefresher(shell, func() *config.Config { return active }, bob, active)
			// A refresh against the unchanged config must be a no-op.
			refresh()
			// Config apply: the active config changes generation.
			active = tt.next
			refresh()
			// A second refresh with no further change must also be a no-op.
			refresh()

			if len(shell.calls) != len(tt.wantCalls) {
				t.Fatalf("SetUserClass calls = %v, want %v (#16071: stale console class)", shell.calls, tt.wantCalls)
			}
			for i, want := range tt.wantCalls {
				if shell.calls[i] != want {
					t.Fatalf("SetUserClass call %d = %q, want %q (all calls %v)", i, shell.calls[i], want, shell.calls)
				}
			}
		})
	}
}

// TestConsoleClassRefresherNilActive16071: a nil active config during
// refresh (store not yet populated) must not panic or set a class.
func TestConsoleClassRefresherNilActive16071(t *testing.T) {
	shell := &refreshShell16071{}
	refresh := consoleClassRefresher(shell, func() *config.Config { return nil }, osident.Identity{UID: 1001, Name: "bob"}, nil)
	refresh()
	if len(shell.calls) != 0 {
		t.Fatalf("SetUserClass calls = %v, want none for nil active config", shell.calls)
	}
}

// TestConsoleClassRefresherSeedIsResolvedConfig16071 pins the startup
// race the #16391 fold closes: the shell is resolved from generation
// A, but by the time the refresher is constructed the active config
// is already generation B (a commit landed between the two reads in
// daemon_run.go). Seeding from B would mark B already-applied and the
// stale A class would survive; seeding from the RESOLVED config (A)
// makes the first refresh re-resolve to B.
//
// FAIL-ON-REVERT: seed the refresher from `active()` (a second read)
// and this row keeps "super-user" — SetUserClass is never called with
// "read-only".
func TestConsoleClassRefresherSeedIsResolvedConfig16071(t *testing.T) {
	bob := osident.Identity{UID: 1001, Name: "bob"}
	genA := cfgWithLogin([2]string{"bob", "super-user"})
	genB := cfgWithLogin([2]string{"bob", "read-only"})

	shell := &refreshShell16071{}
	// Startup: shell resolved from genA (the single daemon_run read).
	applyCLILoginClass(shell, genA, bob)
	// Active has already moved to genB when the refresher is built.
	active := genB
	refresh := consoleClassRefresher(shell, func() *config.Config { return active }, bob, genA)
	refresh()
	want := []string{"super-user", "read-only"}
	if len(shell.calls) != len(want) {
		t.Fatalf("SetUserClass calls = %v, want %v — refresher seeded from a config newer than the resolved one (#16071 startup race)", shell.calls, want)
	}
	for i, w := range want {
		if shell.calls[i] != w {
			t.Fatalf("SetUserClass call %d = %q, want %q (all calls %v)", i, shell.calls[i], w, shell.calls)
		}
	}
}
