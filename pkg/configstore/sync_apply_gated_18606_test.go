package configstore

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18606: SyncApplyGated's gate sees the compiled peer config BEFORE anything
// is promoted, and a refusing gate leaves the store exactly as it was — the
// property the daemon's synced-path control-address refusal depends on (a
// refused text that still became active would be applied by every background
// applier). FAIL-ON-REVERT: run the gate after promotion and the active-text
// and history assertions red.
func TestSyncApplyGatedRefusalPromotesNothing18606(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name before; }\n", nil); err != nil {
		t.Fatalf("seed SyncApply: %v", err)
	}
	beforeText := s.ActiveTree().Format()
	beforeHistory := len(s.history.entries)
	refused := errors.New("refused by the gate")
	var seen *config.Config
	_, err := s.SyncApplyGated("system { host-name after; }\n", nil, func(c *config.Config) error {
		seen = c
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("SyncApplyGated = %v, want the gate's error unchanged", err)
	}
	if seen == nil || seen.System.HostName != "after" {
		t.Fatalf("the gate did not see the compiled peer config (got %+v)", seen)
	}
	if got := s.ActiveTree().Format(); got != beforeText {
		t.Fatalf("a refusing gate changed the active config:\n%s", got)
	}
	if got := len(s.history.entries); got != beforeHistory {
		t.Fatalf("a refusing gate pushed rollback history: %d -> %d entries", beforeHistory, got)
	}
	// A passing gate behaves exactly like SyncApply.
	if _, err := s.SyncApplyGated("system { host-name after; }\n", nil, func(*config.Config) error { return nil }); err != nil {
		t.Fatalf("SyncApplyGated with a passing gate: %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "after" {
		t.Fatalf("a passing gate did not promote: host-name %q", got)
	}
}
