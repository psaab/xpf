package configstore

import "github.com/psaab/xpf/pkg/config"

// scopedAdvisoryBaselineLocked returns the config change-scoped reminders are
// measured against (#18719): the compiled active config, but only while the
// active tree is still the one the last operator commit installed and that
// commit's reminders were shown (or there were none). Otherwise it returns nil,
// and DropUnchangedScopedAdvisories keeps every reminder. A node that booted
// from disk, took its config from peer sync, was auto-rolled back, or promoted
// without presenting its reminders (#18751 review) shows them on the next
// operator commit.
//
// Keyed on the persisted operator tree, not on s.compiled: a DNS refresh
// republishes s.compiled without changing the operator's config, and must
// not turn the reminders back into every-commit noise.
func (s *Store) scopedAdvisoryBaselineLocked() *config.Config {
	if s.advisoryBaselineTree == nil || s.advisoryBaselineTree != s.active {
		return nil
	}
	return s.compiled
}

// InvalidateScopedAdvisoryBaseline makes the next operator commit show its
// change-scoped reminders again. Use this when a commit was promoted but its
// warning block was not presented (bootstrap and apply-error paths, #18751).
func (s *Store) InvalidateScopedAdvisoryBaseline() {
	s.mu.Lock()
	s.advisoryBaselineTree = nil
	s.mu.Unlock()
}
