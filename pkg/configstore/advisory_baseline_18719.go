package configstore

import "github.com/psaab/xpf/pkg/config"

// scopedAdvisoryBaselineLocked returns the config change-scoped reminders are
// measured against (#18719): the compiled active config, but only while the
// active tree is still the one the last operator commit in this process
// installed. Otherwise it returns nil, and DropUnchangedScopedAdvisories
// keeps every reminder. A node that booted from disk, took its config from
// the peer by config sync, or was auto-rolled back has never shown its
// operator the reminders for that config (#18751 review), so its first
// operator commit shows them once.
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
