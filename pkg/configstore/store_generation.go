package configstore

import "github.com/psaab/xpf/pkg/config"

// ActiveDigestFor returns ActiveDigest() when cfg IS the store's compiled active config,
// and "" otherwise (#9641). The identity check and the digest are read under one lock,
// so a concurrent promotion cannot pair cfg with another tree's digest. The IPsec apply
// names charon's generation marker with it, and a wrong name would point HA attribution
// at a generation charon never ran.
func (s *Store) ActiveDigestFor(cfg *config.Config) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cfg == nil || s.active == nil || s.compiled != cfg {
		return ""
	}
	return configTextDigest(s.active.Format())
}

// RetainedGeneration returns the compiled config of the generation whose digest (the
// ActiveDigest function over its tree) is digest, looked up among the trees this node
// retains: the active tree, then the rollback history, most recent first (#9641). It
// turns the generation charon's marker names back into a config after this node has
// promoted newer ones, or restarted: rollback history is reloaded from disk at boot.
//
// A history tree is recompiled from a copy, after Load's retired-syntax rewrite, with the
// tolerant compiler Load and SyncApply use, because every retained tree was accepted once
// already, possibly by an older xpf. ok is false when no retained tree matches or the
// match no longer compiles.
//
// A miss formats every retained tree, so it is for rare callers (an HA re-initiation
// pass), not a hot path.
func (s *Store) RetainedGeneration(digest string) (*config.Config, bool) {
	if digest == "" {
		return nil, false
	}
	s.mu.RLock()
	if s.active != nil && s.compiled != nil && configTextDigest(s.active.Format()) == digest {
		cfg := s.compiled
		s.mu.RUnlock()
		return cfg, true
	}
	entries := s.history.List()
	s.mu.RUnlock()

	// History trees are never mutated once pushed (ListHistory hands them out without a
	// lock), so they are formatted without holding s.mu.
	for _, e := range entries {
		if e == nil || e.Config == nil || configTextDigest(e.Config.Format()) != digest {
			continue
		}
		tree := e.Config.Clone()
		// A slot read from disk skipped Load's preprocessing, and a newer xpf may have
		// retired syntax the slot still carries (Codex review of #9641). Apply Load's
		// retired-dataplane rewrite to the copy; control characters are already tolerated
		// by the lenient compiler (#1798). The digest was matched on the original above.
		rewriteRetiredDataplaneType(tree, LoadCaller)
		// compileTreeLenient reads the node identity, which SetNodeID writes under s.mu.
		s.mu.RLock()
		cfg, err := s.compileTreeLenient(tree)
		s.mu.RUnlock()
		if err != nil || cfg == nil {
			return nil, false
		}
		return cfg, true
	}
	return nil, false
}
