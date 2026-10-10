package configstore

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ShowCandidate returns the candidate configuration as hierarchical text.
func (s *Store) ShowCandidate() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.Format()
	}
	return ""
}

// ShowCandidatePath returns the candidate configuration subtree at the given path.
func (s *Store) ShowCandidatePath(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPath(path)
	}
	return ""
}

// ShowActive returns the active configuration as hierarchical text.
func (s *Store) ShowActive() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Format()
}

// ShowActivePath returns the active configuration subtree at the given path.
func (s *Store) ShowActivePath(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPath(path)
}

// ShowCandidateSet returns the candidate configuration as flat set commands.
func (s *Store) ShowCandidateSet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatSet()
	}
	return ""
}

// ActiveConfig returns the compiled active configuration.
func (s *Store) ActiveConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.compiled
}

// ActiveConfigAndText returns the compiled active config, its hierarchical
// text, and its publication generation under one read lock. The three values
// therefore describe the same active promotion.
func (s *Store) ActiveConfigAndText() (*config.Config, string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var gen uint64
	if snap := s.activeSnap.Load(); snap != nil {
		gen = snap.gen
	}
	if s.compiled == nil {
		return nil, "", gen
	}
	return s.compiled, s.active.Format(), gen
}

// CompileCandidate strictly compiles the current candidate WITHOUT mutating
// any store state (no promote, no persist, no confirm-timer). It is the
// read-only pre-commit hook the daemon's #1956 device-map commit pre-flight
// uses to resolve the proposed map against live hardware BEFORE the store
// promotes it — so a map that would strand management on next boot is
// rejected while the operator is still connected, not at the next reboot.
// Returns the same compiled config Commit() would, or the commit-check error.
func (s *Store) CompileCandidate() (*config.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}
	return s.compileTree(s.candidate)
}

// EverCommitted reports the #1922 step-0 marker: true once a config has
// been successfully committed or synced to this store, or loaded from a
// committed/legacy DB (migration rule C3 defaults a marker-less DB to
// committed). It is false on a fresh store and after the Item 1b
// first-commit rollback persists the never-committed marker. The daemon's
// five-case boot predicate reads it to disambiguate operator-committed-empty
// (normal) from never-committed (bootstrap) when the active config is empty.
func (s *Store) EverCommitted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.everCommitted
}

// ActiveTree returns a deep copy of the active configuration tree.
func (s *Store) ActiveTree() *config.ConfigTree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return nil
	}
	return s.active.Clone()
}

// ExportJSON exports the active config as JSON (for debugging).
func (s *Store) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s.compiled, "", "  ")
}

// ShowActiveSet returns the active configuration as flat set commands.
func (s *Store) ShowActiveSet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatSet()
}

// ShowActivePathSet returns an active config subtree as flat set commands.
func (s *Store) ShowActivePathSet(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathSet(path)
}

// ShowCandidatePathSet returns a candidate config subtree as flat set commands.
func (s *Store) ShowCandidatePathSet(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathSet(path)
	}
	return ""
}

// ShowActiveJSON returns the active configuration as JSON.
func (s *Store) ShowActiveJSON() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatJSON()
}

// ShowActivePathJSON returns an active config subtree as JSON.
func (s *Store) ShowActivePathJSON(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathJSON(path)
}

// ShowCandidateJSON returns the candidate configuration as JSON.
func (s *Store) ShowCandidateJSON() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatJSON()
	}
	return "{}\n"
}

// ShowCandidatePathJSON returns a candidate config subtree as JSON.
func (s *Store) ShowCandidatePathJSON(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathJSON(path)
	}
	return ""
}

// ShowActiveXML returns the active configuration as XML.
func (s *Store) ShowActiveXML() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatXML()
}

// ShowActivePathXML returns an active config subtree as XML.
func (s *Store) ShowActivePathXML(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathXML(path)
}

// ShowCandidateXML returns the candidate configuration as XML.
func (s *Store) ShowCandidateXML() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatXML()
	}
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n</configuration>\n"
}

// ShowCandidatePathXML returns a candidate config subtree as XML.
func (s *Store) ShowCandidatePathXML(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathXML(path)
	}
	return ""
}

// ShowCandidateInheritance returns the candidate with groups expanded and
// annotated with "## inherited from" comments.
func (s *Store) ShowCandidateInheritance() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatInheritance()
	}
	return ""
}

// ShowCandidatePathInheritance returns a subtree with inheritance annotations.
func (s *Store) ShowCandidatePathInheritance(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathInheritance(path)
	}
	return ""
}

// ShowActiveInheritance returns the active config with inheritance annotations.
func (s *Store) ShowActiveInheritance() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatInheritance()
}

// ShowActivePathInheritance returns an active config subtree with inheritance annotations.
func (s *Store) ShowActivePathInheritance(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathInheritance(path)
}

// ShowRollback returns the content of rollback slot n (1-based) as hierarchical text.
func (s *Store) ShowRollback(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.rollbackEntry(n)
	if err != nil {
		return "", err
	}
	return entry.Config.Format(), nil
}

// ShowRollbackSet returns the content of rollback slot n (1-based) as flat set commands.
func (s *Store) ShowRollbackSet(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.rollbackEntry(n)
	if err != nil {
		return "", err
	}
	return entry.Config.FormatSet(), nil
}

// ShowCompareRollback returns a diff between rollback slot n and the candidate.
func (s *Store) ShowCompareRollback(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return "", fmt.Errorf("not in configuration mode")
	}

	entry, err := s.rollbackEntry(n)
	if err != nil {
		return "", err
	}

	diff := config.FormatCompare(entry.Config, s.candidate)
	if diff == "" {
		return "[no changes]\n", nil
	}
	return diff, nil
}

// ShowCompare returns a hierarchical diff between the active and candidate
// configurations in Junos [edit] context format.
func (s *Store) ShowCompare() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	diff := config.FormatCompare(s.active, s.candidate)
	if diff == "" {
		return "[no changes]\n"
	}
	return diff
}

// --- Redacted display renderers (#4051) ---------------------------------
//
// The raw-AST render endpoints (REST config show / export / search /
// rollback + gRPC ShowConfig / ShowCompare / ShowRollback) must not leak
// operator secrets in cleartext the way the typed-struct /config JSON stopped
// leaking them in #2053. These variants render a RedactedClone of the source
// tree — secrets masked with config.SecretDataPlaceholder — so all AST-render
// display formats (text/set/json/xml/inheritance/compare) are redacted at one
// place. The cleartext Show* siblings above stay unchanged: they back HA
// config sync (daemon_ha_sync.go), the DR/compliance archive (daemon_flow.go),
// persistence + rollback, and the on-box CLI, none of which may lose the real
// secret. Each redacted method mirrors its cleartext sibling's nil-source
// default so behaviour is identical except for the masking, and each accepts a
// path (nil/empty selects the whole tree, matching FormatPath(nil) == Format).

// forDisplay returns a redacted deep clone of t, or nil if t is nil.
func forDisplay(t *config.ConfigTree) *config.ConfigTree {
	return t.RedactedClone()
}

// ShowActiveRedacted renders the active config (optional subtree) as
// hierarchical text with secrets masked.
func (s *Store) ShowActiveRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return forDisplay(s.active).FormatPath(path)
}

// ShowActiveSetRedacted renders the active config (optional subtree) as flat
// set commands with secrets masked.
func (s *Store) ShowActiveSetRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return forDisplay(s.active).FormatPathSet(path)
}

// ShowActiveJSONRedacted renders the active config (optional subtree) as JSON
// with secrets masked.
func (s *Store) ShowActiveJSONRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return forDisplay(s.active).FormatPathJSON(path)
}

// ShowActiveXMLRedacted renders the active config (optional subtree) as XML
// with secrets masked.
func (s *Store) ShowActiveXMLRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return forDisplay(s.active).FormatPathXML(path)
}

// ShowActiveInheritanceRedacted renders the active config (optional subtree)
// with inheritance annotations and secrets masked.
func (s *Store) ShowActiveInheritanceRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return forDisplay(s.active).FormatPathInheritance(path)
}

// ShowCandidateRedacted renders the candidate config (optional subtree) as
// hierarchical text with secrets masked.
func (s *Store) ShowCandidateRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	return forDisplay(s.candidate).FormatPath(path)
}

// ShowCandidateSetRedacted renders the candidate config (optional subtree) as
// flat set commands with secrets masked.
func (s *Store) ShowCandidateSetRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	return forDisplay(s.candidate).FormatPathSet(path)
}

// ShowCandidateJSONRedacted renders the candidate config (optional subtree) as
// JSON with secrets masked. Mirrors the split nil default: "{}\n" for the
// whole tree, "" for a subtree path.
func (s *Store) ShowCandidateJSONRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		if len(path) == 0 {
			return "{}\n"
		}
		return ""
	}
	return forDisplay(s.candidate).FormatPathJSON(path)
}

// ShowCandidateXMLRedacted renders the candidate config (optional subtree) as
// XML with secrets masked. Mirrors the split nil default: the empty-config XML
// document for the whole tree, "" for a subtree path.
func (s *Store) ShowCandidateXMLRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		if len(path) == 0 {
			return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n</configuration>\n"
		}
		return ""
	}
	return forDisplay(s.candidate).FormatPathXML(path)
}

// ShowCandidateInheritanceRedacted renders the candidate config (optional
// subtree) with inheritance annotations and secrets masked.
func (s *Store) ShowCandidateInheritanceRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	return forDisplay(s.candidate).FormatPathInheritance(path)
}

// ShowRollbackRedacted renders rollback slot n (1-based) as hierarchical text
// with secrets masked.
func (s *Store) ShowRollbackRedacted(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, err := s.rollbackEntry(n)
	if err != nil {
		return "", err
	}
	return forDisplay(entry.Config).Format(), nil
}

// ShowRollbackSetRedacted renders rollback slot n (1-based) as flat set
// commands with secrets masked.
func (s *Store) ShowRollbackSetRedacted(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, err := s.rollbackEntry(n)
	if err != nil {
		return "", err
	}
	return forDisplay(entry.Config).FormatSet(), nil
}

// ShowCompareRedacted returns a hierarchical diff with secret values constant-
// masked on both arms. Separate adjacent 8-hex SHA-256 fingerprint metadata
// shows secret changes without placing a fingerprint in the config value.
// Credential-bearing URLs retain RedactURL's safe context while fingerprinting
// only the components RedactURL hides.
func (s *Store) ShowCompareRedacted() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	diff := config.FormatCompareRedacted(s.active, s.candidate)
	if diff == "" {
		return "[no changes]\n"
	}
	return diff
}

// ShowCompareRollbackRedacted returns a diff between rollback slot n and the
// candidate with secrets masked on both sides.
func (s *Store) ShowCompareRollbackRedacted(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return "", fmt.Errorf("not in configuration mode")
	}
	entry, err := s.rollbackEntry(n)
	if err != nil {
		return "", err
	}
	diff := config.FormatCompare(forDisplay(entry.Config), forDisplay(s.candidate))
	if diff == "" {
		return "[no changes]\n", nil
	}
	return diff, nil
}

// splitLines splits a string into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
