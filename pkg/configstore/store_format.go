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

// ShowConfigTrees returns a DEEP-COPY snapshot of the rendered tree for
// a ShowConfig target: the active tree for target "active", the
// candidate tree otherwise (mirroring ShowConfig's target switch). The
// snapshot is cloned under one store-lock acquisition, so the caller
// can price it and render it as the same generation: a concurrent
// candidate edit or commit neither races the walk (the live candidate
// is mutated in place under the store lock) nor swaps the generation
// between authorization and rendering (#15995 fold). Callers that
// authorize against these trees MUST render from the same snapshots,
// never re-resolve the target in the store (see the Render*SnapshotOn
// helpers in configstore and the snapshot-carrying call sites).
func (s *Store) ShowConfigTrees(target string) []*config.ConfigTree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var tree *config.ConfigTree
	if target == "active" {
		tree = s.active
	} else {
		tree = s.candidate
	}
	if tree == nil {
		return nil
	}
	return []*config.ConfigTree{tree.Clone()}
}

// CompareTrees returns deep-copy snapshots of both arms of a candidate
// compare: (active, candidate). Either may be nil; a nil arm renders
// nothing. Same snapshot contract as ShowConfigTrees.
func (s *Store) CompareTrees() (active, candidate *config.ConfigTree) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active != nil {
		active = s.active.Clone()
	}
	if s.candidate != nil {
		candidate = s.candidate.Clone()
	}
	return active, candidate
}

// RollbackCompareTrees returns deep-copy snapshots of both arms of a
// rollback compare: (rollback slot n, candidate) for the candidate
// baseline, or (rollback slot n, active) when activeBaseline is set
// (the operational `show system rollback compare` shape). A slot that
// cannot be resolved yields a nil first arm. Same snapshot contract as
// ShowConfigTrees.
func (s *Store) RollbackCompareTrees(n int, activeBaseline bool) (slot, other *config.ConfigTree) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return nil, nil
	}
	slot = tree.Clone()
	if activeBaseline {
		if s.active != nil {
			other = s.active.Clone()
		}
		return slot, other
	}
	if s.candidate != nil {
		other = s.candidate.Clone()
	}
	return slot, other
}

// RollbackTree returns a deep-copy snapshot of the tree a scoped
// rollback render of slot n will disclose (n == 0 is the active
// configuration), or nil when the slot cannot be resolved (the render
// then fails on its own error). Same snapshot contract as
// ShowConfigTrees: price and render this snapshot, do not re-resolve.
func (s *Store) RollbackTree(n int) *config.ConfigTree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return nil
	}
	return tree.Clone()
}

// NodeID returns the store's cluster node identity — the identity the
// inheritance renderers expand apply-groups for (negative = standalone
// node0 view). Authorization for a `display inheritance` read must
// expand with this same identity (#15995 fold).
func (s *Store) NodeID() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodeID
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

// ActiveConfigGeneration returns the canonical content identity used by
// commit-confirmed recovery to bind a durable transition to active state.
func (s *Store) ActiveConfigGeneration() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return guardedConfigHash(s.active)
}

// CandidateEqualsActive reports whether the candidate tree is identical to
// the active tree under the canonical (post-persist-round-trip) hash. It is
// the no-change gate the event engine consults before committing a
// remediation batch (#15022): a batch that restores values already active
// produces a candidate equal to active, and committing it would push an
// identical rollback-history entry and run a full apply for nothing.
// Returns false when there is no candidate (not in configuration mode).
func (s *Store) CandidateEqualsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil || s.active == nil {
		return false
	}
	return guardedConfigHash(s.candidate) == guardedConfigHash(s.active)
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
// annotated with "## inherited from" comments, resolved for this store's
// cluster node (s.nodeID, #15197). An expansion failure is returned as an
// error, never hidden behind the raw candidate.
func (s *Store) ShowCandidateInheritance() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatInheritanceForNode(s.nodeID)
	}
	return "", nil
}

// ShowCandidatePathInheritance returns a subtree with inheritance annotations.
func (s *Store) ShowCandidatePathInheritance(path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathInheritanceForNode(path, s.nodeID)
	}
	return "", nil
}

// ShowActiveInheritance returns the active config with inheritance annotations.
func (s *Store) ShowActiveInheritance() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatInheritanceForNode(s.nodeID)
}

// ShowActivePathInheritance returns an active config subtree with inheritance annotations.
func (s *Store) ShowActivePathInheritance(path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathInheritanceForNode(path, s.nodeID)
}

// ShowRollback returns the content of rollback slot n as hierarchical
// text. n is 0-based Junos-style: 0 is the active configuration,
// 1..N are history slots (#15657 V45-03).
func (s *Store) ShowRollback(n int) (string, error) {
	return s.ShowRollbackPath(n, nil)
}

// ShowRollbackPath renders rollback slot n (0 = active) at path.
func (s *Store) ShowRollbackPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPath(path), nil
}

// ShowRollbackSet returns rollback slot n (0 = active) as set commands.
func (s *Store) ShowRollbackSet(n int) (string, error) {
	return s.ShowRollbackSetPath(n, nil)
}

// ShowRollbackSetPath renders rollback slot n (0 = active) at path as set.
func (s *Store) ShowRollbackSetPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathSet(path), nil
}

// ShowRollbackJSON returns rollback slot n (0 = active) as JSON.
func (s *Store) ShowRollbackJSON(n int) (string, error) {
	return s.ShowRollbackJSONPath(n, nil)
}

// ShowRollbackJSONPath renders rollback slot n (0 = active) at path as JSON.
func (s *Store) ShowRollbackJSONPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathJSON(path), nil
}

// ShowRollbackXML returns rollback slot n (0 = active) as XML.
func (s *Store) ShowRollbackXML(n int) (string, error) {
	return s.ShowRollbackXMLPath(n, nil)
}

// ShowRollbackXMLPath renders rollback slot n (0 = active) at path as XML.
func (s *Store) ShowRollbackXMLPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathXML(path), nil
}

// ShowRollbackInheritance returns rollback slot n (0 = active) with
// inheritance annotations.
func (s *Store) ShowRollbackInheritance(n int) (string, error) {
	return s.ShowRollbackInheritancePath(n, nil)
}

// ShowRollbackInheritancePath renders rollback slot n (0 = active) at
// path with inheritance annotations.
func (s *Store) ShowRollbackInheritancePath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathInheritanceForNode(path, s.nodeID)
}

// ShowCompareRollback returns a diff between rollback slot n and the candidate.
func (s *Store) ShowCompareRollback(n int) (string, error) {
	return s.ShowCompareRollbackAtPath(n, nil)
}

// ShowCompareRollbackAtPath is ShowCompareRollback filtered to path
// (#15272 B24-03); nil/empty path is the global compare. n == 0 is the
// active configuration, so compare rollback 0 is candidate-vs-active
// and needs no history slot (still requires a candidate).
func (s *Store) ShowCompareRollbackAtPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return "", fmt.Errorf("not in configuration mode")
	}

	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}

	diff := config.FormatCompareAtPath(tree, s.candidate, path)
	if diff == "" {
		return "[no changes]\n", nil
	}
	return diff, nil
}

// ShowCompareRollbackActive returns a diff between rollback slot n
// (0 = active) and the ACTIVE configuration (#15657 V45-03). This is
// the operational-mode baseline: it never reads s.candidate and never
// requires configuration mode, so a dirty candidate from another
// session cannot change the answer.
func (s *Store) ShowCompareRollbackActive(n int) (string, error) {
	return s.ShowCompareRollbackActiveAtPath(n, nil)
}

// ShowCompareRollbackActiveAtPath is ShowCompareRollbackActive filtered
// to path; nil/empty path is the global compare.
func (s *Store) ShowCompareRollbackActiveAtPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	diff := config.FormatCompareAtPath(tree, s.active, path)
	if diff == "" {
		return "[no changes]\n", nil
	}
	return diff, nil
}

// ShowCompare returns a hierarchical diff between the active and candidate
// configurations in Junos [edit] context format.
func (s *Store) ShowCompare() string {
	return s.ShowCompareAtPath(nil)
}

// ShowCompareAtPath is ShowCompare filtered to the subtree at path
// (#15272 B24-03); nil/empty path is the global compare.
func (s *Store) ShowCompareAtPath(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	diff := config.FormatCompareAtPath(s.active, s.candidate, path)
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
	return s.active.FormatPathRedacted(path)
}

// ShowActiveSetRedacted renders the active config (optional subtree) as flat
// set commands with secrets masked.
func (s *Store) ShowActiveSetRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathSetRedacted(path)
}

// ShowActiveJSONRedacted renders the active config (optional subtree) as JSON
// with secrets masked.
func (s *Store) ShowActiveJSONRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathJSONRedacted(path)
}

// ShowActiveXMLRedacted renders the active config (optional subtree) as XML
// with secrets masked.
func (s *Store) ShowActiveXMLRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathXMLRedacted(path)
}

// ShowActiveInheritanceRedacted renders the active config (optional subtree)
// with inheritance annotations and secrets masked.
func (s *Store) ShowActiveInheritanceRedacted(path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathInheritanceRedactedForNode(path, s.nodeID)
}

// ShowCandidateRedacted renders the candidate config (optional subtree) as
// hierarchical text with secrets masked.
func (s *Store) ShowCandidateRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	return s.candidate.FormatPathRedacted(path)
}

// ShowCandidateSetRedacted renders the candidate config (optional subtree) as
// flat set commands with secrets masked.
func (s *Store) ShowCandidateSetRedacted(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	return s.candidate.FormatPathSetRedacted(path)
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
	return s.candidate.FormatPathJSONRedacted(path)
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
	return s.candidate.FormatPathXMLRedacted(path)
}

// ShowCandidateInheritanceRedacted renders the candidate config (optional
// subtree) with inheritance annotations and secrets masked.
func (s *Store) ShowCandidateInheritanceRedacted(path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return "", nil
	}
	return s.candidate.FormatPathInheritanceRedactedForNode(path, s.nodeID)
}

// ShowRollbackRedacted renders rollback slot n (0 = active) as
// hierarchical text with secrets masked.
func (s *Store) ShowRollbackRedacted(n int) (string, error) {
	return s.ShowRollbackRedactedPath(n, nil)
}

// ShowRollbackRedactedPath renders rollback slot n (0 = active) at path
// with secrets masked.
func (s *Store) ShowRollbackRedactedPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathRedacted(path), nil
}

// ShowRollbackSetRedacted renders rollback slot n (0 = active) as set
// commands with secrets masked.
func (s *Store) ShowRollbackSetRedacted(n int) (string, error) {
	return s.ShowRollbackSetRedactedPath(n, nil)
}

// ShowRollbackSetRedactedPath renders rollback slot n (0 = active) at
// path as set commands with secrets masked.
func (s *Store) ShowRollbackSetRedactedPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathSetRedacted(path), nil
}

// ShowRollbackJSONRedacted renders rollback slot n (0 = active) as JSON
// with secrets masked.
func (s *Store) ShowRollbackJSONRedacted(n int) (string, error) {
	return s.ShowRollbackJSONRedactedPath(n, nil)
}

// ShowRollbackJSONRedactedPath renders rollback slot n (0 = active) at
// path as JSON with secrets masked.
func (s *Store) ShowRollbackJSONRedactedPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathJSONRedacted(path), nil
}

// ShowRollbackXMLRedacted renders rollback slot n (0 = active) as XML
// with secrets masked.
func (s *Store) ShowRollbackXMLRedacted(n int) (string, error) {
	return s.ShowRollbackXMLRedactedPath(n, nil)
}

// ShowRollbackXMLRedactedPath renders rollback slot n (0 = active) at
// path as XML with secrets masked.
func (s *Store) ShowRollbackXMLRedactedPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathXMLRedacted(path), nil
}

// ShowRollbackInheritanceRedacted renders rollback slot n (0 = active)
// with inheritance annotations and secrets masked.
func (s *Store) ShowRollbackInheritanceRedacted(n int) (string, error) {
	return s.ShowRollbackInheritanceRedactedPath(n, nil)
}

// ShowRollbackInheritanceRedactedPath renders rollback slot n
// (0 = active) at path with inheritance annotations, secrets masked.
func (s *Store) ShowRollbackInheritanceRedactedPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	return tree.FormatPathInheritanceRedactedForNode(path, s.nodeID)
}

// ShowCompareRedacted returns a hierarchical diff with secret values constant-
// masked on both arms. Separate adjacent 8-hex SHA-256 fingerprint metadata
// shows secret changes without placing a fingerprint in the config value.
// Credential-bearing URLs retain RedactURL's safe context while fingerprinting
// only the components RedactURL hides.
func (s *Store) ShowCompareRedacted() string {
	return s.ShowCompareRedactedAtPath(nil)
}

// ShowCompareRedactedAtPath is ShowCompareRedacted filtered to path
// (#15272 B24-03); nil/empty path is the global compare.
func (s *Store) ShowCompareRedactedAtPath(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return ""
	}
	diff := config.FormatCompareRedactedAtPath(s.active, s.candidate, path)
	if diff == "" {
		return "[no changes]\n"
	}
	return diff
}

// ShowCompareRollbackRedacted returns a diff between rollback slot n and the
// candidate with secrets masked on both sides. It must use the fingerprint-
// aware redacted compare (as ShowCompareRedacted does): constant-masking both
// arms via forDisplay collapses distinct secrets to the same placeholder, so
// a secret-only rollback difference would render as [no changes] (#14170).
func (s *Store) ShowCompareRollbackRedacted(n int) (string, error) {
	return s.ShowCompareRollbackRedactedAtPath(n, nil)
}

// ShowCompareRollbackRedactedAtPath is ShowCompareRollbackRedacted filtered
// to path (#15272 B24-03); nil/empty path is the global compare. n == 0 is
// the active configuration (candidate-vs-active, still needs a candidate).
func (s *Store) ShowCompareRollbackRedactedAtPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return "", fmt.Errorf("not in configuration mode")
	}
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	diff := config.FormatCompareRedactedAtPath(tree, s.candidate, path)
	if diff == "" {
		return "[no changes]\n", nil
	}
	return diff, nil
}

// ShowCompareRollbackActiveRedacted returns a diff between rollback
// slot n (0 = active) and the ACTIVE configuration with secrets masked
// (#15657 V45-03, #14170 fingerprint-aware). Operational baseline:
// never reads s.candidate, never requires configuration mode.
func (s *Store) ShowCompareRollbackActiveRedacted(n int) (string, error) {
	return s.ShowCompareRollbackActiveRedactedAtPath(n, nil)
}

// ShowCompareRollbackActiveRedactedAtPath is
// ShowCompareRollbackActiveRedacted filtered to path.
func (s *Store) ShowCompareRollbackActiveRedactedAtPath(n int, path []string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree, err := s.rollbackTree(n)
	if err != nil {
		return "", err
	}
	diff := config.FormatCompareRedactedAtPath(tree, s.active, path)
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
