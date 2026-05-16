// Package configstore implements the Junos-style candidate/active
// configuration management with commit and rollback support.
package configstore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// Store manages the candidate and active configuration.
type Store struct {
	mu        sync.RWMutex
	active    *config.ConfigTree
	candidate *config.ConfigTree
	compiled  *config.Config // compiled active config
	history   *History
	dirty     bool
	configDir bool // true if in configuration mode
	filePath  string

	// Persistent storage
	db      *DB
	journal *Journal

	// Commit confirmed state
	confirmTimer      *time.Timer
	confirmPrevTree   *config.ConfigTree   // active tree before confirmed commit
	confirmPrevCfg    *config.Config       // compiled config before confirmed commit
	centralRollbackFn func(*config.Config) // callback for dataplane central-apply

	// Exclusive configuration mode
	exclusiveHolder string // who holds exclusive lock (empty = unlocked)

	// Config lock tracking: session ID of the holder (for auto-release on disconnect)
	configHolder string    // unique session ID of the config lock holder
	configLockAt time.Time // when the lock was acquired

	// Cluster read-only mode: secondary nodes reject config mutations
	clusterReadOnly bool

	// Cluster node ID for ${node} variable expansion in apply-groups.
	// -1 means non-cluster (use CompileConfig), >= 0 means use CompileConfigForNode.
	nodeID int

	// Edit path for hierarchical navigation (edit/top/up)
	editPath []string

	// Archival settings
	archiveDir string // local archive directory (empty = disabled)
	archiveMax int    // max archives to keep
}

// New creates a new config store.
func New(filePath string) *Store {
	dbDir := filepath.Join(filepath.Dir(filePath), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		slog.Warn("failed to create config db, falling back to file-only", "err", err)
	}

	journalPath := filepath.Join(filepath.Dir(filePath), ".config.journal")

	return &Store{
		active:   &config.ConfigTree{},
		history:  NewHistory(50),
		filePath: filePath,
		db:       db,
		journal:  NewJournal(journalPath),
		nodeID:   -1,
	}
}

// Load builds the configuration from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, err := s.db.ReadActive()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if tree == nil {
		return nil // start fresh with empty config
	}

	compiled, err := s.compileTree(tree)
	if err != nil {
		return fmt.Errorf("compile config: %w", err)
	}

	s.active = tree
	s.compiled = compiled
	s.loadRollbackHistory()
	return nil
}

// Save persists the active configuration to disk.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.WriteActive(s.active)
}

// SetClusterReadOnly toggles cluster read-only mode. When enabled, config
// mutations (EnterConfigure, Commit, Load, Set, Delete) are rejected.
// Used to prevent config changes on secondary cluster nodes.
func (s *Store) SetClusterReadOnly(ro bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterReadOnly = ro
}

// ClusterReadOnly returns whether the store is in cluster read-only mode.
func (s *Store) ClusterReadOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clusterReadOnly
}

// SetNodeID sets the cluster node ID for ${node} variable expansion in
// apply-groups. Use -1 (default) for non-cluster mode.
func (s *Store) SetNodeID(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeID = id
}

// compileTree compiles a config tree using the appropriate method based on
// whether the store is in cluster mode (nodeID >= 0) or standalone.
//
// Order of operations (#1319): the typed-leaf SchemaValidate gate runs
// BEFORE compile, but against the same apply-groups-expanded view the
// compiler consumes. Running on the raw candidate tree would let invalid
// typed leaves inside `groups { ... }` bypass the gate while still reaching
// the compiler after expansion. We still validate at commit/load time rather
// than at `set` time so the candidate-edit flow stays permissive —
// operators can stage half-typed values without each `set` line being
// rejected — and `commit check` is the one place that fails loud on garbage
// like `transmit-rate asd`. cfg is nil at this point because we haven't
// compiled yet; the schedulers validators don't need it.
func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
	if err := s.schemaValidateExpandedTree(tree); err != nil {
		return nil, err
	}
	if s.nodeID >= 0 {
		return config.CompileConfigForNode(tree, s.nodeID)
	}
	return config.CompileConfig(tree)
}

func (s *Store) schemaValidateExpandedTree(tree *config.ConfigTree) error {
	if tree == nil {
		return nil
	}
	expanded := tree.Clone()
	if s.nodeID >= 0 {
		vars := map[string]string{"node": fmt.Sprintf("node%d", s.nodeID)}
		if err := expanded.ExpandGroupsWithVars(vars); err != nil {
			return fmt.Errorf("apply-groups: %w", err)
		}
		return cmdtree.SchemaValidate(expanded, nil)
	}
	if err := expanded.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
				return fmt.Errorf("apply-groups: %w", err2)
			}
		} else {
			return fmt.Errorf("apply-groups: %w", err)
		}
	}
	return cmdtree.SchemaValidate(expanded, nil)
}

// SyncApply applies a config received from the cluster primary.
// Bypasses cluster read-only checks. The chassisPreserve function, if set,
// lets the caller patch the parsed tree before compiling (e.g. to preserve
// local chassis cluster settings).
func (s *Store) SyncApply(content string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return nil, fmt.Errorf("sync config parse error: %v", errs[0])
	}

	// Let caller patch the tree (e.g. preserve local chassis cluster settings).
	if chassisPreserve != nil {
		chassisPreserve(tree)
	}

	compiled, err := s.compileTree(tree)
	if err != nil {
		return nil, fmt.Errorf("sync config compile error: %w", err)
	}

	// Push current active to history.
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	s.active = tree
	s.compiled = compiled
	s.dirty = false

	// If in config mode, update candidate too.
	if s.configDir {
		s.candidate = s.active.Clone()
	}

	if err := s.db.WriteActive(s.active); err != nil {
		slog.Warn("failed to save synced config", "err", err)
	}

	s.journal.Log(&JournalEntry{
		Timestamp: time.Now(),
		Action:    "config_sync",
		After:     compiled,
	})

	s.saveRollbackFiles()
	return compiled, nil
}

// EnterConfigure enters configuration mode by cloning the active config.
// Returns an error if another session is already in config mode.
func (s *Store) EnterConfigure() error {
	return s.EnterConfigureSession("")
}

// EnterConfigureSession enters configuration mode with a session identifier.
// If the same session already holds the lock, it's a no-op.
func (s *Store) EnterConfigureSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterReadOnly {
		return fmt.Errorf("configuration database is not writable (secondary node)")
	}
	if s.configDir {
		// Allow re-entry by same session.
		if sessionID != "" && s.configHolder == sessionID {
			return nil
		}
		return fmt.Errorf("configuration is locked by another user")
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.configHolder = sessionID
	s.configLockAt = time.Now()
	return nil
}

// EnterConfigureExclusive enters exclusive configuration mode.
func (s *Store) EnterConfigureExclusive(holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterReadOnly {
		return fmt.Errorf("configuration database is not writable (secondary node)")
	}
	if s.configDir {
		return fmt.Errorf("configuration is locked by another user")
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.exclusiveHolder = holder
	s.configLockAt = time.Now()
	return nil
}

// ExitConfigureSession exits configuration mode only if the given session holds
// the lock. Returns true if the lock was released.
func (s *Store) ExitConfigureSession(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return false
	}
	if sessionID != "" && s.configHolder != sessionID {
		return false
	}
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	s.editPath = nil
	return true
}

// ForceExitConfigure exits configuration mode regardless of who holds the lock.
// Used for stale lock cleanup.
func (s *Store) ForceExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return
	}
	slog.Warn("force-releasing stale config lock", "holder", s.configHolder,
		"held_for", time.Since(s.configLockAt).Round(time.Second))
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	s.editPath = nil
}

// ConfigHolder returns the session ID of the current config lock holder
// and whether the lock is held.
func (s *Store) ConfigHolder() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configHolder, s.configDir
}

// IsExclusiveLocked returns true if exclusive mode is active.
func (s *Store) IsExclusiveLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exclusiveHolder != ""
}

// ExitConfigure exits configuration mode, discarding the candidate.
func (s *Store) ExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.editPath = nil
}

// SetEditPath sets the edit path for hierarchical navigation.
func (s *Store) SetEditPath(path []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = path
}

// GetEditPath returns a copy of the current edit path.
func (s *Store) GetEditPath() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.editPath...)
}

// NavigateUp moves the edit path up one level.
func (s *Store) NavigateUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.editPath) > 0 {
		s.editPath = s.editPath[:len(s.editPath)-1]
	}
}

// NavigateTop resets the edit path to the root.
func (s *Store) NavigateTop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = nil
}

// InConfigMode returns true if currently in configuration mode.
func (s *Store) InConfigMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configDir
}

// IsDirty returns true if the candidate differs from active.
func (s *Store) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// Set applies a "set" command to the candidate configuration.
func (s *Store) Set(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.SetPath(path); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// SetFromInput parses a "set ..." command string and applies it.
func (s *Store) SetFromInput(input string) error {
	path, err := config.ParseSetCommand("set " + input)
	if err != nil {
		return err
	}
	return s.Set(path)
}

// Delete removes a node at the given path from the candidate configuration.
func (s *Store) Delete(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.DeletePath(path); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// DeleteFromInput parses a "delete ..." command string and applies it.
func (s *Store) DeleteFromInput(input string) error {
	path, err := config.ParseSetCommand("delete " + input)
	if err != nil {
		return err
	}
	return s.Delete(path)
}

// Copy duplicates a config subtree from srcPath to dstPath.
func (s *Store) Copy(srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := s.candidate.CopyPath(srcPath, dstPath); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Rename moves a config subtree from srcPath to dstPath.
func (s *Store) Rename(srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := s.candidate.RenamePath(srcPath, dstPath); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Insert moves an element before or after a reference element within the
// same parent's ordered children list.
func (s *Store) Insert(elementPath, refPath []string, before bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	var err error
	if before {
		err = s.candidate.InsertBefore(elementPath, refPath)
	} else {
		err = s.candidate.InsertAfter(elementPath, refPath)
	}
	if err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Annotate sets a comment on a configuration node in the candidate config.
func (s *Store) Annotate(path []string, comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	children := s.candidate.Children
	var target *config.Node
	for _, key := range path {
		found := false
		for _, child := range children {
			for _, k := range child.Keys {
				if k == key {
					target = child
					children = child.Children
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return fmt.Errorf("path not found: %s", strings.Join(path, " "))
		}
	}

	target.Annotation = comment
	s.dirty = true
	return nil
}

// LoadOverride replaces the entire candidate config with the parsed input.
// The input can be hierarchical Junos config or flat "set" commands.
func (s *Store) LoadOverride(content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return fmt.Errorf("parse error: %v", errs[0])
	}

	s.candidate = tree
	s.dirty = true
	return nil
}

// LoadMerge merges the parsed input into the existing candidate config.
// For flat "set" commands, each line is applied individually.
// For hierarchical input, it's converted to set commands and merged.
func (s *Store) LoadMerge(content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	// Detect format: if content has "set " lines, process as set commands
	lines := strings.Split(content, "\n")
	isSetFormat := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "set ") || strings.HasPrefix(trimmed, "delete ") {
			isSetFormat = true
			break
		}
	}

	if isSetFormat {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.HasPrefix(trimmed, "set ") {
				path, err := config.ParseSetCommand(trimmed)
				if err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
				if err := s.candidate.SetPath(path); err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
			} else if strings.HasPrefix(trimmed, "delete ") {
				path, err := config.ParseSetCommand(trimmed)
				if err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
				if err := s.candidate.DeletePath(path); err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
			}
		}
	} else {
		// Parse as hierarchical config and merge each top-level node
		tree, errs := config.NewParser(content).Parse()
		if len(errs) > 0 {
			return fmt.Errorf("parse error: %v", errs[0])
		}
		// Convert hierarchical to set commands and apply each one
		setLines := strings.Split(tree.FormatSet(), "\n")
		for _, line := range setLines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			path, err := config.ParseSetCommand(trimmed)
			if err != nil {
				continue
			}
			if err := s.candidate.SetPath(path); err != nil {
				return fmt.Errorf("merge: %w", err)
			}
		}
	}

	s.dirty = true
	return nil
}

// LoadSet applies multiple set commands to the candidate config.
// Each line starting with "set " is parsed and applied.
func (s *Store) LoadSet(content string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return 0, fmt.Errorf("not in configuration mode")
	}
	count := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		path, err := config.ParseSetCommand(line)
		if err != nil {
			return count, fmt.Errorf("line %q: %w", line, err)
		}
		if err := s.candidate.SetPath(path); err != nil {
			return count, fmt.Errorf("line %q: %w", line, err)
		}
		count++
	}
	s.dirty = true
	return count, nil
}

// CommitCheck validates the candidate configuration without applying it.
func (s *Store) CommitCheck() (*config.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, err
	}

	return compiled, nil
}

// Commit validates, compiles, and applies the candidate configuration.
// Returns the compiled config for the caller to apply to the dataplane.
func (s *Store) Commit() (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	// Push current active to history
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Persist to disk
	if err := s.db.WriteActive(s.active); err != nil {
		// Non-fatal: log but don't fail the commit
		slog.Warn("failed to save config", "err", err)
	}

	// Log to journal
	s.journal.Log(&JournalEntry{
		Timestamp: time.Now(),
		Action:    "commit",
		After:     compiled,
	})

	s.saveRollbackFiles()

	// Auto-archive if configured
	if s.archiveDir != "" {
		max := s.archiveMax
		if max <= 0 {
			max = 10
		}
		go func() {
			if err := s.ArchiveConfig(s.archiveDir, max); err != nil {
				slog.Warn("auto-archive failed", "err", err)
			}
		}()
	}

	return compiled, nil
}

// CommitWithDescription validates, compiles, and applies the candidate configuration
// with an optional comment/description attached to the history and journal entries.
func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	// Push current active to history with description
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
		Comment:   description,
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Persist to disk
	if err := s.db.WriteActive(s.active); err != nil {
		slog.Warn("failed to save config", "err", err)
	}

	// Log to journal with description
	s.journal.Log(&JournalEntry{
		Timestamp: time.Now(),
		Action:    "commit",
		Detail:    description,
		After:     compiled,
	})

	s.saveRollbackFiles()

	// Auto-archive if configured
	if s.archiveDir != "" {
		max := s.archiveMax
		if max <= 0 {
			max = 10
		}
		go func() {
			if err := s.ArchiveConfig(s.archiveDir, max); err != nil {
				slog.Warn("auto-archive failed", "err", err)
			}
		}()
	}

	return compiled, nil
}

// SetCentralRollbackHandler registers a callback for central-rollback dataplane re-apply.
func (s *Store) SetCentralRollbackHandler(fn func(*config.Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.centralRollbackFn = fn
}

// CommitConfirmed validates, compiles, and applies the candidate with an
// automatic rollback timer. If minutes is 0, defaults to 10.
// If a bare "commit" is not issued within the timeout, the config auto-reverts.
func (s *Store) CommitConfirmed(minutes int) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	if minutes <= 0 {
		minutes = 10
	}

	// Cancel any existing pending confirmation
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
		s.confirmTimer = nil
	}

	// Save current active state for potential rollback
	s.confirmPrevTree = s.active.Clone()
	s.confirmPrevCfg = s.compiled

	// Push current active to history
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Persist to disk
	if err := s.db.WriteActive(s.active); err != nil {
		slog.Warn("failed to save config", "err", err)
	}

	// Log to journal
	s.journal.Log(&JournalEntry{
		Timestamp: time.Now(),
		Action:    "commit_confirmed",
		After:     compiled,
	})

	s.saveRollbackFiles()

	// Start auto-rollback timer
	s.confirmTimer = time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
		s.performAutoRollback()
	})

	slog.Info("commit confirmed started", "timeout_minutes", minutes)
	return compiled, nil
}

// ConfirmCommit cancels the auto-rollback timer, confirming the config.
func (s *Store) ConfirmCommit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.confirmTimer == nil {
		return fmt.Errorf("no pending confirmed commit")
	}

	s.confirmTimer.Stop()
	s.confirmTimer = nil
	s.confirmPrevTree = nil
	s.confirmPrevCfg = nil

	slog.Info("commit confirmed")
	return nil
}

// IsConfirmPending returns true if a commit confirmed is awaiting confirmation.
func (s *Store) IsConfirmPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmTimer != nil
}

// performAutoRollback reverts the active config to the saved pre-confirmed state.
func (s *Store) performAutoRollback() {
	s.mu.Lock()

	if s.confirmPrevTree == nil {
		s.mu.Unlock()
		return
	}

	s.active = s.confirmPrevTree
	s.compiled = s.confirmPrevCfg
	if s.candidate != nil {
		s.candidate = s.active.Clone()
	}
	s.dirty = false

	s.confirmTimer = nil
	s.confirmPrevTree = nil
	prevCfg := s.confirmPrevCfg
	s.confirmPrevCfg = nil

	// Persist reverted config to disk
	if err := s.db.WriteActive(s.active); err != nil {
		slog.Warn("failed to save reverted config", "err", err)
	}

	// Log to journal
	s.journal.Log(&JournalEntry{
		Timestamp: time.Now(),
		Action:    "auto_rollback",
		After:     s.compiled,
	})

	fn := s.centralRollbackFn
	s.mu.Unlock()

	slog.Warn("commit confirmed timed out, configuration rolled back")

	// Call dataplane re-apply outside the lock
	if fn != nil && prevCfg != nil {
		fn(prevCfg)
	}
}

// Rollback reverts the candidate to a previous configuration.
// n=0 reverts to active; n>0 reverts to the nth previous commit.
func (s *Store) Rollback(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if n == 0 {
		s.candidate = s.active.Clone()
		s.dirty = false
		return nil
	}

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return err
	}
	s.candidate = entry.Config.Clone()
	s.dirty = true
	return nil
}

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

// ListHistory returns all history entries, most recent first (goroutine-safe).
func (s *Store) ListHistory() []*HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.history.List()
}

// ListCommitHistory returns recent commit journal entries (most recent last).
func (s *Store) ListCommitHistory(limit int) ([]*JournalEntry, error) {
	entries, err := s.journal.ListEntries(limit)
	if err != nil {
		return nil, err
	}
	// Filter to commit/rollback actions only
	var commits []*JournalEntry
	for _, e := range entries {
		switch e.Action {
		case "commit", "commit_confirmed", "auto_rollback":
			commits = append(commits, e)
		}
	}
	return commits, nil
}

// CommitDiffSummary returns a human-readable summary of changes between
// the active and candidate configs. Must be called while in config mode.
func (s *Store) CommitDiffSummary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	activeSet := s.active.FormatSet()
	candidateSet := s.candidate.FormatSet()

	activeLines := splitLines(activeSet)
	candidateLines := splitLines(candidateSet)

	activeMap := make(map[string]bool, len(activeLines))
	for _, line := range activeLines {
		activeMap[line] = true
	}
	candidateMap := make(map[string]bool, len(candidateLines))
	for _, line := range candidateLines {
		candidateMap[line] = true
	}

	var added, removed int
	for _, line := range activeLines {
		if !candidateMap[line] {
			removed++
		}
	}
	for _, line := range candidateLines {
		if !activeMap[line] {
			added++
		}
	}

	total := added + removed
	if total == 0 {
		return ""
	}

	return fmt.Sprintf("%d statement(s) changed (%d added, %d removed)", total, added, removed)
}

// rollbackPath returns the file path for rollback slot n (1-based).
func (s *Store) rollbackPath(n int) string {
	return filepath.Join(filepath.Dir(s.filePath), fmt.Sprintf("%s.%d", filepath.Base(s.filePath), n))
}

// saveRollbackFiles writes rollback history entries to numbered files.
// Must be called under write lock.
func (s *Store) saveRollbackFiles() {
	if s.filePath == "" {
		return
	}

	entries := s.history.List() // most-recent-first
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			slog.Warn("failed to write rollback file", "path", path, "err", err)
		}
	}
	s.cleanupRollbackFiles(len(entries) + 1)
}

// cleanupRollbackFiles removes stale rollback files starting at startN.
func (s *Store) cleanupRollbackFiles(startN int) {
	for i := startN; i <= s.history.MaxSize()+1; i++ {
		path := s.rollbackPath(i)
		if err := os.Remove(path); err != nil {
			break // stop on first not-found (contiguous sequence)
		}
	}
}

// loadRollbackHistory reads numbered rollback files and populates the history.
// Must be called under write lock.
func (s *Store) loadRollbackHistory() {
	if s.filePath == "" {
		return
	}

	var entries []*HistoryEntry
	for i := 1; i <= s.history.MaxSize(); i++ {
		path := s.rollbackPath(i)
		data, err := os.ReadFile(path)
		if err != nil {
			break // stop on first not-found
		}
		parser := config.NewParser(string(data))
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			slog.Warn("skipping corrupt rollback file", "path", path, "err", errs[0])
			continue
		}
		// Use file modification time as timestamp
		info, _ := os.Stat(path)
		ts := time.Now()
		if info != nil {
			ts = info.ModTime()
		}
		entries = append(entries, &HistoryEntry{
			Config:    tree,
			Timestamp: ts,
		})
	}

	// Push oldest-first so History ordering is correct
	for i := len(entries) - 1; i >= 0; i-- {
		s.history.Push(entries[i])
	}

	if len(entries) > 0 {
		slog.Info("loaded rollback history", "entries", len(entries))
	}
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

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}
	return entry.Config.Format(), nil
}

// ShowRollbackSet returns the content of rollback slot n (1-based) as flat set commands.
func (s *Store) ShowRollbackSet(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.history.Get(n - 1)
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

	entry, err := s.history.Get(n - 1)
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

// SetArchiveConfig configures automatic archival on commit.
func (s *Store) SetArchiveConfig(dir string, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archiveDir = dir
	s.archiveMax = max
}

// ArchiveConfig saves a timestamped copy of the active config.
func (s *Store) ArchiveConfig(archiveDir string, maxArchives int) error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()

	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("create archive dir: %w", err)
	}

	filename := fmt.Sprintf("config-%s.conf", time.Now().Format("20060102-150405"))
	path := filepath.Join(archiveDir, filename)
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	slog.Info("config archived", "path", path)

	// Rotate old archives
	if maxArchives > 0 {
		rotateArchives(archiveDir, maxArchives)
	}
	return nil
}

// rotateArchives keeps only the most recent maxArchives files.
func rotateArchives(dir string, maxArchives int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var archives []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "config-") && strings.HasSuffix(e.Name(), ".conf") {
			archives = append(archives, e.Name())
		}
	}

	if len(archives) <= maxArchives {
		return
	}

	// Sort alphabetically (timestamps sort naturally)
	sort.Strings(archives)

	// Remove oldest
	for i := 0; i < len(archives)-maxArchives; i++ {
		path := filepath.Join(dir, archives[i])
		if err := os.Remove(path); err != nil {
			slog.Warn("failed to remove old archive", "path", path, "err", err)
		}
	}
}

// rescuePath returns the path for the rescue configuration file.
func (s *Store) rescuePath() string {
	return filepath.Join(filepath.Dir(s.filePath), "rescue.conf")
}

// SaveRescueConfig saves the active config as rescue configuration.
func (s *Store) SaveRescueConfig() error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()

	path := s.rescuePath()
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return fmt.Errorf("save rescue config: %w", err)
	}
	slog.Info("rescue configuration saved", "path", path)
	return nil
}

// DeleteRescueConfig removes the rescue configuration.
func (s *Store) DeleteRescueConfig() error {
	path := s.rescuePath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no rescue configuration exists")
		}
		return fmt.Errorf("delete rescue config: %w", err)
	}
	slog.Info("rescue configuration deleted", "path", path)
	return nil
}

// LoadRescueConfig returns the rescue configuration text, or "" if none.
func (s *Store) LoadRescueConfig() (string, error) {
	path := s.rescuePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read rescue config: %w", err)
	}
	return string(data), nil
}
