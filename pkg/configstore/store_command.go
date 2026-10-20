package configstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// Set applies a "set" command to the candidate configuration. It is the
// internal/system entry point (no session ownership check); the gRPC user path
// uses SetAs to carry the caller's session for config-lock holder enforcement
// (#5059).
func (s *Store) Set(path []string) error { return s.SetAs("", path) }

// SetAs is Set scoped to a config-lock holder session (#5059). sessionID == ""
// bypasses ownership (internal/system caller).
//
// It carries NO quote provenance, so nodes it creates record none — correct for
// a synthesized path, and the reason the operator-facing entry point
// (SetFromInputAs) uses SetAsQuoted instead (#6673).
func (s *Store) SetAs(sessionID string, path []string) error {
	return s.SetAsQuoted(sessionID, path, nil)
}

// SetAsQuoted is SetAs carrying the per-token quote provenance produced by
// config.ParseSetCommandQuoted (#6673). It is what lets a bracketed list
// authored through the flat-set path — `set ... commands [ "set" "system
// host-name x" ]` — keep the one bit that distinguishes its members from the
// words of a single unquoted command. It carries no BRACKET grouping: a
// caller with a grouped parse uses SetAsQuotedGrouped instead.
func (s *Store) SetAsQuoted(sessionID string, path []string, quoted []bool) error {
	return s.SetAsQuotedGrouped(sessionID, path, quoted, nil)
}

// SetAsQuotedGrouped is SetAsQuoted carrying the per-token BRACKET GROUPING
// produced by config.ParseSetCommandGrouped (#6668, #9881): grouped[i]
// reports whether path[i] was authored inside a `[ ... ]` list. The grouping
// both widens bracketed container key groups (which the schema arity cannot
// infer) and records Node.KeysBracketed, the bit the #9881 strict gate reads.
// A nil grouping is the pre-#6668 behaviour: nothing is widened and no
// bracket provenance is recorded.
func (s *Store) SetAsQuotedGrouped(sessionID string, path []string, quoted, grouped []bool) error {
	return s.setAsQuotedGroupedPlantClass(sessionID, "", path, quoted, grouped)
}

// SetAsQuotedGroupedPlantClass is the authenticated mutation entry point for
// event-options planting. The class is stamped while the same store lock is
// held as the candidate edit, before the lock is released or another session
// can commit the candidate.
func (s *Store) SetAsQuotedGroupedPlantClass(sessionID, plantClass string, path []string, quoted, grouped []bool, closed ...bool) error {
	return s.setAsQuotedGroupedPlantClass(sessionID, plantClass, path, quoted, grouped, closed...)
}

func (s *Store) setAsQuotedGroupedPlantClass(sessionID, plantClass string, path []string, quoted, grouped []bool, closed ...bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	before := s.candidate.Clone()
	if err := s.candidate.SetPathQuotedGrouped(path, quoted, grouped, closed...); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(before, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// SetFromInput parses a "set ..." command string and applies it.
func (s *Store) SetFromInput(input string) error { return s.SetFromInputAs("", input) }

// SetFromInputAs is SetFromInput scoped to a config-lock holder session (#5059).
// Every operator `set` — CLI, gRPC, REST — arrives here as a string, so this
// method's choice of parser and setter decides which provenance survives
// into the candidate tree. It parses with the grouped pair (#6668, #9881),
// matching the load-merge / replay path (applyEditLine): an interactive set
// line and its `show | display set` replay now build the same tree.
func (s *Store) SetFromInputAs(sessionID, input string) error {
	return s.SetFromInputAsPlantClass(sessionID, "", input)
}

// SetFromInputAsPlantClass binds the authenticated planting class atomically
// with the set mutation.
func (s *Store) SetFromInputAsPlantClass(sessionID, plantClass, input string) error {
	_, path, quoted, grouped, closed, err := config.ParseSetVerbGroupedClosed("set " + input)
	if err != nil {
		return err
	}
	return s.SetAsQuotedGroupedPlantClass(sessionID, plantClass, path, quoted, grouped, closed)
}

// Delete removes a node at the given path from the candidate configuration. The
// internal/system entry point; the gRPC user path uses DeleteAs (#5059).
func (s *Store) Delete(path []string) error { return s.DeleteAs("", path) }

// DeleteAs is Delete scoped to a config-lock holder session (#5059). It
// navigates without bracket grouping: a caller with a grouped parse uses
// DeleteAsGrouped instead.
func (s *Store) DeleteAs(sessionID string, path []string) error {
	return s.DeleteAsGrouped(sessionID, path, nil)
}

// DeleteAsGrouped is DeleteAs carrying the per-token BRACKET GROUPING
// produced by config.ParseSetCommandGrouped (#6668, #9881), so a `delete`
// line navigates to the same node the matching `set` line built. Without it
// the walk re-splits a bracketed container key group at the schema arity and
// reports the node missing. A nil grouping is the pre-#6668 behaviour.
func (s *Store) DeleteAsGrouped(sessionID string, path []string, grouped []bool) error {
	return s.deleteAsGroupedPlantClass(sessionID, "", path, grouped)
}

// DeleteAsGroupedPlantClass binds the authenticated planting class atomically
// with the delete mutation.
func (s *Store) DeleteAsGroupedPlantClass(sessionID, plantClass string, path []string, grouped []bool) error {
	return s.deleteAsGroupedPlantClass(sessionID, plantClass, path, grouped)
}

func (s *Store) deleteAsGroupedPlantClass(sessionID, plantClass string, path []string, grouped []bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	before := s.candidate.Clone()
	if err := s.candidate.DeletePathGrouped(path, grouped); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(before, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// DeleteFromInput parses a "delete ..." command string and applies it.
func (s *Store) DeleteFromInput(input string) error { return s.DeleteFromInputAs("", input) }

// DeleteFromInputAs is DeleteFromInput scoped to a config-lock holder session
// (#5059). It parses with the grouped pair (#6668, #9881), matching the
// replay path (applyEditLine) and the interactive `set` side: after #9881 an
// interactive `set` builds bracketed containers wide, so the matching
// interactive `delete` must navigate wide too.
func (s *Store) DeleteFromInputAs(sessionID, input string) error {
	return s.DeleteFromInputAsPlantClass(sessionID, "", input)
}

// DeleteFromInputAsPlantClass binds the authenticated planting class
// atomically with the delete mutation.
func (s *Store) DeleteFromInputAsPlantClass(sessionID, plantClass, input string) error {
	path, _, grouped, err := config.ParseSetCommandGrouped("delete " + input)
	if err != nil {
		return err
	}
	return s.DeleteAsGroupedPlantClass(sessionID, plantClass, path, grouped)
}

// DeactivateFromInput marks the candidate node at the given path inactive
// (#2051), implementing the interactive Junos `deactivate <path>` verb. input
// is the bare path WITHOUT the verb (mirroring SetFromInput/DeleteFromInput).
//
// It routes through applyEditLine — the same centralized verb switch used by
// LoadSet / LoadMerge flat-line replay (store.go applyEditLine) — so the verb
// logic lives in exactly one place. It deliberately does NOT go through
// ParseSetCommand("set "+input): that parser would build the junk path
// "deactivate <path>" (a config node literally named "deactivate"), never
// reaching DeactivatePath. The node must already exist; DeactivatePath on an
// already-inactive node is idempotent (it re-sets a bool).
func (s *Store) DeactivateFromInput(input string) error {
	return s.DeactivateFromInputAs("", input)
}

// DeactivateFromInputAs is DeactivateFromInput scoped to a config-lock holder
// session (#5059).
func (s *Store) DeactivateFromInputAs(sessionID, input string) error {
	return s.DeactivateFromInputAsPlantClass(sessionID, "", input)
}

// DeactivateFromInputAsPlantClass binds the authenticated planting class
// atomically with a deactivate mutation.
func (s *Store) DeactivateFromInputAsPlantClass(sessionID, plantClass, input string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	before := s.candidate.Clone()
	if err := applyEditLine(s.candidate, "deactivate "+input); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(before, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// ActivateFromInput clears the inactive marker on the candidate node at the
// given path (#2051), implementing the interactive Junos `activate <path>` verb.
func (s *Store) ActivateFromInput(input string) error {
	return s.ActivateFromInputAs("", input)
}

// ActivateFromInputAs is ActivateFromInput scoped to a config-lock holder
// session (#5059).
func (s *Store) ActivateFromInputAs(sessionID, input string) error {
	return s.ActivateFromInputAsPlantClass(sessionID, "", input)
}

// ActivateFromInputAsPlantClass binds the authenticated planting class
// atomically with an activate mutation.
func (s *Store) ActivateFromInputAsPlantClass(sessionID, plantClass, input string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	before := s.candidate.Clone()
	if err := applyEditLine(s.candidate, "activate "+input); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(before, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Copy duplicates a config subtree from srcPath to dstPath.
func (s *Store) Copy(srcPath, dstPath []string) error {
	return s.CopyAs("", srcPath, dstPath)
}

// CopyAs is Copy scoped to a config-lock holder session (#5059).
func (s *Store) CopyAs(sessionID string, srcPath, dstPath []string) error {
	return s.CopyAsPlantClass(sessionID, "", srcPath, dstPath)
}

// CopyAsPlantClass binds the authenticated planting class atomically with a
// copy that may create or replace an event command subtree.
func (s *Store) CopyAsPlantClass(sessionID, plantClass string, srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	before := s.candidate.Clone()
	if err := s.candidate.CopyPath(srcPath, dstPath); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(before, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Rename moves a config subtree from srcPath to dstPath.
func (s *Store) Rename(srcPath, dstPath []string) error {
	return s.RenameAs("", srcPath, dstPath)
}

// RenameAs is Rename scoped to a config-lock holder session (#5059).
func (s *Store) RenameAs(sessionID string, srcPath, dstPath []string) error {
	return s.RenameAsPlantClass(sessionID, "", srcPath, dstPath)
}

// RenameAsPlantClass binds the authenticated planting class atomically with a
// rename that may move an event command subtree.
func (s *Store) RenameAsPlantClass(sessionID, plantClass string, srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	before := s.candidate.Clone()
	if err := s.candidate.RenamePath(srcPath, dstPath); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(before, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	// #15757: record the destination the rename ACTUALLY created, not
	// the raw typed slice. A bare destination (`policy new` for a
	// zone-pair source) is placed under the source parent by
	// RenamePath (BareDestinationParent); logging the bare slice made
	// session-rematch lineage (policyRulePathKey/zoneRenamePath in the
	// daemon) fail to recognise the destination, so renamed-policy
	// sessions fell back to teardown instead of rematch. Resolve
	// against the candidate BEFORE the mutation re-keys the source
	// node (after it, the source identity no longer exists).
	resolvedDst := before.ResolvedRenameDestination(srcPath, dstPath)
	s.recordRenameAncestryLocked(s.candidateGen, RenameDescriptor{
		SourcePath:      srcPath,
		DestinationPath: resolvedDst,
	})
	s.dirty = true
	return nil
}

// Insert moves an element before or after a reference element within the
// same parent's ordered children list.
func (s *Store) Insert(elementPath, refPath []string, before bool) error {
	return s.InsertAs("", elementPath, refPath, before)
}

// InsertAs is Insert scoped to a config-lock holder session (#5059).
func (s *Store) InsertAs(sessionID string, elementPath, refPath []string, before bool) error {
	return s.InsertAsPlantClass(sessionID, "", elementPath, refPath, before)
}

// InsertAsPlantClass binds the authenticated planting class atomically with an
// insertion that may reorder event command nodes.
func (s *Store) InsertAsPlantClass(sessionID, plantClass string, elementPath, refPath []string, before bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	beforeTree := s.candidate.Clone()
	var err error
	if before {
		err = s.candidate.InsertBefore(elementPath, refPath)
	} else {
		err = s.candidate.InsertAfter(elementPath, refPath)
	}
	if err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(beforeTree, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Annotate sets a comment on a configuration node in the candidate config.
func (s *Store) Annotate(path []string, comment string) error {
	return s.AnnotateAs("", path, comment)
}

// AnnotateAs is Annotate scoped to a config-lock holder session (#5379,
// mirroring the #5059 *As mutators). sessionID == "" bypasses ownership.
func (s *Store) AnnotateAs(sessionID string, path []string, comment string) error {
	return s.AnnotateAsPlantClass(sessionID, "", path, comment)
}

// AnnotateAsPlantClass binds the authenticated planting class atomically with
// the annotation mutation.
func (s *Store) AnnotateAsPlantClass(sessionID, plantClass string, path []string, comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	// #3900: reject comments that could escape the emitted block comment or
	// inject control characters. The strict commit path remains a backstop.
	if err := config.ValidateAnnotationText(comment); err != nil {
		return err
	}

	// #4587: navigatePath consumes multi-key configuration nodes as units,
	// unlike the original one-token-per-node walk.
	beforeTree := s.candidate.Clone()
	if err := s.candidate.AnnotatePath(path, comment); err != nil {
		return err
	}
	config.StampChangedEventPlantClasses(beforeTree, s.candidate, plantClass)
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// LoadOverride replaces the entire candidate config with the parsed input.
// The input can be hierarchical Junos config or flat "set" commands.
func (s *Store) LoadOverride(content string) error { return s.LoadOverrideAs("", content) }

// LoadOverrideAs is LoadOverride scoped to a config-lock holder session (#5059).
func (s *Store) LoadOverrideAs(sessionID, content string) error {
	return s.LoadOverrideAsPlantClass(sessionID, "", content)
}

// LoadOverrideAsPlantClass binds the authenticated planting class atomically
// with the complete replacement candidate.
func (s *Store) LoadOverrideAsPlantClass(sessionID, plantClass, content string) error {
	if err := checkConfigSize(content); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	// #7527: classify the input before parsing it. LoadOverride used to call
	// the hierarchical parser unconditionally and then ATOMICALLY REPLACE the
	// candidate with whatever came back. The parser treats newlines as
	// whitespace, so a flat set-command file did not fail — it collapsed into
	// ONE junk top-level node and the call returned nil:
	//
	//   in:  "set system host-name a\nset system domain-name example.net"
	//   out: set set system host-name a set system domain-name example.net
	//
	// The operator's entire configuration was replaced by that, and both the
	// CLI and the RPC reported success. `show configuration | display set >
	// backup.txt` followed by `load override backup.txt` is an ordinary
	// workflow, and `load set` accepts only `terminal` — so there was no
	// file-based path for flat input at all, and the one an operator would
	// reach for silently destroyed the candidate.
	//
	// LoadMerge already classifies and replays line-by-line; this mirrors it.
	// The difference is the starting tree: MERGE replays onto a clone of the
	// candidate, OVERRIDE replays onto an EMPTY one, which is what "override"
	// means.
	//
	// MISCLASSIFICATION FAILS LOUD, which is what makes accepting flat input
	// the bounded choice rather than the risky one. If a hierarchical file were
	// mistaken for flat, the #3442 M3 rule below rejects the first line without
	// a recognized verb — an error, never a silently wrong candidate. The
	// reverse (flat mistaken for hierarchical) is the defect being fixed here.
	tree, err := parseOverrideContent(content)
	if err != nil {
		return err
	}

	config.StampChangedEventPlantClasses(s.candidate, tree, plantClass)
	s.candidate = tree
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: complete candidate replacement retires rename lineage
	s.dirty = true
	return nil
}

// LoadRescueAsPlantClass replaces the candidate with the saved rescue config.
// It never promotes or persists that candidate.
func (s *Store) LoadRescueAsPlantClass(sessionID, plantClass string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	data, err := ReadBoundedFile(s.rescuePath(), MaxConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrRescueNotFound
		}
		return fmt.Errorf("read rescue config: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return ErrRescueNotFound
	}
	tree, err := parseRescueContent(string(data))
	if err != nil {
		return err
	}
	if tree == nil || len(tree.Children) == 0 {
		return ErrRescueNotFound
	}

	config.StampChangedEventPlantClasses(s.candidate, tree, plantClass)
	s.candidate = tree
	s.touchConfigLockLocked()
	s.bumpCandidateGenLocked()
	s.dirty = true
	return nil
}

// rescueParseError retains useful source coordinates while deliberately
// dropping parser text that may include a file-owned secret.
type rescueParseError struct {
	line   int
	column int
}

func (e rescueParseError) Error() string {
	return fmt.Sprintf("rescue configuration parse failed at line %d, column %d", e.line, e.column)
}

func parseRescueContent(content string) (*config.ConfigTree, error) {
	tree, err := parseOverrideContent(content)
	if err == nil {
		return tree, nil
	}
	line, column := rescueParseErrorPosition(err.Error())
	return nil, rescueParseError{line: line, column: column}
}

func rescueParseErrorPosition(message string) (int, int) {
	line, column := 1, 1
	// Flat replay wraps the parser error as `line N: <source>: <cause>`.
	// Trust that outer physical-file coordinate before considering the inner
	// parser text: source content can itself contain strings like "line 9".
	var outerLine int
	if _, err := fmt.Sscanf(message, "line %d:", &outerLine); err == nil && outerLine > 0 {
		return outerLine, column
	}
	position := strings.LastIndex(message, "line ")
	if position < 0 {
		return line, column
	}
	message = message[position:]
	var parsedLine, parsedColumn int
	if _, err := fmt.Sscanf(message, "line %d, column %d", &parsedLine, &parsedColumn); err == nil &&
		parsedLine > 0 && parsedColumn > 0 {
		return parsedLine, parsedColumn
	}
	if _, err := fmt.Sscanf(message, "line %d:", &parsedLine); err == nil && parsedLine > 0 {
		return parsedLine, column
	}
	return line, column
}

// parseOverrideContent turns `load override` input into the replacement tree,
// accepting BOTH the hierarchical form and a flat set/delete/deactivate/
// activate script (#7527).
//
// It builds the tree standalone and returns an error without touching any
// store state, so a caller swaps in a complete result or nothing — the same
// atomicity LoadMerge gained in #5187, for the same reason: a partially
// applied override is a config nobody authored, and a partial DELETE of deny
// terms fails open.
func parseOverrideContent(content string) (*config.ConfigTree, error) {
	isSetFormat, flatContent, err := config.ClassifyLoadContent(content)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	if !isSetFormat {
		// #15718: parse the RAW body so /* ... */ comments attach as
		// Node.Annotation; the classifier's uncommented text would erase
		// them. Gate⊆store still holds: LoadMutationLines now renders
		// annotate lines for annotated leaves, and comments cannot hide
		// tokens from the real lexer either.
		tree, errs := config.NewParser(content).Parse()
		if len(errs) > 0 {
			return nil, fmt.Errorf("parse error: %v", errs[0])
		}
		return tree, nil
	}
	lines := strings.Split(flatContent, "\n")

	// Flat: replay onto an EMPTY tree. Starting from the candidate would make
	// this a merge, which is the other verb.
	tree := &config.ConfigTree{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// #3442 M3, same rule as the merge path: once flat format is
		// selected, every non-comment line MUST carry a recognized verb.
		// Otherwise ParseSetVerb treats free text as a bare `set` path and
		// materializes a junk node — which is the #7527 defect one layer down.
		if !hasFlatVerb(trimmed) {
			return nil, fmt.Errorf("line %d: is not a set/delete/deactivate/activate/annotate command", i+1)
		}
		if err := applyEditLine(tree, trimmed); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, scrubLoadLineError(err))
		}
	}
	return tree, nil
}

// LoadMerge merges the parsed input into the existing candidate config.
// For flat "set" commands, each line is applied individually.
// For hierarchical input, it's converted to set commands and merged.
func (s *Store) LoadMerge(content string) error { return s.LoadMergeAs("", content) }

// LoadMergeAs is LoadMerge scoped to a config-lock holder session (#5059).
func (s *Store) LoadMergeAs(sessionID, content string) error {
	return s.LoadMergeAsPlantClass(sessionID, "", content)
}

// LoadMergeAsPlantClass binds the authenticated planting class atomically
// with the complete merge candidate.
func (s *Store) LoadMergeAsPlantClass(sessionID, plantClass, content string) error {
	if err := checkConfigSize(content); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	// Detect format: if content has set/delete/deactivate/activate lines,
	// process as flat command lines.
	isSetFormat, flatContent, err := config.ClassifyLoadContent(content)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	lines := strings.Split(flatContent, "\n")

	// #5187: merge into a deep clone of the candidate and swap it in only on
	// complete success. Both branches below previously applied each line
	// directly to s.candidate and returned on the first error, leaving every
	// EARLIER set/delete line committed to the live candidate while the
	// RPC/CLI reported the merge FAILED — a non-atomic import (a partial
	// delete could drop replacement deny lines that followed the failing line
	// = fail-open). Mirror LoadOverride's parse-into-a-separate-tree-then-swap
	// discipline so a mid-body error leaves the candidate byte-identical to
	// before the request (dirty/lease state untouched).
	working := s.candidate.Clone()

	if isSetFormat {
		// #3442 M3: once flat set-format is selected, every non-comment line
		// MUST start with a recognized verb. Otherwise ParseSetVerb treats a
		// typo/free-text line (e.g. "not-a-set-line") as a bare `set` path and
		// materializes a junk top-level node. Fail loudly on the bad line
		// instead — the bare-path default in ParseSetVerb is reserved for
		// internal callers that prepend the verb themselves (SetEdit, Deactivate,
		// Activate, ...).
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !hasFlatVerb(trimmed) {
				return fmt.Errorf("line %d: is not a set/delete/deactivate/activate/annotate command", i+1)
			}
			if err := applyEditLine(working, trimmed); err != nil {
				return fmt.Errorf("line %d: %w", i+1, scrubLoadLineError(err))
			}
		}
	} else {
		// #15718: parse the RAW body so /* ... */ comments attach as
		// Node.Annotation (see parseOverrideContent).
		tree, errs := config.NewParser(content).Parse()
		if len(errs) > 0 {
			return fmt.Errorf("parse error: %v", errs[0])
		}
		// Inspect the literal input before hierarchical-to-set lowering erases
		// whether a one-key firewall-filter (#12526) or policy-statement
		// (#12521) term had a name. Group bodies are included, but references
		// are not expanded using only this fragment.
		if err := config.ValidateFirewallNamelessTermsAST12526(tree); err != nil {
			return fmt.Errorf("merge: %w", err)
		}
		if err := config.ValidatePolicyNamelessTermsAST12521(tree); err != nil {
			return fmt.Errorf("merge: %w", err)
		}
		if err := config.ValidateInactiveNamelessPolicyTermReplay12598(tree, working); err != nil {
			return fmt.Errorf("merge: %w", err)
		}
		// Convert hierarchical to flat commands and apply each one. FormatSet
		// emits a `deactivate <path>` line after every inactive node's `set`
		// line(s), so the hierarchical -> flat -> tree round trip must honor
		// the deactivate verb (#2008 H1) to preserve Inactive — applying it as
		// a plain set would silently re-activate the node.
		setLines := strings.Split(tree.FormatSetForLoadMerge(), "\n")
		for _, line := range setLines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if err := applyEditLine(working, trimmed); err != nil {
				return fmt.Errorf("merge: %w", err)
			}
		}
	}

	config.StampChangedEventPlantClasses(s.candidate, working, plantClass)
	s.candidate = working
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// applyEditLine parses a single flat command line and applies the correct
// edit to tree based on its verb (#2008 H1): set, delete, deactivate, or
// activate. Centralizing the verb switch keeps every flat-line replay path
// (LoadMerge flat + hierarchical-via-FormatSet, LoadSet) in agreement, so
// `show | display set` output — which emits `deactivate <path>` for inactive
// nodes — round-trips back to an inactive node instead of being skipped (and
// reloaded active) or parsed as a junk path literally starting "deactivate".
// hasFlatVerb reports whether a line begins with one of the flat config-edit
// verbs that applyEditLine can actually replay (set/delete/deactivate/
// activate) followed by at least one path token. It delegates to the shared
// predicate in pkg/config so the service-mode load paths and their
// authorization gate classify every body identically (#10305).
//
// The first token is matched after splitting on any whitespace, so a tab
// between the verb and path is accepted by the same rule as the lexer.
func hasFlatVerb(line string) bool {
	return config.IsFlatLoadLine(line)
}

func applyEditLine(tree *config.ConfigTree, line string) error {
	// #15718: annotate lines carry a quoted comment ParseSetVerb would
	// fold into the path; split them with the canonical annotate parser.
	// A single trailing ';' (the hierarchical transcript spelling) is
	// stripped first. A ';' anywhere else makes the line malformed here:
	// the lenient annotate lexer would silently drop the tail, applying
	// only the gated prefix (#15167 class).
	annLine := strings.TrimSpace(line)
	annTrim := strings.TrimSuffix(annLine, ";")
	if strings.HasPrefix(annLine, "annotate ") || annLine == "annotate" {
		if strings.Contains(annTrim, ";") {
			return fmt.Errorf("invalid annotate command")
		}
		path, comment, ok := config.ParseAnnotateCommand(annTrim)
		if !ok {
			return fmt.Errorf("invalid annotate command")
		}
		if err := config.ValidateAnnotationText(comment); err != nil {
			return err
		}
		return tree.AnnotatePath(path, comment)
	}
	verb, path, quoted, grouped, closed, err := config.ParseSetVerbGroupedClosed(line)
	if err != nil {
		return err
	}
	switch verb {
	case "delete":
		return tree.DeletePathGrouped(path, grouped)
	case "deactivate":
		return tree.DeactivatePathGrouped(path, grouped)
	case "activate":
		return tree.ActivatePathGrouped(path, grouped)
	default: // "set" (or a bare, unprefixed path)
		return tree.SetPathQuotedGrouped(path, quoted, grouped, closed)
	}
}

// loadLineError is the scrubbed form of a flat-load line failure (#14718).
// It retains only the physical line coordinate — the same discipline
// rescueParseError applies to rescue files — because the raw line and
// the inner tree/parse errors can carry file-owned secrets (a denied
// class whose `show configuration` is redacted under #4099 must not
// recover denied lines one error at a time). The cause category is
// fixed text, never input-derived.
type loadLineError struct{ cause string }

func (e loadLineError) Error() string { return e.cause }

func scrubLoadLineError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, config.ErrPathNotFound) {
		return loadLineError{cause: "path not found"}
	}
	return loadLineError{cause: "invalid set/delete/deactivate/activate/annotate command"}
}

// LoadSet applies multiple flat command lines to the candidate config.
// Each line starting with a recognized verb — set, delete, deactivate, or
// activate (#2008 H1) — is parsed and applied. Blank lines and `#` comments
// are skipped; any other non-empty line is rejected with a line-numbered
// error (#3442 M4 — silently skipping a malformed line, e.g. "sett system
// host-name fw", let an operator commit a config missing the intended
// command). The deactivate/activate verbs make `show | display set` output
// round-trippable: previously a `deactivate <path>` line was skipped here,
// so an inactive node reloaded ACTIVE.
// LoadSet applies multiple flat command lines to the candidate config.
// Each line starting with a recognized verb — set, delete, deactivate, or
// activate (#2008 H1) — is parsed and applied. Blank lines and `#` comments
// are skipped; any other non-empty line is rejected with a line-numbered
// error (#3442 M4).
func (s *Store) LoadSet(content string) (int, error) { return s.LoadSetAs("", content) }

// LoadSetAs is LoadSet scoped to a config-lock holder session (#5059).
func (s *Store) LoadSetAs(sessionID, content string) (int, error) {
	return s.LoadSetAsPlantClass(sessionID, "", content)
}

// LoadSetAsPlantClass binds the authenticated planting class atomically with
// the complete flat-script candidate mutation.
func (s *Store) LoadSetAsPlantClass(sessionID, plantClass, content string) (int, error) {
	if err := checkConfigSize(content); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return 0, err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return 0, err
	}
	if s.candidate == nil {
		return 0, fmt.Errorf("not in configuration mode")
	}
	// #14145: route through the same shared classifier the authorization
	// gate uses, so the store applies exactly the representation that was
	// adjudicated. Before, this replayed the RAW lines while the gate
	// adjudicated its own comment-stripped view; a mid-token '[/*' opened
	// a fictitious comment in the gate's scanner (the real lexer keeps
	// '[', '/' and '*' inside an identifier), the gate adjudicated zero
	// lines, and this raw replay applied the hidden denied lines. A
	// classifier error (unterminated block comment) is refused here too,
	// as LoadMerge/LoadOverride already do.
	_, flatContent, err := config.ClassifyLoadContent(content)
	if err != nil {
		return 0, fmt.Errorf("parse error: %w", err)
	}
	working := s.candidate.Clone()
	count := 0
	for i, line := range strings.Split(flatContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// #3442 M4: a non-blank, non-comment line that is not a recognized
		// verb is malformed input (e.g. "sett system host-name fw"). Previously
		// LoadSet silently `continue`d on it, so REST/gRPC/CLI returned OK while
		// dropping the intended command — the operator could commit a config
		// missing it. Fail with a line-numbered error instead.
		if !hasFlatVerb(line) {
			return count, fmt.Errorf("line %d: is not a set/delete/deactivate/activate/annotate command", i+1)
		}
		if err := applyEditLine(working, line); err != nil {
			return count, fmt.Errorf("line %d: %w", i+1, scrubLoadLineError(err))
		}
		count++
	}
	config.StampChangedEventPlantClasses(s.candidate, working, plantClass)
	s.candidate = working
	s.touchConfigLockLocked()       // #4476: refresh the config-lock idle lease
	s.bumpCandidateMutationLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return count, nil
}
