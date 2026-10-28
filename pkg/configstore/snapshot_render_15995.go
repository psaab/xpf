package configstore

import (
	"github.com/psaab/xpf/pkg/config"
)

// snapshot_render_15995.go renders FROM caller-supplied tree snapshots.
//
// #15995 fold (Codex C4): the descendant-pricing gates snapshot the
// rendered trees under one store-lock acquisition (ShowConfigTrees /
// CompareTrees / RollbackCompareTrees / RollbackTree now deep-copy).
// Authorization is only meaningful for the generation that is actually
// rendered, so every surface that prices a scoped read renders from the
// SAME snapshot it priced — never re-resolving the target in the store,
// where a concurrent candidate edit (in-place under the store lock) or
// commit could swap the generation between gate and render (and race
// the gate's unlocked walk). These helpers are the render half of that
// contract; each mirrors the nil-source default of its store sibling.

// RenderShowRedacted renders one snapshot tree at path in the named
// format ("text"/"set"/"json"/"xml"), mirroring ShowActiveRedacted /
// ShowCandidateRedacted and their format siblings: a nil tree renders
// the same empty/default output the store methods produce for a missing
// candidate at that path shape.
func RenderShowRedacted(tree *config.ConfigTree, path []string, format string) string {
	if tree == nil {
		switch format {
		case "json":
			if len(path) == 0 {
				return "{}\n"
			}
		case "xml":
			if len(path) == 0 {
				return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n</configuration>\n"
			}
		}
		return ""
	}
	switch format {
	case "set":
		return tree.FormatPathSetRedacted(path)
	case "json":
		return tree.FormatPathJSONRedacted(path)
	case "xml":
		return tree.FormatPathXMLRedacted(path)
	default:
		return tree.FormatPathRedacted(path)
	}
}

// RenderShowCleartext is RenderShowRedacted without secret masking, for
// the privileged CLI path (super-user / no-RBAC class) that today reads
// the cleartext Show* siblings.
func RenderShowCleartext(tree *config.ConfigTree, path []string, format string) string {
	if tree == nil {
		switch format {
		case "json":
			if len(path) == 0 {
				return "{}\n"
			}
		case "xml":
			if len(path) == 0 {
				return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n</configuration>\n"
			}
		}
		return ""
	}
	switch format {
	case "set":
		return tree.FormatPathSet(path)
	case "json":
		return tree.FormatPathJSON(path)
	case "xml":
		return tree.FormatPathXML(path)
	default:
		if len(path) == 0 {
			return tree.Format()
		}
		return tree.FormatPath(path)
	}
}

// RenderShowInheritanceRedacted renders one snapshot tree at path with
// inheritance annotations, exactly as the store inheritance renderers
// do for nodeID (they expand a clone of the tree; the snapshot is
// cloned again inside expandForInheritance, so it is never mutated).
func RenderShowInheritanceRedacted(tree *config.ConfigTree, path []string, nodeID int) (string, error) {
	if tree == nil {
		return "", nil
	}
	return tree.FormatPathInheritanceRedactedForNode(path, nodeID)
}

// RenderShowInheritanceCleartext is the cleartext inheritance twin.
func RenderShowInheritanceCleartext(tree *config.ConfigTree, path []string, nodeID int) (string, error) {
	if tree == nil {
		if len(path) == 0 {
			return "", nil
		}
		return "", nil
	}

	if len(path) == 0 {
		return tree.FormatInheritanceForNode(nodeID)
	}
	return tree.FormatPathInheritanceForNode(path, nodeID)
}

// RenderCompareRedacted diffs two snapshot arms at path (redacted),
// mirroring ShowCompareRedactedAtPath: no candidate arm renders "[no
// changes]" only when a candidate exists — callers that know there is
// no candidate pass hasCandidate=false and get "".
func RenderCompareRedacted(oldTree, newTree *config.ConfigTree, path []string, hasCandidate bool) string {
	if !hasCandidate {
		return ""
	}
	diff := config.FormatCompareRedactedAtPath(oldTree, newTree, path)
	if diff == "" {
		return "[no changes]\n"
	}
	return diff
}

// RenderCompareCleartext is the cleartext compare twin.
func RenderCompareCleartext(oldTree, newTree *config.ConfigTree, path []string, hasCandidate bool) string {
	if !hasCandidate {
		return ""
	}
	diff := config.FormatCompareAtPath(oldTree, newTree, path)
	if diff == "" {
		return "[no changes]\n"
	}
	return diff
}

// RenderRollbackRedacted renders one rollback snapshot tree at path in
// the named format, mirroring the ShowRollback*RedactedPath family.
func RenderRollbackRedacted(tree *config.ConfigTree, path []string, format string) string {
	return RenderShowRedacted(tree, path, format)
}

// RenderRollbackInheritanceRedacted renders one rollback snapshot tree
// at path with inheritance annotations.
func RenderRollbackInheritanceRedacted(tree *config.ConfigTree, path []string, nodeID int) (string, error) {
	return RenderShowInheritanceRedacted(tree, path, nodeID)
}

// The rollback slot error travels inside RollbackCapture.Err
// (#17215): gates price a nil Slot as "renders nothing", handlers
// surface capture.Err before rendering — no second live-store read
// re-derives it.
