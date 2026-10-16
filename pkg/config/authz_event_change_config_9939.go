package config

import (
	"fmt"
	"strings"
)

// #9939/#9984: an `event-options policy … then change-configuration commands
// "…"` payload is DATA at authoring time and executable only after two gates:
// the planting request is adjudicated against the authenticated class, and
// the resulting policy record stores that class for fire-time revalidation.
//
// The event engine applies embedded `set`/`delete` operations with its internal
// commit authority, but before any candidate mutation it resolves the recorded
// class from the active login configuration and evaluates every target through
// the same evaluator. Missing, deleted, or denied metadata quarantines the
// payload, so a routine event cannot turn a class denied `security policies`
// into an autonomous root deletion.
//
// The marker is stamped atomically by every config mutation that changes the
// effective event payload, including set/delete, load, copy/rename, rollback,
// and group-derived changes. Trusted root/system writers use the explicit
// `super-user` marker. Payloads persisted before #9984 have no marker and are
// intentionally refused at fire time with an operator-visible fault.

// changeConfigRecursionLimit9939 bounds the payload walk.
//
// A payload may itself plant another `change-configuration`, and an operator who
// writes that deserves each level adjudicated — but a bound is cheaper than
// reasoning about whether the lexer can produce a cycle, and two levels is
// already past anything anyone writes deliberately.
const changeConfigRecursionLimit9939 = 4

// embeddedChangeConfigCommands9939 returns the command lines carried by a
// `change-configuration commands` payload on this line, or nil.
//
// The token boundary is the SAME rule `eventChangeConfigCommands` applies when
// the compiler reads the stanza (#6659): a QUOTED value is one command per
// token, an UNQUOTED tail is a single command that must be re-joined. Using a
// different rule here would adjudicate a command the engine never runs, or miss
// one it does — the #9938 defect, one layer in.
func embeddedChangeConfigCommands9939(parts []string, quoted []bool) []string {
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] != "change-configuration" || parts[i+1] != "commands" {
			continue
		}
		tail := parts[i+2:]
		if len(tail) == 0 {
			return nil
		}
		if len(quoted) == len(parts) && quoted[i+2] {
			return append([]string(nil), tail...)
		}
		return []string{strings.Join(tail, " ")}
	}
	return nil
}

// authorizeEmbeddedChangeConfig9939 adjudicates every command a payload on this
// line carries, against the planting class's own regexes.
//
// The payload is located on the RESOLVED path (#14143), not the typed
// fragment: `authorizeConfigMutationDepth9939` resolves `editPath` into the
// outer paths it adjudicates, and the store prepends the same cursor before
// it writes, so scanning only the typed parts misses every payload planted
// from inside the stanza. An operator who has done
// `edit event-options policy p then change-configuration` and types
// `set commands "set system …"` carries no `change-configuration` token in
// the typed line at all — the ancestors live only in the cursor. The scan
// therefore runs over editPath+parts, with quoted provenance padded for the
// (never quoted) cursor elements.
//
// copy/rename carry no payload text on the line: the commands they plant
// already exist in the candidate under the source subtree, and both
// endpoints are adjudicated as paths by configMutationPaths. What moves is
// re-stamped to the mover's class by StampChangedEventPlantClasses and
// re-adjudicated command-by-command at fire time
// (eventengine.validatePlantClass), so no payload text exists here to scan
// and none is fabricated from the endpoint names.
func authorizeEmbeddedChangeConfig9939(cfg *Config, class string, editPath, parts []string, quoted []bool, depth int) error {
	if depth >= changeConfigRecursionLimit9939 {
		// Refuse rather than allow. A payload nested deeper than anyone writes
		// on purpose is not something to wave through because the walk ran out
		// of budget — "we stopped looking" must not read as "we found nothing".
		return fmt.Errorf("permission denied: login class %q plants a change-configuration payload "+
			"nested deeper than %d levels, which cannot be adjudicated",
			class, changeConfigRecursionLimit9939)
	}
	// #14143: the payload marker is located on the RESOLVED path, but for
	// copy/rename the resolved endpoints are the payload's LOCATION, not its
	// text — the destination words after `commands` (a policy name, a `to`
	// separator) are not commands. Scanning them would adjudicate a command
	// the engine never runs, so those verbs return here: their moved
	// commands are re-stamped and fire-time re-adjudicated (see above).
	if parts[0] == "copy" || parts[0] == "rename" {
		return nil
	}
	resolved := parts
	resolvedQuoted := quoted
	if len(editPath) > 0 && len(parts) > 0 {
		// Resolve exactly as configMutationPaths and the store do: cursor +
		// typed path WITHOUT the verb. Keeping the verb would interleave it
		// between the cursor's `change-configuration` and the typed
		// `commands`, and the adjacent-pair scan would walk past the payload.
		resolved = make([]string, 0, len(editPath)+len(parts)-1)
		resolved = append(resolved, editPath...)
		resolved = append(resolved, parts[1:]...)
		resolvedQuoted = make([]bool, len(editPath))
		if len(quoted) == len(parts) {
			resolvedQuoted = append(resolvedQuoted, quoted[1:]...)
		} else {
			resolvedQuoted = append(resolvedQuoted, quoted...)
		}
	}
	for _, cmd := range embeddedChangeConfigCommands9939(resolved, resolvedQuoted) {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		if err := authorizeConfigMutationDepth9939(cfg, class, nil, cmd, depth+1); err != nil {
			// The inner error already names the class and the denied path's
			// ROOT only, under the same audit rule — so it is safe to wrap, and
			// wrapping is what tells the operator WHY a line about
			// `event-options` was refused for a path that is not under it.
			return fmt.Errorf("%w — planted as a `then change-configuration` payload, which the "+
				"daemon would apply with internal (root) authority (#9939)", err)
		}
	}
	return nil
}
