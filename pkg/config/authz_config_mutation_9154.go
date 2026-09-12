package config

import (
	"fmt"
	"strings"
)

// #9154: THE CONFIGURATION REGEXES WERE ENFORCED ON EXACTLY ONE OF THREE
// DISPATCH SURFACES.
//
// `allow-configuration` / `deny-configuration` were evaluated only by the on-box
// CLI. The gRPC listener the shipped `cli` binary speaks to, and the REST API,
// both performed config mutations without ever consulting them -- so an operator
// who withheld configuration authority from a class saw it withheld only if that
// person happened to log in at the console. The documented way to administer the
// box bypassed it.
//
// Measured, with the control that makes it a finding rather than a guess:
//
//	deny-configuration-only : authorizeRPCCommand(Set) -> nil       ALLOWED
//	deny-commands-only      : authorizeRPCCommand(Set) -> denied    the gate IS live
//
// The second row is what proves the machinery works and simply was not asked
// this question.
//
// SO THE DECISION LIVES HERE, in pkg/config, beside
// ConfigurationLoginRegexesFor. #7172 cut 6 moved the RESOLUTION here for
// exactly this reason -- "so this gate, the operational gate and the gRPC gate
// all read one implementation" -- and the decision stayed behind in pkg/cli,
// where the other two surfaces cannot reach it. A rule enforced by whichever
// caller remembers to call it is the shape that produced this defect.

// configMutationVerbs are the dispatchConfig verbs that CHANGE the candidate
// configuration and therefore carry a path to match.
//
// `edit`, `top` and `up` are deliberately absent: they move the cursor and
// change nothing. Entering a denied subtree is harmless because every mutation
// inside it is denied on its own, and gating navigation would also stop an
// operator merely LOOKING at a subtree they cannot edit.
//
// `commit`, `rollback` and `load` are absent for a different reason and are NOT
// covered by this gate — see configMutationPath.
var configMutationVerbs = map[string]bool{
	"set":        true,
	"delete":     true,
	"deactivate": true,
	"activate":   true,
	"copy":       true,
	"rename":     true,
	"insert":     true,
	"annotate":   true,
}

// configMutationPath returns the configuration path a verb will act on,
// resolved against the current edit path, and whether this verb is gated here.
//
// NOT GATED, and each for a stated reason rather than by omission:
//
//   - `edit`/`top`/`up` — navigation, no change (see configMutationVerbs).
//   - `commit`/`rollback` — they act on the candidate as a whole, not on a
//     path, so there is nothing for a path regex to match. A deny that stopped
//     `commit` would be denying the operator's own already-authorized edits.
//   - `load` — applies arbitrary config whose content is not known until it is
//     parsed, so enforcing deny-configuration against it means matching every
//     path the loaded content touches, which is a different mechanism from a
//     verb gate. Explicitly a REMAINING GAP rather than something this gate
//     quietly covers.
func configMutationPaths(editPath, parts []string, quoted []bool) ([]string, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	verb := parts[0]
	if !configMutationVerbs[verb] {
		return nil, false
	}
	if len(parts) < 2 {
		// The verb's own arity error is a better message than a permission
		// denial, and an empty path cannot match a meaningful deny anyway.
		return nil, false
	}
	// THE RESOLVED PATH, not the typed remainder. See the edit-path bypass note
	// above: matching parts[1:] alone lets `edit system` walk a deny.
	resolve := func(rel []string) string {
		full := make([]string, 0, len(editPath)+len(rel))
		full = append(full, editPath...)
		full = append(full, rel...)
		return strings.Join(full, " ")
	}

	// #9938 F-029: copy and rename act on TWO paths, and the gate used to join
	// them into one string (`<verb> <src> to <dst>`) that the dispatcher never
	// acts on. handleCopyRename / handleCopyRename's gRPC twin split at `to`
	// and call Copy/Rename with two REAL paths, so both endpoints are
	// adjudicated here, separately.
	//
	// It matters under an ANCHORED deny, which is the idiom Junos documents for
	// complex expressions: `^security policies p1$` does not match the joined
	// string in either direction, so `rename <denied> to <allowed>` and
	// `rename <allowed> to <denied>` were both permitted. An UNANCHORED deny
	// caught them incidentally, which is why this survived — the common case
	// hid the mechanism.
	switch verb {
	case "copy", "rename":
		toIdx := -1
		for i, p := range parts {
			if p == "to" {
				toIdx = i
				break
			}
		}
		if toIdx < 2 || toIdx >= len(parts)-1 {
			// MALFORMED — and the answer is the WHOLE REMAINDER, not "ungated".
			//
			// The dispatcher does print its own usage and act on nothing, so
			// "there is nothing to adjudicate" is a true statement about this
			// line. It is still the wrong answer, because it makes the gate's
			// coverage depend on the line PARSING, and the pre-#9938 gate
			// covered it. A change that adds precision must not remove
			// coverage: falling back keeps the old behaviour as a floor and
			// adds the two-endpoint split above it. Caught by
			// TestEveryFlatVerbIsTakenVerbatimNotReparsed9892, which is exactly
			// what that cell exists for.
			break
		}
		return []string{resolve(parts[1:toIdx]), resolve(parts[toIdx+1:])}, true

	case "insert":
		// `insert <element-path> before|after <ref>` moves the element; the ref
		// is a SIBLING identifier that is not itself mutated, and it lives under
		// the same parent, so a deny covering the element covers it.
		kwIdx := -1
		for i, p := range parts {
			if p == "before" || p == "after" {
				kwIdx = i
				break
			}
		}
		if kwIdx < 2 || kwIdx >= len(parts)-1 {
			break // malformed: fall back to the whole remainder, see above
		}
		return []string{resolve(parts[1:kwIdx])}, true

	case "annotate":
		// `annotate <path> "comment"`. The comment is dropped from the path, but
		// ONLY when it was actually written as a quoted string.
		//
		// Trimming the last token unconditionally is wrong and fails in the
		// silent direction: `annotate system root-authentication` has no comment,
		// so the trim leaves `system` and an anchored deny on
		// `^system root-authentication` stops matching. That is a coverage LOSS
		// introduced by a precision gain, which is why quote provenance is
		// carried out of the lexer rather than inferred from position.
		if len(parts) < 3 || !quoted[len(parts)-1] {
			break // no comment token: the whole remainder is the path
		}
		return []string{resolve(parts[1 : len(parts)-1])}, true
	}

	return []string{resolve(parts[1:])}, true
}

// lexConfigMutationLine9938 tokenizes a config-mode line THE WAY THE STORE DOES,
// with quotes consumed.
//
// #9938 F-020: this was `strings.Fields`, which keeps quote characters. The
// store lexes them away (`readString` returns the unquoted body, reached through
// ParseSetVerbGrouped -> SetPathQuoted), so `deactivate security "policies" p1`
// was GATED as `security "policies" p1` and APPLIED as `security policies p1`.
// A deny on the real path did not match the string the gate judged.
//
// Using the lexer rather than a quote-stripping pass is deliberate: the defect
// is that the gate had its own idea of tokenization, and a second
// almost-the-same tokenizer is the same defect with a smaller diff. It also
// makes `annotate`'s trailing comment one token, which is what lets the path be
// extracted without a second parse.
func lexConfigMutationLine9938(line string) (tokens []string, quoted []bool) {
	lex := NewLexer(line)
	for {
		tok := lex.Next()
		switch tok.Type {
		case TokenEOF:
			return tokens, quoted
		case TokenIdentifier, TokenString:
			tokens = append(tokens, tok.Value)
			quoted = append(quoted, tok.Type == TokenString)
		default:
			// A brace or semicolon has no place in a flat config-mode line.
			// Stopping rather than skipping keeps the gate's view of the line a
			// PREFIX of what the dispatcher sees, never a different line.
			return tokens, quoted
		}
	}
}

// AuthorizeConfigMutation adjudicates one config-mode line against a class's
// `*-configuration` regexes, returning nil when the mutation is permitted.
//
// editPath is the operator's current `edit` cursor, or nil where the caller has
// already resolved it -- the remote CLI prepends its own edit path before
// sending, so the gRPC and REST surfaces pass nil and gate the line they will
// actually act on.
func AuthorizeConfigMutation(cfg *Config, class string, editPath []string, line string) error {
	if class == "" {
		return nil
	}
	parts, quoted := lexConfigMutationLine9938(line)
	paths, gated := configMutationPaths(editPath, parts, quoted)
	if !gated {
		return nil
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf(
			"permission denied: login class %q has an invalid configuration regex: %w",
			class, err)
	}
	if !ok {
		return nil
	}
	// #9938 F-029: EVERY acted-upon path is adjudicated, and the FIRST denial
	// refuses the whole command. A copy or rename that is permitted at one
	// endpoint and denied at the other must not run at all — half of it is
	// still a mutation of a path the class was denied.
	for _, path := range paths {
		decision := rules.Evaluate(path)
		if decision.Allowed {
			continue
		}
		// AUDIT: the VERB and the resolved path's leading element only. A config
		// path's trailing tokens are operator data — `set system root-authentication
		// plain-text-password <secret>` puts the secret in the path itself — so the
		// full path must never reach a log line. Cut 3's canonicalPrefix cannot be
		// reused: it walks the operational cmdtree, which config paths do not use.
		return fmt.Errorf("permission denied: login class %q denies %s under %q (%s)",
			class, parts[0], configAuditRoot(path), decision.Reason)
	}
	return nil
}

// configAuditRoot renders only the first element of a configuration path.
//
// One element is a deliberate floor rather than a tuned depth: any deeper and
// the rendering depends on knowing which level of which hierarchy holds a
// secret, and that knowledge does not exist here. `system` tells an operator
// which tree they were denied in without revealing what they set.
func configAuditRoot(path string) string {
	fields := strings.Fields(path)
	if len(fields) == 0 {
		return "<empty>"
	}
	return fields[0]
}
