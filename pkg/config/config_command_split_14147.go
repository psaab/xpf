package config

// #14147: the config-mutation authorization gate and the copy/rename/
// insert executors tokenized the same line differently, so the gate
// adjudicated endpoints no executor acted on (and vice versa).
//
// The gate lexes with the config lexer (lexConfigMutationLine9938):
// quoted strings are unquoted and /* */ comments are stripped. Every
// executor split with strings.Fields instead: quotes stayed attached
// (`"to"` != `to`) and comment words stayed live. For
//
//	rename system services ssh "to" foo to system root-authentication
//
// the gate split at the quoted "to" (a string token whose value is
// `to`) and adjudicated src=`system services ssh`,
// dst=`foo to system root-authentication`, while strings.Fields kept
// `"to"` distinct, split at the second bare `to`, and the store
// renamed into `system root-authentication`. An allow-configuration of
// `^system services` admitted the gate's view and never saw the real
// destination. The same desync hid a denied insert element behind a
// quoted "before"/"after", and let comment words act as separators
// for the executors while the lexer had already stripped them.
//
// The split below is the ONE canonical parse for these verbs. It is
// built on the same lexer the gate uses, and a separator counts only
// when it was authored as a bare (unquoted) keyword token — a quoted
// "to" is a path element whose value happens to be `to`, exactly as
// the store's own lexer treats it. The gate (configMutationPaths) and
// every executor (gRPC, on-box CLI, remote CLI) call these functions,
// so the paths adjudicated are the paths acted on by construction.

// ConfigMutationVerb returns the lexed leading verb of a config-mode
// line when it is a gated mutation verb (set/delete/deactivate/
// activate/copy/rename/insert/annotate). Routing on this — rather
// than on a raw `strings.HasPrefix(input, "copy ")` / Fields split —
// keeps tab-separated and comment-bearing lines routed exactly as
// the gate adjudicated them (#14147, cf. #13628 for annotate).
func ConfigMutationVerb(line string) (verb string, ok bool) {
	tokens, _ := lexConfigMutationLine9938(line)
	if len(tokens) == 0 || !configMutationVerbs[tokens[0]] {
		return "", false
	}
	return tokens[0], true
}

// ParseInsertCommandTokens is ParseInsertCommand without the
// full-refPath construction: it returns the raw ref tokens after the
// keyword. Callers that must prefix an edit path onto the element
// BEFORE building the reference path (the on-box CLI) use this form
// and build the ref via InsertRefPath; callers acting on the resolved
// line (gRPC) use ParseInsertCommand. Both share splitInsertTokens,
// so the element/keyword boundary cannot drift (#14147).
func ParseInsertCommandTokens(line string) (elemPath, refTokens []string, before, ok bool) {
	tokens, quoted := lexConfigMutationLine9938(line)
	return splitInsertTokens(tokens, quoted)
}

// InsertRefPath builds the full reference path from an element path
// and its trailing ref tokens (ref replaces the element's trailing
// identifier, same parent). The caller must have validated
// len(refTokens) <= len(elemPath).
func InsertRefPath(elemPath, refTokens []string) []string {
	return insertRefPath(elemPath, refTokens)
}

// splitCopyRenameTokens splits lexed copy/rename tokens at the first
// BARE `to`. tokens[0] must already be `copy` or `rename`.
// Returns ok=false when the shape is not `<verb> <src...> to <dst...>`.
func splitCopyRenameTokens(tokens []string, quoted []bool) (src, dst []string, ok bool) {
	if len(tokens) == 0 || (tokens[0] != "copy" && tokens[0] != "rename") {
		return nil, nil, false
	}
	for i := 1; i < len(tokens); i++ {
		if tokens[i] == "to" && !quoted[i] {
			if i < 2 || i >= len(tokens)-1 {
				return nil, nil, false
			}
			return tokens[1:i], tokens[i+1:], true
		}
	}
	return nil, nil, false
}

// ParseCopyRenameCommand lexes line and splits it as
// `copy|rename <src...> to <dst...>`, where only a bare (unquoted)
// `to` is the separator. This is the split both the authorization
// gate and every copy/rename executor must use (#14147).
func ParseCopyRenameCommand(line string) (src, dst []string, ok bool) {
	tokens, quoted := lexConfigMutationLine9938(line)
	return splitCopyRenameTokens(tokens, quoted)
}

// splitInsertTokens splits lexed insert tokens at the first BARE
// `before`/`after`. tokens[0] must already be `insert`. refTokens are
// the tokens after the keyword (relative to the element's parent).
func splitInsertTokens(tokens []string, quoted []bool) (elem, refTokens []string, before, ok bool) {
	if len(tokens) == 0 || tokens[0] != "insert" {
		return nil, nil, false, false
	}
	for i := 1; i < len(tokens); i++ {
		if quoted[i] {
			continue
		}
		if tokens[i] != "before" && tokens[i] != "after" {
			continue
		}
		if i < 2 || i >= len(tokens)-1 {
			return nil, nil, false, false
		}
		return tokens[1:i], tokens[i+1:], tokens[i] == "before", true
	}
	return nil, nil, false, false
}

// insertRefPath builds the full reference path from an element path
// and its trailing ref tokens: the ref replaces the element's trailing
// identifier (same parent). Callers must have validated
// len(refTokens) <= len(elemPath).
func insertRefPath(elemPath, refTokens []string) []string {
	parent := elemPath[:len(elemPath)-len(refTokens)]
	ref := make([]string, 0, len(elemPath))
	ref = append(ref, parent...)
	ref = append(ref, refTokens...)
	return ref
}

// ParseInsertCommand lexes line and splits it as
// `insert <elem...> before|after <ref...>`, where only a bare
// (unquoted) keyword separates. It returns the element path and the
// FULL reference path (element parent + ref tokens), which is the
// pair every insert executor passes to the store (#14147).
func ParseInsertCommand(line string) (elemPath, refPath []string, before, ok bool) {
	tokens, quoted := lexConfigMutationLine9938(line)
	elem, refTokens, before, ok := splitInsertTokens(tokens, quoted)
	if !ok || len(refTokens) > len(elem) {
		return nil, nil, false, false
	}
	return elem, insertRefPath(elem, refTokens), before, true
}
