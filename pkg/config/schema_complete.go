package config

import "strings"

// ValueHint identifies what kind of dynamic value is expected at a schema position.
type ValueHint int

const (
	ValueHintNone          ValueHint = iota
	ValueHintZoneName                // security-zone <name>
	ValueHintAddressName             // address-set <name>
	ValueHintAppName                 // application <name>
	ValueHintPoolName                // pool <name>
	ValueHintInterfaceName           // interfaces <name>
	ValueHintScreenProfile           // ids-option <name>
	ValueHintStreamName              // stream <name>
	ValueHintAppSetName              // application-set <name>
	ValueHintUnitNumber              // unit <number>
	ValueHintPolicyAddress           // policy match source/destination-address
	ValueHintPolicyApp               // policy match application (any + apps)
	ValueHintPolicyName              // policy <name> (from path context)
)

// SchemaCompletion is a completion candidate from the config schema.
type SchemaCompletion struct {
	Name string
	Desc string
}

// ValueProvider returns possible values for a given hint.
// The path parameter provides consumed tokens for context (e.g., interface name for unit completion).
type ValueProvider func(hint ValueHint, path []string) []SchemaCompletion

// CompleteSetPath returns possible completions for a partial set/delete path.
// It walks setSchema consuming tokens; at the current position it returns
// child keyword names. If the current position expects a dynamic argument
// (wildcard or args > 0), it returns nil (user must type a name).
func CompleteSetPath(tokens []string) []string {
	results := CompleteSetPathWithValues(tokens, nil)
	if results == nil {
		return nil
	}
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}
	return names
}

// appendTypedValueCompletions appends a typed leaf's placeholder and
// example values to the completion list for its empty value slot (#1319).
// For a non-typed node it returns the input unchanged, so callers can use
// it unconditionally. The placeholder (e.g. "<rate>") is added first when
// the leaf has no schema-level placeholder of its own, followed by each
// configured example value. Examples are illustrative completions, NOT the
// only acceptable inputs — the leaf's validator owns acceptance.
func appendTypedValueCompletions(results []SchemaCompletion, node *schemaNode) []SchemaCompletion {
	if !node.isTypedLeaf() {
		return results
	}
	// Only inject the typed placeholder when the node didn't already supply
	// one via the schema-level `placeholder` field (the provider/placeholder
	// branches above already prepended that). This keeps a single
	// angle-bracket token in the output.
	if node.placeholder == "" {
		if ph := node.valueType.Placeholder(); ph != "" {
			results = append(results, SchemaCompletion{Name: ph, Desc: node.valueDesc})
		}
	}
	for _, ex := range node.valueExamples {
		results = append(results, SchemaCompletion{Name: ex, Desc: node.valueDesc})
	}
	return results
}

// appendTypedKeyCompletions is the typed-KEY-slot counterpart of
// appendTypedValueCompletions (#1319 PR 3): a named-instance container
// whose identity token is typed (keyValidator set, e.g. `family inet
// address <cidr>`) surfaces its key placeholder + examples at the empty
// identity slot. No-op for nodes without key-slot metadata.
func appendTypedKeyCompletions(results []SchemaCompletion, node *schemaNode) []SchemaCompletion {
	if node == nil || node.keyValueType == ValueAny {
		return results
	}
	if node.placeholder == "" {
		if ph := node.keyValueType.Placeholder(); ph != "" {
			results = append(results, SchemaCompletion{Name: ph, Desc: node.keyValueDesc})
		}
	}
	for _, ex := range node.keyValueExamples {
		results = append(results, SchemaCompletion{Name: ex, Desc: node.keyValueDesc})
	}
	return results
}

// strictConsumedStep is one identity consumed by walkStrictConsumedTokens:
// the schema node it resolved to, its resolved keyword (unique-prefix
// expanded; verbatim for a wildcard fallback), and the token range
// [start, end) it spans — keyword + args plus a compoundKey sub-token.
// A truncated final step records end == len(tokens) (its identity counts
// even though the arg span runs past the input).
type strictConsumedStep struct {
	node       *schemaNode
	keyword    string
	subKeyword string // resolved compoundKey sub-token ("" when none)
	start      int
	end        int
}

// strictWalkRules carries ResolveConsumed's strictness over the shared
// kernel (#16149): the strict walks intentionally agree on descent
// mechanics (keyword lookup, wildcard fallback, arg span, compoundKey
// descent, multi re-offer) and intentionally diverge on exactly one
// strictness knob — see TestStrictWalkDivergence16149.
type strictWalkRules struct {
	// requireUniquePrefix fails the walk immediately when a keyword or
	// compoundKey sub-token resolves by neither exactly one prefix
	// match nor the level's wildcard fallback. ResolveConsumed sets
	// this (ambiguous/unknown consumed tokens cannot be expanded);
	// the edit-identity walk leaves it false (such a token merely
	// stops segmentation). Note the fallback ordering: at a wildcard
	// level even this strictest caller accepts the verbatim token
	// without prefix checks — the mutant-defended legacy behavior
	// TestStrictWalkAgreement16149 pins.
	requireUniquePrefix bool
}

// strictWalkOutcome reports how walkStrictConsumedTokens terminated.
type strictWalkOutcome int

const (
	// strictWalkComplete: every token was consumed by some step.
	strictWalkComplete strictWalkOutcome = iota
	// strictWalkStopped: a token resolved to no child (or, when
	// requireUniquePrefix, not uniquely); tokens from that point on
	// were not consumed. With requireUniquePrefix ok is false.
	strictWalkStopped
	// strictWalkTruncated: the final step's span ran past the input;
	// the step is recorded with end clamped to len(tokens).
	strictWalkTruncated
)

// walkStrictConsumedTokens is the shared strict consumed/identity token
// walk (#16149 W2.3 R2): it segments tokens against setSchema exactly
// the way ResolveConsumedSetPathTokens and the edit-identity walk do —
// exact/unique-prefix keyword lookup, wildcard fallback, 1+args span,
// compoundKey sub-token descent (itself unique-prefix resolved), and
// multi-with-no-children staying at the current level.
//
// Returns: steps (one per consumed identity, start/end spanning the raw
// token indices it consumed), outcome, and ok. ok is false only under
// requireUniquePrefix, when a strict failure was hit; otherwise the
// caller interprets outcome itself.
//
// CompleteSetPathWithValues is deliberately NOT built on this kernel:
// it handles partial terminal keywords and early value suggestions
// (non-strict), so it stays separate until a divergence census
// characterizes its strict prefix cleanly (#16149 narrowed form).
func walkStrictConsumedTokens(tokens []string, rules strictWalkRules) (steps []strictConsumedStep, outcome strictWalkOutcome, ok bool) {
	schema := setSchema
	i := 0
	for i < len(tokens) {
		if schema == nil {
			return steps, strictWalkStopped, true
		}
		keyword := tokens[i]
		resolvedKeyword := keyword
		var child *schemaNode
		if schema.children != nil {
			if s, ok := schema.children[keyword]; ok {
				child = s
			} else {
				var matches []string
				for name := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) == 1 {
					resolvedKeyword = matches[0]
					child = schema.children[resolvedKeyword]
				}
			}
		}
		if child == nil && schema.wildcard != nil {
			child = schema.wildcard
		}
		if child == nil {
			if rules.requireUniquePrefix {
				return nil, strictWalkStopped, false
			}
			return steps, strictWalkStopped, true
		}
		start := i
		i += 1 + child.args

		// Compound key: consume child token as part of the key,
		// unique-prefix resolving the sub-token just like a keyword.
		resolvedSub := ""
		if child.compoundKey && i < len(tokens) {
			subKeyword := tokens[i]
			if sub, ok := child.children[subKeyword]; ok {
				resolvedSub = subKeyword
				i++
				child = sub
			} else {
				var matches []string
				for name := range child.children {
					if strings.HasPrefix(name, subKeyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) == 1 {
					resolvedSub = matches[0]
					i++
					child = child.children[matches[0]]
				} else if rules.requireUniquePrefix {
					return nil, strictWalkStopped, false
				}
			}
		}

		truncated := i > len(tokens)
		end := i
		if truncated {
			end = len(tokens)
		}
		steps = append(steps, strictConsumedStep{node: child, keyword: resolvedKeyword, subKeyword: resolvedSub, start: start, end: end})
		if truncated {
			return steps, strictWalkTruncated, true
		}

		if child.multi && child.children == nil {
			continue
		}
		schema = child
	}
	return steps, strictWalkComplete, true
}

// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
// to suggest dynamic values at positions where schema expects a name argument.
// Returns SchemaCompletion pairs with names and descriptions.
func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion {
	schema := setSchema
	i := 0
	var path []string // consumed tokens for context

	for i < len(tokens) {
		if schema == nil {
			return nil
		}
		if schema.children == nil && schema.wildcard == nil {
			return nil // at a leaf with no further options
		}

		keyword := tokens[i]

		// Look up keyword in current schema level.
		var childSchema *schemaNode
		resolvedKeyword := keyword
		if schema.children != nil {
			if s, ok := schema.children[keyword]; ok {
				childSchema = s
			} else {
				var matches []string
				for name := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) == 1 && i < len(tokens)-1 {
					resolvedKeyword = matches[0]
					childSchema = schema.children[resolvedKeyword]
				} else if len(matches) > 0 && i == len(tokens)-1 {
					var completions []SchemaCompletion
					for _, name := range matches {
						completions = append(completions, SchemaCompletion{Name: name, Desc: schema.children[name].desc})
					}
					return completions
				}
			}
		}
		if childSchema == nil && schema.wildcard != nil {
			childSchema = schema.wildcard
		}
		if childSchema == nil {
			// Last token might be a partial prefix — return matching keywords.
			if i == len(tokens)-1 && schema.children != nil {
				var matches []SchemaCompletion
				for name, node := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, SchemaCompletion{Name: name, Desc: node.desc})
					}
				}
				if len(matches) > 0 {
					return matches
				}
			}
			return nil // unknown keyword, no completions
		}

		// Consume keyword + extra args.
		nodeKeyCount := 1 + childSchema.args
		end := i + nodeKeyCount
		if end > len(tokens) {
			end = len(tokens)
		}
		path = append(path, resolvedKeyword)
		if end-i > 1 {
			path = append(path, tokens[i+1:end]...)
		}
		i += nodeKeyCount

		// Compound key: consume child token as part of key.
		if childSchema.compoundKey && i < len(tokens) {
			if sub, ok := childSchema.children[tokens[i]]; ok {
				path = append(path, tokens[i])
				i++
				childSchema = sub
			}
		}

		if i > len(tokens) {
			// Still consuming args for this node — user needs to type a value.
			startIdx := i - nodeKeyCount
			consumed := end - startIdx // tokens consumed for this node (including keyword)

			// Check for fixed keyword in the middle of args (e.g., "to-zone" in "from-zone X to-zone Y").
			if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
				nextPos := consumed // 0-indexed position to complete next (0=keyword, 1=arg1, ...)
				// If the last consumed token is a partial match for the midKeyword, suggest it.
				if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
					lastToken := tokens[end-1]
					if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
					}
				}
				// If we need to complete the midKeyword position, suggest it.
				if nextPos == childSchema.midKeywordAt {
					return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
				}
			}

			// Try to provide dynamic values via the provider.
			if provider != nil && childSchema.valueHint != ValueHintNone {
				results := provider(childSchema.valueHint, path)
				// Add placeholder if available.
				if childSchema.placeholder != "" {
					results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
				}
				// Typed-value/key examples are additive to dynamic provider
				// results (#1319).
				return appendTypedKeyCompletions(appendTypedValueCompletions(results, childSchema), childSchema)
			}
			// No provider but have a placeholder — show it.
			if childSchema.placeholder != "" {
				return appendTypedKeyCompletions(appendTypedValueCompletions(
					[]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}},
					childSchema,
				), childSchema)
			}
			// #1319: a typed leaf with no valueHint/placeholder surfaces its
			// own placeholder + example values at the empty value slot. This
			// is the symptom-1 fix that reaches the live config-mode `set`
			// completer (e.g. `set ... transmit-rate ?` → <rate> + examples).
			if childSchema.isTypedLeaf() {
				return appendTypedValueCompletions(nil, childSchema)
			}
			// #1319 PR 3: a typed KEY slot (named-instance container with a
			// validated identity token, e.g. `family inet address ?`)
			// surfaces its key placeholder + examples the same way.
			if childSchema.keyValueType != ValueAny {
				return appendTypedKeyCompletions(nil, childSchema)
			}
			return nil
		}

		if childSchema.multi && childSchema.children == nil {
			// Stay at current schema level so sibling keywords are offered.
		} else {
			schema = childSchema
		}
	}

	// We've consumed all tokens. Return child keywords at this schema level.
	if schema == nil {
		return nil
	}

	// If we're at a leaf with no children/wildcard, hint that Enter completes.
	if schema.children == nil && schema.wildcard == nil {
		return []SchemaCompletion{{Name: "<[Enter]>", Desc: "Execute this command"}}
	}

	var completions []SchemaCompletion
	if schema.children != nil {
		for name, node := range schema.children {
			completions = append(completions, SchemaCompletion{Name: name, Desc: node.desc})
		}
	}
	// If this level accepts a wildcard name, provide dynamic values too.
	if schema.wildcard != nil {
		if provider != nil && schema.wildcard.valueHint != ValueHintNone {
			completions = append(completions, provider(schema.wildcard.valueHint, path)...)
		}
		// Add placeholder.
		if schema.wildcard.placeholder != "" {
			completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
		}
	}
	if len(completions) == 0 {
		return nil
	}
	return completions
}

// ResolveConsumedSetPathTokens expands uniquely matching keyword prefixes in a
// token list that is already known to contain only consumed words, not the
// current partial token being completed.
func ResolveConsumedSetPathTokens(tokens []string) ([]string, bool) {
	steps, _, ok := walkStrictConsumedTokens(tokens, strictWalkRules{requireUniquePrefix: true})
	if !ok {
		return nil, false
	}
	var resolved []string
	for _, step := range steps {
		resolved = append(resolved, step.keyword)
		// span = keyword + args + optional compoundKey sub-token.
		// Args are verbatim; a compound sub-token is prefix-expanded.
		// node is the POST-compound node, so the sub-token position
		// is derived from the span (last token of the step), not
		// from node.args.
		if step.subKeyword != "" {
			subAt := step.end - 1
			if subAt > step.start+1 {
				resolved = append(resolved, tokens[step.start+1:subAt]...)
			}
			resolved = append(resolved, step.subKeyword)
		} else if step.end-step.start > 1 {
			resolved = append(resolved, tokens[step.start+1:step.end]...)
		}
	}
	return resolved, true
}

// keyword + its args, plus a compoundKey sub-token) from editPath,
// so `up` from `[edit security zones security-zone trust]` lands at
// `[edit security zones]` (#15237 A53-02). A flat per-token pop
// instead left the dangling keyword `security-zone`, and the next
// `set` staged a zone literally named after the following token.
// A cursor whose last identity the schema cannot segment (unknown
// trailing tokens) drops just its last token, and a wholly unknown
// cursor also drops one token — fail-safe navigation, never a
// panic. Returns nil at the root.
func PopEditPathIdentity(editPath []string) []string {
	if len(editPath) == 0 {
		return nil
	}
	starts := editIdentityStarts(editPath)
	if len(starts) == 0 {
		if len(editPath) <= 1 {
			return nil
		}
		return append([]string(nil), editPath[:len(editPath)-1]...)
	}
	last := starts[len(starts)-1]
	consumed := editIdentityConsumed(editPath)
	if consumed < len(editPath) {
		return append([]string(nil), editPath[:len(editPath)-1]...)
	}
	if last <= 0 {
		return nil
	}
	out := append([]string(nil), editPath[:last]...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// TruncateEditPathIdentities keeps the first n schema identities of
// editPath (`up n` / exit-as-up). n<=0 yields the root; an over-large
// n or an unresolvable cursor yields the root (clamped, as Junos
// clamps up past the top).
func TruncateEditPathIdentities(editPath []string, n int) []string {
	if n <= 0 || len(editPath) == 0 {
		return nil
	}
	starts := editIdentityStarts(editPath)
	if n >= len(starts) {
		if len(starts) > 0 && n == len(starts) {
			return append([]string(nil), editPath...)
		}
		return nil
	}
	out := append([]string(nil), editPath[:starts[n]]...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// PopEditPathAfterTruncate truncates to keepCount identities then
// pops one more (nil when keepCount covers the whole cursor).
func PopEditPathAfterTruncate(editPath []string, keepCount int) []string {
	base := TruncateEditPathIdentities(editPath, keepCount)
	return PopEditPathIdentity(base)
}

// editIdentityConsumed returns how many leading tokens of editPath
// the identity walk consumed (len(editPath) when fully segmented, or
// when a truncated final identity's span runs past the input).
func editIdentityConsumed(editPath []string) int {
	steps, _, _ := walkStrictConsumedTokens(editPath, strictWalkRules{})
	if len(steps) == 0 {
		return 0
	}
	return steps[len(steps)-1].end
}

// editIdentityStarts returns the token index at which each schema
// identity (node) in editPath begins, walking setSchema exactly as
// ResolveConsumedSetPathTokens does (args + compoundKey) but tolerantly:
// it shares the strict token-walk kernel (#16149) without
// requireUniquePrefix, so an ambiguous or unknown token stops
// segmentation instead of failing. A truncated final identity still
// counts (its start is recorded). An unknown token stops the walk;
// tokens past it form no further identities.
func editIdentityStarts(editPath []string) []int {
	steps, _, _ := walkStrictConsumedTokens(editPath, strictWalkRules{})
	var starts []int
	for _, step := range steps {
		starts = append(starts, step.start)
	}
	return starts
}

// QuoteConfigPathToken renders one resolved path token for re-joining
// onto a wire line: a token containing whitespace (or that would not
// re-lex as itself) is quoted so the daemon's lexer recovers it as
// ONE token with its interior spacing intact (#15237 A53-07).
func QuoteConfigPathToken(tok string) string {
	return quoteKey(tok)
}

// JoinConfigPathTokens joins resolved path tokens for a wire line,
// quoting any token that needs it (see QuoteConfigPathToken).
func JoinConfigPathTokens(toks []string) string {
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = quoteKey(t)
	}
	return strings.Join(parts, " ")
}
