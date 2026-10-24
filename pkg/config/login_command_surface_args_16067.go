package config

import "strings"

// #16067: the registered command sets are argument-free, but since
// #16067 the remote gates reconstruct the argument-bearing command
// (`show route table secret-vrf`, `ping 10.99.1.1`) and match patterns
// against it. An advisory that asks only "does the pattern match an
// argument-free command" would keep telling operators that an
// argument-scoped restriction is on-box-only after it started firing
// remotely — the false advisory in the dangerous direction (#8189's
// doctrine: silence over a wrong warning, and never a warning for a
// restriction that works).
//
// So a surface may also register ARGUMENT SAMPLES: exemplar
// argument-bearing commands it can produce, one per argument slot
// shape. The advisory then asks the question against the argument-free
// set, the samples, and literal candidates derived from the pattern
// itself: a pattern whose literal spelling extends a registered
// command (`^show route table secret-vrf$` extends `show route table`)
// names a command the surface can now produce with that argument, and
// a pattern whose longest literal word can occupy an argument slot
// (`.*secret-vrf`) can fire on a sample carrying that word.
//
// The candidate is a WITNESS, judged by the real compiled rules, never
// by pattern inspection alone: it counts only when denyPatternDecides
// (or the allow verdict) actually fires on it, exactly the
// spelling-independence bar #7172 set.

var registeredArgumentSamples = map[string]func() []string{}

// RegisterCommandSurfaceArgumentSamples records the argument-bearing
// exemplar commands a registered surface can produce, so commit-time
// advisories can ask whether an argument-scoped restriction is
// expressible there. Called from a surface package's init alongside
// RegisterCommandSurface.
func RegisterCommandSurfaceArgumentSamples(name string, samples func() []string) {
	if name == "" || samples == nil {
		return
	}
	registeredArgumentSamples[name] = samples
}

// candidateSet returns the surface's argument-free commands plus its
// argument samples, and the samples on their own (literal candidates
// may only occupy a slot a sample proves exists).
func (s commandSurface) candidateSet() (all, samples []string) {
	base := s.commands()
	if fn := registeredArgumentSamples[s.name]; fn != nil {
		samples = fn()
	}
	all = make([]string, 0, len(base)+len(samples))
	all = append(all, base...)
	all = append(all, samples...)
	return all, samples
}

// patternCandidateCommands derives witness strings for an
// argument-scoped pattern from the pattern's own literal text and the
// surface's samples. A surface with no registered samples has not
// proven it can produce argument-bearing commands, so no witness is
// derived there and the #8189 advisory keeps speaking for it.
func patternCandidateCommands(src string, cmds, samples []string) []string {
	if len(samples) == 0 {
		return nil
	}
	var out []string
	// Expand alternations/optionals into alternative sources first
	// (#16378 fold): a witness for `^show (route table secret|log x)$`
	// lives under an alternative's literal spelling, not the combined
	// pattern's. denyPatternAlternatives9340 preserves exactly which
	// strings match, so each alternative is a sound source.
	if alts, ok := denyPatternAlternatives9340(src); ok && len(alts) >= 2 {
		for _, alt := range alts {
			out = append(out, patternCandidateCommands(alt.display, cmds, samples)...)
		}
		return out
	}
	if lit, ok := literalPatternString(src); ok && lit != "" {
		// The literal is a witness only where a sample proves an
		// argument slot under the same command, AND that slot is not
		// itself the whole command: `show qqq-zzz` would need a
		// sampled command `show <arg>`, and none exists (samples are
		// `show route table …`, `show log …`) — the literal's head
		// must be a sampled command's head or a registered command a
		// sample extends (`show route table …`).
		litWords := strings.Fields(lit)
		for _, smp := range samples {
			sWords := strings.Fields(smp)
			if len(sWords) < 2 || len(litWords) == 0 {
				continue
			}
			sHead := strings.Join(sWords[:len(sWords)-1], " ")
			litHead := strings.Join(litWords[:len(litWords)-1], " ")
			if lit == smp || litHead == sHead {
				out = append(out, lit)
				break
			}
			for _, c := range cmds {
				if (lit == c || strings.HasPrefix(lit, c+" ")) && strings.HasPrefix(smp, c+" ") && litHead == sHead {
					out = append(out, lit)
					break
				}
			}
			if len(out) > 0 {
				break
			}
		}
	}
	// Argument-word witnesses (#16378 fold): replace the LAST word of
	// each sample with every literal word the pattern carries, so a
	// pattern whose argument is a character class (`[a-z-]+`), an
	// alternation branch, or a dotted literal (`10\.99\.`) gets a
	// witness judged by the real rules. The witness is sound only
	// where the sample proves the slot: the operator's word takes the
	// sample's argument position, and denyPatternDecides still has to
	// fire on the result — a candidate the pattern does not match
	// (e.g. `^qqq-…` against `ping qqq-…` under its anchor) counts for
	// nothing, exactly the spelling-independence bar #7172 set.
	for _, seg := range literalSegments(src) {
		if seg == "" || strings.Contains(seg, " ") {
			continue
		}
		// The segment may only take the argument position of a sample
		// whose command head the pattern itself names. An anchored
		// pattern names its head literally (`^show route table …`,
		// `^show qqq-zzz$`): witnesses exist only under samples whose
		// head EXTENDS that named head by exactly the argument slot
		// (`show route table` for the former; nothing for the latter,
		// whose argument would follow bare `show`). An unanchored
		// pattern names no head, so any proven slot may carry it.
		namedHead := ""
		if hw := literalHeadWords(src); strings.HasPrefix(src, "^") && len(hw) >= 1 {
			namedHead = strings.Join(hw, " ")
		}
		for _, smp := range samples {
			words := strings.Fields(smp)
			if len(words) < 2 {
				continue
			}
			head := strings.Join(words[:len(words)-1], " ")
			if namedHead != "" && head != namedHead {
				continue
			}
			out = append(out, head+" "+seg)
		}
	}
	// Prefix witness: a pattern that anchors a literal HEAD
	// (`^ping 10\.99\.`) fires on the sample's command carrying the
	// pattern's remaining literal text in its slot. Derive it from the
	// literal head before the first metacharacter, completed with the
	// sample's argument where the pattern continues past the slot.
	if strings.HasPrefix(src, "^") {
		if head := literalHeadWords(src); len(head) >= 2 {
			// The head witness is the pattern's own literal start; it
			// is sound only where a sample proves an argument slot
			// under that exact head (`ping` for `^ping 10\.99\.`).
			// Without that check the head of `^show qqq-zzz$` — a
			// fully literal pattern with no metacharacters — was
			// offered as its own witness and silenced the advisory
			// for a command no surface produces (#16378 fold).
			headSampled := false
			for _, s := range samples {
				if w := strings.Fields(s); len(w) >= 2 && strings.Join(w[:len(w)-1], " ") == strings.Join(head[:len(head)-1], " ") {
					headSampled = true
				}
			}
			if headSampled {
				for _, s := range samples {
					words := strings.Fields(s)
					if len(words) >= len(head) && strings.Join(words[:len(head)-1], " ") == strings.Join(head[:len(head)-1], " ") {
						out = append(out, strings.Join(head, " "))
						if segs := literalSegments(src); len(segs) > len(head) {
							tail := head[len(head)-1]
							for _, seg := range segs[len(head):] {
								tail += "." + seg
							}
							completed := append(append([]string(nil), head[:len(head)-1]...), tail+".1")
							out = append(out, strings.Join(completed, " "))
						}
						completed := append(append([]string(nil), head[:len(head)-1]...), words[len(head)-1])
						out = append(out, strings.Join(completed, " "))
					}
				}
			}
		}
	}
	return out
}

// literalSegments returns the distinct literal words of a pattern:
// maximal runs of non-metacharacter text, split on spaces. Used to
// place the operator's own argument words into proven slots.
func literalSegments(src string) []string {
	s := strings.ReplaceAll(src, `\.`, ".")
	var out []string
	seen := map[string]bool{}
	var cur strings.Builder
	flush := func() {
		for _, w := range strings.Fields(cur.String()) {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
		cur.Reset()
	}
	for _, r := range s {
		switch r {
		case '\\', '.', '[', ']', '{', '}', '(', ')', '*', '+', '?', '|', '^', '$':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// literalHeadWords returns the literal words at the start of an
// anchored pattern, up to the first metacharacter: `^ping 10\.99\.`
// yields [ping 10].
func literalHeadWords(src string) []string {
	s := strings.TrimPrefix(strings.ReplaceAll(src, `\.`, "."), "^")
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.[]{}()*+?|$`, r) {
			break
		}
		b.WriteRune(r)
	}
	return strings.Fields(b.String())
}

// literalPatternString returns the plain string a pattern matches
// exactly when the pattern is (after unescaping `\.`) an optionally
// anchored literal with at most a wildcard tail. ok=false for any
// pattern with real regex structure, where no single witness exists.
func literalPatternString(src string) (string, bool) {
	s := strings.ReplaceAll(src, `\.`, ".")
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimSuffix(s, "$")
	s = strings.TrimSuffix(s, ".*")
	s = strings.TrimSuffix(s, ".+")
	if s == "" || strings.ContainsAny(s, `\.[]{}()*+?|`) {
		return "", false
	}
	return s, true
}
