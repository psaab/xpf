package config

import (
	"fmt"
	"regexp"
	"strings"
)

// community_translate.go translates a Junos community member regex into
// the POSIX ERE FRR evaluates against the whole space-joined community
// string, or rejects it (#16788).
//
// Junos semantics (Juniper, "How BGP Communities and Extended
// Communities Are Evaluated in Routing Policy Match Conditions"): each
// member is evaluated against each community associated with the route;
// only one route community needs to match a given member. FRR instead
// runs regexec over community_str() — the numerically sorted values
// joined with single spaces — so a verbatim member such as ^666:.*$
// only matched when the 666 community sorted first, and a peer could
// bypass a reject by adding any lower-sorting community.
//
// Translation, per regex member:
//   - Strip one leading ^ and one trailing $ (the author's per-community
//     anchors); the wrapping below re-expresses them as token
//     boundaries. A ^ or $ anywhere else cannot be confined to one
//     community and is rejected.
//   - Confine every "." outside a bracket expression to [^ ] so a match
//     cannot span communities. A "." INSIDE a bracket expression is a
//     literal dot and is left alone.
//   - Reject members that cannot be confined: a literal space or
//     [[:space:]] (authored to match the joined string's separator), a
//     bracket expression that can match a space (it names ' ', contains
//     a range spanning ' ', is a negated class not excluding ' ', or
//     carries a POSIX class other than [:digit:] — e.g. [:alpha:] or
//     [:alnum:] matches the separator's neighbours only via the class's
//     letters/digits in practice but [:space:] and [:blank:] match the
//     separator itself, and any unanalysed class is refused rather
//     than guessed at), a bracket class whose verbatim text spells
//     "| " (the class renders as-is, so it trips FRR's vty pipe hook —
//     #16776's refusal extended inside brackets, #17977), an escape
//     that can match a space (\s) or whose
//     meaning differs between Junos, Go POSIX and glibc (\d, \w, \b and
//     friends), and "(?..." Perl constructs POSIX ERE has no spelling
//     for.
//   - Wrap: a leading ^ becomes (^|[ ]) — pipe-free, per the R3-A11-04
//     constraint that "| " is consumed by FRR's vty pipe hook — and a
//     trailing $ becomes ([ ]|$). Unanchored edges keep their Junos
//     substring meaning: a confined match contains no space, so it
//     necessarily lies inside one community token.
//
// Literal (non-regex) members never reach this translator; they keep
// the standard list render.
//
// The strict commit gate rejects an untranslatable member
// (ValidCommunityMember); the FRR renderer omits the whole definition
// on the tolerant-load path so referencing terms fail closed via
// communityListMissingAtRender (#10822 posture), exactly as for the
// #15007 as-path translator.

// TranslateCommunityMemberRegex converts one Junos community member
// regex to the per-community FRR expanded-list pattern, or returns an
// error explaining why it cannot be confined to a single community.
func TranslateCommunityMemberRegex(member string) (string, error) {
	body := member
	anchoredStart := strings.HasPrefix(body, "^")
	if anchoredStart {
		body = body[1:]
	}
	anchoredEnd := strings.HasSuffix(body, "$")
	if anchoredEnd {
		body = body[:len(body)-1]
	}
	core, err := translateCommunityCore(body)
	if err != nil {
		return "", err
	}
	pattern := core
	if anchoredStart {
		pattern = "(^|[ ])" + pattern
	}
	if anchoredEnd {
		pattern += "([ ]|$)"
	}
	return pattern, nil
}

// translateCommunityCore confines one anchor-stripped member body to
// a single community token: "." outside brackets becomes [^ ], and
// anything that can match the separator space, an interior anchor, a
// non-POSIX escape, a "(?..." construct, or a bracket class spelling
// "| " (the pipe-hook literal rendered verbatim, #17977) is rejected.
func translateCommunityCore(body string) (string, error) {
	if body == "" {
		return "", fmt.Errorf("member matches only the empty community, which no route carries (#16788)")
	}
	var out strings.Builder
	out.Grow(len(body) + 8)
	for i := 0; i < len(body); {
		switch c := body[i]; c {
		case ' ':
			return "", fmt.Errorf("contains a literal space, which matches the separator " +
				"between communities in FRR's joined community string rather than a " +
				"single community (#16788)")
		case '^', '$':
			return "", fmt.Errorf("anchor %c appears away from the edge of the member; "+
				"it cannot be confined to a single community (#16788)", c)
		case '\\':
			if i+1 >= len(body) {
				return "", fmt.Errorf("ends with a dangling escape")
			}
			return "", fmt.Errorf("escape \\%c cannot be translated: escapes that match a "+
				"space (\\s) or use non-POSIX classes (\\d, \\w, \\b) cannot be confined "+
				"to a single community (#16788)", body[i+1])
		case '(':
			if i+1 < len(body) && body[i+1] == '?' {
				return "", fmt.Errorf("contains a (?...) construct, which POSIX ERE " +
					"(FRR regcomp REG_EXTENDED) cannot express (#16788)")
			}
			out.WriteByte(c)
			i++
		case '[':
			end, class, err := scanCommunityBracket(body, i)
			if err != nil {
				return "", err
			}
			out.WriteString(class)
			i = end
		case '.':
			out.WriteString("[^ ]")
			i++
		case '|':
			if i+1 < len(body) && body[i+1] == ' ' {
				return "", fmt.Errorf("contains \"| \", which FRR's vty pipe hook refuses " +
					"on the daemon path; write the alternation without a space after " +
					"the | (#16788)")
			}
			out.WriteByte(c)
			i++
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String(), nil
}

// TranslateCommunityMemberCore is TranslateCommunityMemberRegex for
// conjunction sequencing: it returns the confined core (no edge
// wrapping) plus which edges the author anchored. The sequence
// builder in pkg/frr re-expresses anchored edges as its own token
// boundaries, so factors can share the single separator between
// adjacent communities instead of each consuming one.
func TranslateCommunityMemberCore(member string) (core string, anchoredStart, anchoredEnd bool, err error) {
	body := member
	anchoredStart = strings.HasPrefix(body, "^")
	if anchoredStart {
		body = body[1:]
	}
	anchoredEnd = strings.HasSuffix(body, "$")
	if anchoredEnd {
		body = body[:len(body)-1]
	}
	core, err = translateCommunityCore(body)
	return core, anchoredStart, anchoredEnd, err
}

// ValidCommunityMemberRegex reports why a regex community member cannot
// be translated to a per-community FRR pattern, or nil when it can. It
// is the translation axis of ValidCommunityMember, shared by the strict
// commit gate and the FRR render belt so the two cannot drift.
func ValidCommunityMemberRegex(member string) error {
	if _, err := regexp.CompilePOSIX(member); err != nil {
		return fmt.Errorf("contains a regex metacharacter (%s) so it renders into an "+
			"FRR `expanded` community-list, but it is not a valid POSIX extended "+
			"regular expression: %w", CommunityRegexChars, err)
	}
	if _, err := TranslateCommunityMemberRegex(member); err != nil {
		return err
	}
	return nil
}

// RenderableCommunityMember returns the FRR expanded pattern to render
// for a stored Junos regex member: the per-community translation, or an
// error when untranslatable. Callers on the render path omit the whole
// definition (and let the term-level fail-closed arms engage) rather
// than emit a divergent pattern.
func RenderableCommunityMember(member string) (string, error) {
	return TranslateCommunityMemberRegex(member)
}

// scanCommunityBracket validates the bracket expression starting at
// body[start] (a '[') and returns the index just past its ']' plus the
// expression verbatim. A bracket expression is refused when it can
// match a space, when it carries a POSIX class other than [:digit:],
// when its verbatim text spells "| " (FRR's vty pipe hook refuses
// that literal even inside a character class, #17977), or when it is
// unterminated.
func scanCommunityBracket(body string, start int) (int, string, error) {
	i := start + 1
	negated := false
	if i < len(body) && body[i] == '^' {
		negated = true
		i++
	}
	// A ']' as the first character (after the optional ^) is a literal.
	// A '.' inside a bracket expression is a literal dot, never the
	// wildcard, so the expression needs no confinement rewriting —
	// only the can-it-match-a-space analysis below.
	type runeRange struct{ lo, hi byte }
	var ranges []runeRange
	var singles []byte
	pos := i
	if pos < len(body) && body[pos] == ']' {
		singles = append(singles, ']')
		pos++
	}
	closed := false
	for ; pos < len(body); pos++ {
		c := body[pos]
		if c == ']' {
			closed = true
			break
		}
		if c == '[' && pos+1 < len(body) && body[pos+1] == ':' {
			end := strings.Index(body[pos+2:], ":]")
			if end < 0 {
				return 0, "", fmt.Errorf("unterminated POSIX character class in bracket expression (#16788)")
			}
			class := body[pos+2 : pos+2+end]
			if class != "digit" {
				return 0, "", fmt.Errorf("POSIX character class [:%s:] inside a community member "+
					"cannot be proven unable to match the space between communities (#16788)", class)
			}
			pos += 2 + end + 1 // land on the ']' of ":]"; loop's pos++ moves past it
			continue
		}
		if c == ' ' && !negated {
			return 0, "", fmt.Errorf("bracket expression can match a space, which is the " +
				"separator between communities in FRR's joined community string (#16788)")
		}
		if c == '-' && pos+1 < len(body) && body[pos+1] != ']' {
			// A leading '-' (no preceding single) ranges from '-'
			// itself, e.g. [-~] is the range '-'..'~'.
			lo := byte('-')
			if len(singles) > 0 {
				lo = singles[len(singles)-1]
				singles = singles[:len(singles)-1]
			}
			hi := body[pos+1]
			if lo <= ' ' && ' ' <= hi {
				return 0, "", fmt.Errorf("bracket range %c-%c spans the space between "+
					"communities in FRR's joined community string (#16788)", lo, hi)
			}
			ranges = append(ranges, runeRange{lo, hi})
			pos++ // consume hi
			continue
		}
		singles = append(singles, c)
	}
	if !closed {
		return 0, "", fmt.Errorf("unterminated bracket expression")
	}
	if negated {
		excluded := func(b byte) bool {
			for _, s := range singles {
				if s == b {
					return true
				}
			}
			for _, r := range ranges {
				if r.lo <= b && b <= r.hi {
					return true
				}
			}
			return false
		}
		if !excluded(' ') {
			return 0, "", fmt.Errorf("negated bracket expression can match a space, which is " +
				"the separator between communities in FRR's joined community string; " +
				"exclude it explicitly, e.g. [^ ] (#16788)")
		}
	}
	if strings.Contains(body[start:pos+1], "| ") {
		return 0, "", fmt.Errorf("bracket expression %s spells \"| \", which the render "+
			"emits verbatim; FRR's vty pipe hook refuses any line containing \"| \" "+
			"while frr-reload.py exits 0, so the community-list would silently "+
			"never install; a community token never contains |, so drop it from "+
			"the class (e.g. [^| ] -> [^ ]) (#17977)", body[start:pos+1])
	}
	return pos + 1, body[start : pos+1], nil
}
