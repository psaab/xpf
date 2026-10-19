package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// aspath_junos_translate.go translates a Junos AS-path regular expression
// into the anchored POSIX ERE FRR evaluates, or rejects it (#15007).
//
// Junos semantics (Juniper, "Understanding AS Path Regular Expressions for
// Use as Routing Policy Match Conditions"):
//   - The basic unit of matching is the AS number, not a character; a
//     pattern matches only if the whole AS path matches it — the UNIX
//     equivalent is ^pattern$ (^ and $ are implicit, optional if written).
//   - A term is an AS number (1..4294967295), "." (any single AS number),
//     a "[...]" set of AS numbers / ranges (a leading ^ negates it), or a
//     "(...)" group. Operators *, +, ?, {m}, {m,}, {m,n} apply to the
//     preceding term with no intervening space; "|" separates alternatives.
//   - A "-" between two AS numbers (or the en-dash spelling) is a range
//     matching ONE AS number: "123-125" matches 123, 124, or 125.
//   - "()" with no intervening space is the null (empty, locally
//     originated) AS path. Repetitions that admit zero occurrences
//     ("1234*", "1234?") likewise match the null path.
//
// FRR instead compiles a `bgp as-path access-list ... permit <regex>` line
// as an UNANCHORED POSIX ERE over the single-space-separated AS-path
// string ("65000 65001"), where "." matches one character and digits are
// characters. Rendering the Junos text verbatim therefore diverges:
// "()" matches every path, "65000" matches any path whose string contains
// that substring (165000, 650001, ...), and ".* 65000 .*" interpreted at
// character level is not the Junos token pattern. The canonical Junos
// anti-transit export policy — accept only "()" (my own routes), reject
// everything else — advertised provider-learned routes to another eBGP
// peer: a route leak.
//
// Translation: parse the Junos expression into terms, then emit an FRR
// ERE that consumes whole AS tokens ([0-9]+). Repetition of a term repeats
// " <term>" (one separating space plus the term), never the term's digits,
// so "1234+" is one-or-more AS 1234 tokens, not digit repetitions.
// Separators are folded into nullable (may-match-empty) elements —
// right-padded before the first mandatory element, left-padded after it —
// so a vanished optional term never leaves a stray separator, and a
// present one always carries exactly one.
//
// Anything outside the Junos grammar above is untranslatable and rejected:
// character classes / ranges inside an AS number ("65[0-9]+", "[0-9]+"),
// escapes, back-references, unbalanced groups, empty alternatives,
// intervals with m > n, AS numbers out of range or with leading zeros,
// and "^"/"$" anywhere but the edges. The strict commit gate rejects
// those (fail closed); the FRR renderer omits them on the tolerant-load
// path so no dangling `match as-path` line can fail open (the term-level
// fail-closed arms in pkg/frr complete that belt, as for #6686/#9881).

// asTokenRE matches exactly one AS number token in the FRR path string.
const asTokenRE = `[0-9]+`

// maxOptionalSeq bounds the subsequence expansion for a concatenation of
// only nullable terms (see parseConcat): 2^8 branches is already generous
// for a hand-written AS-path pattern, and beyond it the operator is told
// to restructure rather than xpf emitting a megabyte access-list.
const maxOptionalSeq = 8

// TranslateJunosASPathRegex converts a Junos AS-path regex to an anchored
// FRR POSIX ERE, or returns an error explaining why it cannot.
func TranslateJunosASPathRegex(junos string) (string, error) {
	s := strings.TrimSpace(junos)
	if s == "" {
		return "", fmt.Errorf("empty regular expression")
	}
	// ^ and $ are implicit in Junos and optional if written; strip one
	// leading ^ / trailing $ so the edges cannot be doubled.
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimSuffix(s, "$")
	s = strings.TrimSpace(s)
	var res string
	if s == "" {
		// "^", "$", "^$": the empty pattern matches only the null path.
		res = `^$`
	} else {
		p := &asPathParser{s: s}
		out, _, _, err := p.parseAlternation()
		if err != nil {
			return "", err
		}
		p.skipSpaces()
		if p.pos != len(p.s) {
			return "", fmt.Errorf("unexpected %q in AS-path regular expression %q", p.s[p.pos:], junos)
		}
		if out == "" {
			res = `^$`
		} else {
			res = "^" + out + "$"
		}
	}
	if _, err := regexp.CompilePOSIX(res); err != nil {
		return "", fmt.Errorf("translated AS-path regex %q is not a valid POSIX extended regular expression: %w", res, err)
	}
	return res, nil
}

// ValidJunosASPathRegex reports why a Junos AS-path regex cannot be
// translated to FRR, or nil when it can. It is the validation predicate
// shared by the strict commit gate and the FRR render belt, replacing the
// bare POSIX check (ValidASPathRegex) that accepted FRR-dialect text whose
// Junos meaning is different or undefined.
func ValidJunosASPathRegex(regex string) error {
	_, err := TranslateJunosASPathRegex(regex)
	return err
}

// RenderableASPathRegex returns the FRR pattern to render for a stored
// Junos regex: the translation, or an error when untranslatable. Callers
// on the render path omit the definition (and let the term-level
// fail-closed arms engage) rather than emit a divergent pattern.
func RenderableASPathRegex(junos string) (string, error) {
	return TranslateJunosASPathRegex(junos)
}

type asPathParser struct {
	s     string
	pos   int
	depth int
}

func (p *asPathParser) skipSpaces() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func (p *asPathParser) peek() byte {
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

// parseAlternation parses concat ('|' concat)*. It returns the FRR
// fragment and whether the fragment can match the empty (null) path.
// An alternative with no terms at all ("a |", "| a", "a || b") is a
// syntax error, not an empty branch.
func (p *asPathParser) parseAlternation() (frag string, nullable bool, terms int, err error) {
	first, firstNullable, firstTerms, err := p.parseConcat()
	if err != nil {
		return "", false, 0, err
	}
	parts := []string{first}
	partTerms := []int{firstTerms}
	nullable = firstNullable
	sawPipe := false
	for {
		p.skipSpaces()
		if p.peek() != '|' {
			break
		}
		sawPipe = true
		p.pos++
		next, nextNullable, nextTerms, err := p.parseConcat()
		if err != nil {
			return "", false, 0, err
		}
		parts = append(parts, next)
		partTerms = append(partTerms, nextTerms)
		nullable = nullable || nextNullable
	}
	if !sawPipe {
		return parts[0], nullable, partTerms[0], nil
	}
	for i, n := range partTerms {
		if n == 0 {
			return "", false, 0, fmt.Errorf("empty alternative in AS-path regex %q", p.s)
		}
		if parts[i] == "" {
			parts[i] = "^$" // a branch of only "()" terms matches the null path
		}
	}
	total := 0
	for _, n := range partTerms {
		total += n
	}
	return "(" + strings.Join(parts, "|") + ")", nullable, total, nil
}

// parseConcat parses a run of terms up to '|', ')' or end of input.
// Elements that can match empty (nullable: "x?", "x*", a group whose
// content is nullable, ...) have their separator folded in: before the
// first mandatory element they are right-padded ("(term )?"), after it
// left-padded ("( term)?"), so exactly one separator appears between any
// two present tokens and none at the edges. A concatenation of ONLY
// nullable elements is expanded to the alternation of its subsequences
// (bounded by maxOptionalSeq), which is the same language.
func (p *asPathParser) parseConcat() (frag string, nullable bool, terms int, err error) {
	type elem struct {
		frag     string
		nullable bool
	}
	var elems []elem
	for {
		p.skipSpaces()
		c := p.peek()
		if c == 0 || c == '|' || c == ')' {
			break
		}
		ef, en, err := p.parseTermWithOperator()
		if err != nil {
			return "", false, 0, err
		}
		terms++
		if ef == "" {
			continue // an empty group "()" contributes no token
		}
		elems = append(elems, elem{frag: ef, nullable: en})
	}
	if len(elems) == 0 {
		return "", true, terms, nil
	}
	firstMandatory := -1
	for i, el := range elems {
		if !el.nullable {
			firstMandatory = i
			break
		}
	}
	if firstMandatory < 0 {
		// All nullable: subsequence alternation.
		if len(elems) > maxOptionalSeq {
			return "", false, 0, fmt.Errorf("AS-path regex %q has %d consecutive optional terms; at most %d can be translated", p.s, len(elems), maxOptionalSeq)
		}
		var branches []string
		for mask := 0; mask < 1<<len(elems); mask++ {
			var toks []string
			for i, el := range elems {
				if mask&(1<<i) != 0 {
					toks = append(toks, el.frag)
				}
			}
			if len(toks) == 0 {
				branches = append(branches, "^$")
			} else {
				branches = append(branches, strings.Join(toks, " "))
			}
		}
		if len(branches) == 1 {
			return branches[0], true, terms, nil
		}
		return "(" + strings.Join(branches, "|") + ")", true, terms, nil
	}
	var b strings.Builder
	for i, el := range elems {
		switch {
		case i < firstMandatory:
			b.WriteString("(" + el.frag + " )?")
		case i == firstMandatory:
			b.WriteString(el.frag)
		case el.nullable:
			b.WriteString("( " + el.frag + ")?")
		default:
			b.WriteString(" " + el.frag)
		}
	}
	return b.String(), false, terms, nil
}

// parseTermWithOperator parses one term and its optional repetition
// operator (*, +, ?, {m}, {m,}, {m,n}) which must follow it with no
// intervening space. nullable reports whether the result can match empty.
func (p *asPathParser) parseTermWithOperator() (frag string, nullable bool, err error) {
	base, baseNullable, err := p.parseTerm()
	if err != nil {
		return "", false, err
	}
	op := ""
	switch p.peek() {
	case '*', '+', '?':
		op = string(p.peek())
		p.pos++
	case '{':
		end := strings.IndexByte(p.s[p.pos:], '}')
		if end < 0 {
			return "", false, fmt.Errorf("unterminated '{' interval in AS-path regex %q", p.s)
		}
		op = p.s[p.pos : p.pos+end+1]
		if err := validateInterval(op); err != nil {
			return "", false, err
		}
		p.pos += end + 1
	}
	if op == "" {
		return base, baseNullable, nil
	}
	if base == "" {
		return "", true, nil // "()" repeated still matches only the null path
	}
	wrapped := base
	if strings.Contains(base, " ") || (strings.Contains(base, "|") && !(strings.HasPrefix(base, "(") && strings.HasSuffix(base, ")"))) {
		wrapped = "(" + base + ")"
	}
	lo, hi, exact := intervalBounds(op)
	switch {
	case op == "*":
		return "(" + wrapped + "( " + wrapped + ")*)", true, nil
	case op == "?":
		return wrapped, true, nil
	case op == "+":
		return wrapped + "( " + wrapped + ")*", baseNullable, nil
	case exact && lo == 0:
		return wrapped + "{0}", true, nil
	case exact && lo == 1:
		return wrapped, baseNullable, nil
	case exact:
		return fmt.Sprintf("%s( %s){%d}", wrapped, wrapped, lo-1), baseNullable, nil
	case lo == 0 && hi < 0: // {0,}
		return "(" + wrapped + "( " + wrapped + ")*)", true, nil
	case lo == 0 && hi == 0: // {0,0}
		return wrapped + "{0}", true, nil
	case lo == 0: // {0,n}, n>=1: the optional element is 1..n occurrences
		return "(" + wrapped + "( " + wrapped + ")" + repeatSuffix(0, hi-1) + ")", true, nil
	case hi < 0: // {m,}, m>=1
		if lo == 1 {
			return wrapped + "( " + wrapped + ")*", baseNullable, nil
		}
		return fmt.Sprintf("%s( %s){%d,}", wrapped, wrapped, lo-1), baseNullable, nil
	default: // {m,n}, m>=1
		if hi == lo {
			return fmt.Sprintf("%s( %s){%d}", wrapped, wrapped, lo-1), baseNullable, nil
		}
		return fmt.Sprintf("%s( %s){%s}", wrapped, wrapped, intervalSpan(lo-1, hi-1)), baseNullable, nil
	}
}

func repeatSuffix(lo, hi int) string {
	if hi < 0 {
		return "*"
	}
	if lo == hi {
		return fmt.Sprintf("{%d}", lo)
	}
	return "{" + intervalSpan(lo, hi) + "}"
}

func intervalSpan(lo, hi int) string {
	if hi < 0 {
		return fmt.Sprintf("%d,", lo)
	}
	return fmt.Sprintf("%d,%d", lo, hi)
}

// intervalBounds returns (lo, hi, exact); hi<0 means unbounded.
func intervalBounds(op string) (lo, hi int, exact bool) {
	switch op {
	case "*":
		return 0, -1, false
	case "+":
		return 1, -1, false
	case "?":
		return 0, 1, false
	}
	inner := op[1 : len(op)-1]
	if !strings.Contains(inner, ",") {
		n, _ := strconv.Atoi(strings.TrimSpace(inner))
		return n, n, true
	}
	parts := strings.Split(inner, ",")
	lo, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
	if strings.TrimSpace(parts[1]) == "" {
		return lo, -1, false
	}
	hi, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
	return lo, hi, false
}

func validateInterval(op string) error {
	inner := op[1 : len(op)-1]
	parts := strings.Split(inner, ",")
	if len(parts) > 2 {
		return fmt.Errorf("invalid interval %q in AS-path regex", op)
	}
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || lo < 0 {
		return fmt.Errorf("invalid interval %q in AS-path regex", op)
	}
	if len(parts) == 1 || strings.TrimSpace(parts[1]) == "" {
		return nil
	}
	hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || hi < 0 || lo > hi {
		return fmt.Errorf("invalid interval %q in AS-path regex (lower bound exceeds upper bound)", op)
	}
	return nil
}

// parseTerm parses one Junos term: an AS number (optionally a "-"-range),
// ".", a "[...]" set, or a "(...)" group. An empty group "()" returns an
// empty fragment with nullable set.
func (p *asPathParser) parseTerm() (frag string, nullable bool, err error) {
	p.skipSpaces()
	if p.pos >= len(p.s) {
		return "", false, fmt.Errorf("missing term in AS-path regex %q", p.s)
	}
	c := p.s[p.pos]
	switch {
	case c == '(':
		if p.depth > 32 {
			return "", false, fmt.Errorf("AS-path regex %q nested too deeply", p.s)
		}
		p.pos++
		save := p.pos
		p.skipSpaces()
		if p.peek() == ')' {
			p.pos++
			return "", true, nil
		}
		p.pos = save
		p.depth++
		inner, innerNullable, _, err := p.parseAlternation()
		p.depth--
		if err != nil {
			return "", false, err
		}
		p.skipSpaces()
		if p.peek() != ')' {
			return "", false, fmt.Errorf("unbalanced '(' in AS-path regex %q", p.s)
		}
		p.pos++
		if inner == "" {
			return "", true, nil
		}
		// An alternation fragment already carries its outer parens.
		// A concatenation containing spaces must be wrapped so a
		// quantifier or separator binds to the whole group; after a
		// quantifier is read, parseConcat's join is only textual and
		// quantifiers on multi-token groups are rejected below by
		// construction (wrapped here when needed).
		if strings.Contains(inner, " ") {
			inner = "(" + inner + ")"
		}
		return inner, innerNullable, nil
	case c == '[':
		frag, err := p.parseASSet()
		return frag, false, err
	case c == '.':
		p.pos++
		return asTokenRE, false, nil
	case c >= '0' && c <= '9':
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
			p.pos++
		}
		num := p.s[start:p.pos]
		if err := validateASN(num); err != nil {
			return "", false, err
		}
		// A "-" (or en-dash) after an AS number is the Junos range
		// operator matching ONE AS in [lo,hi]. Look ahead past optional
		// spaces; a quantifier cannot intervene inside parseTerm.
		save := p.pos
		p.skipSpaces()
		dashLen := 0
		if p.peek() == '-' {
			dashLen = 1
		} else if p.pos+2 < len(p.s) && p.s[p.pos] == 0xe2 && p.s[p.pos+1] == 0x80 && p.s[p.pos+2] == 0x93 {
			dashLen = 3
		}
		if dashLen == 0 {
			p.pos = save
			return num, false, nil
		}
		p.pos += dashLen
		p.skipSpaces()
		if p.peek() < '0' || p.peek() > '9' {
			return "", false, fmt.Errorf("AS range %q has no upper bound in AS-path regex %q", num, p.s)
		}
		s2 := p.pos
		for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
			p.pos++
		}
		num2 := p.s[s2:p.pos]
		if err := validateASN(num2); err != nil {
			return "", false, err
		}
		lo, _ := strconv.ParseUint(num, 10, 64)
		hi, _ := strconv.ParseUint(num2, 10, 64)
		if lo > hi {
			return "", false, fmt.Errorf("AS range %s-%s is descending in AS-path regex %q", num, num2, p.s)
		}
		frag, err := asNumericRangeRE(lo, hi)
		return frag, false, err
	default:
		return "", false, fmt.Errorf("untranslatable character %q in Junos AS-path regex %q: terms are AS numbers, '.', '[...]' AS sets, or '(...)' groups, with '*', '+', '?', '{m,n}' or '|' operators", string(c), p.s)
	}
}

func validateASN(num string) error {
	v, err := strconv.ParseUint(num, 10, 64)
	if err != nil || v < 1 || v > 4294967295 {
		return fmt.Errorf("AS number %q out of range 1-4294967295 in AS-path regex", num)
	}
	if len(num) > 1 && num[0] == '0' {
		return fmt.Errorf("AS number %q has a leading zero in AS-path regex", num)
	}
	return nil
}

type asRange struct{ lo, hi uint64 }

func mergeRanges(rs []asRange) []asRange {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j-1].lo > rs[j].lo; j-- {
			rs[j-1], rs[j] = rs[j], rs[j-1]
		}
	}
	var out []asRange
	for _, r := range rs {
		if len(out) > 0 && r.lo <= out[len(out)-1].hi+1 {
			if r.hi > out[len(out)-1].hi {
				out[len(out)-1].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// parseASSet parses "[...]": a set of AS numbers and "-"-ranges (whitespace
// or commas separate elements). A leading '^' negates the set: the term
// matches one AS NOT in the set, emitted as the complement ranges within
// 1..4294967295. A POSIX character class such as "[0-9]" is NOT a Junos AS
// set — "0" is not a valid AS number — so it rejects, as does a class
// inside an AS number ("65[0-9]+": "65" then a bracket term with no
// separating space is not Junos syntax either, and the bracket element
// "0-9" fails AS validation on its lower bound).
func (p *asPathParser) parseASSet() (string, error) {
	p.pos++ // '['
	negated := false
	if p.peek() == '^' {
		negated = true
		p.pos++
	}
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != ']' {
		p.pos++
	}
	if p.pos >= len(p.s) {
		return "", fmt.Errorf("unterminated '[' in AS-path regex %q", p.s)
	}
	inner := strings.TrimSpace(p.s[start:p.pos])
	p.pos++ // ']'
	if inner == "" {
		return "", fmt.Errorf("empty '[]' AS set in AS-path regex %q", p.s)
	}
	var ranges []asRange
	fields := strings.FieldsFunc(inner, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
	for _, f := range fields {
		f = strings.ReplaceAll(f, "–", "-")
		if strings.Contains(f, "-") {
			parts := strings.Split(f, "-")
			if len(parts) != 2 {
				return "", fmt.Errorf("invalid AS set element %q in AS-path regex", f)
			}
			if err := validateASN(parts[0]); err != nil {
				return "", err
			}
			if err := validateASN(parts[1]); err != nil {
				return "", err
			}
			lo, _ := strconv.ParseUint(parts[0], 10, 64)
			hi, _ := strconv.ParseUint(parts[1], 10, 64)
			if lo > hi {
				return "", fmt.Errorf("AS range %s is descending in AS-path regex", f)
			}
			ranges = append(ranges, asRange{lo, hi})
			continue
		}
		if err := validateASN(f); err != nil {
			return "", err
		}
		v, _ := strconv.ParseUint(f, 10, 64)
		ranges = append(ranges, asRange{v, v})
	}
	if len(ranges) == 0 {
		return "", fmt.Errorf("empty '[]' AS set in AS-path regex %q", p.s)
	}
	if negated {
		ranges = mergeRanges(ranges)
		var frags []string
		next := uint64(1)
		for _, r := range ranges {
			if r.lo > next {
				frag, err := asNumericRangeRE(next, r.lo-1)
				if err != nil {
					return "", err
				}
				frags = append(frags, frag)
			}
			if r.hi >= next {
				next = r.hi + 1
			}
		}
		if next <= 4294967295 {
			frag, err := asNumericRangeRE(next, 4294967295)
			if err != nil {
				return "", err
			}
			frags = append(frags, frag)
		}
		if len(frags) == 0 {
			return "", fmt.Errorf("negated AS set in %q excludes every AS number", p.s)
		}
		if len(frags) == 1 {
			return frags[0], nil
		}
		return "(" + strings.Join(frags, "|") + ")", nil
	}
	var frags []string
	for _, r := range ranges {
		frag, err := asNumericRangeRE(r.lo, r.hi)
		if err != nil {
			return "", err
		}
		frags = append(frags, frag)
	}
	if len(frags) == 1 {
		return frags[0], nil
	}
	return "(" + strings.Join(frags, "|") + ")", nil
}

// asNumericRangeRE returns a POSIX ERE fragment matching exactly one AS
// token whose value lies in [lo,hi], with no leading zeros (AS tokens in
// the FRR path string are canonical decimal).
func asNumericRangeRE(lo, hi uint64) (string, error) {
	if lo > hi {
		return "", fmt.Errorf("descending AS range %d-%d", lo, hi)
	}
	if lo == hi {
		return strconv.FormatUint(lo, 10), nil
	}
	loStr := strconv.FormatUint(lo, 10)
	hiStr := strconv.FormatUint(hi, 10)
	var parts []string
	for l := len(loStr); l <= len(hiStr); l++ {
		segLo := lo
		if minLen := pow10u(l - 1); segLo < minLen {
			segLo = minLen
		}
		segHi := hi
		if maxLen := pow10u(l) - 1; segHi > maxLen {
			segHi = maxLen
		}
		if segLo > segHi {
			continue
		}
		parts = append(parts, sameLengthRangeRE(strconv.FormatUint(segLo, 10), strconv.FormatUint(segHi, 10)))
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, "|") + ")", nil
}

func pow10u(n int) uint64 {
	r := uint64(1)
	for range n {
		r *= 10
	}
	return r
}

// sameLengthRangeRE matches the digit strings of equal length between lo
// and hi inclusive. The result is either a single digit sequence or a
// parenthesised alternation, so it concatenates safely after a prefix.
func sameLengthRangeRE(lo, hi string) string {
	if lo == hi {
		return lo
	}
	i := 0
	for i < len(lo) && lo[i] == hi[i] {
		i++
	}
	prefix := lo[:i]
	if i == len(lo) {
		return lo
	}
	restLo, restHi := lo[i:], hi[i:]
	if allByte(restLo, '0') && allByte(restHi, '9') {
		return prefix + digitRangeClass(restLo[0], restHi[0]) + digitRun(len(restLo)-1)
	}
	var parts []string
	parts = append(parts, prefix+string(lo[i])+suffixAtLeastRE(lo[i+1:]))
	if hi[i]-lo[i] > 1 {
		parts = append(parts, prefix+digitRangeClass(lo[i]+1, hi[i]-1)+digitRun(len(lo)-i-1))
	}
	parts = append(parts, prefix+string(hi[i])+suffixAtMostRE(hi[i+1:]))
	return "(" + strings.Join(parts, "|") + ")"
}

func allByte(s string, c byte) bool {
	if s == "" {
		return false
	}
	for i := range s {
		if s[i] != c {
			return false
		}
	}
	return true
}

func digitRangeClass(a, b byte) string {
	if a == b {
		return string(a)
	}
	if a == '0' && b == '9' {
		return "[0-9]"
	}
	return "[" + string(a) + "-" + string(b) + "]"
}

func digitRun(n int) string {
	switch {
	case n <= 0:
		return ""
	case n == 1:
		return "[0-9]"
	default:
		return fmt.Sprintf("[0-9]{%d}", n)
	}
}

// suffixAtLeastRE matches digit suffixes >= s (same length as s). With
// more than one alternative the result is parenthesised: the caller
// concatenates it after a digit prefix, and a bare "a|b" would lose that
// prefix on every branch after the first.
func suffixAtLeastRE(s string) string {
	if s == "" {
		return ""
	}
	if allByte(s, '0') {
		return digitRun(len(s))
	}
	var parts []string
	for k := range s {
		if s[k] < '9' {
			parts = append(parts, s[:k]+digitRangeClass(s[k]+1, '9')+digitRun(len(s)-k-1))
		}
	}
	parts = append(parts, s)
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "|") + ")"
}

func suffixAtMostRE(s string) string {
	if s == "" {
		return ""
	}
	if allByte(s, '9') {
		return digitRun(len(s))
	}
	var parts []string
	for k := range s {
		if s[k] > '0' {
			parts = append(parts, s[:k]+digitRangeClass('0', s[k]-1)+digitRun(len(s)-k-1))
		}
	}
	parts = append(parts, s)
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "|") + ")"
}
