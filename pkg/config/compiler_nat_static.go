package config

import (
	"net/netip"
	"strconv"
	"strings"
)

// natStaticPrefixInfo classifies a static-NAT address the way the Rust
// parse_nat_prefix (static_nat.rs, #3031) does: it returns the family, the
// prefix length, whether the value is a host route, and whether it parsed as
// an IP at all. A bare address is a host route (len == max). A `/N` mask is
// parsed numerically; bits < 0 flags a malformed/out-of-range mask (a
// non-numeric or `/33`/`/129` suffix) so the caller leaves the existing
// host-route rejection to fire. A non-IP token (address-book name) returns
// parsedIP == false and is not this validator's concern.
func natStaticPrefixInfo(addr string) (fam string, bits int, isHost, parsedIP bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam = natAddrFamily(ipPart)
	if fam == "" {
		return "", -1, false, false
	}
	max := 128
	if fam == "v4" {
		max = 32
	}
	if slash < 0 {
		return fam, max, true, true
	}
	n, err := strconv.Atoi(addr[slash+1:])
	if err != nil || n < 0 || n > max {
		return fam, -1, false, true
	}
	return fam, n, n == max, true
}

// staticNATMatchAddrKey returns the INSTALL IDENTITY of a `match
// destination-address` value: two values with the same key lower to a
// byte-identical dataplane row, so a cardinality gate may count them once.
//
// #6673 fold. The gate over this leaf must count how many DISTINCT external
// prefixes were authored; counting raw value slots invented a commit rejection
// for a repeated identical prefix that origin/master accepted (dedupeValuesBy).
// Exact-text dedupe alone would still reject `192.0.2.1` beside `192.0.2.1/32`,
// which is the SAME host route written two ways — the same invented rejection,
// one spelling over. So the key is the canonical form the dataplane itself
// reduces the value to.
//
// The canonical form mirrors Rust parse_nat_prefix (static_nat.rs): a bare
// address is a host route of the family's full width, and the base is MASKED to
// the prefix length (`base = addr & !host_mask(len)`), which is why
// `192.0.2.5/24` keys the same as `192.0.2.0/24`. That masking is what makes
// collapsing SOUND rather than lenient: equal keys mean the rule translates
// identically whichever spelling the compiler selects, so counting them once
// cannot suppress a rejection that would have changed what installs. The #6659
// rejection for GENUINELY distinct prefixes — where one of them really would
// carry no translation — is untouched.
//
// A value that does not parse as an IP, or whose mask is malformed, has no
// canonical form and keys on its raw text under a distinct prefix, so two
// different malformed tokens never collapse into one and a malformed token can
// never collide with a well-formed address. netip is used rather than net.IP
// because net.IP folds IPv4-mapped IPv6 into IPv4 (#6327); natStaticPrefixInfo
// supplies the family and width from the colon-strict natAddrFamily, so the two
// agree on which width a 4-in-6 literal has.
// staticNATMatchAddrKeyFor picks the install-identity key for a rule's `match
// destination-address` values. The identity depends on the CONSUMER, and static
// NAT and NPTv6 have different ones.
//
// #6673 fold. staticNATMatchAddrKey masks the value to its prefix length
// because plain static NAT's consumer masks too (parse_nat_prefix in
// userspace-dp/src/nat/static_nat.rs: `base = addr & !host_mask(len)`), so two
// spellings that mask alike really do lower to a byte-identical row. NPTv6's
// consumer does the OPPOSITE: parse_prefix in userspace-dp/src/nptv6.rs
// documents "OR host bits are set beyond the prefix length (#4519 — fail
// closed, do NOT mask)" and returns None. So for an NPTv6 rule
// `2001:db8:1:2::/48` and `2001:db8:1::/48` mask alike but do NOT install
// alike — one translates and one is rejected — and collapsing them let a value
// with host bits ride along invisibly: the cardinality gate saw one prefix, the
// per-address validator skips NPTv6 rules, and the NPTv6 validator reads only
// the scalar rule.Match. Nothing rejected it and nothing installed it.
//
// Keying a host-bits value on its raw text restores the distinction, so the
// #6659 cardinality gate fires on the pair. Every widened NPTv6 value is then
// covered by SOME strict gate, which is the honest form of the claim: a value
// DISTINCT from the selected one is rejected by the cardinality gate; a value
// IDENTICAL to it is the selected value, which
// validateNPTv6PrefixesStrict already checks (length, family, /48-or-/64,
// host bits). No per-value NPTv6 validator is added or needed.
func staticNATMatchAddrKeyFor(isNPTv6 bool) func(string) string {
	if !isNPTv6 {
		return staticNATMatchAddrKey
	}
	return nptv6MatchAddrKey
}

// nptv6MatchAddrKey is staticNATMatchAddrKey with masking withheld from any
// value that actually carries host bits — the values NPTv6 refuses to install.
// Two identical spellings still collapse (that is the invented-rejection fix
// dedupeValuesBy exists for), and so do two masked-equal spellings that are both
// already canonical; only a value the NPTv6 consumer would reject is kept
// distinct from the one it accepts.
func nptv6MatchAddrKey(v string) string {
	if p, err := netip.ParsePrefix(v); err == nil && p.Masked() != p {
		return "hostbits\x00" + v
	}
	return staticNATMatchAddrKey(v)
}

func staticNATMatchAddrKey(v string) string {
	_, bits, _, parsedIP := natStaticPrefixInfo(v)
	if !parsedIP || bits < 0 {
		return "raw\x00" + v
	}
	ipPart := v
	if slash := strings.IndexByte(v, '/'); slash >= 0 {
		ipPart = v[:slash]
	}
	addr, err := netip.ParseAddr(ipPart)
	if err != nil {
		return "raw\x00" + v
	}
	p := netip.PrefixFrom(addr, bits)
	if !p.IsValid() {
		return "raw\x00" + v
	}
	return "ip\x00" + p.Masked().String()
}

// isStaticBlockPair reports whether (match, then) is a valid block-to-block
// (subnet) static-NAT 1:1 mapping (#3031): both sides parse as IPs, both are
// non-host prefixes of the SAME family with EQUAL prefix length. The Rust
// dataplane installs exactly this case (offset-preserving remap); a
// host-vs-block, mismatched-length, mixed-family, or malformed-mask pair is
// NOT a block pair and falls through to the existing host-route rejection.
func isStaticBlockPair(match, then string) bool {
	mf, mb, mh, mp := natStaticPrefixInfo(match)
	tf, tb, th, tp := natStaticPrefixInfo(then)
	if !mp || !tp {
		return false // a non-IP token — leave to existing handling
	}
	if mh || th || mb < 0 || tb < 0 {
		return false // a host side or a malformed mask — not a block pair
	}
	return mf == tf && mb == tb
}

// applyStaticNATFromScope stamps a from-scope onto a StaticNATRuleSet.
func applyStaticNATFromScope(rs *StaticNATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.FromInterface = s.value
	case "routing-instance":
		rs.FromRoutingInstance = s.value
	default: // "zone"
		rs.FromZone = s.value
	}
}

// mappedPortNameValuedKeywords is the set of static-NAT `then` keywords that
// CONSUME their following token as an operator-chosen NAME (not an IP/prefix),
// so that name could legally be the literal string "mapped-port". The
// grammar-role-aware operand scan (staticNATMappedPortOperandsFromKeys) treats
// the token immediately after one of these keywords as a consumed VALUE slot,
// never a modifier keyword — so a `mapped-port` sitting in that slot is the name,
// not the port modifier (#6479):
//
//   - `routing-instance <ri>` — a translation-target routing-instance may be
//     NAMED "mapped-port" (#4292).
//   - `prefix-name <name>` — a `then static-nat prefix-name` reference names a
//     global address-book entry (#4290) that may be NAMED "mapped-port".
//
// `prefix` AND `nptv6-prefix` are deliberately ABSENT: both take an IP/CIDR
// prefix value that can NEVER be the string "mapped-port", so the scan does NOT
// consume-and-shadow the token after either literal keyword — a `mapped-port`
// immediately following `prefix`/`nptv6-prefix` is ALWAYS the genuine modifier.
// The canonical separate-set-line Junos forms `prefix <ip>` + `prefix
// mapped-port <port>` and `nptv6-prefix <p6>` + `nptv6-prefix mapped-port
// <port>` collapse the modifier line to Keys `["prefix","mapped-port","<port>"]`
// / `["nptv6-prefix","mapped-port","<port>"]`, and the modifier MUST be
// recovered from that position. `prefix` was a round-4 over-defensive addition
// removed in round 5 (it false-rejected the canonical clean rule AND reopened
// the C179-038 fail-open); `nptv6-prefix` is its sibling and was removed for the
// same reason — treating it as name-valued discarded the mapped-port before it
// could reach recordNPTv6MappedPortPresence, so validateNPTv6Strict never fired
// and a malformed (or well-formed) nptv6 mapped-port on the canonical-separate
// form was SILENTLY ACCEPTED (the last residual C179-038 fail-open). NPTv6 still
// carries no port; recovering the modifier is what lets the nptv6 gate REJECT
// it rather than drop it silently.
var mappedPortNameValuedKeywords = map[string]struct{}{
	"routing-instance": {},
	"prefix-name":      {},
}

// staticNATMappedPortOperandsFromKeys returns the operand token trailing each
// GENUINE `mapped-port` modifier in a static-NAT `then` node's collapsed Keys,
// in AST order (#2491, #6479 grammar-role fix). The lexer collapses `then
// static-nat prefix <ip> mapped-port <port>` onto one leaf whose Keys are
// `["prefix","<ip>","mapped-port","<port>"]` (or, on the static-nat node itself,
// `["static-nat","prefix","<ip>","mapped-port","<port>"]`) because `static-nat`
// is a children:nil schema leaf, so this in-leaf token bypasses the schema value
// validator and must be recovered here.
//
// The scan is GRAMMAR-ROLE-AWARE, not a lexeme lookbehind: it walks the key
// stream tracking whether each position is a KEYWORD slot or a consumed VALUE
// slot, and a `mapped-port` is the modifier ONLY in a keyword slot. A NAME-valued
// keyword (mappedPortNameValuedKeywords: routing-instance / prefix-name) consumes
// its following token as an opaque name, so a `mapped-port` in that consumed slot
// is the NAME and is skipped — even when the name itself is literally
// "prefix-name" or "routing-instance". That is the #6479 root cause a lexeme
// lookbehind could not fix: it inspected the neighbouring TEXT and could not tell
// whether the preceding token was the keyword or its value, so a target NAMED
// after a skip-keyword (`prefix-name prefix-name mapped-port <bad>`) shifted a
// real modifier into the skipped position and silently accepted a malformed port.
// `prefix` and `nptv6-prefix` are NOT name-valued: their IP value can never be
// the literal "mapped-port", so the scan does not consume-and-shadow the token
// after them and `prefix mapped-port <port>` / `nptv6-prefix mapped-port <port>`
// (the canonical separate-set-line forms) still recover the modifier — the nptv6
// one so validateNPTv6Strict can reject the port rather than silently accept it.
// A genuine modifier with no trailing operand (a bare `mapped-port` at the end of
// the key list) contributes an EMPTY operand so combineMappedPortOperands flags
// it malformed rather than dropping the occurrence.
func staticNATMappedPortOperandsFromKeys(keys []string) []string {
	var operands []string
	for i := 0; i < len(keys); {
		tok := keys[i]
		if _, nameValued := mappedPortNameValuedKeywords[tok]; nameValued {
			// A NAME-valued keyword consumes the NEXT token as its opaque name
			// value; skip both slots so a value that is literally "mapped-port"
			// (or a skip-keyword lexeme) is never read as the modifier keyword.
			i += 2
			continue
		}
		if tok == "mapped-port" {
			// A `mapped-port` in a KEYWORD slot: the genuine modifier. Its next
			// token (if any) is the port operand, and it too is consumed so a
			// value that happens to read "mapped-port" is not re-scanned as a
			// keyword. A bare trailing keyword yields "" (malformed).
			if i+1 < len(keys) {
				operands = append(operands, keys[i+1])
			} else {
				operands = append(operands, "")
			}
			i += 2
			continue
		}
		// prefix / nptv6-prefix / inet / static-nat / an IP or port value: a
		// single keyword slot that does NOT shadow the following token (its value
		// can never be the literal "mapped-port"), so advance by one and let a
		// `mapped-port` that follows it be read as the modifier.
		i++
	}
	return operands
}

// mappedPortNodeOperands returns every operand attached to a `mapped-port`
// NODE (a sibling or nested `mapped-port` child of the static-nat / prefix
// node), across both shapes the parser can produce:
//
//   - packed / flat Keys: `mapped-port <p>` → Keys=["mapped-port","<p>"], and a
//     packed duplicate `mapped-port a mapped-port b` collapses onto one leaf's
//     Keys=["mapped-port","a","mapped-port","b"]. staticNATMappedPortOperands-
//     FromKeys walks ALL of them (scan-all, not first-wins), so a malformed
//     second operand fails closed.
//   - hierarchical value-as-child: `mapped-port { <p>; }` → Keys=["mapped-port"]
//     with the operand carried as a child. The key scan yields a single "" (bare
//     keyword) placeholder; replace it with the child value(s) so the operand is
//     recovered rather than mis-flagged as an empty (missing) value.
func mappedPortNodeOperands(c *Node) []string {
	ops := staticNATMappedPortOperandsFromKeys(c.Keys)
	if len(c.Children) > 0 && len(ops) == 1 && ops[0] == "" {
		ops = ops[:0]
		for _, gc := range c.Children {
			ops = append(ops, gc.Name())
		}
	}
	return ops
}

// staticNATMappedPortForNode folds every genuine `mapped-port` modifier operand
// attached to a static-nat `then` node — across EVERY AST shape AND across
// duplicate target children — into the (port, raw, present) triple the strict
// gate (validateNATHostMaskStrict) consumes (#2491, C179-038, #6479 fold).
//
// It gathers operands from:
//   - the static-nat node's own collapsed Keys (the `then static-nat prefix <ip>
//     mapped-port <port>` shape that lands on t.Keys);
//   - each `mapped-port` sibling child (the hierarchical `static-nat { prefix X;
//     mapped-port P; }` shape), scanning ALL of its operands (a packed
//     `mapped-port a mapped-port b` duplicate fails closed, not first-wins);
//   - each target child (`prefix`/`prefix-name` <val>) — BOTH the collapsed
//     modifier on its Keys (the flat-set `prefix <ip> mapped-port <port>` and
//     the canonical separate-set-line `prefix mapped-port <port>` shapes) AND a
//     mapped-port nested inside its Children (the canonical HIERARCHICAL
//     `prefix <ip> { mapped-port P; }` / `prefix { <ip>; mapped-port P; }`
//     shapes) — grammar-aware, so a `mapped-port` that is really a
//     routing-instance/prefix-name VALUE is skipped.
//
// Every child of a cross-node duplicate (two `then static-nat prefix <ip>
// mapped-port <p>` set lines) is scanned, then the WHOLE operand list folds
// through combineMappedPortOperands ONCE: last-wins when every occurrence is a
// valid 1-65535, and a malformed occurrence in ANY shape or ANY duplicate fails
// closed. There is no first-wins gate that could let a later malformed duplicate
// slip past an earlier valid one (the #6479 cross-node first-wins bug).
//
// The (port, raw, present) triple feeds the strict gate: present is the explicit
// presence signal (C179-038 + fold) that MappedPort==0 and raw=="" cannot carry
// on their own (the literal "0", a non-numeric token, an empty operand, and a
// bare keyword all collapse to port 0 / raw "").
func staticNATMappedPortForNode(t *Node) (port int, raw string, present bool) {
	operands := staticNATMappedPortOperandsFromKeys(t.Keys)
	for _, c := range t.Children {
		if c.Name() == "mapped-port" {
			// Hierarchical sibling `mapped-port <p>` (possibly packed).
			operands = append(operands, mappedPortNodeOperands(c)...)
			continue
		}
		// A target child (`prefix`/`prefix-name` <val> [mapped-port <p>]
		// [routing-instance <ri>]). The modifier may ride on the child's
		// collapsed Keys (flat-set) OR nest inside the child's Children (the
		// canonical hierarchical `prefix <ip> { mapped-port P; }` shape). Scan
		// BOTH — grammar-aware — so a malformed operand in either shape, and in
		// every child of a cross-node duplicate, fails closed.
		operands = append(operands, staticNATMappedPortOperandsFromKeys(c.Keys)...)
		for _, gc := range c.Children {
			if gc.Name() == "mapped-port" {
				operands = append(operands, mappedPortNodeOperands(gc)...)
			}
		}
	}
	return combineMappedPortOperands(operands)
}

// recordNPTv6MappedPortPresence stamps a `mapped-port` PRESENCE signal onto an
// NPTv6 static-nat rule WITHOUT installing a port value (#5523/#6479). NPTv6
// (RFC 6296) translates the IPv6 address prefix and has no transport-port
// concept, so a `then static-nat nptv6-prefix <p6> mapped-port <p>` is invalid
// in EVERY shape (collapsed keys, hierarchical nptv6-prefix child, or a distinct
// `mapped-port` sibling). The host-mask loop skips nptv6 rules entirely, so
// without recording presence a mapped-port on an nptv6 rule reached NO
// validator: a malformed operand was silently accepted (the C179-038 class for
// the nptv6 shape) and a well-formed one was silently ignored. This records
// MappedPortPresent (and the raw token for the diagnostic) so the strict nptv6
// gate (validateNPTv6Strict) rejects it — warns on the lenient no-brick path —
// while keeping MappedPort==0: a port is meaningless on nptv6 and no bogus port
// must cross the wire to the port-less nptv6 dataplane path.
//
// #6479 item 1: it folds through mergeMappedPortState with a FORCED port 0 (nptv6
// never installs a value) so PRESENCE accumulates and, critically, a later clean
// `prefix`/`prefix-name` sibling target in the same `then` block can no longer
// overwrite the stamp back to false — the multi-block nptv6 silent-accept.
func recordNPTv6MappedPortPresence(rule *StaticNATRule, t *Node) {
	_, raw, present := staticNATMappedPortForNode(t)
	mergeMappedPortState(rule, 0, raw, present) // nptv6 has no port; never install one
}

// combineMappedPortOperands folds one-or-more `mapped-port` operands (the
// tokens trailing each `mapped-port` keyword, in AST order) into the
// (port, raw, present) triple the strict gate (validateNATHostMaskStrict)
// consumes. It is called once per static-nat `then` node by
// staticNATMappedPortForNode over the UNION of operands from every AST shape
// (collapsed keys, sibling `mapped-port` child, and duplicate target children)
// so all shapes and duplicates fail closed identically.
//
// Returns (C179-038 + #6479 fold):
//   - no operands:                    (0, "",          false) — keyword absent.
//   - every operand a valid 1-65535:  (last, "<last>", true) — last-wins, the
//     Junos duplicate-stanza rule; a single valid token is the common case.
//     #6479 semantics note: an all-valid DUPLICATE on one target
//     (`mapped-port 8080 mapped-port 9090` → 9090) resolves last-wins,
//     which DIFFERS from origin/master's first-wins (8080). A duplicate
//     mapped-port on a single target is contradictory/malformed authoring
//     (either resolution is defensible); last-wins is the INTENTIONAL
//     choice here for consistency with the Junos duplicate-stanza rule the
//     rest of this fold uses, and is NOT a working-config regression (a
//     duplicate is not a valid production config on master either).
//   - ANY operand malformed (empty, bare, non-numeric, or out-of-range):
//     (0, "<first non-empty bad token>", true) — FAIL CLOSED. A contradictory
//     duplicate (`mapped-port 8080 mapped-port notaport`) is rejected, not
//     silently reduced to the one good value; raw names the offending token
//     (or "" → the strict gate prints "(missing value)" for an empty/bare one).
//
// A malformed operand zeroes the port even when another occurrence is valid, so
// the strict gate's `MappedPort < 1` branch rejects and no bogus port ever
// reaches the dataplane; the lenient load / peer-sync path keeps MappedPort==0
// (a plain 1:1, matching the pre-fix fail-closed behaviour).
func combineMappedPortOperands(operands []string) (port int, raw string, present bool) {
	if len(operands) == 0 {
		return 0, "", false
	}
	present = true
	haveBad := false
	badRaw := ""
	lastValidPort := 0
	lastValidRaw := ""
	for _, op := range operands {
		if p, err := strconv.Atoi(op); err == nil && p >= 1 && p <= 65535 {
			lastValidPort = p
			lastValidRaw = op
			continue
		}
		haveBad = true
		// Prefer the first NON-EMPTY bad token for the diagnostic; an
		// all-empty/bare set leaves badRaw=="" → the gate prints
		// "(missing value)".
		if badRaw == "" && op != "" {
			badRaw = op
		}
	}
	if haveBad {
		return 0, badRaw, true
	}
	return lastValidPort, lastValidRaw, true
}

// mergeMappedPortState folds ONE static-nat target block's mapped-port reading
// (port, raw, present) into the rule's ACCUMULATING mapped-port state, so a later
// clean target block in the SAME `then` block can never silently CLEAR a presence
// or malformed stamp an earlier block set (#6479 item 1, the multi-block silent-
// accept). A single `then` may carry several `static-nat` targets (the
// hierarchical `then { static-nat { nptv6-prefix P { mapped-port BAD; } }
// static-nat { prefix Q; } }` sibling shape); Junos merges them into one action,
// so the mapped-port from ANY sibling is part of that action and must be gated.
// Before this fold the per-target direct assignment `rule.MappedPort, … =
// staticNATMappedPortForNode(t)` let the LAST sibling's (0,"",false) reading
// overwrite an earlier sibling's malformed stamp — the C179-038 class reopened
// for the multi-block shape, in BOTH the nptv6 and non-nptv6 branches.
//
// Semantics (matching combineMappedPortOperands, applied across sibling blocks):
//   - present==false: NO-OP. An absent mapped-port neither stamps presence nor
//     clears an earlier stamp — this is the exact overwrite the fix removes.
//   - the FIRST present block stamps MappedPortPresent (never reset to false here).
//   - a malformed operand in ANY block (present && port==0) LATCHES the rule
//     fail-closed (MappedPort==0, raw naming the offending token); a later valid
//     or absent block cannot un-fail it (order-independent fail-closed).
//   - among all-valid blocks the LAST valid port wins (Junos duplicate-stanza
//     last-wins).
//
// The per-`then`-block reset (compileNATStatic) still runs BETWEEN separate
// `then {}` blocks, preserving the #3850 last-then-block-wins semantics: a whole
// superseded `then` block is dead config, not part of the effective action. This
// accumulation is scoped to sibling targets WITHIN one `then` block.
func mergeMappedPortState(rule *StaticNATRule, port int, raw string, present bool) {
	if !present {
		return
	}
	// Latch: once a malformed operand has been seen for this rule the state is
	// fail-closed (present && MappedPort==0). A later block cannot un-fail it;
	// capture a diagnostic token only if none was recorded yet.
	failClosed := rule.MappedPortPresent && rule.MappedPort == 0
	rule.MappedPortPresent = true
	if failClosed {
		// Capture a diagnostic token only from a MALFORMED operand (port==0), and
		// only if none was recorded yet. A later VALID operand (port>=1) must NOT
		// backfill its token: a bare/empty malformed sibling latched raw=="" =
		// "(missing value)", and a subsequent valid `mapped-port 9090` would
		// otherwise overwrite that provenance, so the strict gate misreported
		// `mapped-port "9090" is not a valid port number` instead of the true
		// "(missing value)" diagnostic. The port==0 guard preserves the malformed
		// provenance (a bare/empty-first then valid-second still reports the
		// empty/missing value), while a later malformed operand may still supply a
		// better-than-empty token (#6479).
		if rule.MappedPortRaw == "" && raw != "" && port == 0 {
			rule.MappedPortRaw = raw
		}
		return
	}
	if port == 0 {
		// This block is present-but-malformed (empty, bare, non-numeric,
		// out-of-range, or the literal "0"): fail closed, name its token.
		rule.MappedPort = 0
		rule.MappedPortRaw = raw
		return
	}
	// This block carries a valid 1-65535 port: last-valid-wins.
	rule.MappedPort = port
	rule.MappedPortRaw = raw
}

// mergeMappedPortForNode reads the genuine `mapped-port` modifier(s) attached to
// one static-nat target node (across every AST shape, via staticNATMappedPortFor-
// Node) and folds the result into the rule's accumulating state
// (mergeMappedPortState). It is the accumulate-don't-overwrite replacement for the
// per-target direct assignment on the prefix / prefix-name branches (#6479).
func mergeMappedPortForNode(rule *StaticNATRule, t *Node) {
	port, raw, present := staticNATMappedPortForNode(t)
	mergeMappedPortState(rule, port, raw, present)
}

// staticNATRoutingInstanceFromKeys scans a collapsed static-nat `then` leaf's
// Keys for the trailing `routing-instance <ri>` translation target (#4292) and
// returns the instance name (or "" when absent). The free-form static-nat leaf
// absorbs the whole `then static-nat <target> routing-instance <ri>` line onto
// one node's Keys in the flat-set shape.
//
// It scans from the END and returns the LAST occurrence, because the Junos
// grammar places the target routing-instance at the TAIL of the line. Scanning
// forward (first match) would return the wrong token if an earlier
// "routing-instance" appeared in the key list — e.g. `then static-nat
// prefix-name routing-instance routing-instance MYVRF`, where the address-book
// entry is pathologically NAMED "routing-instance": first-match would return
// that entry name instead of the trailing "MYVRF". Last-match is strictly more
// correct for the trailing-routing-instance grammar.
func staticNATRoutingInstanceFromKeys(keys []string) string {
	for i := len(keys) - 2; i >= 0; i-- {
		if keys[i] == "routing-instance" {
			return keys[i+1]
		}
	}
	return ""
}

// resolveStaticNATThenPrefixName resolves a `then static-nat prefix-name <name>`
// reference (#4290) to the single literal prefix that names the 1:1 translation
// target. Junos `prefix-name` references a single global address-book entry: an
// `address <name> <prefix>` resolves to its prefix; an `address-set` that
// expands to exactly one address resolves to that address's prefix; anything
// else (undefined, an address with no prefix, an empty / multi-member set,
// dangling) is not a valid scalar 1:1 target and returns ok=false so the caller
// leaves Then=="" and the strict guard rejects it.
func resolveStaticNATThenPrefixName(ab *AddressBook, name string) (string, bool) {
	if ab == nil || name == "" {
		return "", false
	}
	if a, ok := ab.Addresses[name]; ok && a != nil && a.Value != "" {
		return a.Value, true
	}
	if _, ok := ab.AddressSets[name]; ok {
		members, err := ExpandAddressSet(name, ab)
		if err != nil || len(members) != 1 {
			return "", false
		}
		if a, ok := ab.Addresses[members[0]]; ok && a != nil && a.Value != "" {
			return a.Value, true
		}
	}
	return "", false
}

// resolveStaticNATThenPrefixNames resolves every `then static-nat prefix-name`
// reference recorded during compileNATStatic into the rule's literal Then
// target (#4290). It runs AFTER the zone-local address books are folded into the
// global book (compiler.go), so the fully-resolved global book is available
// (compileNAT can run before compileAddressBook within a single `security {}`
// root, so resolution cannot happen inline in the then switch). An unresolvable
// reference leaves Then=="" — validateStaticNATThenTargetStrict then rejects it
// at strict commit (warns on the lenient load / peer-sync path, #1960).
func resolveStaticNATThenPrefixNames(sec *SecurityConfig) {
	ab := sec.AddressBook
	for _, rs := range sec.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.ThenPrefixName == "" || rule.Then != "" {
				continue
			}
			if prefix, ok := resolveStaticNATThenPrefixName(ab, rule.ThenPrefixName); ok {
				rule.Then = prefix
			}
		}
	}
}

// staticNATTargetKeywords is the set of `then static-nat` keywords that name a
// mutually-exclusive TRANSLATION TARGET — the destination a 1:1 rule maps to. A
// well-formed static-NAT rule declares EXACTLY ONE of them (#6483). They are
// distinct from the trailing MODIFIER keywords (mapped-port, routing-instance),
// which refine a target rather than being one.
var staticNATTargetKeywords = map[string]struct{}{
	"prefix":       {},
	"prefix-name":  {},
	"nptv6-prefix": {},
	"inet":         {},
}

// staticNATModifierKeywords are the `then static-nat` trailer keywords that are
// NOT targets: they refine a target rather than being one. When one follows an
// IP-VALUED target keyword (prefix / nptv6-prefix, whose value can never be a
// keyword lexeme) the node is a MODIFIER CARRIER, not a second target — e.g. the
// canonical Junos separate-set-line `then static-nat prefix mapped-port <port>`
// collapses to a `prefix` leaf whose value slot is `mapped-port` (#6479 canonical
// form), and the trailing `routing-instance <ri>` (#4292) rides the same way.
// staticNATCollectTargetIdentsFromKeys uses this set to skip a modifier carrier
// so a lone target carrying a modifier still counts as ONE target.
//
// This carrier-skip is deliberately NOT applied after a NAME-valued keyword
// (prefix-name / routing-instance): their value is an OPAQUE address-book / VRF
// name that may be literally "mapped-port" (#6479 second finding), so the token
// after such a keyword is ALWAYS its value and is consumed as such — never
// re-classified as a modifier that would erase the target.
var staticNATModifierKeywords = map[string]struct{}{
	"mapped-port":      {},
	"routing-instance": {},
}

// isStaticNATKeywordLexeme reports whether tok is a static-nat grammar keyword —
// a translation-target keyword, a trailing modifier keyword, or the "static-nat"
// leaf name — as opposed to an operand VALUE. The bracketed/packed multi-value
// target scan (staticNATCollectTargetIdentsFromKeys) uses it to end a value run:
// after a `prefix`/`nptv6-prefix`/`prefix-name` keyword its IP prefix or address-
// book name value can appear one-or-more times (a lexer-collapsed bracketed list,
// #2419), and the run terminates at the first token that is a grammar keyword —
// a trailing modifier or a new target — which a bracketed value list never
// contains. For prefix/nptv6-prefix the value is an IP that can never equal one
// of these lexemes; for prefix-name the FIRST value is consumed unconditionally
// (a pool may be NAMED "mapped-port"/"prefix"), so the lexeme test only bounds
// the SECOND-and-later packed values.
func isStaticNATKeywordLexeme(tok string) bool {
	if _, ok := staticNATTargetKeywords[tok]; ok {
		return true
	}
	if _, ok := staticNATModifierKeywords[tok]; ok {
		return true
	}
	return tok == "static-nat"
}

// staticNATCollectTargetIdentsFromKeys walks a collapsed static-nat key slice —
// a target child's Keys (`["prefix","<ip>","prefix-name","POOL"]`), the static-nat
// node's own Keys, or a hierarchical bare keyword's Keys (`["prefix"]`) — in
// GRAMMAR ORDER and registers a stable IDENTITY into set for every translation
// target it declares (#6483). It is the SAME slot-classification walk
// staticNATMappedPortOperandsFromKeys uses for the mapped-port scan (#6479): it
// tracks whether each position is a KEYWORD slot or a token already CONSUMED as a
// preceding keyword's value, so a value that is literally a keyword lexeme is
// never re-read as a keyword. Reading only the FIRST target pair (the pre-#6484
// `Keys[1]`/`Keys[2]` read) let a genuine multi-target rule whose targets collapse
// onto ONE node/child count as one and escape the >1 gate.
//
// A lexer-collapsed bracketed list (`prefix [ X Y ]` → ["prefix","X","Y"], #2419)
// packs SEVERAL target values after ONE keyword; each value is a DISTINCT target,
// so the scan registers EVERY packed value, not just the first (the pre-#6484
// single-value read let `prefix [ X Y ]` count 1 and escape the >1 gate).
//
// Per-token roles:
//   - `inet`                     → identity "inet"; NO value slot (i += 1).
//   - `prefix <ip> [<ip>...]` /
//     `nptv6-prefix <p6> [...]`  → identity "<kw>\x00<ip>" for EACH value. The
//     value is an IP that can never be a keyword lexeme. If the token right after
//     the keyword is a modifier the node is a MODIFIER CARRIER (the canonical
//     separate-set-line `prefix mapped-port <p>` form) — register nothing and let
//     the modifier consume its own operand. Otherwise consume EVERY following
//     non-keyword token as a distinct packed IP value, stopping at the first
//     trailing modifier or new target keyword.
//   - `prefix-name <name> [...]` → identity "prefix-name\x00<name>" for EACH name.
//     The FIRST token is the OPAQUE address-book name — always consumed as the
//     value, even if it reads "mapped-port"/"routing-instance"/"prefix" (a pool may
//     be so named), never re-classified as a modifier that would erase the target
//     (#6479 name-slot). Further non-keyword tokens are additional packed names,
//     each a distinct target; the run stops at the first modifier/target keyword.
//   - `mapped-port <p>` /
//     `routing-instance <ri>`    → a MODIFIER; consume its operand (i += 2),
//     register no target. Consuming routing-instance's opaque-name operand keeps a
//     VRF NAMED "prefix"/"inet" from being re-read as a target.
//   - a leading "static-nat" or any stray token → advance one, register nothing.
func staticNATCollectTargetIdentsFromKeys(keys []string, set map[string]struct{}) {
	for i := 0; i < len(keys); {
		tok := keys[i]
		switch {
		case tok == "inet":
			set["inet"] = struct{}{} // no value slot
			i++
		case tok == "prefix-name":
			// Name-valued target. The FIRST token after the keyword is ALWAYS the
			// opaque address-book name — consumed verbatim even if it reads
			// "mapped-port"/"prefix" (a pool may be so named). Any FURTHER
			// non-keyword tokens are additional bracketed/packed name values
			// (`prefix-name [ A B ]` collapses to ["prefix-name","A","B"], #2419),
			// each a DISTINCT target; a trailing modifier or new target keyword
			// ends the name run (a bracketed value list contains no keyword).
			i++
			if i < len(keys) {
				set["prefix-name\x00"+keys[i]] = struct{}{}
				i++
				for i < len(keys) && !isStaticNATKeywordLexeme(keys[i]) {
					set["prefix-name\x00"+keys[i]] = struct{}{}
					i++
				}
			}
		case tok == "prefix" || tok == "nptv6-prefix":
			i++
			if i < len(keys) {
				if _, mod := staticNATModifierKeywords[keys[i]]; mod {
					// Modifier carrier (`prefix mapped-port <p>`, the canonical
					// separate-set-line form): NO prefix value on this node — the
					// value rode a restate line. Register nothing; the modifier
					// case below consumes its own operand.
					break
				}
				// First IP value + any further bracketed/packed IP values
				// (`prefix [ X Y ]` → ["prefix","X","Y"]), each a DISTINCT target.
				// An IP prefix can never be a keyword lexeme, so the run stops at
				// the first trailing modifier or new target keyword.
				for i < len(keys) && !isStaticNATKeywordLexeme(keys[i]) {
					set[tok+"\x00"+keys[i]] = struct{}{}
					i++
				}
			}
		case tok == "mapped-port" || tok == "routing-instance":
			i += 2 // modifier consumes its own operand; not a target
		default:
			i++ // leading "static-nat" or a stray token
		}
	}
}

// staticNATCollectTargetIdents adds a stable IDENTITY string for each translation
// target one `static-nat` `then` node declares into set (#6483). A target's
// identity is its keyword plus, for the address/name/prefix targets, its value
// token (inet has no value, so its identity is just "inet"). Using a SET keyed by
// identity — rather than an occurrence count — is what makes the Junos "restate
// the target to attach a modifier" idiom count as ONE target: the canonical
// separate-set-line mapped-port form authors the SAME target twice,
//
//	set ... then static-nat prefix-name TARGET
//	set ... then static-nat prefix-name TARGET mapped-port 8080   (#5523)
//
// which SetPath keeps as two `prefix-name` children with the SAME value TARGET;
// both map to identity "prefix-name\x00TARGET" and collapse to one. Two GENUINELY
// different targets (a prefix and a prefix-name, an inet and a prefix, two
// different prefixes, or a pool NAMED "mapped-port" alongside a prefix) map to
// different identities and stay distinct.
//
// It FULLY TRAVERSES the node, not just the first pair: it walks the static-nat
// node's own Keys AND every child's Keys through the grammar-role-aware
// staticNATCollectTargetIdentsFromKeys (so the one-line
// `prefix <ip> prefix-name POOL` / `prefix <ip> inet` / `prefix <ip> prefix <ip2>`
// collapse — where two targets land on ONE child's Keys — is counted, as is a
// lexer-collapsed bracketed list `prefix [ X Y ]` / `prefix-name [ A B ]`, #2419),
// and expands the hierarchical value-as-child shape (`prefix { <ip>; <ip2>; }`,
// where each grandchild is a distinct prefix value). A MODIFIER CARRIER (`prefix
// mapped-port <port>`) and a modifier riding a target (`prefix <ip> mapped-port
// <p>`, target `routing-instance <ri>`, or a `prefix-name { POOL; mapped-port P; }`
// block whose nested mapped-port is a modifier — NOT a second name) are NOT extra
// targets — the walk consumes them — matching how staticNATMappedPortForNode reads
// the same node.
func staticNATCollectTargetIdents(t *Node, set map[string]struct{}) {
	// The static-nat node's own Keys (a shape that would collapse the target onto
	// ["static-nat","prefix","<ip>", ...]); the leading "static-nat" is a harmless
	// stray token in the walk. In practice SetPath/the parser put the target on a
	// child, but walk t.Keys too so no collapse shape is missed (identities dedup).
	staticNATCollectTargetIdentsFromKeys(t.Keys, set)
	for _, c := range t.Children {
		// A target/modifier child. Its Keys carry the collapsed token stream:
		// ["prefix","<ip>","prefix-name","POOL"] (one-line multi-target escape),
		// ["prefix","<ip>","mapped-port","<p>"] (single target + modifier),
		// ["prefix-name","POOL"] / ["prefix-name","mapped-port"] (bare target, the
		// latter a pool NAMED "mapped-port"), or ["mapped-port","<p>"] (a modifier
		// sibling — registers nothing).
		staticNATCollectTargetIdentsFromKeys(c.Keys, set)
		// Hierarchical value-as-child: a bare target keyword `prefix { <ip>; ... }`
		// carries its value(s) as grandchildren (child Keys are just ["prefix"]).
		// Each VALUE grandchild is a distinct target (two `prefix { X; Y; }` grand-
		// children = two prefixes → count 2), but a nested MODIFIER grandchild
		// (`mapped-port`/`routing-instance`) is skipped — so `prefix-name { POOL;
		// mapped-port 8080; }` is ONE target, not two (the #6484 second finding).
		// Skipped entirely when the value rides inline on the child's Keys (len >=
		// 2), because then any grandchild is a nested modifier (`prefix <ip> {
		// mapped-port P; }`), not another value.
		kw := c.Name()
		if _, isTarget := staticNATTargetKeywords[kw]; !isTarget || kw == "inet" || len(c.Keys) >= 2 {
			continue
		}
		nameValued := kw == "prefix-name" // opaque names; "mapped-port" is legal
		for gi, gc := range c.Children {
			gname := gc.Name()
			// A nested modifier grandchild (`mapped-port <p>` / `routing-instance
			// <ri>`) is NOT a target value. For prefix/nptv6-prefix (IP-valued) a
			// modifier can never be confused with a value, so skip it wherever it
			// appears. For prefix-name the FIRST grandchild is the OPAQUE pool name
			// — a pool may be NAMED "mapped-port", so it is consumed unconditionally;
			// only a LATER modifier grandchild is the genuine modifier and is
			// skipped. Without the gi>0 guard a bare `prefix-name { POOL;
			// mapped-port 8080; }` registered both POOL and mapped-port and
			// FALSE-REJECTED a valid single-target rule (the #6484 second finding).
			if !(nameValued && gi == 0) {
				if _, mod := staticNATModifierKeywords[gname]; mod {
					continue // a nested modifier grandchild, not a target value
				}
			}
			set[kw+"\x00"+gname] = struct{}{}
		}
	}
}

// staticNATThenTargetCount returns how many DISTINCT translation targets one
// `then {}` block declares across EVERY `static-nat` sibling node in it (#6483).
// The flat-set shape collapses targets onto a single static-nat node with several
// target children; the hierarchical shape carries one target per static-nat
// sibling. Either way the distinct-identity count is the rule's declared target
// cardinality for that block, which the strict gate
// (validateStaticNATSingleTargetStrict) requires to be at most one. Restatements
// of the same target (to attach a mapped-port) share an identity and count once.
func staticNATThenTargetCount(thenNode *Node) int {
	set := make(map[string]struct{})
	for _, t := range thenNode.FindChildren("static-nat") {
		staticNATCollectTargetIdents(t, set)
	}
	return len(set)
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// #3096: capture from scope across zone | interface |
		// routing-instance (static NAT has no `to` clause).
		fromScopes, _ := collectNATScopes(rsInst.node, false)

		// Parse rules (shared across all scope expansions)
		var rules []*StaticNATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &StaticNATRule{Name: ruleInst.name}

			// #3850: iterate EVERY `match {}` block, not just the first — a
			// duplicate block (a `load merge`/`load override` that splits its
			// conditions, or a hierarchical config authored twice) must
			// AND-combine every condition, never be dropped by a FindChild-first
			// read (a fail-open widening of the NAT match). Flat-set is
			// unaffected: SetPath merges duplicate containers into one node
			// (ast_edit.go), so this only changes the hierarchical/parser shape.
			for _, matchNode := range ruleInst.node.FindChildren("match") {
				// #9877 compact: a brace-elided unknown leaf never unfolds (see
				// compiler_nat_source.go) — record an unmodeled packed head.
				if len(matchNode.Keys) > 1 && !natMatchLeafKnown("static", matchNode.Keys[1]) {
					rule.UnknownMatchLeaves = appendNATUnknownMatchLeaf(rule.UnknownMatchLeaves, matchNode.Keys[1])
				}
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						// #6659: read EVERY value, not just the first. The
						// schema declares this leaf `multi: true`, so a bracket
						// list collapses onto m.Keys[1:] (flat-set) or
						// m.Children (hierarchical) exactly like the
						// source-address sibling below. nodeVal kept only the
						// first prefix, and the dropped ones ALSO escaped
						// ValidateIPPrefix — a malformed prefix in any slot but
						// the first committed clean.
						//
						// Match keeps LAST-SIBLING-WINS, which is what this
						// compiler did before #6659 and what the tolerant load
						// path still depends on. Do not "simplify" it to
						// MatchAddresses[0].
						//
						// The two differ only for the REPEATED-set shape, which
						// is precisely the shape that had no coverage. Two
						// sibling `destination-address` nodes give
						// MatchAddresses = [first, second]; nodeVal per child
						// leaves Match = second, while MatchAddresses[0] leaves
						// it = first. Measured end-to-end through
						// buildStaticNATSnapshots via Store.Load +
						// CompileConfigLenient, taking [0] flipped ExternalIP
						// from 198.51.100.1/32 to 192.0.2.1/32 — the published
						// service silently stops being translated and an
						// address that was never a NAT target starts DNAT'ing.
						// tree.Format() renders both lines verbatim, so the
						// divergence round-trips through persistence.
						//
						// For the BRACKET shape the two agree (one node, values
						// on Keys[1:]/Children), which is why every existing
						// test stayed green.
						//
						// A genuinely multi-valued list is REJECTED at strict
						// commit by validateStaticNATMatchAddressesStrict rather
						// than silently collapsing — see MatchAddresses. The
						// tolerant path has no such gate, so it must keep the
						// historical selection.
						//
						// #6673: read the list with multiLeafAuthoredValues, NOT
						// firewallMatchValues. The latter drops empty values while
						// nodeVal selects them, so the scalar could hold a value
						// the list did not contain: `destination-address
						// 192.0.2.1/32` followed by `destination-address [ ]`
						// left Match = "" (an inert rule, exactly as before
						// #6659) with MatchAddresses = ["192.0.2.1/32"]. Every
						// consumer of the list is a validator or a diagnostic
						// that describes what installs, so a list that omits the
						// installed value makes all of them wrong at once — the
						// cardinality gate names a prefix that is not in effect,
						// and the prefix loops "cover" a value that was never
						// selected. multiLeafAuthoredValues guarantees
						// MatchAddresses[0] == nodeVal(m) per statement, so the
						// installed value is always present.
						//
						// Empty entries are not a second prefix: the gates count
						// only non-empty values and the value loops skip them, so
						// this changes no accept/reject outcome.
						rule.MatchAddresses = append(rule.MatchAddresses, multiLeafAuthoredValues(m)...)
						rule.Match = nodeVal(m)
					case "source-address":
						// #3435 (M02): support bracket / repeated lists
						// (`source-address [ a b c ]`) — the schema declares
						// this leaf `multi: true`, so the values collapse onto
						// m.Keys[1:] (flat-set) or m.Children (hierarchical).
						// Reading only nodeVal dropped every prefix after the
						// first. Mirror the source/destination-NAT loops above.
						// #6693: read BOTH slots through the natMatchAddressValues
						// SSOT. The either/or form below read Keys[1:] OR the
						// children, never both, so the MIXED shape
						// `source-address <v1> { <v2>; }` — a value in the
						// identifier slot beside a block — silently dropped the
						// child tail. It is the #4121 defect (fixed for
						// `security policies ... match`) at five NAT sites; the
						// four sibling arms in this same switch already use this
						// reader.
						rule.SourceAddresses = append(rule.SourceAddresses, natMatchAddressValues(m)...)
						if len(rule.SourceAddresses) > 0 {
							// Back-compat: first element stays in the singular
							// field (NAT64 "::/0" tests, peer-sync).
							rule.SourceAddress = rule.SourceAddresses[0]
						}
					case "destination-port":
						// #2491: external (pre-translation) destination
						// port the inbound packet must carry. Schema
						// already range-checks 1..65535; tolerate a
						// non-numeric value defensively (leave 0 = any).
						if p, err := strconv.Atoi(nodeVal(m)); err == nil {
							rule.MatchDestinationPort = p
						}
					default:
						// #9877: record the unknown leaf instead of silently
						// dropping it — the static twin of the source arm
						// (see compiler_nat_source.go). Runs for NPTv6 rules
						// too: this loop precedes then-parsing, and a typo'd
						// scope leaf must not evade the #5818 drop.
						rule.UnknownMatchLeaves = appendNATUnknownMatchLeaf(rule.UnknownMatchLeaves, m.Name())
					}
				}
			}

			// #3850: iterate EVERY `then {}` block, not just the first. A NAT
			// rule carries a single translation action, so a duplicate then
			// block resolves last-wins (Junos merges duplicate stanzas) — the
			// second block's action is applied, never silently dropped. RESET
			// the static-nat target fields at the top of each block so only the
			// LAST block's spec survives (no stale prefix/nptv6/mapped-port from
			// an earlier block). The reset covers ONLY the then-set fields
			// (Then/IsNPTv6/MappedPort) — the match fields (Match/SourceAddress
			// (es)/MatchDestinationPort) are set by the match loop above and MUST
			// persist. A single static-nat then-block is a complete spec, so
			// `prefix X mapped-port P` within one block stays coupled: the reset
			// runs BETWEEN blocks, then the whole block is read (#3850 review).
			//
			// #6479 item 1: WITHIN one `then` block the child loop below may see
			// several `static-nat` sibling targets (the hierarchical `then {
			// static-nat {…} static-nat {…} }` shape). Those siblings are one
			// merged Junos action, so their mapped-port readings ACCUMULATE
			// through mergeMappedPortState (not a per-target overwrite): a later
			// clean sibling can no longer clear a presence/malformed stamp an
			// earlier sibling set, in either the nptv6 or the prefix/prefix-name
			// branch. The reset here is scoped to BETWEEN `then` blocks and still
			// gives #3850 last-then-block-wins — a superseded whole block is dead
			// config, distinct from a merged sibling target that is live.
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				rule.Then = ""
				rule.IsNPTv6 = false
				rule.MappedPort = 0
				rule.MappedPortRaw = ""
				rule.MappedPortPresent = false
				// #4290 / #4292: reset the named-target reference and the
				// translation-target routing-instance alongside the other
				// then-set fields so only the LAST then-block's spec survives.
				rule.ThenPrefixName = ""
				rule.ThenRoutingInstance = ""
				// #6483: count the translation targets THIS `then` block declares,
				// from the AST, BEFORE the if/else chain below collapses them into
				// the shared Then/ThenPrefixName fields (prefix/inet/nptv6 all
				// overwrite Then, so the final field state cannot reveal a
				// >1-target rule). Assigned (not accumulated) per block so the LAST
				// block wins, matching the #3850 last-then-block-wins semantics the
				// field resets above encode. validateStaticNATSingleTargetStrict
				// rejects a count > 1.
				rule.ThenTargetCount = staticNATThenTargetCount(thenNode)
				for _, t := range thenNode.Children {
					if t.Name() == "static-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "nptv6-prefix" {
							// set ... then static-nat nptv6-prefix PREFIX
							rule.Then = t.Keys[2]
							rule.IsNPTv6 = true
							recordNPTv6MappedPortPresence(rule, t)
						} else if np := t.FindChild("nptv6-prefix"); np != nil {
							// static-nat { nptv6-prefix { PREFIX; } }
							rule.Then = nodeVal(np)
							rule.IsNPTv6 = true
							recordNPTv6MappedPortPresence(rule, t)
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix-name" {
							// #4290: set ... then static-nat prefix-name NAME.
							// The named form of `prefix <ip>`: NAME references a
							// global address-book entry whose literal prefix is
							// the 1:1 translation target. Recorded raw here and
							// resolved into rule.Then post-address-book-fold by
							// resolveStaticNATThenPrefixNames (the book may not
							// be compiled yet at this point). Before #4290 this
							// keyword fell through, leaving Then=="" (empty
							// translation target, silent broken static NAT).
							rule.ThenPrefixName = t.Keys[2]
							// #6479: a prefix-name target carries the SAME optional
							// `mapped-port <port>` modifier as a literal prefix
							// (`prefix-name FOO mapped-port 8080`). Collect + gate it
							// identically so a malformed prefix-name mapped-port fails
							// closed instead of silently dropping — the C179-038 class,
							// reopened for the prefix-name shape. The scan is grammar-
							// aware: a prefix-name entry NAMED "mapped-port" is the
							// name value, not a modifier, and registers no port.
							mergeMappedPortForNode(rule, t)
						} else if pn := t.FindChild("prefix-name"); pn != nil {
							// static-nat { prefix-name NAME; }
							rule.ThenPrefixName = nodeVal(pn)
							// #6479: gate a prefix-name mapped-port identically (see
							// the collapsed-keys branch above).
							mergeMappedPortForNode(rule, t)
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
							// #2491 / #6479: recover the optional `mapped-port
							// <port>` modifier(s). Flat-set collapses `prefix
							// <ip> mapped-port <port>` onto this leaf's Keys
							// (`static-nat` is a children:nil schema leaf).
							// staticNATMappedPortForNode folds every occurrence
							// — here and on any sibling/nested/duplicate child —
							// through one combine so a malformed operand in any
							// shape fails closed, and skips a `mapped-port` that
							// is actually a routing-instance/prefix-name VALUE.
							mergeMappedPortForNode(rule, t)
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
							// #2491 / C179-038 / #6479: recover the `mapped-port
							// <port>` modifier(s) across EVERY AST shape at once.
							// The modifier may ride on the `prefix` child's
							// collapsed Keys (`["prefix","<ip>","mapped-port",
							// "<port>"]`), on the canonical separate-set-line
							// `prefix mapped-port <port>` leaf, NESTED inside the
							// prefix child's Children (the hierarchical `prefix
							// <ip> { mapped-port P; }` / `prefix { <ip>;
							// mapped-port P; }` shapes), on a distinct
							// `mapped-port` sibling child (`static-nat { prefix X;
							// mapped-port P; }`), or be split across DUPLICATE
							// `then static-nat prefix <ip> mapped-port <p>`
							// children (two set lines). staticNATMappedPortForNode
							// folds them all through one combine — fail-closed on
							// any malformed occurrence, no first-wins gate — and
							// skips a `mapped-port` that is a routing-instance/
							// prefix-name VALUE (a routing-instance or prefix-name
							// NAMED "mapped-port" no longer false-rejects). It does
							// NOT skip after `prefix`, whose value is always an IP,
							// so `prefix mapped-port <port>` is recovered (#6479).
							mergeMappedPortForNode(rule, t)
						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
							// static-nat { inet; } — NAT64 translation. A mapped-port
							// here needs no separate gate: the `inet` target itself is
							// rejected (#5859, not representable), so the whole rule
							// fails closed regardless of any port it carries.
							rule.Then = "inet"
						} else {
							// #6479 SECOND FINDING: a modifier-only `static-nat`
							// sibling. A hierarchical `then { static-nat {
							// mapped-port <p>; } static-nat { prefix <ip>; } }` block
							// can carry a sibling whose ONLY content is a mapped-port
							// modifier (no prefix / prefix-name / nptv6-prefix / inet
							// target). It matched NO target branch above, so its
							// mapped-port reached no validator and a malformed operand
							// was SILENTLY ACCEPTED — the multi-block analogue of the
							// collection gap the prefix/prefix-name branches close.
							// Route it through the SAME accumulator so it fails closed
							// like every co-located modifier, in either sibling order
							// (mergeMappedPortState latches fail-closed order-
							// independently). A sibling with no mapped-port at all (an
							// empty or routing-instance-only static-nat) reads
							// present=false and is a harmless no-op.
							mergeMappedPortForNode(rule, t)
						}
						// #4292: a translation-target `routing-instance <ri>`
						// may trail ANY of the targets above (Junos allows it on
						// inet and prefix). It rides on the free-form static-nat
						// leaf in one of three AST shapes: collapsed onto t.Keys
						// (["static-nat","prefix","<ip>","routing-instance",
						// "<ri>"]); on the TARGET child leaf's Keys (the common
						// flat-set shape — static-nat has a `prefix`/`inet` child
						// whose Keys carry the trailing routing-instance pair); or
						// as a distinct sibling `routing-instance` child. Captured
						// for the accepted-but-unenforced advisory; the dataplane
						// does not route the post-translation packet against a
						// non-ingress table.
						if ri := staticNATRoutingInstanceFromKeys(t.Keys); ri != "" {
							rule.ThenRoutingInstance = ri
						} else if riNode := t.FindChild("routing-instance"); riNode != nil {
							rule.ThenRoutingInstance = nodeVal(riNode)
						} else {
							for _, c := range t.Children {
								if ri := staticNATRoutingInstanceFromKeys(c.Keys); ri != "" {
									rule.ThenRoutingInstance = ri
									break
								}
							}
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand for each from-scope (#3096).
		for _, fs := range fromScopes {
			rs := &StaticNATRuleSet{
				Name:  rsInst.name,
				Rules: rules,
			}
			applyStaticNATFromScope(rs, fs)
			sec.NAT.Static = append(sec.NAT.Static, rs)
		}
	}
	return nil
}
