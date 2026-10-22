package config

import (
	"fmt"
	"sort"
	"strings"
)

// Routing-protocol `authentication-type` canonicalization — #8443.
//
// `protocols isis authentication-type` and `protocols rip authentication-type`
// (and the per-interface IS-IS copy, and both routing-instance copies) were
// untyped in setSchema, so ANY string committed. The FRR renderers then act on
// the literal `"md5"` and treat everything else as the weak arm:
//
//	RIP          `ip rip authentication mode md5`   else  `mode text`
//	IS-IS area   `area-password md5`                else  `area-password clear`
//	IS-IS iface  `isis password md5`                else  `isis password clear`
//
// So a one-character typo does not remove authentication — it SILENTLY
// DOWNGRADES md5 to plaintext, with the operator's key on the wire in the clear
// while `show configuration` still says md5. The issue that filed this claimed
// the adjacency came up unauthenticated; that is not what the code does, and
// the `else` arms predate the commit the issue verified against.
//
// OSPF is deliberately NOT served by this canonicalizer. It uses a different
// grammar — a nested `authentication { md5 <id> { key ...; } | simple-password
// ...; }` block whose AuthType is assigned only from matched keywords
// (`compiler_protocols.go:147,159`), so it cannot hold a free-form value at
// all. Widening this domain to cover OSPF's spellings would relax the strict
// one for no gain; OSPF's own defects are separate and handled separately.

// authTypeSpellings maps every accepted operator spelling to its canonical
// form. Junos writes `md5` and `simple`; FRR's RIP spelling for the plaintext
// arm is `text`, which this product emits, so it is accepted as a synonym
// rather than rejected — refusing the vocabulary of our own output is a
// surprising failure mode (the same reasoning that admits `level-2-only` in
// CanonicalISISLevel).
var authTypeSpellings = map[string]string{
	"md5":    "md5",
	"simple": "simple",
	"text":   "simple",
}

// DefaultAuthType is what an unset `authentication-type` means. Empty rather
// than a spelling: with no type configured the renderers take their weak arm
// only when a key is present, and inventing a default here would make the
// unset case render differently than it does today.
const DefaultAuthType = ""

// CanonicalAuthType maps an authored `authentication-type` to its canonical
// spelling. An empty value canonicalizes to DefaultAuthType so unset and
// explicitly-empty travel the same path. ok is false for a value no accepted
// spelling matches.
func CanonicalAuthType(raw string) (canonical string, ok bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return DefaultAuthType, true
	}
	// Case-SENSITIVE, matching CanonicalISISLevel and Junos itself. Folding
	// case would accept `MD5`, which is a widening this leaf has no reason to
	// take on: the operator gets a clear rejection naming the accepted set
	// instead of a silent success, and the two canonicalizers stay comparable.
	c, ok := authTypeSpellings[v]
	return c, ok
}

// AuthTypeSpellings returns the accepted spellings in sorted order, for
// operator-facing error text and schema value examples.
func AuthTypeSpellings() []string {
	out := make([]string, 0, len(authTypeSpellings))
	for k := range authTypeSpellings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidateAuthType is the setSchema typed-leaf validator for
// `authentication-type`. Shared by all five schema copies (RIP, IS-IS
// router-level, IS-IS per-interface, and both routing-instance copies) so a
// spelling cannot be accepted in one context and rejected in another.
func ValidateAuthType(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected one of %s)",
			strings.Join(AuthTypeSpellings(), ", "))
	}
	if _, ok := CanonicalAuthType(raw); !ok {
		return fmt.Errorf(
			"not a valid authentication-type: %q (expected one of %s) — an "+
				"unrecognized value renders as PLAINTEXT authentication, not as "+
				"md5, so the key would travel in the clear",
			raw, strings.Join(AuthTypeSpellings(), ", "))
	}
	return nil
}

// AuthTypeIsMD5 is the single predicate the FRR renderers ask instead of
// comparing against the literal "md5".
//
// This is the belt, and its direction is deliberate. On the TOLERANT load path
// (#1960) a persisted config can still carry a value the strict gate would now
// reject, and this returns false for it — the same plaintext arm the renderers
// already took. It does NOT promote an unrecognized value to md5: a box running
// plaintext today against a peer expecting plaintext would flip to md5 on
// upgrade and the adjacency would drop, turning a silent downgrade into a
// silent outage on the very path whose purpose is that a persisted config still
// boots. The commit gate stops every NEW instance; the warning at the render
// site tells the operator about the existing one.
func AuthTypeIsMD5(raw string) bool {
	c, ok := CanonicalAuthType(raw)
	return ok && c == "md5"
}

// AuthTypeUnrecognized reports whether a stored value is one the strict gate
// would reject — the condition the renderers warn on.
func AuthTypeUnrecognized(raw string) bool {
	_, ok := CanonicalAuthType(raw)
	return !ok
}

// AuthTypeAbsent reports whether no `authentication-type` was authored at all.
//
// #9105: AN ABSENT TYPE AND A CHOSEN PLAINTEXT TYPE WERE THE SAME STATE at the
// render sites, and the renderers could not tell them apart:
//
//	AuthType=""        Unrecognized=false  IsMD5=false  -> renders CLEAR  (SILENT)
//	AuthType="simple"  Unrecognized=false  IsMD5=false  -> renders CLEAR  (SILENT)
//	AuthType="md5"     Unrecognized=false  IsMD5=true   -> renders md5    (SILENT)
//	AuthType="bogus"   Unrecognized=true   IsMD5=false  -> renders CLEAR  (warned)
//
// Look at the `simple` row: it renders `clear` silently and that is CORRECT --
// the operator asked for plaintext. The empty string takes the identical path,
// so "the operator chose plaintext" and "the type was dropped upstream" are
// indistinguishable at the point of decision. No amount of care at the render
// site could have caught it; the information was destroyed before the renderer
// ran.
//
// WHY IT IS A DOWNGRADE AND NOT A LOSS. Authentication stays ON -- the
// area/domain password is still emitted and adjacencies still authenticate,
// with the key in cleartext in every PDU. An operator verifying that
// adjacencies are authenticated sees exactly that, and `show configuration`
// echoes back the `md5` they wrote. A dropped-authentication defect is noisy:
// adjacencies fail. This one succeeds.
//
// This predicate does NOT change what an absent type MEANS -- CanonicalAuthType
// still canonicalizes "" to DefaultAuthType, and the tolerant path still
// renders plaintext rather than flipping a running adjacency to md5 on upgrade
// (the reasoning AuthTypeIsMD5 records). It only lets a caller ASK whether a
// type was authored, which is the question the render sites needed and could
// not put.
func AuthTypeAbsent(raw string) bool {
	return strings.TrimSpace(raw) == ""
}
