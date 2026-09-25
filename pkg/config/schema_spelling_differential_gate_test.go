package config

// schema_spelling_differential_gate_test.go — the #2419 multi-value-leaf gate.
//
// WHAT THIS GATE ASSERTS
//
// For every value-bearing leaf in setSchema, a two-element list authored in one
// spelling must compile to the same thing as the same list authored in any
// other spelling. The Junos grammar admits five:
//
//	A  hierarchical bracket   leaf [ v1 v2 ];
//	B  hierarchical block     leaf { v1; v2; }
//	C  hierarchical repeated  leaf v1; leaf v2;
//	D  flat-set bracket       set <path> leaf [ v1 v2 ]
//	E  flat-set repeated      set <path> leaf v1   /   set <path> leaf v2
//
// A compiler that reads one side of the AST agrees with itself in some
// spellings and not others, which is the #2419 defect class: the operator's
// config renders back intact and the compiler installed less than it says.
//
// Three classes are reported, and the third is not a refinement of the first
// two — it is the one that catches a reader which ignores a shape ENTIRELY
// rather than truncating it:
//
//	A  shape-dependent drop      some spellings keep the 2nd value, others drop it
//	B  uniform drop, multi leaf  EVERY spelling drops it at a declared value list
//	C  shape-dependent inertness some spellings read the leaf, others do not read
//	                             it at all (multi leaves only)
//
// WHY A BEHAVIOURAL DIFFERENTIAL AND NOT A LINT
//
// There is no single correct reader to lint FOR. This package now contains at
// least six accumulating readers — firewallMatchValues, multiLeafAuthoredValues,
// proxyARPAddressValues, eventMultiWordLeafValues, plainListValues (#7126
// single-sourced #6694's fabricMemberValues into it), and ntpServerValues, the
// last of which must additionally skip per-value option KEYWORDS. A rule
// matching "reads Keys[1]" would flag compliant code, and would have missed the
// #7126 sites entirely: both of those read Keys[1:] AND Children exactly as
// CLAUDE.md instructs, and still dropped, because reading Children is not the
// same as reading every KEY of each child. A differential has no such blind
// spot — it asks whether the compiler disagrees with ITSELF, which is the defect.
//
// ============================================================================
// THREE WAYS THIS HARNESS WAS ITSELF WRONG, AND HOW EACH WAS CAUGHT
// ============================================================================
//
// These are recorded here rather than in a commit message because each is a
// general trap for anyone writing a sweep, and because two of them made the
// harness report ZERO findings in whole subtrees while looking healthy.
//
// (1) A SWEEP THAT CANNOT FIND THE BUG YOU ALREADY HAVE IS A SWEEP THAT REPORTS
//     ZERO. The first version emitted `interfaces fab0 { ... }` for a
//     wildcard-named level, which the brace parser reads as Keys=["interfaces",
//     "fab0"] — one node, not two. The interface compiler never saw the
//     interface, so EVERY spelling compiled empty and the differential happily
//     reported agreement. It silently suppressed every finding under every
//     wildcard-rooted subtree, including #6694, which was known to be there at
//     the time. The distinction that fixes it: an `args` token belongs to the
//     SAME brace level as its keyword (`policy-statement P { ... }`), a WILDCARD
//     name opens a NEW one (`interfaces { fab0 { ... } }`). Hence the two
//     synthetic prefixes below, which is the only reason braceConfig can tell
//     them apart from a flat token slice.
//     The general form: calibrate a sweep against defects you have already
//     confirmed, BEFORE trusting it on code you have not inspected.
//
// (2) "DID THE LITERAL TOKEN SURVIVE" IS BLIND TO TRANSFORMED AND REJECTED
//     VALUES. The second version asked whether the authored token appeared in
//     the compiled config. A transformed value never does — CoS `code-points
//     [ ef af11 ]` compiles to a packed byte slice ("DSCPValues":"Lgo="), and
//     vlan-id-list compiles to ints. And a value the leaf's domain REJECTS makes
//     every spelling compile empty, so the differential sees agreement; that is
//     exactly why #6697 was missed with a synthetic token like "zzqaaa1", which
//     is not a DSCP alias. The primitive used now is encoding-independent:
//
//         dropped(spelling) := compile(spelling, [v1]) == compile(spelling, [v1 v2])
//
//     It does not care whether the value lands as a string, an int, a bitmask or
//     a byte slice — only whether the second value changed anything. The value
//     pairs below span several domains for the same reason.
//
// (3) THE FIX FOR (2) INTRODUCED A THIRD: "OUTPUT UNCHANGED" IS ALSO TRUE WHEN
//     THE LEAF NEVER COMPILED AT ALL. A synthetic parent path the compiler
//     rejects makes every form identical, and the leaf then looks like a uniform
//     drop. That filled the report with VRRP `virtual-address` and security
//     policy `then log` — both of which have readers documented as CORRECT.
//     The baseline guard below requires the FIRST value to move the output off
//     the no-value baseline before any verdict is recorded. Those two dropped
//     straight out when it was added, which is this gate's non-vacuity argument:
//     the guard was validated against known-GOOD code, not only against known
//     bad code.
//
// (4) THE BASELINE GUARD WAS DEFEATED BY THE DIAGNOSTIC CHANNEL. cfg.Warnings
//     is a field of Config, so it was marshalled into the compared string. A
//     value the leaf's domain REJECTS is recorded there by the tolerant compile
//     path — which moves the output off the no-value baseline and satisfies the
//     guard trap (3) added. Worse, the CoS readers fail FAST on the first bad
//     token, so `[v1]` and `[v1 v2]` produced the IDENTICAL single warning and
//     the pair read as a uniform drop at a leaf with no defect at all: the
//     second value changed nothing because the FIRST value had already aborted
//     the read. That is how all five #6697 sites reported "uniform drop" on
//     seven of the eight value pairs — every pair whose values are not in the
//     leaf's domain — and why the one pair that IS in the DSCP domain reported
//     the site clean at the same commit. gateMarshal now clears Warnings before
//     comparing: a warning is what the compiler says ABOUT the input, not
//     configuration it installed. The cost is real and is in the coverage line
//     — 19 sites whose only signal was a warning delta lost their verdict.
//
//     The corollary is that a leaf is only covered by a value pair its DOMAIN
//     accepts. The `pcp` pair (3/5) exists because without a pair inside 0..7
//     the ieee-802.1 and inet-precedence classifier leaves reject all eight
//     other pairs, go inert, and carry no verdict — so a fix there could not be
//     proven by removing an allowlist row.
//
// ============================================================================
// COVERAGE — A GREEN GATE IS NOT A SWEPT SCHEMA
// ============================================================================
//
// Measured at the commit that introduced this file. TestSchemaSpellingCoverage
// re-derives these numbers on every run and logs them, so they cannot rot into
// a stale comment.
//
//   - setSchema holds 1003 distinct value-bearing leaf NODES (children == nil,
//     args <= 1, no midKeyword). Only 5 leaves are excluded by construction
//     (args > 1 or a midKeyword), because a two-value list is not meaningful for
//     a compound leaf like route-filter or address-book `address <name> <prefix>`.
//   - The gate enumerates 1017 SITES from those nodes. The two numbers differ,
//     and the difference is not an error: a schemaNode reachable by more than one
//     path (a shared subtree such as the one under both `protocols` and
//     `routing-instances <n> protocols`) is a distinct site at each path, and
//     must be, because the compiler arm reading it may differ per path.
//   - Only 607 of those 1017 sites are actually COMPARED. The remaining 410 come
//     back inert or unstable under synthetic parent paths the compiler rejects —
//     40% of enumerated sites carry NO verdict from this gate, in either
//     direction. That is the single largest limit here.
//   - Class B (uniform drop) is reported ONLY for leaves the schema marks
//     multi: true. A scalar leaf dropping a second value is the schema working,
//     not a defect, so there is nothing to assert there.
//   - Class C (shape-dependent INERTNESS) exists because classes A and B were
//     both blind to #6697, and blind in the same place: "inert" — the FIRST
//     value not moving the output — removes a spelling from the comparison
//     entirely, so a reader that ignores one shape completely looks identical
//     to a leaf that is simply unreachable in that shape. Reverting all five
//     CoS reads left this gate GREEN before class C existed. It is likewise
//     restricted to multi: true leaves, where the block form is legal Junos:
//     unrestricted it fires at 117 sites, almost all scalar leaves for which
//     `leaf { v; }` is not a spelling at all. Restricted, it fires at ZERO at
//     this commit — which is not an argument that it is vacuous but the reason
//     it can be a build gate at all. Its non-vacuity is the mutation: revert
//     the five CoS code-point reads and it names all three classifier sites,
//     where classes A and B stay silent. When it was written the restricted
//     count was 2 (#6695 and the source-NAT `port range`); #6695 landed and
//     `port range` is classified below as the compound tail its own reader says
//     it is.
//   - Nine value pairs. A leaf whose value domain none of them satisfies stays
//     invisible; that is how #6697 hid from version two, and — via trap (4) —
//     how it then reported the WRONG verdict at the same five sites.
//
// A FIFTH LIMIT, measured by #6714 rather than reasoned about: this gate
// authors ONE statement per site. Three of #6714's four sites were not a leaf
// SPELLING at all — a value tail riding on a block CHILD, a repeated
// `commands` statement, and a second `forwarding-table` BLOCK — and no
// enumeration over spellings of a single statement can emit any of them. The
// rule they share: the parser keeps a repeated same-keyed statement as a
// SIBLING, so a compiler that resolves it with FindChild compiles the first
// and discards the rest. That is a `FindChild`-vs-`FindChildren` audit, not a
// differential, and it is written up in docs/config-schema.md ("The one-sided
// read has a SECOND half").
//
// A sixth spelling was measured and deliberately NOT added: `leaf { v1 v2; }`
// (two tokens on one statement inside a value block) still drops at 30 sites,
// all of them readers that legitimately take one key per child
// (multiLeafAuthoredValues, addressSetMemberValues, proxyARPAddressValues).
// Junos writes one value per statement inside a block, so adding it would
// assert a defect at 30 sites no operator can author — the same mistake
// notAValueList exists to avoid.
//
// A SEVENTH spelling WAS added, by #6693: `leaf <v1> { <v2>; }` — a value in
// the identifier slot BESIDE a block (F-hier-mixed). It is the only spelling
// that puts values in BOTH AST slots of one node, Keys[1:] AND Children, and
// every other spelling puts them in exactly one. An either/or reader
// (`Keys` OR children, never both) therefore agrees with itself across A-E and
// drops the tail only here.
//
// That gap is why #6693's five NAT arms survived this gate. A previous
// investigation enumerated A-E, found perfect agreement, and recorded that the
// mixed shape "is not reachable from any config spelling I can author" — a
// conclusion consistent with its own enumeration and wrong about the grammar.
// It is not reachable from FLAT-SET (SetPath emits a leaf at the same level for
// a `multi` leaf and never descends), which is what that enumeration mostly
// covered; hierarchical text reaches it directly.
//
// Adding it moved exactly ONE site beyond the five it was added for, and that
// site is not a defect: see mixedChildIsAModifierBlock.
//
// This gate also sees ONE DIRECTION. It detects a compiler DROPPING a value. It
// cannot detect the opposite defect — a reader PROMOTING a per-value modifier
// keyword into the value list, the hazard #6690 had to avoid — and no detector
// can, because the lexer strips brackets before anything observes them:
// `route 10.9.0.0/16 discard;` and `route [ 10.9.0.0/16 discard ];` compile
// byte-identically. Separating those requires knowledge of the leaf's Junos
// grammar, which today exists only where setSchema models a leaf's modifiers as
// children. Do not read a green run as "no multi-value defects".

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Known-inconsistent sites, keyed by the ISSUE that owns each one.
//
// A row here says: this leaf is KNOWN to compile differently depending on
// spelling, the defect is tracked, and the gate must not fail the build for it.
// Closing the issue is what removes the row — a stale row (a site that now
// agrees) is a HARD FAILURE, precisely so nobody deletes a row to get green
// without the fix that earned it.
//
// Site keys are normalised: every synthetic name the enumerator invents is
// rendered as <*>, so a row survives the schema growing a level.
// ---------------------------------------------------------------------------
var knownSpellingInconsistencies = map[string]string{
	// EMPTY, and that is a state to defend rather than a state to fill. Every
	// row this map has ever carried has been removed by the change that fixed
	// its defect: #6687, #6688, #6692, #6695, #6697, #7126. Adding a row is the
	// THIRD response to a gate failure and the rarest — see the header: fix the
	// read, or classify the leaf as not-a-value-list with a verified reason.
}

// ---------------------------------------------------------------------------
// Sites where the MIXED spelling's child slot is a MODIFIER position, not a
// second value (#6693).
//
// The F-hier-mixed spelling authors `<leaf> <v1> { <v2>; }`. For most value
// leaves that is two members of one list, which is exactly what makes it able
// to catch an either/or reader. For a leaf whose grammar puts a MODIFIER BLOCK
// under an authored value, the child is not a member at all and dropping it is
// correct — so the F verdict carries no information and is excluded from the
// comparison for that site.
//
// This is a THIRD category, deliberately separate from both neighbours below
// and above: notAValueList says the leaf is not a list in ANY spelling, and
// knownSpellingInconsistencies asserts a tracked DEFECT. Neither is true here,
// and using either would state something false.
//
// Every entry is verified by reading where the child tokens land, not assumed
// from the name.
// ---------------------------------------------------------------------------
var mixedChildIsAModifierBlock = map[string]string{
	// archiveSiteEntries (compiler_system.go): "Any CHILD here is a modifier
	// block for the last authored site (`archive-sites a { password S; }`),
	// never an additional site." An unrecognized modifier is ignored, which is
	// what the F verdict sees as a drop. Verified against that function, whose
	// value-on-Keys branch returns before the children are read at all.
	"system archival configuration archive-sites": "child is a per-site modifier block (`{ password S; }`), not a second site",
}

// ---------------------------------------------------------------------------
// Sites the schema models as value leaves but which are NOT value lists, so a
// two-element "list" is not authorable Junos and the differential's verdict is
// meaningless. These are excluded from enumeration rather than allowlisted:
// allowlisting them by issue number would assert a defect that does not exist.
//
// Every entry was verified by inspecting where the extra tokens land, not
// assumed from the name: the screen and firewall entries put them in the
// UnknownLeaves / UnknownActions DIAGNOSTIC buckets, and the named-container
// entries create a second object rather than a second value.
// ---------------------------------------------------------------------------
var notAValueList = map[string]string{
	// #9235: the three `security flow aging` thresholds. These became comparable
	// to this gate for the FIRST TIME when #9235 taught compileFlow to expand
	// `aging`'s flat run — previously the run sat unsplit on the node's Keys and
	// the gate could not reach the individual leaves at all. So the gate is asking
	// a question here that was never askable before, and the answer is the same as
	// for #8939's filter-term `then` actions above: none of these is a value list.
	// Each is `args: 1` with a `smallint` value pair — exactly ONE value.
	//
	// VERIFIED WHERE THE EXTRA TOKENS LAND, as this map's contract requires,
	// rather than asserted from the arity:
	//
	//	aging { early-ageout 10 20; }      early=10   20 DISCARDED
	//	aging { high-watermark 90 95; }    high=90    95 DISCARDED
	//	aging { low-watermark 60 65; }     low=60     65 DISCARDED
	//	aging { early-ageout [ 10 20 ]; }  early=10   20 DISCARDED
	//	aging { early-ageout { 10; 20; } } early=0    the block form is not read
	//
	// and the typed schema walk REJECTS every one of those spellings, so no
	// operator can author a two-element list here; the tolerant path compiles one
	// value and emits a warning naming the leaf. A second threshold is not a
	// second value of the same setting — it is malformed input — which is exactly
	// the distinction this map exists to record.
	"security flow aging early-ageout":   "args:1 smallint threshold; a second token is malformed input, DISCARDED, and the schema walk rejects it (#9235)",
	"security flow aging high-watermark": "args:1 smallint threshold; a second token is malformed input, DISCARDED, and the schema walk rejects it (#9235)",
	"security flow aging low-watermark":  "args:1 smallint threshold; a second token is malformed input, DISCARDED, and the schema walk rejects it (#9235)",

	// issue 8939: the filter-term `then` ACTIONS. These became comparable to
	// this gate for the first time when `packedStatements` was declared on the
	// two `then` nodes -- previously a run sat unsplit on the node's Keys and
	// the gate could not reach the individual actions at all. So the gate is
	// asking a question here that was never askable before, and the answer is
	// that none of these is a value list:
	//
	//	accept / discard / log / syslog   args:0 -- no value to list
	//	count / dscp / forwarding-class / loss-priority / policer /
	//	routing-instance / traffic-class  args:1 -- exactly ONE value
	//
	// VERIFIED WHERE THE EXTRA TOKENS LAND, as this map's contract requires,
	// rather than asserted from the arity:
	//
	//	then { count c1 c2; }        count="c1"        c2 DISCARDED
	//	then { dscp af11 af21; }     dscp="af11"       af21 DISCARDED
	//	then { accept extra1; }      action="accept"   extra1 DISCARDED
	//
	// strictRejects=false and warnings=0 on all three. The silent discard of a
	// trailing token on a `then` action is a separate question from this issue
	// -- it is malformed input rather than a lost list -- and is NOT fixed
	// here; recorded so the next reader knows it was measured and scoped out
	// rather than missed.
	//
	// REGISTERING THESE COSTS 14 SITES OF GATE COVERAGE (1098/706 -> 1076/692)
	// and that cost is TRACKED AT ISSUE 8971 rather than absorbed here. The
	// divergence these sites report is PRE-EXISTING -- they were invisible in
	// a blind bucket until `packedStatements` made them comparable -- so this
	// registration classifies leaves that were always non-lists; it does not
	// hide something the fix broke. That distinction is the whole reason the
	// tracker exists rather than a paragraph.
	// #9017: `family any` is a third firewall filter family, a deep copy of
	// inet's subtree. These eleven `then` leaves are the same leaves with the
	// same arities and the same discard-the-extras behaviour, so they carry
	// the same reasons. Listed explicitly rather than derived from inet: this
	// map is read by siteKey, and a family that silently inherited entries
	// would be a family nobody could see had been checked. Only the ELEVEN the
	// gate actually flagged are here — mirroring the twelfth would register a
	// site the gate never asked about.
	"firewall family any filter <*> term <*> then accept":             "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then count":              "args:1 — one counter name; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then discard":            "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then dscp":               "args:1 — one code point; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then forwarding-class":   "args:1 — one class name; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then log":                "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then loss-priority":      "args:1 — one priority; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then policer":            "args:1 — one policer name; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then routing-instance":   "args:1 — one instance name; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then syslog":             "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall family any filter <*> term <*> then traffic-class":      "args:1 — one code point; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then accept":            "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then discard":           "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then log":               "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then syslog":            "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then count":             "args:1 — one counter name; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then dscp":              "args:1 — one code point; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then forwarding-class":  "args:1 — one class name; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then loss-priority":     "args:1 — one priority; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then policer":           "args:1 — one policer name; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then routing-instance":  "args:1 — one instance name; extra tokens are DISCARDED, verified below",
	"firewall family inet filter <*> term <*> then traffic-class":     "args:1 — one code point; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then accept":           "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then discard":          "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then log":              "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then syslog":           "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then count":            "args:1 — one counter name; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then dscp":             "args:1 — one code point; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then forwarding-class": "args:1 — one class name; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then loss-priority":    "args:1 — one priority; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then policer":          "args:1 — one policer name; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then routing-instance": "args:1 — one instance name; extra tokens are DISCARDED, verified below",
	"firewall family inet6 filter <*> term <*> then traffic-class":    "args:1 — one code point; extra tokens are DISCARDED, verified below",
	// #9899: implicit inet is a fourth `then`, a deep copy of inet's subtree
	// with its own schema identities. Same eleven leaves, same arities, same
	// discard-the-extras behaviour, so they carry the same reasons. Listed
	// explicitly like #9017: this map is read by siteKey, and a root that
	// silently inherited entries would be a root nobody could see had been
	// checked. Only the ELEVEN the gate flags for a filter `then` are here;
	// `reject` has children and is never enumerated, so mirroring it would
	// register a site the gate never asks about.
	"firewall filter <*> term <*> then accept":           "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then count":            "args:1 — one counter name; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then discard":          "args:0 terminal action; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then dscp":             "args:1 — one code point; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then forwarding-class": "args:1 — one class name; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then log":              "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then loss-priority":    "args:1 — one priority; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then policer":          "args:1 — one policer name; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then routing-instance": "args:1 — one instance name; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then syslog":           "args:0 flag; extra tokens are DISCARDED, verified below",
	"firewall filter <*> term <*> then traffic-class":    "args:1 — one code point; extra tokens are DISCARDED, verified below",

	"applications application-set":  "named container: `application-set <name> { ... }`, not a value list",
	"policy-options prefix-list":    "named container: `prefix-list <name> { <prefix>; }`",
	"security nat destination pool": "named container: `pool <name> { ... }`",
	// #9416: `snmp client-list <name> { <prefix>; }` is a NAMED CONTAINER whose
	// first token is the list IDENTITY, not a list member. `multi: true` carries
	// its body (a run of free-form CIDR prefixes with no modelled keywords, so
	// there is nothing to declare as children), which is what makes this gate
	// read it as a value leaf.
	//
	// VERIFIED WHERE THE EXTRA TOKENS LAND, as this map's contract requires,
	// rather than asserted from the shape — compiled with CompileConfigLenient
	// so a malformed prefix quarantines instead of aborting:
	//
	//	client-list [ a b ];        ClientLists{a:[]}       b is a's PREFIX, malformed -> a quarantined, 1 warning
	//	client-list a { b; }        ClientLists{a:[]}       same: b is a's prefix
	//	client-list a; client-list b;  ClientLists{a:[] b:[]}  a SECOND LIST, not a second value
	//	client-list { a; b; }       ClientLists{}           NO name at all — not authorable Junos
	//	client-list L { 10.0.0.0/8; 172.16.0.0/12; }        BOTH prefixes, ONE list
	//
	// So the tail IS a value list and the head is not part of it, which is why
	// the gate's two-element verdict is meaningless here: its second value is
	// the first ELEMENT, not a second element. The last row is the one that says
	// the reader is not simply broken.
	"snmp client-list": "named container: `client-list <name> { <prefix>; }` — the first token is the list IDENTITY; a repeated statement names a SECOND LIST, not a second value",
	// #9416: `client-list-name` is `args: 1` — a community references exactly
	// one list per statement, and repeating the statement adds a reference
	// rather than extending a value. Read through `nodeVal`, this compiler's
	// SSOT for a single-valued leaf, so every spelling agrees on one value.
	//
	// VERIFIED: with `client-list L { 10.0.0.0/8; }` defined,
	//
	//	client-list-name [ L x ];    ClientListNames=[L]   x DISCARDED, commits clean
	//	client-list-name L { x; }    ClientListNames=[L]   x DISCARDED, commits clean
	//	client-list-name L;          ClientListNames=[L]
	//
	// The silent discard of a trailing token on an args:1 leaf is the same
	// pre-existing behaviour the `then count` / `then dscp` entries above
	// record — malformed input rather than a lost list — and is not changed
	// here.
	"snmp community <*> client-list-name":                      "args:1 — one list name per statement; extra tokens are DISCARDED, verified below",
	"snmp community <*> routing-instance <*> client-list-name": "args:1 — one list name per statement; extra tokens are DISCARDED, same reader as the community-level leaf",

	"chassis cluster redundancy-group <*> preempt": "flag with an optional sub-block (`preempt { delay N; }`)",

	"firewall family inet filter <*> term <*> then reject":  "action plus ONE optional reason token; extras land in UnknownActions",
	"firewall family inet6 filter <*> term <*> then reject": "action plus ONE optional reason token; extras land in UnknownActions",

	"security screen ids-option <*> alarm-without-drop": "bare flag; trailing tokens land in UnknownLeaves",

	// #6683: the screen check flags are modelled in setSchema so the packed
	// stanza body can be expanded (compact_tail.go). They are BARE FLAGS, so a
	// "two-element value list" is not a shape they have; what diverges is only
	// WHICH garbage token gets named. In flat-set a trailing token parks as a
	// CHILD and recordChildExtras names Keys[0] of each child; hierarchically it
	// stays on Keys and recordKeyExtras names every one.
	//
	// That difference does NOT reach the commit decision, which is what this
	// gate is protecting. Verified rather than assumed:
	// TestScreenBareFlagTrailingTokenRejectsInBothSpellings compiles trailing
	// garbage on every one of these ten in BOTH spellings and asserts both are
	// REJECTED. If that ever stops holding, these entries are hiding a
	// fail-open and that test reds rather than this allowlist growing quietly.
	"security screen ids-option <*> icmp fragment":          "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> icmp ping-death":        "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> ip source-route-option": "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> ip tear-drop":           "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> tcp fin-no-ack":         "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> tcp land":               "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> tcp no-flag":            "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> tcp syn-fin":            "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> tcp syn-frag":           "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> tcp winnuke":            "bare flag; trailing tokens land in UnknownLeaves (#6683)",
	"security screen ids-option <*> ip ip-sweep":            "container with sub-knobs (`ip-sweep { threshold N; }`)",
	"security screen ids-option <*> tcp port-scan":          "container with sub-knobs",
	"security screen ids-option <*> tcp syn-flood":          "container with sub-knobs",
	"security screen ids-option <*> udp":                    "container with sub-knobs",

	// #6688 fixed the value drop here and its own reader states the
	// classification in as many words: "`port range` is not a value list — it
	// is a compound value TAIL". Both grammars have FIXED arity (`<low> to
	// <high>` and the legacy `low <lo> high <hi>`), and since #6688 a token the
	// grammar does not consume REJECTS, stamping PortRangeInvalidSpec. So a
	// two-element "list" here does change the compiled output — but only by
	// recording an invalid spec, which is not a value-list verdict in either
	// direction. Verified at parseSourcePoolPortRange (compiler_nat_source.go).
	"security nat source pool <*> port range": "compound value tail with fixed arity (`<low> to <high>`), not a value list — see parseSourcePoolPortRange",

	// #6697. The CLASSIFIER `code-points` leaves ARE value lists and were
	// fixed; these two are the rewrite-rule direction, where Junos writes
	// exactly ONE code point per (forwarding-class, loss-priority) entry. The
	// leaf here is `code-point`, and `code-points` is an accepted ALIAS for it
	// whose own setSchema desc says "first value is used". Verified where the
	// extra tokens land: collectCoSDSCPRewriteCodePoint /
	// collectCoS8021RewriteCodePoint read and domain-CHECK every token, then
	// install the first resolvable one — so a second value is rejected if it is
	// invalid and ignored if it is valid. That is a uniform drop by
	// construction, in every spelling, and it is not a defect.
	"class-of-service rewrite-rules dscp <*> forwarding-class <*> loss-priority <*> code-points":       "alias of the scalar `code-point`: a rewrite entry writes ONE code point, first value wins",
	"class-of-service rewrite-rules ieee-802.1 <*> forwarding-class <*> loss-priority <*> code-points": "alias of the scalar `code-point`: a rewrite entry writes ONE code point, first value wins",

	// #9882: the policer `then discard` flag. args:0 — no value to list; a
	// second token is malformed input, not a second value. Became comparable
	// when the #9882 reader started recording packed/extra tokens (the #8939
	// filter-then shape: the gate asks a question that was never askable
	// before, and the answer is that the leaf is not a list).
	//
	// VERIFIED WHERE THE EXTRA TOKENS LAND (word pair zzqaaa1/zzqbbb2), on
	// the strict path AND the lenient path the gate compares:
	//
	//	then { discard [ zzqaaa1 ]; }            Unknown=[zzqaaa1]         (extras past arity)
	//	then { discard [ zzqaaa1 zzqbbb2 ]; }    Unknown=[zzqaaa1 zzqbbb2]  (extras past arity)
	//	then { discard { zzqaaa1; }; }           Unknown=[zzqaaa1]         (hoisted to sibling)
	//	then { discard { zzqaaa1; zzqbbb2; }; }  Unknown=[zzqaaa1 zzqbbb2]  (hoisted to siblings)
	//	set … then discard [ zzqaaa1 ]           Unknown=[zzqaaa1]         (hoisted to sibling)
	//	set … then discard [ zzqaaa1 zzqbbb2 ]   Unknown=[zzqaaa1]         (zzqbbb2 rides UNDER the
	//	                                          unknown head, kept whole)
	//
	// Strict REJECTS every one of these naming zzqaaa1; lenient warns naming
	// zzqaaa1. The lone divergence the gate reports (D-set-bracket drops
	// while the rest keep) is the last row: SetPath nests the bracket run as
	// a chain under the unknown head, and the hoist keeps an unresolvable
	// head whole WITH its subtree (hoistAndSplitRun8939's bound) while the
	// extras reader skips unknown heads (thenActionExtras8971's bound, which
	// policerThenExtras9882 mirrors exactly). So zzqbbb2 lands nowhere while
	// zzqaaa1 is flagged — but the operator-visible verdict is IDENTICAL for
	// the one- and two-token forms (same reject, same warning, both naming
	// zzqaaa1), and loosening either bound would diverge from the filter-term
	// treatment both bounds were built for. The leaf is not a list; the
	// divergence is which unheard token a loud rejection names second.
	// GPT-4: the "keep" above is DIAGNOSTIC, not retention — UnknownActions is
	// the deferred-reject channel (like Warnings, which gateMarshal clears),
	// not installed config. The installed policer (ThenAction="discard",
	// DiscardExcess=true) is byte-identical for the one- and two-token forms;
	// only the rejection record grows. Comparing installed config alone, every
	// spelling drops.
	// O2: `then { foo bar; }` skips bar the same way — foo is recorded, bar
	// rides under the unknown head and is skipped by the unknown-head bound.
	"firewall policer <*> then discard": "args:0 flag; extra tokens land in UnknownActions (strict rejects / lenient warns naming the first) — D-shape second token rides under the unknown head, verified above (#9882)",
}

// Value pairs must span the DOMAINS setSchema's typed leaves accept, not merely
// be distinctive strings — see trap (2) above.
var gateValuePairs = []struct{ name, v1, v2 string }{
	{"word", "zzqaaa1", "zzqbbb2"},
	{"smallint", "101", "202"},
	{"bigint", "40961", "40962"},
	{"cidr", "10.211.212.0/24", "10.211.213.0/24"},
	{"ipv6", "2001:db8::1", "2001:db8::2"},
	{"iface", "ge-5/0/7", "ge-6/0/7"},
	{"dscp", "ef", "af11"},
	// A 3-bit code-point domain (802.1p PCP, IP precedence). Without a pair
	// inside 0..7 the ieee-802.1 / inet-precedence classifier leaves reject
	// every pair above and go inert, so the gate carries NO verdict for them
	// and a fix there cannot be proven by removing an allowlist row.
	{"pcp", "3", "5"},
	{"proto", "bgp", "ospf"},
	// #8481 typed `protocols ospf ... interface <*> interface-type` against the
	// four network types vtysh accepts, and the compiler now DROPS a value it
	// cannot resolve rather than passing it to FRR. Without a pair inside that
	// domain both leaves go inert under every pair above and fall out of
	// `compared` into `unreachable` — the same shape the `pcp` pair was added
	// for, and the same remedy: give the gate a valid pair rather than raise a
	// blind-spot ceiling over a leaf that is genuinely comparable.
	{"ospfnet", "point-to-point", "broadcast"},
	// #9408 typed `protocols ospf reference-bandwidth` as a Junos bandwidth in
	// BITS PER SECOND and range-gated it to the window FRR's Mbps
	// `auto-cost reference-bandwidth (1-4294967)` can express. Every pair above
	// is below the 1 Mbps floor (the largest is 40962 bits/s), so both
	// reference-bandwidth leaves compile to 0 under all of them and fall out of
	// `compared` into `unreachable` — the same shape the `pcp` and `ospfnet`
	// pairs were added for, and the same remedy: give the gate a valid pair
	// rather than raise a blind-spot ceiling over a leaf that is genuinely
	// comparable.
	{"refbw", "100m", "1g"},
	// #9919 F-161 stores only spellable DH groups and records anything else
	// (unparseable, unlisted numeric, empty) as InvalidSpec for the validator
	// to reject/warn. Every pair above is outside the DH domain (the closest
	// is smallint 101/202, both unlisted), so all three dh-group leaves
	// (`security ike proposal`, `security ipsec proposal`, and the policy
	// PFS `keys` leaf) compile every pair to 0 and fall out of `compared`
	// into `advisory` — the same shape the `pcp`/`ospfnet`/`refbw` pairs
	// were added for, and the same remedy: give the gate a valid pair
	// rather than reclassify leaves that are genuinely comparable.
	{"dhgroup", "14", "19"},
}

type gateLeaf struct {
	path  []string
	leaf  string
	multi bool
	// desc is the schema's operator-facing description, read by #7492 to tell a
	// leaf the project has DECLARED unimplemented from one that is silently so.
	desc string
	// args is the schema's declared value arity. #7484 reads it to prove that
	// `args == 0` does NOT imply value-less, so nobody "optimises" the coverage
	// classifier into excluding those leaves.
	args int
}

// site renders the full dotted path; siteKey renders it with synthetic names
// normalised to <*> so allowlist rows survive schema growth.
func (g gateLeaf) site() string {
	return strings.Join(append(append([]string{}, g.path...), g.leaf), " ")
}

// parentKey renders the leaf's PARENT path with synthetic names normalised, so
// a gateParentPrereq row survives schema growth exactly as an allowlist row does.
func (g gateLeaf) parentKey() string {
	toks := append([]string{}, g.path...)
	for i, t := range toks {
		if isSyntheticName(t) {
			toks[i] = "<*>"
		}
	}
	return strings.Join(toks, " ")
}

func (g gateLeaf) siteKey() string {
	toks := append(append([]string{}, g.path...), g.leaf)
	for i, t := range toks {
		if isSyntheticName(t) {
			toks[i] = "<*>"
		}
	}
	return strings.Join(toks, " ")
}

// Synthetic names are prefixed so braceConfig can tell an `args` token (same
// brace level) from a wildcard name (new brace level) — trap (1).
const (
	gateArgPrefix  = "xa"
	gateWildPrefix = "xw"
)

func isSyntheticName(t string) bool {
	return strings.HasPrefix(t, gateArgPrefix) || strings.HasPrefix(t, gateWildPrefix)
}

// sortedChildKeys makes traversal DETERMINISTIC. setSchema's children are Go
// maps; iterating them directly makes both the enumeration order and — where a
// schemaNode is reachable by more than one path — WHICH path wins the dedup
// vary run to run. A gate that reds at random is disabled within a week and
// takes the real signal with it.
func sortedChildKeys(n *schemaNode) []string {
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func enumerateGateLeaves() []gateLeaf {
	var out []gateLeaf
	seen := map[string]bool{}
	argName := func(d int) string { return fmt.Sprintf("%s%d", gateArgPrefix, d) }
	wildName := func(d int) string { return fmt.Sprintf("%s%d", gateWildPrefix, d) }

	var walk func(n *schemaNode, path []string, depth int)
	walk = func(n *schemaNode, path []string, depth int) {
		if depth > 9 {
			return
		}
		for _, key := range sortedChildKeys(n) {
			ch := n.children[key]
			if ch == nil {
				continue
			}
			if ch.children == nil && ch.wildcard == nil {
				// A compound leaf (args > 1, or a fixed mid-keyword) is not a
				// value list; a two-element list is not meaningful for it.
				if ch.midKeyword != "" || ch.args > 1 {
					continue
				}
				g := gateLeaf{path: append([]string{}, path...), leaf: key, multi: ch.multi, args: ch.args, desc: ch.desc}
				if _, skip := notAValueList[g.siteKey()]; skip {
					continue
				}
				if seen[g.siteKey()] {
					continue
				}
				seen[g.siteKey()] = true
				out = append(out, g)
				continue
			}
			head := []string{key}
			for i := 0; i < ch.args; i++ {
				head = append(head, argName(depth*10+i))
			}
			walk(ch, append(append([]string{}, path...), head...), depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, append(append([]string{}, path...), wildName(depth*10+9)), depth+1)
		}
	}
	// `groups` is excluded: apply-groups leaf-list UNION (#4070) is a different,
	// documented contract, and inheritance deliberately makes spellings differ.
	for _, key := range sortedChildKeys(setSchema) {
		ch := setSchema.children[key]
		if ch == nil || key == "groups" {
			continue
		}
		if ch.children == nil && ch.wildcard == nil {
			if ch.midKeyword == "" && ch.args <= 1 {
				g := gateLeaf{leaf: key, multi: ch.multi}
				if _, skip := notAValueList[g.siteKey()]; !skip && !seen[g.siteKey()] {
					seen[g.siteKey()] = true
					out = append(out, g)
				}
			}
			continue
		}
		head := []string{key}
		for i := 0; i < ch.args; i++ {
			head = append(head, argName(i))
		}
		walk(ch, head, 1)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].site() < out[j].site() })
	return out
}

// gateBraceConfig wraps a leaf statement in the brace nesting its path implies.
// See trap (1): `args` names merge into the preceding head, wildcard names do not.
// The chassis identity fallback is the one exception: gateNumericArgs replaces
// its synthetic `args` names with `7`, so those numeric tokens must merge too.
func gateBraceConfig(path []string, stmt string) string {
	var heads []string
	chassisIdentity := gateChassisIdentityPath(path)
	for _, tok := range path {
		if len(heads) > 0 &&
			(strings.HasPrefix(tok, gateArgPrefix) || (chassisIdentity && tok == "7")) {
			heads[len(heads)-1] += " " + tok
			continue
		}
		heads = append(heads, tok)
	}
	var b strings.Builder
	for _, h := range heads {
		b.WriteString(h)
		b.WriteString(" { ")
	}
	b.WriteString(stmt)
	for range heads {
		b.WriteString(" }")
	}
	return b.String()
}

func gateChassisIdentityPath(path []string) bool {
	for i := 0; i+1 < len(path); i++ {
		if path[i] == "redundancy-group" && path[i+1] == "7" {
			return true
		}
	}
	return false
}

// gateMarshal renders the compiled config for comparison with the DIAGNOSTIC
// channel removed — see trap (4) in this file's header. cfg.Warnings is not
// installed configuration; it is what the compiler says ABOUT the input, and
// comparing it makes a REJECTED value look like an installed one.
func gateMarshal(cfg *Config) (string, error) {
	cfg.Warnings = nil
	j, err := json.Marshal(cfg)
	return string(j), err
}

func gateCompileBrace(body string) (string, error) {
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		return "", fmt.Errorf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", err
	}
	return gateMarshal(cfg)
}

func gateCompileSet(cmds []string) (string, error) {
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			return "", err
		}
		if err := tree.SetPath(path); err != nil {
			return "", err
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", err
	}
	return gateMarshal(cfg)
}

var gateSpellingsMulti = []string{"A-hier-bracket", "B-hier-block", "C-hier-repeat", "D-set-bracket", "E-set-repeat", "F-hier-mixed"}

// gateSpellingsScalar omits the REPEATED spellings. For a leaf the schema marks
// multi: false, a repeated statement legitimately REPLACES (last write wins), so
// comparing C and E against the bracket forms would manufacture a finding at
// every scalar leaf in the schema.
var gateSpellingsScalar = []string{"A-hier-bracket", "B-hier-block", "D-set-bracket"}

// spellingVerdicts returns, per spelling, one of:
//
//	"keep"     the second value changed the compiled config
//	"drop"     it did not — the compiler discarded it
//	"inert"    the FIRST value did not change the config either, so this leaf
//	           never reached the compiler under a synthetic parent path and
//	           carries no verdict (trap (3))
//	"unstable" compiling identical input twice produced different output, so no
//	           comparison here is trustworthy — excluded rather than risked
//	"err"      a spelling failed to parse or compile
//
// ---------------------------------------------------------------------------
// TYPED PATH IDENTIFIERS (#7492).
//
// The harness names every `args` slot in a parent path with a synthetic WORD
// (`xa20`). Many slots are not word-typed: `interfaces <if> unit <n>` needs a
// NUMBER, and `unit xa20` does not parse as a unit, so the compiler discards the
// whole unit subtree and every leaf beneath it looks inert. Measured: retrying
// the unreachable leaves with a numeric arg token recovers 72 of 215, all under
// `interfaces <*>` — one general cause, not 46 per-parent ones.
//
// The numeric form is a FALLBACK, never the default. A leaf is compiled with the
// word path first; the numeric path is used only when the word path leaves the
// FIRST value inert and the numeric path does not. So this can only ever turn
// an uncomparable leaf into a comparable one — it cannot change an existing
// verdict, and a slot that genuinely needs a word is unaffected.
//
// The substitution happens at COMPILE time only. gateLeaf.path keeps its word
// tokens, so siteKey()/parentKey() normalisation, the allowlist rows and the
// prerequisite rows are all untouched by which form a leaf ends up using.
// ---------------------------------------------------------------------------

// gateNumericArgs returns a copy of path with every synthetic ARG token replaced
// by a number. Wildcard tokens are left alone: they name a container instance,
// not a typed value, and a numeric name is no more valid there than a word.
func gateNumericArgs(path []string) []string {
	out := make([]string, len(path))
	for i, tok := range path {
		if strings.HasPrefix(tok, gateArgPrefix) {
			out[i] = "7"
			continue
		}
		out[i] = tok
	}
	return out
}

var gateEffectivePathCache = map[string][]string{}

// gateEffectivePath picks the path this leaf is compiled with: the authored word
// form, or the numeric-arg form when the word form makes the leaf unreadable.
func gateEffectivePath(g gateLeaf) []string {
	key := g.siteKey()
	if p, ok := gateEffectivePathCache[key]; ok {
		return p
	}
	chosen := g.path
	numeric := gateNumericArgs(g.path)
	if !equalPaths(numeric, g.path) {
		if wordInert(g, g.path) && !wordInert(g, numeric) {
			chosen = numeric
		}
	}
	gateEffectivePathCache[key] = chosen
	return chosen
}

func equalPaths(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wordInert reports whether the leaf's FIRST value fails to move the compiled
// output under this path — the same "inert" condition the differential uses,
// tried across every value pair so a type mismatch on one pair is not mistaken
// for the leaf being unreadable.
func wordInert(g gateLeaf, path []string) bool {
	base, err := gateCompileBrace(gateBraceConfig(path, ""))
	if err != nil {
		return true
	}
	for _, vp := range gateValuePairs {
		one, err := gateCompileBrace(gateBraceConfig(path, g.leaf+" "+vp.v1+";"))
		if err == nil && one != base {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// PARENT PREREQUISITES (#7492).
//
// The harness authors a leaf ALONE inside its synthetic parent path. Some
// compilers refuse to build the container until a required sibling is present,
// and then the leaf never reaches the compiler at all: every spelling compiles
// to the same thing, the differential calls them all "inert", and the leaf drops
// out of coverage entirely. #7484 measured 228 leaves in that state.
//
// A row here names the statement(s) that make the container materialise. It is
// NOT an allowlist: it asserts nothing about the leaf, claims no defect, and
// cannot hide one. The same text is injected into the zero-, one- and two-value
// configs alike, so it cancels out of every comparison — it only decides whether
// there is a comparison to make.
//
// SCOPE, MEASURED. A general mechanism was tried first and refuted: scaffolding
// each parent with its own other childless leaves (values picked from the gate's
// candidate pool) recovered 2 of 228. Per-parent recipes were then probed
// directly, and most plausible ones do NOT work — `system syslog host <*>` with
// `any any`, `interfaces <*> unit <*> tunnel` with source+destination,
// `vrrp-group` with a virtual-address, and `dhcp-local-server ... interface`
// with an `upto` sibling all still lose the value. Only rows verified end to end
// belong here.
//
// CORRECTION (#8830). The `vrrp-group` observation above is right and its
// ATTRIBUTION is wrong, and the attribution is the harmful half: read as
// written it says "no prerequisite can help here, stop looking", which is what
// a reader will do. The prerequisite is FINE. What defeats it is the synthetic
// INSTANCE NAME. Isolated:
//
//	synthetic names + virtual-address    priority moves output = FALSE
//	real names      + virtual-address    priority moves output = TRUE
//	real iface + SYNTHETIC vrrp id       priority moves output = FALSE
//
// A VRRP group id must be numeric. The gate synthesises `xa60`, the compiler
// discards the group, and every leaf under it reads as inert no matter what
// prerequisite is supplied. The third row isolates it to the group id rather
// than the interface name.
//
// Root cause: `vrrp-group` is declared `args: 1, placeholder: "<group-id>"`
// with no keyValidator, so nothing tells the gate what a valid identity value
// looks like — and nothing rejects an operator typing a non-numeric group id
// either. #7492's typed path-identifier fallback already does exactly this for
// `interfaces <if> unit <n>` (a NUMERIC unit, which moved 72 leaves); it does
// not cover `args: 1` identity slots. Tracked as the typed-identity-slot issue.
//
// So an unknown fraction of the 228 attributed to "not a parent-path problem"
// is this instead, and it is fixable. Do not inherit that count as settled.
//
// Keyed by parentKey() (synthetic names normalised to <*>). Values are brace
// statements; the set-spelling equivalent is derived by stripping the ";".
// ---------------------------------------------------------------------------
var gateParentPrereq = map[string]string{
	// A BGP group with no neighbor is discarded wholesale by compileBGP, so
	// every group-level leaf (description, authentication-key, hold-time, ...)
	// looked inert. One neighbor is enough to make the group materialise.
	// Verified: 13 leaves under `protocols bgp group <*>` move from no-verdict
	// to compared.
	"protocols bgp group <*>": "neighbor 10.211.199.1;",
	// #7492: a `security log stream` with no `host` compiles to NOTHING —
	// cfg.Security.Log.Streams["s"] stays nil — so every stream-level leaf
	// (severity, facility, category, source-address, source-interface, ...)
	// varied its value against an absent object and looked inert. One host is
	// enough to materialise the stream.
	//
	// Measured before adding, the way the BGP row above was: this parent's
	// unreachable count goes 7 -> 0 and its compared count 1 -> 8. All seven
	// are rescued; none is a flag in disguise.
	"security log stream <*>": "host 10.211.199.1;",
	// #9553: family-level active-server-group and relay-agent-interface-id
	// are observable when a complete group is present. The prerequisite
	// deliberately omits both family leaves under test.
	"forwarding-options dhcp-relay dhcpv6": "server-group sg6 2001:db8::5; group g6 active-server-group sg6; group g6 interface ge-0/0/0.0;",
}

// gateLeafPrereq returns the parent prerequisite for this leaf as a brace body
// and as set-command tails. It is suppressed when the prerequisite would name
// the very leaf under test, so a row can never author the value it is meant to
// make observable.
func gateLeafPrereq(g gateLeaf) (string, []string) {
	body := gateParentPrereq[g.parentKey()]
	if body == "" {
		return "", nil
	}
	var sets []string
	for _, stmt := range strings.Split(body, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if fields := strings.Fields(stmt); len(fields) > 0 && fields[0] == g.leaf {
			// The row would author the leaf under test. Refuse the whole row
			// rather than half of it: a partial prerequisite is a different
			// experiment from the one the row was verified for.
			return "", nil
		}
		sets = append(sets, "set "+strings.Join(gateEffectivePath(g), " ")+" "+stmt)
	}
	return body, sets
}

func spellingVerdicts(g gateLeaf, v1, v2 string) map[string]string {
	epath := gateEffectivePath(g)
	flat := "set " + strings.Join(append(append([]string{}, epath...), g.leaf), " ")
	// #7492: prepend the parent prerequisite, identically in every form, so it
	// cancels out of the comparison and only decides whether a comparison exists.
	preBody, preSets := gateLeafPrereq(g)
	brace := func(stmt string) (string, error) {
		if preBody != "" {
			stmt = preBody + " " + stmt
		}
		return gateCompileBrace(gateBraceConfig(epath, stmt))
	}
	sets := func(cmds ...string) (string, error) {
		return gateCompileSet(append(append([]string{}, preSets...), cmds...))
	}
	forms := map[string][3]func() (string, error){
		"A-hier-bracket": {
			func() (string, error) { return brace(g.leaf + ";") },
			func() (string, error) {
				return brace(fmt.Sprintf("%s [ %s ];", g.leaf, v1))
			},
			func() (string, error) {
				return brace(fmt.Sprintf("%s [ %s %s ];", g.leaf, v1, v2))
			},
		},
		"B-hier-block": {
			func() (string, error) { return brace(g.leaf + " { }") },
			func() (string, error) {
				return brace(fmt.Sprintf("%s { %s; }", g.leaf, v1))
			},
			func() (string, error) {
				return brace(fmt.Sprintf("%s { %s; %s; }", g.leaf, v1, v2))
			},
		},
		"C-hier-repeat": {
			func() (string, error) { return brace(g.leaf + ";") },
			func() (string, error) {
				return brace(fmt.Sprintf("%s %s;", g.leaf, v1))
			},
			func() (string, error) {
				return brace(fmt.Sprintf("%s %s; %s %s;", g.leaf, v1, g.leaf, v2))
			},
		},
		"D-set-bracket": {
			func() (string, error) { return sets(flat) },
			func() (string, error) { return sets(fmt.Sprintf("%s [ %s ]", flat, v1)) },
			func() (string, error) { return sets(fmt.Sprintf("%s [ %s %s ]", flat, v1, v2)) },
		},
		"E-set-repeat": {
			func() (string, error) { return sets(flat) },
			func() (string, error) { return sets(flat + " " + v1) },
			func() (string, error) { return sets(flat+" "+v1, flat+" "+v2) },
		},
		// #6693: a value in the IDENTIFIER slot beside a block. It is the only
		// spelling that puts values in BOTH AST slots of one node — Keys[1:]
		// AND Children — and every spelling above puts them in exactly one, so
		// an either/or reader (`Keys` OR children, never both) agrees with
		// itself across A-E and drops the tail here.
		//
		// That gap is why #6693 survived this gate. A previous investigation
		// enumerated A-E, found perfect agreement, and recorded that the mixed
		// shape "is not reachable from any config spelling I can author" — a
		// conclusion consistent with its own enumeration and wrong about the
		// grammar. Adding the spelling is the durable half of that fix: the
		// class is otherwise invisible to the one gate designed to find it.
		//
		// The zero-value form has no mixed spelling (there is nothing to put in
		// the identifier slot), so it reuses the block form's empty body. That
		// only feeds the inert-leaf check, which asks whether the FIRST value
		// changed anything.
		"F-hier-mixed": {
			func() (string, error) { return brace(g.leaf + " { }") },
			func() (string, error) {
				return brace(fmt.Sprintf("%s %s;", g.leaf, v1))
			},
			func() (string, error) {
				return brace(fmt.Sprintf("%s %s { %s; }", g.leaf, v1, v2))
			},
		},
	}
	state := map[string]string{}
	for _, name := range gateSpellingsMulti {
		f := forms[name]
		zero, e0 := f[0]()
		one, e1 := f[1]()
		two, e2 := f[2]()
		if e0 != nil || e1 != nil || e2 != nil {
			state[name] = "err"
			continue
		}
		// Determinism self-check: a compiler that builds a slice by ranging a
		// Go map can emit a different order for identical input, which would
		// make one == two compare unequal at random. Recompile and require
		// self-equality rather than trusting it.
		if again, err := f[1](); err != nil || again != one {
			state[name] = "unstable"
			continue
		}
		if zero == one {
			state[name] = "inert" // trap (3): the leaf never reached the compiler
			continue
		}
		if one == two {
			state[name] = "drop"
		} else {
			state[name] = "keep"
		}
	}
	return state
}

// TestSchemaSpellingDifferentialGate is the gate itself.
func TestSchemaSpellingDifferentialGate(t *testing.T) {
	leaves := enumerateGateLeaves()

	type hit struct {
		site, key, class, pair string
		state                  map[string]string
		multi                  bool
	}
	var hits []hit
	firedKeys := map[string]bool{}
	var comparedBySubtree = map[string]int{}
	compared := 0
	for _, g := range leaves {
		leafCompared := false
		for _, vp := range gateValuePairs {
			state := spellingVerdicts(g, vp.v1, vp.v2)
			cmpSet := gateSpellingsScalar
			if g.multi {
				cmpSet = gateSpellingsMulti
			}
			// #6693: a leaf whose CHILD slot is a modifier position rather than
			// another value has no meaningful mixed-spelling verdict — see
			// mixedChildIsAModifierBlock. Drop F rather than allowlisting the
			// site, because an allowlist row asserts a DEFECT and there is none.
			if _, modifier := mixedChildIsAModifierBlock[g.siteKey()]; modifier {
				var without []string
				for _, n := range cmpSet {
					if n != "F-hier-mixed" {
						without = append(without, n)
					}
				}
				cmpSet = without
			}
			var flags []bool
			inert := 0
			for _, name := range cmpSet {
				switch state[name] {
				case "err", "unstable":
					continue
				case "inert":
					inert++
					continue
				}
				flags = append(flags, state[name] == "drop")
			}
			class := ""
			// Class C, and the reason #6697 survived the first two classes.
			// "inert" means the FIRST value did not move the output either, and
			// the drop/keep comparison discards those spellings — so a reader
			// that ignores one shape ENTIRELY looks like a leaf that is simply
			// unreachable there, and both `[v1]` and `[v1 v2]` compiling to
			// nothing reads as agreement. For a leaf the schema marks multi
			// (a real value list, where the block form IS legal Junos), a
			// spelling that is READ sitting next to one that is INERT is a
			// defect on its own: the CoS block spelling lost the WHOLE
			// classifier, not one code point of it. Measured at the commit that
			// added this: exactly 2 sites, both already owned by a row below.
			if g.multi && inert > 0 && len(flags) > 0 {
				class = "shape-dependent inertness on a multi:true leaf"
				leafCompared = true
			}
			if class == "" && len(flags) < 2 {
				continue
			}
			leafCompared = true
			differs, allDrop := false, true
			for _, f := range flags {
				if f != flags[0] {
					differs = true
				}
				if !f {
					allDrop = false
				}
			}
			switch {
			case class != "":
				// class C already assigned
			case differs:
				class = "shape-dependent drop"
			case allDrop && g.multi:
				// The schema declares a value list and the compiler installs one
				// value in EVERY spelling: the two SSOTs disagree outright. No
				// differential can see this, which is why it is its own class.
				class = "uniform drop on a multi:true leaf"
			}
			if class != "" && !firedKeys[g.siteKey()] {
				firedKeys[g.siteKey()] = true
				hits = append(hits, hit{
					site: g.site(), key: g.siteKey(), class: class,
					pair: vp.name, state: state, multi: g.multi,
				})
			}
		}
		if leafCompared {
			compared++
			if len(g.path) > 0 {
				switch g.path[0] {
				case "protocols", "policy-options", "routing-options":
					comparedBySubtree[g.path[0]]++
				}
			}
		}
	}

	for _, root := range []string{"protocols", "policy-options", "routing-options"} {
		if comparedBySubtree[root] == 0 {
			t.Errorf("the spelling-differential gate compared no leaves under %q; a green global count must not hide an uncovered routing subtree (#10707)", root)
		}
	}

	t.Logf("COVERAGE: %d value-bearing leaves enumerated, %d actually compared "+
		"(%d carry NO verdict — inert/unstable under synthetic parent paths). "+
		"A green run is NOT a swept schema.",
		len(leaves), compared, len(leaves)-compared)

	sort.Slice(hits, func(i, j int) bool { return hits[i].site < hits[j].site })

	// 1. Unexpected inconsistencies fail the build.
	for _, h := range hits {
		if _, known := knownSpellingInconsistencies[h.key]; known {
			continue
		}
		var parts []string
		for _, n := range gateSpellingsMulti {
			parts = append(parts, n[:1]+"="+h.state[n])
		}
		// Class C is a different complaint from A/B and needs a different
		// remedy line: nothing was TRUNCATED there, a whole shape went unread.
		what := "  A two-element list authored in one spelling compiles differently\n" +
			"  from the same list in another."
		if strings.HasPrefix(h.class, "shape-dependent inertness") {
			what = "  This leaf is READ in one spelling and NOT READ AT ALL in another\n" +
				"  (`inert` = even the FIRST value changed nothing). Nothing was\n" +
				"  truncated: whatever the leaf feeds compiles to nothing in that\n" +
				"  spelling."
		}
		t.Errorf("#2419 class: %s\n"+
			"  site      : %s\n"+
			"  siteKey   : %q\n"+
			"  multi     : %v   (value pair: %s)\n"+
			"  spellings : %s\n"+
			"%s Either fix the compiler's read, or —\n"+
			"  if this leaf is not a value list at all — add it to notAValueList\n"+
			"  with the reason, having VERIFIED where the extra tokens land.",
			h.class, h.site, h.key, h.multi, h.pair, strings.Join(parts, " "), what)
	}

	// 2. A stale allowlist row also fails the build: the row must be removed by
	//    whoever fixes the defect, together with closing the issue that owns it.
	//    Deleting a row to get green is thereby not a silent option.
	var stale []string
	for key, issue := range knownSpellingInconsistencies {
		if !firedKeys[key] {
			stale = append(stale, fmt.Sprintf("%q (owned by %s)", key, issue))
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("STALE allowlist row: %s no longer disagrees across spellings.\n"+
			"  The defect appears to be fixed. Remove the row from\n"+
			"  knownSpellingInconsistencies AND close the issue that owns it.\n"+
			"  (If the site merely stopped being COMPARED — see the coverage line —\n"+
			"  say so explicitly rather than dropping the row.)", s)
	}
}

// TestSchemaSpellingGateIsDeterministic runs the enumeration repeatedly and
// requires an identical leaf list each time. setSchema is built from Go maps,
// so without sortedChildKeys both the ordering and the dedup winner vary per
// run — the failure mode that gets a gate disabled.
func TestSchemaSpellingGateIsDeterministic(t *testing.T) {
	first := enumerateGateLeaves()
	var firstKeys []string
	for _, g := range first {
		firstKeys = append(firstKeys, g.siteKey())
	}
	for i := 0; i < 8; i++ {
		got := enumerateGateLeaves()
		if len(got) != len(first) {
			t.Fatalf("run %d enumerated %d leaves, first run %d", i, len(got), len(first))
		}
		for j, g := range got {
			if g.siteKey() != firstKeys[j] {
				t.Fatalf("run %d differs at index %d: %q vs %q", i, j, g.siteKey(), firstKeys[j])
			}
		}
	}
}

// TestSchemaSpellingCoverage re-derives the coverage numbers quoted in this
// file's header on every run, so they cannot rot into a stale comment.
func TestSchemaSpellingCoverage(t *testing.T) {
	var valueBearing, compound int
	visited := map[*schemaNode]bool{}
	var walk func(n *schemaNode, d int)
	walk = func(n *schemaNode, d int) {
		if n == nil || d > 12 || visited[n] {
			return
		}
		visited[n] = true
		for _, key := range sortedChildKeys(n) {
			ch := n.children[key]
			if ch == nil {
				continue
			}
			if ch.children == nil && ch.wildcard == nil {
				if ch.midKeyword != "" || ch.args > 1 {
					compound++
				} else {
					valueBearing++
				}
				continue
			}
			walk(ch, d+1)
		}
		walk(n.wildcard, d+1)
	}
	walk(setSchema, 0)
	t.Logf("setSchema: %d value-bearing leaves, %d compound leaves excluded by construction",
		valueBearing, compound)
	t.Logf("allowlisted known-inconsistent sites: %d; non-value-list exclusions: %d",
		len(knownSpellingInconsistencies), len(notAValueList))
	if valueBearing < 500 {
		t.Errorf("only %d value-bearing leaves found — the enumerator is probably "+
			"walking a truncated schema, which would make the gate silently vacuous",
			valueBearing)
	}
}
