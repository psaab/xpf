package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Application inactivity-timeout / timeout accepted range, in seconds. The
// upper bound matches the NAT persistent-binding inactivity-timeout
// (schema_security.go) and the session-timeout range a custom application can
// sensibly set. The lower bound is 0 — NOT 1 — because 0 is a pre-existing,
// documented "inherit the global per-protocol timeout" sentinel: the userspace
// serializer treats InactivityTimeout <= 0 as "use the global timeout"
// (pkg/dataplane/userspace/capabilities.go) and the typed field documents it
// (types_security.go: "0 = default"). `inactivity-timeout 0` committed cleanly
// before #3320 (strconv.Atoi("0") = 0, no error), so the strict gate must keep
// accepting it. #3320 targets MALFORMED values only — non-numeric ("30s",
// "thirty"), negative, and out-of-range (>86400) — all of which fall outside
// [0, 86400].
const (
	appTimeoutMin = 0
	appTimeoutMax = 86400
)

// parseAppTimeout parses an application inactivity-timeout / timeout token.
// It returns the integer value and true when the token is a base-10 integer
// within [appTimeoutMin, appTimeoutMax]; otherwise it returns (0, false) so the
// caller records the raw token for a deferred strict rejection rather than
// silently dropping it. It is the single parse authority shared by the
// top-level and inline-term application paths and the strict commit gate.
func parseAppTimeout(raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	if n < appTimeoutMin || n > appTimeoutMax {
		return 0, false
	}
	return n, true
}

// applicationDirectLeafKeywords is the set of statements Junos allows directly
// inside an `applications application <name>` body. It is the SINGLE source of
// truth shared by applicationDirectLeaves (which classifies a token as a leaf
// or as garbage) and the direct-body switch in compileApplications, so the two
// cannot drift: a keyword added to the switch but not here would be recorded as
// unknown and hard-rejected at commit.
var applicationDirectLeafKeywords = map[string]bool{
	"protocol":           true,
	"destination-port":   true,
	"source-port":        true,
	"inactivity-timeout": true,
	"timeout":            true,
	"icmp-type":          true,
	"icmp-code":          true,
	"alg":                true,
	"description":        true,
	"term":               true,
}

// applicationDirectLeaves flattens the DIRECT match body of an `applications
// application <name>` node into its recognized leaf nodes (in document order),
// plus every token that is not a recognized leaf keyword.
//
// #6524: the flat-set grammar does NOT produce one sibling node per leaf. Only
// the FIRST leaf on a `set` line becomes a child of the application node; each
// subsequent leaf is parked as a child of the PREVIOUS leaf's value node,
// because SetPath descends into the node it just created and these leaves
// declare `children: nil` (schema_security.go). So
//
//	set applications application myapp protocol tcp destination-port 8080
//
// builds a CHAIN — application myapp -> `protocol tcp` -> `destination-port
// 8080` — not two siblings. compileApplications iterated only
// inst.node.Children, saw just `protocol`, and never assigned
// DestinationPort; the application compiled protocol-only and a policy
// matching it permitted ALL TCP (pkg/policymatch: an empty DestinationPort
// matches any port). Nothing caught it: `protocol` / `destination-port` /
// `source-port` are the only application match leaves that are neither typed
// nor `scalar: true`, so no arity gate engages and the chained form validates
// clean at both SchemaValidate and strict commit.
//
// This is the direct-body instance of the dual-AST-shape class already fixed
// next door for application-SET members (applicationSetMemberValues, #5181),
// address-set members (addressSetMemberValues, #4791) and firewall match
// values (firewallMatchValues, #2419) — the direct application body never
// received the same treatment.
//
// Both AST shapes are covered. In the hierarchical / one-leaf-per-set-line
// shape the leaves are already siblings, so the walk emits them in order and
// finds nothing to descend into — byte-identical to the pre-#6524
// inst.node.Children iteration. In the chained flat-set shape it follows each
// leaf's value node down the chain.
//
// Only the FIRST link of a flat-set chain gets a node of its own. Because these
// leaves declare `children: nil`, SetPath stops modelling at that point and
// PACKS every remaining token of the line onto ONE child node, so
//
//	protocol tcp source-port 5000 destination-port 8080
//
// becomes `protocol tcp` -> a single child whose Keys are the flat run
// ["source-port","5000","destination-port","8080"]. Each node's Keys are
// therefore split into one leaf per recognized keyword, the tokens between two
// keywords forming that leaf's value — the same keyword-delimited scan
// parseApplicationTerms performs over an inline term's token stream. A leaf that
// is not the node's own first token is re-emitted as a synthesized `keyword
// value` node so the caller sees a uniform shape.
//
// A token that is neither a recognized leaf keyword nor the single value of the
// leaf it follows is returned in unknown rather than silently dropped. That is
// how a bracketed list on a single-valued leaf is caught: `protocol [ tcp udp ]`
// collapses per #2419 onto ONE leaf (the lexer strips the brackets), landing the
// tail either in the packed Keys or as a child value node, and a direct
// application body has room for exactly one protocol and one port.
//
// `term` is emitted as a leaf and terminates the scan: the rest of the run is
// the term's own opaque token stream, which parseApplicationTerms flattens (and
// guards with UnknownTermLeaves, #3352).
func applicationDirectLeaves(appNode *Node) (leaves []*Node, unknown []string, unknownTokens []string) {
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if n == nil || len(n.Keys) == 0 || n.Keys[0] == "" {
				continue
			}
			descend := true
			for i := 0; i < len(n.Keys); {
				kw := n.Keys[i]
				if !applicationDirectLeafKeywords[kw] {
					// Either a typo'd statement or a stray value token; both
					// carry a constraint the compiler cannot honor.
					//
					// POISON the remainder of this run and this node's subtree
					// rather than skipping the token and RECOVERING the next
					// recognized keyword. The tokens after an unparsable one
					// belong to the same statement the parser could not model,
					// so compiling them yields an application the operator never
					// authored — and, critically, one that is WIDER than what
					// master produced. Master ignored an unrecognized child node
					// whole, so `bogus value protocol tcp` left the application
					// PROTOCOL-LESS and therefore unrepresentable (fail-closed:
					// pkg/policymatch reports ContentRejected, the #2124 gate
					// refuses to arm). Recovering `protocol tcp` out of that same
					// line turns an inert residual into an ACTIVE all-TCP permit
					// on the boot / HA SyncApply paths, where the strict reject is
					// only a warning. Sibling leaves are unaffected: they are
					// separate nodes, so a stray `bogus value` line still leaves a
					// neighbouring `protocol tcp` line compiled exactly as master
					// compiled it.
					unknown = append(unknown, kw)
					// #9595: keep every token of the poisoned run (the keyword,
					// its value, and anything a flat-set chain parked below it),
					// so the tolerant path can tell a lost match constraint from a
					// harmless stray statement by the value's shape.
					unknownTokens = append(unknownTokens, n.Keys[i:]...)
					unknownTokens = appendSubtreeKeys9595(unknownTokens, n.Children)
					descend = false
					break
				}
				if kw == "term" {
					if i == 0 {
						// The node IS the term: hand it over untouched so
						// parseApplicationTerms still sees its Children.
						leaves = append(leaves, n)
						descend = false
					} else {
						leaves = append(leaves, &Node{Keys: append([]string(nil), n.Keys[i:]...)})
					}
					break
				}
				// RESERVE the value slot before resuming the keyword scan.
				// Every one of these leaves is `args: 1`, so it consumes
				// exactly ONE token as its value even when that token happens
				// to spell a grammar keyword — `description destination-port`
				// is a description whose text is "destination-port", not a
				// description followed by a port statement. Without the
				// reservation the scan synthesized a PHANTOM valueless
				// `destination-port` leaf that reset an already-assigned field
				// back to "" (an unset port matches EVERY port on the tolerant
				// path — the exact widening this change exists to close) and
				// unconditionally set hasDirectBody, falsely tripping the
				// #3366 mixed direct+term gate on a term-only application.
				start := i
				i++
				valStart := i
				if i < len(n.Keys) {
					i++
				}
				// Any FURTHER non-keyword tokens are a bracket-list tail.
				for i < len(n.Keys) && !applicationDirectLeafKeywords[n.Keys[i]] {
					i++
				}
				vals := n.Keys[valStart:i]
				if kw == "description" {
					// `description` is a TAIL leaf, not an `args: 1` value leaf:
					// Junos takes its text to the end of the statement, so an
					// unquoted multi-word description is legal config. Joining
					// the run keeps the text intact instead of recording the
					// second and later words as unknown content and
					// hard-rejecting the line at commit, over a METADATA leaf
					// with no bearing on what the application matches. It also
					// stops a description from poisoning the rest of the run.
					//
					// Which spellings this actually reaches is worth stating
					// exactly, because the surrounding gates cover the rest and
					// an over-broad claim here would invite someone to loosen a
					// gate master also held. A multi-word description occupies
					// one of three positions:
					//
					//   - SIBLING (hierarchical, or its own `set` line):
					//     `description "my web app";` arrives quoted as one
					//     token, or unquoted as this node's own Keys run. The
					//     schema's `scalar: true` arity (validateScalarValueLeaf
					//     / #3332) is untouched and still governs it.
					//   - HEAD of a flat-set chain: `set ... description my web
					//     app [protocol tcp]` parks the tail in a CHILD node, so
					//     the run this branch joins is just ["my"] and the child
					//     opens with "web". SchemaValidate DOES see that shape
					//     and rejects it ("unexpected trailing token \"web\""),
					//     exactly as it did on master — so the line stays a
					//     commit error, and the join below is not what decides
					//     it.
					//   - PACKED TAIL of a flat-set chain: `set ... protocol tcp
					//     description my web app` packs the whole description
					//     onto ONE node's Keys, BELOW the depth SchemaValidate
					//     walks (it returns nil). This is the only position the
					//     join actually rescues, and the only one where a
					//     spelling master committed would otherwise become a new
					//     hard reject.
					//
					// So the compiler does not invent a second, broader arity
					// rule for a leaf that cannot affect enforcement; it covers
					// the one position no existing gate reaches.
					leaves = append(leaves, &Node{Keys: []string{kw, strings.Join(vals, " ")}})
					continue
				}
				poisoned := false
				if len(vals) > 1 {
					// A single-valued leaf carrying a bracket-list tail. Record
					// the surplus and poison the rest of the run for the same
					// reason as an unknown keyword above: `destination-port
					// [ 22 23 ] protocol tcp` must not drop `23` and then
					// RECOVER `protocol tcp`, which would arm a TCP permit where
					// master left the application protocol-less.
					unknown = append(unknown, vals[1:]...)
					unknownTokens = append(unknownTokens, vals[1:]...)
					poisoned = true
				}
				if start == 0 {
					// nodeVal reads this node's own Keys[1], so pass it through
					// unchanged — byte-identical to the pre-#6524
					// sibling/hierarchical path.
					leaves = append(leaves, n)
				} else {
					syn := &Node{Keys: []string{kw}}
					if len(vals) > 0 {
						syn.Keys = append(syn.Keys, vals[0])
					}
					leaves = append(leaves, syn)
				}
				if poisoned {
					descend = false
					break
				}
			}
			if !descend || len(n.Children) == 0 {
				continue
			}
			if len(n.Keys) < 2 {
				// Value-in-child shape (nodeVal's Children[0] fallback): the
				// first child IS this leaf's value, so only the rest continue
				// the chain.
				walk(n.Children[1:])
				continue
			}
			walk(n.Children)
		}
	}
	walk(appNode.Children)
	return leaves, unknown, unknownTokens
}

// applicationTermKeys reassembles the token stream of an inline `term` node
// across both AST shapes — hierarchical packs every value onto prop.Keys, the
// flat-set path splits them across prop.Keys and prop.Children — and returns
// nil for a term with no name token.
//
// It is the shared reader for the two places that must agree on what a term
// generates: compileApplications (which WRITES `<parent>-<term>` into
// apps.Applications) and collectApplicationCollisions (which must PREDICT those
// same names to guard the flat Junos namespace). Before #6524 both open-coded
// the reassembly; the collision gate additionally enumerated the application
// node's immediate Children while the compiler moved to applicationDirectLeaves,
// so a CHAINED `term` was compiled but invisible to every namespace gate (see
// collectApplicationCollisions).
//
// The returned slice is always a fresh copy. The compiler previously sliced
// `prop.Keys[1:]` and appended child keys onto it, which can write into the
// node's own backing array whenever that slice has spare capacity — a latent
// AST-corruption hazard the copy removes.
func applicationTermKeys(prop *Node) []string {
	if prop == nil || len(prop.Keys) < 2 {
		return nil
	}
	allKeys := append([]string(nil), prop.Keys[1:]...)
	for _, c := range prop.Children {
		allKeys = append(allKeys, c.Keys...)
	}
	return allKeys
}

// applicationTermNodes returns the inline `term` leaves of an `applications
// application <name>` body, walking the direct body with applicationDirectLeaves
// so a term reached through a flat-set CHAIN is found in both AST shapes. It is
// the enumeration half of the term contract shared with applicationTermKeys.
func applicationTermNodes(appNode *Node) []*Node {
	leaves, _, _ := applicationDirectLeaves(appNode)
	var terms []*Node
	for _, leaf := range leaves {
		if leaf.Name() == "term" {
			terms = append(terms, leaf)
		}
	}
	return terms
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("application")) {
		appName := inst.name
		app := &Application{Name: appName}

		var terms []*Application
		// #3366: track whether the application carries a DIRECT match body
		// (protocol / destination-port / source-port / inactivity-timeout /
		// timeout / icmp-type / icmp-code / alg) at the application level, as
		// opposed to one or more `term` sub-blocks. Junos requires a custom
		// application to be EITHER scalar/direct OR term-based, never both. When
		// both are present the all-or-nothing store below kept only the terms and
		// silently DROPPED the direct match (e.g. a deny `protocol tcp
		// destination-port 22` erased by an unrelated term), so the parent app
		// name is recorded for the strict structure gate. `description` does NOT
		// count — it is metadata propagated onto every generated term, not a match
		// constraint.
		hasDirectBody := false
		// #5574: value-aware conflict tracking for the DIRECT (scalar) match body,
		// mirroring the inline-term duplicate detection in parseApplicationTerms
		// (dstPortSet / srcPortSet / algSet / timeoutSet / icmpTypeSet /
		// icmpCodeSet -> DuplicateTermLeaves). A
		// direct application stores each scalar leaf into a SINGLE typed field, so
		// two conflicting sibling leaves (protocol tcp; protocol udp;
		// destination-port 22; destination-port 53) were last-writer-wins — only
		// the FINAL value was enforced, with no commit error, so a deny referencing
		// the app under-matched. Track each scalar leaf's first assigned value and
		// record a CONFLICTING repeat (a differing value that silently discards the
		// earlier one) on app.DuplicateDirectLeaves for the strict structure gate.
		// An idempotent same-value repeat is harmless and accepted. Unlike the
		// inline-term path, `protocol` IS tracked — the direct body has no
		// multi-protocol syntax, so a second protocol overwrites rather than adding
		// a term. The comparison uses the SAME effective form each field is stored
		// in (resolved ports, parsed timeouts/icmp, normalized protocol) so an
		// alias restate (icmp / junos-icmp-all) is not a false conflict.
		var dupDirectLeaves []string
		var (
			incompleteDirectLeaves                       []string
			protoSet, dstSet, srcSet, algSet, timeoutSet bool
			itypeSet, icodeSet                           bool
			protoVal, dstVal, srcVal, algVal             string
			timeoutVal                                   int
			itypeVal, icodeVal                           uint8
		)
		// #6524: walk the direct body across BOTH AST shapes. In the flat-set
		// shape the leaves form a CHAIN (`protocol tcp` -> `destination-port
		// 8080`), not siblings, so iterating inst.node.Children alone saw only
		// the first leaf and compiled the application protocol-only.
		directLeaves, unknownDirect, unknownDirectTokens := applicationDirectLeaves(inst.node)
		app.UnknownDirectLeaves = unknownDirect
		app.UnknownDirectTokens = unknownDirectTokens
		for _, prop := range directLeaves {
			// #8339: a RECOGNIZED value-taking leaf with no value. Checked once
			// here rather than as an `else` on each arm, mirroring the term
			// path -- a per-arm guard has to be repeated for every future
			// value-taking leaf and is the duplication that drifts.
			//
			// The consequence is a permit-WIDENING, not a dropped statement:
			// nodeVal returns "" for a 1-key childless node, resolveAppPort
			// passes it through, and portInSpec("") returns true for every
			// port (pkg/appid/runtime.go). A dangling `destination-port` on
			// `protocol tcp` therefore matched EVERY TCP port, on the STRICT
			// commit path, with the config rendering exactly as typed.
			if valueTakingApplicationLeaves[prop.Name()] && nodeVal(prop) == "" {
				incompleteDirectLeaves = append(incompleteDirectLeaves, prop.Name())
				continue
			}
			switch prop.Name() {
			case "protocol":
				hasDirectBody = true
				v := nodeVal(prop)
				if protoSet && normalizeProtocol(v) != normalizeProtocol(protoVal) {
					dupDirectLeaves = append(dupDirectLeaves, "protocol")
				}
				protoSet, protoVal = true, v
				app.Protocol = v
			case "destination-port":
				hasDirectBody = true
				v := resolveAppPort(nodeVal(prop))
				if dstSet && v != dstVal {
					dupDirectLeaves = append(dupDirectLeaves, "destination-port")
				}
				dstSet, dstVal = true, v
				app.DestinationPort = v
			case "source-port":
				hasDirectBody = true
				v := resolveAppPort(nodeVal(prop))
				if srcSet && v != srcVal {
					dupDirectLeaves = append(dupDirectLeaves, "source-port")
				}
				srcSet, srcVal = true, v
				app.SourcePort = v
			case "inactivity-timeout", "timeout":
				hasDirectBody = true
				if v := nodeVal(prop); v != "" {
					if n, ok := parseAppTimeout(v); ok {
						// inactivity-timeout / timeout are ALIASES for the same
						// field: both set to the same number is idempotent, a
						// different number is a conflict. Record the keyword used.
						if timeoutSet && n != timeoutVal {
							dupDirectLeaves = append(dupDirectLeaves, prop.Name())
						}
						timeoutSet, timeoutVal = true, n
						app.InactivityTimeout = n
					} else {
						// #3320: a non-numeric / out-of-range / unit-suffixed
						// value was silently dropped here (Atoi error ignored),
						// leaving InactivityTimeout at 0 so the application fell
						// back to the global per-protocol timeout. Record the raw
						// token so validateApplicationSpecsStrict can reject it.
						app.UnknownTimeouts = append(app.UnknownTimeouts, v)
					}
				}
			case "icmp-type":
				// #3348: explicit ICMP/ICMPv6 message-type constraint for a
				// custom application. The schema range-validates 0..255 on the
				// strict commit path (schema_security.go ValidateInteger). The
				// tolerant load / peer-sync path does NOT run SchemaValidate, so
				// record a malformed value (mirroring UnknownTimeouts) rather than
				// silently dropping it — a dropped value would leave an ICMP app
				// UNCONSTRAINED (matches all types), a fail-open widening.
				hasDirectBody = true
				if v := nodeVal(prop); v != "" {
					if t, ok := parseICMPTypeCode(v); ok {
						if itypeSet && *t != itypeVal {
							dupDirectLeaves = append(dupDirectLeaves, "icmp-type")
						}
						itypeSet, itypeVal = true, *t
						app.ICMPType = t
					} else {
						app.UnknownICMP = append(app.UnknownICMP, v)
					}
				}
			case "icmp-code":
				hasDirectBody = true
				if v := nodeVal(prop); v != "" {
					if c, ok := parseICMPTypeCode(v); ok {
						if icodeSet && *c != icodeVal {
							dupDirectLeaves = append(dupDirectLeaves, "icmp-code")
						}
						icodeSet, icodeVal = true, *c
						app.ICMPCode = c
					} else {
						app.UnknownICMP = append(app.UnknownICMP, v)
					}
				}
			case "alg":
				hasDirectBody = true
				v := nodeVal(prop)
				if algSet && v != algVal {
					dupDirectLeaves = append(dupDirectLeaves, "alg")
				}
				algSet, algVal = true, v
				app.ALG = v
			case "description":
				app.Description = nodeVal(prop)
			case "term":
				// Inline term: "term <name> [alg <a>] protocol <p> [source-port <sp>]
				//               [destination-port <dp>] [inactivity-timeout <t>];"
				allKeys := applicationTermKeys(prop)
				if len(allKeys) == 0 {
					continue
				}
				termApps := parseApplicationTerms(appName, allKeys)
				terms = append(terms, termApps...)
			}
		}

		// #3348: a custom application whose `protocol` is the junos-ping /
		// junos-pingv6 alias must carry the same echo-request type constraint
		// the predefined junos-ping object does (#3020). Without it the alias
		// lowered to bare ICMP with ICMPType=nil, which the userspace matcher
		// (and the pkg/policymatch simulator) treat as match-ALL ICMP — silently
		// widening any policy referencing the app to every ICMP type
		// (unreachable / redirect / timestamp / ...). Apply the default AFTER the
		// child loop so an explicit `icmp-type` leaf still wins.
		if app.ICMPType == nil {
			if t := aliasEchoICMPType(app.Protocol); t != nil {
				app.ICMPType = t
			}
		}

		// #5574: carry any conflicting direct-scalar leaves onto the app for the
		// strict structure gate. It only matters on the pure-direct store path
		// below (`else`); a term-bearing app discards this struct, and a mixed
		// direct+term app is already rejected by MixedDirectTermApps.
		app.DuplicateDirectLeaves = dupDirectLeaves
		app.IncompleteDirectLeaves = incompleteDirectLeaves

		if len(terms) > 0 {
			// #3366: an application that mixes a direct match body with `term`
			// sub-blocks is a Junos config error. The store below keeps ONLY the
			// terms, silently dropping the direct match (a fail-open under-match
			// for a deny application). Record the parent name so the strict
			// structure gate (validateApplicationStructureStrict) rejects it at
			// commit (lenient-warn on the tolerant load / peer-sync path) instead
			// of compiling a half-defined application.
			if hasDirectBody {
				apps.MixedDirectTermApps = append(apps.MixedDirectTermApps, appName)
			}
			implicitSet := &ApplicationSet{Name: appName}
			for _, t := range terms {
				t.Description = app.Description
				// #6524: the parent `app` struct is DISCARDED on this branch,
				// so an unrecognized token sitting directly on a term-bearing
				// application body would take its UnknownDirectLeaves record
				// with it and escape the strict gate. Carry it onto every
				// generated term application — the only survivors — exactly as
				// Description is carried, mirroring how parseApplicationTerms
				// already lands UnknownTermLeaves on each term (#3352).
				t.UnknownDirectLeaves = app.UnknownDirectLeaves
				t.UnknownDirectTokens = app.UnknownDirectTokens
				// #8339: carried for the SAME reason and it is not optional —
				// this branch discards `app`, so a dangling direct leaf on a
				// term-bearing application would escape the strict gate
				// entirely. That is the shape #6524 documents one line above.
				t.IncompleteDirectLeaves = app.IncompleteDirectLeaves
				apps.Applications[t.Name] = t
				implicitSet.Applications = append(implicitSet.Applications, t.Name)
			}
			apps.ApplicationSets[appName] = implicitSet
		} else {
			apps.Applications[appName] = app
		}
	}

	for _, inst := range namedInstances(node.FindChildren("application-set")) {
		as := &ApplicationSet{Name: inst.name}

		for _, member := range inst.node.Children {
			// An application-set member is either an individual application
			// reference (`application <name>`) or a nested application-set
			// reference (`application-set <name>`). Both kinds are stored in
			// as.Applications; ExpandApplicationSet distinguishes them by
			// looking each member name up in apps.ApplicationSets and recursing
			// (max depth 3). Dropping the nested-set arm here silently lost the
			// child set's applications from the parent, so a policy matching the
			// parent set under-matched (#2068). This mirrors compileAddressBook,
			// which handles both `address` and `address-set` members.
			switch member.Name() {
			case "application", "application-set":
				// A bracketed member list (`application [ a b c ]` or
				// `application-set [ S1 S2 ]`) collapses onto ONE leaf whose
				// Keys hold every value (Keys=["application","a","b","c"]) per
				// the #2419 dual-shape pattern — the lexer strips the brackets
				// and the multi:true-style leaf absorbs the trailing tokens.
				// Reading only nodeVal(member) (== Keys[1]) compiled just the
				// first entry and silently dropped the rest, so a policy
				// referencing the set under-matched — a DENY covered only the
				// first application (#5181, the applications-side analogue of
				// the #4791 address-set fix). Accumulate every value across
				// BOTH AST shapes.
				for _, v := range applicationSetMemberValues(member) {
					as.Applications = append(as.Applications, v)
				}
			case "description":
				// Junos allows a `description` statement on an application-set
				// (metadata, not a member reference). Accept it without adding a
				// member and without flagging it below — a `description` is the
				// documented way to author an otherwise-empty set (the #3144/#3434
				// empty-set gate then rejects it only when it is REFERENCED).
			default:
				// #3890: an unrecognized member statement inside the opaque
				// application-set body. The schema declares `application-set` as
				// an args:1 leaf (children:nil), so the SchemaValidate walk never
				// reaches its members; without this default arm a typo'd member
				// keyword (e.g. `applicaton foo` for `application foo`, or a
				// mistyped `application-set`) was SILENTLY DROPPED — the set was
				// under-populated, and if it was referenced by a DENY policy the
				// deny matched FEWER applications than intended (a fail-open
				// under-match). Mirroring UnknownTermLeaves (#3352), record the
				// offending keyword so validateApplicationSyntaxStrict rejects the
				// first one at commit (lenient-warn on the tolerant load / peer-sync
				// path) instead of compiling an under-populated set.
				if kw := member.Name(); kw != "" {
					as.UnknownMembers = append(as.UnknownMembers, kw)
					// #9595: keep the value too; a value that resolves as an
					// application marks a misspelled member reference.
					as.UnknownMemberValues = append(as.UnknownMemberValues, applicationSetMemberValues(member)...)
				}
			}
		}

		apps.ApplicationSets[as.Name] = as
	}

	return nil
}

// parseApplicationTerms parses an inline term like:
// "term-name [alg ftp] protocol tcp [source-port 22] [destination-port 22] [inactivity-timeout 86400]"
// When multiple protocol values are present, returns one Application per
// unique protocol (each sharing the same ports/timeout/alg).
func parseApplicationTerms(parentName string, keys []string) []*Application {
	if len(keys) == 0 {
		return nil
	}
	termName := keys[0]

	var protocols []string
	var dstPort, srcPort, alg string
	var timeout int
	var badTimeouts []string
	var icmpType, icmpCode *uint8
	var badICMP []string
	// #3366: a scalar (single-valued) leaf repeated inside one term with a
	// DIFFERENT value — via apply-groups, flat-set ordering, or hand authoring —
	// was last-writer-wins: the loop below overwrote the earlier value with no
	// validation, silently narrowing (or widening) the term to the final token by
	// parse order. Each scalar leaf carries a companion `<leaf>Set` flag and a
	// `<leaf>Val` holding the MOST RECENTLY assigned value — not the first: every
	// arm refreshes its comparison value after recording, so the check is
	// "differs from its immediate predecessor", i.e. one record per TRANSITION.
	// `8, 3, 8` therefore records TWO conflicts, where comparing every later value
	// against the first would record one. Nothing observable depends on that
	// difference: acceptance is identical (any sequence carrying more than one
	// distinct value contains at least one transition, so the strict gate rejects
	// it, and an idempotent run records nothing either way), and the gate reports
	// only `DuplicateTermLeaves[0]` (compiler_validate_strict_application.go), so
	// the extra records never reach the error text. Treat the slice as a
	// non-empty/empty signal carrying one representative leaf name, NOT as a
	// conflict tally. An idempotent repeat (the same value again, e.g.
	// the `timeout` / `inactivity-timeout` aliases both set to 1800) is harmless
	// and accepted. `protocol` is deliberately EXCLUDED — a repeated `protocol` is
	// the documented multi-protocol-term syntax (one Application per unique
	// protocol), not a duplicate. #6766: the #3366 framework omitted the ICMP
	// leaves — a conflicting `icmp-type` / `icmp-code` repeat overwrote the
	// pointer with no record, so a referenced deny enforced only the LAST
	// type/code; they are now tracked like the ports (malformed tokens keep the
	// badICMP / UnknownICMP path — duplicate tracking applies only to values
	// that parse).
	dstPortSet, srcPortSet, algSet, timeoutSet := false, false, false, false
	icmpTypeSet, icmpCodeSet := false, false
	var icmpTypeVal, icmpCodeVal uint8
	var dupTermLeaves []string
	// #3352: tokens inside the inline term that are not a recognized leaf.
	// The term subtree is opaque to SchemaValidate (children:nil), so without
	// a default arm an unknown leaf (and its value) were silently dropped,
	// widening the term. Record them for the deferred strict gate.
	var badTermLeaves []string
	// #6564 member 9: RECOGNIZED value-taking leaves that appeared with NO
	// value (last token in the term). Distinct from badTermLeaves, which holds
	// UNRECOGNIZED tokens — the keyword here IS supported, it just has nothing
	// to constrain with, so the strict gate words the two differently.
	var incompleteTermLeaves []string
	// #3348: per normalized-protocol echo-type implied by a junos-ping /
	// junos-pingv6 alias inside an inline term. normalizeProtocol folds the
	// alias to "icmp"/"icmpv6" and loses the ping distinction, so capture the
	// echo type keyed by the normalized protocol before that information is
	// gone.
	echoByProto := map[string]*uint8{}
	// #3348: a normalized protocol for which the SAME term also lists an
	// unconstrained ICMP alias (icmp / icmpv6 / junos-icmp-all / junos-icmp6-all)
	// that dedups onto it. Two app terms — one ping, one all-icmp — union to
	// all-ICMP in the Rust matcher (policy.rs: separate terms OR together), but
	// because both normalize to "icmp" here they collapse to ONE term. Applying
	// the junos-ping echo type to that collapsed term would spuriously NARROW the
	// union to echo-only (a widening INVERSION). Record the poisoning alias so the
	// echo default is suppressed for that protocol.
	unconstrainedICMP := map[string]bool{}

	for i := 1; i < len(keys); i++ {
		// #6564 member 9: a RECOGNIZED value-taking leaf in the LAST position
		// has no value to consume. Every arm below is guarded by
		// `if i+1 < len(keys)` with no else, so such a keyword fell through
		// recording NOTHING — and the `default:` arm that feeds badTermLeaves
		// is unreachable for a keyword the switch recognizes.
		//
		// That is the same fail-open the rest of this function exists to stop:
		// the constraint is dropped and the term WIDENS. `term t1 protocol tcp
		// destination-port` compiled to protocol-only, so an application
		// written to match ONE port matched EVERY TCP port, and any policy
		// permitting it widened with it. #3320 / #3348 / #3352 / #6524 each
		// instrument a MALFORMED value; this shape has no value to be
		// malformed, which is why none of them caught it.
		//
		// Checked ONCE here rather than as eight `else` branches: a per-arm
		// else would have to be repeated for every future value-taking leaf and
		// is exactly the kind of duplication that drifts.
		if i+1 >= len(keys) && valueTakingApplicationLeaves[keys[i]] {
			incompleteTermLeaves = append(incompleteTermLeaves, keys[i])
			continue
		}
		switch keys[i] {
		case "protocol":
			if i+1 < len(keys) {
				i++
				norm := normalizeProtocol(keys[i])
				protocols = append(protocols, norm)
				if t := aliasEchoICMPType(keys[i]); t != nil {
					echoByProto[norm] = t
				} else if norm == "icmp" || norm == "icmpv6" {
					// An unconstrained ICMP alias (icmp / junos-icmp-all / ...)
					// for this normalized protocol — widens to all types, so the
					// junos-ping echo narrowing must NOT apply when both land on
					// the same collapsed term.
					unconstrainedICMP[norm] = true
				}
			}
		case "icmp-type":
			if i+1 < len(keys) {
				i++
				if t, ok := parseICMPTypeCode(keys[i]); ok {
					// #6766: value-aware duplicate tracking, mirroring the
					// ports above — a conflicting repeat is recorded for the
					// strict structure gate; an idempotent same-value repeat
					// is accepted.
					if icmpTypeSet && *t != icmpTypeVal {
						dupTermLeaves = append(dupTermLeaves, "icmp-type")
					}
					icmpTypeSet, icmpTypeVal = true, *t
					icmpType = t
				} else {
					// #3348: a malformed inline-term icmp-type. The schema does
					// NOT validate inside an opaque `term`, so silently dropping
					// it would leave the term UNCONSTRAINED (matches all ICMP) —
					// a fail-open widening. Record it for the strict gate.
					badICMP = append(badICMP, keys[i])
				}
			}
		case "icmp-code":
			if i+1 < len(keys) {
				i++
				if c, ok := parseICMPTypeCode(keys[i]); ok {
					if icmpCodeSet && *c != icmpCodeVal {
						dupTermLeaves = append(dupTermLeaves, "icmp-code")
					}
					icmpCodeSet, icmpCodeVal = true, *c
					icmpCode = c
				} else {
					badICMP = append(badICMP, keys[i])
				}
			}
		case "destination-port":
			if i+1 < len(keys) {
				i++
				v := resolveAppPort(keys[i])
				if dstPortSet && v != dstPort {
					dupTermLeaves = append(dupTermLeaves, "destination-port")
				}
				dstPortSet = true
				dstPort = v
			}
		case "source-port":
			if i+1 < len(keys) {
				i++
				v := resolveAppPort(keys[i])
				if srcPortSet && v != srcPort {
					dupTermLeaves = append(dupTermLeaves, "source-port")
				}
				srcPortSet = true
				srcPort = v
			}
		case "inactivity-timeout", "timeout":
			if i+1 < len(keys) {
				i++
				kw := keys[i-1]
				if v, ok := parseAppTimeout(keys[i]); ok {
					if timeoutSet && v != timeout {
						dupTermLeaves = append(dupTermLeaves, kw)
					}
					timeoutSet = true
					timeout = v
				} else {
					// #3320: malformed inline-term timeout — record the raw
					// token so the deferred strict gate rejects it instead of
					// silently dropping it.
					badTimeouts = append(badTimeouts, keys[i])
				}
			}
		case "alg":
			if i+1 < len(keys) {
				i++
				if algSet && keys[i] != alg {
					dupTermLeaves = append(dupTermLeaves, "alg")
				}
				algSet = true
				alg = keys[i]
			}
		default:
			// #3352: an unrecognized token inside the inline term. This catches
			// both a typo'd leaf keyword (e.g. `destination-poort`) and the value
			// that follows it (which, being a non-keyword, also lands here) —
			// either way the term subtree carried something the parser cannot
			// honor, so record it and let validateApplicationSpecsStrict reject
			// the first one rather than silently dropping the constraint and
			// widening the match.
			badTermLeaves = append(badTermLeaves, keys[i])
		}
	}

	// Deduplicate protocols (e.g. "junos-icmp-all" and "icmp" both normalize to "icmp")
	if len(protocols) == 0 {
		protocols = []string{""}
	}
	seen := make(map[string]bool)
	var unique []string
	for _, p := range protocols {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	var result []*Application
	for _, proto := range unique {
		name := parentName + "-" + termName
		if len(unique) > 1 {
			suffix := proto
			if suffix == "" {
				suffix = "any"
			}
			name = parentName + "-" + termName + "-" + suffix
		}
		// An explicit inline-term `icmp-type` wins; otherwise fall back to the
		// echo type implied by a junos-ping / junos-pingv6 protocol alias on
		// this protocol (#3348) — UNLESS the same term also lists an
		// unconstrained ICMP alias that dedups onto this protocol, in which case
		// the union is all-ICMP and the echo narrowing must be suppressed.
		it := icmpType
		if it == nil && !unconstrainedICMP[proto] {
			it = echoByProto[proto]
		}
		result = append(result, &Application{
			Name:                 name,
			Protocol:             proto,
			DestinationPort:      dstPort,
			SourcePort:           srcPort,
			InactivityTimeout:    timeout,
			ALG:                  alg,
			UnknownTimeouts:      badTimeouts,
			ICMPType:             it,
			ICMPCode:             icmpCode,
			UnknownICMP:          badICMP,
			UnknownTermLeaves:    badTermLeaves,
			IncompleteTermLeaves: incompleteTermLeaves,
			DuplicateTermLeaves:  dupTermLeaves,
		})
	}
	return result
}

// valueTakingApplicationLeaves is the set of application leaves that REQUIRE a
// value (#6564 member 9, extended to the direct body by #8339). It is the
// arity contract for BOTH switches that compile an application body, and it is
// deliberately ONE set rather than two:
//
//   - parseApplicationTerms consumes `keys[i+1]` from a flat key run, so a
//     dangling leaf is `i+1 >= len(keys)`;
//   - the direct body reads the leaf node's own value via nodeVal(prop), so a
//     dangling leaf is `nodeVal(prop) == ""`.
//
// The DETECTION differs because the two grammars park the value in different
// places. The CONTRACT -- which keywords require one at all -- is a property of
// the Junos statement, not of the shape it was typed in, and #8339 is what
// happens when only one of the two enforces it: the term path refused a
// dangling `destination-port` while the direct body accepted it and matched
// EVERY port. Two sets would drift apart exactly the way the two guards did.
//
// Membership is derived from the switches, not asserted: every arm in either
// that consumes a value must appear here, pinned by
// TestValueTakingTermLeavesCoversEveryConsumingArm6564 and
// TestValueTakingLeavesCoverEveryDirectConsumingArm8339.
//
// NOT members, deliberately:
//   - `description`: takes a value, but a dangling one drops a cosmetic field
//     and widens nothing. Excluded to keep the commit-refusal surface to
//     statements whose absence changes what traffic matches.
//   - `term`: a container, not a leaf; its name is consumed by descending into
//     the body rather than by a value read.
var valueTakingApplicationLeaves = map[string]bool{
	"protocol":           true,
	"destination-port":   true,
	"source-port":        true,
	"icmp-type":          true,
	"icmp-code":          true,
	"inactivity-timeout": true,
	"timeout":            true,
	"alg":                true,
}

// aliasEchoICMPType returns the echo-request ICMP / ICMPv6 type implied by a
// "ping" protocol alias — junos-ping -> 8 (ICMP echo-request), junos-pingv6 ->
// 128 (ICMPv6 echo-request) — or nil for any other token.
//
// #3348: a user-defined application that set `protocol junos-ping` was lowered
// to bare ICMP with no type constraint, so the projected policy term matched
// EVERY ICMP type (unreachable / redirect / timestamp / ...) — silently
// widening any policy that referenced it, and broader than the predefined
// junos-ping object which carries ICMPType=8 (#3020). Attaching the echo type
// makes a custom `protocol junos-ping` app behave like the predefined one. The
// all-ICMP aliases (junos-icmp-all / junos-icmp6-all) intentionally return nil
// so they stay unconstrained (match every type).
func aliasEchoICMPType(proto string) *uint8 {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "junos-ping":
		return u8p(8)
	case "junos-pingv6":
		return u8p(128)
	default:
		return nil
	}
}

// parseICMPTypeCode parses an application `icmp-type` / `icmp-code` token. It
// returns the value and true when the token is a base-10 integer in [0,255]
// (the ICMP/ICMPv6 type and code wire range); otherwise (nil, false). The
// strict commit path validates the range earlier via the schema
// (schema_security.go ValidateInteger(0,255)), so this is the compile-time
// projection of an already-accepted token; an unparsable value is dropped
// rather than widening the term.
func parseICMPTypeCode(raw string) (*uint8, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 || n > 255 {
		return nil, false
	}
	v := uint8(n)
	return &v, true
}

// normalizeProtocol maps Junos protocol aliases to canonical names
// so that "junos-icmp-all" and "icmp" deduplicate correctly.
func normalizeProtocol(name string) string {
	switch strings.ToLower(name) {
	case "junos-icmp-all", "junos-ping":
		return "icmp"
	case "junos-icmp6-all", "junos-pingv6", "icmp6":
		return "icmpv6"
	case "junos-gre":
		return "gre"
	case "junos-ospf":
		return "89"
	case "junos-tcp-any":
		return "tcp"
	case "junos-udp-any":
		return "udp"
	case "junos-ip-in-ip", "junos-ipip":
		return "4"
	default:
		return name
	}
}

// resolveAppPort rewrites a custom-application port spec (destination-port /
// source-port) so any Junos service name is replaced by its numeric value,
// leaving the dataplane to ever parse only numerics. This is the application
// counterpart of resolveFilterPortTokens (filter_match_resolve.go): both back
// named-port resolution with the SAME junosServicePorts catalog (the single
// source of truth for Junos service-name → port number), so a name the firewall
// filter path accepts (`domain`, `www`, `kerberos-sec`, ...) is accepted here
// too — closing the #3340 gap where a custom application's destination-port only
// knew a hard-coded 15-name subset (`dns` yes, its alias `domain` no).
//
// Why resolve to a number rather than widen the accepted name set: the Rust
// dataplane's parse_port_spec (userspace-dp/src/policy.rs) and its Go mirror
// userspacePortSpecRepresentable (pkg/dataplane/userspace/capabilities.go, the
// #2124 capability gate) recognize ONLY the 15 literal names. Passing a broader
// name straight through would parse at commit but be unrepresentable at apply —
// the #2124 gate would set ForwardingSupported=false for the whole dataplane (a
// commit/apply split). Resolving to a number here means BOTH the strict commit
// gate and the runtime capability gate see the numeric form and agree.
//
// resolveFilterPort (filter_match_resolve.go) now uses the SAME whole-spec
// catalog lookup first (#3397), so a hyphenated service name (ftp-data,
// tacacs-ds, kerberos-sec) resolves on BOTH the application and the firewall
// filter path. The two helpers are kept separate only because their miss
// contract differs: resolveAppPort returns the spec VERBATIM on an
// unresolvable miss (so validatePortSpec rejects it strictly / the lenient
// path warns), whereas resolveFilterPort returns ok=false so its caller keeps
// the raw token and records it on term.UnknownPorts for the filter commit
// gate.
//
// On success the canonical numeric string is returned. An UNRESOLVABLE spec
// (unknown name, out-of-range / malformed number, inverted or unresolved range)
// is returned verbatim so the caller leaves it for validatePortSpec to reject at
// the strict commit gate (and to downgrade to a warning on the lenient path) —
// the strict-reject + lenient-warn discipline (#1960/#3261). The catalog lookup
// is case-insensitive (strings.ToLower), so a mixed-case service name resolves
// rather than passing through unresolved.
func resolveAppPort(spec string) string {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return spec
	}
	// Whole-spec service name first — covers hyphenated names (ftp-data,
	// kerberos-sec) that a range-split would otherwise mangle.
	if p, ok := junosServicePorts[strings.ToLower(trimmed)]; ok {
		return strconv.Itoa(int(p))
	}
	// A bare numeric port is already in the form the dataplane wants; leave it
	// byte-identical (validatePortSpec still range-checks it).
	if _, err := strconv.Atoi(trimmed); err == nil {
		return spec
	}
	// A low-high range whose endpoints are numbers or (non-hyphenated) service
	// names: resolve each side through the catalog and emit a numeric range.
	if lo, hi, found := strings.Cut(trimmed, "-"); found {
		l, ok1 := resolveSinglePort(lo)
		h, ok2 := resolveSinglePort(hi)
		// #4336: Junos accepts 0 as the FLOOR of a port range. Real vSRX
		// multi-term application defs routinely split a port space as
		// `0-N` / `N+1-65535` (e.g. FaceTime `source-port 0-41640`).
		// resolveSinglePort rejects the literal "0" (it clamps to [1,65535]),
		// which left the raw `0-N` spec to be hard-rejected by validatePortSpec
		// ("invalid port 0: must be 1-65535") — a pure drop-in blocker. Port 0
		// never appears on the wire, so `0-N` matches identically to `1-N`;
		// normalize the floor to 1 here, at the SINGLE canonicalization
		// chokepoint for both direct-match and inline-term ports, so the
		// resulting spec passes validatePortSpec AND is representable by the
		// userspace dataplane (the Rust parse_port_spec and the Go #2124
		// userspacePortSpecRepresentable gate both reject a 0 floor). A bare
		// single port 0 (no hyphen) stays invalid, matching Junos.
		if !ok1 {
			if n, err := parseCanonicalPort(strings.TrimSpace(lo)); err == nil && n == 0 {
				l, ok1 = 1, true
			}
		}
		if ok1 && ok2 && l <= h {
			return fmt.Sprintf("%d-%d", l, h)
		}
	}
	// Unresolvable — return verbatim so the strict gate rejects / lenient warns.
	return spec
}

// ParseCanonicalUint parses a canonical unsigned decimal integer token. Unlike
// strconv.Atoi — which accepts a leading '+' ("+80" -> 80) and a leading '-'
// ("-80" -> -80) — it requires a non-empty bare run of ASCII decimal digits,
// with no sign and no surrounding whitespace.
//
// It is the shared canonical-form primitive behind BOTH the #3606 commit-time
// port parsers (parseCanonicalPort below) AND the #3679 diagnostic port / ICMP
// parsers (policymatch.ParsePort / ParseICMPValue and the REST match-policies
// queryIntStrict helper). Routing every numeric-token parser through this one
// function keeps the config grammar, the dataplane canonical parser, and the
// operator simulators from drifting on the sign / whitespace of a numeric token
// — the residual the diagnostic surfaces carried after #3606 fixed only the
// commit path.
//
// Callers still apply their own value-range check on the returned int; this
// helper only enforces canonical FORM. A parsed value that overflows int
// returns strconv's range error, exactly as Atoi would.
func ParseCanonicalUint(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty numeric token")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf(
				"non-canonical numeric token %q: only unsigned decimal digits are "+
					"allowed (no leading sign or whitespace)", s)
		}
	}
	return strconv.Atoi(s)
}

// parseCanonicalPort parses a canonical unsigned decimal port token. It is the
// port-specific spelling of ParseCanonicalUint retained for the #3606
// commit-time callers.
//
// Junos rejects a signed / non-canonical port, and the userspace dataplane's
// port parsers do NOT agree on the sign, so accepting one at commit is a
// commit-vs-dataplane divergence (#3606): the Go capability gate
// userspacePortSpecRepresentable parses with strconv.ParseUint (which rejects
// "+80"), so an application whose port slips through the old Atoi commit check
// is then silently downgraded to unsupported at apply; and the Rust
// parse_port_spec's u16 FromStr ACCEPTS "+80" as 80. The historical Atoi commit
// gate accepted "+80", the capability gate rejected it, and the simulator
// (portMatches) said it matched — a three-way split on a security leaf.
func parseCanonicalPort(s string) (int, error) {
	return ParseCanonicalUint(s)
}

// validatePortSpec checks that a port specification is valid.
// Valid formats: "80", "8080-8090", named ports like "http".
//
// Application named ports are resolved to numerics by resolveAppPort at compile
// time (compileApplications / parseApplicationTerms), so by the time this gate
// runs a recognized service name is already a number. The 15 literal names below
// are the set the Rust dataplane (parse_port_spec) accepts directly, kept as a
// belt-and-suspenders backstop so those names still validate even if a future
// caller reaches this gate without resolving first. The name SET matches
// userspacePortSpecRepresentable (the #2124 capability gate) and Rust
// parse_port_spec, but the case handling does NOT: this gate is
// case-INSENSITIVE (strings.ToLower), whereas userspacePortSpecRepresentable /
// parse_port_spec match case-SENSITIVELY. That divergence is not a fail-open in
// practice because resolveAppPort lowercases and resolves named ports to
// numerics before this gate ever runs, so a mixed-case name ("HTTP") never
// reaches the runtime capability gate as a raw name.
func validatePortSpec(spec string) error {
	if spec == "" {
		return nil
	}
	namedPorts := map[string]bool{
		"http": true, "https": true, "ssh": true, "telnet": true,
		"ftp": true, "ftp-data": true, "smtp": true, "dns": true,
		"pop3": true, "imap": true, "snmp": true, "ntp": true,
		"bgp": true, "ldap": true, "syslog": true,
	}
	if namedPorts[strings.ToLower(spec)] {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := parseCanonicalPort(parts[0])
		hi, err2 := parseCanonicalPort(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid port range %q: non-numeric", spec)
		}
		if lo < 1 || lo > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", lo)
		}
		if hi < 1 || hi > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", hi)
		}
		if lo > hi {
			return fmt.Errorf("invalid port range %q: start > end", spec)
		}
		return nil
	}
	port, err := parseCanonicalPort(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	return nil
}

// supportedApplicationALGs is the single source of truth for the per-application
// `alg` names xpf recognizes. It MIRRORS the global `security alg <proto>`
// control surface (schema_security.go `alg` children + algDisableFlags in
// pkg/dataplane/userspace/flow.go), which exposes exactly DNS / FTP / SIP / TFTP.
// A name outside this set is a silent operator error today: before #3353 the
// per-application `alg` leaf was a raw `args:1` string with no validator, so a
// typo (`alg ftpp`) committed cleanly and the operator believed an ALG was
// pinned when none existed.
//
// #3353 ships VALIDATION only. The per-application ALG is recorded on
// Application.ALG but is NOT carried into the userspace dataplane snapshot — the
// only ALG signal on the wire is the global alg_disable_flags bitfield
// (userspace-dp snapshot.rs), there is no per-application ALG / custom-port pin.
// Wiring per-application ALG (e.g. `alg ftp destination-port 2121`) through to
// enforcement is a genuine dataplane fork (it needs a new snapshot field plus
// Rust session-metadata handling) and is the per-application slice of the
// broader ALG parity tracked under #2008; it is deliberately deferred. Until
// then this gate makes an unsupported name an operator-visible commit error
// instead of a silent no-op.
var supportedApplicationALGs = map[string]bool{
	"dns":  true,
	"ftp":  true,
	"sip":  true,
	"tftp": true,
}

// validApplicationALG reports whether name is a supported per-application ALG.
// The match is case-insensitive (like validatePortSpec / validateProtocol). An
// empty name means "no alg" and is treated as valid by the caller before this
// is reached.
func validApplicationALG(name string) bool {
	return supportedApplicationALGs[strings.ToLower(strings.TrimSpace(name))]
}

// validateProtocol checks that a protocol specification is valid.
func validateProtocol(proto string) error {
	validProtos := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "icmp6": true, "icmpv6": true,
		"ospf": true, "gre": true, "ipip": true, "ah": true, "esp": true,
		"igmp": true, "pim": true, "sctp": true, "vrrp": true, "egp": true,
	}
	if validProtos[strings.ToLower(proto)] {
		return nil
	}
	// Accept junos-* protocol aliases
	if strings.HasPrefix(strings.ToLower(proto), "junos-") {
		return nil
	}
	n, err := strconv.Atoi(proto)
	if err != nil {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	if n < 0 || n > 255 {
		return fmt.Errorf("invalid protocol number %d: must be 0-255", n)
	}
	return nil
}

func nodeVal(n *Node) string {
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}

// applicationSetMemberValues extracts every value carried by an
// application-set `application` / `application-set` member node, across BOTH
// parser AST shapes (#2419, #5181 — the applications-side instance of the same
// dual-shape class as addressSetMemberValues in compiler_security_addressbook.go
// and firewallMatchValues in compiler_firewall.go):
//
//   - single member          `application a;`         → Keys=["application","a"]
//   - bracket list            `application [ a b c ];` → Keys=["application","a","b","c"]
//     (the lexer strips `[`/`]` and the leaf absorbs every trailing token onto
//     Keys, so a bracketed list collapses onto ONE node)
//   - flat set, one line each `set ... application a` +
//     `set ... application b`                          → one child per value
//
// Reading only member.Keys[1] (nodeVal, the pre-#5181 bug) compiles just the
// first bracket-list entry and silently drops the rest — a security-relevant
// under-match when a DENY policy references the truncated set. Reading BOTH
// Keys[1:] AND each child's Keys[0] covers every shape the parser can produce.
func applicationSetMemberValues(member *Node) []string {
	var vals []string
	for _, k := range member.Keys[1:] {
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range member.Children {
		if len(vn.Keys) >= 1 && vn.Keys[0] != "" {
			vals = append(vals, vn.Keys[0])
		}
	}
	return vals
}
