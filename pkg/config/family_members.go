package config

import (
	"fmt"
	"sort"
	"strings"
)

// familyMember is one address-family member under a compound/split
// `family` node: the node carrying the member's subtree plus the tokens
// that identify it. Built by familyMembers, the single shape-aware
// extractor shared by the firewall compiler/gates (#9883), the interface
// compiler, and the forwarding-options compilers (family inet6 mode and
// sampling instances) (#17196).
type familyMember struct {
	// AfNode carries the member's subtree (for firewall, its `filter`
	// subtree).
	AfNode *Node
	// Af is the effective family token: famNode.Keys[1] for the packed
	// shape (`family inet { ... }`), the child NAME (Keys[0]) for the
	// set-command shape (`family { inet { ... } }`).
	Af string
	// Residue carries trailing keys on STRUCTURED member nodes only
	// (len(Children) > 0): extra tokens that must ALSO be declared, e.g.
	// the `inet` in a malformed `family { inett inet { filter F } }`
	// child. A collapsed flat-set leaf (`["inett","filter","BAD",...]`,
	// no children) carries no residue — its tail is the flattened
	// remainder of the set command, not family tokens, and flagging it
	// would spam one warning per path fragment.
	Residue []string
}

// familyMembers walks a `family` node across BOTH AST shapes and returns
// one member per address family. It is the ONLY family extractor:
// compileFirewall, validateFirewallFilterFamilyCollisionsAST (#3884),
// validateFirewallFilterFamilyAnyMatchesAST (#4296),
// validateFirewallFilterFamilyTokensAST (#9017), compileInterfaces,
// compileForwardingOptionsWithOpts (family inet6 mode) and
// compileSampling all consume it, so the token each compiler installs
// under is always a token the gates judged (#17196).
//
// The sharing is load-bearing, not cosmetic. Before #9883, the firewall
// compiler preferred the SECOND key of a set-shape child
// (`af = afNode.Keys[1]`) while the token gate read the name (Keys[0])
// only: `family { inett inet { filter F } }` (a peer-synced / hand-built
// AST) installed F into FiltersInet while the gate warned it compiles to
// NOTHING (quarantine bypass + message lie), and the converse
// `family { inet inett { ... } }` escaped every gate and committed a
// strict silent void. The three hand copies outside firewall
// (interfaces, forwarding-options mode, sampling) kept the Keys[1]
// preference after #9883 removed it from firewall, so a leading junk
// token was silently ignored there and the trailing family installed
// (#17196); hierarchical text `family { bogus inet { … } }` parses to
// Keys=["bogus","inet"] with children, so the smuggle needs no
// hand-built AST. No valid producer emits a multi-key family child (the
// parser and SetPath always mint single-key children — a flat-set
// unknown collapses to a LEAF, never a structured multi-key node), so
// the residue arm only ever fires on malformed / peer-synced trees, or
// on authored hierarchical text with a leading junk token.
//
// #4827: Name() safely returns "" for an empty Keys slice, so a corrupted
// persisted node (configstore JSON has no Node validator) yields Af ""
// — which quarantines / gets flagged — instead of panicking (#1960
// doctrine). Before #17196 the sampling copy indexed Keys[0] with no
// guard and panicked on exactly that node.
func familyMembers(famNode *Node) []familyMember {
	if famNode == nil {
		return nil
	}
	if len(famNode.Keys) >= 2 {
		// Packed shape: `family inet { ... }` — one node, family on Keys[1].
		m := familyMember{AfNode: famNode, Af: famNode.Keys[1]}
		if len(famNode.Keys) > 2 && len(famNode.Children) > 0 {
			m.Residue = famNode.Keys[2:]
		}
		return []familyMember{m}
	}
	// Set-command shape: `family { inet { ... } ... }` — the family name
	// rides on each CHILD. The effective token is the child NAME
	// (Keys[0]), never Keys[1]: preferring the second key let a malformed
	// leading token smuggle a declared trailing token past the gate into
	// the install path (above).
	var out []familyMember
	for _, ch := range famNode.Children {
		if ch == nil {
			continue
		}
		m := familyMember{AfNode: ch, Af: ch.Name()}
		if len(ch.Keys) > 1 && len(ch.Children) > 0 {
			m.Residue = ch.Keys[1:]
		}
		out = append(out, m)
	}
	return out
}

// unknownFamilyMember17196 reports whether a family member is unknown
// for a caller whose declared families are known: its effective token is
// not in known, or a structured member carries a trailing token that is
// not in known. It is the per-caller analogue of
// firewallFamilyQuarantined9883 (which is firewall-schema-driven): the
// extractor is shared, but each stanza declares its own family set, so
// each caller supplies its own. An empty Af (empty-Keys child, #4827) is
// not in any known set and is therefore unknown.
func unknownFamilyMember17196(m familyMember, known map[string]bool) bool {
	if !known[m.Af] {
		return true
	}
	for _, t := range m.Residue {
		if !known[t] {
			return true
		}
	}
	return false
}

// unknownFamilyMsg17196 formats the #9017-style unknown-family diagnostic
// for a non-firewall top. ctx names the stanza (e.g.
// "forwarding-options family", "interfaces ge-0/0/0 unit 0 family",
// "forwarding-options sampling instance \"i1\" family"); known is sorted
// for the message. The token named is the first unknown token (the
// effective token if undeclared, else the first undeclared residue
// token), matching validateFirewallFilterFamilyTokensAST.
func unknownFamilyMsg17196(ctx string, m familyMember, known map[string]bool, knownSorted []string) string {
	tok := m.Af
	if known[tok] {
		for _, t := range m.Residue {
			if !known[t] {
				tok = t
				break
			}
		}
	}
	return fmt.Sprintf("%s %q is not a known address family "+
		"(known: %s) — the configuration under it compiles to NOTHING: it commits "+
		"clean, renders in `show configuration`, and takes no effect at all "+
		"(#17196)", ctx, tok, strings.Join(knownSorted, ", "))
}

// sortedFamilyKeys17196 returns the keys of a known-family set, sorted,
// for diagnostics.
func sortedFamilyKeys17196(known map[string]bool) []string {
	out := make([]string, 0, len(known))
	for k := range known {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
