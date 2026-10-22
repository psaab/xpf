package config

import (
	"fmt"
	"sort"
	"strings"
)

// #9416: the NAMED spelling of the SNMP source-IP restriction, and the census
// that found the sixth spelling behind the fifth.
//
// THE DEFECT. Junos expresses one control two ways:
//
//	snmp { community c { clients 10.0.0.0/8; } }                       inline
//	snmp { client-list L { 10.0.0.0/8; }
//	       community c { client-list-name L; } }                       named
//
// Only the inline one was modelled. `client-list` and `client-list-name`
// appeared NOWHERE in pkg/config or pkg/snmp, and the SNMP compiler descends
// only into keywords it recognises, so the named form committed clean on all
// four channels (SchemaValidate, CompileConfig, CompileConfigLenient,
// configstore.CheckText) with zero warnings, compiled to an EMPTY allowlist,
// and `AllowsSource` documents an empty allowlist as ALLOW-ALL. The operator
// authored an access restriction and got an agent that answers every source,
// with nothing anywhere saying so.
//
// WHY IT SURVIVED FIVE FIXES. The inline sibling has had this exact fail-open
// repaired five times -- #4289 (the restriction was ignored outright), #5472
// (a duplicate community block overwrote the map and emptied the allowlist),
// #5833 (a `restrict` typo left allow-all instead of quarantining), #5898 (an
// orphan `restrict` was dropped, degrading deny-except to allow), #8778 (the
// one-line `set` spelling dropped the allowlist entirely) -- and every one of
// them assumed the restriction is spelled INLINE. A defect family whose members
// keep arriving is a signal about the SEARCH, not about the members.
//
// SO THE FAMILY WAS CENSUSED BEFORE THE FIFTH WAS FIXED, and there is a sixth:
//
//	community c { routing-instance ri { clients 10.0.0.0/8; } }        per-RI
//	community c { routing-instance ri { client-list-name L; } }        per-RI, named
//
// Measured on `configstore.CheckText` at the parent of this change: ACCEPT,
// zero warnings, `Clients=[]`, and `AllowsSource(203.0.113.9) == true` -- the
// same fail-open, one level deeper. It is handled here rather than left for a
// seventh pass: the source restriction inside a `routing-instance` block is
// APPLIED to the community (leaving it out means allow-all, which is strictly
// worse than applying it on the wrong instance), while the SCOPING itself --
// which xpf's single-socket, instance-unaware agent cannot honour -- is named
// in a commit advisory instead of being silently ignored.
//
// The remaining SNMP source-restriction axes are DIFFERENT controls, not more
// spellings of this one, and they are named by snmpInertKnobWarnings rather
// than implemented here: `snmp interface` / `filter-interfaces` (restrict by
// arrival interface), `snmp routing-instance-access` (restrict by instance),
// and `community <c> logical-system` (xpf has no logical systems at all).

// parseSNMPClientListPrefixes extracts a `client-list <name> { ... }` body,
// across both parser AST shapes (the #2419 dual-shape class).
//
// The node's own Keys carry `["client-list", "<name>", <prefix>...]` in the
// flat/bracketed spelling and `["client-list", "<name>"]` in the braced one,
// where the prefixes are Children. Keys[2:] is therefore the prefix run and
// Keys[1] is the list NAME -- reading from Keys[1] would silently make the list
// name its own first prefix, which parseClientPrefix would reject as malformed
// and which would quarantine every referencing community.
//
// The `<prefix> [restrict]` pairing is delegated to parseSNMPClients, NOT
// reimplemented, so the #5898 orphan-`restrict` fail-closed behaviour and the
// #5833 malformed-token quarantine reach the named list identically to the
// inline one. A named list is where a `restrict` typo is MORE dangerous, not
// less: one list backs every community that references it.
func parseSNMPClientListPrefixes(node *Node) []SNMPClient {
	if node == nil || len(node.Keys) < 2 {
		return nil
	}
	// parseSNMPClients reads Keys[1:] and every child's Keys, so hand it a node
	// whose Keys[0] is a placeholder and whose Keys[1:] is the prefix run.
	run := append([]string{"clients"}, node.Keys[2:]...)
	synth := &Node{Keys: run, Children: node.Children}
	return parseSNMPClients(synth)
}

// snmpClientListName reads the list name a `client-list` node declares, or ""
// when the node names none.
func snmpClientListName(node *Node) string {
	if node == nil || len(node.Keys) < 2 {
		return ""
	}
	return node.Keys[1]
}

// snmpCommunityListRefs collects the `client-list-name` references a community
// authored, in document order, de-duplicated.
//
// Both spellings reach it: `client-list-name L` as its own statement (the node
// carries Keys ["client-list-name", "L"]) and packed onto a flat run, which the
// caller has already split into statements.
func snmpCommunityListRefs(nodes []*Node) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range nodes {
		if n == nil || n.Name() != "client-list-name" {
			continue
		}
		// EXACTLY ONE VALUE, read through `nodeVal`.
		//
		// `client-list-name` is declared `args: 1`, so Keys[1] is its value and
		// anything after it belongs to a following statement. Reading Keys[1:]
		// instead would turn the next statement's keyword into a list NAME on a
		// packed run — which resolves to nothing and quarantines a community
		// the operator configured correctly. That is fail-closed rather than
		// fail-open, but it rejects a valid config, so the bound is real work
		// and not belt-and-braces: expandFlatRun splits such a run before this
		// reader sees it, and this backstops the case where it cannot.
		//
		// `nodeVal` rather than a bare Keys[1] because it is this compiler's
		// SSOT for a single-valued leaf across BOTH AST slots: Keys[1] when the
		// value sits on the node, the first child's name when a spelling put it
		// in a block. Using it makes every spelling of this leaf agree on ONE
		// value — the alternative, reading Keys[1] AND every child, made the
		// bracketed spelling discard a trailing token while the block spelling
		// adopted it as a SECOND list reference, so the same leaf was a scalar
		// in one spelling and a list in another.
		if name := nodeVal(n); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// resolveSNMPClientListRefs turns a community's `client-list-name` references
// into the allowlist entries AllowsSource enforces, and reports whether any
// reference could NOT be honoured.
//
// UNRESOLVABLE AND EMPTY ARE THE SAME ANSWER, and that is the whole point.
// `AllowsSource` reads `len(Clients) == 0` as allow-all, so a reference to a
// list that does not exist -- or to one that exists and is empty -- would
// otherwise produce EXACTLY the state this issue is about: an authored
// restriction that serves every source. Both are reported as unresolved so the
// caller hard-rejects (strict) or quarantines the community to deny-all
// (lenient). Neither may degrade to allow-all.
//
// The list NAME is echoed in the error; the COMMUNITY name never is (it is the
// secret, per the snmpInertKnobWarnings convention).
func resolveSNMPClientListRefs(refs []string, lists map[string][]SNMPClient) (clients []SNMPClient, unresolved []string) {
	for _, name := range refs {
		entries, ok := lists[name]
		if !ok || len(entries) == 0 {
			unresolved = append(unresolved, name)
			continue
		}
		clients = append(clients, entries...)
	}
	return clients, unresolved
}

// snmpUnresolvedClientListError is the strict commit-path rejection for a
// community whose `client-list-name` names no defined, non-empty list.
func snmpUnresolvedClientListError(names []string) error {
	return fmt.Errorf("%s", snmpUnresolvedClientListMessage(names, false))
}

// snmpUnresolvedClientListMessage renders the operator-facing text for an
// unresolvable reference. `lenient` appends the quarantine note, so the two
// paths cannot describe the same condition differently.
func snmpUnresolvedClientListMessage(names []string, lenient bool) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	msg := fmt.Sprintf(
		"snmp community client-list-name %s names no `snmp client-list` with any prefixes "+
			"(an undefined or empty client list would leave the community answerable from "+
			"EVERY source, because an empty allowlist is allow-all)",
		strings.Join(quoteAll(sorted), ", "))
	if lenient {
		msg += " (the affected community is quarantined to deny-all until the reference is fixed)"
	}
	return msg
}

// sortedClientListNames9416 gives the client-list validation loop a
// DETERMINISTIC order. Go map iteration is randomised, so validating in map
// order would make WHICH malformed list is reported first vary between runs of
// the same config on the strict path -- and the strict path returns on the
// first error, so the operator would get a different message each commit.
func sortedClientListNames9416(lists map[string][]SNMPClient) []string {
	out := make([]string, 0, len(lists))
	for name := range lists {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func containsString9416(in []string, want string) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

// snmpCommunitySchema9416 resolves the `snmp community <name>` container so
// expandFlatRun can tell one of its leaves from a value token.
//
// `community` declares `args: 1` and a children map, so the container node IS
// the schema node -- the body's leaves hang off it directly.
func snmpCommunitySchema9416() *schemaNode {
	return refSNMPCommunity.resolve()
}

// snmpRoutingInstanceSchema9416 resolves `snmp community <name>
// routing-instance <ri>`, whose body carries the SIXTH spelling's own
// `clients` / `client-list-name`.
func snmpRoutingInstanceSchema9416() *schemaNode {
	return refSNMPRoutingInstance.resolve()
}
