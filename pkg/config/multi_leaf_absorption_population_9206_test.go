package config

import (
	"sort"
	"strings"
	"testing"
)

// #9206: a `multi` leaf defeats its container's closed world. Absorption
// (#2419) turns trailing tokens into VALUES before any keyword check runs, so
// an undeclared statement standing behind a multi leaf is INJECTED rather than
// refused:
//
//	set protocols rip group g1 authentication-key secret1                    REJECT
//	set protocols rip group g1 neighbor ge-0/0/0 authentication-key secret1  ACCEPT
//	  -> ifaces = [ge-0/0/0 authentication-key secret1]
//
// THE POPULATION, not the instance. Every `multi: true` leaf under a
// `closedWorld: true` container has the shape; this measures how many actually
// reach the compiled config, because that is what decides the remedy.
//
//	19  structural sites (multi leaf, closed-world ancestor)
//	 2  of those are `groups`-rehosted duplicates of the RIP pair -- the SAME
//	    schema nodes reached by a second route (#8921), so 17 are distinct
//	19  absorb at the SCHEMA WALK (all 19 controls reject without the multi leaf)
//	 1  survives the COMPILER and reaches the config
//
// So the mechanism is general and the exposure is singular, which is the same
// shape #9181 turned out to have. The discriminator is not the container: it is
// whether the absorbing leaf's VALUE TYPE has a downstream validator.
// `neighbor` takes free-form interface names and nothing checks that an
// interface exists, so the garbage becomes two non-existent interfaces named to
// FRR. Every other multi leaf in the set validates its values -- `export`
// requires a known policy, the NAT match leaves require parseable addresses --
// and each rejects the absorbed token by name.
//
// THE `multi` PREDICATE IS CORROBORATED, NOT ASSUMED. Mutating the filter away
// -- counting EVERY leaf under a closed-world container, not just multi ones --
// leaves the count unchanged at 19. So no non-multi leaf absorbs, which is the
// mechanism's own prediction measured rather than restated. That mutant
// SURVIVING is the evidence; had the filter been doing the work, widening it
// would have added sites.
//
// A SCHEMA-WALK RESULT IS AN UPPER BOUND on what commits, which is why the
// walk's 19 and the compiler's 1 are both reported. Each compiler row is paired
// with a BASELINE that omits the absorbed token: without it, a rejection for a
// missing `then` or an undefined pool is indistinguishable from the absorption
// being caught, and three of these rows initially rejected for exactly those
// unrelated reasons.
func TestMultiLeafAbsorptionPopulation9206(t *testing.T) {
	type site struct {
		path []string
		leaf string
		node *schemaNode
	}
	var sites []site
	seen := map[string]bool{}
	var walk func(path []string, n *schemaNode, closed bool)
	walk = func(path []string, n *schemaNode, closed bool) {
		if n == nil || len(path) > 9 {
			return
		}
		closed = closed || n.closedWorld
		for k, c := range n.children {
			if c == nil {
				continue
			}
			// The fixture path must carry an INSTANCE NAME for every node that
			// takes one. `protocols rip group` is args:1 with no wildcard, so a
			// path without one makes the undeclared keyword the GROUP NAME --
			// the control then wrongly ACCEPTS and the row is discarded. That
			// silently removed 15 of 19 sites, the RIP instance among them.
			childPath := append(append([]string{}, path...), k)
			if c.args >= 1 || c.wildcard != nil {
				childPath = append(childPath, "xpfinst")
			}
			key := strings.Join(childPath, " ")
			if seen[key] {
				continue
			}
			seen[key] = true
			if closed && c.multi && c.children == nil && c.wildcard == nil {
				sites = append(sites, site{append([]string{}, path...), k, c})
			}
			next := c
			if c.wildcard != nil {
				next = c.wildcard
			}
			walk(childPath, next, closed || c.closedWorld)
		}
	}
	for k, c := range setSchema.children {
		p0 := []string{k}
		if c.args >= 1 || c.wildcard != nil {
			p0 = append(p0, "xpfinst")
		}
		next := c
		if c.wildcard != nil {
			next = c.wildcard
		}
		walk(p0, next, c.closedWorld)
	}

	validate := func(lines []string) error {
		tree := &ConfigTree{}
		for _, l := range lines {
			p, err := ParseSetCommand(l)
			if err != nil {
				return err
			}
			tree.SetPath(p)
		}
		return SchemaValidateWithDefinitions(tree, tree, nil)
	}
	synth := func(n *schemaNode) string {
		if v, _, ok := synthPair(n); ok && v != "" {
			return v
		}
		return "xpfv"
	}

	var absorbing, distinct int
	var rows []string
	for _, s := range sites {
		base := "set " + strings.Join(s.path, " ")
		if validate([]string{base + " xpfbogus9206 v1"}) == nil {
			t.Errorf("#9206: control ACCEPTED at %q — the container is not closed "+
				"there, so an ACCEPT below would prove nothing", base)
			continue
		}
		if validate([]string{base + " " + s.leaf + " " + synth(s.node) + " xpfbogus9206 v1"}) == nil {
			absorbing++
			if !strings.HasPrefix(strings.Join(s.path, " "), "groups") {
				distinct++
			}
			rows = append(rows, strings.Join(s.path, " ")+" multi="+s.leaf)
		}
	}
	sort.Strings(rows)

	// #9351: 19 -> 23 absorbing, 17 -> 19 distinct. Making
	// `routing-instances <n> protocols` the GLOBAL protocols node brought the
	// whole `rip` subtree — including its closedWorld `group` — into the
	// per-instance grammar, so `rip group <g>` {export, neighbor} now absorb
	// there as well as globally. The two extra `absorbing` rows over the two
	// distinct ones are the `groups <name>` rehosts of the same nodes.
	//
	// The GREW note below says to check whether the new absorption reaches the
	// compiler too. MEASURED, both spellings in one run:
	//
	//	set routing-instances RI protocols rip group r1 neighbor [ ge-0/0/0.0 ge-0/0/1.0 ]
	//	  -> ri.RIP.Interfaces = [ge-0/0/0.0 ge-0/0/1.0]
	//	set protocols rip group r1 neighbor [ ge-0/0/0.0 ge-0/0/1.0 ]
	//	  -> cfg.Protocols.RIP.Interfaces = [ge-0/0/0.0 ge-0/0/1.0]
	//
	// so the absorption is read, and it is read identically at both sites —
	// which is the point of #9351, since it is now literally the same node.
	// #9416: 23 -> 25 absorbing, 19 -> 20 distinct. `snmp community <c>
	// routing-instance <ri>` was declared with closedWorld (its body is
	// leaf-complete and every keyword it could absorb is a SOURCE RESTRICTION),
	// which brings its `clients` multi leaf into this population; the second
	// absorbing row is the `groups <name>` rehost of the same node.
	//
	// The GREW note below says to check whether the new absorption reaches the
	// COMPILER too. MEASURED, against the community-level sibling as a control:
	//
	//	set snmp community c routing-instance ri clients [ 10.0.0.0/8 172.16.0.0/12 ]
	//	  -> Clients = [10.0.0.0/8, 172.16.0.0/12]
	//	set snmp community c routing-instance ri clients 10.0.0.0/8
	//	set snmp community c routing-instance ri clients 172.16.0.0/12
	//	  -> Clients = [10.0.0.0/8, 172.16.0.0/12]
	//	CONTROL, community level:
	//	set snmp community c clients [ 10.0.0.0/8 172.16.0.0/12 ]
	//	  -> Clients = [10.0.0.0/8, 172.16.0.0/12]
	//
	// so the absorption is read, and read identically to the sibling. The
	// closed world is doing work rather than decorating: a bogus keyword under
	// `routing-instance` is REJECTED ("unknown configuration keyword ... under
	// closed-world subtree") while the SAME keyword one level up, at the
	// open-world community, still commits clean and compiles to nothing.
	// #9265: 25 -> 39 absorbing, 20 -> 27 distinct. Arming fourteen instance-name
	// containers' `closedWorld` brings seven more multi leaves inside a closed
	// world (each with a `groups` rehost of the same node, so +14 structural for
	// +7 distinct):
	//
	//	policy-options community <c> multi=members
	//	security address-book global address-set <s> multi=address
	//	security address-book global address-set <s> multi=address-set
	//	security nat proxy-arp interface <if> multi=address
	//	security zones security-zone <z> address-book address-set <s> multi=address
	//	security zones security-zone <z> address-book address-set <s> multi=address-set
	//	system login class <c> multi=permissions
	//
	// THE GREW NOTE BELOW SAYS TO CHECK WHETHER THE NEW ABSORPTION REACHES THE
	// COMPILER. Measured, and it splits the eight exactly along #9206's own
	// discriminator — whether the absorbing leaf's value type has a downstream
	// validator (`snmp community <c> clients` was measured the same way and rejects
	// too, but `snmp community` was dropped from the arming batch, so its only
	// armed position remains #9416's `routing-instance` child):
	//
	//	nat proxy-arp interface <if> address   STRICT COMPILE REJECT (not a valid
	//	                                      IP address or CIDR prefix)
	//	policy-options community members       COMMITS -> Members:[65000:1 xpfbogus9206 v1]
	//	system login class permissions         COMMITS -> Permissions:[view xpfbogus9206 v1]
	//	address-set <s> address (both books)   COMMITS -> Addresses:[a1 xpfbogus9206 v1]
	//	address-set <s> address-set (global)   COMMITS
	//
	// ARMING DID NOT CREATE THE FOUR THAT COMMIT, and that was measured rather
	// than argued. On a PRISTINE origin/master worktree with no arming applied the
	// compiled output is BYTE-IDENTICAL, and all six spellings commit clean at
	// configstore.CheckText there too — including the BRACKETED-LIST form
	// (`members [ 65000:1 xpfbogus9206 v1 ]`), which is not a flat-run question at
	// all. Absorption is a property of the `multi` leaf and SetPath, not of
	// closedWorld; what arming changed is only that these containers now fall
	// inside this census's DEFINITION. Before it, the same garbage was accepted as
	// a plain SIBLING statement as well, so arming is a strict improvement that
	// simply does not close the multi-leaf route.
	//
	// Filed as #9490 rather than fixed here: the remedy is a per-leaf validator for
	// validateMultiValueLeaf to run (#2497), a different change from arming a
	// container's keyword world.
	//
	// #9490 then closed all four, in two places:
	//   - `system login class permissions` became a TYPED multi leaf with a
	//     validator, so it is refused at THIS walk. It left the census at both
	//     positions, top-level and the `groups` rehost: 39 -> 37 absorbing,
	//     27 -> 26 distinct.
	//   - community members and address-set members are refused at COMPILE
	//     (ValidCommunityMember, validateAddressSetMembersDefinedStrict). They
	//     still absorb at the schema walk, so they stay in the count.
	const wantAbsorbing, wantDistinct = 37, 26
	if absorbing != wantAbsorbing || distinct != wantDistinct {
		t.Errorf("#9206: %d sites absorb at the schema walk (%d excluding `groups` "+
			"rehosts), want %d (%d).\n  %s\n\n"+
			"GREW: a new multi leaf under a closed-world container, or a new "+
			"closedWorld flip over an existing one — check whether it reaches the "+
			"compiler too. SHRANK: absorption is being refused somewhere; re-derive.",
			absorbing, distinct, wantAbsorbing, wantDistinct, strings.Join(rows, "\n  "))
	}
}
