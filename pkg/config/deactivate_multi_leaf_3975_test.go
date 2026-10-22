package config

import (
	"sort"
	"strings"
	"testing"
)

// TestDeactivateMultiLeaf_3975 pins the deactivate/activate counterpart of the
// #2419 multi-value-leaf class. On a `multi: true` value-list leaf that holds a
// bracket list (`from protocol [ tcp udp icmp ]`, policy match values,
// host-inbound-services), `deactivate`/`activate` must toggle the leaf's
// Inactive marker across the WHOLE bracket-list node — before #3975 the
// schema-driven traversal ate the first member as an extra key and then treated
// the remaining members as container tokens, so:
//
//   - `deactivate ... from protocol tcp udp icmp` (exactly what display-set
//     emits for an inactive bracket leaf) ERRORED with "container \"protocol
//     tcp\" does not exist"; and
//   - an inactive bracket leaf therefore did NOT round-trip — FormatSet emitted
//     the expanded `deactivate` line and replaying it errored, so the leaf
//     reloaded ACTIVE (a silent loss of the operator's deactivate intent).
//
// fail-on-revert: reverting the markMultiLeafMembersInactive branch makes the
// whole-list / round-trip / activate assertions RED (deactivate errors and the
// leaf reloads active, so the compiler sees the protocols instead of an empty
// match).

// deactivateProtocols reads the compiled `from protocol` match values for a
// firewall-filter term (the read side). An inactive leaf is pruned by the
// compiler, so the returned slice is empty.
func deactivateProtocols(t *testing.T, tree *ConfigTree, filter, term string) []string {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	f := cfg.Firewall.FiltersInet[filter]
	if f == nil {
		t.Fatalf("filter %q not found", filter)
	}
	for _, tm := range f.Terms {
		if tm.Name == term {
			got := append([]string(nil), tm.Protocols...)
			sort.Strings(got)
			return got
		}
	}
	t.Fatalf("term %q not found in filter %q", term, filter)
	return nil
}

func mustDeactivate(t *testing.T, tree *ConfigTree, cmd string) {
	t.Helper()
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.DeactivatePath(path); err != nil {
		t.Fatalf("DeactivatePath(%q): %v", cmd, err)
	}
}

func mustActivate(t *testing.T, tree *ConfigTree, cmd string) {
	t.Helper()
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.ActivatePath(path); err != nil {
		t.Fatalf("ActivatePath(%q): %v", cmd, err)
	}
}

func TestDeactivateMultiLeaf_FirewallProtocol(t *testing.T) {
	base := "set firewall family inet filter F term T from protocol [ tcp udp icmp ]"
	accept := "set firewall family inet filter F term T then accept"
	allProtos := []string{"icmp", "tcp", "udp"}

	// (1) Whole expanded list — the exact line display-set emits. Before #3975
	// this ERRORED; now it marks the whole leaf inactive so the compiler prunes it.
	t.Run("deactivate-whole-expanded-list", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDeactivate(t, tree, "deactivate firewall family inet filter F term T from protocol tcp udp icmp")
		if got := deactivateProtocols(t, tree, "F", "T"); len(got) != 0 {
			t.Fatalf("after deactivate expanded list: protocols = %v, want empty (leaf inactive)", got)
		}
	})

	// (2) Bare `deactivate ... from protocol` (no member) toggles the whole leaf.
	t.Run("deactivate-no-member", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDeactivate(t, tree, "deactivate firewall family inet filter F term T from protocol")
		if got := deactivateProtocols(t, tree, "F", "T"); len(got) != 0 {
			t.Fatalf("after deactivate no-member: protocols = %v, want empty", got)
		}
	})

	// (3) Naming a single member toggles the whole bracket-list statement
	// (Inactive is node-level — a bracket list cannot be half-deactivated).
	t.Run("deactivate-single-member-toggles-whole-leaf", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDeactivate(t, tree, "deactivate firewall family inet filter F term T from protocol udp")
		if got := deactivateProtocols(t, tree, "F", "T"); len(got) != 0 {
			t.Fatalf("after deactivate one member: protocols = %v, want empty", got)
		}
	})

	// (4) Deactivating an absent member is a not-found error (delete's contract).
	t.Run("deactivate-absent-member-errors", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		path, _ := ParseSetCommand("deactivate firewall family inet filter F term T from protocol gre")
		if err := tree.DeactivatePath(path); err == nil {
			t.Fatal("deactivating an absent member should return an error")
		}
		if got := deactivateProtocols(t, tree, "F", "T"); !equalStrs3846(got, allProtos) {
			t.Fatalf("failed deactivate must not disturb the leaf: protocols = %v, want %v", got, allProtos)
		}
	})

	// (5) activate reverses the deactivate — the leaf compiles again.
	t.Run("activate-reverses", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDeactivate(t, tree, "deactivate firewall family inet filter F term T from protocol tcp udp icmp")
		if got := deactivateProtocols(t, tree, "F", "T"); len(got) != 0 {
			t.Fatalf("precondition: leaf should be inactive, protocols = %v", got)
		}
		mustActivate(t, tree, "activate firewall family inet filter F term T from protocol tcp udp icmp")
		if got := deactivateProtocols(t, tree, "F", "T"); !equalStrs3846(got, allProtos) {
			t.Fatalf("after activate: protocols = %v, want %v", got, allProtos)
		}
	})

	// (6) Round-trip: deactivate -> FormatSet -> replay every line -> the leaf
	// is STILL inactive and the compiler STILL prunes it. This is the core
	// RED-on-revert: on revert the replayed `deactivate ... protocol tcp udp
	// icmp` line errors, the leaf reloads ACTIVE, and the compiler sees the
	// protocols again.
	t.Run("round-trip-through-display-set", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDeactivate(t, tree, "deactivate firewall family inet filter F term T from protocol")

		flat := tree.FormatSet()
		if !strings.Contains(flat, "deactivate firewall family inet filter F term T from protocol tcp udp icmp") {
			t.Fatalf("FormatSet missing the expanded deactivate line:\n%s", flat)
		}

		replay := &ConfigTree{}
		for _, line := range strings.Split(flat, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			verb, p, err := ParseSetVerb(line)
			if err != nil {
				t.Fatalf("ParseSetVerb(%q): %v", line, err)
			}
			switch verb {
			case "deactivate":
				err = replay.DeactivatePath(p)
			case "activate":
				err = replay.ActivatePath(p)
			case "delete":
				err = replay.DeletePath(p)
			default:
				err = replay.SetPath(p)
			}
			if err != nil {
				t.Fatalf("replay %q (%s): %v", line, verb, err)
			}
		}
		if got := deactivateProtocols(t, replay, "F", "T"); len(got) != 0 {
			t.Fatalf("round-trip lost the deactivate: protocols = %v, want empty (leaf reloaded ACTIVE)", got)
		}
		// Re-serializing the replayed tree reproduces the deactivate line.
		if again := replay.FormatSet(); !strings.Contains(again,
			"deactivate firewall family inet filter F term T from protocol tcp udp icmp") {
			t.Fatalf("second FormatSet dropped the deactivate marker:\n%s", again)
		}
	})
}

// TestDeactivateMultiLeaf_PolicyMatchSourceAddress exercises the fix on a
// security-policy match value list (source-address). Naming one member toggles
// the whole source-address statement; because a security policy REQUIRES a
// source-address (the #3044 gate), the deactivated leaf is a legitimately
// uncompilable "parked" edit — assert on the AST node + display-set round-trip,
// and prove the policy compiles again once re-activated.
func TestDeactivateMultiLeaf_PolicyMatchSourceAddress(t *testing.T) {
	build := func() *ConfigTree {
		return buildTree3846(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security address-book global address a1 10.0.1.0/24",
			"set security address-book global address a2 10.0.2.0/24",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address [ a1 a2 ]",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		)
	}
	srcNode := func(tree *ConfigTree) *Node {
		return tree.FindChild("security").FindChild("policies").FindChild("from-zone").
			FindChild("policy").FindChild("match").FindChild("source-address")
	}

	tree := build()
	// Baseline compiles.
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("baseline compile: %v", err)
	}

	// Naming one member toggles the whole source-address statement.
	mustDeactivate(t, tree, "deactivate security policies from-zone trust to-zone untrust policy p1 match source-address a1")
	sn := srcNode(tree)
	if sn == nil || !sn.Inactive {
		t.Fatalf("source-address leaf should be inactive after member deactivate: %+v", sn)
	}
	// A parked source-address is intentionally uncompilable (#3044 required-criterion).
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("policy with a deactivated source-address should fail the required-criterion gate")
	}

	// FormatSet round-trips the deactivate on the expanded member list.
	flat := tree.FormatSet()
	if !strings.Contains(flat, "deactivate security policies from-zone trust to-zone untrust policy p1 match source-address a1 a2") {
		t.Fatalf("FormatSet missing expanded deactivate line:\n%s", flat)
	}
	replay := &ConfigTree{}
	for _, line := range strings.Split(flat, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		verb, p, err := ParseSetVerb(line)
		if err != nil {
			t.Fatalf("ParseSetVerb(%q): %v", line, err)
		}
		switch verb {
		case "deactivate":
			err = replay.DeactivatePath(p)
		case "activate":
			err = replay.ActivatePath(p)
		case "delete":
			err = replay.DeletePath(p)
		default:
			err = replay.SetPath(p)
		}
		if err != nil {
			t.Fatalf("replay %q (%s): %v", line, verb, err)
		}
	}
	if rn := srcNode(replay); rn == nil || !rn.Inactive {
		t.Fatalf("round-trip lost the deactivate: source-address reloaded ACTIVE: %+v", rn)
	}

	// activate restores both members and the policy compiles again.
	mustActivate(t, tree, "activate security policies from-zone trust to-zone untrust policy p1 match source-address a1 a2")
	if sn := srcNode(tree); sn == nil || sn.Inactive {
		t.Fatalf("activate should clear the inactive flag: %+v", sn)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile after activate: %v", err)
	}
	var got []string
	for _, pr := range cfg.Security.Policies {
		if pr.FromZone == "trust" && pr.ToZone == "untrust" {
			for _, p := range pr.Policies {
				if p.Name == "p1" {
					got = append([]string(nil), p.Match.SourceAddresses...)
				}
			}
		}
	}
	sort.Strings(got)
	if !equalStrs3846(got, []string{"a1", "a2"}) {
		t.Fatalf("after activate source-address: %v, want [a1 a2]", got)
	}
}

// TestDeactivateMultiLeaf_BlockShapeMember exercises the hierarchical block
// shape of a value-list leaf (one child node per member): a member named on
// `deactivate` toggles ONLY that child node, leaving its siblings active.
func TestDeactivateMultiLeaf_BlockShapeMember(t *testing.T) {
	// Block shape only comes from hierarchical text (NewParser); the flat-set
	// path always yields the bracket shape.
	tree := parseHierText(t, `security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services {
                    ssh;
                    https;
                    ping;
                }
            }
        }
    }
}`)
	mustDeactivate(t, tree, "deactivate security zones security-zone trust host-inbound-traffic system-services ssh")

	svc := tree.FindChild("security").FindChild("zones").FindChild("security-zone").
		FindChild("host-inbound-traffic").FindChild("system-services")
	if svc == nil {
		t.Fatalf("system-services node not found: %+v", tree.Children)
	}
	if svc.Inactive {
		t.Fatal("member deactivate must NOT toggle the parent system-services container")
	}
	for _, c := range svc.Children {
		if len(c.Keys) == 0 {
			continue
		}
		switch c.Keys[0] {
		case "ssh":
			if !c.Inactive {
				t.Fatal("ssh child should be inactive")
			}
		default:
			if c.Inactive {
				t.Fatalf("sibling %q should stay active", c.Keys[0])
			}
		}
	}

	// activate reverses it.
	mustActivate(t, tree, "activate security zones security-zone trust host-inbound-traffic system-services ssh")
	for _, c := range svc.Children {
		if c.Inactive {
			t.Fatalf("child %v should be active after activate", c.Keys)
		}
	}
}

// TestDeactivateMultiLeaf_SingleValueLeafUnchanged asserts a non-multi
// (single-value) leaf keeps the pre-#3975 whole-node toggle: the new
// multi-leaf branch must not fire for it.
func TestDeactivateMultiLeaf_SingleValueLeafUnchanged(t *testing.T) {
	tree := buildTree3846(t,
		"set system host-name parked",
	)
	mustDeactivate(t, tree, "deactivate system host-name parked")
	hn := tree.FindChild("system").FindChild("host-name")
	if hn == nil || !hn.Inactive {
		t.Fatalf("single-value host-name leaf should be inactive: %+v", hn)
	}
	mustActivate(t, tree, "activate system host-name parked")
	if hn.Inactive {
		t.Fatal("activate should clear the single-value leaf")
	}
}

// TestDeactivateMultiLeaf_KeyedEntryUnchanged asserts the args==2 keyed multi
// entry (address <name> <prefix>) keeps whole-node toggle semantics — the new
// args==1 member branch must NOT fire for it.
func TestDeactivateMultiLeaf_KeyedEntryUnchanged(t *testing.T) {
	tree := buildTree3846(t,
		"set security address-book global address a1 10.0.1.0/24",
		"set security address-book global address a2 10.0.2.0/24",
	)
	mustDeactivate(t, tree, "deactivate security address-book global address a1")
	book := tree.FindChild("security").FindChild("address-book").FindChild("global")
	if book == nil {
		t.Fatalf("address-book global not found: %+v", tree.Children)
	}
	for _, c := range book.Children {
		if len(c.Keys) >= 2 && c.Keys[0] == "address" && c.Keys[1] == "a1" {
			if !c.Inactive {
				t.Fatal("address a1 should be inactive")
			}
		}
		if len(c.Keys) >= 2 && c.Keys[0] == "address" && c.Keys[1] == "a2" {
			if c.Inactive {
				t.Fatal("address a2 should stay active")
			}
		}
	}
}
