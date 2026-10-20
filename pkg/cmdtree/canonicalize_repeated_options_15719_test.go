package cmdtree

import (
	"strings"
	"testing"
)

// #15719: Canonicalize did not track seen option keys on Options:true
// nodes, and it resolved child keywords before checking a pending value
// slot. Both are the #14688/#14687 defect class one level down:
//
//   - Repeated option: `show firewall filter secret effective effective`
//     canonicalized OK with the duplicate in the judged string, while
//     cli_show.go's firewallArgsHaveWord scan ignores the duplicate and
//     renders `secret` effective once. An anchored
//     deny `^show firewall filter secret effective$` therefore missed.
//     `show security flow session zone guest zone untrust` likewise
//     judged two zones while parseSessionFilterMode keeps the last.
//   - Value-token that is a child keyword: `show security flow session
//     zone zone` and `sort-by` with no value canonicalized OK, while the
//     dispatcher consumes/skips the would-be value and runs a broader
//     (or differently filtered) command. `show security policies
//     from-zone to-zone` is the non-Options form: from-zone's pending
//     dynamic value was skipped by resolving `to-zone` as its child.
//
// The regression cells below must fail on the pre-fix code and pass after.
func TestCanonicalizeRepeatedOptionsRefused15719(t *testing.T) {
	for _, line := range []string{
		// Options:true nodes — exact and abbreviated repeats.
		"show firewall filter secret effective effective",
		"show firewall filter secret effective eff",
		"show firewall filter secret eff effective",
		"show firewall filter secret family inet family inet6",
		"show firewall filter secret fam inet fam inet6",
		"show firewall filter secret family inet effective effective",
		"show security flow session zone guest zone untrust",
		"show security flow session zone guest zone",
		"show security flow session source-prefix 10.0.0.0/8 source-prefix 192.168.0.0/16",
		"show security flow session summary summary",
		"show security flow session brief brief",
		"show security flow session nat nat",
		"show security flow session destination-port 22 destination-port 80",
		"show security flow session sort-by bytes sort-by packets",
		"clear security flow session zone trust zone untrust",
		"ping 1.1.1.1 count 5 count 6",
		"ping 1.1.1.1 count 5 cou 6",
		"traceroute 1.1.1.1 source 10.0.0.1 source 10.0.0.2",
		"monitor traffic interface ge-0/0/0 interface ge-0/0/1",
		"test routing destination 1.1.1.1 destination 2.2.2.2",
		"show security log zone trust zone untrust",
		// Pending value slot must be filled before a child keyword or the
		// next option resolves (#14687-class mid-walk value-skip).
		"show security flow session sort-by",
		"show security flow session sort-by sort-by",
		"show security flow session zone sort-by",
		"show security flow session zone zone",
		"show security flow session zone trust sort-by bytes zone untrust",
		"show firewall filter secret family family",
		"show firewall filter secret family",
		"ping 1.1.1.1 count count",
		// NOTE: `ping count 5` is not a Canonicalize refusal: under an
		// Options node the <host> placeholder is optional for the walk
		// (#14687), and ParsePingOptions rejects `count` as a target.
		"show security policies from-zone to-zone",
		"show security policies from-zone trust to-zone to-zone",
		"show route table table",
		// Placeholder with children under a keyword node: the value that
		// is itself a child keyword must not skip the placeholder slot.
		"show chassis cluster data-plane flows flows",
		"show chassis cluster data-plane flows limit limit",
	} {
		if got, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK as %q; repeated option / skipped value must be refused", line, strings.Join(got, " "))
		}
	}
}

// Controls: no neighbouring valid spelling may regress.
func TestCanonicalizeRepeatedOptionsControls15719(t *testing.T) {
	for _, line := range []string{
		"show firewall filter secret effective",
		"show firewall filter secret family inet",
		"show firewall filter secret family inet effective",
		"show firewall filter secret effective family inet",
		"show firewall filter secret",
		"show security flow session",
		"show security flow session zone trust",
		"show security flow session zone trust destination-port 22",
		"show security flow session summary",
		"show security flow session brief",
		"show security flow session nat",
		"show security flow session sort-by bytes",
		"show security flow session sort-by packets",
		// A pending value that abbreviates a keyword is still a value
		// (#9505): `fl` is zone's value here, not the `flag` option.
		"show security flow session sort-by packets zone trust",
		"clear security flow session zone trust nat-only",
		"ping 1.1.1.1 count 5",
		"ping 1.1.1.1 count 5 source 10.0.0.1 size 1400 routing-instance vrf1",
		"traceroute 1.1.1.1 source 10.0.0.1",
		"monitor traffic interface ge-0/0/0 count 5",
		"test routing destination 1.1.1.1 instance vrf1",
		"show security log zone trust 50",
		"show security log 50 zone trust",
		"show security policies from-zone trust to-zone untrust policy p1",
		"show security policies from-zone trust to-zone untrust",
		"show route table inet.0",
		"show route 10.0.0.0/8 exact",
		"show chassis cluster data-plane flows limit 10",
		"show chassis cluster data-plane flows 10",
		"show chassis cluster data-plane flows all",
		// Non-Options dynamic chains keep working.
		"show security zones trust detail",
		"show interfaces ge-0/0/0 detail",
	} {
		got, res := Canonicalize(OperationalTree, strings.Fields(line))
		if res != CanonicalOK {
			t.Errorf("%q: result %v (canon %q), want CanonicalOK; a restricted class would be refused a lawful command", line, res, strings.Join(got, " "))
		}
	}
}

// Synthetic: the seen-set and pending-value rules are properties of the
// walk, not of today's real tree.
func TestCanonicalizeRepeatedOptionsSynthetic15719(t *testing.T) {
	tree := syntheticTree9505()
	// Refused rows that do not depend on value-vs-keyword ambiguity:
	for _, line := range []string{
		"opts t1 flag flag",
		"opts t1 port 22 port 23",
		"opts zone z1 zone z2",
		"opts port port",
	} {
		if _, res := Canonicalize(tree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("synthetic %q canonicalized OK; want refusal", line)
		}
	}
	for _, tc := range []struct{ line, canon string }{
		{"opts t1 flag", "opts t1 flag"},
		{"opts zone z1 port 22 t1 flag", "opts zone z1 port 22 t1 flag"},
		{"opts zone fl t1", "opts zone fl t1"},
		{"opts port fl t1", "opts port fl t1"},
	} {
		got, res := Canonicalize(tree, strings.Fields(tc.line))
		if res != CanonicalOK || strings.Join(got, " ") != tc.canon {
			t.Errorf("synthetic %q: (%q,%v), want (%q,CanonicalOK)", tc.line, strings.Join(got, " "), res, tc.canon)
		}
	}
}
