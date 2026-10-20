package cli

import (
	"strings"
	"testing"
)

// #15942 H1-02 (Defect 1): operationalLiveAllowed judged the RAW typed
// words (`sh`, `sec`) against the canonical regexes while the cmdtree
// walkers expand abbreviations before reading DynamicFn values — so an
// abbreviated denied path disclosed live names the fully-spelled path
// withheld. The gate now canonicalizes the words first.
func TestCompletionAbbreviatedOperationalDenied15942(t *testing.T) {
	// Control: open class DOES get live zone values on the abbreviated
	// path, so the test is not vacuous.
	_, open := completion14988CLI(t, "open-view", false)
	openCands := open.cli.completeForHelp([]string{"sh", "sec", "zones"}, "")
	if !hasCandNamed(openCands, "trust") {
		t.Fatalf("control (open-view) missing trust on abbreviated path; test would be vacuous: %v", candNames(openCands))
	}

	_, limited := completion14988CLI(t, "limited-view", false)
	for _, words := range [][]string{
		{"sh", "sec", "zones"},
		{"show", "sec", "zones"},
		{"show", "security", "zones"},
	} {
		cands := limited.cli.completeForHelp(words, "")
		assertNoSecrets14988(t, "abbreviated op "+strings.Join(words, " "), cands)
		if hasCandNamed(cands, "trust") || hasCandNamed(cands, "untrust") {
			t.Errorf("abbreviated path %v leaked denied zone names: %v", words, candNames(cands))
		}
	}
}

// #15942 H1-02 (Defect 3): providerHintAllowed returned true
// unconditionally for ValueHintPolicyName / ValueHintUnitNumber, and
// configPathAllowed judged the literal `groups <g> …` cursor — so a
// class denied `security policies` but allowed `groups` was offered
// policy names inside a group body. Policy/unit hint roots are also now
// denied when a class denies their owning subtree. Both spellings
// (definition and unwrapped body) are judged.
func TestCompletionGroupsBodyHintRoots15942(t *testing.T) {
	// Control: open class gets the policy name under a group body.
	_, open := completion14988CLI(t, "open-view", true)
	openCands := open.cli.completeForHelp([]string{"set", "groups", "g1", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"}, "")
	if !hasCandNamed(openCands, "allow-web") {
		t.Fatalf("control (open-view) missing allow-web under groups; test would be vacuous: %v", candNames(openCands))
	}

	_, limited := completion14988CLI(t, "limited-view", true)
	for _, words := range [][]string{
		{"set", "groups", "g1", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"},
		{"set", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"},
	} {
		cands := limited.cli.completeForHelp(words, "")
		if strings.Contains(strings.Join(candNames(cands), " "), "allow-web") {
			t.Errorf("%v leaked denied policy name: %v", words, candNames(cands))
		}
		assertNoSecrets14988(t, "groups "+strings.Join(words, " "), cands)
	}

	// Unit-number hints use the interfaces owning root: an allowlist
	// class that permits only interfaces retains unit values there, while
	// the same live unit data must not be reached at a policy-name cursor.
	_, allowed := completion14988CLI(t, "allow-interfaces", true)
	if cands := allowed.cli.completeForHelp([]string{"set", "interfaces", "ge-0/0/0", "unit"}, ""); !hasCandNamed(cands, "0") {
		t.Errorf("allow-interfaces should retain allowed unit value, got %v", candNames(cands))
	}
	if cands := allowed.cli.completeForHelp([]string{"set", "groups", "g1", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"}, ""); strings.Contains(strings.Join(candNames(cands), " "), "allow-web") {
		t.Errorf("allow-interfaces leaked policy name outside interfaces: %v", candNames(cands))
	}
}
