package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9416: the `client-list-name` references a community authored are a live
// authorization input and must move the reconcile hash, for a reason the
// resolved `Clients` allowlist cannot cover.
//
// THE CASE THAT MATTERS is an UNRESOLVABLE reference. The community's Clients
// is EMPTY — the referenced list does not exist, or is empty — and it is
// quarantined to deny-all through `clientNets`, which #5833 deliberately keeps
// OFF the config surface this hash reads. So hashing only Clients makes
//
//	community public { authorization read-only; }
//
// and
//
//	community public { authorization read-only; client-list-name nope; }
//
// hash EQUAL, while the first serves every source and the second serves none.
// Reconcile then takes the idempotent no-op path and the running agent keeps
// whichever policy it already had — which, on the edit that ADDS the reference,
// is allow-all. That is the #5105 class reached through a new door.
//
// Fail-on-revert: drop the `client-list-names` block from snmpConfigHash and
// the first two assertions below fail.
func TestSNMPConfigHashIncludesClientListNames9416(t *testing.T) {
	cfgWith := func(clients []config.SNMPClient, refs []string) *config.Config {
		cfg := &config.Config{}
		cfg.System.SNMP = &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only", Clients: clients, ClientListNames: refs},
			},
		}
		return cfg
	}
	h := func(clients []config.SNMPClient, refs []string) uint64 {
		return snmpConfigHash(cfgWith(clients, refs))
	}

	// THE ROW THIS CELL EXISTS FOR: both sides have an empty Clients, so only
	// the reference distinguishes them — and the two enforce OPPOSITE policies
	// (allow-all vs. quarantined deny-all).
	noRestriction := h(nil, nil)
	unresolvableRef := h(nil, []string{"nope"})
	if noRestriction == unresolvableRef {
		t.Fatal("#9416: adding an unresolvable client-list-name to an unrestricted community did not " +
			"change the hash. Both have an empty Clients; the quarantine lives in clientNets, which this " +
			"hash cannot see — so reconcile no-ops and the agent keeps serving EVERY source while the " +
			"commit reports success")
	}

	// Renaming the referenced list is an authorization change even when the
	// resolved allowlist happens to be identical: the two names can resolve to
	// different lists on the next edit, and one of them may not exist.
	refA := h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"listA"})
	refB := h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"listB"})
	if refA == refB {
		t.Fatal("#9416: changing which client-list a community references did not change the hash")
	}

	// Removing the reference must be detected in the other direction too.
	if h(nil, []string{"trusted"}) == h(nil, nil) {
		t.Fatal("#9416: removing a client-list-name did not change the hash")
	}

	// CONTROL, and it is what keeps this from being satisfied by hashing
	// something random: identical input still hashes equal, so an unchanged
	// stanza takes the reconcile no-op path.
	if h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"trusted"}) !=
		h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"trusted"}) {
		t.Fatal("CONTROL: identical SNMP config must hash equal, or every reconcile tick restarts the agent")
	}

	// CONTROL: the pre-existing #5105 property is untouched — the resolved
	// allowlist still moves the hash on its own, with no references present.
	if h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, nil) == h([]config.SNMPClient{{Prefix: "192.168.0.0/16"}}, nil) {
		t.Fatal("CONTROL: #5105 regressed — changing the client prefix no longer changes the hash")
	}
}

// TestSNMPConfigHashIncludesCrossRootQuarantine18844 pins the config-surface
// blind spot from #18844: the lenient second-root compile keeps the authored
// Clients and ClientListNames intact, but folds the effective clientNets
// enforcement to deny-all. Both configs must compile from source text so the
// root-local taint fold, rather than a hand-built cache, is exercised.
//
// Fail-on-revert: removing the source-restriction-quarantined marker from
// snmpConfigHash makes these configs hash equal despite the assertions below
// proving that their authored community fields are identical.
func TestSNMPConfigHashIncludesCrossRootQuarantine18844(t *testing.T) {
	const validRoot = `system {
    host-name fw;
    snmp {
        client-list mgmt { 0.0.0.0/0; }
        community scoped { authorization read-only; client-list-name mgmt; }
    }
}`
	const malformedRoot = `system {
    domain-name example.test;
    snmp { client-list mgmt { 10.1.0.0/16 restrict extra; } }
}`
	compile := func(text string, lenient bool) *config.Config {
		t.Helper()
		tree, parseErrs := config.NewParser(text).Parse()
		if len(parseErrs) != 0 {
			t.Fatalf("parse SNMP config: %v", parseErrs)
		}
		var (
			cfg *config.Config
			err error
		)
		if lenient {
			cfg, err = config.CompileConfigLenient(tree)
		} else {
			cfg, err = config.CompileConfig(tree)
		}
		if err != nil {
			t.Fatalf("compile lenient=%v SNMP config: %v", lenient, err)
		}
		return cfg
	}

	valid := compile(validRoot, false)
	quarantined := compile(validRoot+"\n"+malformedRoot, true)
	validCommunity := valid.System.SNMP.Communities["scoped"]
	quarantinedCommunity := quarantined.System.SNMP.Communities["scoped"]
	if validCommunity == nil || quarantinedCommunity == nil {
		t.Fatal("both compiled configs must contain community scoped")
	}
	if !reflect.DeepEqual(validCommunity.Clients, quarantinedCommunity.Clients) {
		t.Fatalf("Clients differ before hash comparison: valid=%+v quarantined=%+v",
			validCommunity.Clients, quarantinedCommunity.Clients)
	}
	if !reflect.DeepEqual(validCommunity.ClientListNames, quarantinedCommunity.ClientListNames) {
		t.Fatalf("ClientListNames differ before hash comparison: valid=%+v quarantined=%+v",
			validCommunity.ClientListNames, quarantinedCommunity.ClientListNames)
	}
	if validCommunity.SourceRestrictionQuarantined() {
		t.Fatal("valid-only community must not be marked quarantined")
	}
	if !quarantinedCommunity.SourceRestrictionQuarantined() {
		t.Fatal("two-root lenient community must expose its deny-all quarantine")
	}

	validHash, quarantinedHash := snmpConfigHash(valid), snmpConfigHash(quarantined)
	if validHash == quarantinedHash {
		t.Fatalf("#18844: valid-only and cross-root-quarantined configs hash equal (%d) despite identical authored Clients/ClientListNames and opposite effective source enforcement",
			validHash)
	}

	// A reference may have the same text as the marker. The tagged,
	// unconditional boolean must prevent that authored value from
	// impersonating quarantine when the other community fields are identical.
	validWithMarkerReference := compile(validRoot, false)
	markerReferenceCommunity := validWithMarkerReference.System.SNMP.Communities["scoped"]
	markerReferenceCommunity.ClientListNames = append(markerReferenceCommunity.ClientListNames, "source-restriction-quarantined")
	if !reflect.DeepEqual(markerReferenceCommunity.Clients, quarantinedCommunity.Clients) {
		t.Fatalf("marker-reference control changed Clients: valid=%+v quarantined=%+v",
			markerReferenceCommunity.Clients, quarantinedCommunity.Clients)
	}
	if markerReferenceCommunity.SourceRestrictionQuarantined() {
		t.Fatal("marker-reference control must not be quarantined")
	}
	if markerReferenceHash := snmpConfigHash(validWithMarkerReference); markerReferenceHash == quarantinedHash {
		t.Fatalf("#18844: authored reference text impersonated the quarantine marker; both configs hash to %d",
			markerReferenceHash)
	}
}
