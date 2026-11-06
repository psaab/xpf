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

// TestSNMPConfigHashFramesCommunities18986 reproduces the ambiguous legacy
// stream from compiled configuration text. The six references on the single
// community begin with the old quarantine marker/value, then spell a second
// community's name, authorization, and empty list fields. With no count or
// boundary token, that stream aliases the two-community form exactly.
func TestSNMPConfigHashFramesCommunities18986(t *testing.T) {
	const listDefinitions = `
        client-list source-restriction-quarantined { 10.0.0.1/32; }
        client-list false { 10.0.0.2/32; }
        client-list b { 10.0.0.3/32; }
        client-list read-only { 10.0.0.4/32; }
        client-list clients { 10.0.0.5/32; }
        client-list client-list-names { 10.0.0.6/32; }
`
	compile := func(text string) *config.Config {
		t.Helper()
		tree, parseErrs := config.NewParser(text).Parse()
		if len(parseErrs) != 0 {
			t.Fatalf("parse SNMP config: %v", parseErrs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile SNMP config: %v", err)
		}
		return cfg
	}
	oneCommunity := compile(`system { host-name fw; snmp {` + listDefinitions + `
        community a {
            authorization read-only;
            client-list-name source-restriction-quarantined;
            client-list-name false;
            client-list-name b;
            client-list-name read-only;
            client-list-name clients;
            client-list-name client-list-names;
        }
    } }`)
	twoCommunities := compile(`system { host-name fw; snmp {` + listDefinitions + `
        community a {
            authorization read-only;
            clients 10.0.0.1/32;
            clients 10.0.0.2/32;
            clients 10.0.0.3/32;
            clients 10.0.0.4/32;
            clients 10.0.0.5/32;
            clients 10.0.0.6/32;
        }
        community b { authorization read-only; }
    } }`)
	oneA := oneCommunity.System.SNMP.Communities["a"]
	twoA := twoCommunities.System.SNMP.Communities["a"]
	if !reflect.DeepEqual(oneA.Clients, twoA.Clients) {
		t.Fatalf("crafted alias changed resolved Clients: one=%+v two=%+v", oneA.Clients, twoA.Clients)
	}
	if len(twoCommunities.System.SNMP.Communities) != 2 || len(oneCommunity.System.SNMP.Communities) != 1 {
		t.Fatalf("compiled community counts: one=%d two=%d",
			len(oneCommunity.System.SNMP.Communities), len(twoCommunities.System.SNMP.Communities))
	}
	if oneHash, twoHash := snmpConfigHash(oneCommunity), snmpConfigHash(twoCommunities); oneHash == twoHash {
		t.Fatalf("#18986: one crafted community and two communities alias the reconcile hash (%d)", oneHash)
	}
}

// TestSNMPConfigHashIncludesClientListDefinitions18986 hashes definitions even
// when unreferenced. This is a conservative superset of live enforcement: an
// unreferenced edit may cause a safe extra reconcile, but cannot leave the
// retained definition surface out of the fingerprint.
func TestSNMPConfigHashIncludesClientListDefinitions18986(t *testing.T) {
	compile := func(prefix string) *config.Config {
		t.Helper()
		text := `system { host-name fw; snmp {
            client-list unused { ` + prefix + `; }
            community public { authorization read-only; }
        } }`
		tree, parseErrs := config.NewParser(text).Parse()
		if len(parseErrs) != 0 {
			t.Fatalf("parse SNMP config: %v", parseErrs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile SNMP config: %v", err)
		}
		return cfg
	}
	before := compile("10.0.0.0/8")
	after := compile("192.168.0.0/16")
	if !reflect.DeepEqual(before.System.SNMP.Communities, after.System.SNMP.Communities) {
		t.Fatal("editing an unreferenced list changed compiled communities")
	}
	if beforeHash, afterHash := snmpConfigHash(before), snmpConfigHash(after); beforeHash == afterHash {
		t.Fatalf("#18986: an unreferenced ClientLists definition edit did not change the hash (%d)", beforeHash)
	}
}

// TestSNMPConfigHashFramesSameCountLenientRefs18986 closes the same-count
// framing alias: undefined refs can impersonate the in-band quarantine marker,
// community terminator, and following community header without changing the
// number of communities or resolved Clients.
func TestSNMPConfigHashFramesSameCountLenientRefs18986(t *testing.T) {
	compile := func(communities string) *config.Config {
		t.Helper()
		text := `system { host-name fw; snmp {` + communities + `} }`
		tree, parseErrs := config.NewParser(text).Parse()
		if len(parseErrs) != 0 {
			t.Fatalf("parse SNMP config: %v", parseErrs)
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile lenient SNMP config: %v", err)
		}
		return cfg
	}

	x := compile(`
        community a {
            authorization read-only;
            client-list-name source-restriction-quarantined;
            client-list-name false;
            client-list-name end-community;
            client-list-name b;
            client-list-name read-only;
            client-list-name clients;
            client-list-name client-list-names;
        }
        community b {
            authorization read-only;
            client-list-name z;
        }
    `)
	y := compile(`
        community a { authorization read-only; }
        community b {
            authorization read-only;
            client-list-name source-restriction-quarantined;
            client-list-name true;
            client-list-name end-community;
            client-list-name b;
            client-list-name read-only;
            client-list-name clients;
            client-list-name client-list-names;
            client-list-name z;
        }
    `)

	xA, xB := x.System.SNMP.Communities["a"], x.System.SNMP.Communities["b"]
	yA, yB := y.System.SNMP.Communities["a"], y.System.SNMP.Communities["b"]
	if xA == nil || xB == nil || yA == nil || yB == nil {
		t.Fatal("both lenient configs must contain communities a and b")
	}
	wantXARefs := []string{
		"source-restriction-quarantined", "false", "end-community", "b",
		"read-only", "clients", "client-list-names",
	}
	wantYBRefs := []string{
		"source-restriction-quarantined", "true", "end-community", "b",
		"read-only", "clients", "client-list-names", "z",
	}
	for _, got := range []struct {
		name string
		comm *config.SNMPCommunity
		refs []string
	}{
		{name: "X.a", comm: xA, refs: wantXARefs},
		{name: "X.b", comm: xB, refs: []string{"z"}},
		{name: "Y.a", comm: yA, refs: nil},
		{name: "Y.b", comm: yB, refs: wantYBRefs},
	} {
		if len(got.comm.Clients) != 0 {
			t.Errorf("%s resolved Clients = %+v, want no resolved entries", got.name, got.comm.Clients)
		}
		if !reflect.DeepEqual(got.comm.ClientListNames, got.refs) {
			t.Errorf("%s ClientListNames = %q, want %q", got.name, got.comm.ClientListNames, got.refs)
		}
	}
	if !xA.SourceRestrictionQuarantined() || yA.SourceRestrictionQuarantined() {
		t.Fatalf("community a quarantine states: X=%v Y=%v, want X quarantined and Y unrestricted",
			xA.SourceRestrictionQuarantined(), yA.SourceRestrictionQuarantined())
	}
	if xHash, yHash := snmpConfigHash(x), snmpConfigHash(y); xHash == yHash {
		t.Fatalf("#18986: same-count lenient reference streams alias the reconcile hash (%d)", xHash)
	}
}
