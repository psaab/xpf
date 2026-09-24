package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #9416 unit-level cells for the pieces the configstore channel tests exercise
// end-to-end: the AllowsSource predicate change, the dual-shape list parse, and
// the resolution's fail-closed arm.

// THE QUARANTINE WAS ARMED AND UNREACHABLE, and this is the cell for it.
//
// #5833 quarantines a community by overriding `clientNets` with an explicit
// deny-all while leaving `Clients` untouched (the config text stays intact for
// display and hashing). That worked only because the case it was written for —
// a malformed INLINE token — still leaves that token in `Clients`, so
// AllowsSource's `len(Clients) == 0 -> allow-all` early return never fired.
//
// An unresolvable `client-list-name` has no such residue. It resolves to
// nothing, `Clients` stays empty, and before #9416 the community returned
// ALLOW-ALL through that early return while carrying a deny-all match set two
// fields over.
//
// The three rows must give three different answers, which is what makes the
// predicate observable: only the middle one changed, and a fix that simply
// deleted the early return would red the third.
func TestSNMPAllowsSourceDistinguishesQuarantineFromUnrestricted9416(t *testing.T) {
	probe := snmpClientTestSource10687("203.0.113.9")

	// (1) No restriction authored at all: allow-all is CORRECT.
	unrestricted := &SNMPCommunity{Name: "c"}
	if !unrestricted.AllowsSource(probe) {
		t.Error("a community with no restriction must allow every source (the Junos default)")
	}

	// (2) QUARANTINED with an EMPTY Clients — the shape an unresolvable
	// client-list reference produces. This is the row that was wrong.
	quarantined := &SNMPCommunity{Name: "c", clientNets: snmpQuarantineClientNets()}
	if quarantined.AllowsSource(probe) {
		t.Error("#9416: a quarantined community must DENY even with an empty Clients. The #5833 " +
			"quarantine overrides clientNets only, so an `len(Clients) == 0 -> allow-all` early " +
			"return makes it unreachable exactly when the restriction resolved to nothing")
	}
	if quarantined.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Error("#9416: a quarantined community must deny EVERY source, not only unlisted ones")
	}

	// (3) A real allowlist still discriminates. Without this row, (2) is
	// satisfiable by making AllowsSource deny unconditionally.
	restricted := &SNMPCommunity{Name: "c", Clients: []SNMPClient{{Prefix: "10.0.0.0/8"}}}
	restricted.clientNets = compileClientNets(restricted.Clients)
	if restricted.AllowsSource(probe) {
		t.Error("an allowlisted community must deny an unlisted source")
	}
	if !restricted.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Error("an allowlisted community must admit a listed source")
	}

	// (4) A DIRECTLY-CONSTRUCTED community (no compile) keeps the on-the-fly
	// path: clientNets nil, Clients populated. The new predicate must not
	// change it.
	uncompiled := &SNMPCommunity{Name: "c", Clients: []SNMPClient{{Prefix: "10.0.0.0/8"}}}
	if uncompiled.AllowsSource(probe) {
		t.Error("an uncompiled community must still deny an unlisted source (the on-the-fly parse path)")
	}
	if !uncompiled.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Error("an uncompiled community must still admit a listed source")
	}
}

// The named list's body reaches parseSNMPClients through BOTH parser AST
// shapes, and the list NAME is Keys[1] — reading the prefix run from Keys[1:]
// would make the list name its own first prefix, which parseClientPrefix
// rejects as malformed and which would quarantine every referencing community.
func TestSNMPClientListPrefixParseDualShape9416(t *testing.T) {
	// FLAT / bracketed: prefixes on the node's own Keys after the name.
	flat := parseSNMPClientListPrefixes(&Node{
		Keys: []string{"client-list", "trusted", "10.0.0.0/8", "10.1.0.0/16", "restrict"},
	})
	// BRACED: prefixes as children.
	braced := parseSNMPClientListPrefixes(&Node{
		Keys: []string{"client-list", "trusted"},
		Children: []*Node{
			{Keys: []string{"10.0.0.0/8"}},
			{Keys: []string{"10.1.0.0/16", "restrict"}},
		},
	})
	for _, tc := range []struct {
		name string
		got  []SNMPClient
	}{{"flat", flat}, {"braced", braced}} {
		if len(tc.got) != 2 {
			t.Fatalf("%s: got %d entries, want 2: %+v", tc.name, len(tc.got), tc.got)
		}
		if tc.got[0].Prefix != "10.0.0.0/8" || tc.got[0].Restrict {
			t.Errorf("%s: first entry %+v, want 10.0.0.0/8 allow", tc.name, tc.got[0])
		}
		if tc.got[1].Prefix != "10.1.0.0/16" || !tc.got[1].Restrict {
			t.Errorf("%s: second entry %+v, want 10.1.0.0/16 restrict", tc.name, tc.got[1])
		}
		for _, e := range tc.got {
			if e.Prefix == "trusted" {
				t.Errorf("%s: the list NAME was read as a prefix — that entry is unparseable, which "+
					"would quarantine every community referencing the list", tc.name)
			}
		}
	}
}

// `client-list-name` is declared `args: 1`, so exactly ONE token follows it. A
// reader taking Keys[1:] turns the next statement's keyword into a list name on
// a packed flat run — fail-closed rather than fail-open, but it rejects a config
// the operator wrote correctly.
func TestSNMPCommunityListRefsReadsOneToken9416(t *testing.T) {
	refs := snmpCommunityListRefs([]*Node{
		{Keys: []string{"client-list-name", "trusted", "authorization", "read-only"}},
	})
	if len(refs) != 1 || refs[0] != "trusted" {
		t.Errorf("got %v, want exactly [trusted] — `client-list-name` takes ONE argument, and the "+
			"tokens after it belong to the following statement", refs)
	}
	// De-duplication across repeated statements.
	dup := snmpCommunityListRefs([]*Node{
		{Keys: []string{"client-list-name", "a"}},
		{Keys: []string{"client-list-name", "a"}},
		{Keys: []string{"client-list-name", "b"}},
	})
	if len(dup) != 2 || dup[0] != "a" || dup[1] != "b" {
		t.Errorf("got %v, want [a b] in document order, de-duplicated", dup)
	}
}

// UNRESOLVABLE and EMPTY are one answer, because AllowsSource treats an empty
// allowlist as allow-all: a reference that resolves to nothing must reach the
// caller's fail-closed arm, not its success arm.
func TestSNMPResolveClientListRefsFailsClosed9416(t *testing.T) {
	lists := map[string][]SNMPClient{
		"good":  {{Prefix: "10.0.0.0/8"}},
		"empty": {},
	}
	for _, tc := range []struct {
		name           string
		refs           []string
		wantClients    int
		wantUnresolved []string
	}{
		{"resolvable", []string{"good"}, 1, nil},
		{"undefined", []string{"nope"}, 0, []string{"nope"}},
		{"defined but empty", []string{"empty"}, 0, []string{"empty"}},
		{"one good one bad", []string{"good", "nope"}, 1, []string{"nope"}},
	} {
		clients, unresolved := resolveSNMPClientListRefs(tc.refs, lists)
		if len(clients) != tc.wantClients {
			t.Errorf("%s: got %d clients, want %d", tc.name, len(clients), tc.wantClients)
		}
		if len(unresolved) != len(tc.wantUnresolved) {
			t.Errorf("%s: got unresolved %v, want %v", tc.name, unresolved, tc.wantUnresolved)
			continue
		}
		for i := range unresolved {
			if unresolved[i] != tc.wantUnresolved[i] {
				t.Errorf("%s: got unresolved %v, want %v", tc.name, unresolved, tc.wantUnresolved)
				break
			}
		}
	}
	// The "one good one bad" row is the one that matters: a partially resolved
	// reference set must STILL reach the fail-closed arm. Returning the good
	// half and swallowing the bad one would leave a narrower-than-authored
	// allowlist silently in force.
}

// The API surface must show the authored reference and the list definitions —
// the marshal aliases enumerate fields explicitly, so a field added to the
// struct and not to the alias silently vanishes.
func TestSNMPClientListSurvivesJSONMarshal9416(t *testing.T) {
	s := SNMPConfig{
		Communities: map[string]*SNMPCommunity{
			"secret-community-string": {Name: "secret-community-string", Authorization: "read-only",
				ClientListNames: []string{"trusted"}},
		},
		ClientLists: map[string][]SNMPClient{"trusted": {{Prefix: "10.0.0.0/8"}}},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, "ClientLists") || !strings.Contains(out, "10.0.0.0/8") {
		t.Errorf("the client-list definitions must reach the API surface; got %s", out)
	}
	if !strings.Contains(out, "ClientListNames") || !strings.Contains(out, "trusted") {
		t.Errorf("the authored reference must reach the API surface — it is the only visible reason a "+
			"community with an empty Clients is quarantined; got %s", out)
	}
	// The community STRING stays redacted. A list name is not a secret; the
	// community is, and adding fields must not weaken #2053.
	if strings.Contains(out, "secret-community-string") {
		t.Errorf("#2053: the community string must stay redacted; got %s", out)
	}
}
