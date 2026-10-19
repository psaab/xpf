package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8443: the authentication render census, varying BOTH axes.
//
// Two independent defects hid behind one-axis checks:
//
//   - varying the TYPE with a key always present cannot see that OSPF emitted
//     `ip ospf message-digest-key 1 md5` with no argument when the key was
//     empty — a keyword missing its argument, which vtysh rejects, and one
//     rejected line fails the ENTIRE managed-section reload (#1880/#2223);
//   - varying the KEY with a recognized type always set cannot see that an
//     unrecognized type silently downgrades md5 to plaintext.
//
// So the census walks {every accepted type, plus an unrecognized one} x {key
// present, key absent} across all four render sites.

// keyBearingLines maps a rendered line PREFIX to the minimum number of
// whitespace-separated fields a well-formed instance must have.
//
// Keyed by prefix rather than by last token, because the same word plays both
// roles: `ip rip authentication mode md5` legitimately ENDS in `md5` (there it
// is the value of `mode`), while `area-password md5` ending there is malformed
// (there `md5` names the algorithm and the key must follow). An earlier version
// of this cell used a last-token set and reported that correct RIP line as a
// defect — the distinction is the line's shape, not the word.
var keyBearingLines = map[string]int{
	"ip ospf message-digest-key":   6, // ip ospf message-digest-key <id> md5 <key>
	"ip ospf authentication-key":   4, // ip ospf authentication-key <key>
	"ip rip authentication string": 5, // ip rip authentication string <key>
	"area-password":                3, // area-password <alg> <key>
	"domain-password":              3, // domain-password <alg> <key>
	"isis password":                4, // isis password <alg> <key>
}

// No rendered authentication line may end in a keyword that expects an
// argument — for ANY combination of type and key presence.
//
// This is the half my own and the review's censuses both missed, and it is the
// one that catches the OSPF empty-key defect.
func TestNoAuthLineEndsInADanglingKeyword8443(t *testing.T) {
	types := append(config.AuthTypeSpellings(), "", "md5-typo", "MD5")
	keys := []string{"s3cret", ""}

	for _, at := range types {
		for _, key := range keys {
			m := New()
			isis := &config.ISISConfig{
				NET:        "49.0001.0100.0000.0001.00",
				Level:      "level-2",
				AuthType:   at,
				AuthKey:    config.Secret(key),
				Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: at, AuthKey: config.Secret(key)}},
			}
			rip := &config.RIPConfig{
				AuthType:   at,
				AuthKey:    config.Secret(key),
				Interfaces: []string{"trust0"},
			}
			ospf := &config.OSPFConfig{
				Areas: []*config.OSPFArea{{
					ID: "0.0.0.0",
					Interfaces: []*config.OSPFInterface{
						{Name: "trust0", AuthType: at, AuthKey: config.Secret(key)},
					},
				}},
			}
			got := m.generateProtocols(ospf, nil, nil, rip, isis, "", 0, nil, nil)

			for _, line := range strings.Split(got, "\n") {
				l := strings.TrimSpace(line)
				for prefix, minFields := range keyBearingLines {
					if !strings.HasPrefix(l, prefix) {
						continue
					}
					if n := len(strings.Fields(l)); n < minFields {
						t.Fatalf("type=%q key=%q rendered a key-bearing line with "+
							"%d fields, want at least %d: %q\n"+
							"vtysh rejects a keyword missing its argument, and ONE "+
							"rejected line fails the whole managed-section reload "+
							"(#1880/#2223)", at, key, n, minFields, l)
					}
				}
			}
		}
	}
}

// A recognized type with a key must render md5 for md5 and the plaintext arm
// for the plaintext spellings — the control that keeps the cell above from
// being satisfied by rendering nothing at all.
func TestRecognizedAuthTypesStillRender8443(t *testing.T) {
	cases := []struct {
		authType string
		wantISIS string
		wantRIP  string
	}{
		{"md5", "area-password md5 s3cret", "ip rip authentication mode md5"},
		{"simple", "area-password clear s3cret", "ip rip authentication mode text"},
		{"text", "area-password clear s3cret", "ip rip authentication mode text"},
	}
	for _, tc := range cases {
		m := New()
		isis := &config.ISISConfig{
			NET: "49.0001.0100.0000.0001.00", Level: "level-2",
			AuthType: tc.authType, AuthKey: "s3cret",
			Interfaces: []*config.ISISInterface{{Name: "trust0"}},
		}
		rip := &config.RIPConfig{
			AuthType: tc.authType, AuthKey: "s3cret", Interfaces: []string{"trust0"},
		}
		got := m.generateProtocols(nil, nil, nil, rip, isis, "", 0, nil, nil)
		for _, want := range []string{tc.wantISIS, tc.wantRIP} {
			if !strings.Contains(got, want) {
				t.Errorf("authentication-type %q: missing %q in:\n%s", tc.authType, want, got)
			}
		}
	}
}

// An UNRECOGNIZED type carrying a key used to take the plaintext arm.
//
// #8443 pinned that deliberately: promoting it to md5 would flip a box
// running plaintext today into md5 against a peer expecting plaintext
// and drop the adjacency on upgrade. #14977 (D33-05) supersedes the
// render arm of that choice: plaintext-for-an-unrecognized-type is a
// silently DOWNGRADED adjacency — the operator's `show configuration`
// still claims the type they typed — so the renderer now fails closed
// instead: no IS-IS activation and no RIP enrollment at all. That is
// neither the md5 promotion #8443 rejected (nothing renders as md5)
// nor the silent plaintext it accepted; the strict gate still rejects
// new instances, and the tolerant path now withholds the adjacency
// loudly (slog) rather than forming it weakened.
func TestUnrecognizedAuthTypeRendersPlaintextNotMD5OrSilence8443(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET: "49.0001.0100.0000.0001.00", Level: "level-2",
		AuthType: "md5-typo", AuthKey: "s3cret",
		Interfaces: []*config.ISISInterface{{Name: "trust0"}},
	}
	rip := &config.RIPConfig{AuthType: "md5-typo", AuthKey: "s3cret", Interfaces: []string{"trust0"}}
	got := m.generateProtocols(nil, nil, nil, rip, isis, "", 0, nil, nil)

	if strings.Contains(got, "area-password md5") || strings.Contains(got, "mode md5") {
		t.Fatalf("an unrecognized type was promoted to md5; that drops adjacencies "+
			"on upgrade against a peer expecting plaintext:\n%s", got)
	}
	for _, bad := range []string{"area-password", "domain-password", "ip rip authentication", "network trust0", "ip router isis"} {
		if strings.Contains(got, bad) {
			t.Fatalf("an unrecognized type still activated routing (%q present); "+
				"#14977 fails closed — no weakened adjacency:\n%s", bad, got)
		}
	}
}

// #14397 (DR9-H1): a keyless OSPF auth selection (AuthType md5 with every
// MD5 key empty, or simple with an empty key) must NEVER render as a silent
// unauthenticated interface. The strict gate rejects it at compile; on the
// tolerant path the renderer fails closed by omitting the interface
// activation entirely (with a warning) rather than emitting ip ospf area
// with zero authentication lines. Keyed auth must render byte-identical.
func TestKeylessOSPFAuthNeverRendersUnauthenticated14397(t *testing.T) {
	keyless := map[string]*config.OSPFConfig{
		"md5-no-keys": {Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
			{Name: "ge-0/0/1.0", AuthType: "md5", AuthKeyID: 1, AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 1, Key: ""}}},
		}}}},
		"md5-empty-slice": {Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
			{Name: "ge-0/0/1.0", AuthType: "md5"},
		}}}},
		"simple-empty-key": {Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
			{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: ""},
		}}}},
	}
	for name, ospf := range keyless {
		t.Run(name, func(t *testing.T) {
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") {
				t.Fatalf("keyless OSPF auth rendered an (unauthenticated) interface activation; want fail-closed omission (#14397):\n%s", got)
			}
		})
	}

	keyed := map[string]struct {
		ospf *config.OSPFConfig
		want []string
	}{
		"md5-keyed": {
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "ge-0/0/1.0", AuthType: "md5", AuthKeyID: 1, AuthKey: "s3cret", AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 1, Key: "s3cret"}}},
			}}}},
			want: []string{"interface ge-0/0/1.0", " ip ospf authentication message-digest\n", " ip ospf message-digest-key 1 md5 s3cret\n", " ip ospf area 0.0.0.0\n"},
		},
		"md5-rollover-mix": {
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "ge-0/0/1.0", AuthType: "md5", AuthKeyID: 2, AuthKey: "s3cret", AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 1, Key: ""}, {ID: 2, Key: "s3cret"}}},
			}}}},
			want: []string{"interface ge-0/0/1.0", " ip ospf authentication message-digest\n", " ip ospf message-digest-key 2 md5 s3cret\n", " ip ospf area 0.0.0.0\n"},
		},
		"simple-keyed": {
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: "s3cret"},
			}}}},
			want: []string{"interface ge-0/0/1.0", " ip ospf authentication\n", " ip ospf authentication-key s3cret\n", " ip ospf area 0.0.0.0\n"},
		},
		"no-auth": {
			ospf: &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "ge-0/0/1.0"},
			}}}},
			want: []string{"interface ge-0/0/1.0", " ip ospf area 0.0.0.0\n"},
		},
	}
	for name, tc := range keyed {
		t.Run(name, func(t *testing.T) {
			got := New().generateProtocols(tc.ospf, nil, nil, nil, nil, "", 0, nil, nil)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("keyed OSPF auth (%s) missing %q; rendered output changed:\n%s", name, want, got)
				}
			}
		})
	}
}
