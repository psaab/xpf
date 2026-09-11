package ipsec

import (
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9641: attribution before this process's first load reads what charon has actually
// loaded. These cells parse REAL `swanctl --list-conns --raw` output, captured on
// strongSwan 6.0.5 from a config Manager.renderConfig produced
// (testdata/swanctl_list_conns_source_9641.conf; capture procedure in docs/log/9641.md).

func readFixture9641(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	return string(b)
}

func sortedChildren9641(c LoadedConns) map[string]string {
	out := map[string]string{}
	for conn, lc := range c {
		var cp []string
		if lc != nil {
			cp = append(cp, lc.Children...)
		}
		sort.Strings(cp)
		out[conn] = strings.Join(cp, ",")
	}
	return out
}

func TestParseListConnsRawRealFixture9641(t *testing.T) {
	got, err := parseListConnsRaw(readFixture9641(t, "swanctl_list_conns_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"proof-ms":    "proof-ms-ts1,proof-ms-ts2",
		"proof-plain": "proof-plain",
	}
	g := sortedChildren9641(got)
	if len(g) != len(want) {
		t.Fatalf("connections = %v, want %v", g, want)
	}
	for conn, ch := range want {
		if g[conn] != ch {
			t.Errorf("connection %q children = [%s], want [%s]; the local-1/remote-1 auth "+
				"sections must not be mistaken for children, and `class=pre-shared key` must "+
				"not split into a section name", conn, g[conn], ch)
		}
	}
}

// An independent second instrument over the SAME load: the text format, read line by line
// (a connection header at column 0 with an IKE version, a child header at two spaces with
// a mode). The raw parser and this reading must agree, so neither can drift alone.
func TestParseListConnsRawAgreesWithTextFixture9641(t *testing.T) {
	raw, err := parseListConnsRaw(readFixture9641(t, "swanctl_list_conns_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse raw: %v", err)
	}
	text := LoadedConns{}
	cur := ""
	for _, line := range strings.Split(readFixture9641(t, "swanctl_list_conns_text_9641.txt"), "\n") {
		switch {
		case line != "" && line[0] != ' ' && strings.Contains(line, ": IKE"):
			cur = line[:strings.Index(line, ":")]
			text[cur] = &LoadedConn{}
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") &&
			(strings.Contains(line, ": TUNNEL") || strings.Contains(line, ": TRANSPORT")):
			name := strings.TrimSpace(line[:strings.Index(line, ":")])
			text[cur].Children = append(text[cur].Children, name)
		}
	}
	if len(text) == 0 {
		t.Fatal("FIXTURE: the text reading found no connections; the cross-check would pass vacuously")
	}
	r, x := sortedChildren9641(raw), sortedChildren9641(text)
	if len(r) != len(x) {
		t.Fatalf("raw %v and text %v disagree on the connection set", r, x)
	}
	for conn, ch := range x {
		if r[conn] != ch {
			t.Errorf("connection %q: raw children [%s], text children [%s]", conn, r[conn], ch)
		}
	}
}

func TestLoadedConnsSANamesMatchesTheRenderIndex9641(t *testing.T) {
	got, err := parseListConnsRaw(readFixture9641(t, "swanctl_list_conns_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	names := got.SANames()
	for _, n := range []string{"proof-ms", "proof-ms-ts1", "proof-ms-ts2", "proof-plain"} {
		if !names[n] {
			t.Errorf("SANames() lacks %q; got %v", n, names)
		}
	}
	if len(names) != 4 {
		t.Errorf("SANames() = %v, want exactly the 4 connection and child names", names)
	}
}

func TestParseListConnsRawEmptyAndMalformed9641(t *testing.T) {
	got, err := parseListConnsRaw("list-conns reply {}\n")
	if err != nil || len(got) != 0 {
		t.Errorf("an empty charon must parse to no connections, got %v (err %v)", got, err)
	}
	for _, bad := range []string{
		"list-conn event {proof-ms {children {proof-ms-ts1 {mode=TUNNEL}}\n",
		"list-conn event {proof-ms {}}}\n",
	} {
		if _, err := parseListConnsRaw(bad); err == nil {
			t.Errorf("unbalanced output %q must be an error, not a partial loaded set", bad)
		}
	}
}

// Charon unreachable is an ERROR, never an empty loaded set: "nothing loaded" and
// "could not ask" must stay distinguishable, because the caller's fallback depends on it.
func TestListLoadedConnsUnreachableIsAnError9641(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) {
		return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed: No such file or directory")
	}
	got, err := m.ListLoadedConns()
	if err == nil {
		t.Fatalf("an unreachable charon must return an error, got loaded set %v", got)
	}
}

func proofConfig9641() *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"proof-plain": {Name: "proof-plain", Gateway: "198.51.100.61"},
			"proof-ms": {Name: "proof-ms", Gateway: "198.51.100.62",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.61.1.0/24", RemoteIP: "10.62.1.0/24"},
					"ts2": {Name: "ts2", LocalIP: "10.61.2.0/24", RemoteIP: "10.62.2.0/24"},
				}},
		},
	}
}

// A renderer-SKIPPED VPN never reaches charon and is excluded, while its siblings stay
// expected: the production render still succeeds and loads them. A skipped VPN renders
// nothing, so the config still renders to the captured source, and the expectation must
// still equal what charon listed.
func TestExpectedLoadedConnsExcludesSkippedVPN9641(t *testing.T) {
	cfg := proofConfig9641()
	cfg.VPNs["skipped"] = &config.IPsecVPN{Name: "skipped", Gateway: "dangling"}
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil || rendered["skipped"] {
		t.Fatalf("FIXTURE: a dangling gateway must be a skip, not a render error (err %v, rendered %v)", err, rendered)
	}
	if text != readFixture9641(t, "swanctl_list_conns_source_9641.conf") {
		t.Fatal("FIXTURE: a skipped VPN must render nothing, leaving the captured source unchanged")
	}
	got, err := expectedLoadedConns(cfg, nil)
	if err != nil {
		t.Fatalf("a skip is not a render error, got %v", err)
	}
	if _, ok := got["skipped"]; ok {
		t.Errorf("a renderer-skipped VPN never reaches charon and must not be expected, got %s", describe9641(got))
	}
	loaded, err := parseListConnsRaw(readFixture9641(t, "swanctl_list_conns_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !loaded.Equal(got) {
		t.Errorf("CONTROL: the siblings still render and must equal what charon listed: expected %s, charon %s",
			describe9641(got), describe9641(loaded))
	}
}

// A HARD render error aborts the whole production render, so charon cannot have loaded
// ANY part of that generation (Codex #9641 plan review P2). The candidate must be
// disqualified as a whole. Excluding only the broken VPN would describe a generation
// charon never ran.
func TestExpectedLoadedConnsDisqualifiesACandidateWithARenderError9641(t *testing.T) {
	cfg := proofConfig9641()
	cfg.IKEProposals = map[string]*config.IKEProposal{"prop-bad": {Name: "prop-bad", AuthMethod: "bogus"}}
	cfg.IKEPolicies = map[string]*config.IKEPolicy{"pol-bad": {Proposals: []string{"prop-bad"}}}
	cfg.Gateways = map[string]*config.IPsecGateway{"gw-bad": {Address: "172.16.9.9", IKEPolicy: "pol-bad"}}
	cfg.VPNs["broken"] = &config.IPsecVPN{Name: "broken", Gateway: "gw-bad"}
	got, err := expectedLoadedConns(cfg, nil)
	if err == nil {
		t.Fatalf("a render error must disqualify the whole candidate, got expected %s", describe9641(got))
	}
}

// The per-connection address lists: the discriminator a name set lacks (an RG move keeps
// the names but loads a different local address). Both real fixtures, and the auth
// subsections' own lists must not be read as addresses.
func TestParseListConnsRawEndpointAddrs9641(t *testing.T) {
	for _, tc := range []struct {
		fixture, conn, local, remote, children string
	}{
		{"swanctl_list_conns_raw_9641.txt", "proof-ms", "%any", "198.51.100.62", "proof-ms-ts1,proof-ms-ts2"},
		{"swanctl_list_conns_raw_9641.txt", "proof-plain", "%any", "198.51.100.61", "proof-plain"},
		{"swanctl_list_conns_localaddr_raw_9641.txt", "proof-la", "192.0.2.61", "198.51.100.63", "proof-la-ts1"},
	} {
		got, err := parseListConnsRaw(readFixture9641(t, tc.fixture))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.fixture, err)
		}
		lc := got[tc.conn]
		if lc == nil {
			t.Fatalf("%s: connection %q missing, got %v", tc.fixture, tc.conn, got)
		}
		if l := strings.Join(lc.LocalAddrs, ","); l != tc.local {
			t.Errorf("%s %s: LocalAddrs = [%s], want [%s]", tc.fixture, tc.conn, l, tc.local)
		}
		if r := strings.Join(lc.RemoteAddrs, ","); r != tc.remote {
			t.Errorf("%s %s: RemoteAddrs = [%s], want [%s]", tc.fixture, tc.conn, r, tc.remote)
		}
		if c := sortedChildren9641(got)[tc.conn]; c != tc.children {
			t.Errorf("%s %s: children = [%s], want [%s]", tc.fixture, tc.conn, c, tc.children)
		}
	}
}
