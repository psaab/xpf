package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9511: ActiveConnectionNames publishes CHILD SA names, and a VPN with
// traffic-selector entries renders one child `<vpn>-<selector>` per selector and
// no child named `<vpn>`. The HA per-RG attribution needs the VPN, so it inverts
// the render with BuildSANameIndex. These cells drive the index against the
// sections the renderer ACTUALLY emits, read out of the parsed document, rather
// than against a hand-written list of names that could agree with a wrong rule.

func saIndexPolicies9511() map[string]*config.IPsecPolicyDef {
	return map[string]*config.IPsecPolicyDef{
		"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
	}
}

func ts9511(name, local, remote string) *config.IPsecTrafficSelector {
	return &config.IPsecTrafficSelector{Name: name, LocalIP: local, RemoteIP: remote}
}

func TestSANameIndexCoversEveryRenderedSection9511(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			// Multi-selector: children site-a-ts1 / site-a-ts2, none named site-a.
			"site-a": {Name: "site-a", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": ts9511("ts1", "10.0.1.0/24", "10.9.1.0/24"),
					"ts2": ts9511("ts2", "10.0.2.0/24", "10.9.2.0/24"),
				}},
			// No selector: the one child is named after the VPN (the control).
			"plain": {Name: "plain", Gateway: "172.16.0.2", IPsecPolicy: "ipsec-pol"},
			// #5122 sanitised collision: both children carry a hash suffix.
			"coll": {Name: "coll", Gateway: "172.16.0.3", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"x/y": ts9511("x/y", "10.0.3.0/24", "10.9.3.0/24"),
					"x:y": ts9511("x:y", "10.0.4.0/24", "10.9.4.0/24"),
				}},
		},
		Policies: saIndexPolicies9511(),
	}
	idx := BuildSANameIndex(cfg)

	conns := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections")
	connNames := conns.childNames()
	if len(connNames) != 3 {
		t.Fatalf("FIXTURE: expected 3 rendered connections, got %v — a skipped VPN "+
			"would leave its names out of the population under test", connNames)
	}
	children := 0
	for _, conn := range connNames {
		if got := idx.VPNs(conn); len(got) != 1 || got[0] != conn {
			t.Errorf("rendered connection %q indexed to %v, want [%s] (an IKE SA with "+
				"no child yet reports this name)", conn, got, conn)
		}
		for _, child := range conns.at(t, conn, "children").childNames() {
			children++
			if got := idx.VPNs(child); len(got) != 1 || got[0] != conn {
				t.Errorf("#9511: rendered child %q of connection %q indexed to %v; want "+
					"[%s]. The HA attribution looks the VPN up by this name and fell "+
					"to RG 0 on a miss.", child, conn, got, conn)
			}
			if conn == "site-a" && child == "site-a" {
				t.Errorf("FIXTURE: the multi-selector VPN rendered a child named after " +
					"the VPN; the cell no longer distinguishes child from VPN names")
			}
		}
	}
	if children != 5 {
		t.Fatalf("FIXTURE: expected 5 rendered children (2+1+2), got %d", children)
	}
	for _, name := range []string{"", "site-a-ts3", "nosuch"} {
		if got := idx.VPNs(name); got != nil {
			t.Errorf("a name nothing renders (%q) must index to nothing, got %v", name, got)
		}
	}
}

// Renders can collide ACROSS VPNs, child with child and connection with child.
// Nothing in the name says which VPN swanctl reported, so the index must list
// every candidate. Picking the exact VPN name first (the first version of this
// fix) answered `blue-red` for a name that is also blue's child.
func TestSANameIndexListsEveryVPNRenderingACollidingName9511(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"a": {Name: "a", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"b-c": ts9511("b-c", "10.0.1.0/24", "10.9.1.0/24"),
					"d":   ts9511("d", "10.0.2.0/24", "10.9.2.0/24"),
				}},
			"a-b": {Name: "a-b", Gateway: "172.16.0.2", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"c": ts9511("c", "10.0.3.0/24", "10.9.3.0/24"),
				}},
			"blue": {Name: "blue", Gateway: "172.16.0.3", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"red": ts9511("red", "10.0.4.0/24", "10.9.4.0/24"),
				}},
			"blue-red": {Name: "blue-red", Gateway: "172.16.0.4", IPsecPolicy: "ipsec-pol"},
		},
		Policies: saIndexPolicies9511(),
	}

	conns := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections")
	hasChild := func(conn, child string) bool {
		for _, c := range conns.at(t, conn, "children").childNames() {
			if c == child {
				return true
			}
		}
		return false
	}
	for _, f := range [][2]string{{"a", "a-b-c"}, {"a-b", "a-b-c"}, {"blue", "blue-red"}, {"blue-red", "blue-red"}} {
		if !hasChild(f[0], f[1]) {
			t.Fatalf("FIXTURE: connection %q does not render child %q, so the collision "+
				"this cell is about does not exist", f[0], f[1])
		}
	}

	idx := BuildSANameIndex(cfg)
	for _, tc := range []struct {
		name string
		want string
	}{
		{"a-b-c", "a,a-b"},            // child/child
		{"blue-red", "blue,blue-red"}, // child/connection+child
		{"a-d", "a"},                  // CONTROL: rendered by one VPN only
		{"blue", "blue"},              // CONTROL: blue's connection name
	} {
		if got := strings.Join(idx.VPNs(tc.name), ","); got != tc.want {
			t.Errorf("idx.VPNs(%q) = [%s], want [%s]", tc.name, got, tc.want)
		}
	}
}

// A VPN the renderer SKIPS loads nothing and so owns no SA name. If the index
// enumerated the config instead of the render, a skipped VPN whose would-be name
// collides with a loaded VPN's child would make that child look ambiguous and
// the attribution would refuse to initiate a tunnel that is really up.
func TestSANameIndexExcludesVPNsTheRendererSkips9511(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"good": {Name: "good", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"x": ts9511("x", "10.0.1.0/24", "10.9.1.0/24"),
				}},
			// A dangling single-label gateway reference is unrenderable (#2074),
			// reachable through the tolerant load and peer-sync paths.
			"good-x": {Name: "good-x", Gateway: "dangling", IPsecPolicy: "ipsec-pol"},
		},
		Policies: saIndexPolicies9511(),
	}
	conns := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections").childNames()
	if len(conns) != 1 || conns[0] != "good" {
		t.Fatalf("FIXTURE: expected only connection good to render (good-x skipped), "+
			"got %v", conns)
	}

	idx := BuildSANameIndex(cfg)
	if got := strings.Join(idx.VPNs("good-x"), ","); got != "good" {
		t.Errorf("good-x is rendered only as good's child; the skipped VPN good-x "+
			"loads nothing. idx.VPNs(good-x) = [%s], want [good]", got)
	}
}

// The PUBLISHER end of the same contract, driven from real `--list-sas` output
// for a two-selector VPN. The names published must be the CHILD names, since
// they are what the peer later hands to `swanctl --initiate --child`, and each
// must index back to the VPN. Publishing SAStatus.ConnectionName instead (the
// remedy #9075 adjudicated as harmful) would publish `site-a`, which names no
// child section.
func TestActiveSANamesPublishesResolvableChildNames9511(t *testing.T) {
	output := `site-a: #1, ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '10.0.2.1' @ 10.0.2.1[500]
  site-a-ts1: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    local  10.0.1.0/24
    remote 10.9.1.0/24
  site-a-ts2: #2, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    local  10.0.2.0/24
    remote 10.9.2.0/24
`
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {Name: "site-a", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": ts9511("ts1", "10.0.1.0/24", "10.9.1.0/24"),
					"ts2": ts9511("ts2", "10.0.2.0/24", "10.9.2.0/24"),
				}},
		},
		Policies: saIndexPolicies9511(),
	}

	got := activeSANames(parseSAOutput(output))
	if len(got) != 2 || got[0] != "site-a-ts1" || got[1] != "site-a-ts2" {
		t.Fatalf("#9511: the published names must be the CHILD SA names, got %v, "+
			"want [site-a-ts1 site-a-ts2]. The peer initiates with "+
			"`swanctl --initiate --child <name>`, and no child is named site-a.", got)
	}
	idx := BuildSANameIndex(cfg)
	for _, name := range got {
		if vpns := idx.VPNs(name); len(vpns) != 1 || vpns[0] != "site-a" {
			t.Errorf("published name %q indexed to %v, want [site-a]", name, vpns)
		}
	}
}

// One VPN whose render fails OUTRIGHT (an unsupported IKE authentication method
// aborts the whole production render) must not empty the index. A failed Apply
// leaves the previously loaded swanctl config in force, so the other VPNs are
// still live and their child names still need attributing; and the broken VPN's
// own names stay candidates, because it may still be loaded too.
func TestSANameIndexSurvivesAnUnrelatedRenderError9511(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"prop-bad": {Name: "prop-bad", AuthMethod: "bogus"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol-bad": {Proposals: []string{"prop-bad"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-bad": {Address: "172.16.9.9", IKEPolicy: "pol-bad"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {Name: "site-a", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": ts9511("ts1", "10.0.1.0/24", "10.9.1.0/24"),
					"ts2": ts9511("ts2", "10.0.2.0/24", "10.9.2.0/24"),
				}},
			"bad": {Name: "bad", Gateway: "gw-bad", IPsecPolicy: "ipsec-pol"},
		},
		Policies: saIndexPolicies9511(),
	}
	if _, _, err := (&Manager{}).renderConfig(cfg); err == nil {
		t.Fatal("FIXTURE: the whole render must fail on the unsupported auth method, " +
			"or this cell does not exercise the error path")
	}

	idx := BuildSANameIndex(cfg)
	for _, name := range []string{"site-a-ts1", "site-a-ts2", "site-a"} {
		if got := strings.Join(idx.VPNs(name), ","); got != "site-a" {
			t.Errorf("an unrelated VPN's render error emptied the index: idx.VPNs(%q) = [%s], "+
				"want [site-a] — every name would fall back to the pre-#9511 lookup", name, got)
		}
	}
	if got := strings.Join(idx.VPNs("bad"), ","); got != "bad" {
		t.Errorf("a VPN whose render fails outright may still be loaded from the previous "+
			"apply; its names must stay candidates. idx.VPNs(bad) = [%s], want [bad]", got)
	}
}

// Eligibility is keyed by VPN IDENTITY, not by the sanitised connection name. Two
// VPN names that sanitise to one connection name (`x y`, and x<TAB>y whose tab
// becomes a space) must not borrow each other's result.
//
// #9495 changed what this cell can observe, not the property. The only way two
// distinct VPN names sanitise alike is a C0 byte becoming a space, and a space in a
// swanctl section header makes strongSwan discard the whole file (measured,
// docs/log/9495.md). The render belt therefore skips BOTH names, so neither is
// indexed and neither can borrow the other's eligibility. Before #9495 `x y`
// rendered; it only ever produced a file strongSwan refused. The per-VPN keying
// itself stays pinned by the unrelated-render-error cell above.
func TestSANameIndexKeysEligibilityByVPNNotSanitizedName9511(t *testing.T) {
	tabbed := "x" + string(rune(9)) + "y"
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"x y":  {Name: "x y", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			tabbed: {Name: tabbed, Gateway: "dangling", IPsecPolicy: "ipsec-pol"},
		},
		Policies: saIndexPolicies9511(),
	}
	if sanitizeSwanctlValue(tabbed) != "x y" {
		t.Fatalf("FIXTURE: the tabbed name must sanitise to `x y`, got %q", sanitizeSwanctlValue(tabbed))
	}
	_, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil || len(rendered) != 0 {
		t.Fatalf("both section-breaking names must be skipped (#9495), got rendered %v (err %v)", rendered, err)
	}

	idx := BuildSANameIndex(cfg)
	if got := idx.VPNs("x y"); len(got) != 0 {
		t.Errorf("a VPN the renderer skips was indexed under the shared sanitised name: "+
			"idx.VPNs(`x y`) = %q, want none", got)
	}
}

// An IKE SA with no child yet is published under its CONNECTION name. The index
// attributes it to the VPN, but for a multi-selector VPN that name is not a child
// section, so `swanctl --initiate --child site-a` cannot bring it up. This cell
// pins both halves so the documented limitation cannot silently change shape.
func TestActiveSANamesIKEOnlyRowPublishesTheConnectionName9511(t *testing.T) {
	output := `site-a: #1, CONNECTING, IKEv2, 8f7c1c8e3a2b1234_i* 0000000000000000_r
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '10.0.2.1' @ 10.0.2.1[500]
`
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {Name: "site-a", Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": ts9511("ts1", "10.0.1.0/24", "10.9.1.0/24"),
					"ts2": ts9511("ts2", "10.0.2.0/24", "10.9.2.0/24"),
				}},
		},
		Policies: saIndexPolicies9511(),
	}

	got := activeSANames(parseSAOutput(output))
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("an IKE-only row must publish its connection name, got %v", got)
	}
	if vpns := BuildSANameIndex(cfg).VPNs("site-a"); len(vpns) != 1 || vpns[0] != "site-a" {
		t.Errorf("the IKE-only name must still attribute to its VPN, got %v", vpns)
	}
	for _, child := range parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "site-a", "children").childNames() {
		if child == "site-a" {
			t.Errorf("a child section is now named after the multi-selector VPN; the " +
				"documented IKE-only initiate limitation no longer holds — update " +
				"ActiveConnectionNames' doc and docs/sync-protocol.md")
		}
	}
}
