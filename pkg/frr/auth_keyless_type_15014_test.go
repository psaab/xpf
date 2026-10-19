package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15014 (A12-02): one predicate, "auth configured but no renderable
// auth line", must fail closed everywhere. #14977 implemented it for
// the lone-fragment OSPF simple / IS-IS global / IS-IS interface
// shapes, but the OSPF arm reads the UNIONED interface
// (config.OSPFInterfaceUnion12186.Merge, #12186) — and Merge only
// copies AuthKey under a matched simple/md5 AuthType. A key carried
// with NO type is therefore dropped by the union before the #14977
// `AuthType == "" && AuthKey != ""` guard ever sees it: the guard is
// dead for exactly the shape it was written for, and the interface
// renders `ip ospf area` with zero auth lines — an unauthenticated
// adjacency on the tolerant path. That is the surviving leg of the
// three A12-02 probes (OSPF simple/unrenderable, IS-IS passwords,
// IS-IS keyless type): the IS-IS legs and the lone OSPF legs are
// already withheld by #14977 and are pinned below as controls so
// they cannot regress while the typeless-key hole is closed.
//
// The fix preserves the key through the union as auth-configured
// evidence (without inventing a type or emitting the key), so the
// existing renderer guard can withhold the interface. It does NOT
// render the typeless key as plaintext: OSPF's compiler only ever
// sets a key with a type, so a typeless OSPF key is a
// foreign/tolerant construction with no established plaintext
// semantics (unlike the RIP/IS-IS #9105 absent-type arms).
//
// Each test has a keyed / plain control in the same test so a
// blanket suppression cannot pass.

// --- OSPF: key with no authentication-type (union drops the key) ---

func TestOSPFKeyWithNoTypeDoesNotActivate15014(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthKey: "s3cret"},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") {
		t.Fatalf("OSPF key-with-no-type activated the interface unauthenticated (union dropped the key before the #14977 guard):\n%s", got)
	}
	if strings.Contains(got, "authentication-key") {
		t.Fatalf("typeless OSPF key must not be emitted as a plaintext auth line either:\n%s", got)
	}
	// Control: no auth at all still activates (plain OSPF by design).
	plain := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0"},
	}}}}
	got = m.generateProtocols(plain, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "interface ge-0/0/1.0\n") || !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
		t.Fatalf("unauthenticated-by-design OSPF interface no longer activates:\n%s", got)
	}
	// Control: keyed simple still activates byte-identically.
	keyed := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: "s3cret"},
	}}}}
	got = m.generateProtocols(keyed, nil, nil, nil, nil, "", 0, nil, nil)
	for _, w := range []string{"interface ge-0/0/1.0\n", " ip ospf authentication\n", " ip ospf authentication-key s3cret\n", " ip ospf area 0.0.0.0\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("renderable simple key lost %q:\n%s", w, got)
		}
	}
}

// The typeless-key shape split across two unioned fragments: the
// first fragment carries only the key, the second only the
// activation settings. The union must not launder it into plain.
func TestOSPFKeyWithNoTypeSplitFragments15014(t *testing.T) {
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthKey: "s3cret"},
		{Name: "ge-0/0/1.0", Cost: 10},
	}}}}
	got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") {
		t.Fatalf("split-fragment typeless OSPF key activated unauthenticated:\n%s", got)
	}
	// Control: two plain fragments still union and activate.
	plain := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0"},
		{Name: "ge-0/0/1.0", Cost: 10},
	}}}}
	got = New().generateProtocols(plain, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "interface ge-0/0/1.0\n") || !strings.Contains(got, " ip ospf cost 10\n") || !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
		t.Fatalf("plain split-fragment OSPF control changed:\n%s", got)
	}
}

// --- A12-02 probe legs already withheld by #14977: pinned so the
// typeless-key fix cannot regress them, and so the three named
// probes have a test in this file. ---

// OSPF simple with an unrenderable key renders no activation.
func TestOSPFSimpleUnrenderableKeyNoActivation15014(t *testing.T) {
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: "bad key"},
	}}}}
	got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") {
		t.Fatalf("OSPF simple with unrenderable key activated unauthenticated:\n%s", got)
	}
	// Keyed control byte-identical.
	ospf.Areas[0].Interfaces[0].AuthKey = "s3cret"
	got = New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	for _, w := range []string{"interface ge-0/0/1.0\n", " ip ospf authentication\n", " ip ospf authentication-key s3cret\n", " ip ospf area 0.0.0.0\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("keyed simple control lost %q:\n%s", w, got)
		}
	}
}

// IS-IS area/interface passwords with an unrenderable key, and
// IS-IS keyless type, render no activation; a global failure
// withholds every enrolment.
func TestISISUnrenderableAndKeylessNoActivation15014(t *testing.T) {
	cases := map[string]*config.ISISConfig{
		"area unrenderable": {NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: "bad key",
			Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: "s3cret"}}},
		"area keyless type": {NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5",
			Interfaces: []*config.ISISInterface{{Name: "trust0"}}},
		"iface unrenderable": {NET: "49.0001.0100.0000.0001.00", Level: "level-2",
			Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: "bad key"}}},
		"iface keyless type": {NET: "49.0001.0100.0000.0001.00", Level: "level-2",
			Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5"}}},
	}
	for name, isis := range cases {
		t.Run(name, func(t *testing.T) {
			got := New().generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
			if strings.Contains(got, "ip router isis") || strings.Contains(got, "isis password") {
				t.Fatalf("IS-IS %s activated without a renderable password:\n%s", name, got)
			}
			if strings.HasPrefix(name, "area") && strings.Contains(got, "router isis") {
				t.Fatalf("IS-IS %s still emitted the router stanza:\n%s", name, got)
			}
		})
	}
	// Controls: keyed global+iface byte-identical; plain IS-IS activates.
	keyed := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: "s3cret",
		Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: "s3cret"}}}
	got := New().generateProtocols(nil, nil, nil, nil, keyed, "", 0, nil, nil)
	for _, w := range []string{"router isis xpf\n", " area-password md5 s3cret\n", " domain-password md5 s3cret\n", " ip router isis xpf\n", " isis password md5 s3cret\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("keyed IS-IS control lost %q:\n%s", w, got)
		}
	}
	plain := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2",
		Interfaces: []*config.ISISInterface{{Name: "trust0"}}}
	got = New().generateProtocols(nil, nil, nil, nil, plain, "", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") || !strings.Contains(got, " ip router isis xpf\n") || strings.Contains(got, "password") {
		t.Errorf("plain IS-IS control changed:\n%s", got)
	}
	// Per-interface failure keeps a healthy global + sibling.
	mixed := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: "s3cret",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0", AuthType: "md5", AuthKey: "bad key"},
			{Name: "trust1", AuthType: "md5", AuthKey: "s3cret"},
		}}
	got = New().generateProtocols(nil, nil, nil, nil, mixed, "", 0, nil, nil)
	if !strings.Contains(got, " area-password md5 s3cret\n") || strings.Contains(got, "interface trust0\n") ||
		!strings.Contains(got, "interface trust1\n") || !strings.Contains(got, " isis password md5 s3cret\n") {
		t.Errorf("healthy IS-IS sibling/global changed by bad interface:\n%s", got)
	}
}
