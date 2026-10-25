package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16867 render belt: the commit gate (ValidateFRRPrefixListName) runs on
// commit/commit-check only, so a prefix-list name over FRR's 128-byte YANG
// `list-name` bound persisted or peer-synced before the gate existed still
// reaches this renderer. Rendering it unchanged puts the overlong name
// into `ip prefix-list <name>` and `match ... prefix-list <name>`; FRR
// rejects the leaf with "Unsatisfied length", leaves a half-built
// match-condition node, and the next `show running-config` SIGABRTs the
// routing daemons. frrName must therefore alias an overlong name (any
// class — the belt cannot tell which YANG leaf a name will land in) to a
// deterministic bounded token, with definition and reference agreeing.
//
// FAIL-ON-REVERT: restoring `if config.FRRSingleToken(name) { return name }`
// returns the 137-byte name unchanged and every bound assertion below reds.

func TestFRRNameOverlongAlias16867(t *testing.T) {
	long := strings.Repeat("a", 137)
	got := frrName(long)
	if got == long {
		t.Fatalf("frrName returned the %d-byte name unchanged; FRR would reject it (#16867)", len(long))
	}
	if len(got) > config.FRRNameMaxLen {
		t.Errorf("alias %q is %d bytes, over FRR's %d-byte limit", got, len(got), config.FRRNameMaxLen)
	}
	if !config.FRRSingleToken(got) {
		t.Errorf("alias %q is not one FRR token", got)
	}
	if got != frrName(long) {
		t.Errorf("alias is not deterministic: %q vs %q", got, frrName(long))
	}
	// Two distinct long names sharing the truncated fragment must stay
	// apart — the hash of the FULL name is what separates them.
	other := strings.Repeat("a", 137) + "b"
	if frrName(other) == got {
		t.Errorf("two distinct long names collapsed to one alias %q", got)
	}
	// Multibyte input: the alias is pure ASCII (sanitizeFRRIdent), so the
	// byte bound can never split a rune.
	multi := strings.Repeat("é", 100) // 200 bytes
	if a := frrName(multi); len(a) > config.FRRNameMaxLen {
		t.Errorf("multibyte alias is %d bytes, over the bound: %q", len(a), a)
	}
}

// Boundary controls: a name at exactly 128 bytes is carried unchanged
// (byte-identical renders), and the pre-existing short/unsafe behaviour
// is untouched.
func TestFRRNameBoundaryUnchanged16867(t *testing.T) {
	at := strings.Repeat("a", config.FRRNameMaxLen)
	if got := frrName(at); got != at {
		t.Errorf("a %d-byte name at FRR's limit must render byte-identically, got %q", config.FRRNameMaxLen, got)
	}
	if got := frrName("EXPORT"); got != "EXPORT" {
		t.Errorf("a short safe name must render byte-identically, got %q", got)
	}
	// One byte over takes the alias.
	over := strings.Repeat("a", config.FRRNameMaxLen+1)
	if got := frrName(over); got == over || len(got) > config.FRRNameMaxLen {
		t.Errorf("a %d-byte name must alias within the bound, got %q (%d bytes)", config.FRRNameMaxLen+1, got, len(got))
	}
}

// Render-level cell (the source report's l1 shape, on the tolerant path):
// a persisted 137-byte prefix-list name referenced by a policy term must
// render with NO token over 128 bytes anywhere, and the prefix-list
// definition and its route-map reference must name the same alias.
func TestLongPrefixListRenderBoundedAndResolves16867(t *testing.T) {
	longPL := strings.Repeat("a", 137)
	cmds := []string{
		`set policy-options prefix-list "` + longPL + `" 10.0.0.0/8`,
		`set policy-options policy-statement EXPORT term t1 from prefix-list "` + longPL + `"`,
		`set policy-options policy-statement EXPORT term t1 then accept`,
		"set protocols bgp group g1 type external",
		"set protocols bgp group g1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.2 export EXPORT",
	}
	tree := &config.ConfigTree{}
	for _, c := range cmds {
		path, err := config.ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile (persisted-config path) must stay tolerant: %v", err)
	}
	m := New()
	fc := &FullConfig{BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions}
	out := m.buildManagedSection(fc)

	alias := frrName(longPL)
	if len(alias) > config.FRRNameMaxLen {
		t.Fatalf("alias %q exceeds the bound", alias)
	}
	// No whitespace-delimited token in the whole managed section may
	// exceed FRR's 128-byte list-name bound.
	for _, tok := range strings.Fields(out) {
		if len(tok) > config.FRRNameMaxLen {
			t.Errorf("rendered token of %d bytes exceeds FRR's %d-byte limit: %.40q...", len(tok), config.FRRNameMaxLen, tok)
		}
	}
	// Definition and reference agree on the alias.
	if !strings.Contains(out, "ip prefix-list "+alias+" seq ") {
		t.Errorf("prefix-list definition does not use the bounded alias %q:\n%s", alias, out)
	}
	if !strings.Contains(out, "match ip address prefix-list "+alias+"\n") &&
		!strings.Contains(out, "match ip address "+alias+"\n") {
		t.Errorf("route-map reference does not use the bounded alias %q:\n%s", alias, out)
	}
	if strings.Contains(out, longPL) {
		t.Errorf("the raw 137-byte name reached frr.conf:\n%s", out)
	}
}

// Kimi gate (PR #17819): frrName is not injective against operator names
// — an overlong raw name L and the literal A = frrName(L) both render as
// A. On the tolerant path (both already persisted / peer-synced) the
// render belt must fail the apply CLOSED (frrNameAliasCollision, wired
// into ApplyFull) rather than let FRR merge the two distinct objects.
//
// FAIL-ON-REVERT: removing the frrNameAliasCollision call from ApplyFull
// (or the gate itself) lets the L/A pair render fused below.
func TestFRRNameAliasCollisionFailsClosed16867(t *testing.T) {
	long := strings.Repeat("a", 137)
	alias := frrName(long)
	if alias == long {
		t.Fatalf("fixture: frrName(%d-byte name) returned it unchanged", len(long))
	}
	mkPO := func(pls map[string]*config.PrefixList) *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{PrefixLists: pls}
	}
	// The defect pair: overlong L + literal alias A, distinct prefixes.
	pair := mkPO(map[string]*config.PrefixList{
		long:  {Name: long, Prefixes: []string{"10.0.0.0/8"}},
		alias: {Name: alias, Prefixes: []string{"192.168.0.0/16"}},
	})
	if err := frrNameAliasCollision(pair); err == nil {
		t.Fatal("the L/A pair passed the render belt — the two prefix-lists would render " +
			"as one FRR list and silently merge (#16867)")
	} else if !strings.Contains(err.Error(), "#16867") || !strings.Contains(err.Error(), alias) {
		t.Errorf("belt rejection must name the fused FRR name and #16867: %v", err)
	}
	// Same collision in the route-map class (policy-statements).
	psPair := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		long:  {Name: long},
		alias: {Name: alias},
	}}
	if err := frrNameAliasCollision(psPair); err == nil {
		t.Error("the L/A policy-statement pair passed the render belt")
	}
	// Whitespace-source pair: raw "A B" aliases onto a forged literal.
	wsAlias := frrName("A B")
	wsPair := &config.PolicyOptionsConfig{Communities: map[string]*config.CommunityDef{
		"A B":   {Name: "A B", Members: []string{"65000:1"}},
		wsAlias: {Name: wsAlias, Members: []string{"65000:2"}},
	}}
	if err := frrNameAliasCollision(wsPair); err == nil {
		t.Error("the whitespace L/A community pair passed the render belt")
	}
	// Controls: L alone, A alone, distinct names, and the same raw name
	// in DIFFERENT classes (per-class FRR namespaces) are clean.
	if err := frrNameAliasCollision(mkPO(map[string]*config.PrefixList{
		long: {Name: long, Prefixes: []string{"10.0.0.0/8"}},
	})); err != nil {
		t.Errorf("L alone must be clean: %v", err)
	}
	if err := frrNameAliasCollision(mkPO(map[string]*config.PrefixList{
		alias: {Name: alias, Prefixes: []string{"192.168.0.0/16"}},
	})); err != nil {
		t.Errorf("A alone must be clean at render (the belt only refuses PAIRS): %v", err)
	}
	crossClass := &config.PolicyOptionsConfig{
		PrefixLists:      map[string]*config.PrefixList{long: {Name: long}},
		PolicyStatements: map[string]*config.PolicyStatement{alias: {Name: alias}},
	}
	if err := frrNameAliasCollision(crossClass); err != nil {
		t.Errorf("same final name in different FRR classes must be clean: %v", err)
	}
	if err := frrNameAliasCollision(nil); err != nil {
		t.Errorf("nil must be clean: %v", err)
	}
}

// Alias fixed-point and shape properties, shared by frrName and the
// pkg/config mirror (frrNameAlias16867): every alias carries the reserved
// marker, stays within the bound, and aliasing an alias is a no-op — so
// the strict pair gate and the render belt judge the same pairs.
func TestFRRNameAliasProperties16867(t *testing.T) {
	for _, raw := range []string{
		"EXPORT",
		strings.Repeat("a", config.FRRNameMaxLen),
		strings.Repeat("a", config.FRRNameMaxLen+1),
		strings.Repeat("a", 137),
		strings.Repeat("a", 300),
		"A B",
		"x\nrouter bgp 65000",
		"",
		strings.Repeat("é", 100),
	} {
		got := frrName(raw)
		if len(got) > config.FRRNameMaxLen {
			t.Errorf("frrName(%q) = %q exceeds the bound", raw, got)
		}
		if got != raw && !strings.Contains(got, config.FRRNameEscapeMarker) {
			t.Errorf("frrName(%q) = %q is an alias without the reserved marker", raw, got)
		}
		if again := frrName(got); again != got {
			t.Errorf("alias %q is not a fixed point: frrName gives %q", got, again)
		}
	}
}

// Gate fold (PR #17819): an OVERLONG composed chain name aliases at
// render (final identity frrName(composed)), so bgpComposedChainCollision
// must compare in that final space. A chain of two legal policies whose
// joined name exceeds 128 bytes, beside an operator policy-statement
// literally spelling the chain's alias, must fail closed — a raw-name
// comparison would miss it and FRR would merge the two route-maps.
//
// FAIL-ON-REVERT: restoring the raw `PolicyStatements[name]` lookup (and
// raw seen-key) in bgpComposedChainCollision lets this pair through.
func TestComposedChainAliasCollision16867(t *testing.T) {
	memberA := strings.Repeat("a", 70)
	memberB := strings.Repeat("b", 70)
	chain := []string{memberA, memberB}
	composed := composedChainName(chain) // 70 + 1 + 70 + len("-xpf-chain") = 151 bytes
	if len(composed) <= config.FRRNameMaxLen {
		t.Fatalf("fixture: composed name must be overlong, got %d bytes", len(composed))
	}
	alias := frrName(composed)
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		memberA: {Name: memberA, Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		memberB: {Name: memberB, Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		alias:   {Name: alias, Terms: []*config.PolicyTerm{{Name: "t", Action: "reject"}}},
	}}
	bgp := &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{
		{Address: "10.0.0.2", PeerAS: 65001, Export: chain},
	}}
	fc := &FullConfig{BGP: bgp, PolicyOptions: po}
	if err := bgpComposedChainCollision(fc); err == nil {
		t.Fatal("an overlong composed chain whose alias is literally spelled by an operator " +
			"policy-statement passed — FRR would merge the composed route-map with the " +
			"operator's (#16867)")
	}
	// Control: without the alias-spelling policy, the same chain is clean.
	poClean := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		memberA: {Name: memberA, Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		memberB: {Name: memberB, Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
	}}
	if err := bgpComposedChainCollision(&FullConfig{BGP: bgp, PolicyOptions: poClean}); err != nil {
		t.Errorf("control: overlong composed chain alone must be clean, got: %v", err)
	}
}

// F1 (Gate4 Opus): frrName and the pkg/config mirror frrNameAlias16867
// must agree on EVERY input, or the strict pair gate and the render belt
// judge different pairs. pkg/config cannot import pkg/frr, so the mirror
// is duplicated; this test is the pin the compiler_validate comment
// cites — it runs the renderer's frrName against the mirror (exposed
// via config.FRRNameAlias16867ForTest) over the full fixture space.
func TestFRRNameAliasParity16867(t *testing.T) {
	fixtures := []string{
		"EXPORT", "export-v4", "p.1", "a_b", "",
		"A B", "a\tb", "x\nrouter bgp 65000", "a b c",
		strings.Repeat("a", config.FRRNameMaxLen-1),
		strings.Repeat("a", config.FRRNameMaxLen),
		strings.Repeat("a", config.FRRNameMaxLen+1),
		strings.Repeat("a", 137),
		strings.Repeat("a", 300),
		strings.Repeat("Z9_", 90),
		strings.Repeat("é", 64),  // exactly 128 bytes, multibyte
		strings.Repeat("é", 100), // 200 bytes
		"PL-xpfesc-deadbeef",     // literal forged alias (fixed point)
		"name with-dash_and.dot",
	}
	for _, raw := range fixtures {
		got, mirror := frrName(raw), config.FRRNameAlias16867ForTest(raw)
		if got != mirror {
			t.Errorf("parity: frrName(%q) = %q, config mirror = %q — the strict gate and render belt disagree", raw, got, mirror)
		}
	}
}

// F2 (Gate4 Opus): the ApplyFull-level refusal. The belt test above calls
// frrNameAliasCollision directly; this cell drives the REAL ApplyFull
// path (fake executor, temp frr.conf): install a last-good config, then
// apply the persisted L/A prefix-list pair — ApplyFull must refuse with
// the #16867 error and leave the on-disk last-good section byte-identical
// (FRR keeps its last-good config).
//
// FAIL-ON-REVERT: deleting the frrNameAliasCollision call from ApplyFull
// makes this apply succeed (and rewrites frr.conf) while the direct belt
// test above stays green — that gap is what this cell closes.
func TestApplyFullRefusesAliasPair16867(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	lastGood := &FullConfig{BGP: &config.BGPConfig{
		LocalAS:   64512,
		Neighbors: []*config.BGPNeighbor{{Address: "198.51.100.1", PeerAS: 64513, FamilyInet: true}},
	}}
	if err := m.ApplyFull(lastGood); err != nil {
		t.Fatalf("ApplyFull(last-good): %v", err)
	}
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}

	long := strings.Repeat("a", 137)
	alias := frrName(long)
	fc := &FullConfig{
		BGP: lastGood.BGP,
		PolicyOptions: &config.PolicyOptionsConfig{PrefixLists: map[string]*config.PrefixList{
			long:  {Name: long, Prefixes: []string{"10.0.0.0/8"}},
			alias: {Name: alias, Prefixes: []string{"192.168.0.0/16"}},
		}},
	}
	err = m.ApplyFull(fc)
	if err == nil || !strings.Contains(err.Error(), "#16867") || !strings.Contains(err.Error(), alias) {
		t.Fatalf("ApplyFull accepted the persisted L/A alias pair; want a fail-closed #16867 refusal naming %q, got %v", alias, err)
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("refused apply rewrote frr.conf — FRR must keep its last-good config:\n got %q\nwant %q", after, before)
	}
	// Control: L alone applies clean through the same path.
	fcOK := &FullConfig{
		BGP: lastGood.BGP,
		PolicyOptions: &config.PolicyOptionsConfig{PrefixLists: map[string]*config.PrefixList{
			long: {Name: long, Prefixes: []string{"10.0.0.0/8"}},
		}},
	}
	if err := m.ApplyFull(fcOK); err != nil {
		t.Fatalf("control: overlong prefix-list alone must apply (aliased), got: %v", err)
	}
}

// Gate5 Astra F1 witness (deterministic, computed in the gate report):
// the bounded alias ERASES generated-family suffix separation. With
// X = "a"x113: P = X+"R133605" (redist raw P+"-static-xpf-redist", 138
// bytes) and C = X+"C6471" with B="B" (composed raw C+"-B-xpf-chain",
// 130 bytes) share the 112-byte fragment AND the 4-byte hash b3656692,
// so both render as the identical 128-byte final name. No per-family
// guard compares composed-BGP finals against redist finals. The
// cross-family belt (emittedRouteMapFinalCollision16867, wired into
// ApplyFull) must refuse the exact witness through REAL ApplyFull —
// before any write or reload — and a neighboring non-colliding control
// must apply.
//
// FAIL-ON-REVERT: removing emittedRouteMapFinalCollision16867 (or its
// ApplyFull call) lets the witness apply fused.
func witnessNames16867() (pName, cName, bName, final string) {
	x := strings.Repeat("a", 113)
	return x + "R133605", x + "C6471", "B",
		strings.Repeat("a", 112) + "-xpfesc-b3656692"
}

func witnessFC16867(pName, cName, bName string, collide bool) *FullConfig {
	cMember := cName
	if !collide {
		cMember = "CCTRL" // short, non-colliding chain member
	}
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		pName: {Name: pName, Terms: []*config.PolicyTerm{
			{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"},
		}},
		cMember: {Name: cMember, Terms: []*config.PolicyTerm{{Name: "t1", Action: "reject"}}},
		bName:   {Name: bName, Terms: []*config.PolicyTerm{{Name: "t1", Action: "reject"}}},
	}}
	bgp := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, FamilyInet: true, Import: []string{cMember, bName}},
		},
		Export: []string{pName},
	}
	return &FullConfig{BGP: bgp, PolicyOptions: po}
}

func TestApplyFullRefusesCrossFamilyAliasWitness16867(t *testing.T) {
	pName, cName, bName, final := witnessNames16867()
	// Fixture sanity: the two raw generated names really do alias to
	// the witness final (guards against a vacuous fixture).
	if got := frrName(pName + "-static-xpf-redist"); got != final {
		t.Fatalf("redist raw aliases to %q, want witness %q", got, final)
	}
	if got := frrName(cName + "-B-xpf-chain"); got != final {
		t.Fatalf("composed raw aliases to %q, want witness %q", got, final)
	}

	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{}
	m := &Manager{frrConf: confPath, exec: exec}
	lastGood := &FullConfig{BGP: &config.BGPConfig{
		LocalAS:   64512,
		Neighbors: []*config.BGPNeighbor{{Address: "198.51.100.1", PeerAS: 64513, FamilyInet: true}},
	}}
	if err := m.ApplyFull(lastGood); err != nil {
		t.Fatalf("ApplyFull(last-good): %v", err)
	}
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	reloadsBefore := exec.frrReloadPyCalls

	err = m.ApplyFull(witnessFC16867(pName, cName, bName, true))
	if err == nil || !strings.Contains(err.Error(), "#16867") || !strings.Contains(err.Error(), final) {
		t.Fatalf("ApplyFull accepted the cross-family alias witness; want a fail-closed #16867 refusal naming %q, got %v", final, err)
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("refused witness rewrote frr.conf:\n got %q\nwant %q", after, before)
	}
	if exec.frrReloadPyCalls != reloadsBefore {
		t.Fatalf("refused witness triggered a reload (reloads %d -> %d); refusal must precede write/reload", reloadsBefore, exec.frrReloadPyCalls)
	}

	// Neighboring non-colliding control: same shape, chain member
	// renamed off the colliding fragment — must apply successfully.
	if err := m.ApplyFull(witnessFC16867(pName, cName, bName, false)); err != nil {
		t.Fatalf("control: non-colliding neighbor config must apply, got: %v", err)
	}
}
