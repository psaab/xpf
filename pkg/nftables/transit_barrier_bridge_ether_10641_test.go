package nftables

import (
	"bytes"
	"sort"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #10641 (residual of #9888): the userspace XDP shim XDP_PASSes single-tag and
// untagged non-IP ethertypes for local-stack delivery (ARP/LLDP must reach the
// local L2 state machine — lib.rs pass_non_ip_l2_direct, above the ingress-set
// test). On a bridge-domain member that PASS also hands the frame to the kernel
// bridge, and the armed bridge-family forward fence admitted ANY such frame
// from a member carrying a tracked XDP link: one unmarked iifname ACCEPT with
// no ethertype qualification, so LLDP/EAPOL/custom ethertypes crossed zone
// boundaries with no policy.
//
// The fence is the kernel-forwarding policy point, so the bridge leg now
// qualifies the unmarked pinhole by ethertype: three ACCEPTs (ip, ip6, arp).
// ARP is the explicit L2-control allowlist the bridge needs to function;
// every other non-IP ethertype reaches the base-chain DROP. Local-stack
// delivery (input path) is untouched. QinQ fails closed here too: the VLAN
// slave strips the outer tag before bridge processing, so a stacked frame
// presents its inner TPID at the forward hook and matches none of the three.
//
// The inet leg is unchanged: inet forward only ever carries IP by
// construction, and the link-layer header is not addressable there at all.

func newBridgeBuildPlan10641(t *testing.T, tableName string) *nlPlan {
	t.Helper()
	c, err := gnft.New()
	if err != nil {
		t.Skipf("nftables.New unavailable (%v)", err)
	}
	tbl := c.AddTable(&gnft.Table{Family: gnft.TableFamilyBridge, Name: tableName})
	return &nlPlan{c: c, table: tbl, chain: transitBarrierChain(tbl)}
}

// bridgeEtherGolden10641 is the fixed emission order and wire bytes of the
// bridge unmarked pinhole. Big-endian (wire order): a LE flip would never
// match a real frame (the #10410 P0 class), so the bytes are pinned
// literally, not via the encoder the implementation uses.
func bridgeEtherGolden10641() ([]uint16, [][]byte) {
	return []uint16{0x0800, 0x86dd, 0x0806},
		[][]byte{{0x08, 0x00}, {0x86, 0xdd}, {0x08, 0x06}}
}

func TestBridgeFenceUnmarkedEtherScoped10641(t *testing.T) {
	p := newBridgeBuildPlan10641(t, "xpf_transit_10641")
	emitTransitFencePinhole(p, ForwardFenceSpec{AllowedIfnames: []string{"xdp-owned0"}})
	if p.err != nil {
		t.Fatalf("bridge pinhole plan failed: %v", p.err)
	}
	wantEther, wantBE := bridgeEtherGolden10641()
	if len(p.rules) != len(wantEther) {
		t.Fatalf("bridge fence emitted %d rules, want %d ether-scoped pinholes (ip, ip6, arp)",
			len(p.rules), len(wantEther))
	}
	for i, rule := range p.rules {
		if len(rule) != 5 {
			t.Fatalf("bridge rule %d: %d exprs, want 5 (iifname meta+cmp, ether payload+cmp, verdict)", i, len(rule))
		}
		if meta, ok := rule[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyIIFNAME {
			t.Fatalf("bridge rule %d first expr = %#v, want iifname meta", i, rule[0])
		}
		if cmp, ok := rule[1].(*expr.Cmp); !ok || cmp.Op != expr.CmpOpEq {
			t.Fatalf("bridge rule %d second expr = %#v, want iifname equality", i, rule[1])
		}
		pay, ok := rule[2].(*expr.Payload)
		if !ok || pay.Base != expr.PayloadBaseLLHeader || pay.Offset != 12 || pay.Len != 2 || pay.DestRegister != 1 {
			t.Fatalf("bridge rule %d third expr = %#v, want LL payload load @12/2 to reg 1", i, rule[2])
		}
		ecmp, ok := rule[3].(*expr.Cmp)
		if !ok || ecmp.Op != expr.CmpOpEq || ecmp.Register != 1 {
			t.Fatalf("bridge rule %d fourth expr = %#v, want ether equality on reg 1", i, rule[3])
		}
		if !bytes.Equal(ecmp.Data, wantBE[i]) {
			t.Fatalf("bridge rule %d ether bytes = %x, want %x (ethertype %#04x)",
				i, ecmp.Data, wantBE[i], wantEther[i])
		}
		if verdict, ok := rule[4].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictAccept {
			t.Fatalf("bridge rule %d verdict = %#v, want ACCEPT", i, rule[4])
		}
	}
}

func TestBridgeFenceUnmarkedMultiNameEtherScoped10641(t *testing.T) {
	p := newBridgeBuildPlan10641(t, "xpf_transit_10641_multi")
	names := []string{"xdp-owned0", "xdp-owned1"}
	emitTransitFencePinhole(p, ForwardFenceSpec{AllowedIfnames: names})
	if p.err != nil {
		t.Fatalf("bridge pinhole plan failed: %v", p.err)
	}
	wantEther, wantBE := bridgeEtherGolden10641()
	if len(p.rules) != len(wantEther) {
		t.Fatalf("bridge fence emitted %d rules, want %d ether-scoped pinholes", len(p.rules), len(wantEther))
	}
	// Each rule carries its own iifname set (the proven single-rule shape,
	// repeated per ethertype — no cross-rule set sharing): three sets, each
	// holding exactly the allowlisted names.
	if len(p.sets) != len(wantEther) {
		t.Fatalf("bridge fence allocated %d anonymous sets, want %d (one iifname set per ether rule)",
			len(p.sets), len(wantEther))
	}
	wantNames := append([]string(nil), names...)
	sort.Strings(wantNames)
	for i, rule := range p.rules {
		if len(rule) != 5 {
			t.Fatalf("bridge rule %d: %d exprs, want 5", i, len(rule))
		}
		lookup, ok := rule[1].(*expr.Lookup)
		if !ok || lookup.SourceRegister != 1 {
			t.Fatalf("bridge rule %d second expr = %#v, want iifname set lookup", i, rule[1])
		}
		els, exists := p.sets[lookup.SetID]
		if !exists {
			t.Fatalf("bridge rule %d references unallocated set id %d", i, lookup.SetID)
		}
		var got []string
		for _, el := range els {
			got = append(got, string(bytes.TrimRight(el.Key, "\x00")))
		}
		sort.Strings(got)
		if len(got) != len(wantNames) || got[0] != wantNames[0] || got[1] != wantNames[1] {
			t.Fatalf("bridge rule %d iifname set = %q, want %q", i, got, wantNames)
		}
		ecmp, ok := rule[3].(*expr.Cmp)
		if !ok || !bytes.Equal(ecmp.Data, wantBE[i]) {
			t.Fatalf("bridge rule %d ether bytes = %x, want %x", i, ecmp.Data, wantBE[i])
		}
	}
}

// TestBridgeFenceDesiredShapeCarriesEther10641 pins the idempotency contract:
// the desired bridge shape is three ether-qualified rules, so a live table
// that lost the qualification (pre-fix shape) reads back UNEQUAL and takes
// the replace path instead of skipping the install.
func TestBridgeFenceDesiredShapeCarriesEther10641(t *testing.T) {
	spec := ForwardFenceSpec{AllowedIfnames: []string{"xdp-owned0"}}
	wantEther, _ := bridgeEtherGolden10641()
	shapes := desiredTransitFenceRuleShapes(spec, gnft.TableFamilyBridge)
	if len(shapes) != len(wantEther) {
		t.Fatalf("desired bridge shapes = %d, want %d", len(shapes), len(wantEther))
	}
	for i, sh := range shapes {
		if !sh.hasEther || sh.ether != wantEther[i] {
			t.Fatalf("desired bridge shape %d = ether %#04x(has=%v), want %#04x",
				i, sh.ether, sh.hasEther, wantEther[i])
		}
	}
	inet := desiredTransitFenceRuleShapes(spec, gnft.TableFamilyINet)
	if len(inet) != 1 || inet[0].hasEther {
		t.Fatalf("desired inet shapes = %+v, want one ether-less rule", inet)
	}
}

// TestBridgeFenceOldShapeReadsUnequal10641 is the revert tripwire at the
// decoder level: a live bridge rule WITHOUT the ether conjunction (the exact
// pre-fix emission) must NOT compare equal to the desired shape.
func TestBridgeFenceOldShapeReadsUnequal10641(t *testing.T) {
	spec := ForwardFenceSpec{AllowedIfnames: []string{"xdp-owned0"}}
	old := &gnft.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname16("xdp-owned0")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	chain := transitBarrierChain(&gnft.Table{Family: gnft.TableFamilyBridge, Name: "xpf_transit_10641"})
	live := transitFenceLiveShape{chain: chain, rules: []*gnft.Rule{old}, sets: map[string][]string{}}
	if forwardFenceLiveShapeEqual(spec, gnft.TableFamilyBridge, live) {
		t.Fatal("pre-fix bridge rule (no ether conjunction) compared EQUAL to the desired shape — " +
			"the armed gate would skip the install and leave the bypass open")
	}
}

// TestBridgeFenceEmittedShapeReadsEqual10641 closes the loop without a
// kernel: what the emitter builds must decode back to the desired shape, so
// a faithful live table takes the skip path (no reinstall churn).
func TestBridgeFenceEmittedShapeReadsEqual10641(t *testing.T) {
	for _, names := range [][]string{{"xdp-owned0"}, {"xdp-owned0", "xdp-owned1"}} {
		spec := ForwardFenceSpec{AllowedIfnames: names}
		p := newBridgeBuildPlan10641(t, "xpf_transit_10641_eq")
		emitTransitFencePinhole(p, spec)
		if p.err != nil {
			t.Fatalf("names %q: plan failed: %v", names, p.err)
		}
		sets := map[string][]string{}
		var rules []*gnft.Rule
		for _, exprs := range p.rules {
			if lookup, ok := exprs[1].(*expr.Lookup); ok {
				var vals []string
				for _, el := range p.sets[lookup.SetID] {
					vals = append(vals, string(bytes.TrimRight(el.Key, "\x00")))
				}
				sets[lookup.SetName] = canonicalFenceNames(vals)
			}
			rules = append(rules, &gnft.Rule{Exprs: exprs})
		}
		chain := transitBarrierChain(&gnft.Table{Family: gnft.TableFamilyBridge, Name: "xpf_transit_10641"})
		live := transitFenceLiveShape{chain: chain, rules: rules, sets: sets}
		if !forwardFenceLiveShapeEqual(spec, gnft.TableFamilyBridge, live) {
			t.Fatalf("names %q: emitted bridge rules do not decode to the desired shape", names)
		}
	}
}

func TestInetFenceUnmarkedUnchanged10641(t *testing.T) {
	p := newBuildPlan(t, "xpf_transit_10641_inet", *gnft.ChainPriorityFilter)
	p.chain = transitBarrierChain(p.table)
	emitTransitFencePinhole(p, ForwardFenceSpec{AllowedIfnames: []string{"xdp-owned0"}})
	if p.err != nil {
		t.Fatalf("inet pinhole plan failed: %v", p.err)
	}
	// Control: the inet leg keeps the exact pre-fix shape — one rule, no
	// link-layer match (inet forward carries IP only, and LL is not
	// addressable in that family).
	if len(p.rules) != 1 {
		t.Fatalf("inet fence emitted %d rules, want 1 (unchanged)", len(p.rules))
	}
	for i, e := range p.rules[0] {
		if _, isPayload := e.(*expr.Payload); isPayload {
			t.Fatalf("inet rule expr %d is a payload match — the inet leg must stay ether-less", i)
		}
	}
}

func TestBridgeFenceMarkedUnchanged10641(t *testing.T) {
	p := newBridgeBuildPlan10641(t, "xpf_transit_10641_mark")
	emitTransitFencePinhole(p, ForwardFenceSpec{
		AllowedMarks: []ForwardFenceMark{{
			Ifname: "xpf-usp1",
			Mark:   AdjudicatedTransitMark,
			Mask:   AdjudicatedTransitMarkMask,
		}},
	})
	if p.err != nil {
		t.Fatalf("marked bridge plan failed: %v", p.err)
	}
	// Control: the marked (xpf-usp1 TUN) bridge rule is unchanged — a TUN
	// can never be a bridge port, so the rule is dead in this family and
	// gains nothing from an ether conjunction.
	if len(p.rules) != 1 {
		t.Fatalf("marked bridge fence emitted %d rules, want 1 (unchanged)", len(p.rules))
	}
	for i, e := range p.rules[0] {
		if _, isPayload := e.(*expr.Payload); isPayload {
			t.Fatalf("marked bridge rule expr %d is a payload match — marked rules stay ether-less", i)
		}
	}
}

func TestBridgeFenceEmptySpecNoRules10641(t *testing.T) {
	p := newBridgeBuildPlan10641(t, "xpf_transit_10641_empty")
	emitTransitFencePinhole(p, ForwardFenceSpec{})
	if p.err != nil {
		t.Fatalf("empty bridge plan failed: %v", p.err)
	}
	if len(p.rules) != 0 {
		t.Fatalf("empty bridge fence emitted %d rules, want none", len(p.rules))
	}
}

// TestArmedBridgeFenceLoadsInKernel10641 proves against the real nf_tables
// subsystem that the ether-scoped bridge rules INSTALL (the kernel validates
// every expr on Flush — a bad base/offset/len is rejected), read back with
// their qualification intact, and satisfy the production live-shape check,
// so the armed gate neither churns nor skips wrongly.
func TestArmedBridgeFenceLoadsInKernel10641(t *testing.T) {
	enterPrivateNetns(t)
	in := newNetlinkInstallerConn(func() (*gnft.Conn, error) { return gnft.New() })
	spec := ForwardFenceSpec{
		AllowedIfnames: []string{"xdp-owned0", "xdp-owned1"},
		AllowedMarks: []ForwardFenceMark{{
			Ifname: "xpf-usp1",
			Mark:   AdjudicatedTransitMark,
			Mask:   AdjudicatedTransitMarkMask,
		}},
	}
	if err := in.InstallArmedTransitFence(spec); err != nil {
		if IsTransitBarrierBridgeUnsupportedOnly(err) {
			t.Skipf("bridge nf_tables unavailable: %v", err)
		}
		t.Fatalf("armed fence install: %v", err)
	}
	defer func() {
		if err := in.RemoveTransitBarrier(); err != nil {
			t.Errorf("remove barrier after cell: %v", err)
		}
	}()

	_, wantBE := bridgeEtherGolden10641()
	assertFenceFamily10641(t, gnft.TableFamilyBridge, 4, wantBE, true)
	assertFenceFamily10641(t, gnft.TableFamilyINet, 2, nil, false)

	// The production live-shape read must accept its own install: a faithful
	// table takes the skip path.
	equal, err := in.readForwardFenceLiveEqual(spec)
	if err != nil {
		t.Fatalf("live-shape read: %v", err)
	}
	if !equal {
		t.Fatal("installed fence does not read back equal to the desired shape — the armed gate would reinstall every tick")
	}

	// A byte-equal reassert must succeed (via skip or replace — either is a
	// correct steady state).
	if err := in.InstallArmedTransitFence(spec); err != nil {
		t.Fatalf("armed fence reassert: %v", err)
	}
}

func assertFenceFamily10641(t *testing.T, family gnft.TableFamily, wantRules int, wantBE [][]byte, wantEther bool) {
	t.Helper()
	conn, err := gnft.New()
	if err != nil {
		t.Fatalf("family %d: open nftables connection: %v", family, err)
	}
	tables, err := conn.ListTablesOfFamily(family)
	if err != nil {
		t.Fatalf("family %d: list tables: %v", family, err)
	}
	var table *gnft.Table
	for _, candidate := range tables {
		if candidate != nil && candidate.Name == TransitBarrierTableName {
			table = candidate
			break
		}
	}
	if table == nil {
		t.Fatalf("family %d: %s table missing after install", family, TransitBarrierTableName)
	}
	chain, err := conn.ListChain(table, "forward")
	if err != nil {
		t.Fatalf("family %d: read forward chain: %v", family, err)
	}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		t.Fatalf("family %d: read rules: %v", family, err)
	}
	if len(rules) != wantRules {
		t.Fatalf("family %d: %d forward rules, want %d", family, len(rules), wantRules)
	}
	seen := map[string]int{}
	unmarked := 0
	for _, rule := range rules {
		marked := false
		for _, e := range rule.Exprs {
			if meta, ok := e.(*expr.Meta); ok && meta.Key == expr.MetaKeyMARK {
				marked = true
			}
		}
		if marked {
			continue
		}
		unmarked++
		var key string
		for i, e := range rule.Exprs {
			pay, ok := e.(*expr.Payload)
			if !ok {
				continue
			}
			if pay.Base != expr.PayloadBaseLLHeader || pay.Offset != 12 || pay.Len != 2 {
				t.Fatalf("family %d: unmarked rule payload = base %d off %d len %d, want LL/12/2",
					family, pay.Base, pay.Offset, pay.Len)
			}
			if i+1 >= len(rule.Exprs) {
				t.Fatalf("family %d: unmarked rule ends right after the ether load", family)
			}
			ecmp, ok := rule.Exprs[i+1].(*expr.Cmp)
			if !ok || ecmp.Op != expr.CmpOpEq {
				t.Fatalf("family %d: unmarked rule ether load not followed by equality", family)
			}
			key = string(ecmp.Data)
		}
		if wantEther && key == "" {
			t.Fatalf("family %d: unmarked rule has no ether conjunction", family)
		}
		if !wantEther && key != "" {
			t.Fatalf("family %d: unmarked rule unexpectedly carries an ether conjunction", family)
		}
		if key != "" {
			seen[key]++
		}
	}
	if wantEther {
		if unmarked != len(wantBE) {
			t.Fatalf("family %d: %d unmarked rules, want %d", family, unmarked, len(wantBE))
		}
		for _, be := range wantBE {
			if seen[string(be)] != 1 {
				t.Fatalf("family %d: ether %x seen %d times, want exactly once (seen=%v)",
					family, be, seen[string(be)], seen)
			}
		}
	}
}
