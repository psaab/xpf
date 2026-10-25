package nftables

import (
	"errors"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #16618: a QuarantineAll guard built from a normal (non-quarantine) spec
// must inherit the caller's LifelineNetdevs. Before the fix,
// normalizeIpsecQuarantineSpec cleared lifelines on the normal spec
// before InstallIpsecDivertWithDrain / installNormalUnderQuarantineGuard
// copied them into the guard, so a retained guard rendered {lo, DROP}
// and blackholed fxp0 input. The bridge input chain must additionally
// carry no sdifname rule (#16703 EOPNOTSUPP).

func normalDivertSpec16618() IpsecDivertSpec {
	return IpsecDivertSpec{
		InetForward:     []IpsecDivertRule{{Ifname: "st0", Queue: 1001}},
		InetInput:       []IpsecDivertRule{{Ifname: "st0", Queue: 1002}},
		BridgeForward:   []IpsecDivertRule{{Ifname: "st0", Queue: 1003}},
		BridgeInput:     []IpsecDivertRule{{Ifname: "st0", Queue: 1004}},
		LifelineNetdevs: []string{"fxp0"},
	}
}

func assertGuardInputAdmitsFxp016618(t *testing.T, family string) {
	t.Helper()
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 7,
		LifelineNetdevs:      []string{"fxp0"},
	})
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecQuarantineTableName}
	if family == "bridge" {
		tbl.Family = gnft.TableFamilyBridge
	}
	p := newBuildPlan(t, IpsecQuarantineTableName, IpsecQuarantinePriority)
	p.chain = ipsecDenyChain(tbl, "input", gnft.ChainHookInput, IpsecQuarantinePriority)
	emitIpsecQuarantineRules(p, family, "input", spec, false)
	if p.err != nil {
		t.Fatalf("%s render: %v", family, p.err)
	}
	// iifname fxp0 accept must be present (rule 1, after lo).
	assertIpsecQuarantineLifelineAccept14696(t, p.rules[1], []string{"fxp0"})
	if family == "bridge" {
		for i, rule := range p.rules {
			for _, e := range rule {
				if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKey(metaKeySDIFNAME) {
					t.Fatalf("bridge rule %d carries sdifname: %#v", i, rule)
				}
			}
		}
	}
}

func TestIpsecGuardFromNormalSpecCarriesLifelines16618(t *testing.T) {
	// The exact installer order: normalize the normal spec first, then
	// build the guard from it (InstallIpsecDivertWithDrain:519-537).
	spec := normalizeIpsecQuarantineSpec(normalDivertSpec16618())
	if spec.QuarantineAll {
		t.Fatalf("normal spec quarantined: %+v", spec)
	}
	guard := IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: spec.QuarantineGeneration,
		LifelineNetdevs:      append([]string(nil), spec.LifelineNetdevs...),
	}
	guard = normalizeIpsecQuarantineSpec(guard)
	if len(guard.LifelineNetdevs) != 1 || guard.LifelineNetdevs[0] != "fxp0" {
		t.Fatalf("guard lifelines = %v, want [fxp0] inherited from normal spec", guard.LifelineNetdevs)
	}
	assertGuardInputAdmitsFxp016618(t, "inet")
	assertGuardInputAdmitsFxp016618(t, "bridge")
}

// Kernel cell (acceptance): install a lifeline-carrying quarantine guard
// through the real netlink installer in a private netns. Pre-fix this
// failed on bridge with EOPNOTSUPP (sdifname) and, for guards built from
// normal specs, installed with no lifelines at all. Skips without
// CAP_NET_ADMIN (see enterPrivateNetns).
func TestIpsecQuarantineGuardWithLifelinesLoadsInKernel16618(t *testing.T) {
	enterPrivateNetns(t)
	in, ok := NewNetlinkInstaller().(*netlinkInstaller)
	if !ok {
		t.Fatal("NewNetlinkInstaller is not *netlinkInstaller")
	}
	spec := IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 7,
		LifelineNetdevs:      []string{"fxp0"},
	}
	if err := in.InstallIpsecQuarantineGuard(spec); err != nil {
		t.Fatalf("InstallIpsecQuarantineGuard with lifelines: %v", err)
	}
	if err := in.InstallIpsecDivert(spec); err != nil {
		t.Fatalf("InstallIpsecDivert quarantine with lifelines: %v", err)
	}
	// Guarded transition: seed a normal divert, then fail the drain; the
	// retained guard must be the lifeline-carrying one. Install the
	// normal generation first via the unguarded path.
	normal := normalDivertSpec16618()
	if err := in.InstallIpsecDivert(normal); err != nil {
		t.Fatalf("seed normal divert: %v", err)
	}
	drainErr := errors.New("injected old.close failure")
	if err := in.InstallIpsecDivertWithDrain(normal, func() error { return drainErr }); !errors.Is(err, drainErr) {
		t.Fatalf("guarded transition err = %v, want drain failure", err)
	}
	present, err := in.ipsecTableBothFamiliesPresent(IpsecQuarantineTableName)
	if err != nil {
		t.Fatalf("guard presence readback: %v", err)
	}
	if !present {
		t.Fatal("retained guard missing after failed guarded transition")
	}
	// The retained inet guard input chain must contain an fxp0 accept.
	rules := readChainRules16618(t, in, gnft.TableFamilyINet, IpsecQuarantineTableName, "input")
	if !rulesContainIfnameAccept16618(rules, "fxp0") {
		t.Fatalf("retained inet guard input rules lack fxp0 iifname ACCEPT: %v rules", len(rules))
	}
	bridgeRules := readChainRules16618(t, in, gnft.TableFamilyBridge, IpsecQuarantineTableName, "input")
	if rulesContainSdifname16618(bridgeRules) {
		t.Fatal("retained bridge guard input carries sdifname (kernel rejects it)")
	}
	if !rulesContainIfnameAccept16618(bridgeRules, "fxp0") {
		t.Fatal("retained bridge guard input lacks fxp0 iifname ACCEPT")
	}
}

func readChainRules16618(t *testing.T, in *netlinkInstaller, family gnft.TableFamily, table, chain string) [][]expr.Any {
	t.Helper()
	c, err := in.newConn()
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	tbl := &gnft.Table{Family: family, Name: table}
	ch := &gnft.Chain{Name: chain, Table: tbl}
	rules, err := c.GetRules(tbl, ch)
	if err != nil {
		t.Fatalf("GetRules %v %s/%s: %v", family, table, chain, err)
	}
	out := make([][]expr.Any, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Exprs)
	}
	return out
}

func rulesContainIfnameAccept16618(rules [][]expr.Any, name string) bool {
	want := ifname16(name)
	for _, rule := range rules {
		hasIfname, accept := false, false
		for _, e := range rule {
			switch x := e.(type) {
			case *expr.Meta:
				if x.Key == expr.MetaKeyIIFNAME {
					hasIfname = true
				}
			case *expr.Cmp:
				_ = x
			case *expr.Verdict:
				if x.Kind == expr.VerdictAccept {
					accept = true
				}
			}
		}
		if !hasIfname || !accept {
			continue
		}
		// Confirm the rule matches the wanted name (Cmp data or set).
		for _, e := range rule {
			if cmp, ok := e.(*expr.Cmp); ok && len(cmp.Data) == len(want) {
				match := true
				for i := range want {
					if cmp.Data[i] != want[i] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}
	return false
}

func rulesContainSdifname16618(rules [][]expr.Any) bool {
	for _, rule := range rules {
		for _, e := range rule {
			if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKey(metaKeySDIFNAME) {
				return true
			}
		}
	}
	return false
}
