package nftables

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestEarlyInputBarrierPlanClosesHostServicesAndPreservesControl10751(t *testing.T) {
	p := newBuildPlan(t, EarlyInputBarrierTableName, gnft.ChainPriority(earlyInputBarrierPriority))
	chain := earlyInputBarrierChain(p.table)
	if chain.Hooknum != gnft.ChainHookInput || chain.Type != gnft.ChainTypeFilter {
		t.Fatalf("early input barrier chain = hook %v type %v, want filter/input", chain.Hooknum, chain.Type)
	}
	if chain.Priority == nil || *chain.Priority != gnft.ChainPriority(earlyInputBarrierPriority) {
		t.Fatalf("early input barrier priority = %v, want %d", chain.Priority, earlyInputBarrierPriority)
	}
	if chain.Policy == nil || *chain.Policy != gnft.ChainPolicyDrop {
		t.Fatalf("early input barrier policy = %v, want DROP", chain.Policy)
	}
	p.chain = chain
	emitEarlyInputBarrierAdmits(p)
	if p.err != nil {
		t.Fatalf("build early input barrier: %v", p.err)
	}
	if len(p.rules) != 9 {
		t.Fatalf("early input barrier rule count = %d, want loopback + five mandatory L3 + three routing/HA admits", len(p.rules))
	}

	loopback := p.rules[0]
	if len(loopback) != 3 {
		t.Fatalf("loopback rule has %d expressions, want iifname + compare + ACCEPT", len(loopback))
	}
	meta, ok := loopback[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("loopback first expression = %#v, want iifname", loopback[0])
	}
	cmp, ok := loopback[1].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || !bytes.Equal(cmp.Data, ifname16("lo")) {
		t.Fatalf("loopback interface comparison = %#v, want lo", loopback[1])
	}
	assertInputBarrierAccepts10751(t, loopback)

	for i, rule := range p.rules {
		assertInputBarrierAccepts10751(t, rule)
		if i == 0 {
			continue
		}
		for _, e := range rule {
			if verdict, ok := e.(*expr.Verdict); ok && verdict.Kind == expr.VerdictDrop {
				t.Fatalf("barrier rule %d contains explicit DROP; only policy DROP closes the tail", i)
			}
		}
	}

	if got := inputBarrierLookupSet10751(t, p, p.rules[6]); !reflect.DeepEqual(got, [][]byte{{89}, {112}}) {
		t.Fatalf("routing protocol set = %v, want OSPF(89) + VRRP(112)", got)
	}
	tcpPorts := inputBarrierLookupPorts10751(t, p, p.rules[7])
	if !reflect.DeepEqual(tcpPorts, []uint16{4785}) {
		t.Fatalf("early TCP admits = %v, want only HA session-sync 4785 (SSH 22 and BGP 179 must remain blocked)", tcpPorts)
	}
	for _, blocked := range []uint16{22, 179} {
		for _, admitted := range tcpPorts {
			if admitted == blocked {
				t.Errorf("early TCP barrier admits exposed service port %d", blocked)
			}
		}
	}
	udpPorts := inputBarrierLookupPorts10751(t, p, p.rules[8])
	if !reflect.DeepEqual(udpPorts, []uint16{520, 521, 3784, 3785, 4784}) {
		t.Fatalf("early UDP admits = %v, want RIP/RIPng, BFD, HA heartbeat only", udpPorts)
	}
	for _, blocked := range []uint16{500, 4500} {
		for _, admitted := range udpPorts {
			if admitted == blocked {
				t.Errorf("early UDP barrier admits exposed IKE service port %d", blocked)
			}
		}
	}
}

func assertInputBarrierAccepts10751(t *testing.T, rule []expr.Any) {
	t.Helper()
	if len(rule) == 0 {
		t.Fatal("empty early input barrier rule")
	}
	verdict, ok := rule[len(rule)-1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("early input rule terminal expression = %#v, want ACCEPT", rule[len(rule)-1])
	}
}

func inputBarrierLookupSet10751(t *testing.T, p *nlPlan, rule []expr.Any) [][]byte {
	t.Helper()
	for _, e := range rule {
		lookup, ok := e.(*expr.Lookup)
		if !ok {
			continue
		}
		elements, ok := p.sets[lookup.SetID]
		if !ok {
			t.Fatalf("rule references unrecorded nft set %d", lookup.SetID)
		}
		out := make([][]byte, len(elements))
		for i := range elements {
			out[i] = elements[i].Key
		}
		return out
	}
	t.Fatalf("rule has no lookup set: %#v", rule)
	return nil
}

func inputBarrierLookupPorts10751(t *testing.T, p *nlPlan, rule []expr.Any) []uint16 {
	t.Helper()
	for i, e := range rule {
		payload, ok := e.(*expr.Payload)
		if !ok || payload.Base != expr.PayloadBaseTransportHeader || payload.Offset != 2 || payload.Len != 2 {
			continue
		}
		if i+1 >= len(rule) {
			continue
		}
		var keys [][]byte
		switch match := rule[i+1].(type) {
		case *expr.Cmp:
			keys = [][]byte{match.Data}
		case *expr.Lookup:
			elements, ok := p.sets[match.SetID]
			if !ok {
				t.Fatalf("port rule references unrecorded nft set %d", match.SetID)
			}
			keys = make([][]byte, len(elements))
			for j := range elements {
				keys[j] = elements[j].Key
			}
		default:
			continue
		}
		out := make([]uint16, len(keys))
		for j, key := range keys {
			if len(key) != 2 {
				t.Fatalf("port match key = %x, want 2 bytes", key)
			}
			out[j] = binary.BigEndian.Uint16(key)
		}
		return out
	}
	t.Fatalf("rule has no transport-header destination-port match: %#v", rule)
	return nil
}

func TestEarlyInputBarrierNetlinkLifecycle10751(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if err := in.InstallEarlyInputBarrier(); err != nil {
		t.Fatalf("install early input barrier: %v", err)
	}
	assertEarlyInputBarrierInstalled10751(t)
	if err := in.InstallEarlyInputBarrier(); err != nil {
		t.Fatalf("replace early input barrier: %v", err)
	}
	assertEarlyInputBarrierInstalled10751(t)
	if err := in.RemoveEarlyInputBarrier(); err != nil {
		t.Fatalf("remove early input barrier: %v", err)
	}
	if err := in.RemoveEarlyInputBarrier(); err != nil {
		t.Fatalf("remove absent early input barrier: %v", err)
	}
	c, err := gnft.New()
	if err != nil {
		t.Fatalf("open netlink after remove: %v", err)
	}
	exists, err := tableExists(c, EarlyInputBarrierTableName)
	if err != nil {
		t.Fatalf("check removed table: %v", err)
	}
	if exists {
		t.Fatal("early input barrier table remains after idempotent removal")
	}
}

func assertEarlyInputBarrierInstalled10751(t *testing.T) {
	t.Helper()
	c, err := gnft.New()
	if err != nil {
		t.Fatalf("open nftables netlink: %v", err)
	}
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: EarlyInputBarrierTableName}
	chains, err := c.ListChainsOfTableFamily(gnft.TableFamilyINet)
	if err != nil {
		t.Fatalf("list inet chains: %v", err)
	}
	var found *gnft.Chain
	for _, chain := range chains {
		if chain != nil && chain.Table != nil && chain.Table.Name == EarlyInputBarrierTableName && chain.Name == "input" {
			found = chain
			break
		}
	}
	if found == nil {
		t.Fatalf("inet %s input chain is absent", EarlyInputBarrierTableName)
	}
	if found.Hooknum == nil || *found.Hooknum != *gnft.ChainHookInput ||
		found.Type != gnft.ChainTypeFilter || found.Priority == nil ||
		*found.Priority != gnft.ChainPriority(earlyInputBarrierPriority) ||
		found.Policy == nil || *found.Policy != gnft.ChainPolicyDrop {
		t.Fatalf("installed early input chain shape = %+v, want filter/input priority %d policy DROP", found, earlyInputBarrierPriority)
	}
	rules, err := c.GetRules(tbl, found)
	if err != nil {
		t.Fatalf("read early input barrier rules: %v", err)
	}
	if len(rules) != 9 {
		t.Fatalf("installed early input barrier has %d rules, want 9", len(rules))
	}
}
