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
	if len(p.rules) != 7 {
		t.Fatalf("early input barrier rule count = %d, want loopback + five mandatory L3 + DHCP-client admits", len(p.rules))
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

	// B5: pin the complete admit surface. The only transport dports in the
	// chain are DHCP-client 68/546 over UDP; no TCP dport rule exists at
	// all; the only l4proto set is ESP/AH {50,51}; every exposed service
	// port stays blocked.
	protosSeen := map[uint8]int{}
	var udpDports []uint16
	udpDportRules := 0
	for i, rule := range p.rules {
		// l4proto values: scalar guards and set lookups following Meta L4PROTO.
		for j, e := range rule {
			meta, ok := e.(*expr.Meta)
			if !ok || meta.Key != expr.MetaKeyL4PROTO || j+1 >= len(rule) {
				continue
			}
			switch m := rule[j+1].(type) {
			case *expr.Cmp:
				if len(m.Data) != 1 {
					t.Fatalf("rule %d l4proto compare has %d bytes, want 1", i, len(m.Data))
				}
				protosSeen[m.Data[0]]++
			case *expr.Lookup:
				elements, ok := p.sets[m.SetID]
				if !ok {
					t.Fatalf("rule %d references unrecorded nft set %d", i, m.SetID)
				}
				for _, el := range elements {
					if len(el.Key) != 1 {
						t.Fatalf("rule %d proto set key = %x, want 1 byte", i, el.Key)
					}
					protosSeen[el.Key[0]]++
				}
			}
		}
		// Transport dport matches: allowed only as a single UDP {68,546} rule.
		if hasTransportDportMatch10751(rule) {
			proto := scalarL4Proto10751(t, rule, i)
			ports := inputBarrierLookupPorts10751(t, p, rule)
			if proto != 17 {
				t.Errorf("rule %d is an l4proto %d dport %v rule; the barrier must admit no TCP ports", i, proto, ports)
			} else {
				udpDportRules++
				udpDports = append(udpDports, ports...)
			}
		}
	}
	// Liveness: the scan must see the mandatory ESP/AH set, or every
	// absence assertion below would pass vacuously.
	if protosSeen[50] == 0 || protosSeen[51] == 0 {
		t.Fatal("proto scan found no ESP/AH references; the walker is not seeing l4proto matches")
	}
	for _, banned := range []uint8{6, 89, 112} {
		if protosSeen[banned] > 0 {
			t.Errorf("barrier admits l4proto %d (%d reference(s)); TCP and FRR/HA protocols must stay deferred", banned, protosSeen[banned])
		}
	}
	if udpDportRules != 1 || !reflect.DeepEqual(udpDports, []uint16{68, 546}) {
		t.Fatalf("UDP dport admits = %v across %d rule(s), want exactly one {68 546} DHCP-client rule", udpDports, udpDportRules)
	}
	for _, blocked := range []uint16{22, 179, 500, 4500, 4785, 4784, 520, 521, 3784, 3785, 67, 547} {
		for _, admitted := range udpDports {
			if admitted == blocked {
				t.Errorf("early UDP barrier admits blocked port %d", blocked)
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

func hasTransportDportMatch10751(rule []expr.Any) bool {
	for _, e := range rule {
		if payload, ok := e.(*expr.Payload); ok &&
			payload.Base == expr.PayloadBaseTransportHeader && payload.Offset == 2 && payload.Len == 2 {
			return true
		}
	}
	return false
}

func scalarL4Proto10751(t *testing.T, rule []expr.Any, i int) uint8 {
	t.Helper()
	for j, e := range rule {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyL4PROTO || j+1 >= len(rule) {
			continue
		}
		if cmp, ok := rule[j+1].(*expr.Cmp); ok {
			if len(cmp.Data) != 1 {
				t.Fatalf("rule %d l4proto compare has %d bytes, want 1", i, len(cmp.Data))
			}
			return cmp.Data[0]
		}
	}
	t.Fatalf("rule %d has a dport match but no scalar l4proto guard", i)
	return 0
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
