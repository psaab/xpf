package nftables

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestIpsecDivertSpecRejectsProvenanceQueueAlias9506(t *testing.T) {
	err := validateIpsecDivertSpec(IpsecDivertSpec{
		InetForward:   []IpsecDivertRule{{Ifname: "st0", Queue: 1001}},
		InetInput:     []IpsecDivertRule{{Ifname: "st0", Queue: 1002}},
		BridgeForward: []IpsecDivertRule{{Ifname: "st0", Queue: 1001}},
	})
	if err == nil {
		t.Fatal("queue alias across family/hook classes was accepted")
	}
}

type fakeIpsecNftState struct {
	tables map[gnft.TableFamily]map[string]bool
}

func newFakeIpsecNftState() *fakeIpsecNftState {
	return &fakeIpsecNftState{
		tables: map[gnft.TableFamily]map[string]bool{
			gnft.TableFamilyINet:   {},
			gnft.TableFamilyBridge: {},
		},
	}
}

func (s *fakeIpsecNftState) hasTable(family gnft.TableFamily, name string) bool {
	return s.tables[family][name]
}

func (s *fakeIpsecNftState) dial(req []netlink.Message) ([]netlink.Message, error) {
	for _, msg := range req {
		kind := uint16(msg.Header.Type) & 0xff
		if len(msg.Data) < 4 {
			continue
		}
		family := gnft.TableFamily(msg.Data[0])
		switch kind {
		case unix.NFT_MSG_GETTABLE:
			var response []netlink.Message
			for name, present := range s.tables[family] {
				if !present {
					continue
				}
				attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{
					Type: unix.NFTA_TABLE_NAME,
					Data: []byte(name + "\x00"),
				}})
				if err != nil {
					return nil, err
				}
				response = append(response, netlink.Message{
					Header: netlink.Header{
						Type:     netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWTABLE),
						Sequence: msg.Header.Sequence,
					},
					Data: append([]byte{byte(family), 0, 0, 0}, attrs...),
				})
			}
			return response, nil
		case unix.NFT_MSG_GETCHAIN:
			var response []netlink.Message
			for name, present := range s.tables[family] {
				if !present {
					continue
				}
				for _, chainName := range []string{"forward", "input"} {
					attrs, err := fakeIpsecChainAttrs(name, chainName)
					if err != nil {
						return nil, err
					}
					response = append(response, netlink.Message{
						Header: netlink.Header{
							Type:     netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWCHAIN),
							Sequence: msg.Header.Sequence,
						},
						Data: append([]byte{byte(family), 0, 0, 0}, attrs...),
					})
				}
			}
			return response, nil
		case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
			name, err := fakeIpsecAttrString(msg.Data, unix.NFTA_TABLE_NAME)
			if err != nil {
				return nil, err
			}
			if name == "" {
				continue
			}
			if s.tables[family] == nil {
				s.tables[family] = map[string]bool{}
			}
			s.tables[family][name] = kind == unix.NFT_MSG_NEWTABLE
		}
	}
	return nil, nil
}

func fakeIpsecAttrString(data []byte, wanted uint16) (string, error) {
	ad, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return "", err
	}
	for ad.Next() {
		if ad.Type() == wanted {
			return ad.String(), ad.Err()
		}
	}
	return "", ad.Err()
}

func fakeIpsecChainAttrs(tableName, chainName string) ([]byte, error) {
	hook := uint32(unix.NF_INET_FORWARD)
	if chainName == "input" {
		hook = uint32(unix.NF_INET_LOCAL_IN)
	}
	priority := int32(IpsecDivertPriority)
	policy := uint32(gnft.ChainPolicyAccept)
	if tableName == IpsecQuarantineTableName {
		priority = int32(IpsecQuarantinePriority)
		policy = uint32(gnft.ChainPolicyDrop)
	}
	if tableName == IpsecDivertTableName {
		policy = uint32(gnft.ChainPolicyDrop)
	}
	hookAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: binary.BigEndian.AppendUint32(nil, hook)},
		{Type: unix.NFTA_HOOK_PRIORITY, Data: binary.BigEndian.AppendUint32(nil, uint32(priority))},
	})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(tableName + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(chainName + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_CHAIN_HOOK, Data: hookAttrs},
		{Type: unix.NFTA_CHAIN_POLICY, Data: binary.BigEndian.AppendUint32(nil, policy)},
		{Type: unix.NFTA_CHAIN_TYPE, Data: []byte("filter\x00")},
	})
}

func TestIpsecQuarantineInstallRemoveRoundTripFake9506(t *testing.T) {
	state := newFakeIpsecNftState()
	in := newNetlinkInstallerConn(func() (*gnft.Conn, error) {
		return gnft.New(gnft.WithTestDial(state.dial))
	})
	spec := IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 7,
		CandidateIfindices:   []uint32{17},
	}
	if err := in.InstallIpsecDivert(spec); err != nil {
		t.Fatalf("fake quarantine install: %v", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		if !state.hasTable(family, IpsecDivertTableName) {
			t.Fatalf("family %v missing deny divert table after install", family)
		}
		if state.hasTable(family, IpsecQuarantineTableName) {
			t.Fatalf("family %v retained guard table after install", family)
		}
	}
	if err := in.RemoveIpsecDivert(); err != nil {
		t.Fatalf("fake quarantine remove: %v", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		if state.hasTable(family, IpsecDivertTableName) || state.hasTable(family, IpsecQuarantineTableName) {
			t.Fatalf("family %v retained ipsec tables after remove", family)
		}
	}
}

func TestIpsecDivertRuleShape9506(t *testing.T) {
	tests := []struct {
		name  string
		hook  *gnft.ChainHook
		class []IpsecDivertRule
	}{
		{"forward", gnft.ChainHookForward, []IpsecDivertRule{{Ifname: "st0", Queue: 1001}}},
		{"input", gnft.ChainHookInput, []IpsecDivertRule{{Ifname: "st0", Queue: 1002}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecDivertTableName}
			chain := ipsecDivertChain(tbl, tc.name, tc.hook)
			if chain.Priority == nil || *chain.Priority != IpsecDivertPriority {
				t.Fatalf("priority = %v, want %d", chain.Priority, IpsecDivertPriority)
			}
			if chain.Policy == nil || *chain.Policy != gnft.ChainPolicyAccept {
				t.Fatalf("policy = %v, want ACCEPT", chain.Policy)
			}
			p := newBuildPlan(t, IpsecDivertTableName, IpsecDivertPriority)
			p.chain = chain
			emitIpsecDivertRules(p, tc.class)
			if p.err != nil {
				t.Fatalf("render: %v", p.err)
			}
			if len(p.rules) != 1 {
				t.Fatalf("rendered %d rules, want one", len(p.rules))
			}
			rule := p.rules[0]
			if len(rule) < 3 {
				t.Fatalf("rule expression count = %d, want iifname + queue", len(rule))
			}
			if meta, ok := rule[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyIIFNAME {
				t.Fatalf("first expression = %#v, want iifname", rule[0])
			}
			queue, ok := rule[len(rule)-1].(*expr.Queue)
			if !ok {
				t.Fatalf("last expression = %#v, want queue", rule[len(rule)-1])
			}
			if queue.Num != tc.class[0].Queue || queue.Flag != 0 {
				t.Fatalf("queue = %#v, want num=%d flag=0 (no bypass)", queue, tc.class[0].Queue)
			}
		})
	}
}

func TestIpsecDivertInstallsBothFamiliesAtomically9506(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	spec := IpsecDivertSpec{
		InetForward:   []IpsecDivertRule{{Ifname: "st0", Queue: 1101}},
		InetInput:     []IpsecDivertRule{{Ifname: "st0", Queue: 1102}},
		BridgeForward: []IpsecDivertRule{{Ifname: "st0", Queue: 1103}},
		BridgeInput:   []IpsecDivertRule{{Ifname: "st0", Queue: 1104}},
	}
	if err := in.InstallIpsecDivert(spec); err != nil {
		if IsTransitBarrierBridgeUnsupportedOnly(err) {
			t.Skipf("kernel lacks bridge nftables support; degraded S3 branch: %v", err)
		}
		t.Fatalf("divert install: %v", err)
	}
	t.Cleanup(func() { _ = in.RemoveIpsecDivert() })

	c, err := gnft.New()
	if err != nil {
		t.Fatalf("new nftables conn: %v", err)
	}
	chains, err := c.ListChainsOfTableFamily(gnft.TableFamilyINet)
	if err != nil {
		t.Fatalf("list inet chains: %v", err)
	}
	assertDivertChains(t, chains, gnft.TableFamilyINet)
	chains, err = c.ListChainsOfTableFamily(gnft.TableFamilyBridge)
	if err != nil {
		t.Fatalf("list bridge chains: %v", err)
	}
	assertDivertChains(t, chains, gnft.TableFamilyBridge)
}

func assertDivertChains(t *testing.T, chains []*gnft.Chain, family gnft.TableFamily) {
	t.Helper()
	seen := map[string]bool{}
	for _, chain := range chains {
		if chain == nil || chain.Table == nil || chain.Table.Name != IpsecDivertTableName {
			continue
		}
		seen[chain.Name] = true
		if chain.Priority == nil || *chain.Priority != IpsecDivertPriority {
			t.Fatalf("%v %s priority = %v, want %d", family, chain.Name, chain.Priority, IpsecDivertPriority)
		}
		if chain.Policy == nil || *chain.Policy != gnft.ChainPolicyAccept {
			t.Fatalf("%v %s policy = %v, want ACCEPT", family, chain.Name, chain.Policy)
		}
	}
	for _, name := range []string{"forward", "input"} {
		if !seen[name] {
			t.Fatalf("%v divert chain %q missing", family, name)
		}
	}
}

func TestIpsecDivertUnsupportedClassifierRemainsNarrow9506(t *testing.T) {
	if IsTransitBarrierBridgeUnsupportedOnly(nil) {
		t.Fatal("nil unexpectedly classified as degraded")
	}
	if IsTransitBarrierBridgeUnsupportedOnly(errors.New("inet: operation not supported")) {
		t.Fatal("unattributed error unexpectedly classified as bridge degraded")
	}
}
func TestIpsecDivertAtomicFlushFailure9506(t *testing.T) {
	var mutateCalls, readCalls int
	var flush []netlink.Message
	in := newNetlinkInstallerConn(func() (*gnft.Conn, error) {
		return gnft.New(gnft.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			mutating := false
			for _, msg := range req {
				switch uint16(msg.Header.Type) & 0xff {
				case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE,
					unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN,
					unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
					mutating = true
				}
			}
			if mutating {
				mutateCalls++
				flush = append([]netlink.Message(nil), req...)
				return nil, errors.New("injected flush failure")
			}
			readCalls++
			return nil, nil
		}))
	})
	err := in.installIpsecDivertAtomic(IpsecDivertSpec{
		InetForward:   []IpsecDivertRule{{Ifname: "st0", Queue: 1201}},
		InetInput:     []IpsecDivertRule{{Ifname: "st0", Queue: 1202}},
		BridgeForward: []IpsecDivertRule{{Ifname: "st0", Queue: 1203}},
		BridgeInput:   []IpsecDivertRule{{Ifname: "st0", Queue: 1204}},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("flush failure")) {
		t.Fatalf("atomic install error = %v, want injected flush failure", err)
	}
	if mutateCalls != 1 || readCalls < 4 {
		t.Fatalf("netlink batches = mutating:%d reads:%d, want one mutating batch and at least four reads", mutateCalls, readCalls)
	}
	if len(flush) == 0 {
		t.Fatal("combined flush sent no netlink messages")
	}
	t.Logf("combined flush messages=%d", len(flush))
}

func TestIpsecDivertRemoveFlushFailureIsNotBridgeDegraded9506(t *testing.T) {
	in := newNetlinkInstallerConn(func() (*gnft.Conn, error) {
		return gnft.New(gnft.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			if len(req) == 1 && uint16(req[0].Header.Type)&0xff == unix.NFT_MSG_GETTABLE {
				attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{
					Type: unix.NFTA_TABLE_NAME,
					Data: []byte(IpsecDivertTableName + "\x00"),
				}})
				if err != nil {
					return nil, err
				}
				data := append([]byte{req[0].Data[0], 0, 0, 0}, attrs...)
				return []netlink.Message{{
					Header: netlink.Header{
						Type:     netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWTABLE),
						Sequence: req[0].Header.Sequence,
					},
					Data: data,
				}}, nil
			}
			return nil, unix.ENOENT
		}))
	})
	err := in.RemoveIpsecDivert()
	if err == nil {
		t.Fatal("remove unexpectedly succeeded after injected flush ENOENT")
	}
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("remove error = %v, want injected ENOENT", err)
	}
	if IsTransitBarrierBridgeUnsupportedOnly(err) {
		t.Fatalf("remove flush failure was misclassified as bridge degraded: %v", err)
	}
}
func TestIpsecQuarantineUnknownInputDeniesAndPreservesRaw9506(t *testing.T) {
	rawMask := IpsecQuarantineReasonMask(1 << 29)
	rawReason := IpsecQuarantineReason(0xfe)
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantinePrimaryReason: rawReason,
		QuarantineReasonMask:    rawMask,
		InetForward:             []IpsecDivertRule{{Ifname: "st0", Queue: 1401}},
	})
	if !spec.QuarantineAll {
		t.Fatal("unknown quarantine input did not close admission")
	}
	if spec.QuarantineRawMask != rawMask || spec.QuarantineRawReason != rawReason {
		t.Fatalf("raw quarantine identity = mask 0x%x/reason %d, want 0x%x/%d",
			spec.QuarantineRawMask, spec.QuarantineRawReason, rawMask, rawReason)
	}
	if len(spec.InetForward) != 0 || spec.QuarantineReasonMask&ipsecQuarantineMaskUnknown == 0 {
		t.Fatalf("unknown quarantine retained admission rules or unknown bit: %+v", spec)
	}
	if err := validateIpsecDivertSpec(spec); err != nil {
		t.Fatalf("normalized unknown quarantine was rejected: %v", err)
	}
}

func TestIpsecQuarantineDefaultIsDenyAll9506(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{QuarantineAll: true})
	if !spec.QuarantineAll || spec.QuarantinePrimaryReason != IpsecQuarantineReasonUnknown {
		t.Fatalf("default quarantine = %+v, want closed UNKNOWN", spec)
	}
	if spec.QuarantineReasonMask&ipsecQuarantineMaskUnknown == 0 {
		t.Fatalf("default quarantine mask = 0x%x, want unknown bit", spec.QuarantineReasonMask)
	}
	if err := validateIpsecDivertSpec(spec); err != nil {
		t.Fatalf("default quarantine rejected: %v", err)
	}
}

func TestIpsecQuarantineRuleShape9506(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 12,
		CandidateIfindices:   []uint32{17},
	})
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecQuarantineTableName}
	chain := ipsecDenyChain(tbl, "forward", gnft.ChainHookForward, IpsecQuarantinePriority)
	p := newBuildPlan(t, IpsecQuarantineTableName, IpsecQuarantinePriority)
	p.chain = chain
	emitIpsecQuarantineRules(p, "inet", "forward", spec, true)
	if p.err != nil {
		t.Fatalf("render quarantine rules: %v", p.err)
	}
	if len(p.rules) != 2 {
		t.Fatalf("quarantine rule count = %d, want candidate + base", len(p.rules))
	}
	if _, ok := p.rules[0][0].(*expr.Meta); !ok {
		t.Fatalf("candidate first expression = %#v, want meta iif", p.rules[0][0])
	}
	if verdict, ok := p.rules[0][len(p.rules[0])-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictDrop {
		t.Fatalf("candidate verdict = %#v, want DROP", p.rules[0][len(p.rules[0])-1])
	}
	if verdict, ok := p.rules[1][len(p.rules[1])-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictDrop {
		t.Fatalf("base verdict = %#v, want DROP", p.rules[1][len(p.rules[1])-1])
	}
}
func TestIpsecQuarantineLaterHookDropsWithoutCounter9506(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineAll:      true,
		CandidateIfindices: []uint32{17},
	})
	tbl := &gnft.Table{Family: gnft.TableFamilyBridge, Name: IpsecQuarantineTableName}
	p := newBuildPlan(t, IpsecQuarantineTableName, IpsecQuarantinePriority)
	p.chain = ipsecDenyChain(tbl, "input", gnft.ChainHookInput, IpsecQuarantinePriority)
	emitIpsecQuarantineRules(p, "bridge", "input", spec, false)
	if p.err != nil {
		t.Fatalf("render later-hook rules: %v", p.err)
	}
	if len(p.counters) != 0 {
		t.Fatalf("later-hook counters = %v, want none", p.counters)
	}
	for _, rule := range p.rules {
		for _, expression := range rule {
			if _, ok := expression.(*expr.Objref); ok {
				t.Fatalf("later-hook rule contains counter reference: %#v", rule)
			}
		}
	}
}

func TestIpsecQuarantineMetadataPreservesRawReason9506(t *testing.T) {
	metadata := ipsecQuarantineMetadata(IpsecDivertSpec{
		QuarantineGeneration: 4,
		QuarantineRawReason:  IpsecQuarantineReason(0xfe),
		QuarantineRawMask:    IpsecQuarantineReasonMask(1 << 29),
	})
	if !bytes.Contains(metadata, []byte("raw_reason=254")) ||
		!bytes.Contains(metadata, []byte("raw_mask=0x20000000")) {
		t.Fatalf("quarantine metadata = %q, want raw reason and mask", metadata)
	}
}

func TestIpsecQuarantineInstallRemoveRoundTrip9506(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	spec := IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 19,
		QuarantineReasonMask: IpsecQuarantineMaskLinkLookup,
		CandidateIfindices:   []uint32{17, 3},
	}
	if err := in.InstallIpsecDivert(spec); err != nil {
		if IsTransitBarrierBridgeUnsupportedOnly(err) {
			t.Skipf("kernel lacks bridge nftables support; quarantine requires both families: %v", err)
		}
		t.Fatalf("quarantine install: %v", err)
	}
	c, err := gnft.New()
	if err != nil {
		t.Fatalf("new nftables conn: %v", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		chains, err := c.ListChainsOfTableFamily(family)
		if err != nil {
			t.Fatalf("%v list chains: %v", family, err)
		}
		found := false
		for _, chain := range chains {
			if chain != nil && chain.Table != nil && chain.Table.Name == IpsecDivertTableName &&
				(chain.Name == "forward" || chain.Name == "input") {
				found = true
				if chain.Policy == nil || *chain.Policy != gnft.ChainPolicyDrop {
					t.Fatalf("%v %s policy = %v, want DROP", family, chain.Name, chain.Policy)
				}
			}
			if chain != nil && chain.Table != nil && chain.Table.Name == IpsecQuarantineTableName {
				t.Fatalf("%v quarantine guard remained after successful replacement", family)
			}
		}
		if !found {
			t.Fatalf("%v quarantine divert chains missing", family)
		}
	}
	if err := in.RemoveIpsecDivert(); err != nil {
		t.Fatalf("quarantine remove: %v", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		tables, err := c.ListTablesOfFamily(family)
		if err != nil {
			t.Fatalf("%v list tables after remove: %v", family, err)
		}
		for _, table := range tables {
			if table != nil && (table.Name == IpsecDivertTableName || table.Name == IpsecQuarantineTableName) {
				t.Fatalf("%v stale IPsec table after remove: %q", family, table.Name)
			}
		}
	}
}
