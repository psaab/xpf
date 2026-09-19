package nftables

import (
	"bytes"
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
