package nftables

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestTransitBarrierUnsupportedClassification9852(t *testing.T) {
	single := errors.Join(fmt.Errorf("%w: bridge family unavailable", ErrTransitBarrierBridgeUnsupported))
	if !IsTransitBarrierBridgeUnsupportedOnly(single) {
		t.Fatal("single-child production-shaped join must classify as bridge-only degradation")
	}
	mixed := errors.Join(single, errors.New("inet: permission denied"))
	if IsTransitBarrierBridgeUnsupportedOnly(mixed) {
		t.Fatal("mixed inet plus bridge errors must remain fatal")
	}
	if IsTransitBarrierBridgeUnsupportedOnly(nil) {
		t.Fatal("nil error must not classify as bridge-only degradation")
	}
	plain := errors.Join(errors.New("plain netlink failure"))
	if IsTransitBarrierBridgeUnsupportedOnly(plain) {
		t.Fatal("plain single-child join must not classify as bridge-only degradation")
	}
}

func TestTransitBarrierUnsupportedErrnoTagging9852(t *testing.T) {
	unsupported := []error{unix.ENOENT, unix.EOPNOTSUPP, unix.EAFNOSUPPORT}
	for _, errno := range unsupported {
		t.Run("bridge_"+errno.Error(), func(t *testing.T) {
			in := transitBarrierFakeInstaller9852(nil, errno)
			err := in.InstallTransitBarrier()
			if err == nil {
				t.Fatalf("bridge %v unexpectedly succeeded", errno)
			}
			if !IsTransitBarrierBridgeUnsupportedOnly(err) {
				t.Fatalf("bridge %v error was not tagged as sole unsupported degradation: %v", errno, err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("bridge %v was not preserved through wrapping: %v", errno, err)
			}
		})
	}

	for _, errno := range unsupported {
		t.Run("inet_"+errno.Error(), func(t *testing.T) {
			in := transitBarrierFakeInstaller9852(errno, nil)
			err := in.InstallTransitBarrier()
			if err == nil {
				t.Fatalf("inet %v unexpectedly succeeded", errno)
			}
			if IsTransitBarrierBridgeUnsupportedOnly(err) {
				t.Fatalf("inet %v was misclassified as bridge-only degradation: %v", errno, err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("inet %v was not preserved through wrapping: %v", errno, err)
			}
		})
	}

	t.Run("bridge_permission_denied", func(t *testing.T) {
		in := transitBarrierFakeInstaller9852(nil, unix.EPERM)
		err := in.InstallTransitBarrier()
		if err == nil {
			t.Fatal("bridge EPERM unexpectedly succeeded")
		}
		if IsTransitBarrierBridgeUnsupportedOnly(err) {
			t.Fatalf("bridge EPERM was misclassified as unsupported degradation: %v", err)
		}
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("bridge EPERM was not preserved through wrapping: %v", err)
		}
	})
}

func transitBarrierFakeInstaller9852(inetErr, bridgeErr error) *netlinkInstaller {
	family := 0
	return newNetlinkInstallerConn(func() (*gnft.Conn, error) {
		flushErr := inetErr
		if family == 1 {
			flushErr = bridgeErr
		}
		family++
		calls := 0
		return gnft.New(gnft.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			calls++
			if calls == 3 && flushErr != nil {
				return nil, flushErr
			}
			return nil, nil
		}))
	})
}

func TestArmedTransitFencePlanShape10302(t *testing.T) {
	p := newBuildPlan(t, "xpf_transit_10302", *gnft.ChainPriorityFilter)
	chain := transitBarrierChain(p.table)
	if chain.Hooknum != gnft.ChainHookForward {
		t.Fatalf("transit fence hook = %v, want forward", chain.Hooknum)
	}
	if chain.Policy == nil || *chain.Policy != gnft.ChainPolicyDrop {
		t.Fatalf("transit fence policy = %v, want DROP", chain.Policy)
	}
	p.chain = chain
	emitTransitFencePinhole(p, ForwardFenceSpec{AllowedIfnames: []string{"xdp-owned0"}})
	if p.err != nil {
		t.Fatalf("armed pinhole plan failed: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("armed fence emitted %d rules, want one explicit pinhole", len(p.rules))
	}
	rule := p.rules[0]
	if len(rule) < 3 {
		t.Fatalf("armed pinhole expression count = %d, want iifname comparison plus verdict", len(rule))
	}
	if meta, ok := rule[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("armed pinhole first expression = %#v, want iifname meta", rule[0])
	}
	if cmp, ok := rule[1].(*expr.Cmp); !ok || cmp.Op != expr.CmpOpEq {
		t.Fatalf("armed pinhole second expression = %#v, want iifname equality", rule[1])
	}
	if verdict, ok := rule[len(rule)-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("armed pinhole verdict = %#v, want ACCEPT", rule[len(rule)-1])
	}

	empty := newBuildPlan(t, "xpf_transit_10302_empty", *gnft.ChainPriorityFilter)
	empty.chain = transitBarrierChain(empty.table)
	emitTransitFencePinhole(empty, ForwardFenceSpec{})
	if empty.err != nil {
		t.Fatalf("empty fence plan failed: %v", empty.err)
	}
	if len(empty.rules) != 0 {
		t.Fatalf("empty armed fence emitted %d ACCEPT rules, want none", len(empty.rules))
	}
}
func TestArmedTransitFenceMarkPinhole10391(t *testing.T) {
	p := newBuildPlan(t, "xpf_transit_10391_mark", *gnft.ChainPriorityFilter)
	p.chain = transitBarrierChain(p.table)
	emitTransitFencePinhole(p, ForwardFenceSpec{
		AllowedMarks: []ForwardFenceMark{{
			Ifname: armedTransitReinjectIfname10391,
			Mark:   AdjudicatedTransitMark,
			Mask:   AdjudicatedTransitMarkMask,
		}},
	})
	if p.err != nil {
		t.Fatalf("marked pinhole plan failed: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("marked fence emitted %d rules, want one", len(p.rules))
	}
	rule := p.rules[0]
	if len(rule) < 6 {
		t.Fatalf("marked pinhole expression count = %d, want iif+mark conjunction plus verdict", len(rule))
	}
	if meta, ok := rule[0].(*expr.Meta); !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("marked pinhole first expression = %#v, want iifname meta", rule[0])
	}
	if meta, ok := rule[2].(*expr.Meta); !ok || meta.Key != expr.MetaKeyMARK {
		t.Fatalf("marked pinhole mark expression = %#v, want mark meta", rule[2])
	}
	if bitwise, ok := rule[3].(*expr.Bitwise); !ok {
		t.Fatalf("marked pinhole bitwise expression = %#v, want bitwise mask", rule[3])
	} else {
		if !bytes.Equal(bitwise.Mask, binaryutil.NativeEndian.PutUint32(AdjudicatedTransitMarkMask)) {
			t.Fatalf("marked pinhole mask bytes = %x, want %x", bitwise.Mask,
				binaryutil.NativeEndian.PutUint32(AdjudicatedTransitMarkMask))
		}
		if !bytes.Equal(bitwise.Xor, []byte{0, 0, 0, 0}) {
			t.Fatalf("marked pinhole xor bytes = %x, want zero", bitwise.Xor)
		}
	}
	if cmp, ok := rule[4].(*expr.Cmp); !ok {
		t.Fatalf("marked pinhole comparison = %#v, want mark comparison", rule[4])
	} else if cmp.Op != expr.CmpOpEq || cmp.Register != 1 {
		t.Fatalf("marked pinhole comparison op/register = %v/%d, want eq/1", cmp.Op, cmp.Register)
	} else if !bytes.Equal(cmp.Data, binaryutil.NativeEndian.PutUint32(
		AdjudicatedTransitMark&AdjudicatedTransitMarkMask,
	)) {
		t.Fatalf("marked pinhole comparison bytes = %x, want %x", cmp.Data,
			binaryutil.NativeEndian.PutUint32(AdjudicatedTransitMark&AdjudicatedTransitMarkMask))
	} else if !bytes.Equal(cmp.Data, []byte{0x01, 0x50, 0x46, 0x58}) {
		// Literal LE golden for 0x58465001 (BE would be 58 46 50 01):
		// guards against a joint impl+test endian flip (#10410 P0).
		t.Fatalf("marked pinhole comparison bytes = %x, want LE golden 01504658", cmp.Data)
	}
	if verdict, ok := rule[len(rule)-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("marked pinhole verdict = %#v, want ACCEPT", rule[len(rule)-1])
	}
}

const armedTransitReinjectIfname10391 = "xpf-usp1"
