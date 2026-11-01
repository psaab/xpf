package nftables

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// #18721: the #9506 host-input fence readback must accept the #16841
// zero-hop-limit DROP ahead of the overlay (that rule leads every host-input
// chain by design) and must keep refusing any rule ahead of the overlay that
// can admit a packet, including one whose admitting expression the
// google/nftables decoder cannot type.
//
// These cells judge the rules buildHostInboundNetlink really emits, through
// the same verifyHostOverlayRuleChain the kernel readback runs, in BOTH views
// the readback can meet: the build plan's typed expressions, and the kernel
// readback's (GetRules minus every expression google/nftables v0.3.0 skips).
// The live install + readback twin is the forced kernel cell
// TestHostInputFenceLiveReadbackAndRestore9506 (make test-daemon-kernel-lib).

func overlay18721() HostInputFenceOverlay {
	return CanonicalHostInputFenceOverlay(HostInputFenceOverlay{
		MasterSet:       []string{"st0"},
		Generation:      7,
		PermitEpoch:     11,
		CloseRequestSeq: 13,
		CloseRequestKey: "3/7/[xfrmi:st0]",
		WatchGeneration: 7,
		State:           "CLOSING",
	})
}

// kernelExprName18721 is the kernel's name for a typed expression, as the
// rule dump lists it (verdicts are immediates with the verdict register).
func kernelExprName18721(t *testing.T, e expr.Any) string {
	t.Helper()
	switch e.(type) {
	case *expr.Meta:
		return "meta"
	case *expr.Payload:
		return "payload"
	case *expr.Cmp:
		return "cmp"
	case *expr.Bitwise:
		return "bitwise"
	case *expr.Byteorder:
		return "byteorder"
	case *expr.Fib:
		return "fib"
	case *expr.Lookup:
		return "lookup"
	case *expr.Counter:
		return "counter"
	case *expr.Objref:
		return "objref"
	case *expr.Verdict, *expr.Immediate:
		return "immediate"
	case *expr.Queue:
		return "queue"
	case *expr.Target:
		return "target"
	case *expr.Dup:
		return "dup"
	case *expr.TProxy:
		return "tproxy"
	case *expr.Socket:
		return "socket"
	case *expr.Rt:
		return "rt"
	case *expr.Ct:
		return "ct"
	case *expr.Reject:
		return "reject"
	}
	t.Fatalf("fixture: no kernel name for %T", e)
	return ""
}

// decoderSkips18721 reports whether google/nftables v0.3.0 drops an
// expression of this type on readback: expr.exprFromName has no case for
// byteorder, dup, tproxy, socket or rt, and exprsFromBytes `continue`s past
// any name it cannot type. A netns probe confirmed byteorder, rt and socket
// vanish from GetRules.
func decoderSkips18721(e expr.Any) bool {
	switch e.(type) {
	case *expr.Byteorder, *expr.Dup, *expr.TProxy, *expr.Socket, *expr.Rt:
		return true
	}
	return false
}

type view18721 struct {
	name  string
	rules []*nftables.Rule
	names [][]string
}

// views18721 returns the plan view (every expression typed) and the kernel
// readback view (decoder-skipped expressions missing from rule.Exprs but still
// named by the kernel) of the same rule list.
func views18721(t *testing.T, exprLists [][]expr.Any) []view18721 {
	t.Helper()
	plan := view18721{name: "plan"}
	kernel := view18721{name: "kernel readback"}
	for _, exprs := range exprLists {
		var names []string
		var decoded []expr.Any
		for _, e := range exprs {
			names = append(names, kernelExprName18721(t, e))
			if !decoderSkips18721(e) {
				decoded = append(decoded, e)
			}
		}
		plan.rules = append(plan.rules, &nftables.Rule{Exprs: exprs})
		plan.names = append(plan.names, names)
		kernel.rules = append(kernel.rules, &nftables.Rule{Exprs: decoded})
		kernel.names = append(kernel.names, names)
	}
	return []view18721{plan, kernel}
}

// inputExprs18721 builds the host-inbound table for spec and returns its
// input-chain rules' expressions in emission order.
func inputExprs18721(t *testing.T, spec HostInboundSpec) [][]expr.Any {
	t.Helper()
	p := newBuildPlan(t, HostInboundTableName, hostInboundPriority)
	buildHostInboundNetlink(p, spec)
	if p.err != nil {
		t.Fatalf("build host inbound: %v", p.err)
	}
	var out [][]expr.Any
	for i, exprs := range p.rules {
		if p.ruleChains[i] == "input" {
			out = append(out, exprs)
		}
	}
	if len(out) == 0 {
		t.Fatal("fixture: the host-inbound build emitted no input rules")
	}
	return out
}

func verify18721(v view18721, o HostInputFenceOverlay) error {
	return verifyHostOverlayRuleChain(v.rules, v.names, map[string][]string{}, HostInputFenceOverlayCounterName(o), o)
}

func hasType18721[T expr.Any](exprs []expr.Any) bool {
	for _, e := range exprs {
		if _, ok := e.(T); ok {
			return true
		}
	}
	return false
}

// The defect cell: the production default (zero-hop DROP on) puts that DROP
// first and the overlay second. Before #18721 this read "host overlay leading
// rule absent" — the production apply then failed (daemon_nft.go).
func TestOverlayReadbackAcceptsTheZeroHopDropAhead18721(t *testing.T) {
	o := overlay18721()
	exprs := inputExprs18721(t, HostInboundSpec{Overlay: &o})
	marker := HostInputFenceOverlayCounterName(o)
	if _, _, markerSeen, _ := decodeHostOverlayRule(&nftables.Rule{Exprs: exprs[0]}, nil, marker); markerSeen {
		t.Fatal("fixture: rule 0 is the overlay; the zero-hop DROP no longer leads, so this cell does not reach the defect")
	}
	// The byteorder is what makes the two views differ: the kernel readback
	// loses it, so the count rule has to hold for both.
	if !hasType18721[*expr.Byteorder](exprs[0]) || !hasType18721[*expr.Fib](exprs[0]) {
		t.Fatalf("fixture: rule 0 should be the #16841 `fib daddr type` zero-hop DROP, got %#v", exprs[0])
	}
	for _, v := range views18721(t, exprs) {
		if !hostInputRuleIsDropOnly(v.rules[0], v.names[0]) {
			t.Errorf("%s: the zero-hop DROP is not judged DROP-only (names %v)", v.name, v.names[0])
		}
		if err := verify18721(v, o); err != nil {
			t.Errorf("%s: readback of the production rule order failed: %v", v.name, err)
		}
	}
}

// The other order: with the knob set there is no zero-hop rule and the
// overlay leads. That must still verify.
func TestOverlayReadbackAcceptsTheOverlayFirst18721(t *testing.T) {
	o := overlay18721()
	exprs := inputExprs18721(t, HostInboundSpec{Overlay: &o, NoIPv6RejectZeroHopLimit: true})
	if _, _, markerSeen, _ := decodeHostOverlayRule(&nftables.Rule{Exprs: exprs[0]}, nil, HostInputFenceOverlayCounterName(o)); !markerSeen {
		t.Fatal("fixture: with the knob set the overlay should be rule 0")
	}
	for _, v := range views18721(t, exprs) {
		if err := verify18721(v, o); err != nil {
			t.Errorf("%s: readback with the overlay first failed: %v", v.name, err)
		}
	}
}

func drop18721() expr.Any { return &expr.Verdict{Kind: expr.VerdictDrop} }

// refusedHeads18721 are rules that must never stand ahead of the fence. Each
// either admits or diverts a packet, or carries a kind outside the allowlist
// (several of which the decoder cannot even see).
func refusedHeads18721() map[string][]expr.Any {
	return map[string][]expr.Any{
		"accept":                      {&expr.Verdict{Kind: expr.VerdictAccept}},
		"return to the accept policy": {&expr.Verdict{Kind: expr.VerdictReturn}},
		"jump":                        {&expr.Verdict{Kind: expr.VerdictJump, Chain: "junos-host"}},
		"goto":                        {&expr.Verdict{Kind: expr.VerdictGoto, Chain: "junos-host"}},
		"accept then drop":            {&expr.Verdict{Kind: expr.VerdictAccept}, drop18721()},
		"no verdict (falls through)":  {&expr.Counter{}},
		"two drops":                   {drop18721(), drop18721()},
		// A verdict map can jump or accept.
		"verdict map then drop": {
			&expr.Lookup{SourceRegister: 1, DestRegister: 0, IsDestRegSet: true, SetName: "vm"},
			drop18721(),
		},
		// NF_QUEUE: userspace can re-inject the packet with ACCEPT.
		"queue then drop": {&expr.Queue{Num: 1}, drop18721()},
		// The same through an xt-compat target, which the denylist missed.
		"xt NFQUEUE target then drop": {&expr.Target{Name: "NFQUEUE", Rev: 3}, drop18721()},
		// Kinds the decoder skips: invisible in rule.Exprs, named by the kernel.
		"dup then drop":    {&expr.Dup{RegAddr: 1, RegDev: 2, IsRegDevSet: true}, drop18721()},
		"tproxy then drop": {&expr.TProxy{Family: unix.NFPROTO_IPV4, TableFamily: unix.NFPROTO_INET, RegPort: 1}, drop18721()},
		"socket match then drop": {
			&expr.Socket{Key: expr.SocketKeyTransparent, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			drop18721(),
		},
		"rt match then drop": {
			&expr.Rt{Register: 1, Key: expr.RtClassid},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: make([]byte, 4)},
			drop18721(),
		},
		// Not on the allowlist even though it does not admit: the list names
		// what the head rules use, nothing more.
		"data immediate then drop": {&expr.Immediate{Register: 1, Data: []byte{1, 2, 3, 4}}, drop18721()},
		"ct then drop":             {&expr.Ct{Register: 1, Key: expr.CtKeySTATE}, drop18721()},
		"reject":                   {&expr.Reject{Type: unix.NFT_REJECT_TCP_RST}},
		"objref ahead of the fence": {
			&expr.Objref{Type: 1, Name: "c"},
			drop18721(),
		},
	}
}

// The property the fence exists for: nothing outside the DROP-only allowlist
// may run before it. Each shape, put ahead of the real overlay (alone, or
// after the real zero-hop DROP), must fail the readback in both views.
func TestOverlayReadbackRefusesANonDropRuleAhead18721(t *testing.T) {
	o := overlay18721()
	knobSet := inputExprs18721(t, HostInboundSpec{Overlay: &o, NoIPv6RejectZeroHopLimit: true})
	zeroHop := inputExprs18721(t, HostInboundSpec{Overlay: &o})[0]
	for name, head := range refusedHeads18721() {
		for prefixName, prefix := range map[string][][]expr.Any{
			"alone":              {head},
			"after the zero-hop": {zeroHop, head},
		} {
			exprs := append(append([][]expr.Any(nil), prefix...), knobSet...)
			for _, v := range views18721(t, exprs) {
				err := verify18721(v, o)
				if err == nil || !strings.Contains(err.Error(), "leading rule absent") {
					t.Errorf("%s (%s, %s view) ahead of the overlay: readback = %v, want \"leading rule absent\"", name, prefixName, v.name, err)
				}
			}
		}
	}
}

// The decoder-blind cells, stated directly: the typed decode of these rules
// looks like a plain DROP-only rule, and only the kernel's names show the
// extra expression. Each must be refused; the control (the same rule with
// nothing hidden) must pass, so the refusal is caused by the hidden kind.
func TestOverlayReadbackSeesExpressionsTheDecoderSkips18721(t *testing.T) {
	decoded := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		drop18721(),
	}
	rule := &nftables.Rule{Exprs: decoded}
	if !hostInputRuleIsDropOnly(rule, []string{"payload", "cmp", "immediate"}) {
		t.Fatal("control: [payload cmp drop] with matching names is not DROP-only")
	}
	for _, hidden := range []string{"dup", "tproxy", "socket", "rt", "queue", "target", "fwd", "xfrm", "osf"} {
		names := []string{"payload", hidden, "cmp", "immediate"}
		if hostInputRuleIsDropOnly(rule, names) {
			t.Errorf("a %q expression the decoder dropped passed as DROP-only (names %v)", hidden, names)
		}
	}
	// The kernel names are judged by KIND, not only counted: a name outside
	// the allowlist fails even when the counts happen to agree (a rule that
	// changed between the two reads into one holding rt where cmp was).
	if hostInputRuleIsDropOnly(rule, []string{"payload", "rt", "immediate"}) {
		t.Error("a kernel name outside the allowlist passed because the counts agreed")
	}
	// A rule that changed between GetRules and the name dump: the views do not
	// describe the same rule, so the readback fails closed.
	if hostInputRuleIsDropOnly(rule, []string{"payload", "cmp", "cmp", "immediate"}) {
		t.Error("an extra allowlisted kernel expression with no typed twin passed as DROP-only")
	}
	if hostInputRuleIsDropOnly(rule, []string{"payload", "immediate"}) {
		t.Error("a typed expression the kernel did not list passed as DROP-only")
	}
	if hostInputRuleIsDropOnly(rule, nil) {
		t.Error("a rule with no kernel names passed as DROP-only")
	}
}

// The overlay rules themselves are held to the same allowlist (plus the
// marker objref): a queue or xt target inside a marked DROP rule could hand
// a fenced master's packet to userspace before the DROP.
func TestOverlayReadbackRefusesADivertingOverlayRule18721(t *testing.T) {
	o := overlay18721()
	for name, extra := range map[string]expr.Any{
		"queue":     &expr.Queue{Num: 1},
		"xt target": &expr.Target{Name: "NFQUEUE", Rev: 3},
		"dup":       &expr.Dup{RegAddr: 1},
	} {
		exprs := inputExprs18721(t, HostInboundSpec{Overlay: &o, NoIPv6RejectZeroHopLimit: true})
		overlayRule := exprs[0]
		last := len(overlayRule) - 1
		if v, ok := overlayRule[last].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
			t.Fatalf("fixture: the overlay rule should end in DROP, got %#v", overlayRule[last])
		}
		withExtra := append(append(append([]expr.Any(nil), overlayRule[:last]...), extra), overlayRule[last])
		exprs[0] = withExtra
		for _, v := range views18721(t, exprs) {
			if err := verify18721(v, o); err == nil || !strings.Contains(err.Error(), "outside the fence shape") {
				t.Errorf("overlay rule carrying %s (%s view): readback = %v, want \"outside the fence shape\"", name, v.name, err)
			}
		}
	}
}

// A DROP-only prefix does not stand in for the overlay: with no overlay rule
// at all the readback still fails.
func TestOverlayReadbackStillNeedsTheOverlayRule18721(t *testing.T) {
	o := overlay18721()
	exprs := inputExprs18721(t, HostInboundSpec{Overlay: &o})
	for _, v := range views18721(t, exprs[:1]) {
		if err := verify18721(v, o); err == nil || !strings.Contains(err.Error(), "leading rule absent") {
			t.Errorf("%s: a chain holding only the zero-hop DROP verified as a fence: %v", v.name, err)
		}
	}
	other := o
	other.MasterSet = []string{"st1"}
	for _, v := range views18721(t, exprs) {
		if err := verify18721(v, other); err == nil {
			t.Errorf("%s: readback accepted an overlay for a different master set", v.name)
		}
	}
	// The two inputs must line up rule for rule.
	v := views18721(t, exprs)[0]
	if err := verifyHostOverlayRuleChain(v.rules, v.names[:1], map[string][]string{}, HostInputFenceOverlayCounterName(o), o); err == nil {
		t.Error("readback accepted fewer expression lists than rules")
	}
}

func TestHostInputRuleIsDropOnly18721(t *testing.T) {
	for name, tc := range map[string]struct {
		exprs []expr.Any
		names []string
		want  bool
	}{
		"drop":                   {[]expr.Any{&expr.Counter{}, drop18721()}, []string{"counter", "immediate"}, true},
		"bitwise then drop":      {[]expr.Any{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4}, &expr.Cmp{Register: 1, Data: make([]byte, 4)}, drop18721()}, []string{"meta", "bitwise", "cmp", "immediate"}, true},
		"set lookup then drop":   {[]expr.Any{&expr.Lookup{SourceRegister: 1, SetName: "s"}, drop18721()}, []string{"lookup", "immediate"}, true},
		"byteorder, plan view":   {[]expr.Any{&expr.Fib{Register: 1}, &expr.Byteorder{SourceRegister: 1, DestRegister: 1}, &expr.Lookup{SourceRegister: 1, SetName: "s"}, drop18721()}, []string{"fib", "byteorder", "lookup", "immediate"}, true},
		"byteorder, kernel view": {[]expr.Any{&expr.Fib{Register: 1}, &expr.Lookup{SourceRegister: 1, SetName: "s"}, drop18721()}, []string{"fib", "byteorder", "lookup", "immediate"}, true},
		"accept":                 {[]expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, []string{"immediate"}, false},
		"two drops":              {[]expr.Any{drop18721(), drop18721()}, []string{"immediate", "immediate"}, false},
		"no verdict":             {[]expr.Any{&expr.Counter{}}, []string{"counter"}, false},
		"map lookup then drop":   {[]expr.Any{&expr.Lookup{SourceRegister: 1, IsDestRegSet: true, SetName: "m"}, drop18721()}, []string{"lookup", "immediate"}, false},
		"queue then drop":        {[]expr.Any{&expr.Queue{Num: 2}, drop18721()}, []string{"queue", "immediate"}, false},
		"xt target then drop":    {[]expr.Any{&expr.Target{Name: "NFQUEUE"}, drop18721()}, []string{"target", "immediate"}, false},
		"objref then drop":       {[]expr.Any{&expr.Objref{Name: "c"}, drop18721()}, []string{"objref", "immediate"}, false},
	} {
		if got := hostInputRuleIsDropOnly(&nftables.Rule{Exprs: tc.exprs}, tc.names); got != tc.want {
			t.Errorf("%s: hostInputRuleIsDropOnly = %v, want %v", name, got, tc.want)
		}
	}
	// The overlay variant admits the marker objref, and nothing else extra.
	marked := &nftables.Rule{Exprs: []expr.Any{&expr.Objref{Name: "c"}, drop18721()}}
	if !hostInputRuleOnlyDrops(marked, []string{"objref", "immediate"}, true) {
		t.Error("an objref + DROP overlay rule is not DROP-only with objref allowed")
	}
}

// ruleMsg18721 encodes an NFT_MSG_NEWRULE payload: nfgenmsg + handle +
// expression list, each element carrying the given name (empty = no name).
func ruleMsg18721(t *testing.T, handle *uint64, names ...string) []byte {
	t.Helper()
	var elems []netlink.Attribute
	for _, name := range names {
		var inner []netlink.Attribute
		if name != "" {
			inner = append(inner, netlink.Attribute{Type: unix.NFTA_EXPR_NAME, Data: []byte(name + "\x00")})
		}
		inner = append(inner, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: nil})
		b, err := netlink.MarshalAttributes(inner)
		if err != nil {
			t.Fatal(err)
		}
		elems = append(elems, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: b})
	}
	list, err := netlink.MarshalAttributes(elems)
	if err != nil {
		t.Fatal(err)
	}
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(HostInboundTableName + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte("input\x00")},
	}
	if handle != nil {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, *handle)})
	}
	attrs = append(attrs, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: list})
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, b...)
}

func TestDecodeRuleExprNames18721(t *testing.T) {
	h := uint64(0x0102030405)
	handle, names, err := decodeRuleExprNames(ruleMsg18721(t, &h, "meta", "cmp", "rt", "immediate"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if handle != h || fmt.Sprint(names) != "[meta cmp rt immediate]" {
		t.Fatalf("decode = handle %#x names %v, want handle %#x names [meta cmp rt immediate]", handle, names, h)
	}
	if _, _, err := decodeRuleExprNames(ruleMsg18721(t, &h, "meta", "")); err == nil {
		t.Error("an expression without a name decoded")
	}
	if _, _, err := decodeRuleExprNames(ruleMsg18721(t, nil, "meta")); err == nil {
		t.Error("a rule without a handle decoded")
	}
	if _, _, err := decodeRuleExprNames([]byte{1, 0}); err == nil {
		t.Error("a short message decoded")
	}
}
