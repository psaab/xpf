package routing

import (
	"encoding/binary"
	"net"
	"runtime"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// ruleDumpMessage17078 builds one synthetic RTM_NEWRULE dump row with
// the given header action and FRA_PRIORITY.
func ruleDumpMessage17078(t *testing.T, priority int, table int, action uint8) []byte {
	t.Helper()
	msg := nl.NewRtMsg()
	msg.Family = unix.AF_INET
	msg.Dst_len = 32
	msg.Table = uint8(table)
	if table > 255 {
		msg.Table = unix.RT_TABLE_UNSPEC
	}
	msg.Type = action
	raw := append([]byte(nil), msg.Serialize()...)
	raw = append(raw, nl.NewRtAttr(nl.FRA_DST, net.ParseIP("192.0.2.53").To4()).Serialize()...)
	raw = append(raw, nl.NewRtAttr(nl.FRA_IIFNAME, []byte("lo\x00")).Serialize()...)
	raw = append(raw, nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(uint32(priority))).Serialize()...)
	if table > 255 {
		raw = append(raw, nl.NewRtAttr(unix.RTA_TABLE, nl.Uint32Attr(uint32(table))).Serialize()...)
	}
	raw = append(raw, nl.NewRtAttr(nl.FRA_IP_PROTO, nl.Uint32Attr(uint32(unix.IPPROTO_UDP))).Serialize()...)
	var portBuf [4]byte
	binary.NativeEndian.PutUint16(portBuf[0:2], 53)
	binary.NativeEndian.PutUint16(portBuf[2:4], 53)
	raw = append(raw, nl.NewRtAttr(nl.FRA_DPORT_RANGE, portBuf[:]).Serialize()...)
	return raw
}

// TestRuleDumpDecodesActionAndExtendedTable17078 is the moved #11385
// synthetic-dump cell: the shared decoder must surface the fib-rule
// action and the extended (>255) table id. Pre-#17078 this decode
// lived in pkg/daemon; the daemon projection is covered there by
// TestNetlinkMgmtDNSRuleListReadsKernelAction11385.
func TestRuleDumpDecodesActionAndExtendedTable17078(t *testing.T) {
	lookup, err := ruleRowFromDumpMessage(unix.AF_INET,
		ruleDumpMessage17078(t, 2500, 999, unix.RTN_UNICAST))
	if err != nil {
		t.Fatalf("decode lookup row: %v", err)
	}
	if lookup.Type != unix.RTN_UNICAST || lookup.Table != 999 || lookup.Priority != 2500 {
		t.Fatalf("lookup row = type %d table %d priority %d, want %d/999/2500",
			lookup.Type, lookup.Table, lookup.Priority, unix.RTN_UNICAST)
	}
	if lookup.Dst == nil || lookup.Dst.String() != "192.0.2.53/32" || lookup.IifName != "lo" ||
		lookup.IPProto != unix.IPPROTO_UDP || lookup.Dport == nil ||
		lookup.Dport.Start != 53 || lookup.Dport.End != 53 {
		t.Fatalf("lookup selectors decoded wrong: %+v", lookup.Rule)
	}
	shadow, err := ruleRowFromDumpMessage(unix.AF_INET,
		ruleDumpMessage17078(t, 2501, unix.RT_TABLE_UNSPEC, nl.FR_ACT_UNREACHABLE))
	if err != nil {
		t.Fatalf("decode shadow row: %v", err)
	}
	if shadow.Type != nl.FR_ACT_UNREACHABLE {
		t.Fatalf("shadow action = %d, want unreachable (%d)", shadow.Type, nl.FR_ACT_UNREACHABLE)
	}
}

// TestRuleDumpRejectsMalformedRows17078 pins the validation the old
// pkg/routing DSCP sidecar lacked: short attributes must fail the
// decode instead of panicking on an unchecked [0:4] slice, and the
// FRA_IP_PROTO width rule (1..4 bytes, #14971) must hold both ways.
func TestRuleDumpRejectsMalformedRows17078(t *testing.T) {
	build := func(attrs ...*nl.RtAttr) []byte {
		msg := nl.NewRtMsg()
		msg.Family = unix.AF_INET
		raw := append([]byte(nil), msg.Serialize()...)
		for _, attr := range attrs {
			raw = append(raw, attr.Serialize()...)
		}
		return raw
	}
	// An unpadded final attribute: FRA_IP_PROTO carries one byte, so
	// its header claims 5 bytes but RTA alignment requires 8. Stripping
	// the padding leaves a tail ParseRouteAttr would advance past the
	// end of (aligned length > remaining bytes) and panic on.
	unpaddedTail := build(nl.NewRtAttr(nl.FRA_IP_PROTO, []byte{6}))
	unpaddedTail = unpaddedTail[:len(unpaddedTail)-3]
	cases := []struct {
		name string
		raw  []byte
	}{
		{"short message", []byte{1, 2, 3}},
		{"short priority", build(nl.NewRtAttr(nl.FRA_PRIORITY, []byte{1, 2}))},
		{"short table", build(nl.NewRtAttr(unix.RTA_TABLE, []byte{1}))},
		{"short dport range", build(nl.NewRtAttr(nl.FRA_DPORT_RANGE, []byte{1, 2}))},
		{"short tun id", build(nl.NewRtAttr(nl.FRA_TUN_ID, []byte{1, 2, 3, 4}))},
		{"empty ip proto", build(nl.NewRtAttr(nl.FRA_IP_PROTO, []byte{}))},
		{"oversize ip proto", build(nl.NewRtAttr(nl.FRA_IP_PROTO, []byte{1, 2, 3, 4, 5}))},
		{"bad dst width", build(nl.NewRtAttr(nl.FRA_DST, []byte{1, 2, 3}))},
		{"empty dscp", build(nl.NewRtAttr(FRA_DSCP, []byte{}))},
		{"truncated attribute tail", unpaddedTail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ruleRowFromDumpMessage(unix.AF_INET, tc.raw); err == nil {
				t.Fatalf("%s: decode succeeded, want error", tc.name)
			}
		})
	}
	// Width-tolerant control: the kernel's 1-byte FRA_IP_PROTO (#14971)
	// and the library's 4-byte spelling both decode to the same value.
	for _, width := range [][]byte{{6}, {6, 0, 0, 0}} {
		row, err := ruleRowFromDumpMessage(unix.AF_INET,
			build(nl.NewRtAttr(nl.FRA_IP_PROTO, width)))
		if err != nil {
			t.Fatalf("ip proto width %d: %v", len(width), err)
		}
		if row.IPProto != 6 {
			t.Fatalf("ip proto width %d decoded %d, want 6", len(width), row.IPProto)
		}
	}
}

// TestPBRAppliedStatusDetectsActionMismatch17078 is the acceptance
// cell from #17078: a lookup rule replaced by an unreachable rule at
// the same priority must report a mismatch. Pre-fix, PBRAppliedStatus
// normalised Type away (expected.Type = observed.Type) and
// netlink.RuleList never decoded it, so this read back as matched.
//
// FAIL-ON-REVERT: restore the Type normalisation in
// pbrNetlinkRuleMatches (or stop setting Type in
// pbrExpectedLookupRule) and the unreachable row matches again.
func TestPBRAppliedStatusDetectsActionMismatch17078(t *testing.T) {
	base := config.PBRRulePriorityBase
	desired := []PBRRule{{
		Family:  syscall.AF_INET,
		TableID: 100,
		IifName: "eth0",
	}}
	expected, valid := pbrExpectedLookupRule(desired[0], base)
	if !valid {
		t.Fatal("fixture rule must materialize")
	}
	if expected.Type != unix.RTN_UNICAST {
		t.Fatalf("expected lookup action = %d, want unicast (%d)", expected.Type, unix.RTN_UNICAST)
	}

	occupancy, mismatched, ok := PBRAppliedStatus(
		fakeRuleOps7422{v4: []netlink.Rule{expected}}, desired)
	if !ok || occupancy != 1 || mismatched != 0 {
		t.Fatalf("unicast lookup: occupancy=%d mismatched=%d ok=%v, want 1/0/true",
			occupancy, mismatched, ok)
	}

	replaced := expected
	replaced.Type = nl.FR_ACT_UNREACHABLE
	occupancy, mismatched, ok = PBRAppliedStatus(
		fakeRuleOps7422{v4: []netlink.Rule{replaced}}, desired)
	if !ok || occupancy != 1 || mismatched != 1 {
		t.Fatalf("unreachable replacement: occupancy=%d mismatched=%d ok=%v, want 1/1/true",
			occupancy, mismatched, ok)
	}
}

// fakeFullRuleOps17078 serves full rows so the DSCP sidecar comparison
// in PBRAppliedStatus is reachable hermetically.
type fakeFullRuleOps17078 struct {
	v4, v6 []RuleRow
	errV4  error
	errV6  error
}

func (f fakeFullRuleOps17078) RuleAdd(*netlink.Rule) error { return nil }
func (f fakeFullRuleOps17078) RuleDel(*netlink.Rule) error { return nil }
func (f fakeFullRuleOps17078) RuleAddDSCP(*netlink.Rule, uint8) error {
	return nil
}
func (f fakeFullRuleOps17078) RuleList(family int) ([]netlink.Rule, error) {
	rows, err := f.RuleListFullRows(family)
	if err != nil {
		return nil, err
	}
	rules := make([]netlink.Rule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, row.Rule)
	}
	return rules, nil
}
func (f fakeFullRuleOps17078) RuleListFullRows(family int) ([]RuleRow, error) {
	if family == syscall.AF_INET {
		return f.v4, f.errV4
	}
	return f.v6, f.errV6
}

// TestPBRAppliedStatusChecksDeclaredDSCP17078: when the desired rule
// declares a DSCP selector, a readback row with a different (or
// missing) FRA_DSCP is a mismatch; when it declares none, the sidecar
// is not consulted.
func TestPBRAppliedStatusChecksDeclaredDSCP17078(t *testing.T) {
	base := config.PBRRulePriorityBase
	desired := []PBRRule{{
		Family:  syscall.AF_INET,
		TableID: 100,
		IifName: "eth0",
		DSCP:    46,
		DSCPSet: true,
	}}
	expected, valid := pbrExpectedLookupRule(desired[0], base)
	if !valid {
		t.Fatal("fixture rule must materialize")
	}
	row := func(dscp uint8, set bool) RuleRow {
		return RuleRow{Rule: expected, DSCP: dscp, DSCPSet: set}
	}

	_, mismatched, ok := PBRAppliedStatus(
		fakeFullRuleOps17078{v4: []RuleRow{row(46, true)}}, desired)
	if !ok || mismatched != 0 {
		t.Fatalf("matching dscp: mismatched=%d ok=%v, want 0/true", mismatched, ok)
	}
	_, mismatched, ok = PBRAppliedStatus(
		fakeFullRuleOps17078{v4: []RuleRow{row(10, true)}}, desired)
	if !ok || mismatched != 1 {
		t.Fatalf("wrong dscp: mismatched=%d ok=%v, want 1/true", mismatched, ok)
	}
	_, mismatched, ok = PBRAppliedStatus(
		fakeFullRuleOps17078{v4: []RuleRow{row(0, false)}}, desired)
	if !ok || mismatched != 1 {
		t.Fatalf("missing dscp: mismatched=%d ok=%v, want 1/true", mismatched, ok)
	}

	undeclared := []PBRRule{{Family: syscall.AF_INET, TableID: 100, IifName: "eth0"}}
	_, mismatched, ok = PBRAppliedStatus(
		fakeFullRuleOps17078{v4: []RuleRow{row(10, true)}}, undeclared)
	if !ok || mismatched != 0 {
		t.Fatalf("undeclared dscp must not be checked: mismatched=%d ok=%v, want 0/true", mismatched, ok)
	}
}

// TestRuleListFullRoundTrip17078 is the class-N kernel cell (#17078
// acceptance: an `unshare -rn` round-trip). It installs a lookup rule
// and an unreachable shadow in a private netns through the production
// encoders, then reads them back through RuleListFull and requires
// the action, table, DSCP sidecar and selectors to survive.
//
// Run: unshare -rn go test ./pkg/routing/ -run '^TestRuleListFullRoundTrip17078$'
// Outside a private netns it SKIPs (never touches the host rule table).
func TestRuleListFullRoundTrip17078(t *testing.T) {
	ns := enterPrivateNetns17078(t)
	_ = ns
	ops := liveDSCPOps(t)

	lookup := netlink.NewRule()
	lookup.Priority = 30900
	lookup.Family = unix.AF_INET
	lookup.Table = 100
	lookup.IifName = "lo"
	lookup.Type = unix.RTN_UNICAST
	if err := ops.RuleAddDSCP(lookup, 46); err != nil {
		t.Fatalf("install lookup rule: %v", err)
	}
	defer delRuleDSCP7796(t, ops, lookup)

	rows, err := RuleListFull(unix.AF_INET)
	if err != nil {
		t.Fatalf("RuleListFull: %v", err)
	}
	var found *RuleRow
	for i := range rows {
		if rows[i].Priority == 30900 {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("installed rule not in RuleListFull readback: %+v", rows)
	}
	if found.Type != unix.RTN_UNICAST {
		t.Fatalf("readback action = %d, want unicast (%d)", found.Type, unix.RTN_UNICAST)
	}
	if found.Table != 100 || found.IifName != "lo" {
		t.Fatalf("readback table/iif = %d/%q, want 100/lo", found.Table, found.IifName)
	}
	if !found.DSCPSet || found.DSCP != 46 {
		t.Fatalf("readback DSCP = %d set=%t, want 46/true", found.DSCP, found.DSCPSet)
	}

	// The DSCP projection must agree with the full row it came from.
	selectors, err := RuleListDSCPSelectors(unix.AF_INET)
	if err != nil {
		t.Fatalf("RuleListDSCPSelectors: %v", err)
	}
	joined := false
	for _, sel := range selectors {
		if sel.Priority == 30900 {
			joined = sel.Table == 100 && sel.DSCP == 46
		}
	}
	if !joined {
		t.Fatalf("DSCP projection does not join the full row: %+v", selectors)
	}
}

// enterPrivateNetns17078 is enterPrivateNetns7796 under this issue's
// name so the cell's isolation contract is greppable from #17078; it
// hard-fails (via the 7796 helper's Skipf only when namespace creation
// is denied by the environment) rather than ever running against the
// host rule table.
func enterPrivateNetns17078(t *testing.T) netns.NsHandle {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns (%v)", err)
	}
	// Refuse to run in the initial namespace when we can prove it:
	// creating a NEW namespace is the isolation, so compare the new
	// handle against the original rather than trusting the caller.
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns — needs CAP_NET_ADMIN (run under `unshare -rn`): %v", err)
	}
	if ns == orig {
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
		t.Fatal("new netns handle equals original; refusing host-netns execution")
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
	return ns
}
