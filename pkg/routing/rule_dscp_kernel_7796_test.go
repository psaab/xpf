package routing

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// rule_dscp_kernel_7796_test.go is the APPLY LEG for #7796.
//
// A compile-side test cannot catch this class of defect. The pre-fix code built
// a perfectly well-formed netlink.Rule and every build-side assertion passed —
// the failure was entirely in what the KERNEL accepted: FRA_TOS is masked to
// IPTOS_TOS_MASK (0x1E), so a DSCP shifted into a TOS byte was rejected with
// EINVAL for every DSCP >= 8, taking the whole commit down. The only instrument
// that can see that is one that actually asks the kernel.
//
// These run in a private netns so they cannot touch the host's rule table. They
// SKIP with an explicit reason when netns creation is denied (no silent caps):
//   unshare -rn go test ./pkg/routing/ -run 7796

// enterPrivateNetns7796 locks the goroutine to its OS thread and moves it into a
// fresh network namespace, restoring the original on cleanup.
func enterPrivateNetns7796(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns (%v)", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns — needs CAP_NET_ADMIN (run under `unshare -rn` or as root): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

// liveDSCPOps returns the PRODUCTION ops bound to a real netlink handle in the
// current (private) netns. Using the production type is the point: a fake would
// prove nothing about what the kernel accepts.
func liveDSCPOps(t *testing.T) dscpRuleOps {
	t.Helper()
	h, err := netlink.NewHandle()
	if err != nil {
		t.Skipf("cannot open netlink handle: %v", err)
	}
	t.Cleanup(h.Close)
	return dscpRuleOps{h}
}

// TestRuleAddDSCPAcceptedByKernel7796 is the regression guard. Every DSCP the
// config layer can name must install.
//
// FAIL-ON-REVERT: restore the pre-#7796 emit (rule.Tos = dscp << 2 through the
// library's RuleAdd) and every row from cs1 (8) up returns
// "invalid argument" — which is exactly what took the FBF commit down.
func TestRuleAddDSCPAcceptedByKernel7796(t *testing.T) {
	enterPrivateNetns7796(t)
	ops := liveDSCPOps(t)

	// The full set of values dscpValue can produce, including the boundary the
	// legacy tos selector could still represent (7) and the ones it could not.
	for _, dscp := range []uint8{0, 1, 7, 8, 10, 16, 24, 26, 32, 40, 46, 48, 56, 63} {
		t.Run(fmt.Sprintf("dscp-%d", dscp), func(t *testing.T) {
			rule := netlink.NewRule()
			rule.Family = unix.AF_INET
			rule.Table = 236616 // a real FBF table id: > 255, so FRA_TABLE carries it
			rule.Priority = config.PBRRulePriorityBase + int(dscp)

			if err := ops.RuleAddDSCP(rule, dscp); err != nil {
				t.Fatalf("kernel REJECTED a dscp %d rule: %v\n\n"+
					"This is #7796. The legacy FRA_TOS selector masks to "+
					"IPTOS_TOS_MASK (0x1E), so DSCP<<2 overflows it from dscp 8 up "+
					"and the commit fails. The rule must carry FRA_DSCP.", dscp, err)
			}
		})
	}
}

// The kernel must have stored the DSCP we sent, not merely accepted the message.
// Acceptance alone would pass against an encoder that emitted a well-formed
// message with the WRONG value — the rule would install and steer the wrong
// traffic, which is worse than the crash it replaced.
func TestRuleDSCPRoundTripsThroughKernel7796(t *testing.T) {
	enterPrivateNetns7796(t)
	ops := liveDSCPOps(t)

	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2 `ip` not found; cannot read the kernel's stored selector back")
	}

	// One rule per DSCP, each at its own priority so the readback can tell them
	// apart. netlink's own RuleList cannot be used as the reader here: the
	// library has no FRA_DSCP support at all (that is the premise of this fix),
	// so it would silently report every rule as having no DSCP and the
	// assertion would pass against ANY value. iproute2 is an INDEPENDENT reader.
	want := map[int]uint8{}
	for i, dscp := range []uint8{0, 8, 26, 46, 63} {
		prio := 31500 + i
		rule := netlink.NewRule()
		rule.Family = unix.AF_INET
		rule.Table = 236616
		rule.Priority = prio
		if err := ops.RuleAddDSCP(rule, dscp); err != nil {
			t.Fatalf("install dscp %d at prio %d: %v", dscp, prio, err)
		}
		want[prio] = dscp
	}

	out, err := exec.Command(ip, "rule", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("ip rule list: %v (%s)", err, out)
	}
	listing := string(out)

	// iproute2 renders a DSCP either by DiffServ name (CS1, AF31, EF) or
	// numerically, and renders 0 as "default". Accept any spelling the tool
	// chooses; what must hold is that the rule carries A dscp selector and that
	// it decodes to the value we installed.
	for prio, dscp := range want {
		line := ruleLineForPriority7796(listing, prio)
		if line == "" {
			t.Errorf("no rule at priority %d in:\n%s", prio, listing)
			continue
		}
		if !strings.Contains(line, "dscp") {
			t.Errorf("rule at priority %d carries NO dscp selector (%q). A rule "+
				"without the selector matches EVERY DSCP — the #3430 H2 over-match.",
				prio, line)
			continue
		}
		if got, ok := dscpFromRuleLine7796(line); !ok {
			t.Errorf("could not decode the dscp from %q", line)
		} else if got != dscp {
			t.Errorf("priority %d: kernel stored dscp %d, want %d (line %q). The "+
				"encoder produced a well-formed message with the wrong value, which "+
				"installs a rule that steers the wrong traffic.", prio, got, dscp, line)
		}
	}
	unreachable := netlink.NewRule()
	unreachable.Family = unix.AF_INET
	unreachable.Priority = 31505
	unreachable.Type = pbrTerminatorAction
	if err := ops.RuleAddDSCP(unreachable, 46); err != nil {
		t.Fatalf("install DSCP-qualified unreachable action: %v", err)
	}
	out, err = exec.Command(ip, "rule", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("ip rule list after unreachable action: %v (%s)", err, out)
	}
	listing = string(out)
	line := ruleLineForPriority7796(listing, unreachable.Priority)
	if !strings.Contains(line, "unreachable") || !strings.Contains(line, "dscp") {
		t.Fatalf("DSCP-qualified action was not read back as unreachable with its selector: %q", line)
	}
	if got, ok := dscpFromRuleLine7796(line); !ok || got != 46 {
		t.Errorf("DSCP-qualified unreachable action has DSCP %d (valid=%v), want 46: %q",
			got, ok, line)
	}
}

// A rule that sets BOTH the legacy tos and a dscp must be refused rather than
// silently dropping one. Emitting both is how the pre-fix value would sneak back.
func TestRuleAddDSCPRejectsLegacyTOS7796(t *testing.T) {
	enterPrivateNetns7796(t)
	ops := liveDSCPOps(t)

	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = 236616
	rule.Priority = config.PBRRulePriorityBase + config.PBRRuleWindow - 1
	rule.Tos = 46 << 2 // the pre-#7796 value

	err := ops.RuleAddDSCP(rule, 46)
	if err == nil {
		t.Fatal("a rule carrying BOTH the legacy tos byte and a dscp was accepted; " +
			"the tos byte is the #7796 defect and must not ride along")
	}
	if !strings.Contains(err.Error(), "tos") {
		t.Errorf("error %q should name the legacy tos selector", err)
	}
}

// An out-of-range DSCP must be refused before it reaches the kernel: 6 bits is
// the whole domain, and a wider value would be silently truncated on the wire.
func TestRuleAddDSCPRejectsOutOfRange7796(t *testing.T) {
	ops := dscpRuleOps{} // no kernel access needed; the guard is pre-flight
	err := ops.RuleAddDSCP(netlink.NewRule(), 64)
	if err == nil {
		t.Fatal("dscp 64 must be rejected: the field is 6 bits, so 64 truncates to 0 " +
			"and would install a best-effort rule under a name that is not one")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error %q should say the value is out of range", err)
	}
}

// ruleLineForPriority7796 returns the `ip rule list` line whose priority field
// matches, or "" when absent.
func ruleLineForPriority7796(listing string, prio int) string {
	prefix := fmt.Sprintf("%d:", prio)
	for _, line := range strings.Split(listing, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// dscpFromRuleLine7796 decodes the dscp token iproute2 rendered, accepting the
// DiffServ name, a bare number, or "default" (its spelling for 0).
func dscpFromRuleLine7796(line string) (uint8, bool) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f != "dscp" || i+1 >= len(fields) {
			continue
		}
		tok := fields[i+1]
		if strings.EqualFold(tok, "default") {
			return 0, true
		}
		if v, ok := dscpValue(tok); ok {
			return v, true
		}
		return 0, false
	}
	return 0, false
}

// errUnusedGuard keeps errors imported if the assertions above are trimmed; the
// encoder's contract is checked by message, not by sentinel, because netlink
// returns bare errno values that carry no domain meaning.
var _ = errors.Is

// TestDSCPZeroIsDistinctFromNoDSCP7796 is the cell that makes
// "presence-as-selector" a measured claim rather than a description.
//
// The whole justification for dropping DSCP 0 was that a zero value is
// indistinguishable from "no selector". That was TRUE of the legacy tos byte.
// Asserting only that a dscp-0 rule installs would not refute it — a rule that
// silently carried no selector at all also installs, and matches every DSCP.
// The distinction is only real if the two render DIFFERENTLY, so this installs
// both and reads them back:
//
//	dscp 0      -> a rule WITH a dscp selector, rendered "dscp default"
//	no dscp     -> a rule with NO dscp token at all
//
// FAIL-ON-REVERT: make the encoder skip the FRA_DSCP attribute when dscp == 0
// (the shape the old drop assumed) and the two rules become indistinguishable —
// this cell reds while every "does it install" assertion stays green.
func TestDSCPZeroIsDistinctFromNoDSCP7796(t *testing.T) {
	enterPrivateNetns7796(t)
	ops := liveDSCPOps(t)

	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2 `ip` not found; cannot read the kernel's stored selector back")
	}

	const zeroPrio = config.PBRRulePriorityBase + 700
	const nonePrio = config.PBRRulePriorityBase + 701

	zeroRule := netlink.NewRule()
	zeroRule.Family = unix.AF_INET
	zeroRule.Table = 236616
	zeroRule.Priority = zeroPrio
	if err := ops.RuleAddDSCP(zeroRule, 0); err != nil {
		t.Fatalf("install dscp-0 rule: %v", err)
	}

	// The contrast: the SAME rule shape with no DSCP, installed the ordinary way.
	noneRule := netlink.NewRule()
	noneRule.Family = unix.AF_INET
	noneRule.Table = 236616
	noneRule.Priority = nonePrio
	if err := ops.RuleAdd(noneRule); err != nil {
		t.Fatalf("install dscp-less rule: %v", err)
	}

	out, err := exec.Command(ip, "rule", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("ip rule list: %v (%s)", err, out)
	}
	listing := string(out)

	zeroLine := ruleLineForPriority7796(listing, zeroPrio)
	noneLine := ruleLineForPriority7796(listing, nonePrio)
	if zeroLine == "" || noneLine == "" {
		t.Fatalf("expected both rules present; dscp0=%q none=%q in:\n%s", zeroLine, noneLine, listing)
	}

	if !strings.Contains(zeroLine, "dscp") {
		t.Errorf("the dscp-0 rule carries NO dscp selector (%q). Then it matches EVERY "+
			"DSCP, and the pre-#7796 decision to drop DSCP-0 rather than install one "+
			"was right — presence-as-selector would be false.", zeroLine)
	}
	if got, ok := dscpFromRuleLine7796(zeroLine); !ok || got != 0 {
		t.Errorf("dscp-0 rule decoded to %d,%v; want 0,true (line %q)", got, ok, zeroLine)
	}
	if strings.Contains(noneLine, "dscp") {
		t.Errorf("a rule installed with NO dscp reports one (%q); the two cases must "+
			"stay distinguishable or the selector means nothing", noneLine)
	}

	// State it as the single claim being made, so a future reader sees the
	// property rather than three separate assertions.
	if zeroLine == noneLine {
		t.Errorf("dscp-0 and dscp-less rules render identically (%q)", zeroLine)
	}
}
