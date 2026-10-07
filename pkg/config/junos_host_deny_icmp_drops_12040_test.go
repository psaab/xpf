package config

import (
	"strings"
	"testing"
)

// TestJunosHostBadICMPTypePermitCarvesNothing12040 is the #12040 fail-on-revert
// guard. On the tolerant path an application whose icmp-type failed to parse
// keeps ICMPType=nil plus an UnknownICMP drop record
// (compiler_applications.go records the raw token instead of silently dropping
// it, #3348). The userspace expansion refuses any policy referencing such an
// application (ApplicationReferenceMatchDrops, #9525) and NAT emits a
// never-match term (#11587) — but the kernel junos-host projection reduced the
// reference anyway, so a PERMIT referencing it rendered as an all-ICMP return
// (nil type matches every type) AHEAD of a later deny in the zone's subchain.
//
// The projection must treat a non-empty ApplicationReferenceMatchDrops like a
// LenientContentDropped permit (#5575/#9572): skip the permit (it carves
// nothing) while the authored deny still projects. A poisoned DENY is left
// intact because widening a DROP is the fail-closed direction.
//
// Fixture shape: permit referencing badType FIRST, then a deny. RED mechanism
// on revert: the unfixed projection emits a JunosHostReturn with an
// unconstrained (nil-type) ICMP fragment ahead of the deny, so the "projects
// no return" assertion fails.
func TestJunosHostBadICMPTypePermitCarvesNothing12040(t *testing.T) {
	cmds := append(append([]string{}, junosHostBaseZones...),
		// The malformed application: strict commit rejects it (downgrade
		// membership, asserted below); the tolerant load keeps it with an
		// UnknownICMP drop and ICMPType=nil.
		"set applications application badType protocol icmp",
		"set applications application badType icmp-type bogus",
		// A well-formed control deny application.
		"set applications application sshOnly protocol tcp",
		"set applications application sshOnly destination-port 22",
		// Permit referencing the malformed application, FIRST.
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-icmp match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-icmp match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-icmp match application badType",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-icmp then permit",
		// Authored deny AFTER the permit.
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match application sshOnly",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh then deny",
	)
	if _, err := CompileConfig(buildJunosHostWarnTree(t, cmds)); err == nil {
		t.Fatal("fixture is not a member of the tolerant downgrade: strict CompileConfig accepted an invalid icmp-type")
	}
	cfg, err := CompileConfigLenient(buildJunosHostWarnTree(t, cmds))
	if err != nil {
		t.Fatalf("the tolerant compile must still accept the fixture (#1960 no-brick): %v", err)
	}
	// Fixture sanity: the reference must carry a named match drop, the
	// predicate the projection is required to honor.
	if drops := ApplicationReferenceMatchDrops("badType", &cfg.Applications); len(drops) == 0 {
		t.Fatal("badType must carry match drops (UnknownICMP); got none, so the projection assertion below is vacuous")
	} else if !strings.Contains(strings.Join(drops, "\n"), "bogus") {
		t.Fatalf("badType drops = %q, want the malformed icmp-type token named", drops)
	}

	proj := BuildJunosHostDenyProjection(cfg)
	var prog *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "untrust" {
			prog = &proj.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Fatalf("no untrust program in projection: %+v", proj.Programs)
	}
	if !prog.Representable {
		t.Fatalf("untrust program must stay representable (the bad permit is skipped, not poisoned): %+v", *prog)
	}
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostReturn {
			t.Fatalf("badType permit projected a return ahead of the deny: %+v — "+
				"an invalid icmp-type leaves ICMPType=nil (all types), so the return carves every ICMP type off the later deny (#12040)", r)
		}
	}
	foundDeny := false
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostDrop && len(r.L4) == 1 && r.L4[0].Proto == HostInboundProtoTCP {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Fatalf("the authored tcp/22 deny must still project; RulesV4 = %+v", prog.RulesV4)
	}
}

// TestJunosHostBadICMPTypeDenyStillProjects12040 pins the keep-a-deny half of
// #12040: a deny referencing the malformed application is left intact (widening
// a DROP is the fail-closed direction), exactly like a LenientContentDropped
// deny (#5575). Passes before and after the fix.
func TestJunosHostBadICMPTypeDenyStillProjects12040(t *testing.T) {
	cmds := append(append([]string{}, junosHostBaseZones...),
		"set applications application badType protocol icmp",
		"set applications application badType icmp-type bogus",
		"set security policies from-zone untrust to-zone junos-host policy block-bad-icmp match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-bad-icmp match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-bad-icmp match application badType",
		"set security policies from-zone untrust to-zone junos-host policy block-bad-icmp then deny",
	)
	cfg, err := CompileConfigLenient(buildJunosHostWarnTree(t, cmds))
	if err != nil {
		t.Fatalf("the tolerant compile must still accept the fixture (#1960 no-brick): %v", err)
	}
	if drops := ApplicationReferenceMatchDrops("badType", &cfg.Applications); len(drops) == 0 {
		t.Fatal("badType must carry match drops; got none, so the projection assertion below is vacuous")
	}
	proj := BuildJunosHostDenyProjection(cfg)
	var prog *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "untrust" {
			prog = &proj.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Fatalf("no untrust program in projection: %+v", proj.Programs)
	}
	if !prog.Representable {
		t.Fatalf("a deny referencing a dropped-constraint app must stay representable (fail-closed DROP intact): %+v", *prog)
	}
	if len(prog.RulesV4) != 1 || prog.RulesV4[0].Verdict != JunosHostDrop {
		t.Fatalf("want exactly the fail-closed drop for the badType deny; RulesV4 = %+v", prog.RulesV4)
	}
	if len(prog.RulesV4[0].L4) != 1 || prog.RulesV4[0].L4[0].Proto != HostInboundProtoICMP {
		t.Fatalf("badType deny L4 = %+v, want the single ICMP fragment", prog.RulesV4[0].L4)
	}
}

// TestJunosHostGoodICMPTypePermitStillCarves12040 is the #12040 control: a
// permit referencing a WELL-FORMED icmp-type application still renders its
// type-constrained return ahead of the deny. It passes before and after the
// fix and fails on an over-suppressing implementation. The nested-set row
// proves a set-member drop is also honored (ApplicationReferenceMatchDrops
// walks nested sets the way the userspace expansion does).
func TestJunosHostGoodICMPTypePermitStillCarves12040(t *testing.T) {
	cmds := append(append([]string{}, junosHostBaseZones...),
		"set applications application goodType protocol icmp",
		"set applications application goodType icmp-type 8",
		"set applications application sshOnly protocol tcp",
		"set applications application sshOnly destination-port 22",
		"set security policies from-zone untrust to-zone junos-host policy allow-echo match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy allow-echo match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy allow-echo match application goodType",
		"set security policies from-zone untrust to-zone junos-host policy allow-echo then permit",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match application sshOnly",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh then deny",
	)
	cfg, err := CompileConfigLenient(buildJunosHostWarnTree(t, cmds))
	if err != nil {
		t.Fatalf("the tolerant compile must accept the well-formed fixture: %v", err)
	}
	if drops := ApplicationReferenceMatchDrops("goodType", &cfg.Applications); len(drops) != 0 {
		t.Fatalf("goodType must carry no match drops; got %q", drops)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	var prog *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "untrust" {
			prog = &proj.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Fatalf("no untrust program in projection: %+v", proj.Programs)
	}
	if !prog.Representable {
		t.Fatalf("well-formed program must be representable: %+v", *prog)
	}
	if len(prog.RulesV4) < 2 || prog.RulesV4[0].Verdict != JunosHostReturn {
		t.Fatalf("well-formed goodType permit must still carve its return ahead of the deny; RulesV4 = %+v", prog.RulesV4)
	}
	ret := prog.RulesV4[0]
	if len(ret.L4) != 1 || ret.L4[0].Proto != HostInboundProtoICMP || ret.L4[0].ICMPType == nil || *ret.L4[0].ICMPType != 8 {
		t.Fatalf("goodType return L4 = %+v, want the single ICMP fragment constrained to type 8", ret.L4)
	}
}

// TestJunosHostBadICMPTypeSetPermitCarvesNothing12040 extends #12040 through an
// application-set: a permit referencing a set whose member carries a dropped
// constraint is skipped just like a direct reference (the userspace expansion
// refuses the same reference via the same predicate).
func TestJunosHostBadICMPTypeSetPermitCarvesNothing12040(t *testing.T) {
	cmds := append(append([]string{}, junosHostBaseZones...),
		"set applications application badType protocol icmp",
		"set applications application badType icmp-type bogus",
		"set applications application-set badSet application badType",
		"set applications application sshOnly protocol tcp",
		"set applications application sshOnly destination-port 22",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-set match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-set match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-set match application badSet",
		"set security policies from-zone untrust to-zone junos-host policy allow-bad-set then permit",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh match application sshOnly",
		"set security policies from-zone untrust to-zone junos-host policy block-ssh then deny",
	)
	cfg, err := CompileConfigLenient(buildJunosHostWarnTree(t, cmds))
	if err != nil {
		t.Fatalf("the tolerant compile must still accept the fixture (#1960 no-brick): %v", err)
	}
	if drops := ApplicationReferenceMatchDrops("badSet", &cfg.Applications); !strings.Contains(strings.Join(drops, "\n"), "bogus") {
		t.Fatalf("badSet drops = %q, want the nested malformed ICMP constraint named", drops)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	var prog *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "untrust" {
			prog = &proj.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Fatalf("no untrust program in projection: %+v", proj.Programs)
	}
	if !prog.Representable {
		t.Fatalf("untrust program must stay representable (the bad permit is skipped, not poisoned): %+v", *prog)
	}
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostReturn {
			t.Fatalf("badSet permit projected a return ahead of the deny: %+v (#12040 via application-set)", r)
		}
	}
	foundDeny := false
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostDrop && len(r.L4) == 1 && r.L4[0].Proto == HostInboundProtoTCP {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Fatalf("the authored tcp/22 deny must still project; RulesV4 = %+v", prog.RulesV4)
	}
}
