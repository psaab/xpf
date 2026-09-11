package flowexport

import (
	"testing"
)

// TestUndefinedTemplateGroupDoesNotClaimItsFamily9172 is #9172 V076.
//
// An instance whose inet flow-server names a defined template and whose ONLY
// inet6 flow-server names an undefined one. Both resolvers drop the inet6 group
// (the strict gate rejects the reference; this is the tolerant population), so
// only the inet group is built -- but the instance-level family flags were
// derived before that drop and still claimed inet6. ServesFamily(true) then let
// an IPv6 record consume a 1-in-N slot on the instance's shared counter and be
// exported nowhere, diluting the inet group's rate below the configured 1-in-N
// (which IPFIX also advertises in its #3748 sampler Options record).
//
// FAIL-ON-REVERT: drop the narrowToSurvivingFamilies9172 call from either
// resolver and that resolver's cell reports ServesInet6=true.
func TestUndefinedTemplateGroupDoesNotClaimItsFamily9172(t *testing.T) {
	for _, c := range []struct {
		name    string
		resolve func() []*ExportConfig
	}{
		{"v9", func() []*ExportConfig {
			fo := bothFamiliesInstance("10.0.0.1", "2001:db8::9", "t")
			fo.Sampling.Instances["both"].FamilyInet6.FlowServers[0].Version9Template = "undefined"
			return ResolveV9TemplateGroups(v9Svc(), fo)
		}},
		{"ipfix", func() []*ExportConfig {
			fo := bothFamiliesInstance("10.0.0.1", "2001:db8::9", "t")
			fo.Sampling.Instances["both"].FamilyInet6.FlowServers[0].VersionIPFIXTemplate = "undefined"
			return ResolveIPFIXTemplateGroups(ipfixSvc(), fo)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			groups := c.resolve()
			// CONTROL: the drop really happened and the inet group survived, so
			// the flags below are about the surviving group and not about a
			// resolver that built nothing.
			if len(groups) != 1 {
				t.Fatalf("got %d groups, want 1 (the inet group; the inet6 group names an "+
					"undefined template and is dropped)", len(groups))
			}
			g := groupFor(t, groups, false)
			if !g.ServesInet || !g.ServesFamily(false) {
				t.Fatalf("the surviving inet group must still serve inet (ServesInet=%v)", g.ServesInet)
			}
			if g.ServesInet6 || g.ServesFamily(true) {
				t.Errorf("ServesInet6=%v: the instance has NO inet6 group left, so an IPv6 "+
					"record passing this gate consumes a 1-in-N sampling slot and is exported "+
					"nowhere -- the inet group's effective rate is diluted below the "+
					"configured 1-in-N", g.ServesInet6)
			}
		})
	}
}

// TestDefinedTemplatesKeepBothFamilies9172 is the other side: with both
// templates defined, narrowing must not remove a family the instance really
// serves (TestInstanceFamilyFlagsStayInstanceWide_6811 pins the per-instance
// meaning; this pins that the narrowing leaves it alone).
func TestDefinedTemplatesKeepBothFamilies9172(t *testing.T) {
	fo := bothFamiliesInstance("10.0.0.1", "2001:db8::9", "t")
	for _, groups := range [][]*ExportConfig{
		ResolveV9TemplateGroups(v9Svc(), fo),
		ResolveIPFIXTemplateGroups(ipfixSvc(), fo),
	} {
		if len(groups) != 2 {
			t.Fatalf("got %d groups, want 2", len(groups))
		}
		for _, g := range groups {
			if !g.ServesInet || !g.ServesInet6 {
				t.Errorf("group v6=%v: ServesInet=%v ServesInet6=%v, want both true",
					g.GroupIsV6, g.ServesInet, g.ServesInet6)
			}
		}
	}
}
