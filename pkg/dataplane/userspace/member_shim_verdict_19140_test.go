package userspace

import (
	"strings"
	"testing"
)

// #19140: the #19110 classification, published lock-free. These cells pin
// that the snapshot is republished at every input change (an observation
// pass, a link event, a compile) and that it says exactly what readiness says.

func verdictMember19140(t *testing.T, m *Manager, name string) (DataMemberShimVerdict, DataMemberShimState) {
	t.Helper()
	v, ok := m.DataMemberShimVerdict()
	if !ok {
		t.Fatal("no member-shim verdict published")
	}
	for _, mem := range v.Members {
		if mem.LinuxName == name {
			return v, mem
		}
	}
	t.Fatalf("verdict %+v lacks %s", v, name)
	return v, DataMemberShimState{}
}

// The observation pass publishes: attached, then positively missing, with the
// verdict's earliest observation as At.
func TestMemberShimVerdictPublishedByTheObservationPass19140(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	v, mem := verdictMember19140(t, f.m, "ge-0-0-1")
	if !v.Checked || mem.Status != DataMemberShimAttached {
		t.Fatalf("checked=%v status=%s, want an attached member", v.Checked, mem.Status)
	}
	if !v.At.Equal(f.k.clock()) {
		t.Fatalf("At = %v, want the observation time %v", v.At, f.k.clock())
	}
	f.k.set("ge-0-0-1", 29, 0) // the shim is gone, the link is not
	f.k.advance(1e9)
	f.m.observeDataMembers()
	_, mem = verdictMember19140(t, f.m, "ge-0-0-1")
	if mem.Status != DataMemberShimMissing || !strings.Contains(mem.Detail, "not-attached") {
		t.Fatalf("status=%s detail=%q, want positively missing (not-attached)", mem.Status, mem.Detail)
	}
}

// A link event that changes the member's device downgrades a framing exclusion
// to unverified in the PUBLISHED view at once, as it does for readiness. A
// stale exclusion must never read as "not required".
func TestMemberShimVerdictLinkEventDropsTheExclusion19140(t *testing.T) {
	f := nonEthernetMember19110(t)
	_, mem := verdictMember19140(t, f.m, "ge-0-0-1")
	if mem.Status != DataMemberShimNotRequired {
		t.Fatalf("setup: a non-Ethernet member is %s, want not-required", mem.Status)
	}
	f.replace19110(41)
	f.linkEvent19110(t, "ge-0-0-1")
	_, mem = verdictMember19140(t, f.m, "ge-0-0-1")
	if mem.Status != DataMemberShimUnverified || !strings.Contains(mem.Detail, "device changed") {
		t.Fatalf("status=%s detail=%q after the device changed, want unverified", mem.Status, mem.Detail)
	}
}

// A compile publishes against the new membership authority: until a pass
// observes against it, every member is unverified.
func TestMemberShimVerdictPublishedByTheCompile19140(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	cfg2 := f4Config19110(true)
	f.m.refreshGenericDataMembers(cfg2)
	v, mem := verdictMember19140(t, f.m, "ge-0-0-1")
	if v.Config != cfg2 {
		t.Fatal("the compile did not republish against its config")
	}
	if mem.Status != DataMemberShimUnverified {
		t.Fatalf("status=%s right after a compile, want unverified (not observed against this config)", mem.Status)
	}
}

// Parity: a member is a readiness reason exactly when the published verdict
// classifies it missing or unverified, with the same detail.
func TestMemberShimVerdictMatchesReadiness19140(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shape func(f *memberFixture19110)
	}{
		{"attached", func(*memberFixture19110) {}},
		{"not-attached", func(f *memberFixture19110) { f.k.set("ge-0-0-1", 29, 0) }},
		{"foreign-program", func(f *memberFixture19110) { f.k.set("ge-0-0-1", 29, shimProg19110+1) }},
		{"absent", func(f *memberFixture19110) {
			f.k.mu.Lock()
			delete(f.k.devs, "ge-0-0-1")
			f.k.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMemberFixture19110(t, false)
			tc.shape(f)
			f.m.observeDataMembers()
			_, mem := verdictMember19140(t, f.m, "ge-0-0-1")
			reasons := reasonsOnly19110(f.m)
			isReason := mem.Status == DataMemberShimMissing || mem.Status == DataMemberShimUnverified
			found := false
			for _, r := range reasons {
				if strings.Contains(r, "ge-0-0-1") && (mem.Detail == "" || strings.Contains(r, mem.Detail)) {
					found = true
				}
			}
			if found != isReason {
				t.Fatalf("published %s (%q) but readiness reasons are %v", mem.Status, mem.Detail, reasons)
			}
		})
	}
}
