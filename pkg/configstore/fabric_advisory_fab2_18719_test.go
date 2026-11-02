package configstore

import "testing"

func TestFab2MemberChangeWarnsOnSecondCommit18719(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	set18719(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab2",
		"interfaces fab2 fabric-options member-interfaces ge-0/0/0",
	)
	if warnings := commitWarnings18719(t, s); !hasWarning18719(warnings, fabricZoneStampMarker18719) {
		t.Fatalf("the commit that adds fab2 must print the reminder; warnings=%v", warnings)
	}

	set18719(t, s, "interfaces fab2 fabric-options member-interfaces ge-0/0/1")
	if warnings := commitWarnings18719(t, s); !hasWarning18719(warnings, fabricZoneStampMarker18719) {
		t.Fatalf("a fab2 member change must print the reminder on the second commit; warnings=%v", warnings)
	}
}
