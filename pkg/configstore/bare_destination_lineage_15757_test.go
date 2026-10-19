package configstore

import (
	"reflect"
	"testing"
)

// #15757 store half of TestBareDestinationCopyRenameAuthzAndRenameLineage
// (authz half in pkg/config): RenameAsPlantClass recorded the RAW typed
// dstPath as session-rematch lineage. For a bare destination (#15237,
// identity-only) RenamePath places the node under the source parent, so
// the recorded descriptor named a path that never existed — the daemon's
// policyRulePathKey/zoneRenamePath could not recognise the destination
// and renamed-policy sessions fell back to teardown instead of rematch.
//
// FAIL-ON-REVERT: recording dstPath verbatim again turns the bare cells
// RED (recorded `policy p-new` / `security-zone trust2` instead of the
// resolved full destination).
func TestBareDestinationRenameLineage15757(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy p-old match source-address any",
		"security policies from-zone trust to-zone untrust policy p-old match destination-address any",
		"security policies from-zone trust to-zone untrust policy p-old match application any",
		"security policies from-zone trust to-zone untrust policy p-old then permit",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}

	// Bare policy rename: full source, identity-only destination.
	src := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p-old"}
	if err := s.Rename(src, []string{"policy", "p-new"}); err != nil {
		t.Fatalf("bare Rename: %v", err)
	}
	got := s.PendingRenameAncestry()
	if len(got) != 1 {
		t.Fatalf("bare rename recorded %d lineage entries, want 1", len(got))
	}
	wantDst := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p-new"}
	if !reflect.DeepEqual(got[0].SourcePath, src) {
		t.Fatalf("lineage source = %v, want %v", got[0].SourcePath, src)
	}
	if !reflect.DeepEqual(got[0].DestinationPath, wantDst) {
		t.Fatalf("lineage destination = %v, want resolved %v (#15757: raw bare dst breaks session rematch)", got[0].DestinationPath, wantDst)
	}

	// Bare zone rename: single-token identity under security zones.
	if err := s.Rename(
		[]string{"security", "zones", "security-zone", "trust"},
		[]string{"security-zone", "trust2"}); err != nil {
		t.Fatalf("bare zone Rename: %v", err)
	}
	got = s.PendingRenameAncestry()
	if len(got) != 2 {
		t.Fatalf("renames recorded %d lineage entries, want 2", len(got))
	}
	wantZoneDst := []string{"security", "zones", "security-zone", "trust2"}
	if !reflect.DeepEqual(got[1].DestinationPath, wantZoneDst) {
		t.Fatalf("zone lineage destination = %v, want resolved %v (#15757)", got[1].DestinationPath, wantZoneDst)
	}

	// Control: full destination is recorded verbatim (unchanged leg).
	if err := s.Rename(
		[]string{"security", "zones", "security-zone", "untrust"},
		[]string{"security", "zones", "security-zone", "untrust2"}); err != nil {
		t.Fatalf("full Rename: %v", err)
	}
	got = s.PendingRenameAncestry()
	if len(got) != 3 {
		t.Fatalf("renames recorded %d lineage entries, want 3", len(got))
	}
	if want := []string{"security", "zones", "security-zone", "untrust2"}; !reflect.DeepEqual(got[2].DestinationPath, want) {
		t.Fatalf("full lineage destination = %v, want %v", got[2].DestinationPath, want)
	}
}
