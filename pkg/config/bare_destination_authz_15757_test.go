package config

import (
	"reflect"
	"testing"
)

// #15757: bare-destination copy/rename (#15237) was adjudicated by
// AuthorizeConfigMutation at the literal typed destination
// (editPath+dst) while CopyPath/RenamePath place it under the SOURCE
// parent (BareDestinationParent). An anchored deny on the real
// destination therefore missed (fail-open) and an anchored allow on it
// false-denied. The store half — RenameAsPlantClass recording the raw
// bare dstPath as session-rematch lineage — is pinned in pkg/configstore
// (TestBareDestinationRenameLineage15757); the authz half and the
// shared resolver are pinned here.
//
// FAIL-ON-REVERT: restoring `resolve(dst)` in configMutationPaths, or
// making ResolveBareCopyRenameDestination return dst unchanged, turns
// the deny cells below RED (they were RED pre-fix at the first cell).
func TestBareDestinationCopyRenameAuthzAndRenameLineage(t *testing.T) {
	denyRoot := classWithConfigRegex9154(t, "", `^system login user root`)

	// Report sketch, nil cursor: bare dst `user root` for source
	// `system login user operator` lands at `system login user root`.
	if err := AuthorizeConfigMutation(denyRoot, "limited", nil,
		"copy system login user operator to user root"); err == nil {
		t.Fatalf("expected bare-destination copy to user root to be denied by ^system login user root")
	}
	// Same rename verb — both endpoints of copy AND rename are gated.
	if err := AuthorizeConfigMutation(denyRoot, "limited", nil,
		"rename system login user operator to user root"); err == nil {
		t.Fatalf("expected bare-destination rename to user root to be denied by ^system login user root")
	}
	// Edit cursor elsewhere: [edit system] + `copy login user operator
	// to user root`. Pre-fix this adjudicated `system user root`.
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"system"},
		"copy login user operator to user root"); err == nil {
		t.Fatalf("expected bare-destination copy under [edit system] to be denied by ^system login user root")
	}
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"system"},
		"rename login user operator to user root"); err == nil {
		t.Fatalf("expected bare-destination rename under [edit system] to be denied by ^system login user root")
	}
	// Policy-shaped bare destination (the lineage shape): deny anchored
	// on the full zone-pair destination must bite for a bare `policy`
	// destination typed with a full source.
	polDeny := classWithConfigRegex9154(t, "",
		`^security policies from-zone trust to-zone untrust policy root`)
	if err := AuthorizeConfigMutation(polDeny, "limited", nil,
		"copy security policies from-zone trust to-zone untrust policy operator to policy root"); err == nil {
		t.Fatalf("expected bare policy copy to be denied at resolved zone-pair destination")
	}

	// Controls that must stay ALLOWED (unaffected legs):
	// bare copy/rename to a non-denied sibling identity.
	if err := AuthorizeConfigMutation(denyRoot, "limited", nil,
		"copy system login user operator to user alice"); err != nil {
		t.Fatalf("bare copy to user alice should be allowed, got %v", err)
	}
	if err := AuthorizeConfigMutation(denyRoot, "limited", []string{"system"},
		"rename login user operator to user alice"); err != nil {
		t.Fatalf("bare rename to user alice under [edit system] should be allowed, got %v", err)
	}
	// Full (non-bare) destination: already denied pre-fix, still denied.
	if err := AuthorizeConfigMutation(denyRoot, "limited", nil,
		"copy system login user operator to system login user root"); err == nil {
		t.Fatalf("full-destination copy to user root should be denied (control)")
	}
	// Full destination to a non-denied path stays allowed.
	if err := AuthorizeConfigMutation(denyRoot, "limited", nil,
		"copy system login user operator to system login user alice"); err != nil {
		t.Fatalf("full-destination copy to user alice should be allowed, got %v", err)
	}

	// Anchored ALLOW leg (false-deny direction): a class allow-listed
	// only under `^security policies` must be permitted a bare policy
	// copy whose resolved destination is under that prefix, and denied
	// one whose resolved destination is outside it.
	allowPol := classWithConfigRegex9154(t, `^security policies`, "")
	if err := AuthorizeConfigMutation(allowPol, "limited", nil,
		"copy security policies from-zone trust to-zone untrust policy a to policy b"); err != nil {
		t.Fatalf("bare policy copy inside allow prefix should be allowed, got %v", err)
	}
	if err := AuthorizeConfigMutation(allowPol, "limited", nil,
		"copy system login user operator to user root"); err == nil {
		t.Fatalf("bare login copy outside allow prefix should be denied")
	}

	// Resolver units: bare resolves under source parent; non-bare and
	// unsegmentable sources are identity (executor keeps its own errors).
	for _, tc := range []struct {
		name string
		src  []string
		dst  []string
		want []string
	}{
		{"bare user", []string{"system", "login", "user", "operator"}, []string{"user", "root"},
			[]string{"system", "login", "user", "root"}},
		{"bare policy", []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "deny-ssh"}, []string{"policy", "deny-ssh-v2"},
			[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "deny-ssh-v2"}},
		{"bare interface", []string{"interfaces", "ge-0/0/0"}, []string{"ge-0/0/2"},
			[]string{"interfaces", "ge-0/0/2"}},
		{"full dst unchanged", []string{"system", "login", "user", "operator"}, []string{"system", "login", "user", "root"},
			[]string{"system", "login", "user", "root"}},
		{"root-level bare unchanged", []string{"system"}, []string{"system2"},
			[]string{"system2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveBareCopyRenameDestination(tc.src, tc.dst); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ResolveBareCopyRenameDestination(%v, %v) = %v, want %v (#15757)", tc.src, tc.dst, got, tc.want)
			}
		})
	}
}
