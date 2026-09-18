package dhcpserver

import "testing"

func TestApplyAsyncWithLeaseAuthorityPublishesPerFamilyProof10170(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	authority := LeaseApplyAuthority{
		Generation: 42,
		Scopes4:    []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.1.0/24", RGID: 2}},
	}
	m.ApplyAsyncWithLeaseAuthority(v4Config("ge-0-0-0"), "authority-test", authority)
	waitForCondition(t, "authority-bearing async apply", func() bool {
		generation, _, _ := m.LeaseAuthorityResult(4)
		return generation == authority.Generation
	})
	generation, scopes, applied := m.LeaseAuthorityResult(4)
	if generation != 42 || !applied || len(scopes) != 1 || !scopes[0].Applied || scopes[0].Generation != 42 {
		t.Fatalf("successful v4 apply did not publish bound proof: generation=%d scopes=%+v applied=%v", generation, scopes, applied)
	}

	generation, scopes, applied = m.LeaseAuthorityResult(6)
	if generation != 42 || !applied || len(scopes) != 0 {
		t.Fatalf("successful unconfigured v6 branch did not publish its result: generation=%d scopes=%+v applied=%v", generation, scopes, applied)
	}
}

func TestApplyAsyncWithLeaseAuthorityFailureInvalidatesFamilyProof10170(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "restart "+kea4Svc)
	authority := LeaseApplyAuthority{
		Generation: 43,
		Scopes4:    []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.1.0/24", RGID: 2}},
	}
	m.ApplyAsyncWithLeaseAuthority(v4Config("ge-0-0-0"), "authority-failure-test", authority)
	waitForCondition(t, "failed authority-bearing async apply", func() bool {
		generation, _, _ := m.LeaseAuthorityResult(4)
		return generation == authority.Generation
	})
	generation, scopes, applied := m.LeaseAuthorityResult(4)
	if generation != 43 || applied || len(scopes) != 1 || scopes[0].Applied {
		t.Fatalf("failed v4 apply retained proof: generation=%d scopes=%+v applied=%v", generation, scopes, applied)
	}
}

func TestApplyClusterCommitWithLeaseAuthorityPublishesProof10170(t *testing.T) {
	m, _ := testManager(t, map[string]bool{kea4Svc: true}, "")
	authority := LeaseApplyAuthority{
		Generation: 44,
		Scopes4:    []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.1.0/24", RGID: 2, Served: true}},
	}
	if err := m.ApplyClusterCommitWithLeaseAuthority(v4Config("ge-0-0-0"), authority); err != nil {
		t.Fatalf("authority-bearing cluster commit failed: %v", err)
	}
	generation, scopes, applied := m.LeaseAuthorityResult(4)
	if generation != 44 || !applied || len(scopes) != 1 || !scopes[0].Applied {
		t.Fatalf("cluster commit did not publish bound proof: generation=%d scopes=%+v applied=%v", generation, scopes, applied)
	}
}

func TestApplyClusterCommitWithLeaseAuthorityDoesNotProveInactiveUnit10170(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	authority := LeaseApplyAuthority{
		Generation: 45,
		Scopes4:    []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.1.0/24", RGID: 2, Served: true}},
	}
	if err := m.ApplyClusterCommitWithLeaseAuthority(v4Config("ge-0-0-0"), authority); err != nil {
		t.Fatalf("inactive authority-bearing cluster commit failed: %v", err)
	}
	generation, scopes, applied := m.LeaseAuthorityResult(4)
	if generation != 45 || applied || len(scopes) != 1 || !scopes[0].Served || scopes[0].Applied {
		t.Fatalf("inactive unit was advertised as an applied served authority: generation=%d scopes=%+v applied=%v", generation, scopes, applied)
	}
}

func TestApplyAsyncWithLeaseAuthorityAfterShutdownCannotReproveServing10170(t *testing.T) {
	m, _ := testManager(t, map[string]bool{kea4Svc: true}, "")
	if err := m.Shutdown(); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
	authority := LeaseApplyAuthority{
		Generation: 46,
		Scopes4:    []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.1.0/24", RGID: 2, Served: true}},
	}
	m.ApplyAsyncWithLeaseAuthority(v4Config("ge-0-0-0"), "late-authority-after-shutdown", authority)
	waitForCondition(t, "late authority-bearing shutdown apply", func() bool {
		generation, _, _ := m.LeaseAuthorityResult(4)
		return generation == authority.Generation
	})
	generation, scopes, applied := m.LeaseAuthorityResult(4)
	if generation != 46 || applied || len(scopes) != 1 || scopes[0].Served || scopes[0].Applied {
		t.Fatalf("shutdown-latched apply re-proved serving authority: generation=%d scopes=%+v applied=%v", generation, scopes, applied)
	}
}
