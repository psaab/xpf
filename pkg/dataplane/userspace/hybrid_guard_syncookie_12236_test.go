package userspace

import "testing"

func TestAuthKeyRotationIsVisibleToHybridGuard12236(t *testing.T) {
	before := synCookieCfg9173(keyedCluster9173("auth-key-before", ""), "", "fw")
	after := synCookieCfg9173(keyedCluster9173("auth-key-after", ""), "", "fw")
	if !sameRedactedMarshal9161(t, before, after) {
		t.Fatal("fixture: primary auth-key rotation changed redacted JSON")
	}
	if configsContentEqual(before, after) {
		t.Fatal("primary auth-key rotation with active SYN-cookie protection compared equal (#12236)")
	}
}

func TestAdditionalAuthKeyRotationIsVisibleToHybridGuard12236(t *testing.T) {
	before := synCookieCfg9173(keyedCluster9173("primary", "additional-before"), "", "fw")
	after := synCookieCfg9173(keyedCluster9173("primary", "additional-after"), "", "fw")
	if !sameRedactedMarshal9161(t, before, after) {
		t.Fatal("fixture: additional auth-key rotation changed redacted JSON")
	}
	if configsContentEqual(before, after) {
		t.Fatal("additional auth-key rotation with active SYN-cookie protection compared equal (#12236)")
	}
}

func TestUnchangedAuthKeyWithCookieProtectionRemainsEqual12236(t *testing.T) {
	before := synCookieCfg9173(keyedCluster9173("auth-key", "additional"), "", "fw")
	after := synCookieCfg9173(keyedCluster9173("auth-key", "additional"), "", "fw")
	if !configsContentEqual(before, after) {
		t.Fatal("unchanged auth-key ring was reported as a helper-visible difference")
	}
}

func TestAuthKeyRotationWithoutCookieProtectionRemainsCoarsened12236(t *testing.T) {
	before := synCookieCfg9173(keyedCluster9173("auth-key-before", ""), "", "fw")
	after := synCookieCfg9173(keyedCluster9173("auth-key-after", ""), "", "fw")
	before.Security.Flow.SynFloodProtectionMode = ""
	after.Security.Flow.SynFloodProtectionMode = ""
	if !sameRedactedMarshal9161(t, before, after) {
		t.Fatal("fixture: inactive-protection auth-key rotation changed redacted JSON")
	}
	if !configsContentEqual(before, after) {
		t.Fatal("auth-key rotation without an installed SYN-cookie ring was reported as a helper-visible difference")
	}
}
