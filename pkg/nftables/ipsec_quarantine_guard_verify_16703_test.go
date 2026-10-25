package nftables

import (
	"errors"
	"testing"

	gnft "github.com/google/nftables"
)

// #16703: VerifyIpsecQuarantineGuard is the exported re-verification the
// daemon consults after a failed guarded transition. Before the fix the
// only verification was unexported and ran inside the installers, so a
// guard install that itself failed (bridge sdifname EOPNOTSUPP) left
// the daemon assuming a guard existed. Kernel cell: the verifier must
// fail on an empty netns, pass after a lifeline-carrying guard install
// through each entry point, and keep passing for the guard retained by
// a failed guarded transition. Skips without CAP_NET_ADMIN.

func TestIpsecQuarantineGuardVerify16703(t *testing.T) {
	enterPrivateNetns(t)
	in, ok := NewNetlinkInstaller().(*netlinkInstaller)
	if !ok {
		t.Fatal("NewNetlinkInstaller is not *netlinkInstaller")
	}
	if err := in.VerifyIpsecQuarantineGuard(); err == nil {
		t.Fatal("VerifyIpsecQuarantineGuard on empty netns = nil, want missing-guard error")
	}
	spec := IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 11,
		LifelineNetdevs:      []string{"fxp0"},
	}
	if err := in.InstallIpsecQuarantineGuard(spec); err != nil {
		t.Fatalf("InstallIpsecQuarantineGuard with lifelines: %v", err)
	}
	if err := in.VerifyIpsecQuarantineGuard(); err != nil {
		t.Fatalf("VerifyIpsecQuarantineGuard after guard install: %v", err)
	}
	if err := in.InstallIpsecDivert(spec); err != nil {
		t.Fatalf("InstallIpsecDivert quarantine with lifelines: %v", err)
	}
	// A quarantine divert install replaces the divert table under the
	// guard and then removes the guard table: the guard verifier must
	// report it absent (the divert table is the authority then).
	if err := in.VerifyIpsecQuarantineGuard(); err == nil {
		t.Fatal("VerifyIpsecQuarantineGuard after divert quarantine install = nil, want guard-absent error")
	}
	// Guarded transition with a failing drain retains the guard.
	normal := normalDivertSpec16618()
	if err := in.InstallIpsecDivert(normal); err != nil {
		t.Fatalf("seed normal divert: %v", err)
	}
	drainErr := errors.New("injected drain failure")
	if err := in.InstallIpsecDivertWithDrain(normal, func() error { return drainErr }); !errors.Is(err, drainErr) {
		t.Fatalf("guarded transition err = %v, want drain failure", err)
	}
	if err := in.VerifyIpsecQuarantineGuard(); err != nil {
		t.Fatalf("VerifyIpsecQuarantineGuard after failed guarded transition: %v", err)
	}
	// The retained guard's inet input carries fxp0 iif/sdif accepts and
	// the bridge input carries fxp0 iifname with no sdifname (#16703).
	inetRules := readChainRules16618(t, in, gnft.TableFamilyINet, IpsecQuarantineTableName, "input")
	if !rulesContainIfnameAccept16618(inetRules, "fxp0") {
		t.Fatal("retained inet guard input lacks fxp0 iifname ACCEPT")
	}
	if !rulesContainSdifname16618(inetRules) {
		t.Fatal("retained inet guard input lacks sdifname lifeline ACCEPT")
	}
	bridgeRules := readChainRules16618(t, in, gnft.TableFamilyBridge, IpsecQuarantineTableName, "input")
	if rulesContainSdifname16618(bridgeRules) {
		t.Fatal("retained bridge guard input carries sdifname (kernel rejects it)")
	}
	if !rulesContainIfnameAccept16618(bridgeRules, "fxp0") {
		t.Fatal("retained bridge guard input lacks fxp0 iifname ACCEPT")
	}
	// Removal makes the verifier fail again.
	if err := in.RemoveIpsecDivert(); err != nil {
		t.Fatalf("RemoveIpsecDivert: %v", err)
	}
	if err := in.VerifyIpsecQuarantineGuard(); err == nil {
		t.Fatal("VerifyIpsecQuarantineGuard after removal = nil, want missing-guard error")
	}
}
