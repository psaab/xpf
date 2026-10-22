package factoryreset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderedSecret4585 stands in for any prior-tenant secret rendered into a
// service config outside /etc/xpf (BGP MD5 / OSPF / IS-IS routing-auth key, IKE
// PSK, Kea credential). The test proves wipeRenderedConfigs erases every one
// of them so a device yanked/re-tenanted after a factory reset does not hand the
// next owner the prior tenant's secrets.
const renderedSecret4585 = "MARKER-SECRET-4585-routing-auth"

// TestZeroizeRenderedConfigsErasesSecrets pins #4585: the zeroize wipe must
// erase the RENDERED service configs (not just the .configdb SSOT #4582 wipes)
// because a post-zeroize boot enters bootstrap / nil-active-config normal boot
// and SKIPS the reconcile that would otherwise clear them — so the secrets are a
// PERSISTENT residual, not transient.
//
// RED on revert: before this fix wipeRenderedConfigs / StripManagedSectionFile
// did not exist and performWipe removed only .configdb state, so the
// frr.conf managed section (routing-auth keys, mode 0644 world-readable), the
// swanctl PSK snippet, and the Kea configs all SURVIVED the wipe. Each assertion
// below fails on revert.
func TestZeroizeRenderedConfigsErasesSecrets(t *testing.T) {
	dir := t.TempDir()

	// FRR: operator content OUTSIDE the markers + an xpf-managed section that
	// carries a routing-auth secret INSIDE the markers.
	frrConf := filepath.Join(dir, "frr.conf")
	const operatorContent = "hostname r1\nrouter bgp 65000\n ! operator-managed, must survive\n"
	frrBody := operatorContent +
		"! BEGIN BPFRX MANAGED CONFIG - do not edit this section\n" +
		"router ospf\n area 0 authentication message-digest\n" +
		" ip ospf message-digest-key 1 md5 " + renderedSecret4585 + "\n" +
		"! END BPFRX MANAGED CONFIG\n"
	mustWriteFile(t, frrConf, []byte(frrBody))

	// swanctl snippet (IKE PSK) + Kea configs — xpf owns these whole files.
	swanctlSnippet := filepath.Join(dir, "swanctl", "xpf.conf")
	kea4 := filepath.Join(dir, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(dir, "kea", "kea-dhcp6.conf")
	mustWriteFile(t, swanctlSnippet, []byte("secrets {\n ike-peer { secret = "+renderedSecret4585+" }\n}\n"))
	mustWriteFile(t, kea4, []byte(renderedSecret4585))
	mustWriteFile(t, kea6, []byte(renderedSecret4585))

	if err := wipeRenderedConfigs(frrConf, swanctlSnippet, kea4, kea6); err != nil {
		t.Fatalf("wipeRenderedConfigs returned error: %v", err)
	}

	// FRR: the managed section AND its secret are stripped; operator content
	// outside the markers is preserved.
	got, err := os.ReadFile(frrConf)
	if err != nil {
		t.Fatalf("read frr.conf after strip: %v", err)
	}
	if strings.Contains(string(got), renderedSecret4585) {
		t.Errorf("frr.conf still carries the routing-auth secret after zeroize:\n%s", got)
	}
	if strings.Contains(string(got), "BPFRX MANAGED CONFIG") {
		t.Errorf("frr.conf still carries the xpf managed section after zeroize:\n%s", got)
	}
	if !strings.Contains(string(got), "router bgp 65000") {
		t.Errorf("zeroize removed operator content outside the managed section:\n%s", got)
	}

	// swanctl snippet + Kea configs removed outright.
	assertAbsent(t, swanctlSnippet)
	assertAbsent(t, kea4)
	assertAbsent(t, kea6)
}

// TestZeroizeRenderedConfigsLeavesUnmanagedFRRUntouched pins the ownership
// scope: a purely operator-managed frr.conf (no xpf managed section) must be
// left byte-for-byte untouched — the wipe erases xpf-owned secrets, never an
// operator's hand-managed FRR content. Absent swanctl/Kea paths are a clean
// no-op (os.ErrNotExist is excluded, mirroring wipeConfigDir).
func TestZeroizeRenderedConfigsLeavesUnmanagedFRRUntouched(t *testing.T) {
	dir := t.TempDir()
	frrConf := filepath.Join(dir, "frr.conf")
	const operatorOnly = "hostname r1\nrouter bgp 65000\n neighbor 10.0.0.1 password operatorsecret\n"
	mustWriteFile(t, frrConf, []byte(operatorOnly))

	if err := wipeRenderedConfigs(
		frrConf,
		filepath.Join(dir, "absent-swanctl.conf"),
		filepath.Join(dir, "absent-kea4.conf"),
		filepath.Join(dir, "absent-kea6.conf"),
	); err != nil {
		t.Fatalf("wipeRenderedConfigs with absent snippets returned error: %v", err)
	}

	got, err := os.ReadFile(frrConf)
	if err != nil {
		t.Fatalf("read frr.conf: %v", err)
	}
	if string(got) != operatorOnly {
		t.Errorf("zeroize modified an operator-managed frr.conf with no xpf section:\ngot:  %q\nwant: %q", got, operatorOnly)
	}
}
