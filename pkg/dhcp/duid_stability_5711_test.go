package dhcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// firstHWIface returns a local interface whose hardware address is at least 4
// bytes long — dhcpv6.NewSolicit derives the IA_NA IAID from the last 4 MAC
// bytes and errors on a shorter address, so loopback (empty MAC) will not do.
// Skips the test when no such interface exists.
func firstHWIface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("enumerate interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if len(ifc.HardwareAddr) >= 4 {
			return ifc
		}
	}
	t.Skip("no interface with a >=4-byte hardware address available")
	return net.Interface{}
}

// clientIDBytes rebuilds the SOLICIT the acquisition path actually sends
// (dhcpv6.NewSolicit + WithRapidCommit, mirroring nclient6.RapidSolicit) and
// the RENEW the renewal path sends (buildV6RenewMessage), then returns the
// Client-ID DUID bytes each presents on the wire.
func acquisitionDUID(t *testing.T, m *Manager, ifc net.Interface) []byte {
	t.Helper()
	mods := m.buildDHCPv6Modifiers(ifc.Name, nil)
	sol, err := dhcpv6.NewSolicit(ifc.HardwareAddr, append(mods, dhcpv6.WithRapidCommit)...)
	if err != nil {
		t.Fatalf("build acquisition SOLICIT: %v", err)
	}
	duid := sol.Options.ClientID()
	if duid == nil {
		t.Fatal("acquisition SOLICIT carries no Client-ID")
	}
	return duid.ToBytes()
}

func renewalDUID(t *testing.T, m *Manager, ifc net.Interface) []byte {
	t.Helper()
	renewMods := m.buildDHCPv6RenewModifiers(ifc.Name, nil)
	msg, err := buildV6RenewMessage(ifc.HardwareAddr, nil, nil, false, renewMods, nil, nil)
	if err != nil {
		t.Fatalf("build RENEW: %v", err)
	}
	duid := msg.Options.ClientID()
	if duid == nil {
		t.Fatal("RENEW carries no Client-ID")
	}
	return duid.ToBytes()
}

// TestDHCPv6DUIDStableAcrossAcquisitionAndRenew pins #5711: the DUID a bare
// DHCPv6 client presents at initial acquisition (SOLICIT) MUST be byte-identical
// to the DUID it presents at RENEW/REBIND. RFC 8415 §11 requires a stable
// client DUID for the client's lifetime; the server binds the lease to it, so a
// renewal sent under a different DUID is a new client and the original lease is
// not renewed.
//
// RED on revert: before the fix, buildDHCPv6Modifiers returned nil when
// opts == nil, so RapidSolicit/NewSolicit fell back to its default DUID-LLT
// (Time = GetTime() at send) while the renew path always used the persistent
// getDUID (default DUID-LL). Acquisition presented a DUID-LLT and renewal a
// DUID-LL — different type and different bytes — and this assertion fails.
func TestDHCPv6DUIDStableAcrossAcquisitionAndRenew(t *testing.T) {
	ifc := firstHWIface(t)

	// Default DUID type (empty -> DUID-LL). Both paths must read the same
	// persistent identity.
	m := &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{},
		stateDir:  t.TempDir(),
	}

	acq := acquisitionDUID(t, m, ifc)
	renew := renewalDUID(t, m, ifc)
	if !bytes.Equal(acq, renew) {
		t.Fatalf("DUID diverges between acquisition and renewal:\n  acquisition=%x\n  renewal    =%x", acq, renew)
	}
}

// TestDHCPv6DUIDLLTStableAcrossAcquisitionAndRenew is the DUID-LLT companion to
// the above. A DUID-LLT embeds a generation timestamp; the stable identity must
// come from the once-generated, persisted DUID-LLT — the same Time on every
// message — NOT a per-message GetTime().
//
// This models the real production timeline: the DUID-LLT is generated and
// persisted at boot (T0), and a RENEW fires hours later (T1). We seed the
// persistent DUID-LLT with a Time set an hour in the PAST so it is clearly
// distinct from a fresh GetTime() stamped at send. getDUID returns this cached
// identity to both paths.
//
// RED on revert: with the fix neutralized (opts == nil -> nil mods),
// acquisition falls through to dhcpv6.NewSolicit's default DUID-LLT whose Time
// is GetTime() ≈ now, while the renew path presents the persisted DUID-LLT with
// Time ≈ now-3600. Same DUID *type*, but the Time field (and thus the bytes)
// differ by ~3600 — so the assertion flips RED. A naive "generate the LLT via
// getDUID and compare" would NOT flip, because the default-at-send Time and a
// just-generated persisted Time collapse to the same whole second.
func TestDHCPv6DUIDLLTStableAcrossAcquisitionAndRenew(t *testing.T) {
	ifc := firstHWIface(t)

	// Persisted-at-boot DUID-LLT, Time one hour ago (relative to the dhcpv6
	// 2000-01-01 epoch getDUID/GetTime both use). Seed the in-memory cache so
	// getDUID returns exactly this identity for both paths.
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	pastTime := uint32(time.Since(epoch).Seconds()) - 3600 // an hour before "now"
	persisted := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          pastTime,
		LinkLayerAddr: ifc.HardwareAddr,
	}
	m := &Manager{
		duids:     map[string]dhcpv6.DUID{ifc.Name: persisted},
		duidTypes: map[string]string{ifc.Name: "duid-llt"},
		stateDir:  t.TempDir(),
	}

	acq := acquisitionDUID(t, m, ifc)
	renew := renewalDUID(t, m, ifc)
	if !bytes.Equal(acq, renew) {
		t.Fatalf("DUID-LLT diverges between acquisition and renewal (per-message GetTime() vs persisted Time?):\n  acquisition=%x\n  renewal    =%x", acq, renew)
	}

	// Both paths must present the persisted DUID-LLT byte-for-byte (including
	// the past Time), not a silently substituted default-at-send LLT.
	if want := persisted.ToBytes(); !bytes.Equal(acq, want) {
		t.Fatalf("acquisition DUID-LLT is not the persisted identity:\n  got  =%x\n  want =%x", acq, want)
	}
}
