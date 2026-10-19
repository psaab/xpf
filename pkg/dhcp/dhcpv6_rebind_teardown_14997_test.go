package dhcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// #14997 (D40-03): a DHCPv6 REBIND Reply from a non-granting server was
// accepted on transaction/client-DUID alone and its contents trusted to
// tear down the held lease and IA_PD delegation in one packet:
//   - IA_PD NoPrefixAvail from the new server cleared every held prefix
//     (run-loop pdRefused arm), although that server never granted them
//     and holds no binding for this client (RFC 8415 SS18.2.5 lets any
//     server answer a Rebind, but only about bindings it actually has);
//   - IA_NA/IA_PD valid-lifetime 0 from the new server deconfigured the
//     held address (errV6AddrInvalidated) and withdrew held prefixes,
//     although RFC 8415 SS18.2.10.1/SS12.1 teardown directives are only
//     meaningful from the server that granted the binding.
// RFC 8415 SS18.2.10/SS21 forbids moving to a different server on a Reply
// received during Renew/Rebind processing at all; xpf deliberately keeps
// the #14600 failover behaviour (a partner may EXTEND the binding and
// becomes the next RENEW server), so the fix keeps extension from any
// server but requires the granting server for every destructive content
// class on a REBIND Reply. RENEW already binds the granting server.
//
// Fail-on-revert: dropping the RENEW/REBIND content gate in
// v6RenewMatcher turns the attacker cells below GREEN again (matcher
// accepts, held PD cleared / address invalidated); the partner-extension
// and granting-teardown controls pin that legitimate behaviour survives.

var (
	v6TeardownClientDUID   = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	v6TeardownGrantDUID    = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}}
	v6TeardownPartnerDUID  = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 3}}
	v6TeardownAttackerDUID = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}}
)

func v6TeardownPrev() (*Lease, []DelegatedPrefix) {
	prev := &Lease{
		Interface:    "wan0",
		Family:       AFInet6,
		Address:      netip.MustParsePrefix("2606:4700::50/128"),
		LeaseTime:    time.Hour,
		Obtained:     time.Now(),
		v6ServerDUID: v6TeardownGrantDUID,
	}
	pds := []DelegatedPrefix{{
		Interface: "wan0", Prefix: netip.MustParsePrefix("2606:4700:1000::/48"),
		PreferredLifetime: time.Hour, ValidLifetime: time.Hour, Obtained: time.Now(),
	}}
	return prev, pds
}

func v6TeardownRequest(t *testing.T, prev *Lease, pds []DelegatedPrefix, rebind bool) *dhcpv6.Message {
	t.Helper()
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	req, err := buildV6RenewMessage(hw, prev, pds, rebind, []dhcpv6.Modifier{dhcpv6.WithClientID(v6TeardownClientDUID)}, nil, nil)
	if err != nil {
		t.Fatalf("build renew/rebind: %v", err)
	}
	return req
}

func v6TeardownReply(t *testing.T, xid dhcpv6.TransactionID, server dhcpv6.DUID, build func(*dhcpv6.Message)) *dhcpv6.Message {
	t.Helper()
	msg, err := dhcpv6.NewMessage(dhcpv6.WithClientID(v6TeardownClientDUID), dhcpv6.WithServerID(server))
	if err != nil {
		t.Fatalf("build Reply: %v", err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	msg.TransactionID = xid
	if build != nil {
		build(msg)
	}
	return msg
}

func v6TeardownHeldNA(id [4]byte, lifetime time.Duration) dhcpv6.Option {
	ia := &dhcpv6.OptIANA{IaId: id}
	ia.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr: net.ParseIP("2606:4700::50"), PreferredLifetime: lifetime, ValidLifetime: lifetime,
	})
	return ia
}

func v6TeardownBuildNoPrefixAvail(msg *dhcpv6.Message) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	msg.AddOption(v6TeardownHeldNA(v6IANAIAID(hw), time.Hour))
	pd := &dhcpv6.OptIAPD{IaId: v6IAPDIAID}
	pd.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail, StatusMessage: "no prefixes"})
	msg.AddOption(pd)
}

func v6TeardownBuildWithdrawAll(msg *dhcpv6.Message) {
	msg.AddOption(v6TeardownHeldNA(v6IANAIAID(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}), 0))
	pd := &dhcpv6.OptIAPD{IaId: v6IAPDIAID}
	pd.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: 0, ValidLifetime: 0,
		Prefix: &net.IPNet{IP: net.ParseIP("2606:4700:1000::"), Mask: net.CIDRMask(48, 128)},
	})
	msg.AddOption(pd)
}

func v6TeardownBuildNoBinding(msg *dhcpv6.Message) {
	ia := &dhcpv6.OptIANA{IaId: v6IANAIAID(net.HardwareAddr{0x02, 0, 0, 0, 0, 1})}
	ia.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoBinding, StatusMessage: "no binding"})
	ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2606:4700::50")})
	msg.AddOption(ia)
	pd := &dhcpv6.OptIAPD{IaId: v6IAPDIAID}
	pd.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoBinding, StatusMessage: "no binding"})
	msg.AddOption(pd)
}

func v6TeardownBuildZeroAddress(msg *dhcpv6.Message) {
	msg.AddOption(v6TeardownHeldNA(v6IANAIAID(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}), 0))
}

func v6TeardownBuildMessageFailure(msg *dhcpv6.Message) {
	msg.AddOption(&dhcpv6.OptStatusCode{StatusCode: iana.StatusUnspecFail, StatusMessage: "failed"})
	msg.AddOption(v6TeardownHeldNA(v6IANAIAID(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}), time.Hour))
}

func v6TeardownBuildExtension(msg *dhcpv6.Message) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	msg.AddOption(v6TeardownHeldNA(v6IANAIAID(hw), time.Hour))
	pd := &dhcpv6.OptIAPD{IaId: v6IAPDIAID}
	pd.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: time.Hour, ValidLifetime: time.Hour,
		Prefix: &net.IPNet{IP: net.ParseIP("2606:4700:1000::"), Mask: net.CIDRMask(48, 128)},
	})
	msg.AddOption(pd)
}

// TestV6RebindNonGrantingTeardownRejected14997 is the D40-03 regression:
// every destructive Reply class from a non-granting REBIND responder is
// rejected at the matcher, so the run loop never sees it and the held
// lease/PD survive untouched.
func TestV6RebindNonGrantingTeardownRejected14997(t *testing.T) {
	prev, pds := v6TeardownPrev()
	req := v6TeardownRequest(t, prev, pds, true)

	destructive := map[string]func(*dhcpv6.Message){
		"IA_PD NoPrefixAvail refusal":   v6TeardownBuildNoPrefixAvail,
		"zero-lifetime IA_NA and IA_PD": v6TeardownBuildWithdrawAll,
		"NoBinding IA_NA and IA_PD":     v6TeardownBuildNoBinding,
		"zero-lifetime held IA_NA only": v6TeardownBuildZeroAddress,
		"message-level failure status":  v6TeardownBuildMessageFailure,
	}
	for name, build := range destructive {
		t.Run(name, func(t *testing.T) {
			mgr := &Manager{}
			reply := v6TeardownReply(t, req.TransactionID, v6TeardownAttackerDUID, build)
			if v6RenewMatcher(mgr, req, prev, true)(reply) {
				t.Errorf("REBIND %s from non-granting server accepted; one spoofed packet must not tear down the lease/PD", name)
			}
			if got := mgr.RenewalBindingStats().DHCPv6TeardownRejects; got != 1 {
				t.Errorf("teardown rejects = %d, want 1", got)
			}
			if got := mgr.RenewalBindingStats().DHCPv6ServerIdentityRejects; got != 0 {
				t.Errorf("server-identity rejects = %d, want 0 (content gate, not identity gate)", got)
			}
		})
	}
}

// TestV6RebindPartnerExtensionStillAccepted14997 is the adjacent control:
// the #14600 failover behaviour survives — a partner (or the granting
// server) may extend the held bindings on REBIND, and the granting
// server may still tear them down; a non-granting RENEW teardown stays
// rejected by the pre-existing server binding.
func TestV6RebindPartnerExtensionStillAccepted14997(t *testing.T) {
	prev, pds := v6TeardownPrev()

	t.Run("partner extension on REBIND", func(t *testing.T) {
		req := v6TeardownRequest(t, prev, pds, true)
		mgr := &Manager{}
		reply := v6TeardownReply(t, req.TransactionID, v6TeardownPartnerDUID, v6TeardownBuildExtension)
		if !v6RenewMatcher(mgr, req, prev, true)(reply) {
			t.Fatal("partner REBIND extension rejected; #14600 any-server extension must keep working")
		}
		hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
		naID := v6IANAIAID(hw)
		res, err := (&Manager{}).parseV6ReplyChecked(context.Background(), "wan0", reply,
			&DHCPv6Options{IATypes: []string{"ia-na", "ia-pd"}}, &naID, &v6IAPDIAID)
		if err != nil {
			t.Fatalf("parse partner extension: %v", err)
		}
		if res.lease.Address != prev.Address {
			t.Errorf("extended address = %s, want held %s", res.lease.Address, prev.Address)
		}
		if !sameDUID(res.lease.v6ServerDUID, v6TeardownPartnerDUID) {
			t.Errorf("stored server DUID = %v, want partner (next RENEW binding)", res.lease.v6ServerDUID)
		}
		rec, apply := reconcileDelegatedPDs(pds, res.prefixes, res.withdrawnPDs)
		if !apply || len(rec) != 1 || rec[0].Prefix != pds[0].Prefix {
			t.Errorf("reconciled PDs = %v apply=%v, want held prefix extended", rec, apply)
		}
		if got := mgr.RenewalBindingStats().DHCPv6TeardownRejects; got != 0 {
			t.Errorf("teardown rejects = %d, want 0 for a pure extension", got)
		}
	})

	t.Run("granting extension on REBIND", func(t *testing.T) {
		req := v6TeardownRequest(t, prev, pds, true)
		reply := v6TeardownReply(t, req.TransactionID, v6TeardownGrantDUID, v6TeardownBuildExtension)
		if !v6RenewMatcher(&Manager{}, req, prev, true)(reply) {
			t.Fatal("granting-server REBIND extension rejected")
		}
	})

	for name, build := range map[string]func(*dhcpv6.Message){
		"granting NoPrefixAvail on REBIND": v6TeardownBuildNoPrefixAvail,
		"granting zero-lifetime on REBIND": v6TeardownBuildWithdrawAll,
		"granting NoBinding on REBIND":     v6TeardownBuildNoBinding,
	} {
		t.Run(name, func(t *testing.T) {
			req := v6TeardownRequest(t, prev, pds, true)
			reply := v6TeardownReply(t, req.TransactionID, v6TeardownGrantDUID, build)
			if !v6RenewMatcher(&Manager{}, req, prev, true)(reply) {
				t.Errorf("%s rejected; the granting server's explicit teardown must keep working", name)
			}
		})
	}

	t.Run("granting teardown on RENEW", func(t *testing.T) {
		req := v6TeardownRequest(t, prev, pds, false)
		reply := v6TeardownReply(t, req.TransactionID, v6TeardownGrantDUID, v6TeardownBuildNoPrefixAvail)
		if !v6RenewMatcher(&Manager{}, req, prev, false)(reply) {
			t.Fatal("granting-server RENEW Reply rejected")
		}
	})

	t.Run("partner teardown on RENEW stays identity-rejected", func(t *testing.T) {
		req := v6TeardownRequest(t, prev, pds, false)
		mgr := &Manager{}
		reply := v6TeardownReply(t, req.TransactionID, v6TeardownPartnerDUID, v6TeardownBuildNoPrefixAvail)
		if v6RenewMatcher(mgr, req, prev, false)(reply) {
			t.Fatal("partner RENEW teardown accepted; RENEW stays bound to the granting server")
		}
		if got := mgr.RenewalBindingStats().DHCPv6ServerIdentityRejects; got != 1 {
			t.Errorf("server-identity rejects = %d, want 1", got)
		}
		if got := mgr.RenewalBindingStats().DHCPv6TeardownRejects; got != 0 {
			t.Errorf("teardown rejects = %d, want 0 (identity gate fires first)", got)
		}
	})
}
