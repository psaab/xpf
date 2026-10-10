package dhcp

// Regression tests for #6531: a DHCPv6 IA_PD whose IAPREFIX carries a wire
// prefix-length > 128 decoded to a <ip>/0 delegated prefix that was stored and
// then advertised to the downstream LAN as on-link + autonomous.
//
// The insomniacslk/dhcp decoder builds the prefix as
// net.CIDRMask(int(length), 128); net.CIDRMask returns a NIL mask when
// ones > bits, and net.IPMask(nil).Size() is (0, 0). extractDelegatedPrefixes
// read only `ones` and discarded `bits`, so a crafted length of 129..255
// became /0.
//
// These tests drive the REAL WIRE DECODER. The pre-existing IA_PD tests build
// dhcpv6.OptIAPrefix{Prefix: &net.IPNet{Mask: net.CIDRMask(48, 128)}} structs
// directly, which is precisely why this survived: a hand-built struct can only
// hold a mask net.CIDRMask already accepted.
//
// The option bytes here MUST be hand-rolled. OptIAPrefix.ToBytes derives the
// on-wire prefix-length from Prefix.Mask.Size(), so the library's own
// marshaller is structurally incapable of emitting a length > 128 — a
// round-trip through it can never produce the hostile input.
//
// RED-on-revert: restore `ones, _ := prefix.Prefix.Mask.Size()` and drop the
// `bits != 128 || ones == 0` guard in extractDelegatedPrefixes.
// TestIAPDPrefixLen6531_WireBoundaryTable fails on the 129/130/255 rows (each
// yields a live /0), and TestIAPDPrefixLen6531_BadSiblingDoesNotRideAlong,
// TestIAPDPrefixLen6531_BadWithdrawalIsDropped and
// TestIAPDPrefixLen6531_MixedIANAReplyStaysUsable fail as well. Every other
// test in this file is the OVER-REACH guard and must stay GREEN under the
// revert.

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// iaPrefixWire builds the raw bytes of one IAPREFIX (option 26) TLV:
// 4B preferred lifetime | 4B valid lifetime | 1B prefix-length | 16B address.
// prefLen is written verbatim so out-of-range values reach the decoder.
func iaPrefixWire(prefLen uint8, ip string, preferred, valid uint32) []byte {
	body := make([]byte, 0, 25)
	body = binary.BigEndian.AppendUint32(body, preferred)
	body = binary.BigEndian.AppendUint32(body, valid)
	body = append(body, prefLen)
	body = append(body, net.ParseIP(ip).To16()...)

	tlv := make([]byte, 0, 4+len(body))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(dhcpv6.OptionIAPrefix))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(len(body)))
	return append(tlv, body...)
}

// iaAddrWire builds the raw bytes of one IAADDR (option 5) TLV:
// 16B address | 4B preferred lifetime | 4B valid lifetime.
func iaAddrWire(ip string, preferred, valid uint32) []byte {
	body := make([]byte, 0, 24)
	body = append(body, net.ParseIP(ip).To16()...)
	body = binary.BigEndian.AppendUint32(body, preferred)
	body = binary.BigEndian.AppendUint32(body, valid)

	tlv := make([]byte, 0, 4+len(body))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(dhcpv6.OptionIAAddr))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(len(body)))
	return append(tlv, body...)
}

// iaNAWire wraps IAADDR TLVs in an IA_NA (option 3):
// 4B IAID | 4B T1 | 4B T2 | sub-options.
func iaNAWire(inner ...[]byte) []byte {
	body := []byte{0, 0, 0, 1}
	body = binary.BigEndian.AppendUint32(body, 1800)
	body = binary.BigEndian.AppendUint32(body, 2880)
	for _, b := range inner {
		body = append(body, b...)
	}

	tlv := make([]byte, 0, 4+len(body))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(dhcpv6.OptionIANA))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(len(body)))
	return append(tlv, body...)
}

// iaPDWire wraps IAPREFIX TLVs in an IA_PD (option 25):
// 4B IAID | 4B T1 | 4B T2 | sub-options.
func iaPDWire(inner ...[]byte) []byte {
	body := []byte{0, 0, 0, 1}
	body = binary.BigEndian.AppendUint32(body, 1800)
	body = binary.BigEndian.AppendUint32(body, 2880)
	for _, b := range inner {
		body = append(body, b...)
	}

	tlv := make([]byte, 0, 4+len(body))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(dhcpv6.OptionIAPD))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(len(body)))
	return append(tlv, body...)
}

// decodeReplyWire assembles a DHCPv6 Reply from raw option bytes and parses it
// through the production decoder, returning the parsed message.
//
// It asserts the IA_PD and its IAPREFIX sub-options actually SURVIVED the
// parse. Without this the tests would be tautological: if a future library
// version rejected an out-of-range prefix-length at parse time, the
// "no live prefix" assertions below would pass for the wrong reason and stop
// exercising xpf's guard at all.
func decodeReplyWire(t *testing.T, wantPrefixes int, opts ...[]byte) *dhcpv6.Message {
	t.Helper()

	raw := []byte{byte(dhcpv6.MessageTypeReply), 0xab, 0xcd, 0xef}
	for _, o := range opts {
		raw = append(raw, o...)
	}

	msg, err := dhcpv6.MessageFromBytes(raw)
	if err != nil {
		t.Fatalf("MessageFromBytes(% x): %v", raw, err)
	}

	var got int
	for _, o := range msg.Options.Options {
		if pd, ok := o.(*dhcpv6.OptIAPD); ok {
			got += len(pd.Options.Prefixes())
		}
	}
	if got != wantPrefixes {
		t.Fatalf("decoder kept %d IAPREFIX sub-options, want %d — "+
			"the library rejected the option before xpf's guard ran, so this "+
			"test no longer exercises extractDelegatedPrefixes", got, wantPrefixes)
	}
	return msg
}

// The boundary table. Every row is decoded from real wire bytes.
//
// A refused row must produce NO live and NO withdrawn prefix: the entry is
// dropped outright, never re-sorted into the withdrawal set (where a /0 would
// be logged as a server withdrawal that matches nothing).
func TestIAPDPrefixLen6531_WireBoundaryTable(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		prefLen uint8
		want    string // "" => refused
		why     string
	}{
		{
			name:    "length 0 refused",
			prefLen: 0,
			want:    "",
			why: "Refusing a zero-length delegation is an xpf POLICY choice, not " +
				"an RFC prohibition — do not re-justify this row by citation. " +
				"RFC 8415 §21.22 constrains only the CLIENT's outbound hint: the " +
				"client 'SHOULD NOT send an IA Prefix option with 0 in the " +
				"\"prefix-length\" field (and an unspecified value (::) in the " +
				"\"IPv6-prefix\" field)'. It sets no floor on what a server may " +
				"delegate — its only normative statement on the field is " +
				"'prefix-length: Length for this prefix in bits. A 1-octet " +
				"unsigned integer.' And nothing downstream would reject the /0 " +
				"either: RFC 4861 §4.6.2 says a Prefix Information prefix length " +
				"'ranges from 0 to 128'. xpf refuses it because DeriveSubPrefix " +
				"passes a /0 through unchanged and the RA sender then advertises " +
				"::/0 to the LAN as on-link + autonomous. " +
				"Mechanically this row is already GREEN: the library maps a wire " +
				"length of 0 to a nil Prefix, so the pre-existing nil check " +
				"skipped it before and after the fix — the row pins that the /0 " +
				"cannot re-enter through the length-0 door.",
		},
		{
			name:    "length 1 refused for non-unicast coverage",
			prefLen: 1,
			want:    "",
			why: "Although /1 is a contiguous wire mask, it covers address space " +
				"outside the IPv6 global-unicast allocation and therefore cannot " +
				"be accepted as a globally scoped delegation (#10856).",
		},
		{
			name:    "length 48 accepted",
			prefLen: 48,
			want:    "2606:4700:4700:1000::/48",
			why:     "Over-reach guard: a global-unicast /48 must still decode.",
		},
		{
			name:    "length 56 accepted",
			prefLen: 56,
			want:    "2606:4700:4700:1000::/56",
			why:     "Over-reach guard: a global-unicast /56 must still decode.",
		},
		{
			name:    "length 64 accepted",
			prefLen: 64,
			want:    "2606:4700:4700:1000::/64",
			why:     "Over-reach guard: a global-unicast /64 must still decode.",
		},
		{
			name:    "length 128 accepted",
			prefLen: 128,
			want:    "2606:4700:4700:1000::/128",
			why: "Legal: a single-address global-unicast delegation. The upper bound is " +
				"INCLUSIVE — an off-by-one guard (>= 128) would reject it.",
		},
		{
			name:    "length 129 refused",
			prefLen: 129,
			want:    "",
			why: "First out-of-range value. net.CIDRMask(129, 128) is nil, " +
				"Size() is (0,0), and the old code stored 2001:db8:1000::/0.",
		},
		{
			name:    "length 130 refused",
			prefLen: 130,
			want:    "",
			why:     "Same nil-mask decode, one past the first bad value.",
		},
		{
			name:    "length 255 refused",
			prefLen: 255,
			want:    "",
			why:     "Maximum encodable byte; same nil-mask decode.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := decodeReplyWire(t, 1,
				iaPDWire(iaPrefixWire(tc.prefLen, "2606:4700:4700:1000::", 3600, 7200)))

			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", now)

			if tc.want == "" {
				if len(live) != 0 {
					t.Errorf("prefix-length %d must be refused, got live %v (%s)",
						tc.prefLen, live[0].Prefix, tc.why)
				}
				if len(withdrawn) != 0 {
					t.Errorf("prefix-length %d must be dropped outright, "+
						"got withdrawn %v (%s)", tc.prefLen, withdrawn[0].Prefix, tc.why)
				}
				return
			}

			if len(live) != 1 {
				t.Fatalf("prefix-length %d must be accepted, got %d live prefixes (%s)",
					tc.prefLen, len(live), tc.why)
			}
			if got := live[0].Prefix; got != netip.MustParsePrefix(tc.want) {
				t.Errorf("prefix = %s, want %s (%s)", got, tc.want, tc.why)
			}
			if live[0].ValidLifetime != 7200*time.Second {
				t.Errorf("valid lifetime = %s, want 2h0m0s", live[0].ValidLifetime)
			}
		})
	}
}

// A hostile server cannot smuggle a /0 through by pairing the malformed
// IAPREFIX with a well-formed sibling in the SAME IA_PD.
//
// This pins the skip-the-entry policy: the good /56 is honored (a correct
// server would have sent it alone), and the bad entry is dropped — so the
// attacker gains nothing over simply sending the good prefix by itself.
// Both orderings are exercised so the guard cannot be order-sensitive.
func TestIAPDPrefixLen6531_BadSiblingDoesNotRideAlong(t *testing.T) {
	now := time.Now()

	good := func() []byte { return iaPrefixWire(56, "2606:4700:4700:900d::", 3600, 7200) }
	bad := func() []byte { return iaPrefixWire(200, "2001:db8:bad::", 3600, 7200) }

	for _, tc := range []struct {
		name  string
		order [][]byte
	}{
		{"bad first", [][]byte{bad(), good()}},
		{"good first", [][]byte{good(), bad()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := decodeReplyWire(t, 2, iaPDWire(tc.order...))

			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", now)

			if len(live) != 1 {
				t.Fatalf("got %d live prefixes %v, want exactly the good /56", len(live), live)
			}
			if got := live[0].Prefix; got != netip.MustParsePrefix("2606:4700:4700:900d::/56") {
				t.Errorf("live prefix = %s, want 2606:4700:4700:900d::/56", got)
			}
			if len(withdrawn) != 0 {
				t.Errorf("withdrawn = %v, want empty", withdrawn)
			}
			for _, dp := range live {
				if dp.Prefix.Bits() == 0 {
					t.Errorf("a /0 reached the live set: %v", dp.Prefix)
				}
			}
		})
	}
}

// The same guard must cover the WITHDRAWAL path. A malformed IAPREFIX with
// valid-lifetime 0 must not land in the withdrawn set either.
//
// reconcileDelegatedPDs keys its withdrawal set by exact netip.Prefix
// equality, so a /0 withdrawal cannot mass-revoke held prefixes today — but
// letting it through would log a phantom "server withdrew 2001:db8:bad::/0"
// and leave a containment-based matcher one refactor away from a wipe.
func TestIAPDPrefixLen6531_BadWithdrawalIsDropped(t *testing.T) {
	msg := decodeReplyWire(t, 1,
		iaPDWire(iaPrefixWire(129, "2001:db8:bad::", 0, 0)))

	live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now())

	if len(live) != 0 {
		t.Errorf("live = %v, want empty", live)
	}
	if len(withdrawn) != 0 {
		t.Errorf("withdrawn = %v, want empty (a malformed prefix is not a withdrawal)", withdrawn)
	}
}

// What ACTUALLY happens when the skip empties both PD sets, for the common
// mixed ia-na + ia-pd client (#6581 review).
//
// The original fix documented this as "the reply is treated as unusable and
// retried", which is only true for a PD-ONLY client. parseV6Reply's rejection
// requires BOTH no IA_NA address AND no live PD, so a valid IA_NA lets parsing
// SUCCEED even when every IAPREFIX was skipped. This test pins the real
// behavior end-to-end through the production parser, and pins that the real
// behavior is still safe on both counts:
//
//  1. The reply parses cleanly and the IA_NA address installs — dropping a
//     malformed IAPREFIX must not cost the client its v6 address.
//  2. NO prefix reaches either set, so nothing downstream can advertise a /0.
//  3. Empty live+withdrawn is SILENCE to reconcileDelegatedPDs, so a prior
//     delegation is RETAINED verbatim (apply=false, the #1844 anti-outage
//     rule). A hostile server cannot use a malformed IAPREFIX to clear the
//     held set — the attack the "retried" wording obscured.
//
// RED-on-revert (assertions, not a build break): the length-200 IAPREFIX
// becomes a live 2001:db8:bad::/0, so assertion 2 reds ("got 1 live prefix …
// 2001:db8:bad::/0") and assertion 3 reds twice — reconcileDelegatedPDs takes
// the apply=true branch and the /0 lands in the reconciled set alongside the
// held /56.
func TestIAPDPrefixLen6531_MixedIANAReplyStaysUsable(t *testing.T) {
	msg := decodeReplyWire(t, 1,
		iaNAWire(iaAddrWire("2001:db8:a::5", 3600, 7200)),
		iaPDWire(iaPrefixWire(200, "2001:db8:bad::", 3600, 7200)))

	m := NewManagerForTesting(nil)
	res, err := m.parseV6Reply(context.Background(), "wan0", msg,
		&DHCPv6Options{IATypes: []string{"ia-na", "ia-pd"}})

	// 1. The reply is USABLE — not "unusable and retried".
	if err != nil {
		t.Fatalf("parseV6Reply returned %v; a reply whose IA_NA address is valid "+
			"must still parse when every IAPREFIX was skipped — the rejection at "+
			"parseV6Reply requires BOTH no address and no live PD", err)
	}
	if got, want := res.lease.Address, netip.MustParsePrefix("2001:db8:a::5/128"); got != want {
		t.Errorf("lease address = %s, want %s — the IA_NA must survive a "+
			"skipped IAPREFIX", got, want)
	}

	// 2. Nothing reached either PD set.
	if len(res.prefixes) != 0 {
		t.Errorf("got %d live prefixes %v, want 0 — a wire prefix-length of 200 "+
			"must never become a delegated prefix", len(res.prefixes), res.prefixes)
	}
	if len(res.withdrawnPDs) != 0 {
		t.Errorf("got %d withdrawn prefixes %v, want 0", len(res.withdrawnPDs), res.withdrawnPDs)
	}

	// 3. Silence, not withdrawal: the held delegation is retained verbatim.
	prior := []DelegatedPrefix{{
		Interface:     "wan0",
		Prefix:        netip.MustParsePrefix("2001:db8:900d::/56"),
		ValidLifetime: 7200 * time.Second,
	}}
	got, apply := reconcileDelegatedPDs(prior, res.prefixes, res.withdrawnPDs)
	if apply {
		t.Errorf("reconcileDelegatedPDs applied a change (apply=true) for a reply "+
			"whose only IAPREFIX was skipped; empty live+withdrawn is SILENCE and "+
			"must retain the held set untouched (#1844). Reconciled set: %v", got)
	}
	if len(got) != 1 || got[0].Prefix != prior[0].Prefix {
		t.Errorf("reconciled set = %v, want the held %v unchanged", got, prior)
	}
	for _, dp := range got {
		if dp.Prefix.Bits() == 0 {
			t.Errorf("a /0 reached the reconciled PD set: %v", dp.Prefix)
		}
	}
}

// Over-reach guard for the FIRST LEG of the PD → RA chain: wire bytes →
// extractDelegatedPrefixes → DeriveSubPrefix. That is where this leg stops.
//
// It deliberately does NOT claim end-to-end RA coverage (#6581 review): it
// never calls Daemon.buildRAConfigs, never calls ra.buildRA, and never
// marshals an RA. The remaining legs are covered where their seams live —
// pkg/daemon/ra_pd_prefixlen_6531_test.go runs the real buildRAConfigs over a
// stored PD, and pkg/ra/sender_prefixlen_6531_test.go marshals the resulting
// config.RAPrefix and asserts on the re-parsed wire bytes. DeriveSubPrefix is
// the boundary pkg/daemon crosses (daemon_ra.go) to turn a delegated prefix
// into the advertised one, so it is the right handoff point for this leg.
//
// Must stay GREEN under the revert.
func TestIAPDPrefixLen6531_NormalDelegationSurvivesSubPrefixDerivation(t *testing.T) {
	now := time.Now()

	for _, tc := range []struct {
		prefLen    uint8
		delegated  string
		subPrefLen int
		advertised string
	}{
		{56, "2606:4700:4700:9000::/56", 64, "2606:4700:4700:9000::/64"},
		{64, "2606:4700:4700:9000::/64", 64, "2606:4700:4700:9000::/64"},
		{48, "2606:4700:4700:9000::/48", 0, "2606:4700:4700:9000::/48"},
	} {
		t.Run(tc.delegated, func(t *testing.T) {
			msg := decodeReplyWire(t, 1,
				iaPDWire(iaPrefixWire(tc.prefLen, "2606:4700:4700:9000::", 3600, 7200)))

			live, _ := extractDelegatedPrefixes(msg, "wan0", now)
			if len(live) != 1 {
				t.Fatalf("a /%d delegation must decode, got %d live prefixes",
					tc.prefLen, len(live))
			}
			if got := live[0].Prefix; got != netip.MustParsePrefix(tc.delegated) {
				t.Fatalf("delegated = %s, want %s", got, tc.delegated)
			}

			sub := DeriveSubPrefix(live[0].Prefix, tc.subPrefLen)
			if got := sub; got != netip.MustParsePrefix(tc.advertised) {
				t.Errorf("DeriveSubPrefix(%s, %d) = %s, want %s",
					live[0].Prefix, tc.subPrefLen, got, tc.advertised)
			}
			if sub.Bits() == 0 {
				t.Errorf("a legitimate delegation collapsed to a /0: %s", sub)
			}
		})
	}
}
