package dhcp

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func TestExtractDelegatedPrefixes(t *testing.T) {
	now := time.Now()

	t.Run("single prefix", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply

		iapd := &dhcpv6.OptIAPD{
			IaId: [4]byte{0, 0, 0, 1},
		}
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
			Prefix: &net.IPNet{
				IP:   net.ParseIP("2606:4700:4700::"),
				Mask: net.CIDRMask(48, 128),
			},
		})
		msg.AddOption(iapd)

		pds, _ := extractDelegatedPrefixes(msg, "wan0", now)
		if len(pds) != 1 {
			t.Fatalf("got %d prefixes, want 1", len(pds))
		}
		want := netip.MustParsePrefix("2606:4700:4700::/48")
		if pds[0].Prefix != want {
			t.Errorf("prefix = %s, want %s", pds[0].Prefix, want)
		}
		if pds[0].PreferredLifetime != 3600*time.Second {
			t.Errorf("preferred = %s, want 1h0m0s", pds[0].PreferredLifetime)
		}
		if pds[0].ValidLifetime != 7200*time.Second {
			t.Errorf("valid = %s, want 2h0m0s", pds[0].ValidLifetime)
		}
		if pds[0].Interface != "wan0" {
			t.Errorf("interface = %q, want wan0", pds[0].Interface)
		}
	})

	t.Run("no IA_PD", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply

		pds, _ := extractDelegatedPrefixes(msg, "wan0", now)
		if len(pds) != 0 {
			t.Errorf("got %d prefixes, want 0", len(pds))
		}
	})

	t.Run("multiple prefixes", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply

		iapd := &dhcpv6.OptIAPD{
			IaId: [4]byte{0, 0, 0, 1},
		}
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
			Prefix: &net.IPNet{
				IP:   net.ParseIP("2606:4700:4700::"),
				Mask: net.CIDRMask(48, 128),
			},
		})
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 1800 * time.Second,
			ValidLifetime:     3600 * time.Second,
			Prefix: &net.IPNet{
				IP:   net.ParseIP("2606:4700:4700:2000::"),
				Mask: net.CIDRMask(56, 128),
			},
		})
		msg.AddOption(iapd)

		pds, _ := extractDelegatedPrefixes(msg, "wan0", now)
		if len(pds) != 2 {
			t.Fatalf("got %d prefixes, want 2", len(pds))
		}
		if pds[1].Prefix != netip.MustParsePrefix("2606:4700:4700:2000::/56") {
			t.Errorf("second prefix = %s, want 2606:4700:4700:2000::/56", pds[1].Prefix)
		}
	})
}

func TestDelegatedPrefixes(t *testing.T) {
	m := &Manager{
		delegatedPDs: map[string][]DelegatedPrefix{
			"wan0": {
				{Interface: "wan0", Prefix: netip.MustParsePrefix("2001:db8::/48")},
			},
			"wan1": {
				{Interface: "wan1", Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
				{Interface: "wan1", Prefix: netip.MustParsePrefix("2001:db8:2::/56")},
			},
		},
	}

	pds := m.DelegatedPrefixes()
	if len(pds) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(pds))
	}
}

func TestBuildDHCPv6Modifiers(t *testing.T) {
	m := &Manager{
		duids:     make(map[string]dhcpv6.DUID),
		duidTypes: make(map[string]string),
		v6opts:    make(map[string]*DHCPv6Options),
	}

	t.Run("nil opts", func(t *testing.T) {
		// Post-#5711 contract: even with no configured DHCPv6 options, the
		// modifiers MUST carry the persistent Client-ID DUID so acquisition
		// and renewal present the same identity. Seed a known DUID so getDUID
		// resolves deterministically from the in-memory cache — independent of
		// whether an "eth0" happens to exist on the test host (the old
		// len(mods)==0 assertion only passed because getDUID errored on a host
		// with no eth0; on a host with one it would have failed).
		want := &dhcpv6.DUIDLL{
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		}
		m.duids["eth0"] = want
		defer delete(m.duids, "eth0")

		mods := m.buildDHCPv6Modifiers("eth0", nil)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}
		got := msg.Options.ClientID()
		if got == nil {
			t.Fatal("nil opts must still attach the persistent Client-ID DUID (#5711)")
		}
		if !bytes.Equal(got.ToBytes(), want.ToBytes()) {
			t.Errorf("Client-ID DUID = %x, want %x", got.ToBytes(), want.ToBytes())
		}
	})

	t.Run("ia-pd with hint", func(t *testing.T) {
		opts := &DHCPv6Options{
			IATypes:   []string{"ia-pd"},
			PDPrefLen: 56,
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		found := false
		for _, opt := range msg.Options.Options {
			if _, ok := opt.(*dhcpv6.OptIAPD); ok {
				found = true
			}
		}
		if !found {
			t.Error("IA_PD option not found")
		}
	})

	t.Run("ia-pd without hint", func(t *testing.T) {
		opts := &DHCPv6Options{
			IATypes:   []string{"ia-pd"},
			PDPrefLen: 0,
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		found := false
		for _, opt := range msg.Options.Options {
			if _, ok := opt.(*dhcpv6.OptIAPD); ok {
				found = true
			}
		}
		if !found {
			t.Error("IA_PD option should be present even without hint")
		}
	})

	t.Run("requested options", func(t *testing.T) {
		opts := &DHCPv6Options{
			ReqOptions: []string{"dns-server", "domain-name"},
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		oro := msg.Options.RequestedOptions()
		hasDNS, hasDomain := false, false
		for _, code := range oro {
			if code == dhcpv6.OptionDNSRecursiveNameServer {
				hasDNS = true
			}
			if code == dhcpv6.OptionDomainSearchList {
				hasDomain = true
			}
		}
		if !hasDNS {
			t.Error("DNS option not in ORO")
		}
		if !hasDomain {
			t.Error("Domain option not in ORO")
		}
	})

	t.Run("both ia types with req opts", func(t *testing.T) {
		opts := &DHCPv6Options{
			IATypes:    []string{"ia-na", "ia-pd"},
			PDPrefLen:  60,
			ReqOptions: []string{"dns-server"},
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		hasIAPD := false
		for _, opt := range msg.Options.Options {
			if _, ok := opt.(*dhcpv6.OptIAPD); ok {
				hasIAPD = true
			}
		}
		if !hasIAPD {
			t.Error("IA_PD not found when both ia types requested")
		}
	})
}

func TestDeriveSubPrefix(t *testing.T) {
	tests := []struct {
		name       string
		delegated  string
		subPrefLen int
		want       string // empty = invalid
	}{
		{
			name:       "48 to 64",
			delegated:  "2001:db8:1000::/48",
			subPrefLen: 64,
			want:       "2001:db8:1000::/64",
		},
		{
			name:       "56 to 64",
			delegated:  "2001:db8:1000::/56",
			subPrefLen: 64,
			want:       "2001:db8:1000::/64",
		},
		{
			name:       "sub_len 0 returns delegated as-is",
			delegated:  "2001:db8:1000::/48",
			subPrefLen: 0,
			want:       "2001:db8:1000::/48",
		},
		{
			name:       "same length returns as-is",
			delegated:  "2001:db8:1000::/64",
			subPrefLen: 64,
			want:       "2001:db8:1000::/64",
		},
		{
			name:       "already 64 with sub_len 0",
			delegated:  "2001:db8:abcd:ef00::/64",
			subPrefLen: 0,
			want:       "2001:db8:abcd:ef00::/64",
		},
		{
			name:       "shorter sub_len invalid",
			delegated:  "2001:db8:1000::/64",
			subPrefLen: 48,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delegated := netip.MustParsePrefix(tt.delegated)
			got := DeriveSubPrefix(delegated, tt.subPrefLen)
			if tt.want == "" {
				if got.IsValid() {
					t.Errorf("DeriveSubPrefix(%s, %d) = %s, want invalid", tt.delegated, tt.subPrefLen, got)
				}
				return
			}
			want := netip.MustParsePrefix(tt.want)
			if got != want {
				t.Errorf("DeriveSubPrefix(%s, %d) = %s, want %s", tt.delegated, tt.subPrefLen, got, want)
			}
		})
	}
}

func TestDelegatedPrefixesForRA(t *testing.T) {
	m := &Manager{
		delegatedPDs: map[string][]DelegatedPrefix{
			"wan0": {
				{Interface: "wan0", Prefix: netip.MustParsePrefix("2001:db8::/48")},
			},
			"wan1": {
				{Interface: "wan1", Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
			},
		},
		v6opts: map[string]*DHCPv6Options{
			"wan0": {RAIface: "trust0", PDSubLen: 64},
			"wan1": {RAIface: ""}, // no RA interface
		},
	}

	mappings := m.DelegatedPrefixesForRA()
	if len(mappings) != 1 {
		t.Fatalf("got %d mappings, want 1", len(mappings))
	}
	if mappings[0].RAIface != "trust0" {
		t.Errorf("RAIface = %q, want trust0", mappings[0].RAIface)
	}
	if mappings[0].SubPrefLen != 64 {
		t.Errorf("SubPrefLen = %d, want 64", mappings[0].SubPrefLen)
	}
	if mappings[0].Interface != "wan0" {
		t.Errorf("Interface = %q, want wan0", mappings[0].Interface)
	}
}

func TestDHCPv6OptionsSetGet(t *testing.T) {
	m := &Manager{
		v6opts: make(map[string]*DHCPv6Options),
	}

	opts := &DHCPv6Options{
		IATypes:    []string{"ia-na", "ia-pd"},
		PDPrefLen:  60,
		PDSubLen:   64,
		ReqOptions: []string{"dns-server"},
		RAIface:    "trust0",
	}

	m.SetDHCPv6Options("wan0", opts)

	m.mu.Lock()
	got := m.v6opts["wan0"]
	m.mu.Unlock()

	if got == nil {
		t.Fatal("v6opts not set")
	}
	if len(got.IATypes) != 2 {
		t.Errorf("IATypes = %v, want [ia-na ia-pd]", got.IATypes)
	}
	if got.PDPrefLen != 60 {
		t.Errorf("PDPrefLen = %d, want 60", got.PDPrefLen)
	}
	if got.RAIface != "trust0" {
		t.Errorf("RAIface = %q, want trust0", got.RAIface)
	}
}
