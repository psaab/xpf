package daemon

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestEffectiveLLDPConfigChassis14618 pins the daemon half of #14618:
// effectiveLLDPConfig must carry ONE system chassis MAC (fxp0 first,
// then em0) into LLDPConfig, and fall back to nil (pkg/lldp derives the
// deterministic smallest LLDP-port MAC) when no management MAC exists.
// Without this wiring the lldp-level chassis would still be right via
// the fallback, but it would change whenever the LLDP interface set
// changed — the management MAC is the stable box identity.
func TestEffectiveLLDPConfigChassis14618(t *testing.T) {
	fxp := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xf0}
	em0 := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xe0}

	cfg := &config.Config{}
	cfg.System.HostName = "fw0"
	cfg.Protocols.LLDP = &config.LLDPConfig{
		Interfaces: []config.LLDPInterface{{Name: "ge-0/0/0"}, {Name: "ge-0/0/1"}},
	}

	prev := chassisMACLookup
	t.Cleanup(func() { chassisMACLookup = prev })

	// fxp0 present: it wins over em0.
	chassisMACLookup = func(name string) (net.HardwareAddr, error) {
		switch name {
		case "fxp0":
			return fxp, nil
		case "em0":
			return em0, nil
		}
		return nil, errors.New("not found")
	}
	got := effectiveLLDPConfig(cfg)
	if got == nil {
		t.Fatal("effectiveLLDPConfig = nil, want config")
	}
	if !bytes.Equal(got.ChassisMAC, []byte(fxp)) {
		t.Fatalf("ChassisMAC = %v, want fxp0 MAC %v", got.ChassisMAC, fxp)
	}
	// Deterministic: a second call yields the identical chassis, so the
	// #2372 diff-guard does not re-Apply on every commit.
	if again := effectiveLLDPConfig(cfg); !bytes.Equal(again.ChassisMAC, got.ChassisMAC) {
		t.Fatalf("chassis not deterministic: %v vs %v", again.ChassisMAC, got.ChassisMAC)
	}

	// fxp0 absent: em0 is used.
	chassisMACLookup = func(name string) (net.HardwareAddr, error) {
		if name == "em0" {
			return em0, nil
		}
		return nil, errors.New("not found")
	}
	if got := effectiveLLDPConfig(cfg); !bytes.Equal(got.ChassisMAC, []byte(em0)) {
		t.Fatalf("ChassisMAC = %v, want em0 MAC %v", got.ChassisMAC, em0)
	}

	// Neither: nil, delegating to the pkg/lldp fallback.
	chassisMACLookup = func(string) (net.HardwareAddr, error) {
		return nil, errors.New("not found")
	}
	if got := effectiveLLDPConfig(cfg); got.ChassisMAC != nil {
		t.Fatalf("ChassisMAC = %v, want nil fallback delegation", got.ChassisMAC)
	}

	// Zero/short management MACs are not usable chassis IDs.
	chassisMACLookup = func(name string) (net.HardwareAddr, error) {
		if name == "fxp0" {
			return net.HardwareAddr{0, 0, 0, 0, 0, 0}, nil
		}
		return net.HardwareAddr{0x01, 0x02}, nil
	}
	if got := effectiveLLDPConfig(cfg); got.ChassisMAC != nil {
		t.Fatalf("zero/short MAC must not become chassis, got %v", got.ChassisMAC)
	}
}
