// #15675: a tolerated `port no-translation` + `port deterministic`
// pool must not emit deterministic wire fields (strict compile rejects
// the combination; the builder guard keeps the lenient path honest).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestDeterministicFieldsSuppressedNoTranslation_15675(t *testing.T) {
	pool := &config.NATPool{
		Name:              "p1",
		PortNoTranslation: true,
		Deterministic:     &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "10.0.0.0/24"},
	}
	mode, bs, bpi, _, _ := deterministicSourceNATFields(pool, 1024, 65535)
	if mode != 0 || bs != 0 || bpi != 0 {
		t.Fatalf("deterministicSourceNATFields(no-translation) = mode %d block %d bpi %d, want all zero", mode, bs, bpi)
	}
	// Control: same pool without no-translation emits mode 1.
	pool2 := &config.NATPool{
		Name:          "p1",
		Deterministic: &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "10.0.0.0/24"},
	}
	mode2, _, _, _, _ := deterministicSourceNATFields(pool2, 1024, 65535)
	if mode2 != 1 {
		t.Fatalf("deterministicSourceNATFields(control) mode = %d, want 1", mode2)
	}
	// NAT64 mode-2 guard.
	if _, _, _, _, ok := deterministicNAT64V6Fields(pool); ok {
		t.Fatalf("deterministicNAT64V6Fields(no-translation v4 host) ok=true, want false")
	}
	poolV6 := &config.NATPool{
		Name:              "p64",
		PortNoTranslation: true,
		Deterministic:     &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "2001:db8::/64"},
	}
	if _, _, _, _, ok := deterministicNAT64V6Fields(poolV6); ok {
		t.Fatalf("deterministicNAT64V6Fields(no-translation) ok=true, want false")
	}
	poolV6b := &config.NATPool{
		Name:          "p64",
		Deterministic: &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "2001:db8::/64"},
	}
	if _, _, _, _, ok := deterministicNAT64V6Fields(poolV6b); !ok {
		t.Fatalf("deterministicNAT64V6Fields(control) ok=false, want true")
	}
}
