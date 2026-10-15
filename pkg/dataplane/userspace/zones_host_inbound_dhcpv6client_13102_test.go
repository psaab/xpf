package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestStableRethUnitHasIPv6RecognizesDHCPv6Client13102(t *testing.T) {
	if !stableRethUnitHasIPv6(&config.InterfaceUnit{
		DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateful"},
	}) {
		t.Fatal("structured DHCPv6 client must count as an IPv6 address source")
	}
}
