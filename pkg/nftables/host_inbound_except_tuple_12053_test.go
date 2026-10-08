package nftables

import (
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestHostInboundNetlinkUsesCompiledExceptTuples12053(t *testing.T) {
	tree, parseErrs := config.NewParser(`security { zones { security-zone trust { host-inbound-traffic { system-services { all; ssh { except; } } } } } }`).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse host-inbound fixture: %v", parseErrs)
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile host-inbound fixture: %v", err)
	}
	zone := compiled.Security.Zones["trust"]
	if zone == nil || zone.HostInboundTraffic == nil {
		t.Fatal("compiled trust zone has no host-inbound-traffic")
	}
	services := zone.HostInboundTraffic.SystemServices
	if len(services) == 0 {
		t.Fatal("compiled all-service expansion is empty")
	}

	view := HostInboundZoneView{Zone: "trust", SystemServices: services}
	for _, family := range []nlFamily{famV4, famV6} {
		fragments := hostInboundMatchFragments(view, family)
		if len(fragments) == 0 {
			t.Fatalf("%s: no nft fragments rendered from compiled services", familyToken(family))
		}
		var tcp80 bool
		for _, fragment := range fragments {
			if fragment.key == "tcp:80" {
				tcp80 = true
			}
			if nftFragmentAdmitsTCPPort12053(fragment.key, 22) {
				t.Errorf("%s: nft fragment %q re-admits excluded TCP/22", familyToken(family), fragment.key)
			}
		}
		if !tcp80 {
			t.Errorf("%s: normal HTTP service was not rendered; fragment check would be vacuous", familyToken(family))
		}
	}
}

func nftFragmentAdmitsTCPPort12053(key string, port uint16) bool {
	protocol, ports, ok := strings.Cut(key, ":")
	if !ok || protocol != "tcp" {
		return false
	}
	for _, part := range strings.Split(ports, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			continue
		}
		lo, err := strconv.ParseUint(bounds[0], 10, 16)
		if err != nil {
			continue
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = strconv.ParseUint(bounds[1], 10, 16)
			if err != nil {
				continue
			}
		}
		if lo <= uint64(port) && uint64(port) <= hi {
			return true
		}
	}
	return false
}
