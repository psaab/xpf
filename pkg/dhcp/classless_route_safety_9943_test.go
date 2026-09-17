package dhcp

import (
	"net/netip"
	"testing"
)

func TestClasslessRouteSafetyPredicate_9943(t *testing.T) {
	for _, cidr := range []string{
		"0.0.0.0/0",
		"0.0.0.0/1",
		"128.0.0.0/1",
		"0.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	} {
		prefix := netip.MustParsePrefix(cidr)
		if !ClasslessRouteIsTooBroad(prefix) && !ClasslessRouteIsMartian(prefix) {
			t.Errorf("unsafe classless prefix %s was accepted by both predicates", cidr)
		}
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"192.0.2.0/24",
	} {
		prefix := netip.MustParsePrefix(cidr)
		if ClasslessRouteIsTooBroad(prefix) || ClasslessRouteIsMartian(prefix) {
			t.Errorf("legitimate private/documentation prefix %s was rejected", cidr)
		}
	}
}
