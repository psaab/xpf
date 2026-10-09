package daemon

import (
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestHostInboundNftAllExceptSSHDoesNotRenderAlias12053(t *testing.T) {
	tree, parseErrs := config.NewParser(`security { zones { security-zone edge { host-inbound-traffic { system-services { all; ssh { except; } } } } } }`).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse host-inbound fixture: %v", parseErrs)
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile host-inbound fixture: %v", err)
	}
	zone := compiled.Security.Zones["edge"]
	if zone == nil || zone.HostInboundTraffic == nil {
		t.Fatal("compiled edge zone has no host-inbound-traffic")
	}

	cfg := allScopingTestConfig()
	cfg.Security.Zones["edge"].HostInboundTraffic = zone.HostInboundTraffic
	payload := allScopingPayload(t, cfg)
	for _, family := range []string{"ip", "ip6"} {
		if admitted, line := daemonPayloadAdmitsTCPPort12053(payload, family, 22); admitted {
			t.Errorf("%s nft payload re-admits excluded TCP/22: %s", family, line)
		}
	}
	for _, want := range []string{
		"ip daddr 10.0.2.1 tcp dport 80 accept",
		"ip daddr 10.0.2.1 tcp dport 830 accept",
		"ip6 daddr 2001:db8:2::1 tcp dport 80 accept",
		"ip6 daddr 2001:db8:2::1 tcp dport 830 accept",
		"ip daddr 10.0.2.1 counter",
		"ip6 daddr 2001:db8:2::1 counter",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("kernel nft payload missing non-vacuity control %q\n%s", want, payload)
		}
	}
}

func daemonPayloadAdmitsTCPPort12053(payload, family string, port uint16) (bool, string) {
	prefix := family + " daddr "
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, " accept") {
			continue
		}
		_, spec, ok := strings.Cut(line, "tcp dport ")
		if !ok {
			continue
		}
		spec = strings.TrimSuffix(spec, " accept")
		if daemonPortSpecHas12053(spec, port) {
			return true, line
		}
	}
	return false, ""
}

func daemonPortSpecHas12053(spec string, want uint16) bool {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "{") && strings.HasSuffix(spec, "}") {
		spec = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(spec, "{"), "}"))
	}
	for _, member := range strings.Split(spec, ",") {
		bounds := strings.Split(strings.TrimSpace(member), "-")
		if len(bounds) > 2 {
			continue
		}
		lo, err := strconv.ParseUint(strings.TrimSpace(bounds[0]), 10, 16)
		if err != nil {
			continue
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = strconv.ParseUint(strings.TrimSpace(bounds[1]), 10, 16)
			if err != nil {
				continue
			}
		}
		if lo <= uint64(want) && uint64(want) <= hi {
			return true
		}
	}
	return false
}
