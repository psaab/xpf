package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInboundUnzonedTestConfig extends the shared host-inbound fixture with an
// addressed interface assigned to NO security zone (#4420 HI-2 fail-open) and an
// addressed LIFELINE (fab*) also in no zone (must never be denied).
func hostInboundUnzonedTestConfig() *config.Config {
	cfg := hostInboundTestConfig()
	cfg.Interfaces.Interfaces["ge-0/0/9"] = &config.InterfaceConfig{
		Name: "ge-0/0/9",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8:99::1/64"}},
		},
	}
	cfg.Interfaces.Interfaces["fab5"] = &config.InterfaceConfig{
		Name: "fab5",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.5.5.5/24"}},
		},
	}
	return cfg
}

// TestHostInboundUnzonedInterfaceDenied is the #4420 HI-2 fail-on-revert proof:
// the kernel host-inbound chain emits a catch-all DROP scoping the firewall-local
// addresses of an addressed-but-unzoned interface (counted under the reserved
// junos-host sentinel), so host-bound traffic to it is denied by default instead
// of falling through the chain's `policy accept` to the host stack (the fail-open,
// and a deviation from Junos where an unzoned interface passes no traffic). A
// ZONED address must not leak into that deny, and an unzoned LIFELINE must never
// be denied. Reverting emitUnzonedHostInboundDeny (or BuildUnzonedHostInboundAddrs)
// turns this RED.
func TestHostInboundUnzonedInterfaceDenied(t *testing.T) {
	cfg := hostInboundUnzonedTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	v4, v6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	payload := buildHostInboundFilterPayload(views, v4, v6, nil, nil, true)

	sentinel := dpuserspace.UnzonedHostInboundZoneLabel
	wantV4 := hiDrop("ip", "192.0.2.1", sentinel)
	wantV6 := hiDrop("ip6", "2001:db8:99::1", sentinel)
	for _, want := range []string{
		wantV4, wantV6,
		"counter " + xnft.HostInboundDenyCounterName(sentinel, "ip") + " {",
		"counter " + xnft.HostInboundDenyCounterName(sentinel, "ip6") + " {",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing unzoned host-inbound deny %q\n---\n%s", want, payload)
		}
	}

	// The LIFELINE (fab5) address must NEVER be denied.
	if strings.Contains(payload, "10.5.5.5") {
		t.Errorf("payload denies a LIFELINE (fab5) unzoned address 10.5.5.5:\n%s", payload)
	}
	// A ZONED address (wan reth0.50) must not appear under the unzoned sentinel.
	if strings.Contains(payload, hiDrop("ip", "172.16.50.8", sentinel)) {
		t.Errorf("zoned wan address leaked into the unzoned deny:\n%s", payload)
	}

	// The global established accept must precede the unzoned catch-all drop, so
	// ND / PMTUD / established / ESP still work on an unzoned interface.
	if idxDrop := strings.Index(payload, wantV4); idxDrop >= 0 {
		if idxEstab := strings.Index(payload, "ct state established,related accept"); idxEstab < 0 || idxEstab > idxDrop {
			t.Errorf("established accept must precede the unzoned catch-all drop:\n%s", payload)
		}
	}
}

// TestHostInboundUnzonedNoZonesNoTable asserts a config with unzoned addressed
// interfaces but ZERO security zones emits no unzoned deny (the builder is a
// no-op without the zone model), so a bootstrap/zoneless box is never turned
// into deny-all host-inbound (#4420 HI-2 scope guard).
func TestHostInboundUnzonedNoZonesNoTable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	if v4, v6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg); v4 != nil || v6 != nil {
		t.Fatalf("zoneless config must yield no unzoned deny, got v4=%v v6=%v", v4, v6)
	}
}
