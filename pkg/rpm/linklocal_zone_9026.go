package rpm

import (
	"fmt"
	"net"

	"github.com/psaab/xpf/pkg/routing"
)

// #9026: probeICMP RESOLVED an IPv6 link-local scope and probeTCP DID NOT, so
// the same unscopeable target HELD the test on one probe type and counted as
// PATH LOSS on the other.
//
// The consumer distinction is load-bearing: pkg/rpm treats ErrProbeSetup as
// "this probe never ran" (no counters, no transition) and anything else as a
// path signal that increments SuccFail and can trip a state change. `services
// ip-monitoring` drives preferred-route injection off that state, so a tcp-ping
// to an unscopeable fe80:: address -- a probe that never left the box -- could
// fail over a WAN.
//
// THE GUARD IS SHARED NOW RATHER THAN COPIED. #2494 wrote it once for ICMP and
// the TCP path was never given it; duplicating it would leave the same drift
// available a third time, at http-get. One function, called by each probe, is
// what makes "both probe types agree about scope" a property rather than a
// coincidence.
//
// The deliberate NON-fallback is preserved verbatim from #2494 and is the
// subtle half: opts.BindDevice can hold the routing-instance VRF device
// ("vrf-<ri>") from probeOpts, which is NOT an egress link for fe80::.
// Defaulting to it would let the probe SEND -- counted as path loss -- instead
// of HOLDING, which is the #1960 hold-state doctrine inverted. Only a real
// %zone or destination-interface satisfies the scope.
func (m *Manager) resolveLinkLocalZone9026(kind string, dst net.IP, zone, destinationInterface string) (string, error) {
	if dst.To4() != nil || !dst.IsLinkLocalUnicast() {
		return zone, nil
	}
	m.mu.RLock()
	rethMap := m.rethMap
	m.mu.RUnlock()
	// #12907: an explicit %zone names the same egress a
	// destination-interface can, Junos spelling included, so it goes
	// through the SAME routing.ResolveProbeInterface normalization — RETH
	// base resolved through rethMap to the local physical member, default
	// ".0" unit stripped, slashes to dashes. A bare config.LinuxIfName
	// turned `fe80::1%reth0.0` into "reth0.0", a name no kernel netdev
	// answers to (ENODEV, probe held), while `destination-interface
	// reth0.0` resolved to the physical member and probed — one spelling
	// of one egress decided between holding and probing. Zone keeps its
	// precedence over destination-interface: ResolveProbeInterface
	// returns "" only for an empty name, so a typed zone never falls
	// through. On a rethMap MISS it stays the raw translated name, the
	// same #7173 fail-closed doctrine the destination-interface path
	// follows — ENODEV holds the probe rather than probing unpinned.
	if zone != "" {
		return routing.ResolveProbeInterface(zone, rethMap), nil
	}
	resolved := routing.ResolveProbeInterface(destinationInterface, rethMap)
	if resolved == "" {
		return "", fmt.Errorf("%w: %s link-local target %s needs a zone "+
			"(%%zone or destination-interface; a routing-instance VRF is not an egress link)",
			ErrProbeSetup, kind, dst)
	}
	return resolved, nil
}
