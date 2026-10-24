package config

import "strings"

// MaxRibGroupLeakRules bounds the number of per-prefix rib-group leak rules
// installed per address family. It is the single admission cap shared by the
// commit-time gate (pkg/config) and the runtime applier (pkg/routing, which
// imports this package): both MUST admit the same configs, so the value lives
// here and nowhere else (#16203). The shared leak-rule clear range is sized
// by RouteLeakRulePriorityWindow, independently of this cap.
const MaxRibGroupLeakRules = 1000

// RibInstanceFromName extracts the routing-instance prefix from a non-default
// rib name of the EXACT form "<instance>.inet.0" or "<instance>.inet6.0",
// returning ok=false for any other shape. The instance prefix must be
// non-empty. Junos rib names are exactly "<table>.inet.0" (IPv4 unicast) or
// "<table>.inet6.0" (IPv6 unicast); bare "inet.0" / "inet6.0" (the main
// table) are handled by callers directly and are NOT treated as instance ribs
// here. Malformed family tokens (".inetX.0", ".inetfoo.0", ".inet60.0") and
// trailing garbage (".inet.0.x") return ok=false so callers reject them
// rather than silently mapping a typo'd rib onto the instance table (#2253).
//
// This is the single implementation shared by the commit-time gate
// (pkg/config) and the runtime applier (pkg/routing) so the two agree on
// what resolves (#2226, hoisted by #16203).
func RibInstanceFromName(ribName string) (string, bool) {
	for _, suffix := range []string{".inet.0", ".inet6.0"} {
		if instance, ok := strings.CutSuffix(ribName, suffix); ok && instance != "" {
			return instance, true
		}
	}
	return "", false
}
