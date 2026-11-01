package dataplane

import "strings"

// #18740: the management (fxp*) and cluster control-link (em*) netdevs are
// zoned, so compileZones used to put them in the shim's attach set like any
// other zone member. The userspace dataplane never adjudicates either: its
// ingress set excludes them by name (the "fxp name" and "em name" classes in
// pkg/dataplane/userspace/ingress_exclusions.go), and the shim's verdict for
// an ifindex outside that set is cpumap_or_pass, a plain hand-off to the
// kernel. So every apply attached the shim to fxp0 and em0 FRESH (the previous
// apply had detached and unpinned them), and syncInterfaceAttachments detached
// it again at the acceptance point 25-142 ms later. That is two XDP program
// changes per commit, per node, on the HA control link. One heartbeat frame
// that arrived at the instant of an em0 attach was lost on the udp lab cluster.
//
// Nothing needs the shim there in the meantime:
//   - The verdict is pass for an unadjudicated ifindex (the #8279 gate in
//     userspace-xdp/src/lib.rs runs before any parse), so host-inbound
//     traffic reaches the kernel stack and its filters exactly as it does
//     with no program attached.
//   - AttachXDP's side effects (the link pin, the interface-counter seed)
//     serve a link that the next acceptance removes.
//   - The forward fence (#10302) only governs transit, and these interfaces
//     carry host traffic.
//
// So the fix is at the source: they never enter the attach set. They are
// recorded as SKIPPED unarmed surfaces so the arm-coverage proof still lists
// them without counting them toward WouldGate.

// controlPlaneNetdevNameClasses are the name classes the userspace dataplane
// never adjudicates and therefore never shims. The userspace ingress
// exclusion consults the SAME list (ControlPlaneNetdevNameClass), so the
// attach set and the ingress set cannot disagree about these names.
//
// Deliberately narrower than the full ingress exclusion:
//   - "fab": the zone interface fab0 resolves to its local member's PARENT
//     netdev (compiler_iface.go, LocalFabricMember), which carries the fabric
//     redirect path and must stay shimmed.
//   - lo0, tunnels and secure tunnels are separate questions with their own
//     gates.
var controlPlaneNetdevNameClasses = []struct {
	name   string
	prefix string
}{
	{name: "fxp name", prefix: "fxp"},
	{name: "em name", prefix: "em"},
}

// ControlPlaneNetdevNameClass reports which control-plane name class a netdev
// or interface name belongs to ("fxp name", "em name"), judged on the name
// with any ".unit" suffix removed. ok is false for every other name.
func ControlPlaneNetdevNameClass(name string) (class string, ok bool) {
	base := name
	if idx := strings.IndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	for _, c := range controlPlaneNetdevNameClasses {
		if strings.HasPrefix(base, c.prefix) {
			return c.name, true
		}
	}
	return "", false
}

// controlPlaneSurfaceRecord is the arm-coverage record for a control-plane
// netdev kept out of the attach set. StillForwarding is false: the netdev is
// reached by host traffic only, it carries no xpf-adjudicated transit, and
// without a shim its kernel path is exactly what the shim's pass verdict
// would have produced. The proof therefore counts it as skipped, not
// uncovered.
func controlPlaneSurfaceRecord(name string, ifindex int, class string) UnarmedSurface {
	return UnarmedSurface{
		Name:    name,
		Ifindex: ifindex,
		Reason: "control-plane netdev (" + class + "): the userspace dataplane never " +
			"adjudicates it, so the shim is not attached; attaching it only to detach it " +
			"at acceptance cost two XDP program changes per commit on the HA control link (#18740)",
	}
}

// xdpTransitionSeam18740, when a test sets it, sees every AttachXDP and
// DetachXDP entry before any kernel work and may answer in place of it
// (handled=true). It exists so a hermetic cell can count XDP transitions
// across a run of commits: the property #18740 needs is that an unchanged
// commit makes none. Production never sets it.
var xdpTransitionSeam18740 func(op string, ifindex int, generic bool) (handled bool, err error)

// SetXDPTransitionSeamForTest installs fn as the #18740 transition seam and
// returns a restore func. op is "attach" or "detach". Returning handled=false
// lets the real method run, so a test can observe without emulating.
func SetXDPTransitionSeamForTest(fn func(op string, ifindex int, generic bool) (handled bool, err error)) (restore func()) {
	old := xdpTransitionSeam18740
	xdpTransitionSeam18740 = fn
	return func() { xdpTransitionSeam18740 = old }
}
