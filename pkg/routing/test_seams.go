package routing

// test_seams.go holds exported constructors used ONLY by tests in this package
// and in dependent packages (e.g. pkg/daemon) that need to drive the routing
// Manager against a fake netlink surface. They live in a production-compiled
// file (not _test.go) so cross-package tests can reach them, mirroring
// pkg/configstore/test_seams.go. They are never called from production code.

// NewManagerWithLinkOpsForTest builds a *Manager whose link-lifecycle domains
// (vrf, tunnel, xfrm, bond, reth, monitor — every domain whose ops field is
// satisfied by the narrow linkOps surface) are backed by the supplied linkOps
// instead of a live *netlink.Handle. It exists so tests in dependent packages
// can exercise the apply/commit error-propagation wiring (#5310: a genuine
// xfrmi/bond create failure must fail the commit closed) against an in-memory
// fake — no root, no real netlink handle, no side effects on the host.
//
// Scope: the rule/route domains (routes, nextTbl, ribGroup, pbr, probePin) are
// left nil — their ops interfaces (routeLister/ruleOps/probePinOps) are NOT a
// subset of linkOps, so they cannot share this fake. Callers exercising
// interface-reconcile (ApplyTunnels/ApplyXfrmi/ApplyBonds/ClearRethInterfaces)
// do not touch those domains. nlHandle stays nil (Close nil-guards it).
//
// Callers pass any value whose method set matches linkOps (the interface's
// methods are all exported, so a fake defined in another package satisfies it
// structurally).
func NewManagerWithLinkOpsForTest(ops linkOps) *Manager {
	m := &Manager{}
	m.vrf = &vrfManager{ops: ops}
	m.tunnel = &tunnelManager{ops: ops, vrfBinder: m.vrf, keepalives: make(map[string]*keepaliveRunner)}
	m.xfrm = &xfrmManager{ops: ops}
	m.bond = &bondManager{ops: ops}
	m.reth = &rethManager{ops: ops}
	m.monitor = &monitorManager{ops: ops, monitorStatus: make(map[int][]InterfaceMonitorStatus)}
	return m
}

// NewManagerWithRuleOpsForTest builds a *Manager whose policy-routing rule
// domains (nextTbl, ribGroup, pbr — every domain whose ops field is the narrow
// ruleOps surface) are backed by the supplied ruleOps instead of a live
// *netlink.Handle. It exists so tests in dependent packages (e.g. pkg/daemon)
// can drive applyRoutingRules' ip-rule reconcile — notably the #5642
// final-rib-group removal, which must STILL run the rib-group clear() so the
// stale per-prefix leak ip-rule is deleted on the zero-transition — against an
// in-memory fake (no root, no netlink handle, no host side effects).
//
// Only the three rule domains are wired; every other domain is left nil (these
// tests exercise the rule reconcile only). nlHandle and tunnel stay nil (Close
// nil-guards both, #5718 A7-b02-C01), so `defer m.Close()` is safe here.
//
// Callers pass any value whose method set matches ruleOps (RuleAdd / RuleDel /
// RuleList — all exported, so a fake defined in another package satisfies it
// structurally).
func NewManagerWithRuleOpsForTest(ops ruleOps) *Manager {
	m := &Manager{}
	m.nextTbl = &nextTableManager{ops: ops}
	m.ribGroup = &ribGroupManager{ops: ops}
	m.pbr = &pbrManager{ops: ops}
	return m
}

// NewManagerWithRouteListerForTest builds a *Manager whose route-read domain
// (routeReader) is backed by the supplied routeLister instead of a live
// *netlink.Handle. It exists so tests in dependent packages (e.g. pkg/grpcapi)
// can drive the GetRoutes/GetRoutesForTable/GetAllTableRoutes read path — and
// the callers that render it — against an in-memory fake that fails a single
// address family, proving the partial-render-with-warning contract (#5125)
// without root, a real netlink handle, or host side effects.
//
// Only the routes domain is wired; every other domain is left nil (these
// tests exercise reads only). nlHandle and tunnel stay nil (Close nil-guards
// both, #5718 A7-b02-C01), so `defer m.Close()` is safe here.
//
// Callers pass any value whose method set matches routeLister (the interface's
// methods are all exported, so a fake defined in another package satisfies it
// structurally).
func NewManagerWithRouteListerForTest(ops routeLister) *Manager {
	m := &Manager{}
	m.routes = &routeReader{ops: ops}
	return m
}

// NewManagerWithLinkAndTermOpsForTest builds a *Manager for VRF-reconcile
// cells that must observe the #9819 miss-terminator installs the reconcile
// issues alongside the link lifecycle (#10421: a clean restart must reassert
// the managed pref-2000 rules while adopting the surviving VRF devices). It
// wires the same link-lifecycle domains as NewManagerWithLinkOpsForTest and
// additionally binds the VRF manager's terminator surface to term; the
// rule/route domains stay nil as in the link-only constructor.
//
// Callers pass any values whose method sets match linkOps and
// vrfMissTerminatorOps (all methods exported, so fakes defined in another
// package satisfy them structurally, as with the sibling constructors).
func NewManagerWithLinkAndTermOpsForTest(ops linkOps, term vrfMissTerminatorOps) *Manager {

	m := NewManagerWithLinkOpsForTest(ops)
	m.vrf.term = term
	return m
}

// NewManagerWithLinkTermAndRuleOpsForTest combines the link/VRF fake with the
// policy-rule fake for daemon apply-pipeline tests that must run both VRF
// activation and the normal routing tail without a live netlink handle.
func NewManagerWithLinkTermAndRuleOpsForTest(ops linkOps, term vrfMissTerminatorOps, rules ruleOps) *Manager {
	m := NewManagerWithLinkAndTermOpsForTest(ops, term)
	m.nextTbl = &nextTableManager{ops: rules}
	m.ribGroup = &ribGroupManager{ops: rules}
	m.pbr = &pbrManager{ops: rules}
	return m
}
