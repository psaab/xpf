package config

import ()

// compiler_ipsec_plaintext_warn.go carries the #5619 commit-time WARNING that
// a route-based IPsec VPN's decrypted plaintext is not zone-adjudicated.
//
// The defect it makes visible: route-based IPsec decrypts in the KERNEL XFRM
// stack, which delivers the plaintext on the xfrmi netdev. xpf's userspace
// dataplane does not adjudicate that interface — it is excluded from the
// ingress-adjudication map (userspaceSkipsIngressInterface, which reads the
// snapshot's SecureTunnel flag; #6691 round 5 stopped it calling
// IsSecureTunnelIfName, and the Rust mirror is_secure_tunnel_ifname was
// deleted rather than re-derived) because there is no path to hand a plaintext
// frame back INTO an xfrmi for the egress direction. While transit is open (the
// daemon's transit gate), ip_forward is 1 and no forward-hook rule covers the
// plaintext; the #7191 forward-hook barrier exists only while transit is closed.
// So the plaintext is forwarded by the kernel with no zone policy, no session,
// no NAT and no screen.
//
// Why a warning and not a rejection. Route-based (st0/XFRM) IPsec is the ONLY
// IPsec model xpf supports — policy-based `then permit tunnel` is hard-rejected
// at commit (#3114). Rejecting a route-based VPN would not be a guard, it would
// be a feature removal, and it would leave an operator with a working tunnel
// unable to commit an UNRELATED change. This is the #1960 no-brick posture:
// strict enough to tell the truth, never strict enough to brick a config the
// box already accepts and runs.
//
// This function CANNOT reject. It has no error return and takes no `lenient`
// flag — the no-brick property is structural, not a convention a later edit
// could quietly invert. If a future change genuinely needs to reject one of
// these, that belongs in a separate gate with its own justification, not here.
//
// ONE aggregated advisory per commit, not one per tunnel. An advisory that
// fires N times on every commit is filtered out, and then it protects nobody —
// the same reason compiler_system.go folds several inert knobs into a single
// message. The affected tunnels are named inside it.
//
// It fires whenever a secure tunnel is configured, NOT only when one carries a
// zone. Leaving a tunnel out of a zone is not a mitigation: the plaintext never
// reaches zone policy at all, so zoning or not zoning the interface does not
// change whether it is adjudicated. Gating this advisory on zoning would tell
// that operator nothing at all.
//
// #6682: this comment used to say an unzoned interface resolves to zone id 0
// and could be "affirmatively PERMITTED by a wildcard rule". That was never
// true — #3110 has fenced every rule tier, wildcard tiers included, against
// zone 0 since before the claim was written — and #6682 made an unzoned INGRESS
// an explicit deny on top of that. The advisory still fires for the reason
// above.
//
// The two groups are worded differently on purpose. A ZONED tunnel is the acute
// case and reads as an escalation, because the operator has been told something
// specific and untrue. An unzoned tunnel is a plain statement of the gap.
//
// Why the operator needs telling. Before #5619 the config gave an affirmative
// FALSE signal: `set security zones security-zone vpn interfaces st0.0`
// commits cleanly (#4515 accepts a zone referencing a bind-interface even with
// no explicit `set interfaces st0 unit 0`), the zone assignment is accepted,
// and nothing in the CLI or the commit output distinguishes it from a zone
// that is enforced. Everything READS as enforced.
//
// What actually happens is the opposite, and it is worth naming precisely
// because the obvious description of it is wrong twice over. The tunnel is
// excluded from the ingress-adjudication set, and `syncInterfaceAttachments`
// (pkg/dataplane/userspace/manager_compile.go) then builds an `allowed` set
// from buildUserspaceIngressIfindexes and calls DetachXDP on every ifindex
// outside it — so the shim is DETACHED from the xfrmi, not attached to it.
// (An earlier revision of this comment said "the XDP shim is attached to it",
// and attributed the programming to `iface_zone_map`, which now exists only in
// the retired-eBPF tree — pkg/dataplane/loader.go and maps_stale.go, behind
// the retirement canary. Neither statement described this code.) An operator who zones a VPN interface and sees
// it accepted has been told something specific and untrue about their security
// posture — which is worse than an unimplemented feature, and is what this
// warning corrects.
//
// Coupling, restated in #7090 because the old wording named a mechanism that
// no longer exists. It said the warning keys off the SAME predicate as the
// dataplane exclusion (IsSecureTunnelIfName) "so the two cannot drift". That
// stopped being true in #6691 round 5: the exclusion now runs
// userspaceSkipsIngressInterface -> userspaceUnbindableNetdev -> the
// SecureTunnel class -> matchesSecureTunnelClass -> iface.SecureTunnel, which
// the snapshot builder sets from snapshotSecureTunnel (config ownership via
// SecureTunnelNetdevForRef, UNION a live xfrm device). xfrmi.go says it
// outright: IsSecureTunnelIfName "is NOT the ownership test and no longer
// gates any dataplane set".
//
// What actually keeps the two populations coincident is the if_id, not a
// shared predicate: pkg/routing/xfrm.go creates an xfrmi for exactly
// vpn.BindInterface via XFRMIfNameAndID and skips ifID == 0, and the
// dataplane's ownership join reaches the same devices through that id. So the
// conclusion the old comment drew still holds — it was the stated reason that
// had gone stale, which is the more dangerous half, because a later reader
// relies on the reason instead of re-deriving it.
//
// This is a coincidence of populations, NOT a mechanical binding. If a real
// anti-drift guard is wanted it has to be a test asserting the two populations
// agree; it cannot live here, because snapshotSecureTunnel is unexported in
// pkg/dataplane/userspace.
//
// #7949 NARROWED WHAT "AN OPERATOR WHO ZONES A VPN INTERFACE HAS BEEN TOLD
// SOMETHING UNTRUE" MEANS, and the direction matters. This advisory is about
// the INGRESS half — the plaintext the kernel XFRM stack delivers ON the
// xfrmi, which is still kernel-forwarded and still unadjudicated (#9506 owns
// that half; the exclusion above is what makes it so). It is NOT about the
// EGRESS half. Before #7949 a `bind-interface`-only tunnel produced no
// interface row at all, so its LAN -> tunnel direction resolved NoRoute and was
// slow-path reinjected to the kernel too; that direction is now adjudicated
// whenever the operator zones the tunnel, exactly as the same tunnel written
// WITH a `set interfaces` stanza already was.
//
// So the warning stays, unchanged and unconditional, but a reader must not
// take it as saying the zone does nothing. It says the zone does not govern
// the DECRYPTED traffic. Widening it back to "the zone is inert" would now be
// the false statement.
//
// An AST pre-walk (like validateSecureTunnelBindInterfaceAST) rather than a
// typed-Config pass, so it runs on the group-expanded, inactive-pruned tree in
// compileExpanded: an apply-groups-inherited bind-interface is covered and an
// `inactive:` VPN is ignored for free.
func warnSecureTunnelPlaintextUnadjudicatedAST(nodes []*Node) []string {
	zoneByIfID := collectZoneInterfaceRefsAST(nodes)

	seen := map[string]struct{}{}
	var findings []plaintextTunnelFinding

	// #3562 shape: iterate EVERY top-level `security` node and EVERY `ipsec`
	// sibling. parseStatements APPENDS a repeated top-level block rather than
	// merging it, and the compiler compiles every one, so a VPN can live in a
	// duplicate block and must not be missed here either.
	_ = forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "ipsec", func(ipsec *Node) error {
			for _, inst := range namedInstances(ipsec.FindChildren("vpn")) {
				biNode := inst.node.FindChild("bind-interface")
				if biNode == nil {
					continue
				}
				bindIface := nodeVal(biNode)
				if bindIface == "" {
					continue
				}
				// An if_id of 0 means the name materializes NO xfrm device, so
				// there is no plaintext path to warn about — that config is
				// already reported by the #5297 arm of
				// validateSecureTunnelBindInterfaceAST (silent tunnel down).
				// Warning here too would just add noise to a config that is
				// already being told about a worse problem.
				_, ifID := XFRMIfNameAndID(bindIface)
				if ifID == 0 {
					continue
				}
				// #7090: there is deliberately no IsSecureTunnelIfName check
				// here. It used to follow, justified as keying the advisory off
				// the same predicate as the dataplane exclusion — but it could
				// not fire for any input, because a non-zero ifID ALREADY
				// implies it: XFRMIfNameAndID returns non-zero only after
				// secureTunnelIndex succeeds on the base name, and
				// IsSecureTunnelIfName IS secureTunnelIndex on that same base.
				// TestNonZeroIfIDImpliesSecureTunnelName_7090 binds the
				// implication, so if that ever stops holding this population
				// widens and the test says so.
				key := inst.name + "\x00" + bindIface
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, plaintextTunnelFinding{
					ref:    bindIface,
					detail: "security ipsec vpn " + inst.name,
					zone:   zoneByIfID[ifID],
				})
			}
			return nil
		})
	})

	// ONE aggregated advisory per commit, the zoned/unzoned partition, the sort,
	// and the rule that the unzoned caveat appears only when a tunnel IS
	// unzoned are the SHARED shape (renderPlaintextUnadjudicatedAdvisory,
	// compiler_tunnel_plaintext_advisory.go) — the #5618 WireGuard advisory
	// renders through the same function, so the two cannot diverge in
	// structure. Every sentence lives here, the group headings and the #6682
	// unzoned caveat included: since #8274 a WireGuard tunnel's zone is enforced
	// on its dataplane path and an IPsec tunnel's is not, so the two advisories
	// no longer share those sentences (#9251).
	return renderPlaintextUnadjudicatedAdvisory(findings, secureTunnelPlaintextAdvisoryWording())
}

// IPsec's group headings and unzoned caveat. Moved here from
// compiler_tunnel_plaintext_advisory.go by #9251 with their TEXT UNCHANGED:
// they are still exactly true for route-based IPsec, whose plaintext never
// reaches the dataplane. They stopped being shared because they are false for
// WireGuard (see plaintextAdvisoryWording).
const (
	// ipsecPlaintextZonedHeading introduces the ACUTE group. A zoned tunnel is
	// worse than an unimplemented feature: the zone assignment commits cleanly
	// and nothing distinguishes it from a zone that is enforced, so the
	// operator has been told something specific and untrue.
	ipsecPlaintextZonedHeading = "ASSIGNED A ZONE THAT IS NOT ENFORCED — this reads as protected and is not:"

	// ipsecPlaintextUnzonedHeading introduces the plain-statement group.
	ipsecPlaintextUnzonedHeading = "NOT ZONE-ADJUDICATED:"

	// ipsecPlaintextUnzonedCaveat is emitted only when at least one tunnel is
	// unzoned. Leaving a tunnel out of a zone is NOT a mitigation, and an
	// operator reading only the zoned paragraph could conclude that it is.
	// #6682: this sentence used to say an unzoned interface resolves to zone id
	// 0 "which a `from-zone any to-zone any permit` rule matches". That was
	// never true -- the #3110 guard has fenced every rule tier, wildcard tiers
	// included, against zone 0 since before the claim was written -- and #6682
	// went further and made an unzoned INGRESS an explicit deny. The conclusion
	// survives; only the mechanism was wrong, and it is the mechanism an
	// operator would act on.
	ipsecPlaintextUnzonedCaveat = "An UNZONED tunnel is not safer: leaving it out of a zone does " +
		"not bring its plaintext under policy, it only leaves it unadjudicated by a different route " +
		"(#6682)."
)

// secureTunnelPlaintextAdvisoryWording is the #5619 advisory's text.
func secureTunnelPlaintextAdvisoryWording() plaintextAdvisoryWording {
	return plaintextAdvisoryWording{
		lead: "security ipsec: decrypted traffic on route-based IPsec secure tunnels is " +
			"NOT evaluated against xpf security policies (#5619).",
		zonedHeading:   ipsecPlaintextZonedHeading,
		zonedSuffix:    "but that zone does NOT govern its decrypted traffic",
		unzonedHeading: ipsecPlaintextUnzonedHeading,
		mechanism: "Route-based IPsec decrypts in the kernel XFRM stack and the plaintext is " +
			"forwarded by Linux routing, which xpf does not adjudicate: no zone policy, no " +
			"session, no NAT and no screen are applied to it.",
		unzonedCaveat: ipsecPlaintextUnzonedCaveat,
		remedy: "Restrict what the tunnel can reach with routing or with the peer's own " +
			"policy until this is enforced.",
	}
}

// collectZoneInterfaceRefsAST maps each `security zones security-zone <z>
// interfaces <ref>` secure-tunnel member to its zone name, keyed by XFRM
// if_id rather than by the literal ref string.
//
// The if_id is the key because the two spellings of one device are NOT
// interchangeable as strings but ARE the same device: `bind-interface st0` and
// a zone on `st0.0` describe the same xfrmi (both if_id 1,
// pkg/routing/xfrm.go). Matching literally would miss that pairing and report a
// ZONED tunnel as unzoned — dropping the escalation in exactly the case that
// earns it, where the operator HAS been told something untrue. This is the same
// spelling-mismatch class as the #5619 netdev-name bug, so it is keyed the same
// way: join on if_id, with XFRMIfNameAndID as the single source of truth.
//
// Membership is read through forEachZoneInterfaceMemberAST, which reads the
// stanza with the compiler's own flattener (#5248/#2419): a bracketed list
// `interfaces [ st0.0 st0.1 ]` arrives bracket-stripped and NESTED under the
// first member, so reading only iface.Name() would see just the first and
// silently miss the rest. The #5618 WireGuard advisory enumerates membership
// through the SAME walker — a divergence in which members the two advisories
// can see would always be a bug.
func collectZoneInterfaceRefsAST(nodes []*Node) map[uint32]string {
	out := map[uint32]string{}
	forEachZoneInterfaceMemberAST(nodes, func(zone, member string) {
		_, ifID := XFRMIfNameAndID(member)
		if ifID == 0 {
			// Not a secure tunnel; irrelevant here.
			return
		}
		// First zone wins; a duplicate assignment is a separate concern with
		// its own gate.
		if _, exists := out[ifID]; !exists {
			out[ifID] = zone
		}
	})
	return out
}
