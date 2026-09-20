package config

import (
	"fmt"
	"strconv"
	"strings"
)

// secureTunnelIndex parses a secure-tunnel BASE name (`st<N>`, no unit
// suffix) into its index, reporting ok=false for every name that is NOT a
// secure tunnel.
//
// This is the ONE range rule for the `st` namespace, and it is deliberately
// unexported: XFRMIfNameAndID (which builds the device) and
// IsSecureTunnelIfName (which classifies it) both call it, so the two can no
// longer disagree about what an `st` name is.
//
// #6691: they DID disagree. IsSecureTunnelIfName ran a bare strconv.Atoi with
// no bounds, so `st-3` and `st65536` classified as secure tunnels while
// XFRMIfNameAndID refuses to derive an if_id for either (negative index; index
// >= 0x10000 would overflow the 16-bit index field of `stIndex<<16 | unit+1`).
// Interface names are wildcard-authorable with no `st` reservation
// (schema_interfaces.go), so `st65536` is a perfectly ordinary data interface —
// and classifying it as a secure tunnel dropped it from the userspace ingress
// map, the AF_XDP binding plan and the RSS allowlist. That is a traffic outage
// on a valid interface, produced by a classifier that admitted names the
// constructor rejects.
//
// The sign is accepted because strconv.Atoi accepts it: `st+5` parses to index
// 5 and DOES yield a device, so it must classify as a secure tunnel. `st-3`
// parses to -3 and yields nothing, so it must not.
//
// There is no longer a Rust mirror of this rule to keep in step. #6691 round 5
// DELETED `is_secure_tunnel_ifname` (userspace-dp/src/server/helpers/planning.rs)
// rather than re-deriving the range on that plane: the dataplane's question is
// ownership, which only the control plane can answer, so it now reads the
// snapshot's `secure_tunnel` flag. This range therefore has exactly one
// implementation, and the lexical question it answers is asked only in Go.
func secureTunnelIndex(base string) (int, bool) {
	if len(base) < 3 || base[:2] != "st" {
		return 0, false
	}
	idx, err := strconv.Atoi(base[2:])
	if err != nil || idx < 0 || idx >= 0x10000 {
		return 0, false
	}
	return idx, true
}

// XFRMIfNameAndID resolves a secure-tunnel bind-interface to the Linux xfrmi
// device name and a stable XFRM if_id.
func XFRMIfNameAndID(bindIface string) (string, uint32) {
	if bindIface == "" {
		return "", 0
	}

	parts := strings.SplitN(bindIface, ".", 2)
	stIndex, ok := secureTunnelIndex(parts[0])
	if !ok {
		return "", 0
	}

	unit := 0
	if len(parts) == 2 {
		parsed, err := strconv.Atoi(parts[1])
		if err != nil || parsed < 0 || parsed >= 0xffff {
			return "", 0
		}
		unit = parsed
	}

	ifID := uint32(stIndex)<<16 | uint32(unit+1)
	if ifID == 0 {
		return "", 0
	}

	return LinuxIfName(bindIface), ifID
}

// IsSecureTunnelIfName reports whether an interface BASE name (no unit
// suffix) is a secure-tunnel interface — `st<N>` for an N that yields a
// usable XFRM if_id.
//
// This is the shared predicate behind the "do not unit-zero-collapse a secure
// tunnel" rule. A secure tunnel is materialized by the xfrmi reconciler
// (pkg/routing/xfrm.go) under exactly `LinuxIfName(bindInterface)` — the
// AUTHORED string. It is NOT "the dotted ref verbatim", as an earlier revision
// of this comment said: `bind-interface st0.0` creates a netdev named `st0.0`
// but `bind-interface st0` creates one named `st0`, and the unit ref is
// `st0.0` in both cases. The name therefore cannot be derived from the ref at
// all — see SecureTunnelUnitNetdev, which reads it back from the config.
//
// It is NOT true that every resolver calls it. Two live sites in
// pkg/dataplane/compiler_iface.go still derive the netdev from the ref, and
// both are reached on the userspace path (loader.go CompileConfig →
// compiler.go compileZones):
//
//	:73   resolveInterfaceRef          physName = config.LinuxIfName(ref)
//	:805  buildInterfaceNetworkdModels XFRMIfNameAndID("<ifName>.<unit>")
//
// That file calls SecureTunnelUnitNetdev zero times. The migration is 3 of 5
// resolvers, tracked as #6728-#6731, and userspace-dp/src/server/README.md
// scopes it correctly — this comment is the one that overstated it. Do not
// restore the absolute here without re-counting the call sites; an unqualified
// "every" in a doc is what a later reader will rely on instead of grepping.
//
// Callers of the PREDICATE, as of #6691 round 6: SecureTunnelUnitNetdev and
// ResolveKernelIfName's verbatim fallback — both LEXICAL questions ("is this
// ref shaped like an xfrmi unit at all?"). It is NOT the ownership test and
// no longer gates any dataplane set: userspaceSkipsIngressInterface used to
// call it and now reads the snapshot's SecureTunnel flag instead (round 5),
// and the Rust mirror is_secure_tunnel_ifname was deleted rather than
// re-derived. Before #5619 the dataplane copy silently lacked the RESOLUTION
// rule, so a secure-tunnel unit resolved to a nonexistent netdev, reported
// ifindex 0 / MTU 0 / no addresses, and fell out of every ifindex-keyed
// dataplane set.
//
// Scope: this is the BASE-name test, and it answers exactly one question —
// "would XFRMIfNameAndID build an xfrmi for this base?". It shares
// secureTunnelIndex with that constructor, so the two cannot drift.
//
// #6691 folded the range in, which is a behaviour change and the point of the
// fix: the earlier revision ran a bare Atoi with no bounds and so classified
// `st-3` and `st65536` as secure tunnels even though XFRMIfNameAndID creates no
// device for either. Interface names are wildcard-authorable and nothing
// reserves the `st` prefix, so `st65536` is an ordinary data interface — and
// mis-classifying it removed it from the ingress-adjudication map, the AF_XDP
// binding plan and the RSS allowlist. A classifier that admits names the
// constructor rejects does not "stay a pure name-shape question"; it takes a
// live interface out of the dataplane.
//
// This does NOT bound the UNIT (`st0.70000`): the unit lives on the ref, not on
// the base, and every caller passes a base. Callers that need the unit bounded
// go through XFRMIfNameAndID, which checks it.
func IsSecureTunnelIfName(base string) bool {
	_, ok := secureTunnelIndex(base)
	return ok
}

// SecureTunnelUnitNetdev resolves the kernel netdev for a secure-tunnel UNIT
// ref (`st<N>.<unit>`), and is the SINGLE resolver behind that rule — not a
// rule restated in each caller and asserted to agree.
//
// Returns ok=false when the ref is not a secure-tunnel unit, which is the
// signal for the caller to fall through to its ordinary resolution. It never
// returns ok=true with an empty name.
//
// Callers: ResolveKernelIfName (types.go), snapshotLinuxName
// (pkg/dataplane/userspace/interfaces.go) and junosHostLinuxName
// (junos_host_deny.go).
//
// #6691: junosHostLinuxName is why this exists as a function rather than three
// copies. It resolves the iifname scope for the `to-zone junos-host ... deny`
// nft rules, and it did NOT have the rule. Before #5619 that was harmless —
// both sides collapsed `st0.0` to `st0` and agreed on a wrong name. Adding the
// rule to the snapshot alone made them disagree on a RIGHT one: the snapshot
// said `st0.0` (the device the xfrmi reconciler actually creates) while the nft
// renderer still emitted `iifname st0`, so with `bind-interface st0.0` a
// junos-host deny was scoped to a netdev that does not exist and the decrypted
// traffic — arriving on `st0.0` — never matched it. A security guard that
// cannot fire.
//
// THIS RESOLVER IS KEYED ON OWNERSHIP, NOT ON NAME SHAPE — the same rule the
// exclusion predicate is keyed on, and the half that was left behind when the
// predicate moved (#6691 round 6). An earlier revision returned ok=true with
// the verbatim ref for EVERY `st<N>.<unit>` that no VPN owned, which made the
// resolver lexical again one level down: nothing reserves the `st` prefix
// (schema_interfaces.go accepts a wildcard interface name), so
//
//	set interfaces st5 unit 0 family inet address 192.0.2.1/24
//
// with no IPsec anywhere resolved to the netdev `st5.0` instead of the NIC
// `st5`. At a name that exists on no box the row reports ifindex 0, and
// userspace-dp/src/filter/compiler.rs skips `if iface.ifindex <= 0` — so the
// unit's `filter input` never installed, nor its per-unit CoS, nor its
// routing-instance binding. On a VLAN unit (`st5 unit 3 vlan-id 80`, real
// device `st5.80`) it also took the junos-host DENY with it: the guard was
// scoped to a netdev on no box and could not fire, verbatim the failure
// TestJunosHostDenyScopeNamesTheSecureTunnelDevice exists to prevent. It also
// shadowed the TunnelNameMap arm at both dataplane call sites, so a GRE unit
// `st0.1` — real device `st0u1` — resolved to `st0.1` and fell out of
// populate_interfaces, assign_interface_filters and populate_egress.
//
// So ok=false is returned whenever NOTHING binds the ref: the caller then runs
// its ordinary resolution, which is what names the NIC, the VLAN device and
// the GRE device. The one case that still returns the verbatim ref is an if_id
// COLLISION, where routing creates NEITHER device (see
// SecureTunnelNetdevForRef): the ref names nothing on the box, and the caller's
// unit-0 collapse would alias the unit row onto `st<N>` — a name that is
// equally absent but LOOKS resolvable, and which is also the BASE row's name,
// so two rows would claim one netdev. Naming the absent-but-honest `st<N>.<M>`
// keeps the rows distinct.
func (c *Config) SecureTunnelUnitNetdev(ref string) (string, bool) {
	base, _, hasUnit := strings.Cut(ref, ".")
	if !hasUnit || !IsSecureTunnelIfName(base) {
		return "", false
	}
	switch dev, binding := c.secureTunnelBindingForRef(ref); binding {
	case secureTunnelBound:
		return dev, true
	case secureTunnelIDCollision:
		return LinuxIfName(ref), true
	default:
		return "", false
	}
}

// secureTunnelBinding is the three-way answer to "does an IPsec configuration
// bind this secure-tunnel ref, and can routing create the device?". The middle
// state exists because "unbound" and "collides" are DIFFERENT facts with
// different correct fallbacks — an unbound ref belongs to whatever ordinary
// interface carries the name, a colliding one belongs to nothing at all.
type secureTunnelBinding int

const (
	// secureTunnelUnbound: no configured VPN binds this ref. It is not a
	// secure tunnel, whatever it is spelled.
	secureTunnelUnbound secureTunnelBinding = iota
	// secureTunnelBound: exactly one xfrmi device owns it, and routing
	// creates that device.
	secureTunnelBound
	// secureTunnelIDCollision: distinct bind-interface strings derive this
	// ref's if_id, so pkg/routing/xfrm.go creates NEITHER device.
	secureTunnelIDCollision
)

// bindInterfaceOwnsRef reports whether the xfrmi device an authored
// `bind-interface` string creates IS the device an interface ref denotes.
// Callers must have already established that the two derive the same if_id.
//
// #6691: the if_id ALONE cannot answer this, which is the defect this exists to
// close. XFRMIfNameAndID derives the index with strconv.Atoi, and Atoi erases a
// leading `+` and leading zeros — so `st5`, `st05`, `st+5` and `st0000005` all
// derive if_id 0x50001 while LinuxIfName keeps them as four DIFFERENT device
// names. Keying ownership on the if_id alone therefore let a VPN binding `st05`
// claim a wildcard-authored NIC named `st5`: the NIC's rows came back
// secureTunnel=true with an empty ingress set and an empty RSS allowlist, a
// live interface removed from the dataplane by a VPN that never names it.
// Commit does not stop this — ValidateSecureTunnelBindInterface only requires
// if_id != 0, and `st05` is a perfectly good (if unusual) xfrmi name.
//
// Ownership is therefore decided on the AUTHORED SPELLING, which is what the
// device name is made of: pkg/routing/xfrm.go keys its desired set by
// LinuxIfName(bindInterface), so `bind-interface st05` creates a device called
// `st05` and NOTHING called `st5`. Comparing the authored strings directly is
// exact here because every base that reaches this point is `st` followed by an
// optionally-signed decimal (secureTunnelIndex enforces it) and LinuxIfName —
// which only rewrites `/` to `-` — is the identity on such a name.
//
// THE RELATION IS DIRECTIONAL, and #6691 round 7 is the round that got that
// right. An earlier revision compared BASES ONLY, which is symmetric, and a
// symmetric test cannot express "the device is `st5.0`, so the row named `st5`
// is not it":
//
//   - A DOTTED ref (`st5.0`) is a LOGICAL UNIT. Its device is whatever spelling
//     the operator authored, because a bare `st5` and an explicit `st5.0` are
//     the same xfrmi under two names (pkg/routing/xfrm.go). Both authored
//     spellings own it. The unit does not need comparing: given equal if_ids
//     and equal bases the indexes are equal, so `stIndex<<16 | unit+1` forces
//     the units equal too — which is why a bare `st0` owns `st0.0` while
//     `st10` does NOT own `st10.5`.
//   - A BARE ref (`st5`) is a BASE ROW, and a base row's netdev is the ref
//     itself — snapshotLinuxName keeps `LinuxIfName(ifName)` for it and does
//     NOT consult this resolver. So it is an xfrmi only when a VPN authored
//     that exact bare name. `bind-interface st5.0` creates `st5.0` and nothing
//     called `st5`, so it must not claim the `st5` row.
//
// Measured on the second half, with `bind-interface st5.0` and a real NIC
// `st5` (nothing reserves the prefix) carrying a zoned unit 3: the base row
// came back `LinuxName "st5"`, ifindex 11, `secureTunnel=true`, and `st5`
// was ABSENT from the RSS/AF_XDP allowlist — the same live-NIC removal the
// `st05` half above describes, one spelling over.
func bindInterfaceOwnsRef(bindIface, ref string) bool {
	bindBase, _, bindHasUnit := strings.Cut(bindIface, ".")
	refBase, _, refHasUnit := strings.Cut(ref, ".")
	if bindBase != refBase {
		return false
	}
	if !refHasUnit {
		// The base row's netdev IS the bare ref; only a bare authored
		// spelling creates a device under that name.
		return !bindHasUnit
	}
	return true
}

// BindInterfaceOwnsRef reports whether the xfrmi device an authored
// `bind-interface` string creates IS the device an interface ref denotes.
// It is the exported daemon-facing wrapper over bindInterfaceOwnsRef and the
// only ownership API the P-MECH (#9506) staging path may call; config remains
// the single source of truth for ownership.
//
// Callers MUST have already established that both strings derive the same
// nonzero if_id via XFRMIfNameAndID. Rule: same base required; a BARE ref is
// owned only by a BARE bind, while a DOTTED ref is owned by either spelling.
func BindInterfaceOwnsRef(bindIface, ref string) bool {
	return bindInterfaceOwnsRef(bindIface, ref)
}

// SecureTunnelNetdevForRef returns the Linux netdev the xfrmi reconciler
// creates for a secure-tunnel UNIT reference (e.g. "st0.0"), resolved from the
// AUTHORED `bind-interface` string rather than reconstructed from the ref.
//
// This distinction is the whole point. The reconciler creates the device as
// `LinuxIfName(bindInterface)` VERBATIM, and a bare `st0` and an explicit
// `st0.0` derive the SAME XFRM if_id under DIFFERENT device names — stated
// outright in pkg/routing/xfrm.go:
//
//	"a bare "st0" and an explicit "st0.0" both yield if_id 1 ... under
//	 DIFFERENT device names ("st0" vs "st0.0")"
//
// So the netdev name simply CANNOT be derived from the unit ref: `st0.0` is
// the device for `bind-interface st0.0` and `st0` is the device for
// `bind-interface st0`, and the ref is identical in both cases. It has to be
// read back from whichever string the operator actually authored.
//
// The if_id is the join key that makes that lookup well-defined, and
// XFRMIfNameAndID is the single source of truth for both halves of it.
// Reconstructing a name that another component owns is exactly what caused the
// #5619 drift; doing it again inside the fix would be the same mistake one
// level down.
//
// Returns ("", false) when no configured VPN binds this ref's if_id — then no
// xfrmi device exists for the unit at all and the caller keeps its own
// fallback, rather than this inventing a name for a device nobody creates.
//
// FAILS CLOSED under an if_id collision — two DISTINCT bind-interface strings
// deriving one if_id (e.g. `st0` and `st0.0`) resolve to NOTHING, not to a
// winner. #6691: an earlier revision picked the lexicographically smallest name
// "for determinism", which is the wrong contract. pkg/routing/xfrm.go treats a
// collision as unresolvable and deletes BOTH devices from its desired set
// ("refusing to create either (cross-VPN leak / EEXIST risk)"), so on a box in
// that state NEITHER name exists. Naming one of them anyway does not make the
// resolver deterministic-and-correct; it makes it deterministically WRONG, and
// it attaches forwarding state to a device the reconciler has guaranteed is
// absent (or, worse, to a stale leftover under that name).
//
// Two VPNs authoring the SAME bind-interface string are not a collision — one
// name, one device — and routing programs it. This mirrors that: only DISTINCT
// names for one if_id fail.
//
// Strict commit rejects such a config (#2933) and apply refuses it (#2909), so
// this governs only the tolerant-load path — which is precisely the path that
// must not invent a device.
//
// OWNERSHIP AND THE COLLISION VETO ARE SEPARATE TESTS (#6691 round 6), because
// they answer to different components. Ownership asks "is this ref THIS
// device?" and is settled on the authored spelling (bindInterfaceOwnsRef) — an
// if_id match alone let `bind-interface st05` claim a NIC named `st5`. The veto
// asks "will routing create the device at all?" and must stay keyed on the
// if_id, because that is the key pkg/routing/xfrm.go collides on. Both are
// needed: drop the veto and a config binding BOTH `st5` and `st05` would
// resolve `st5.0` to `st5`, a device routing has already refused to create —
// the same divergence one spelling over.
//
// AND THEY ARE ASKED IN THAT ORDER (#6691 round 7). Round 6 evaluated the veto
// first, so a collision between two spellings that name NEITHER of the ref's
// devices still vetoed the ref — see secureTunnelBindingForRef for the
// measured counterexample. A veto is only the ref's to cast once something has
// said the ref is in scope.
func (c *Config) SecureTunnelNetdevForRef(ref string) (string, bool) {
	dev, binding := c.secureTunnelBindingForRef(ref)
	return dev, binding == secureTunnelBound
}

// secureTunnelBindingForRef is the shared core of SecureTunnelNetdevForRef and
// SecureTunnelUnitNetdev. It reports the owning device name (empty unless the
// binding is secureTunnelBound) and which of the three states the ref is in.
//
// OWNERSHIP IS SETTLED BEFORE THE VETO IS CONSULTED, and the order is the
// contract (#6691 round 7):
//
//	no name owner        -> unbound
//	owner + collision    -> collision veto
//	owner + no collision -> bound
//
// Round 6 answered the two questions in the opposite order — it returned
// secureTunnelIDCollision from inside the loop, before anything had asked
// whether the ref was in scope at all — and a veto that fires for a ref nobody
// owns is a veto cast on someone else's device. Measured, through the real
// lenient compiler (strict commit rejects the config under #2933, so this is
// the tolerant load / peer-sync path the veto exists to govern):
//
//	set security ipsec vpn a bind-interface st05
//	set security ipsec vpn b bind-interface st0005
//	set interfaces st5 unit 0 family inet address 192.0.2.1/24
//
// Both bindings derive if_id 0x50001 and NEITHER names `st5`, yet the
// collision branch fired and SecureTunnelUnitNetdev returned ("st5.0", true).
// The `st5.0` row therefore reported the netdev `st5.0` — a name on no box, so
// ifindex 0 — instead of collapsing onto the real NIC `st5` at ifindex 11: its
// `filter input`, its per-unit CoS and its routing-instance binding never
// installed, the junos-host deny was scoped to a device that does not exist,
// and a phantom `st5.0` entered the AF_XDP/RSS allowlist.
//
// The collision must still be detected across the WHOLE loop rather than
// short-circuited, so it is accumulated. That keeps the result a pure function
// of the config: `owner` is set by any binding that names the ref, `collision`
// once two distinct names have been seen, and both are order-independent (with
// no collision every claimant carries the same name, so `owner` is unique).
func (c *Config) secureTunnelBindingForRef(ref string) (string, secureTunnelBinding) {
	if c == nil {
		return "", secureTunnelUnbound
	}
	_, wantID := XFRMIfNameAndID(ref)
	if wantID == 0 {
		return "", secureTunnelUnbound
	}
	// claimant is the device name routing would create for this if_id; owner
	// is the one that also NAMES this ref. They differ exactly in the `st05`
	// vs `st5` case, which is the round-6 F2 defect.
	claimant, owner := "", ""
	collision := false
	for _, vpn := range c.Security.IPsec.VPNs {
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		name, id := XFRMIfNameAndID(vpn.BindInterface)
		if id != wantID || name == "" {
			continue
		}
		if claimant != "" && name != claimant {
			// Distinct names, one if_id: routing creates neither.
			collision = true
		}
		claimant = name
		if bindInterfaceOwnsRef(vpn.BindInterface, ref) {
			owner = name
		}
	}
	if owner == "" {
		// Either nothing derives this if_id at all, or something does but
		// under a spelling that names a DIFFERENT device — not this ref. A
		// collision among those other spellings is not this ref's business:
		// the devices routing refuses to create are theirs, not its.
		return "", secureTunnelUnbound
	}
	if collision {
		return "", secureTunnelIDCollision
	}
	return owner, secureTunnelBound
}

// ValidateSecureTunnelBindInterface reports whether a `security ipsec vpn
// <name> bind-interface` value is a canonical secure-tunnel interface — the
// only shape the route-based-VPN datapath can bind. The accepted lexical form
// is st<N> or st<N>.<unit> (e.g. st0, st0.1); XFRMIfNameAndID resolves every
// other name to if_id 0, which the pkg/routing reconciler treats as "invalid
// bind-interface name" and creates NO XFRM device for. Such a config commits
// successfully yet the VPN is silently DOWN (#5297).
//
// The if_id-0 sentinel from XFRMIfNameAndID is the authoritative
// "creates no XFRM device" signal; the message states the canonical lexical
// requirement so the operator sees an actionable error rather than an opaque
// id reference.
//
// Used both as the #1319 typed-leaf commit-check validator on the
// `bind-interface` schema leaf (schema_security.go) and — mirrored via
// XFRMIfNameAndID's if_id-0 check — by the compiled-config strict gate in
// compiler_ipsec_bindiface.go, which additionally catches group-expanded /
// packed forms the schema layer can miss (#1960 layered-defense doctrine).
func ValidateSecureTunnelBindInterface(raw string, _ *Config) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		return fmt.Errorf(
			"missing bind-interface (expected a secure-tunnel interface " +
				"st<N> or st<N>.<unit>, e.g. st0 or st0.1)")
	}
	if _, ifID := XFRMIfNameAndID(name); ifID == 0 {
		return fmt.Errorf(
			"invalid bind-interface %q: must be a secure-tunnel interface "+
				"st<N> or st<N>.<unit> (e.g. st0 or st0.1); any other name "+
				"resolves to no XFRM interface, so the route-based VPN commits "+
				"but carries no traffic (silent tunnel down)",
			raw)
	}
	return nil
}
