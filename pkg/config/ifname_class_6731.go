package config

import "strings"

// ifname_class_6731.go carries the canonical name-class predicates for the
// interface namespaces that a DHCP client can never live on: loopback, GRE,
// IP-IP, flexible-tunnel and secure-tunnel.
//
// They exist because raw prefix tests are WRONG here, not merely loose.
// Interface names are wildcard-authorable with no reservation on these prefixes
// (`schema_interfaces.go`), so `strings.HasPrefix(name, "lo")` also matches
// `login0`, `"st"` matches `start0`, `"fti"` matches `ftime0`, and `"gr-"`
// matches `gr-eenwich`. Each of those is an ordinary data interface that an
// operator may legitimately name and run a DHCP client on, and the prefix test
// refused it (#6731).
//
// The rule per namespace is the one the rest of the tree already uses to
// RESOLVE a device in that namespace, so a name that no resolver would ever
// turn into a tunnel is not classified as one:
//
//   - `st<N>`  — IsSecureTunnelIfName, which shares its range rule with
//     XFRMIfNameAndID (`xfrmi.go`). A name outside the if_id range yields no
//     xfrmi, so it is not a secure tunnel — `st65536` is a data interface.
//   - `lo<N>` / `fti<N>` — the prefix followed by digits and nothing else.
//   - `gr-<port>` / `ip-<port>` — the prefix followed by a Junos port path,
//     which is how the interface compiler recognises them when it defaults a
//     tunnel's mode (`compiler_interfaces.go`: "ip-X/X/X → ipip, gr-X/X/X →
//     gre") and what LinuxIfName rewrites into a kernel name.

// ifNameNumericSuffix reports whether name is exactly prefix followed by one or
// more decimal digits — the `lo0` / `fti3` shape. The digits are not parsed into
// a value: no caller needs the index, and refusing a huge one would invent a
// range rule this namespace does not have (contrast IsSecureTunnelIfName, whose
// range comes from the XFRM if_id it must produce).
//
// NOTE: `isCanonicalFabricName` (lifeline.go) is the same rule for the `fab`
// namespace, and its doc makes the same point ("`fabric0` are NOT canonical").
// The two are not merged here because the management-interface arm of this same
// validator still uses raw prefixes and has the identical defect; single-sourcing
// this formula belongs with that fix, where both callers change together, rather
// than half-done now. Filed separately as #7515.
func ifNameNumericSuffix(name, prefix string) bool {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ifNameJunosPortPath reports whether name is prefix followed by a Junos port
// path — `gr-0/0/0`, and the `gr-0-0-0` spelling LinuxIfName produces. The
// component COUNT is deliberately not checked: this repo accepts both
// separators and the compiler's own tunnel-mode default keys on the prefix
// alone, so requiring exactly fpc/pic/port here would reject a form the rest of
// the tree admits. What it does reject is the reported defect — a name whose
// first character after the prefix is not a digit (`gr-eenwich`, `ip-sec0`).
func ifNameJunosPortPath(name, prefix string) bool {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" {
		return false
	}
	if rest[0] < '0' || rest[0] > '9' {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && r != '/' && r != '-' {
			return false
		}
	}
	return true
}

// IsTunnelOrLoopbackIfName reports whether base names an interface in a class
// that cannot carry a DHCP client: loopback, GRE, IP-IP, flexible-tunnel or
// secure-tunnel.
//
// It answers a LEXICAL question only. A caller that also has the compiled
// interface should test `ifc.Tunnel != nil` / `unit.Tunnel != nil` first — that
// is authoritative where it applies, and this predicate covers the case those
// miss: a tunnel-class NAME with no `tunnel` stanza, on which the interface
// compiler still accepts `family inet dhcp`.
func IsTunnelOrLoopbackIfName(base string) bool {
	switch {
	case IsSecureTunnelIfName(base):
		return true
	case ifNameNumericSuffix(base, "lo"), ifNameNumericSuffix(base, "fti"):
		return true
	case ifNameJunosPortPath(base, "gr-"), ifNameJunosPortPath(base, "ip-"):
		return true
	}
	return false
}

// IsLoopbackIfName reports whether base names a loopback interface: `lo<N>`
// (`lo0`, `lo1`, ...) or the bare kernel `lo`.

// It is deliberately loopback-ONLY. Do NOT substitute IsTunnelOrLoopbackIfName
// here: that predicate also matches GRE / IP-IP / flexible-tunnel /
// secure-tunnel names, which ARE legitimate policy-routing ingress interfaces,
// and using it would silently drop their steering (#9810 LEAD-O4 / SYN-LO0-02).

// The bare-`lo` arm deliberately diverges from the DHCP predicate, which pins
// {"lo", false}: DHCP asks "may a client live here", while policy routing asks
// "may an `iif` scope name this device" — and an `iif lo` rule matches traffic
// from sockets bound to ANOTHER VRF (the #9420 cross-VRF hijack). The two
// predicates must never be unified; see TestDefaultInstanceIngressIfacesExcludesLoopback_9810.
func IsLoopbackIfName(base string) bool {
	return base == "lo" || ifNameNumericSuffix(base, "lo")
}

// IsLoopbackIngress reports whether a configured interface name or a resolved
// kernel ingress name denotes loopback. Unit suffixes are stripped first: a
// configured `lo0` unit 5 resolves to `lo0.5`, which is loopback as much as
// `lo0` is (#9810 lo0.5 hole). The single shared test keeps the next-table
// scoping set and the PBR builder identical.
func IsLoopbackIngress(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	return IsLoopbackIfName(base)
}

// IsManagementIfName reports whether name is in the MANAGEMENT interface class —
// the names the daemon binds to `vrf-mgmt`.
//
// It is the SSOT for a rule that was previously restated verbatim at three
// sites, where a divergence is always a bug rather than a legitimate difference:
//
//   - `pkg/daemon/daemon_apply_interfaces.go` builds the management-VRF
//     interface set, which decides which leases `collectDHCPRoutes` EXCLUDES
//     from FRR (their routes go into table 999 by netlink instead);
//   - `pkg/dataplane/compiler_iface.go` emits `VRF=vrf-mgmt` into the
//     interface's `.network` file so `networkctl reconfigure` preserves that
//     binding;
//   - `pkg/config/compiler_services.go` refuses such an interface as an
//     ip-monitoring preferred-route next-hop, precisely BECAUSE its lease is
//     excluded from FRR.
//
// The third only tells the truth while it agrees with the first two. Three
// copies of a prefix list cannot be kept in agreement by convention.
//
// DELIBERATELY LOOSER THAN isCanonicalFabricName (lifeline.go), and the two must
// not be merged. That predicate answers "is this one of the daemon-CREATED
// fabric devices" for host-inbound lifeline exemption, and it excludes
// `fabric0`. This one answers "does the daemon bind this to vrf-mgmt", and today
// it DOES bind `fabric0` — so an ip-monitoring next-hop on `fabric0` is refused
// truthfully, not spuriously. Narrowing this class to match would change which
// interfaces land in the management VRF and therefore which DHCP routes FRR
// owns: a behaviour decision, tracked separately, and one this SSOT reduces to a
// single edit.
func IsManagementIfName(name string) bool {
	return strings.HasPrefix(name, "fxp") ||
		strings.HasPrefix(name, "fab") ||
		strings.HasPrefix(name, "em")
}
