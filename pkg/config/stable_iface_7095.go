package config

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
)

// stable_iface_7095.go — #7095: a CLUSTER-STABLE name for a session's ingress
// interface, so the #4983 identity can ride the HA session-sync wire.
//
// WHY NOT THE IFINDEX. An ifindex is NODE-LOCAL. Node 0's `ge-0-0-1` and node
// 1's `ge-7-0-1` are the same logical RETH member with different numbers, so
// shipping the originating node's value renders a confidently WRONG interface
// name on the importing node — worse than the zone approximation it would
// replace. #6928 therefore syncs nothing and the peer falls back to the zone.
//
// WHAT IS STABLE. The RETH-RELATIVE name is: `docs/ha-cluster-userspace.conf`
// binds its zones to `reth0.50` / `reth0.80` / `reth1` — byte-identical strings
// on both nodes — while only the members differ, and RethToPhysical resolves
// reth to the LOCAL member by node id. So both nodes agree on the name by
// construction, and each resolves it to its own device. That is what rides the
// wire, folded to a u32 in the manner of StableZoneID (#3075).
//
// ZERO IS "UNKNOWN", AND IT IS ALSO WHAT A LEGACY PEER SENDS. The wire field is
// length-gated (the #2170 Generation pattern), so an old sender emits nothing,
// the decoder reads absent, and the value is 0 — the same 0 a fabric-redirected
// session records deliberately (#7096: the fabric stamp carries a u16 zone id
// and nothing else, so the peer's real ingress interface is not knowable on the
// receiving node). One encoding serves both, and the consumer's fallback for
// both is the #4792 zone approximation. Do NOT add a separate unknown marker.

// StableIfaceID folds a cluster-stable interface name to a non-zero u32.
//
// Zero is reserved as the unknown/legacy sentinel, so the fold never returns
// it: a name that hashes to 0 is mapped to 1. That collision is one extra name
// sharing bucket 1, which the reverse lookup resolves the same way it resolves
// any other collision — by comparing candidate names, not by trusting the id.
func StableIfaceID(name string) uint32 {
	if name == "" {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint32(s) ^ uint32(s>>32)
	if folded == 0 {
		return 1
	}
	return folded
}

// stableIfaceSelectionKind classifies how ClusterStableIfaceName resolved
// its fold owner (#9821 F-R71): the VLAN-append rule depends on the KIND,
// because a string-suffix comparison alone confuses declaration text with
// encoded VLAN (`p.100`+100 vs `p.100.100`+0 diverge).
type stableIfaceSelectionKind int

const (
	// stableIfaceDeclaredExact: the input linux-matches a declaration —
	// fold base is the input, and a param suffix is ALWAYS appended (it
	// is declaration text, never an encoding).
	stableIfaceDeclaredExact stableIfaceSelectionKind = iota
	// stableIfaceChildDevice: the input is a vlan/unit child device of a
	// declared owner — fold base is the owner, and the param wins on
	// conflict (legacy shape).
	stableIfaceChildDevice
	// stableIfaceLegacy: everything else — byte-identical legacy.
	stableIfaceLegacy
)

// ClusterStableIfaceName maps a LOCAL interface name and VLAN id to the name
// both nodes agree on, or "" when there is none.
//
// A member of a RETH becomes its reth-relative form (`ge-0-0-1` -> `reth1`); a
// non-member keeps its own name, which is stable only if both nodes happen to
// name it identically. That second case is deliberately included: a
// single-homed interface with the same name on both nodes (a management or
// fabric-parent link) is as agreed as a reth is, and excluding it would report
// "unknown" for a session whose interface both nodes can name.
//
// The VLAN suffix is appended when vlan > 0, matching how zones bind units
// (`reth0.50`). A VID of 0 is not distinguishable from an untagged frame at
// this layer (see SessionValue.IngressVlanID), so it contributes no suffix —
// except on a vlan-child DEVICE input, whose inherent suffix is part of the
// child identity (#9821 D25 convergence: (D,V)+(V) ≡ (D.V,0)).
func (c *Config) ClusterStableIfaceName(local string, vlan uint16) string {
	if c == nil || local == "" {
		return ""
	}
	owner, kind, childSuffix := c.selectStableIfaceOwner(local)
	// RETH conversion AFTER owner selection, in all arms (Codex
	// prescription): a member folds to its reth-relative form, dotted
	// owners never match dot-free members and fall through.
	//
	// The caller's name may be either spelling: config carries the Junos form
	// (`ge-0/0/1`) while the kernel — and therefore anything derived from an
	// ifindex — carries the Linux one (`ge-0-0-1`). Compare in the Linux form so
	// both land on the same member.
	//
	// Getting this wrong does not fail loudly: an unmatched member keeps its own
	// name, so node 0 would fold `ge-0-0-1` while node 1 folds `ge-7-0-1`, the
	// folds would disagree, the peer would resolve nothing, and every session
	// would silently degrade to the zone approximation — the exact outcome this
	// change exists to remove, with no error anywhere.
	stable := owner
	for reth, member := range c.RethToPhysical() {
		if LinuxIfName(member) == LinuxIfName(owner) {
			stable = reth
			break
		}
	}
	switch kind {
	case stableIfaceChildDevice:
		// Fold base is the OWNER: param wins on conflict (`p.0.100`,50 →
		// `p.0.50`), the inherent suffix stays otherwise (`p.0.100`,0 and
		// (…,100) both fold `p.0.100` — no double). This is the
		// convergence theorem: (D,V)+(V) ≡ (D.V,0) whenever V is a
		// configured vlan/unit of D.
		if vlan > 0 {
			return stable + "." + strconv.FormatUint(uint64(vlan), 10)
		}
		return stable + "." + childSuffix
	default:
		// DeclaredExact appends unconditionally (declaration text, never an
		// encoding); Legacy is byte-identical to before.
		if vlan > 0 {
			return stable + "." + strconv.FormatUint(uint64(vlan), 10)
		}
		return stable
	}
}

// selectStableIfaceOwner derives the fold owner with its selection kind
// (#9821 D25): (a) a linux-exact match of the input against a DECLARED
// interface folds the input UNTRUNCATED — dash-declared dotted now RESOLVES
// instead of truncating onto a possibly-declared truncation; (b) else a
// strip-one-numeric-suffix whose owner is linux-declared AND whose suffix is
// one of that owner's configured vlan-ids-or-unit-numbers folds the vlan/unit
// child device (D13 children `p.0.100`, unit-numbered devices); (c) else
// legacy first-cut (unknown shapes — byte-identical legacy).
//
// The child suffix is canonicalized numerically: kernel device spellings are
// canonical already, and a config-spelling caller with a padded suffix folds
// onto the enum candidate (which the enumeration builds canonically) instead
// of hash-missing beside it.
//
// Preservation proof (F-EVIDENCE, reworded): the fixture's three dot-free
// cells stay green (traced — each reaches (c) with the same owner the legacy
// cut produced, or (a) with the identical dot-free owner); the member
// vlan-child input is NOT pinned by the fixture — its preservation follows
// from (b)'s owner-scoped predicate (members carry no units, so (b) misses
// and (c) cuts to the member exactly as before). Explicit suffixed-input
// sender cells pin both (`reth0` / `reth0.50`).
//
// Rolling upgrade (F-MIXED): no wire bump — fold VALUE semantics, not schema,
// and a bump would flag-day ALL mixed pairs including dot-free. Mixed-window
// behavior is PROVED never-worse both directions (old-behavior equivalence
// pins: TestStableIfaceMixedNewToOld9821 in stable_iface_declared_9821_test.go
// and TestIngressFoldMixedOldToNew9821 in
// pkg/daemon/ingress_fold_declared_9821_test.go): new→old ≡ old→old
// case-by-case, old→new identical by construction (old folds are
// truncated/legacy forms the new receiver handles identically). New→new is
// the fixed cohort behavior.
func (c *Config) selectStableIfaceOwner(local string) (owner string, kind stableIfaceSelectionKind, childSuffix string) {
	want := LinuxIfName(local)
	for name, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if LinuxIfName(name) == want {
			return local, stableIfaceDeclaredExact, ""
		}
	}
	if i := strings.LastIndexByte(local, '.'); i > 0 {
		rawSuf, ownerText := local[i+1:], local[:i]
		if sufNum, err := strconv.Atoi(rawSuf); err == nil && rawSuf != "" {
			wantOwner := LinuxIfName(ownerText)
			var names []string
			for name, ifc := range c.Interfaces.Interfaces {
				if ifc == nil || LinuxIfName(name) != wantOwner {
					continue
				}
				names = append(names, name)
			}
			// First-sorted on linux-colliding declarations
			// (strict-injective per #5832/#7795; lenient pairs resolve
			// deterministically).
			sort.Strings(names)
			for _, name := range names {
				ifc := c.Interfaces.Interfaces[name]
				for unitNum, unit := range ifc.Units {
					if unit == nil {
						continue
					}
					if unit.VlanID == sufNum || unitNum == sufNum {
						// The declaration is used ONLY for the unit-set
						// membership check; the fold keeps the INPUT spelling
						// (ownerText), exactly as arm (a) folds the input
						// untruncated. Returning the config spelling here
						// split one dash-spelled identity into a dash fold
						// ((D,V)) and a slash fold ((D.V,0)) — one of which
						// misses the enum the other hits. Input spelling on
						// both arms keeps convergence within a spelling and
						// preserves slash-approximation for kernel (dash)
						// inputs: they fold dash and hash-miss the slash
						// enum, exactly as legacy first-cut did.
						return ownerText, stableIfaceChildDevice, strconv.Itoa(sufNum)
					}
				}
			}
		}
	}
	base := local
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base, stableIfaceLegacy, ""
}

// ClusterStableIfaceNames enumerates every cluster-stable name this config can
// produce, in a deterministic order.
//
// It is the candidate set the reverse lookup folds over. Enumerating rather
// than inverting the hash is what makes a collision harmless: two names folding
// alike are both candidates, and the caller sees the ambiguity instead of
// silently getting the wrong one.
func (c *Config) ClusterStableIfaceNames() []string {
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{})
	add := func(n string) {
		if n != "" {
			seen[n] = struct{}{}
		}
	}
	rethOf := make(map[string]string)
	for reth, member := range c.RethToPhysical() {
		rethOf[member] = reth
		add(reth)
	}
	for name, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		base := name
		if reth, ok := rethOf[name]; ok {
			base = reth
		}
		add(base)
		for _, unit := range ifc.Units {
			if unit != nil && unit.VlanID > 0 {
				add(base + "." + strconv.FormatUint(uint64(unit.VlanID), 10))
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// LocalIfaceForStableID resolves a wire fold back to a LOCAL interface name.
//
// It returns ok=false for 0 (unknown / legacy peer) and for an id no local name
// folds to — a session whose ingress interface this node does not have, which
// happens when the peer's config is ahead of ours. Both are the same answer to
// the consumer: fall back to the zone approximation rather than name a device.
//
// On a collision it returns ok=false as well, rather than the first match: two
// names folding alike means this node cannot tell WHICH interface the peer
// meant, and the zone approximation is honest where a coin flip is not.
func (c *Config) LocalIfaceForStableID(id uint32) (string, bool) {
	if c == nil || id == 0 {
		return "", false
	}
	var hit string
	for _, name := range c.ClusterStableIfaceNames() {
		if StableIfaceID(name) != id {
			continue
		}
		if hit != "" {
			return "", false
		}
		hit = name
	}
	if hit == "" {
		return "", false
	}
	return c.ResolveReth(hit), true
}
