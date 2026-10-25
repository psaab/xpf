// bfd.go holds the BFD (Bidirectional Forwarding Detection) profile/peer
// accumulator the protocol renderer uses to dedup and emit a single
// global `bfd` block across the default instance and every VRF (#2550).
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - bfdProfile, bfdPeer, bfdSection (+ methods), newBFDSection
//   - bfdProfileName
package frr

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// bfdProfile holds a unique BFD profile (interval + multiplier).
type bfdProfile struct {
	interval   int
	multiplier int
}

// bfdPeer holds a BGP BFD peer destined for the single top-level `bfd`
// block. vrfName carries the routing-instance the peer belongs to so
// bfdd associates the session with the VRF-bound neighbor (#2489).
type bfdPeer struct {
	address    string
	vrfName    string
	interval   int
	multiplier int
	// multihop (#14587): bgpd keys an iBGP (non-shared-network) or
	// ebgp-multihop session as multihop in bfdd (port 4784, local-address
	// = update-source). A plain single-hop peer stanza for such a
	// neighbor is an orphan bfdd never matches to bgpd's dynamic session,
	// so the configured timers never apply. #15135: a multihop peer is
	// renderable only WITH a valid localAddress — bfdd rejects the bare
	// `peer X multihop` line — so render() omits the peer entirely when
	// localAddress is empty/invalid (the bound profile still applies).
	multihop     bool
	localAddress string
}

// bfdSection accumulates BFD profiles and peers across the default
// routing instance AND every VRF so the FRR manager can emit a SINGLE
// top-level `bfd { ... }` block exactly once (#2550). FRR's bfdd is one
// global daemon; emitting a `bfd` stanza per routing instance produced
// redundant blocks and repeated profile definitions in the consolidated
// frr.conf, risking frr-reload parse warnings.
type bfdSection struct {
	profiles map[string]bfdProfile
	peers    []bfdPeer
}

// newBFDSection returns an empty accumulator.
func newBFDSection() *bfdSection {
	return &bfdSection{profiles: make(map[string]bfdProfile)}
}

// addProfile records a unique profile (dedup is by name, which already
// encodes interval+multiplier via bfdProfileName).
func (s *bfdSection) addProfile(name string, p bfdProfile) {
	s.profiles[name] = p
}

// addPeer appends a BGP BFD peer in caller (instance) order.
func (s *bfdSection) addPeer(p bfdPeer) {
	s.peers = append(s.peers, p)
}

// empty reports whether nothing was accumulated.
func (s *bfdSection) empty() bool {
	return len(s.profiles) == 0 && len(s.peers) == 0
}

// bfdDefaultMultiplier16813 / bfdDefaultInterval16813 are FRR bfdd's
// own defaults (frr-bfdd.yang: detection-multiplier default 3,
// desired-transmission-interval / required-receive-interval default
// 300000us). bfdd is northbound/YANG-backed: a leaf set to its YANG
// default is elided from `show running-config`, so rendering a
// default-valued line makes every `frr-reload.py --test` list it as
// an addition — a perpetual diff that can never certify the #15203
// benign-reload re-check (#16813). Render only non-default values;
// an all-default profile/peer renders as the bare header, which is
// exactly what FRR holds. Live-verified on FRR 10.7.1 (see
// docs/log/16813.md).
const (
	bfdDefaultMultiplier16813 = 3
	bfdDefaultInterval16813   = 300
)

// renderBFDTimers16813 writes the timer lines of one profile/peer
// stanza, omitting any line whose value equals the FRR default
// (#16813). interval drives both receive- and transmit-interval.
func renderBFDTimers16813(b *strings.Builder, interval, multiplier int) {
	if multiplier == 0 {
		multiplier = bfdDefaultMultiplier16813
	}
	if interval == 0 {
		interval = bfdDefaultInterval16813
	}
	if multiplier != bfdDefaultMultiplier16813 {
		fmt.Fprintf(b, "  detect-multiplier %d\n", multiplier)
	}
	if interval != bfdDefaultInterval16813 {
		fmt.Fprintf(b, "  receive-interval %d\n", interval)
		fmt.Fprintf(b, "  transmit-interval %d\n", interval)
	}
}

// render emits a single top-level `bfd` block containing all accumulated
func (s *bfdSection) render() string {
	if s.empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("bfd\n")
	for _, p := range s.peers {
		// A `peer <addr>` line with no `vrf` suffix lands in the DEFAULT
		// VRF. A VRF-scoped BGP session's BFD peer MUST carry the same
		// `vrf <name>` so bfdd associates the BFD session with the
		// VRF-bound neighbor; otherwise the session stays DOWN and
		// sub-second failover never works (#2489).
		// #14587: a multihop BGP neighbor (iBGP over loopbacks, or
		// ebgp-multihop) must be keyed `multihop local-address L` so
		// bfdd matches the static stanza to the dynamic session bgpd
		// creates (multihop port, update-source as local address). A
		// plain peer line is an orphan single-hop session at the
		// configured timers while bgpd's session runs FRR defaults.
		// #15135 (A89-03): a multihop peer WITHOUT a valid local-address
		// would render the bare line `peer X multihop`, which bfdd
		// 10.7.1 rejects (a multihop peer requires a local address to
		// bind) — frr-reload.py exits 1 and every commit fails to
		// converge. Emit NO static peer for such a neighbor: the
		// `neighbor X bfd profile <p>` binding still carries the
		// configured timers to bgpd's own dynamic multihop session, and
		// the `bfd` block survives on the profile alone. (A single-hop
		// fallback stanza would be the proven #14587 orphan, so it is
		// NOT emitted.) The validity test is the same single-token belt
		// as the BGP update-source render (#9493): an empty or
		// whitespace-bearing local-address has no renderable
		// local-address clause, hence no renderable multihop peer.
		if p.multihop && (p.localAddress == "" || !frrOperandOrOmit("bfd peer local-address", p.localAddress)) {
			slog.Warn("frr: omitting multihop BFD peer without a valid local-address; bound profile still carries timers (#15135)",
				"peer", sanitizeFRRValue(p.address))
			continue
		}
		suffix := ""
		if p.vrfName != "" {
			// Render belt (#5557): sanitize the routing-instance name like the
			// `router ... vrf` and static-route vrf clauses. A leniently-loaded
			// control character in the instance name would otherwise inject a
			// standalone line into the managed `bfd` block.
			suffix += " vrf " + sanitizeFRRValue(p.vrfName)
		}
		if p.multihop {
			suffix += " multihop local-address " + sanitizeFRRValue(p.localAddress)
		}
		fmt.Fprintf(&b, " peer %s%s\n", p.address, suffix)
		renderBFDTimers16813(&b, p.interval, p.multiplier)
		b.WriteString(" exit\n")
	}
	var profileNames []string
	for name := range s.profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		p := s.profiles[name]
		fmt.Fprintf(&b, " profile %s\n", name)
		renderBFDTimers16813(&b, p.interval, p.multiplier)
		b.WriteString(" exit\n")
	}
	b.WriteString("exit\n!\n")
	return b.String()
}

// bfdProfileName returns a deterministic profile name like "xpf-300-3".
func bfdProfileName(interval, multiplier int) string {
	if interval == 0 {
		interval = 300
	}
	if multiplier == 0 {
		multiplier = 3
	}
	return fmt.Sprintf("xpf-%d-%d", interval, multiplier)
}
