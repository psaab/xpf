package config

import (
	"fmt"
	"strings"
)

// Predefined IKE/IPsec proposal-set expansion (fable-167 V-1, #4297).
//
// Junos `security ike policy P proposal-set <set>` and
// `security ipsec policy P proposal-set <set>` are the standard shorthand
// operators use to avoid hand-defining proposals. Each named set expands to
// a fixed list of concrete proposals. Before this change the keyword was
// silently dropped by the compiler switch (unknown keys are ignored), so the
// policy resolved to NO proposal: the IPsec side hard-rejected with a
// misleading "no resolvable ipsec proposal" message and the IKE side left the
// chain unresolved (errIKEChainUnresolved) — either way the common vSRX idiom
// could not commit a working tunnel.
//
// The tables below are the single source of truth. They use Junos algorithm
// spellings; the pkg/ipsec renderer normalizes them to swanctl tokens
// (buildIKEProposalFromIKE / buildESPProposal) so the expansion needs no
// crypto knowledge here — it only names the members. Keeping the members in
// one explicit, tested table (rather than a hidden default substitution) is
// deliberate: the crypto is auditable and correctable, never fabricated.
//
// Members follow Juniper's published predefined-proposal tables:
//   - basic / compatible / standard: legacy DES/3DES/SHA1/MD5 sets. `basic`
//     is DH group 1 in Phase-1; `compatible` and `standard` are DH group 2.
//     These are weak by modern standards and a hardened strongSwan
//     build may not have the `des` plugin loaded; the operator asked for the
//     legacy set, so we expand it faithfully rather than silently upgrading.
//   - suiteb-gcm-128 / suiteb-gcm-256: RFC 6379 Suite-B — AES-GCM AEAD with
//     ECDSA authentication and an ECP (elliptic-curve) DH group. suiteb
//     requires ECDSA certificates (authMethodToSwan maps ecdsa-signatures to
//     pubkey); that is the operator's responsibility, exactly as on Junos.

// ikeProposalSetSpec is one Phase-1 proposal member of a predefined set.
type ikeProposalSetSpec struct {
	authMethod string // Junos authentication-method (pre-shared-keys / ecdsa-signatures)
	enc        string // Junos encryption-algorithm
	auth       string // Junos authentication-algorithm (also the AEAD PRF hint)
	dhGroup    int    // Diffie-Hellman group number
}

// espProposalSetSpec is one Phase-2 (ESP) proposal member of a predefined set.
type espProposalSetSpec struct {
	enc     string // Junos encryption-algorithm
	auth    string // Junos authentication-algorithm ("" for AEAD/GCM)
	dhGroup int    // PFS DH group carried on the proposal (0 = no PFS)
}

// ikeProposalSets maps a Junos IKE proposal-set keyword to its member
// proposals, in negotiation-preference order.
var ikeProposalSets = map[string][]ikeProposalSetSpec{
	"basic": {
		// Junos `basic` IKE set is DH GROUP 1 (not group 2 — that is
		// `compatible`/`standard`). A real vSRX peer with `proposal-set basic`
		// offers group1/DES in Phase-1, so offering group2 here would mismatch
		// the DH group and no common proposal would negotiate.
		{"pre-shared-keys", "des-cbc", "sha1", 1},
		{"pre-shared-keys", "des-cbc", "md5", 1},
	},
	"compatible": {
		{"pre-shared-keys", "3des-cbc", "sha1", 2},
		{"pre-shared-keys", "3des-cbc", "md5", 2},
		{"pre-shared-keys", "des-cbc", "sha1", 2},
		{"pre-shared-keys", "des-cbc", "md5", 2},
	},
	"standard": {
		{"pre-shared-keys", "3des-cbc", "sha1", 2},
		{"pre-shared-keys", "aes-128-cbc", "sha1", 2},
	},
	"suiteb-gcm-128": {
		{"ecdsa-signatures", "aes-128-gcm", "sha-256", 19},
	},
	"suiteb-gcm-256": {
		{"ecdsa-signatures", "aes-256-gcm", "sha-384", 20},
	},
}

// espProposalSets maps a Junos IPsec proposal-set keyword to its member ESP
// proposals. Junos defines `standard` as the group-2 PFS set (g2-esp-3des /
// g2-esp-aes128), so its members carry DH group 2 on the proposal and
// buildESPProposal renders the -modp1024 term; without it a Junos peer's
// PFS child rekey is refused NO_PROPOSAL_CHOSEN (#15026). `basic` and
// `compatible` carry no PFS; the suiteb sets carry their Suite-B ECP group
// as the proposal's PFS group so buildESPProposal renders the ecp<N> term.
var espProposalSets = map[string][]espProposalSetSpec{
	"basic": {
		{"des-cbc", "hmac-sha1-96", 0},
		{"des-cbc", "hmac-md5-96", 0},
	},
	"compatible": {
		{"3des-cbc", "hmac-sha1-96", 0},
		{"3des-cbc", "hmac-md5-96", 0},
		{"des-cbc", "hmac-sha1-96", 0},
		{"des-cbc", "hmac-md5-96", 0},
	},
	"standard": {
		{"3des-cbc", "hmac-sha1-96", 2},
		{"aes-128-cbc", "hmac-sha1-96", 2},
	},
	"suiteb-gcm-128": {
		{"aes-128-gcm", "", 19},
	},
	"suiteb-gcm-256": {
		{"aes-256-gcm", "", 20},
	},
}

// ProposalSetNames returns the supported predefined proposal-set keywords
// (sorted, stable) for schema enum validation and completion.
func ProposalSetNames() []string {
	return []string{"basic", "compatible", "standard", "suiteb-gcm-128", "suiteb-gcm-256"}
}

// reservedProposalSetNamePrefix is the name namespace the compiler OWNS for the
// synthetic proposals it mints when expanding a predefined `proposal-set`
// (syntheticProposalSetName). expandIKEProposalSets / expandIPsecProposalSets
// write concrete proposals under `<prefix><policy>/<set>/<index>` names into the
// SAME IKEProposals / Proposals maps that hold operator-authored proposals,
// AFTER those maps are built. Because the lexer permits `/ _ .` in bare
// identifiers an operator can author a proposal with that exact name, so the two
// namespaces could alias and one would silently overwrite the other — installing
// a different (typically weaker) crypto proposal than configured, a silent
// downgrade (#5195, codex-177 A3-b2-F7). validateReservedIPsecProposalNamesAST
// reserves this prefix at strict commit so an authored proposal can never take
// a synthetic name, and the expand loops keep an occupancy guard as belt-and-
// suspenders on the lenient load path.
const reservedProposalSetNamePrefix = "__proposal-set/"

// syntheticProposalSetName builds a deterministic, collision-resistant name
// for a proposal synthesized from a policy's proposal-set. The rendered
// swanctl proposal is the crypto token string (buildIKEProposalFromIKE /
// buildESPProposal), not this name, so the name is internal only; the reserved
// "__proposal-set/" prefix (rejected for authored names at commit) keeps it
// clear of operator-authored proposal names.
func syntheticProposalSetName(policy, set string, n int) string {
	return fmt.Sprintf("%s%s/%s/%d", reservedProposalSetNamePrefix, policy, set, n)
}

// validateReservedIPsecProposalNamesAST rejects (strict) or warns (lenient) any
// operator-authored IKE or IPsec `proposal <name>` whose name uses the
// reservedProposalSetNamePrefix namespace the compiler owns for synthetic
// proposal-set expansion (#5195, codex-177 A3-b2-F7).
//
// Without this gate, an authored proposal named exactly
// `__proposal-set/<policy>/<set>/<index>` aliases the synthetic proposal that
// expandIKEProposalSets / expandIPsecProposalSets mint into the same name-keyed
// map, and the unconditional map write silently overwrites one with the other —
// a different, typically weaker crypto proposal is installed than the operator
// configured (a silent downgrade). Reserving the prefix at commit guarantees the
// authored and synthetic namespaces never alias, so the expansion is
// collision-free by construction.
//
// Runs on the group-expanded, inactive-pruned AST (apply-groups-inherited
// proposals covered; inactive ones ignored) and enumerates proposal names with
// the SAME namedInstances helper compileIKE / compileIPsec use to key the maps,
// so it checks exactly the names that could collide. Strict (commit /
// commit-check): the first reserved-prefix authored name hard-rejects. Lenient
// (load / peer-sync): warn so an already-persisted or peer-synced config an
// older binary silently accepted still boots (#1960) — the expand-time occupancy
// guard then keeps the authored proposal from being clobbered.
func validateReservedIPsecProposalNamesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(section, name string) error {
		msg := fmt.Sprintf(
			"security %s proposal %q uses the reserved %q name prefix, which the "+
				"compiler owns for predefined proposal-set expansion; an authored "+
				"proposal with this name would silently overwrite (or be overwritten "+
				"by) a synthetic set member, installing a different crypto proposal "+
				"than configured — rename the proposal (#5195)",
			section, name, reservedProposalSetNamePrefix)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}
	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		for _, section := range []string{"ike", "ipsec"} {
			if err := forEachChild(security.Children, section, func(s *Node) error {
				for _, inst := range namedInstances(s.FindChildren("proposal")) {
					if strings.HasPrefix(inst.name, reservedProposalSetNamePrefix) {
						if err := emit(section, inst.name); err != nil {
							return err
						}
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// expandIKEProposalSets synthesizes concrete IKE (Phase 1) proposals for every
// IKE policy that carries a `proposal-set`, appending them to the IKE proposal
// map and pointing the policy's Proposals list at them. It runs after the IKE
// proposal and policy loops so both maps exist. A policy that ALSO lists
// explicit `proposals` keeps them (proposal-set is the no-explicit-proposals
// shorthand and is mutually exclusive with `proposals` in Junos); the set only
// fills an empty list. An unknown set keyword is left unexpanded — the schema
// enum validator rejects it at commit.
func expandIKEProposalSets(sec *SecurityConfig) {
	if sec == nil || sec.IPsec.IKEPolicies == nil {
		return
	}
	if sec.IPsec.IKEProposals == nil {
		sec.IPsec.IKEProposals = make(map[string]*IKEProposal)
	}
	for _, pol := range sec.IPsec.IKEPolicies {
		if pol == nil || pol.ProposalSet == "" || len(pol.Proposals) > 0 {
			continue
		}
		specs, ok := ikeProposalSets[pol.ProposalSet]
		if !ok {
			continue
		}
		for i, s := range specs {
			name := syntheticProposalSetName(pol.Name, pol.ProposalSet, i+1)
			// #5195 defense in depth: never silently clobber a slot already
			// occupied by an operator-authored proposal. The strict commit gate
			// (validateReservedIPsecProposalNamesAST) reserves this prefix, so on
			// the commit path the slot is always free; the guard matters only on
			// the lenient load / peer-sync path, where a config an older binary
			// accepted may still squat the name — keep the authored proposal
			// rather than overwriting it with the (possibly weaker) set member.
			if _, taken := sec.IPsec.IKEProposals[name]; !taken {
				sec.IPsec.IKEProposals[name] = &IKEProposal{
					Name:          name,
					AuthMethod:    s.authMethod,
					EncryptionAlg: s.enc,
					AuthAlg:       s.auth,
					DHGroup:       s.dhGroup,
				}
			}
			pol.Proposals = append(pol.Proposals, name)
		}
	}
}

// expandIPsecProposalSets is the Phase-2 (ESP) mirror of
// expandIKEProposalSets.
func expandIPsecProposalSets(sec *SecurityConfig) {
	if sec == nil || sec.IPsec.Policies == nil {
		return
	}
	if sec.IPsec.Proposals == nil {
		sec.IPsec.Proposals = make(map[string]*IPsecProposal)
	}
	for _, pol := range sec.IPsec.Policies {
		if pol == nil || pol.ProposalSet == "" || len(pol.Proposals) > 0 {
			continue
		}
		specs, ok := espProposalSets[pol.ProposalSet]
		if !ok {
			continue
		}
		for i, s := range specs {
			name := syntheticProposalSetName(pol.Name, pol.ProposalSet, i+1)
			// #5195 defense in depth: see expandIKEProposalSets — do not
			// overwrite an operator-authored proposal that squats a synthetic
			// name on the lenient load path (the strict gate reserves the prefix
			// so this cannot happen on commit).
			if _, taken := sec.IPsec.Proposals[name]; !taken {
				sec.IPsec.Proposals[name] = &IPsecProposal{
					Name:          name,
					Protocol:      "esp",
					EncryptionAlg: s.enc,
					AuthAlg:       s.auth,
					DHGroup:       s.dhGroup,
				}
			}
			pol.Proposals = append(pol.Proposals, name)
		}
	}
}
