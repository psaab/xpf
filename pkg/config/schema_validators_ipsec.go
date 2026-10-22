package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateDHGroup accepts a Diffie-Hellman group as either a bare integer
// (e.g. "14") or the Junos "group<N>" spelling (e.g. "group14") — both are
// configured in the wild and both compile (compiler_ipsec.go strips the
// "group" prefix then Atoi's the remainder). The group number must be a
// positive integer: the compiler leaves DHGroup at 0 on a parse failure,
// and a 0/garbage group silently drops the modp term from the swanctl
// proposal (pkg/ipsec/ipsec.go buildIKEProposal / buildESPProposal gate on
// DHGroup > 0), so an invalid value commits and then quietly weakens the
// negotiated proposal. This validator closes that silent-drop while staying
// faithful to the two spellings the compiler already accepts.
func ValidateDHGroup(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a DH group, e.g. 14 or group14)")
	}
	num := strings.TrimPrefix(trimmed, "group")
	v, err := strconv.Atoi(num)
	if err != nil {
		return fmt.Errorf("not a valid DH group (got %q; expected an integer like 14 or group14)", raw)
	}
	if v < 1 {
		return fmt.Errorf("DH group must be a positive integer (got %d); 0 silently drops the modp term from the negotiated proposal", v)
	}
	// #8597 (muse-004 K88): accept exactly the groups the renderer can SPELL.
	//
	// Any positive integer used to pass here, and pkg/ipsec's formatDHGroup
	// falls through to `modp<n>` for anything outside its table — measured,
	// `dh-group 99` committed clean and rendered `modp99`, which charon
	// rejects. The operator gets an IPsec that never establishes and
	// diagnostics that point at charon rather than at the value they typed.
	//
	// Binding to config.DHGroupKeyword rather than a second list here is the
	// whole fix: the defect was a validator and a renderer with different
	// ideas of the accepted set, and a hand-copied set in the validator would
	// reproduce it.
	if _, ok := DHGroupKeyword(v); !ok {
		return fmt.Errorf("unsupported DH group %d; accepted groups are %v "+
			"(an unlisted group renders as a proposal keyword strongSwan does not "+
			"accept, so IPsec never establishes)", v, SupportedDHGroups())
	}
	return nil
}
