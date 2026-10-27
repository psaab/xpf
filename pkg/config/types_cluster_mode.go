package config

// RethOwnershipMode is the derived classification of how redundancy-group
// ownership is decided for RETH interfaces (#17170). The two chassis-cluster
// booleans NoRethVRRP and PrivateRGElection are the persisted Junos surface;
// this enum is the single derived reading of the pair.
//
// The zero value is invalid and classifies a nil cluster config. A nil
// ClusterConfig is not the compiler default: it means "no cluster stanza at
// all", so it deliberately belongs to none of the three ownership modes.
// Consumers that must fail closed on an absent config (for example the
// #15165 legacy commit-ready gate) keep their own explicit nil check.
type RethOwnershipMode int

const (
	// RethOwnershipUnknown means no cluster config is present (nil receiver).
	RethOwnershipUnknown RethOwnershipMode = iota
	// RethVRRP means legacy mode: neither no-reth-vrrp nor private-RG
	// election, so RETH interfaces run VRRP.
	RethVRRP
	// RethDirectNoVRRP means no-reth-vrrp is set without private-RG
	// election: the daemon directly manages VIPs/GARPs without RETH VRRP.
	RethDirectNoVRRP
	// RethPrivateRG means private-RG election is in effect (the compiler
	// default): election runs over the control link and RETH VRRP is
	// suppressed. It wins over NoRethVRRP when both are set — the compiler
	// warns that the latter is then redundant.
	RethPrivateRG
)

// RethOwnershipMode classifies the two ownership booleans into the single
// mode they jointly select. Precedence when both are set is RethPrivateRG,
// matching the compiler's "no-reth-vrrp is redundant" warning.
func (cc *ClusterConfig) RethOwnershipMode() RethOwnershipMode {
	if cc == nil {
		return RethOwnershipUnknown
	}
	switch {
	case cc.PrivateRGElection:
		return RethPrivateRG
	case cc.NoRethVRRP:
		return RethDirectNoVRRP
	default:
		return RethVRRP
	}
}

// UsesRethVRRP reports whether RETH interfaces run VRRP (the legacy mode).
// Because it is derived from RethOwnershipMode, a nil cluster config — which
// carries no cluster stanza and therefore no RETH VRRP instances — returns
// false. That is the reading every former `cc != nil && (cc.NoRethVRRP ||
// cc.PrivateRGElection)` suppression site needs: with private-RG election
// the compiler default, "no flag" suppresses RETH VRRP, not the reverse.
func (cc *ClusterConfig) UsesRethVRRP() bool {
	return cc.RethOwnershipMode() == RethVRRP
}
