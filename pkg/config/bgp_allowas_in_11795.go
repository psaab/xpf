package config

import (
	"fmt"
	"sort"
)

// MaxBGPAllowASIn is the largest BGP AS-path loop count accepted by Junos
// `loops` and FRR `allowas-in`.
const MaxBGPAllowASIn = 10

// validateBGPAllowASInStrict checks effective group-inherited and
// per-neighbor loops values after compilation. Zero is the unset value;
// authored zero and unparseable values are preserved as invalid nonzero values
// by the BGP compiler so direct CompileConfig callers receive the same gate as
// commit callers receive from schema validation.
func validateBGPAllowASInStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
		sort.SliceStable(neighbors, func(i, j int) bool {
			if neighbors[i] == nil {
				return neighbors[j] != nil
			}
			if neighbors[j] == nil {
				return false
			}
			return neighbors[i].Address < neighbors[j].Address
		})
		for _, n := range neighbors {
			if n == nil || n.AllowASIn == 0 {
				continue
			}
			if n.AllowASIn >= 1 && n.AllowASIn <= MaxBGPAllowASIn {
				continue
			}

			detail := fmt.Sprintf("%sprotocols bgp neighbor %s", scope, n.Address)
			if n.GroupName != "" {
				detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s", scope, n.GroupName, n.Address)
			}
			return fmt.Errorf("%s: loops %d is outside the allowed BGP range 1..%d; set loops to a value in that range",
				detail, n.AllowASIn, MaxBGPAllowASIn)
		}
		return nil
	}

	if err := checkBGP("", cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkBGP(scope, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}
