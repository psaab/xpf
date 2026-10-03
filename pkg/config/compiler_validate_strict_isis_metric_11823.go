package config

import "fmt"

// validateISISMetrics11823 rejects compiled IS-IS interface metrics outside
// FRR's default wide-style 0..MaxISISMetric domain. Schema validation handles
// operator commits; this gate also protects direct compiler callers and
// downgrades to a warning on tolerant load / peer-sync paths.
func validateISISMetrics11823(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, isis *ISISConfig) error {
		if isis == nil {
			return nil
		}
		for _, iface := range isis.Interfaces {
			if iface == nil || (iface.Metric >= 0 && iface.Metric <= MaxISISMetric) {
				continue
			}
			return fmt.Errorf("%sprotocols isis interface %s metric %d is outside 0..%d",
				scope, iface.Name, iface.Metric, MaxISISMetric)
		}
		return nil
	}
	if err := check("", cfg.Protocols.ISIS); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %q ", ri.Name), ri.ISIS); err != nil {
			return err
		}
	}
	return nil
}
