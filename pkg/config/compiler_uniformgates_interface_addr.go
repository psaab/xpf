package config

import "fmt"

// runUniformGatesInterfaceAddr runs the interface sub-run of the P6b
// uniform fail-open gate phase (#9424, #9837). It is appended at the END of
// the phase rather than inserted among the pre-existing gates: the gate order
// is observable (first failing gate wins the strict error slot, invariant
// #6), so a new gate placed in the middle would change which error an
// operator sees for a config that trips two of them.
func runUniformGatesInterfaceAddr(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	// #9424 bracketed interface-address-list gate. Strict on commit /
	// commit-check (hard-reject a token inside `address [ ... ]` that is neither
	// a valid address for its family nor a declared `address` sub-statement —
	// the typed-leaf gate validates only the FIRST key slot of an `address`
	// leaf, so before this it was accepted and silently discarded). Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config still
	// boots — #1960 no-brick; the unit carries the addresses that did parse,
	// which is strictly more than the pre-#9424 first-address-only behaviour).
	if err := validateInterfaceAddressListStrict(cfg); err != nil {
		if opts.lenientInterfaceAddressList {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("interface address list (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9837 tagged-unit-MTU gate. Strict on commit / commit-check
	// (hard-reject a tagged unit whose family MTU exceeds the
	// interface-level `mtu` — Linux refuses a VLAN child MTU above its
	// parent's, so the committed value would never be realised). Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config
	// still boots — #1960 no-brick; the runtime warning already covers the
	// leniently-loaded case). Runs AFTER the address-list gate so a
	// malformed-address error still wins the first-error slot.
	if err := validateVlanUnitMTUStrict(cfg); err != nil {
		if opts.lenientVlanUnitMTU {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("tagged unit MTU (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	return nil
}
