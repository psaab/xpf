package config

import "fmt"

// ValidateRIPNeighborInterface gates each value of `protocols rip group <g>
// neighbor` (#9206).
//
// WHY THIS LEAF SPECIFICALLY. `neighbor` is `multi: true` under a
// `closedWorld: true` container, and absorption (#2419) turns trailing tokens
// into VALUES before any keyword check runs. So an undeclared statement
// standing behind it is INJECTED rather than refused:
//
//	set protocols rip group g1 authentication-key secret1                    REJECT
//	set protocols rip group g1 neighbor ge-0/0/0 authentication-key secret1  ACCEPT
//	  -> ifaces = [ge-0/0/0 authentication-key secret1]
//
// and two non-existent interfaces are named to FRR.
//
// MEASURED POPULATION (#9206): 19 sites have that structural shape and exactly
// ONE reaches the compiled config -- this one. The discriminator is not the
// container but whether the absorbing leaf's VALUE TYPE has a downstream
// validator: `export` requires a known policy, the NAT match leaves require
// parseable addresses, and each rejects the absorbed token by name. Interface
// names were free-form, so nothing did.
//
// THE SHAPE RULE, and it is a property of the naming scheme rather than a
// convenient filter. In an interface name a hyphen is the MEDIA-TYPE separator
// and is always followed by the FPC digit -- `ge-0/0/0`, `xe-1/0/0`,
// `gr-0/0/0`, `ip-0/0/0.0`. Censused across every interface-name value in the
// repo: ZERO real names have a hyphen followed by anything else. Junos keywords
// hyphenate the other way round (`authentication-key`, `route-timeout`,
// `update-interval`), so the rule separates them.
//
// WHAT IT DOES NOT CATCH, stated because a partial fix that looks total is
// worse than none. A BARE single-word keyword -- `export`, `metric`, `passive`
// -- is shape-indistinguishable from a bare interface name, because `irb` is a
// real one this repo configures (`set interfaces irb`). No shape can reject the
// first without rejecting the second. Those still absorb, and
// TestRIPNeighborBareKeywordStillAbsorbs9206 pins that they do, so this fix
// cannot be mistaken for a complete one.
func ValidateRIPNeighborInterface(raw string) error {
	// The character allowlist first: it is the SECURITY half (the name is
	// rendered into a systemd [Match] Name=, where whitespace and globs claim
	// other devices) and this slot had none at all.
	if err := ValidateInterfaceName(raw); err != nil {
		return err
	}
	for i := 0; i < len(raw)-1; i++ {
		if raw[i] != '-' {
			continue
		}
		if c := raw[i+1]; c < '0' || c > '9' {
			return fmt.Errorf(
				"rip neighbor %q is not an interface name: a hyphen in an interface name is "+
					"the media-type separator and is followed by the FPC number (`ge-0/0/0`, "+
					"`xe-1/0/0`), but %q follows the hyphen at byte %d. This usually means a "+
					"trailing statement was ABSORBED as a neighbour: `neighbor ge-0/0/0 "+
					"authentication-key secret1` puts every token after the interface into the "+
					"neighbour list (#9206), so the keyword and its value become non-existent "+
					"interfaces named to FRR. Put the statement on its own `set` line",
				raw, string(c), i+1)
		}
	}
	if raw[len(raw)-1] == '-' {
		return fmt.Errorf("rip neighbor %q ends with a hyphen, which no interface name does", raw)
	}
	return nil
}
