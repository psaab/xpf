package config

import (
	"fmt"
	"strings"
)

// validate_interface_name.go — the commit-time gate on the `interfaces`
// wildcard identity token (#6834).
//
// WHY AT COMMIT RATHER THAN AT RENDER. The interface name is interpolated into
// the generated systemd units at four sites in pkg/networkd — `[NetDev] Name=`
// (x2), `[Link] Name=` and, the one that matters, `[Match] Name=` in the
// .network file. Validating the identity once here closes all four at the
// source, and gives the operator a diagnosable commit error instead of a
// rename that silently fails at the next boot.
//
// WHY ESCAPING AT RENDER WOULD BE WORSE THAN DOING NOTHING. The obvious
// treatment is to reuse the neighbouring sanitizeUnitValue, which is applied to
// `Description=` on adjacent lines. Do not. It maps every control byte to a
// SPACE, and systemd documents `[Match] Name=` (and `[Match] OriginalName=`) as
// "a whitespace-separated list of shell-style globs matching the device name,
// or device's alternative names". A sanitizer whose replacement character is
// the sink's SEPARATOR does not neutralise the value — it MANUFACTURES a second
// pattern out of one, and each pattern claims devices. Applying that helper to
// these fields is strictly worse than rendering them raw. This comment exists
// so a later simplification into a call to it is recognisably wrong.
//
// WHAT IS AND IS NOT REACHABLE. Measured on the real config path:
//
//	"ge 0"           ACCEPTED before this gate -> Name="ge 0"
//	"ge-0-0-0 eth0"  ACCEPTED before this gate -> a TWO-pattern payload
//	"ge*"            ACCEPTED before this gate -> a glob
//	"ge\t0"          already REJECTED at compile ("contains control characters")
//
// So the newline/directive-injection vector is ALREADY closed by the existing
// control-character guard and needs nothing here; and `OriginalName=` is not
// operator-reachable at all (it is daemon-derived from the kernel). The live
// vector is whitespace and glob metacharacters in the operator-authored name.
//
// NO LENGTH BOUND, DELIBERATELY. The kernel's IFNAMSIZ limit applies to the
// FINAL kernel name, which is derived from this token (`/` becomes `-`) and,
// for a unit, extended with `.<unit>`. Deriving a correct bound here would mean
// modelling that derivation, and a bound that is wrong in the REJECTING
// direction turns a working config into a failed commit with no operator
// workaround — the #6564 ValidateOSPFArea lesson, where a `>= 1` floor copied
// from a sibling would have refused OSPF area 0, the backbone. The repo already
// carries a 17-character fixture (`ge-0/0/1234567890`), so the population here
// is not obviously bounded either. Character class only.

// interfaceNameAllowed reports whether c may appear in an interface name.
//
// The set is the intersection of what the kernel accepts and what renders
// unambiguously into a systemd match list: alphanumerics plus '-', '.', '_'
// and '/'. The slash is included because the Junos spelling `ge-0/0/0` is the
// normal way to write these and is canonicalised to `ge-0-0-0` downstream
// (types.go); rejecting it here would refuse the documented syntax.
func interfaceNameAllowed(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '/':
		return true
	}
	return false
}

// ValidateInterfaceName gates the `interfaces <name>` identity token.
//
// It is an ALLOWLIST rather than a denylist of the two known-dangerous classes.
// A denylist would have to enumerate every character that is a separator or a
// metacharacter to some consumer of the name, and the consumers are not all in
// this repo; the legal shape of an interface name is narrow and known, so
// stating it positively is both shorter and closed against a consumer nobody
// has thought of yet.
func ValidateInterfaceName(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("interface name must not be empty")
	}
	// A THIRD actively-dangerous class, and the only one about POSITION rather
	// than about which characters appear (#9885). `-` is legitimate everywhere
	// else in a name — `ge-0-0-0` is the normal spelling — so the allowlist
	// loop below cannot see this, and no amount of tightening it would.
	//
	// The name reaches an argv slot (`networkctl reconfigure <names...>`,
	// pkg/networkd), where a leading `-` is read as an OPTION. The sharp case
	// is not a name that errors: `--help` and `--version` EXIT 0 WITHOUT
	// ACTING, so one such interface silently leaves every interface in that
	// batch unconfigured while the caller reads success and clears its retry
	// debt. `-x` would at least fail loudly.
	if strings.HasPrefix(raw, "-") {
		return fmt.Errorf(
			"interface name %q begins with '-'; the name is passed as an argv element to "+
				"`networkctl reconfigure`, where a leading dash is read as an OPTION rather "+
				"than as a link — and an option like `--help` EXITS 0 WITHOUT ACTING, so this "+
				"one name would leave every interface in the batch unconfigured while the "+
				"apply reported success. '-' is allowed everywhere else in the name", raw)
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if interfaceNameAllowed(c) {
			continue
		}
		// The two classes that are not merely invalid but ACTIVELY dangerous
		// get their own message, because "invalid character" would not tell an
		// operator that the name they wrote would have claimed other devices.
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			return fmt.Errorf(
				"interface name %q contains whitespace at byte %d; the name is rendered into "+
					"the generated .network file's [Match] Name=, which systemd reads as a "+
					"WHITESPACE-SEPARATED list of globs — a name with a space matches, and "+
					"claims, more than one interface", raw, i)
		case c == '*' || c == '?' || c == '[' || c == ']':
			return fmt.Errorf(
				"interface name %q contains the glob metacharacter %q at byte %d; the name is "+
					"rendered into the generated .network file's [Match] Name=, which systemd "+
					"reads as a list of SHELL-STYLE GLOBS — the name would match, and claim, "+
					"every interface it globs (including by alternative name)", raw, string(c), i)
		}
		return fmt.Errorf(
			"interface name %q contains %q at byte %d; allowed characters are letters, digits, "+
				"'-', '.', '_' and '/'", raw, string(c), i)
	}
	return nil
}

// interfaceNameRendersAsOnePattern reports whether name occupies exactly one
// slot of a systemd whitespace-separated match list. It exists so the property
// the validator protects can be asserted directly against systemd's documented
// grammar, rather than only through the validator's own allowlist — a test that
// checked the allowlist against itself would be true by construction.
func interfaceNameRendersAsOnePattern(name string) bool {
	return len(strings.Fields(name)) == 1 && strings.Fields(name)[0] == name
}

// interfaceNameIsNotAnOptionWord reports whether name occupies an argv slot as
// an OPERAND rather than as an option, per the POSIX utility syntax guideline
// that an argument beginning with '-' is an option.
//
// It exists for the same reason as the helper above: so the property the
// validator protects can be asserted against the convention DIRECTLY, rather
// than only through the validator's own prefix test — a cell that checked the
// prefix test against itself would be true by construction.
func interfaceNameIsNotAnOptionWord(name string) bool {
	return name != "" && !strings.HasPrefix(name, "-")
}
