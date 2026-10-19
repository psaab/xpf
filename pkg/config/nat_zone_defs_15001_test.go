package config

import (
	"regexp"
	"sort"
	"strings"
)

// #15001 test support: many pre-existing NAT fixtures reference zones
// (from zone trust etc.) without defining them, relying on the old
// warn-only treatment. Now that strict commit rejects an undefined NAT
// zone, those fixtures must define the zones they reference. These
// helpers derive the referenced names from the fixture itself and
// prepend the definitions, so no fixture's zone names are invented.

var natZoneRef15001 = regexp.MustCompile(`(?:from|to) zone \[([^\]]*)\]|(?:from|to) zone ([A-Za-z0-9_\-\."]+)`)
var hierZoneRef15001 = regexp.MustCompile(`zone\s+([A-Za-z0-9_\-\.]+)\s*;`)

func natReferencedZones15001(cmds []string) []string {
	seen := map[string]bool{}
	defined := map[string]bool{}
	for _, c := range cmds {
		if strings.Contains(c, "security-zone") {
			if f := strings.Fields(c); len(f) > 0 {
				defined[f[len(f)-1]] = true
			}
			continue
		}
		for _, m := range natZoneRef15001.FindAllStringSubmatch(c, -1) {
			if m[1] != "" {
				for _, z := range strings.Fields(m[1]) {
					seen[strings.Trim(z, `"`)] = true
				}
			} else if m[2] != "" {
				seen[strings.Trim(m[2], `"`)] = true
			}
		}
	}
	for z := range defined {
		delete(seen, z)
	}
	var out []string
	for z := range seen {
		if z != "" {
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out
}

// prependNATZoneDefs15001 returns cmds with `set security zones
// security-zone <z>` definitions prepended for every zone the cmds
// reference from/to a NAT rule-set.
func prependNATZoneDefs15001(cmds []string) []string {
	zones := natReferencedZones15001(cmds)
	if len(zones) == 0 {
		return cmds
	}
	out := make([]string, 0, len(zones)+len(cmds))
	for _, z := range zones {
		out = append(out, "set security zones security-zone "+z)
	}
	return append(out, cmds...)
}

// injectHierNATZones15001 inserts a `zones { security-zone <z>; ... }`
// block into a hierarchical `security { ... }` fixture for every zone
// its NAT rule-sets reference, unless the fixture already defines zones.
func injectHierNATZones15001(src string) string {
	if strings.Contains(src, "security-zone") {
		return src
	}
	var zones []string
	seen := map[string]bool{}
	add := func(z string) {
		if z != "" && !seen[z] {
			seen[z] = true
			zones = append(zones, z)
		}
	}
	for _, m := range hierZoneRef15001.FindAllStringSubmatch(src, -1) {
		add(m[1])
	}
	for _, m := range natZoneRef15001.FindAllStringSubmatch(src, -1) {
		if m[1] != "" {
			for _, z := range strings.Fields(m[1]) {
				add(strings.Trim(z, `"`))
			}
		} else {
			add(strings.Trim(m[2], `"`))
		}
	}
	if len(zones) == 0 {
		return src
	}
	sort.Strings(zones)
	var b strings.Builder
	b.WriteString("zones {\n")
	for _, z := range zones {
		b.WriteString("security-zone " + z + ";\n")
	}
	b.WriteString("}\n")
	idx := strings.Index(src, "security {")
	if idx < 0 {
		return src
	}
	insertAt := idx + len("security {")
	return src[:insertAt] + "\n" + b.String() + src[insertAt:]
}
