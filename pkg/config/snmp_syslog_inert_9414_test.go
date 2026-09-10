package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// spelling9414 is one way an operator can write a stanza. Braced text goes
// through NewParser (which also covers the brace-elided form); flat lines go
// through ParseSetCommand + SetPath, the only faithful flat-set builder.
type spelling9414 struct {
	label  string
	braced string
	flat   []string
}

func (s spelling9414) tree(t *testing.T) *ConfigTree {
	t.Helper()
	if s.braced != "" {
		tree, errs := NewParser(s.braced).Parse()
		if len(errs) > 0 {
			t.Fatalf("%s: parse %q: %v", s.label, s.braced, errs[0])
		}
		return tree
	}
	return buildTree4303(t, s.flat)
}

// warnings9414 compiles one spelling on the strict AND the tolerant path and
// returns the #9414 advisories of each. Every row in this file is an
// operator-valid config that committed clean before #9414, so a REJECT on any
// channel fails the cell: the remedy is an advisory, never a refusal (#1960).
func warnings9414(t *testing.T, s spelling9414) (strict, lenient []string, c *Config) {
	t.Helper()
	tree := s.tree(t)
	sc, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("%s: strict CompileConfig REJECTED an operator-valid config: %v", s.label, err)
	}
	if err := SchemaValidate(tree, sc); err != nil {
		t.Fatalf("%s: SchemaValidate REJECTED an operator-valid config: %v", s.label, err)
	}
	lc, err := CompileConfigLenient(s.tree(t))
	if err != nil {
		t.Fatalf("%s: CompileConfigLenient REJECTED an operator-valid config: %v", s.label, err)
	}
	return only9414(sc.Warnings), only9414(lc.Warnings), sc
}

func only9414(ws []string) []string {
	var out []string
	for _, w := range ws {
		if strings.Contains(w, "(#9414)") {
			out = append(out, w)
		}
	}
	return out
}

func hasPrefix9414(ws []string, prefix string) bool {
	for _, w := range ws {
		if strings.HasPrefix(w, prefix) {
			return true
		}
	}
	return false
}

// assertOnlyAdvisory9414 requires an advisory starting with prefix, NO #9414
// advisory about anything else (a keyword read from the wrong AST position shows
// up as an extra advisory), and no configured value echoed into any of them.
func assertOnlyAdvisory9414(t *testing.T, channel string, ws []string, prefix string, values []string) {
	t.Helper()
	found := false
	for _, w := range ws {
		if strings.HasPrefix(w, prefix) {
			found = true
		} else {
			t.Errorf("#9414: %s raised an advisory for a statement this config does not contain "+
				"(a keyword read from the wrong AST position): %q", channel, w)
		}
		for _, v := range values {
			if strings.Contains(w, v) {
				t.Errorf("#9414: %s echoed the configured VALUE %q into an advisory (keywords only, "+
					"never values): %q", channel, v, w)
			}
		}
	}
	if !found {
		t.Errorf("#9414: %s raised no advisory starting %q. The statement commits clean and compiles "+
			"to nothing, so silence is the defect. #9414 advisories: %q", channel, prefix, ws)
	}
}

// TestSNMPInertStatementsAreLoudInEverySpelling9414: each SNMP statement xpf
// accepts and does not compile raises its advisory in every spelling, on the
// strict and the tolerant path, while still being ACCEPTED everywhere.
func TestSNMPInertStatementsAreLoudInEverySpelling9414(t *testing.T) {
	const pw = "xpfpass9414SECRET"
	user := " { authentication-sha { authentication-password " + pw + "; } }"
	rows := []struct {
		name, prefix string
		values       []string
		spellings    []spelling9414
	}{
		{"v3 vacm", "snmp v3 vacm:", []string{"secname9414"}, []spelling9414{
			{label: "braced", braced: "snmp { v3 { vacm { security-to-group { security-model usm { security-name secname9414 { group g1; } } } } } }"},
			{label: "brace-elided", braced: "snmp { v3 vacm { security-to-group { security-model usm { security-name secname9414 { group g1; } } } } }"},
			{label: "flat-set", flat: []string{"set snmp v3 vacm security-to-group security-model usm security-name secname9414 group g1"}},
		}},
		{"v3 notify", "snmp v3 notify:", []string{"notif9414"}, []spelling9414{
			{label: "braced", braced: "snmp { v3 { notify notif9414 { type trap; target-address t1; } } }"},
			{label: "brace-elided", braced: "snmp { v3 notify notif9414 { type trap; } }"},
			{label: "flat-set", flat: []string{"set snmp v3 notify notif9414 type trap", "set snmp v3 notify notif9414 target-address t1"}},
		}},
		{"v3 target-address", "snmp v3 target-address:", []string{"10.9.9.14"}, []spelling9414{
			{label: "braced", braced: "snmp { v3 { target-address t1 { address 10.9.9.14; target-parameters p1; } } }"},
			{label: "brace-elided", braced: "snmp { v3 target-address t1 { address 10.9.9.14; } }"},
			{label: "flat-set", flat: []string{"set snmp v3 target-address t1 address 10.9.9.14"}},
		}},
		{"v3 target-parameters", "snmp v3 target-parameters:", nil, []spelling9414{
			{label: "braced", braced: "snmp { v3 { target-parameters p1 { parameters { message-processing-model v3; } } } }"},
			{label: "flat-set", flat: []string{"set snmp v3 target-parameters p1 parameters message-processing-model v3"}},
		}},
		{"v3 notify-filter (complement, not a list)", "snmp v3 notify-filter:", nil, []spelling9414{
			{label: "braced", braced: "snmp { v3 { notify-filter f1 { oid 1.3 include; } } }"},
			{label: "flat-set", flat: []string{"set snmp v3 notify-filter f1 oid 1.3 include"}},
		}},
		{"v3 snmp-community (complement, not a list)", "snmp v3 snmp-community:", []string{"secname9414"}, []spelling9414{
			{label: "braced", braced: "snmp { v3 { snmp-community idx1 { security-name secname9414; } } }"},
			{label: "flat-set", flat: []string{"set snmp v3 snmp-community idx1 security-name secname9414"}},
		}},
		{"v3 usm remote-engine", "snmp v3 usm remote-engine:", []string{"800007e5809414", pw, "ruser9414"}, []spelling9414{
			{label: "braced", braced: "snmp { v3 { usm { remote-engine 800007e5809414 { user ruser9414" + user + " } } } }"},
			{label: "brace-elided", braced: "snmp { v3 usm remote-engine 800007e5809414 { user ruser9414" + user + " } }"},
			{label: "flat-set", flat: []string{"set snmp v3 usm remote-engine 800007e5809414 user ruser9414 authentication-sha authentication-password " + pw}},
		}},
		{"v3 usm remote-engine BESIDE a working local-engine user", "snmp v3 usm remote-engine:", []string{"800007e5809414", pw}, []spelling9414{
			{label: "braced", braced: "snmp { v3 { usm { remote-engine 800007e5809414 { user ruser9414" + user + " } local-engine { user u1" + user + " } } } }"},
			{label: "flat-set", flat: []string{
				"set snmp v3 usm remote-engine 800007e5809414 user ruser9414 authentication-sha authentication-password " + pw,
				"set snmp v3 usm local-engine user u1 authentication-sha authentication-password " + pw,
			}},
		}},
		{"engine-id local", "snmp engine-id:", []string{"8000abcd9414"}, []spelling9414{
			{label: "braced", braced: "snmp { engine-id { local 8000abcd9414; } }"},
			{label: "brace-elided", braced: "snmp { engine-id local 8000abcd9414; }"},
			{label: "flat-set", flat: []string{"set snmp engine-id local 8000abcd9414"}},
		}},
		{"engine-id use-mac-address", "snmp engine-id:", nil, []spelling9414{
			{label: "braced", braced: "snmp { engine-id { use-mac-address; } }"},
			{label: "flat-set", flat: []string{"set snmp engine-id use-mac-address"}},
		}},
		{"name", "snmp name:", []string{"sysname9414"}, []spelling9414{
			{label: "braced", braced: "snmp { name sysname9414; }"},
			{label: "flat-set", flat: []string{"set snmp name sysname9414"}},
		}},
		{"arp", "snmp arp:", nil, []spelling9414{
			{label: "braced", braced: "snmp { arp; }"},
			{label: "flat-set", flat: []string{"set snmp arp host-name-resolution"}},
		}},
		{"filter-duplicates", "snmp filter-duplicates:", nil, []spelling9414{
			{label: "braced", braced: "snmp { filter-duplicates; }"},
			{label: "flat-set", flat: []string{"set snmp filter-duplicates"}},
		}},
		{"nonvolatile", "snmp nonvolatile:", nil, []spelling9414{
			{label: "braced", braced: "snmp { nonvolatile { commit-delay 5; } }"},
			{label: "brace-elided", braced: "snmp { nonvolatile commit-delay 5; }"},
			{label: "flat-set", flat: []string{"set snmp nonvolatile commit-delay 5"}},
		}},
		{"proxy", "snmp proxy:", []string{"proxy9414"}, []spelling9414{
			{label: "braced", braced: "snmp { proxy proxy9414 { device-name d1; } }"},
			{label: "flat-set", flat: []string{"set snmp proxy proxy9414 device-name d1"}},
		}},
	}
	for _, r := range rows {
		for _, sp := range r.spellings {
			r, sp := r, sp
			t.Run(r.name+"/"+sp.label, func(t *testing.T) {
				strict, lenient, _ := warnings9414(t, sp)
				assertOnlyAdvisory9414(t, "strict CompileConfig", strict, r.prefix, r.values)
				assertOnlyAdvisory9414(t, "CompileConfigLenient", lenient, r.prefix, r.values)
			})
		}
	}
}

// TestSNMPSyslogAdvisoryIsSilentOnWhatCompiles9414 holds the LOAD-BEARING rows:
// configs xpf DOES compile must commit with no #9414 advisory, and each row's
// positive control proves the config really compiled into something. "Every
// SNMP/syslog stanza warns" satisfies every loud cell above; these rows are
// what refuse it. The NAMED rows put an inert keyword in a VALUE position, which
// a keyword search over all tokens would report.
func TestSNMPSyslogAdvisoryIsSilentOnWhatCompiles9414(t *testing.T) {
	const pw = "xpfpass9414SECRET"
	user := " { authentication-sha { authentication-password " + pw + "; } }"
	rows := []struct {
		name      string
		spellings []spelling9414
		compiled  func(c *Config) error
	}{
		{"v3 usm local-engine user (the implemented path)", []spelling9414{
			{label: "braced", braced: "snmp { v3 { usm { local-engine { user u1" + user + " } } } }"},
			{label: "flat-set", flat: []string{"set snmp v3 usm local-engine user u1 authentication-sha authentication-password " + pw}},
		}, func(c *Config) error {
			if c.System.SNMP == nil || c.System.SNMP.V3Users["u1"] == nil {
				return fmt.Errorf("v3 user u1 did not compile")
			}
			return nil
		}},
		{"v3 users NAMED vacm / remote-engine / notify", []spelling9414{
			{label: "braced", braced: "snmp { v3 { usm { local-engine { user vacm" + user + " user remote-engine" + user + " user notify" + user + " } } } }"},
			{label: "flat-set", flat: []string{
				"set snmp v3 usm local-engine user vacm authentication-sha authentication-password " + pw,
				"set snmp v3 usm local-engine user remote-engine authentication-sha authentication-password " + pw,
				"set snmp v3 usm local-engine user notify authentication-sha authentication-password " + pw,
			}},
		}, func(c *Config) error {
			for _, u := range []string{"vacm", "remote-engine", "notify"} {
				if c.System.SNMP == nil || c.System.SNMP.V3Users[u] == nil {
					return fmt.Errorf("v3 user %q did not compile", u)
				}
			}
			return nil
		}},
		{"top-level statements NAMED engine-id / name", []spelling9414{
			{label: "braced", braced: `snmp { location "dc1"; contact "noc"; description "fw"; community name { authorization read-only; } trap-group engine-id { targets 10.0.0.9; } }`},
			{label: "flat-set", flat: []string{
				"set snmp location dc1", "set snmp contact noc", "set snmp description fw",
				"set snmp community name authorization read-only",
				"set snmp trap-group engine-id targets 10.0.0.9",
			}},
		}, func(c *Config) error {
			s := c.System.SNMP
			if s == nil || s.Location != "dc1" || s.Contact != "noc" || s.Description != "fw" ||
				len(s.Communities) != 1 || s.TrapGroups["engine-id"] == nil {
				return fmt.Errorf("the snmp stanza did not compile: %+v", s)
			}
			return nil
		}},
		{"syslog host modifiers xpf DOES apply", []spelling9414{
			{label: "braced", braced: "system { syslog { host 10.0.0.9 { any any; source-address 10.0.0.1; port 5514; allow-duplicates; } } }"},
			{label: "flat-set", flat: []string{
				"set system syslog host 10.0.0.9 any any",
				"set system syslog host 10.0.0.9 source-address 10.0.0.1",
				"set system syslog host 10.0.0.9 port 5514",
				"set system syslog host 10.0.0.9 allow-duplicates",
			}},
		}, func(c *Config) error {
			sl := c.System.Syslog
			if sl == nil || len(sl.Hosts) != 1 || sl.Hosts[0].SourceAddress != "10.0.0.1" ||
				sl.Hosts[0].Port != 5514 || !sl.Hosts[0].AllowDuplicates {
				return fmt.Errorf("the host modifiers did not compile: %+v", sl)
			}
			return nil
		}},
		{"syslog file and user with selectors only", []spelling9414{
			{label: "braced", braced: "system { syslog { file messages { any any; } user * { any emergency; } } }"},
			{label: "flat-set", flat: []string{"set system syslog file messages any any", "set system syslog user * any emergency"}},
		}, func(c *Config) error {
			sl := c.System.Syslog
			if sl == nil || len(sl.Files) != 1 || len(sl.Files[0].Selectors) != 1 || len(sl.Users) != 1 {
				return fmt.Errorf("the file/user destinations did not compile: %+v", sl)
			}
			return nil
		}},
	}
	for _, r := range rows {
		for _, sp := range r.spellings {
			r, sp := r, sp
			t.Run(r.name+"/"+sp.label, func(t *testing.T) {
				strict, lenient, c := warnings9414(t, sp)
				if err := r.compiled(c); err != nil {
					t.Fatalf("POSITIVE CONTROL: %v — without it a silent advisory proves nothing", err)
				}
				if len(strict) > 0 || len(lenient) > 0 {
					t.Errorf("#9414: a config xpf compiles raised an advisory claiming it does not.\n"+
						"  strict:  %q\n  lenient: %q", strict, lenient)
				}
			})
		}
	}
}

// TestSyslogModifierPopulationIsAppliedOrAdvised9414 takes the POPULATION from
// the schema rather than from a list: every modifier setSchema declares for a
// host / file / user destination is either one the compiler applies (named
// here, and asserted to still exist) or raises its advisory in both spellings.
// A modifier added to the schema without a compiler arm reds this cell instead
// of committing silently.
func TestSyslogModifierPopulationIsAppliedOrAdvised9414(t *testing.T) {
	applied := map[string]map[string]bool{
		"host": {"source-address": true, "port": true, "allow-duplicates": true},
		"file": {"archive": true}, // recorded and warned by #7146
		"user": {},
	}
	// Distinctive destination names: the value-echo check is a substring test, and
	// an ordinary name like `messages` collides with the advisory's own prose.
	names := map[string]string{"host": "10.94.14.9", "file": "xpflog9414", "user": "*"}
	floor := map[string]int{"host": 8, "file": 5, "user": 5}
	for _, kind := range []string{"file", "host", "user"} {
		sn := schemaForPath("system", "syslog", kind)
		if sn == nil || len(sn.children) == 0 {
			t.Fatalf("POSITIVE CONTROL: setSchema declares no modifiers for system syslog %s", kind)
		}
		for kw := range applied[kind] {
			if sn.children[kw] == nil {
				t.Errorf("the applied set names %s %q, which setSchema no longer declares", kind, kw)
			}
		}
		var advised []string
		for kw := range sn.children {
			if !applied[kind][kw] {
				advised = append(advised, kw)
			}
		}
		sort.Strings(advised)
		if len(advised) < floor[kind] {
			t.Fatalf("POSITIVE CONTROL: only %d unapplied %s modifiers in the schema (%v), want >= %d",
				len(advised), kind, advised, floor[kind])
		}
		for _, kw := range advised {
			stmt := kw
			if sn.children[kw].args > 0 {
				stmt += " value9414"
			}
			prefix := fmt.Sprintf("system syslog %s %s:", kind, kw)
			for _, sp := range []spelling9414{
				{label: "braced", braced: fmt.Sprintf("system { syslog { %s %s { any any; %s; } } }", kind, names[kind], stmt)},
				{label: "flat-set", flat: []string{
					fmt.Sprintf("set system syslog %s %s any any", kind, names[kind]),
					fmt.Sprintf("set system syslog %s %s %s", kind, names[kind], stmt),
				}},
			} {
				kind, sp, prefix := kind, sp, prefix
				t.Run(kind+"/"+kw+"/"+sp.label, func(t *testing.T) {
					strict, lenient, _ := warnings9414(t, sp)
					values := []string{"value9414", names[kind]}
					if kind == "user" {
						values = []string{"value9414"}
					}
					assertOnlyAdvisory9414(t, "strict CompileConfig", strict, prefix, values)
					assertOnlyAdvisory9414(t, "CompileConfigLenient", lenient, prefix, values)
				})
			}
		}
	}
}

// TestSNMPTopLevelKeywordPopulationFromTheJunosCapture9414 takes the population of
// top-level `snmp` keywords from the in-tree Junos capture (`show configuration
// snmp ?`), not from a list assembled by noticing. Every keyword is either
// compiled (and its typed field asserted) or raises an advisory. The table must
// equal the capture in both directions.
func TestSNMPTopLevelKeywordPopulationFromTheJunosCapture9414(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "junos-config-display-reference.md"))
	if err != nil {
		t.Fatalf("read the in-tree Junos capture: %v", err)
	}
	const anchor = "**`show configuration snmp ?`:**"
	text := string(raw)
	i := strings.Index(text, anchor)
	if i < 0 {
		t.Fatalf("POSITIVE CONTROL: the Junos capture no longer contains %q", anchor)
	}
	rest := text[i+len(anchor):]
	fence := strings.Index(rest, "```")
	if fence < 0 {
		t.Fatal("POSITIVE CONTROL: no fenced block after the snmp capture heading")
	}
	rest = rest[fence+3:]
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatal("POSITIVE CONTROL: the snmp capture block is not terminated")
	}
	var capture []string
	for _, line := range strings.Split(rest[:end], "\n") {
		if f := strings.Fields(strings.TrimLeft(line, ">+ ")); len(f) > 0 {
			capture = append(capture, f[0])
		}
	}
	if len(capture) != 20 {
		t.Fatalf("POSITIVE CONTROL: parsed %d keywords from the capture, want 20: %q", len(capture), capture)
	}

	type disposition struct {
		stanza   string                   // placed inside `snmp { ... }`
		advisory string                   // the advisory it must raise; "" for a compiled keyword
		compiled func(s *SNMPConfig) bool // for a compiled keyword: the typed field it lands in
	}
	table := map[string]disposition{
		"arp":                     {stanza: "arp;", advisory: "snmp arp:"},
		"client-list":             {stanza: "client-list trusted { 10.0.0.0/8; }", compiled: func(s *SNMPConfig) bool { return len(s.ClientLists["trusted"]) == 1 }},
		"community":               {stanza: "community pub { authorization read-only; }", compiled: func(s *SNMPConfig) bool { return len(s.Communities) == 1 }},
		"contact":                 {stanza: `contact "noc";`, compiled: func(s *SNMPConfig) bool { return s.Contact == "noc" }},
		"description":             {stanza: `description "fw";`, compiled: func(s *SNMPConfig) bool { return s.Description == "fw" }},
		"engine-id":               {stanza: "engine-id { local 8000abcd; }", advisory: "snmp engine-id:"},
		"filter-duplicates":       {stanza: "filter-duplicates;", advisory: "snmp filter-duplicates:"},
		"filter-interfaces":       {stanza: "filter-interfaces { interfaces { ge-0/0/0; } }", advisory: "snmp interface / filter-interfaces:"},
		"health-monitor":          {stanza: "health-monitor;", advisory: "snmp health-monitor:"},
		"interface":               {stanza: "interface ge-0/0/0.0;", advisory: "snmp interface / filter-interfaces:"},
		"location":                {stanza: `location "dc1";`, compiled: func(s *SNMPConfig) bool { return s.Location == "dc1" }},
		"name":                    {stanza: "name fw1;", advisory: "snmp name:"},
		"nonvolatile":             {stanza: "nonvolatile { commit-delay 5; }", advisory: "snmp nonvolatile:"},
		"proxy":                   {stanza: "proxy p1 { device-name d1; }", advisory: "snmp proxy:"},
		"rmon":                    {stanza: "rmon;", advisory: "snmp rmon:"},
		"routing-instance-access": {stanza: "routing-instance-access;", advisory: "snmp routing-instance-access:"},
		"trap-group":              {stanza: "trap-group tg1 { targets 10.0.0.9; }", compiled: func(s *SNMPConfig) bool { return s.TrapGroups["tg1"] != nil }},
		"trap-options":            {stanza: "trap-options { source-address 10.0.0.1; }", advisory: "snmp trap-options source-address:"},
		"v3":                      {stanza: "v3 { usm { local-engine { user u1 { authentication-sha { authentication-password xpfpass123; } } } } }", compiled: func(s *SNMPConfig) bool { return s.V3Users["u1"] != nil }},
		"view":                    {stanza: "view v1 { oid 1.3.6.1.2.1 include; }", advisory: "snmp view:"},
	}
	seen := map[string]bool{}
	for _, kw := range capture {
		d, ok := table[kw]
		if !ok {
			t.Errorf("#9414: the Junos capture lists top-level `snmp %s`, which has no disposition here. "+
				"Decide whether xpf compiles it or advises that it does not; with neither it commits silently", kw)
			continue
		}
		seen[kw] = true
		kw, d := kw, d
		t.Run(kw, func(t *testing.T) {
			sp := spelling9414{label: "braced", braced: "snmp { " + d.stanza + " }"}
			c, err := CompileConfig(sp.tree(t))
			if err != nil {
				t.Fatalf("strict CompileConfig REJECTED `snmp { %s }`: %v", d.stanza, err)
			}
			if d.advisory != "" {
				if !hasPrefix9414(c.Warnings, d.advisory) {
					t.Errorf("#9414: `snmp %s` is accepted and not compiled, but raised no advisory starting %q; warnings: %q",
						kw, d.advisory, c.Warnings)
				}
				return
			}
			if c.System.SNMP == nil || !d.compiled(c.System.SNMP) {
				t.Errorf("POSITIVE CONTROL: `snmp { %s }` did not compile into SNMPConfig, so it cannot be classed as compiled", d.stanza)
			}
			if w := only9414(c.Warnings); len(w) > 0 {
				t.Errorf("#9414: `snmp %s` compiles, yet raised a #9414 advisory: %q", kw, w)
			}
		})
	}
	for kw := range table {
		if !seen[kw] {
			t.Errorf("the table carries %q, which the capture does not list; the table must BE the capture", kw)
		}
	}
}

// TestSNMPV3StatementsAreReadByPosition9414 drives snmpV3InertWarnings9414 on raw
// nodes in each shape, including the brace-elided shapes whether or not a
// normalizer reaches them first, so every position clause stays exercisable.
func TestSNMPV3StatementsAreReadByPosition9414(t *testing.T) {
	for _, tc := range []struct {
		name string
		v3   *Node
		want []string
	}{
		{"elided `v3 vacm { security-to-group ... }`: the children belong to vacm",
			&Node{Keys: []string{"v3", "vacm"}, Children: []*Node{{Keys: []string{"security-to-group"}}}},
			[]string{"snmp v3 vacm:"}},
		{"elided `v3 usm remote-engine <id> { user ... }`",
			&Node{Keys: []string{"v3", "usm", "remote-engine", "800007e5809414"}, Children: []*Node{{Keys: []string{"user", "ruser9414"}}}},
			[]string{"snmp v3 usm remote-engine:"}},
		{"elided `v3 usm { remote-engine ...; local-engine { ... } }`",
			&Node{Keys: []string{"v3", "usm"}, Children: []*Node{{Keys: []string{"remote-engine", "800007e5809414"}}, {Keys: []string{"local-engine"}}}},
			[]string{"snmp v3 usm remote-engine:"}},
		{"`usm remote-engine <id> { ... }` elided inside a braced v3",
			&Node{Keys: []string{"v3"}, Children: []*Node{{Keys: []string{"usm", "remote-engine", "800007e5809414"}}}},
			[]string{"snmp v3 usm remote-engine:"}},
		{"braced, only the implemented path, with a user NAMED vacm",
			&Node{Keys: []string{"v3"}, Children: []*Node{{Keys: []string{"usm"}, Children: []*Node{
				{Keys: []string{"local-engine"}, Children: []*Node{{Keys: []string{"user", "vacm"}}}}}}}},
			nil},
	} {
		got := snmpV3InertWarnings9414(tc.v3)
		var prefixes []string
		for _, w := range got {
			if i := strings.Index(w, ":"); i > 0 {
				prefixes = append(prefixes, w[:i+1])
			}
			if strings.Contains(w, "800007e5809414") || strings.Contains(w, "ruser9414") {
				t.Errorf("%s: an advisory echoed a configured value: %q", tc.name, w)
			}
		}
		if strings.Join(prefixes, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: advisories %q, want exactly %q", tc.name, prefixes, tc.want)
		}
	}
}

// TestSyslogFlatSetChainIsReadWhole9414: one flat-set line may carry several
// destination statements, and SetPath builds it as a NESTED chain. Before #9414
// every statement after the first was dropped unread, invisibly, because the
// skipped modifiers were inert either way; the advisory made that loss
// observable (the #8939 ratchet reported six NEWLY LOSING syslog rows). The
// destination arms now read the chain whole.
func TestSyslogFlatSetChainIsReadWhole9414(t *testing.T) {
	names := map[string]string{"host": "10.94.14.9", "file": "xpflog9414", "user": "*"}
	for _, kind := range []string{"file", "host", "user"} {
		kind := kind
		t.Run(kind+"/two advised modifiers on one line", func(t *testing.T) {
			sp := spelling9414{label: "flat-set chain", flat: []string{
				fmt.Sprintf("set system syslog %s %s any any", kind, names[kind]),
				fmt.Sprintf("set system syslog %s %s explicit-priority match-strings value9414", kind, names[kind]),
			}}
			strict, lenient, _ := warnings9414(t, sp)
			for _, ch := range []struct {
				name string
				ws   []string
			}{{"strict CompileConfig", strict}, {"CompileConfigLenient", lenient}} {
				for _, kw := range []string{"explicit-priority", "match-strings"} {
					prefix := fmt.Sprintf("system syslog %s %s:", kind, kw)
					if !hasPrefix9414(ch.ws, prefix) {
						t.Errorf("#9414: %s: the chained `%s` raised no advisory starting %q; the "+
							"destination arm dropped the rest of the flat-set line. #9414 advisories: %q",
							ch.name, kw, prefix, ch.ws)
					}
				}
			}
		})
	}
	// POSITIVE CONTROL on a statement xpf APPLIES: a `port` trailing a flag on
	// the same line must reach the host config, so the chain read is observable
	// in typed output and not only in advisories.
	// The inversion the #8939 ratchet caught on the first wiring: a chain read
	// must not lift a statement out of a BODY it belongs to (archive) and read it
	// as a destination facility pair.
	t.Run("file/archive body statements stay in the archive body", func(t *testing.T) {
		sp := spelling9414{label: "flat-set chain", flat: []string{
			"set system syslog file xpflog9414 any any",
			"set system syslog file xpflog9414 archive files 3 size 1m",
		}}
		_, _, c := warnings9414(t, sp)
		sl := c.System.Syslog
		if sl == nil || len(sl.Files) != 1 {
			t.Fatalf("the file destination did not compile: %+v", sl)
		}
		f := sl.Files[0]
		if strings.Join(f.ArchiveKnobs, " ") != "files size" || len(f.Selectors) != 1 {
			t.Errorf("#9414: the archive body was read wrong: ArchiveKnobs=%q Selectors=%+v. A chain "+
				"read must not lift an archive statement out of its body", f.ArchiveKnobs, f.Selectors)
		}
	})
	t.Run("host/an applied statement trailing a flag", func(t *testing.T) {
		sp := spelling9414{label: "flat-set chain", flat: []string{
			"set system syslog host 10.94.14.9 any any",
			"set system syslog host 10.94.14.9 allow-duplicates port 5514",
		}}
		_, _, c := warnings9414(t, sp)
		sl := c.System.Syslog
		if sl == nil || len(sl.Hosts) != 1 || !sl.Hosts[0].AllowDuplicates || sl.Hosts[0].Port != 5514 {
			t.Errorf("#9414: `allow-duplicates port 5514` on one line did not compile both statements: %+v", sl)
		}
	})
}
