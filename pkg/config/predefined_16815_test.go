package config

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The fixture transcribes all 159 application bodies and 23 set memberships
// from the issue-cited capture, changing whitespace only. Source and release
// are pinned in the fixture; this is not a current-release parity claim.
// Compare L3/L4 tuples and timeouts, not ALG behavior (a separate feature gap).
func TestPredefined16815_CaptureDiff(t *testing.T) {
	data, err := os.ReadFile("testdata/junos-defaults-12.1X44-D35.5.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Source       string
		Version      string
		Applications map[string]string
		Sets         map[string][]string
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Version != "12.1X44-D35.5" || capture.Source == "" || len(capture.Applications) != 159 || len(capture.Sets) != 23 {
		t.Fatal("capture provenance or census changed; re-diff the source")
	}

	// Refuse names whose match constraints cannot be represented. Do not
	// reduce a UUID/program-number application to a protocol-wide match.
	omitted := map[string]bool{"junos-persistent-nat": true}
	for name, body := range capture.Applications {
		if strings.Contains(body, " uuid ") || strings.Contains(body, " rpc-program-number ") {
			omitted[name] = true
		}
	}
	for name, members := range capture.Sets {
		for _, member := range members {
			if _, ok := capture.Applications[member]; !ok {
				t.Fatalf("capture set %s has non-application member %s", name, member)
			}
			if omitted[member] {
				omitted[name] = true
			}
		}
	}
	if len(omitted) != 57 {
		t.Fatalf("omitted census = %d, want 57 (see docs/feature-gaps.md)", len(omitted))
	}
	for name := range omitted {
		if _, ok := ResolveApplication(name, nil); ok {
			t.Errorf("unsupported capture name %s must not resolve as an application", name)
		}
		if _, ok := ResolveApplicationSet(name, nil); ok {
			t.Errorf("unsupported capture name %s must not resolve as a partial set", name)
		}
	}

	type tuple struct {
		Protocol, Source, Destination string
		Timeout                       uint32
	}
	termStart := regexp.MustCompile(`term t[0-9]+ `)
	leaf := func(body, key string) string {
		m := regexp.MustCompile(`(?:^|[ ;])` + key + ` ([^ ;]+)`).FindStringSubmatch(body)
		if m == nil {
			return ""
		}
		return m[1]
	}
	for name, body := range capture.Applications {
		if omitted[name] {
			continue
		}
		t.Run(name, func(t *testing.T) {
			var want []tuple
			for _, term := range termStart.Split(body, -1) {
				if strings.TrimSpace(term) == "" {
					continue
				}
				proto := leaf(term, "protocol")
				switch proto {
				case "6":
					proto = "tcp"
				case "1":
					proto = "icmp"
				case "58":
					proto = "icmpv6"
				case "47":
					proto = "gre"
				}
				var timeout uint64
				if raw := leaf(term, "inactivity-timeout"); raw != "" {
					timeout, err = strconv.ParseUint(raw, 10, 32)
					if err != nil {
						t.Fatal(err)
					}
				}
				want = append(want, tuple{proto, leaf(term, "source-port"), leaf(term, "destination-port"), uint32(timeout)})
			}
			members := []string{name}
			if len(want) > 1 {
				if _, ok := ResolveApplication(name, nil); ok {
					t.Fatal("multi-term application must be set-only; a bare app shadows it")
				}
				members, err = ExpandApplicationSet(name, &ApplicationsConfig{})
				if err != nil {
					t.Fatal(err)
				}
			}
			var got []tuple
			for _, member := range members {
				app, ok := ResolveApplication(member, nil)
				if !ok {
					t.Fatalf("capture application %s missing", member)
				}
				got = append(got, tuple{app.Protocol, app.SourcePort, app.DestinationPort, AppTimeoutWireSecs(app)})
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("capture tuples/timeouts = %+v, table = %+v", want, got)
			}
		})
	}
	for name, members := range capture.Sets {
		if omitted[name] {
			continue
		}
		set, ok := ResolveApplicationSet(name, nil)
		if !ok || !reflect.DeepEqual(set.Applications, members) {
			t.Errorf("capture set %s: got %+v, want %v", name, set, members)
		}
	}
}

// Acceptance uses the same strict compiler gate as commit, without injecting
// user applications that could mask a missing predefined name.
func TestPredefined16815_PoliciesCommit(t *testing.T) {
	for _, name := range []string{
		"junos-mail", "junos-echo", "junos-lpr", "junos-ymsg", "junos-chargen",
		"junos-discard", "junos-biff", "junos-who", "junos-uucp", "junos-nfs",
		"junos-sql-monitor", "junos-snmp-agentx", "junos-wxcontrol", "junos-snpp",
		"junos-dhcp-relay", "junos-nsm", "junos-r2cp", "junos-realaudio",
		"junos-internet-locator-service",
		// Existing controls and unsupported UUID/program-number references.
		"junos-http", "junos-sip", "junos-ms-rpc-epm", "junos-sun-rpc-nfs",
	} {
		t.Run(name, func(t *testing.T) {
			cmds := append(append([]string{}, zoneBoilerplate...),
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application "+name,
				"set security policies from-zone trust to-zone untrust policy p then permit",
			)
			_, err := CompileConfig(buildAppMatchTree(t, cmds...))
			if name == "junos-ms-rpc-epm" || name == "junos-sun-rpc-nfs" {
				if err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("omitted name must fail commit naming the token; got %v", err)
				}
			} else if err != nil {
				t.Fatalf("policy with %s must commit: %v", name, err)
			}
		})
	}
}
