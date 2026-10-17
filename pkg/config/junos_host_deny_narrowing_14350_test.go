package config

import (
	"strings"
	"testing"
)

// #14350: a to-zone junos-host DENY/REJECT whose application reference was
// NARROWED by a dropped clause on the tolerant load must be unrepresentable.
// The compiled application keeps only the surviving fragment (last duplicate
// value, surviving set members), so projecting it would deny only that
// fragment, leave the dropped ports/applications open, and — via
// RenderedPolicyKeys — suppress the #4168 warning that would have told the
// operator the policy is not fully enforced.
//
// Widening drops (a lost constraint that makes the compiled match BROADER,
// e.g. a malformed icmp-type leaving the term unconstrained) keep the
// #12040 fail-closed behaviour: the deny still projects, because a broader
// DROP denies at least everything authored.
//
// Fixtures use hierarchical syntax via NewParser (flat-set SetPath collapses
// duplicate sibling leaves before the compiler can record them).

func junosHost14350Parse(t *testing.T, body string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(body).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func junosHost14350Program(t *testing.T, proj JunosHostDenyProjection) *JunosHostDenyProgram {
	t.Helper()
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "untrust" {
			return &proj.Programs[i]
		}
	}
	t.Fatalf("no untrust program in projection: %+v", proj.Programs)
	return nil
}

const junosHost14350Zones = `interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone untrust {
            interfaces { ge-0/0/1.0; }
            host-inbound-traffic { system-services { ssh; } }
        }
        security-zone trust {
            interfaces { ge-0/0/0.0; }
        }
    }
}
`

func TestJunosHostDenyWithNarrowingApplicationMatchDropsIsUnrepresentable(t *testing.T) {
	cases := []struct {
		name       string
		apps       string
		ref        string
		action     string
		wantDropIn string // substring expected in ApplicationReferenceMatchDrops(ref)
	}{
		{
			name: "DuplicateDirectLeaves deny",
			apps: `application dup-port {
                protocol tcp;
                destination-port 22;
                destination-port 23;
            }`,
			ref:        "dup-port",
			action:     "deny",
			wantDropIn: "destination-port",
		},
		{
			name: "DuplicateDirectLeaves reject",
			apps: `application dup-port {
                protocol tcp;
                destination-port 22;
                destination-port 23;
            }`,
			ref:        "dup-port",
			action:     "reject",
			wantDropIn: "destination-port",
		},
		{
			name: "DuplicateTermLeaves deny",
			apps: `application dup-term {
                term t1 {
                    protocol tcp;
                    destination-port 22;
                    destination-port 23;
                }
            }`,
			ref:        "dup-term",
			action:     "deny",
			wantDropIn: "destination-port",
		},
		{
			name: "MixedDirectTermApps deny",
			apps: `application mixed-app {
                protocol tcp;
                destination-port 22;
                term t1 {
                    protocol tcp;
                    destination-port 8080;
                }
            }`,
			ref:        "mixed-app",
			action:     "deny",
			wantDropIn: "direct match body was discarded",
		},
		{
			name: "ApplicationSet UnknownMembers deny",
			apps: `application web-app {
                protocol tcp;
                destination-port 80;
            }
            application-set web-set {
                application web-app;
                applicaton junos-https;
            }`,
			ref:        "web-set",
			action:     "deny",
			wantDropIn: "junos-https",
		},
		{
			name: "duplicate direct leaves via set deny",
			apps: `application dup-port {
                protocol tcp;
                destination-port 22;
                destination-port 23;
            }
            application-set dup-set {
                application dup-port;
            }`,
			ref:        "dup-set",
			action:     "deny",
			wantDropIn: "destination-port",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := junosHost14350Zones + `
applications {
    ` + tc.apps + `
}
security {
    policies {
        from-zone untrust to-zone junos-host {
            policy block-narrowed {
                match {
                    source-address any;
                    destination-address any;
                    application ` + tc.ref + `;
                }
                then { ` + tc.action + `; }
            }
        }
    }
}
`
			tree := junosHost14350Parse(t, body)
			// Strict must reject every fixture (the drops are a tolerant-load
			// phenomenon); if strict accepts, the lenient assertions below do
			// not measure the issue's path.
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("fixture is not a tolerant-downgrade member: strict CompileConfig accepted it")
			}
			cfg, err := CompileConfigLenient(junosHost14350Parse(t, body))
			if err != nil {
				t.Fatalf("CompileConfigLenient must still accept the fixture (#1960 no-brick): %v", err)
			}
			drops := ApplicationReferenceMatchDrops(tc.ref, &cfg.Applications)
			if len(drops) == 0 {
				t.Fatalf("premise broken: %q must carry match drops; got none", tc.ref)
			}
			if !strings.Contains(strings.Join(drops, "\n"), tc.wantDropIn) {
				t.Fatalf("drops = %q, want substring %q", drops, tc.wantDropIn)
			}

			proj := BuildJunosHostDenyProjection(cfg)
			prog := junosHost14350Program(t, proj)
			if prog.Representable {
				t.Fatalf("narrowed %s via %q must make the whole untrust program unrepresentable; prog=%+v rulesV4=%+v rulesV6=%+v",
					tc.action, tc.ref, *prog, prog.RulesV4, prog.RulesV6)
			}
			key := JunosHostZonePairPolicyKey("untrust", "block-narrowed")
			if proj.RenderedPolicyKeys[key] {
				t.Fatalf("narrowed %s must NOT enter RenderedPolicyKeys (that suppresses #4168); keys=%v", tc.action, proj.RenderedPolicyKeys)
			}
		})
	}
}

// The mixed-app term-only deny/control: a well-formed deny over the same zone
// shape still projects, so the gate above is not over-suppressing.
func TestJunosHostDenyWellFormedStillProjects14350(t *testing.T) {
	body := junosHost14350Zones + `
applications {
    application ssh-app {
        protocol tcp;
        destination-port 22;
    }
}
security {
    policies {
        from-zone untrust to-zone junos-host {
            policy block-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application ssh-app;
                }
                then { deny; }
            }
        }
    }
}
`
	cfg, err := CompileConfigLenient(junosHost14350Parse(t, body))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if drops := ApplicationReferenceMatchDrops("ssh-app", &cfg.Applications); len(drops) != 0 {
		t.Fatalf("ssh-app must carry no drops; got %q", drops)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	prog := junosHost14350Program(t, proj)
	if !prog.Representable {
		t.Fatalf("well-formed deny must stay representable: %+v", *prog)
	}
	key := JunosHostZonePairPolicyKey("untrust", "block-ssh")
	if !proj.RenderedPolicyKeys[key] {
		t.Fatalf("well-formed deny must enter RenderedPolicyKeys; keys=%v", proj.RenderedPolicyKeys)
	}
	found := false
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostDrop && len(r.L4) == 1 && len(r.L4[0].Ports) == 1 && r.L4[0].Ports[0] == (PortRange{Lo: 22, Hi: 22}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("well-formed deny must project tcp/22 drop; RulesV4=%+v", prog.RulesV4)
	}
}

// A permit referencing a narrowed application must still be SKIPPED (not made
// unrepresentable): skipping keeps the sibling deny's program alive, the
// #12040 behaviour generalised to narrowing drops.
func TestJunosHostPermitWithNarrowingDropsSkipsNotPoisons14350(t *testing.T) {
	body := junosHost14350Zones + `
applications {
    application dup-port {
        protocol tcp;
        destination-port 22;
        destination-port 23;
    }
    application ssh-app {
        protocol tcp;
        destination-port 22;
    }
}
security {
    policies {
        from-zone untrust to-zone junos-host {
            policy allow-dup {
                match {
                    source-address any;
                    destination-address any;
                    application dup-port;
                }
                then { permit; }
            }
            policy block-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application ssh-app;
                }
                then { deny; }
            }
        }
    }
}
`
	cfg, err := CompileConfigLenient(junosHost14350Parse(t, body))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	prog := junosHost14350Program(t, proj)
	if !prog.Representable {
		t.Fatalf("narrowed permit must be skipped, not poison the program: %+v", *prog)
	}
	for _, r := range append(append([]JunosHostDenyRule{}, prog.RulesV4...), prog.RulesV6...) {
		if r.Verdict == JunosHostReturn {
			t.Fatalf("narrowed permit must carve nothing (no return); rule=%+v", r)
		}
	}
	key := JunosHostZonePairPolicyKey("untrust", "block-ssh")
	if !proj.RenderedPolicyKeys[key] {
		t.Fatalf("sibling deny must still be rendered; keys=%v", proj.RenderedPolicyKeys)
	}
}
