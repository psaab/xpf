package config

import (
	"strings"
	"testing"
)

// #14403 (DR11-H1): VRRP authentication-key / authentication-type one level up
// evades the #4288 reject. The #4288 gate (validateVRRPAuthenticationAST) only
// inspected a vrrp-group node's own Keys/direct children. An identical leaf on
// the address node that OWNS the group — or on family/unit/interface ancestors,
// or nested under the group but not a direct child — was never read by the
// compiler (parseVRRPGroups visits only vrrp-group children) and never seen by
// the gate, so the group compiled with AuthKey=="" and ACTIVATED claiming the
// VIP with unauthenticated adverts while `show configuration` displayed an
// authentication-key on the address.
//
// Each cell must either hard-reject at strict commit (naming the misplaced
// keyword) or warn-and-drop the group on the lenient path; the position control
// (auth-key as direct child of the group) keeps its strict-reject; a group with
// NO auth statement anywhere nearby must still compile and activate.

const vrrpMisplacedAuthVIP = "10.0.61.1/24"

func vrrpMisplacedHier(cell, leaf string) string {
	// leaf is "authentication-key SUPERSECRETVRRPKEY14403" or "authentication-type md5"
	auth := leaf + ";"
	switch cell {
	case "address":
		return `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    ` + auth + `
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + `;
                    }
                }
            }
        }
    }
}`
	case "family":
		return `interfaces {
    reth0 {
        unit 0 {
            family inet {
                ` + auth + `
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + `;
                    }
                }
            }
        }
    }
}`
	case "unit":
		return `interfaces {
    reth0 {
        unit 0 {
            ` + auth + `
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + `;
                    }
                }
            }
        }
    }
}`
	case "interface":
		return `interfaces {
    reth0 {
        ` + auth + `
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + `;
                    }
                }
            }
        }
    }
}`
	case "nested-virtual-address":
		return `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + ` {
                            ` + auth + `
                        }
                    }
                }
            }
        }
    }
}`
	case "nested-track-interface":
		// auth leaf nested under track-interface child of the group
		if strings.HasPrefix(leaf, "authentication-key") {
			return `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + `;
                        track-interface ge-0/0/1 {
                            ` + auth + `
                        }
                    }
                }
            }
        }
    }
}`
		}
		return `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address ` + vrrpMisplacedAuthVIP + `;
                        track-interface ge-0/0/1 {
                            ` + auth + `
                        }
                    }
                }
            }
        }
    }
}`
	}
	panic("unknown cell " + cell)
}

var vrrpMisplacedCells = []string{"address", "family", "unit", "interface", "nested-virtual-address", "nested-track-interface"}
var vrrpMisplacedLeaves = []struct{ name, text string }{
	{"authentication-key", "authentication-key SUPERSECRETVRRPKEY14403"},
	{"authentication-type", "authentication-type md5"},
}

func TestVRRPMisplacedAuthRejected14403(t *testing.T) {
	for _, cell := range vrrpMisplacedCells {
		for _, leaf := range vrrpMisplacedLeaves {
			t.Run(cell+"/"+leaf.name, func(t *testing.T) {
				tree := parseHier(t, vrrpMisplacedHier(cell, leaf.text))
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("CompileConfig: expected rejection of misplaced VRRP %s at %s, got nil (group would activate unauthenticated)", leaf.name, cell)
				}
				if !strings.Contains(err.Error(), leaf.name) {
					t.Fatalf("error must name misplaced keyword %q, got: %v", leaf.name, err)
				}
				if !strings.Contains(err.Error(), "#4288") {
					t.Fatalf("error must reference #4288, got: %v", err)
				}
				if strings.Contains(err.Error(), "SUPERSECRETVRRPKEY14403") {
					t.Fatalf("error LEAKED secret: %v", err)
				}
			})
		}
	}
}

func TestVRRPMisplacedAuthLenientDropsGroup14403(t *testing.T) {
	for _, cell := range vrrpMisplacedCells {
		for _, leaf := range vrrpMisplacedLeaves {
			t.Run(cell+"/"+leaf.name, func(t *testing.T) {
				tree := parseHier(t, vrrpMisplacedHier(cell, leaf.text))
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("CompileConfigLenient: %v", err)
				}
				found := false
				for _, w := range cfg.Warnings {
					if strings.Contains(w, leaf.name) && strings.Contains(w, "#4288") {
						found = true
					}
					if strings.Contains(w, "SUPERSECRETVRRPKEY14403") {
						t.Fatalf("warning LEAKED secret: %q", w)
					}
				}
				if !found {
					t.Fatalf("expected #4288 warning naming %s, got: %v", leaf.name, cfg.Warnings)
				}
				if vg := firstVRRPGroupWithVIP(t, cfg, vrrpMisplacedAuthVIP); vg != nil {
					t.Fatalf("lenient left misplaced-auth group ACTIVE at %s: %+v", cell, vg)
				}
				// base address survives where present (address node still there)
				ifc := cfg.Interfaces.Interfaces["reth0"]
				if ifc == nil || ifc.Units[0] == nil {
					t.Fatal("reth0 unit 0 must still compile")
				}
			})
		}
	}
}

func TestVRRPMisplacedAuthAncestorKeysPackedNoLeak14403(t *testing.T) {
	// Ancestor Keys-packed: `address 10.0.61.10/24 authentication-key <secret>;` hierarchical packed leaf
	for _, hier := range []string{
		`interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 authentication-key SUPERSECRETVRRPKEY14403 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                    }
                }
            }
        }
    }
}`,
		`interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
    ge-0/0/3 {
        unit 0 {
            family inet {
                address 10.0.3.1/24;
            }
        }
    }
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        track-interface ge-0/0/1 authentication-key SUPERSECRETVRRPKEY14403;
                    }
                }
            }
        }
    }
}`,
	} {
		_, err := CompileConfig(parseHier(t, hier))
		if err == nil {
			t.Fatal("expected rejection")
		}
		if strings.Contains(err.Error(), "SUPERSECRETVRRPKEY14403") {
			t.Fatalf("error LEAKED secret: %v", err)
		}
		if !strings.Contains(err.Error(), "authentication-key") {
			t.Fatalf("error must name keyword: %v", err)
		}
		cfg, err := CompileConfigLenient(parseHier(t, hier))
		if err != nil {
			t.Fatalf("lenient: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "SUPERSECRETVRRPKEY14403") {
				t.Fatalf("warning LEAKED secret: %q", w)
			}
		}
		if vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24"); vg != nil {
			t.Fatalf("lenient left group ACTIVE: %+v", vg)
		}
	}
}

func TestVRRPNoAuthNearbyStillCommits14403(t *testing.T) {
	// group with NO auth anywhere must still compile+activate
	tree := parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                    }
                }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("no-auth group must commit: %v", err)
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24"); vg == nil {
		t.Fatal("no-auth group must activate")
	}
	// Scope guard: auth leaf with NO vrrp-group anywhere in its subtree is not
	// reported by the new #14403 gate. For family/unit/interface placements
	// (which have no other gate), it must compile clean. (The address-node
	// placement is already hard-rejected by the pre-existing #9424 address-list
	// gate, so it is not used as the no-group control here.)
	tree2 := parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                authentication-key SUPERSECRETVRRPKEY14403;
                address 10.0.61.10/24 {
                }
            }
        }
    }
}`)
	if _, err := CompileConfig(tree2); err != nil {
		t.Fatalf("auth leaf with no vrrp-group nearby must not hard-reject (scope guard), got: %v", err)
	}
}
