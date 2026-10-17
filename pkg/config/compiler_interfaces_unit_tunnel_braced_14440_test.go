// #14440 (DR18-H4): unit-tunnel braced-scalar source / destination /
// mode (and keepalive / keepalive-retry at both levels) were silently
// dropped. The interface-level reader has a raw pre-pass over
// tunnelNode.Children that reads nodeVal before tunnelRunChildren9156
// flattens `source { 10.0.0.1; }` into `[source]` + stray `[10.0.0.1]`;
// the unit reader iterated ONLY the flattened children, so the
// v != ""-guarded leaves read empty and the unit inherited the
// interface tunnel's peer/mode (fail-open misdelivery; a braced
// `mode { wireguard; }` flipping to inherited gre also discards the
// WireGuard keys/peers and sends plaintext GRE to the wrong peer).
// Interface-level keepalive/keepalive-retry braced scalars dropped the
// same way (pre-pass covered only source/destination/mode).
package config

import (
	"reflect"
	"testing"
)

func TestUnitTunnelBracedScalars14440(t *testing.T) {
	t.Run("unit braced scalars override inherited interface tunnel", func(t *testing.T) {
		src := `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode gre;
            key 1;
            keepalive { 10; }
            keepalive-retry { 3; }
        }
        unit 0 {
            tunnel {
                source { 10.0.1.1; }
                destination { 10.0.1.2; }
                mode { wireguard; }
                wireguard {
                    listen-port 51820;
                    private-key ` + wgKeyA + `;
                    peer ` + wgKeyB + ` {
                        allowed-ips 10.0.1.0/24;
                    }
                }
                keepalive { 20; }
                keepalive-retry { 5; }
            }
        }
    }
}`
		cfg := compileHierarchical(t, src)
		iface := cfg.Interfaces.Interfaces["gr-0/0/0"]
		if iface == nil || iface.Tunnel == nil {
			t.Fatalf("interface tunnel not compiled: %+v", cfg.Interfaces.Interfaces)
		}
		if iface.Tunnel.Source != "10.0.0.1" || iface.Tunnel.Destination != "10.0.0.2" ||
			iface.Tunnel.Mode != "gre" || iface.Tunnel.Key != 1 {
			t.Errorf("interface tunnel = %+v, want src 10.0.0.1 dst 10.0.0.2 mode gre key 1", iface.Tunnel)
		}
		if iface.Tunnel.Keepalive != 10 {
			t.Errorf("interface Keepalive = %d, want 10 (braced keepalive)", iface.Tunnel.Keepalive)
		}
		if iface.Tunnel.KeepaliveRetry != 3 {
			t.Errorf("interface KeepaliveRetry = %d, want 3 (braced keepalive-retry)", iface.Tunnel.KeepaliveRetry)
		}
		unit := iface.Units[0]
		if unit == nil || unit.Tunnel == nil {
			t.Fatalf("unit 0 tunnel not compiled: %+v", iface.Units)
		}
		ut := unit.Tunnel
		if ut.Source != "10.0.1.1" {
			t.Errorf("unit Source = %q, want 10.0.1.1 (braced unit source, not inherited 10.0.0.1)", ut.Source)
		}
		if ut.Destination != "10.0.1.2" {
			t.Errorf("unit Destination = %q, want 10.0.1.2 (braced unit destination, not inherited 10.0.0.2)", ut.Destination)
		}
		if ut.Mode != "wireguard" {
			t.Errorf("unit Mode = %q, want wireguard (braced unit mode, not inherited gre)", ut.Mode)
		}
		if ut.Keepalive != 20 {
			t.Errorf("unit Keepalive = %d, want 20 (braced unit keepalive)", ut.Keepalive)
		}
		if ut.KeepaliveRetry != 5 {
			t.Errorf("unit KeepaliveRetry = %d, want 5 (braced unit keepalive-retry)", ut.KeepaliveRetry)
		}
		if ut.Key != 1 {
			t.Errorf("unit Key = %d, want 1 (inherited from interface tunnel)", ut.Key)
		}
		if len(ut.WgPeers) != 1 {
			t.Errorf("unit WgPeers = %v, want 1 peer (mode wireguard must retain WG peers, not plaintext GRE)", ut.WgPeers)
		}
	})

	t.Run("braced unit tunnel equals flat spelling", func(t *testing.T) {
		braced := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode gre;
            key 1;
        }
        unit 0 {
            tunnel {
                source { 10.0.1.1; }
                destination { 10.0.1.2; }
                mode { gre; }
                keepalive { 20; }
                keepalive-retry { 5; }
            }
        }
    }
}`)
		flat := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode gre;
            key 1;
        }
        unit 0 {
            tunnel {
                source 10.0.1.1;
                destination 10.0.1.2;
                mode gre;
                keepalive 20;
                keepalive-retry 5;
            }
        }
    }
}`)
		bu := braced.Interfaces.Interfaces["gr-0/0/0"].Units[0].Tunnel
		fu := flat.Interfaces.Interfaces["gr-0/0/0"].Units[0].Tunnel
		if bu == nil || fu == nil {
			t.Fatalf("unit tunnels: braced=%+v flat=%+v", bu, fu)
		}
		if !reflect.DeepEqual(bu, fu) {
			t.Errorf("braced unit tunnel %+v != flat unit tunnel %+v", bu, fu)
		}
		bi := braced.Interfaces.Interfaces["gr-0/0/0"].Tunnel
		fi := flat.Interfaces.Interfaces["gr-0/0/0"].Tunnel
		if !reflect.DeepEqual(bi, fi) {
			t.Errorf("braced fixture interface tunnel %+v != flat %+v", bi, fi)
		}
	})

	t.Run("interface braced keepalive equals flat", func(t *testing.T) {
		braced := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        tunnel {
            source { 10.0.0.1; }
            destination { 10.0.0.2; }
            mode { gre; }
            keepalive { 10; }
            keepalive-retry { 3; }
        }
    }
}`)
		flat := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode gre;
            keepalive 10;
            keepalive-retry 3;
        }
    }
}`)
		bi := braced.Interfaces.Interfaces["gr-0/0/0"].Tunnel
		fi := flat.Interfaces.Interfaces["gr-0/0/0"].Tunnel
		if bi == nil || fi == nil {
			t.Fatalf("interface tunnels: braced=%+v flat=%+v", bi, fi)
		}
		if !reflect.DeepEqual(bi, fi) {
			t.Errorf("braced interface tunnel %+v != flat %+v", bi, fi)
		}
		if bi.Keepalive != 10 || bi.KeepaliveRetry != 3 {
			t.Errorf("braced interface keepalive = %d/%d, want 10/3", bi.Keepalive, bi.KeepaliveRetry)
		}
	})

	t.Run("standalone unit braced mode wireguard", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        unit 0 {
            tunnel {
                source { 10.0.2.1; }
                destination { 10.0.2.2; }
                mode { wireguard; }
                wireguard {
                    listen-port 51821;
                    private-key `+wgKeyA+`;
                    peer `+wgKeyB+` {
                        allowed-ips 10.0.2.0/24;
                    }
                }
            }
        }
    }
}`)
		iface := cfg.Interfaces.Interfaces["gr-0/0/0"]
		if iface == nil {
			t.Fatalf("interface not compiled: %+v", cfg.Interfaces.Interfaces)
		}
		if iface.Tunnel != nil {
			t.Errorf("interface tunnel = %+v, want nil (no interface-level tunnel authored)", iface.Tunnel)
		}
		unit := iface.Units[0]
		if unit == nil || unit.Tunnel == nil {
			t.Fatalf("unit 0 tunnel not compiled: %+v", iface.Units)
		}
		if unit.Tunnel.Mode != "wireguard" {
			t.Errorf("standalone unit Mode = %q, want wireguard (braced mode, not default gre)", unit.Tunnel.Mode)
		}
		if unit.Tunnel.Source != "10.0.2.1" || unit.Tunnel.Destination != "10.0.2.2" {
			t.Errorf("standalone unit endpoints = %q/%q, want 10.0.2.1/10.0.2.2",
				unit.Tunnel.Source, unit.Tunnel.Destination)
		}
	})

	t.Run("unit without tunnel leaves still inherits interface tunnel", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode gre;
            key 7;
            keepalive 9;
            keepalive-retry 2;
        }
        unit 0 {
            tunnel {
                clear-dont-fragment-bit;
            }
        }
    }
}`)
		unit := cfg.Interfaces.Interfaces["gr-0/0/0"].Units[0]
		if unit == nil || unit.Tunnel == nil {
			t.Fatalf("unit 0 tunnel not compiled: %+v", cfg.Interfaces.Interfaces["gr-0/0/0"].Units)
		}
		ut := unit.Tunnel
		if ut.Source != "10.0.0.1" || ut.Destination != "10.0.0.2" || ut.Mode != "gre" ||
			ut.Key != 7 || ut.Keepalive != 9 || ut.KeepaliveRetry != 2 {
			t.Errorf("inheriting unit tunnel = %+v, want interface values src 10.0.0.1 dst 10.0.0.2 mode gre key 7 keepalive 9/2", ut)
		}
		if !ut.ClearDontFragmentBit {
			t.Errorf("unit ClearDontFragmentBit = false, want true (unit's own leaf)")
		}
	})

	t.Run("flat unit tunnel unchanged", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode gre;
            key 1;
            keepalive 10;
            keepalive-retry 3;
        }
        unit 0 {
            tunnel {
                source 10.0.1.1;
                destination 10.0.1.2;
                mode gre;
                keepalive 20;
                keepalive-retry 5;
            }
        }
    }
}`)
		iface := cfg.Interfaces.Interfaces["gr-0/0/0"]
		if iface.Tunnel.Keepalive != 10 || iface.Tunnel.KeepaliveRetry != 3 {
			t.Errorf("flat interface keepalive = %d/%d, want 10/3", iface.Tunnel.Keepalive, iface.Tunnel.KeepaliveRetry)
		}
		ut := iface.Units[0].Tunnel
		if ut.Source != "10.0.1.1" || ut.Destination != "10.0.1.2" || ut.Mode != "gre" ||
			ut.Keepalive != 20 || ut.KeepaliveRetry != 5 || ut.Key != 1 {
			t.Errorf("flat unit tunnel = %+v, want src 10.0.1.1 dst 10.0.1.2 mode gre keepalive 20/5 key 1", ut)
		}
	})
}

// #14440: astTunnelModeWireguard must honour braced `mode { wireguard; }`
// (via nodeVal) so the collision gate registers only the lowest unit ref
// for an interface-level WireGuard tunnel, matching the compiled outcome.
// Pre-fix (Keys[1] check) it registered wg0.0 AND wg0.1; wg0.1 collides
// with wg341 under the frozen fold and would falsely reject the commit.
func TestBracedModeWireguardTunnelID14440(t *testing.T) {
	for _, mode := range []string{"mode { wireguard; }", "mode wireguard;"} {
		tree, perrs := NewParser(`interfaces {
    wg0 {
        tunnel {
            ` + mode + `
        }
        unit 0 {
            description a;
        }
        unit 1 {
            description b;
        }
    }
}`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("mode %q parse errors: %v", mode, perrs)
		}
		ifaces := tree.FindChildren("interfaces")
		if len(ifaces) != 1 {
			t.Fatalf("mode %q: interfaces nodes = %d, want 1", mode, len(ifaces))
		}
		out := map[string]struct{}{}
		collectTunnelEndpointNamesAST(ifaces[0], out)
		if _, ok := out["wg0.0"]; !ok {
			t.Errorf("mode %q: registered %v, want wg0.0 present", mode, out)
		}
		if _, ok := out["wg0.1"]; ok {
			t.Errorf("mode %q: registered %v, wg0.1 must not be registered for interface-level wireguard", mode, out)
		}
	}
}
