package config

import "testing"

// #19190: the tolerant load path (boot, HA sync) honors a packed `disable`
// after a flag or a valued statement, in both packed shapes: the hierarchical
// one-line body and the flat-set line.
func TestALGPackedDisableAfterFlagOrValueIsHonoredWhenLoaded19190(t *testing.T) {
	for proto, stmt := range map[string]string{
		"ftp": "allow-mismatch-ip-address", "dns": "maximum-message-length 1024", "sip": "hide-via-headers",
	} {
		t.Run(proto, func(t *testing.T) {
			for name, tree := range map[string]*ConfigTree{
				"flat-set": parseSetCommands(t, "set security alg "+proto+" "+stmt+" disable"),
				"hier":     parseHierText(t, "security { alg "+proto+" "+stmt+" disable; }"),
			} {
				if cfg := compileTreeLenientKit(t, tree); !cfg.Security.ALG.ALGDisabled(proto) {
					t.Fatalf("%s: packed `%s disable` loaded with ALG %s ENABLED", name, stmt, proto)
				}
			}
		})
	}
}

// Control: a `disable` inside a container's braced body stays the body's.
func TestALGInertBodyDisableDoesNotLeak19190(t *testing.T) {
	cfg := compileTreeLenientKit(t, parseHierText(t, "security { alg { ftp { traceoptions { disable; } } } }"))
	if cfg.Security.ALG.ALGDisabled("ftp") {
		t.Fatal("a disable inside the opaque traceoptions body disabled the ftp ALG")
	}
}
