package configstore

import (
	"strings"
	"testing"
)

func isisIfCommit8450(t *testing.T, level string) (string, error) {
	t.Helper()
	cfg, err := CheckText(isisBase8446+
		"protocols { isis { net 49.0001.1921.6800.1001.00; interface ge-0/0/0.0 { level "+
		level+"; } } }\n", 0)
	if err != nil {
		return "", err
	}
	if cfg.Protocols.ISIS == nil || len(cfg.Protocols.ISIS.Interfaces) == 0 {
		t.Fatalf("level %q committed but produced no IS-IS interface", level)
	}
	return cfg.Protocols.ISIS.Interfaces[0].Level, nil
}

// #8450: the per-interface level leaf was untyped, so any string committed and
// the renderer silently emitted nothing for it.
func TestISISInterfaceLevelRejectedAtCommit_8450(t *testing.T) {
	for _, bad := range []string{"garbage", "level-3", "3", "LEVEL-1", "0"} {
		if _, err := isisIfCommit8450(t, bad); err == nil {
			t.Errorf("interface level %q committed clean — it renders no circuit-type "+
				"and the interface stays at the router-wide is-type", bad)
		}
	}
}

// POSITIVE CONTROL. Both the Junos bare-digit spelling and the FRR level-N
// spellings must commit — a gate that rejects the digits would reject the way
// Junos actually writes this leaf.
func TestISISInterfaceLevelCanonicalAccepted_8450(t *testing.T) {
	for _, good := range []string{"1", "2", "1-2", "level-1", "level-2", "level-1-2", "level-2-only"} {
		got, err := isisIfCommit8450(t, good)
		if err != nil {
			t.Errorf("interface level %q REJECTED: %v", good,
				strings.SplitN(err.Error(), "\n", 2)[0])
			continue
		}
		if got != good {
			t.Errorf("interface level %q stored as %q; this leaf is stored verbatim and "+
				"canonicalized at render, so a change here needs the renderer checked too",
				good, got)
		}
	}
}

// The routing-instance schema copy. Stripping the validator from that copy alone
// was a surviving mutation for the router-wide leaf in #8446; this is the same
// exposure one level down.
func TestISISInterfaceLevelTypedInRoutingInstanceCopy_8450(t *testing.T) {
	ri := func(level string) error {
		// The RI must own the interface since #11310 (protocol refs gated
		// by instance membership); the level validator is what this cell
		// measures, not the membership gate.
		_, err := CheckText(isisBase8446+
			"routing-instances { vrf-a { instance-type virtual-router; interface ge-0/0/0.0; protocols { isis { "+
			"net 49.0001.1921.6800.1001.00; interface ge-0/0/0.0 { level "+level+"; } } } } }\n", 0)
		return err
	}
	// CONTROL: a canonical value must COMMIT here, so a rejection below means
	// the validator fired rather than the stanza being unreachable.
	if err := ri("1"); err != nil {
		t.Fatalf("control: a canonical interface level was rejected in a routing-instance: %v", err)
	}
	for _, bad := range []string{"garbage", "level-3", "3"} {
		if err := ri(bad); err == nil {
			t.Errorf("routing-instances copy: interface level %q committed clean — "+
				"the second schema copy is unguarded", bad)
		}
	}
}
