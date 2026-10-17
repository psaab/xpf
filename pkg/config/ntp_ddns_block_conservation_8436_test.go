package config

import "testing"

// #8436 final batch: `system ntp server` and `system services dynamic-dns
// provider` — the last two SILENT entries in the census.
//
// NEITHER IS THE SHAPE THE PREVIOUS BATCHES FIXED, and the NTP one especially
// is not: it already iterated every `server` node and already appended to a
// slice, so it LOOKED merged. What it did was append the address a second time
// (a duplicate chrony directive) and REPLACE the per-address option entry, so
// `server 1.1.1.1 { key 5; }` followed by `server 1.1.1.1 { version 4; }`
// compiled to key 0. Measured before the fix was written, not assumed from the
// family.
//
// Both cells are paired with a different-name control, for the same reason as
// every other batch: a merge keyed on the wrong thing passes the merge cell
// while collapsing two servers or two providers into one.

// ---------- system ntp server ----------

// The defect had TWO halves that fail differently: the duplicated slice entry
// and the wiped option. Asserted separately — an option-only fix leaves a
// duplicate `server` line in the rendered chrony config, and a dedupe-only fix
// still loses `key`.
func TestDuplicateNTPServerBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    ntp {
        server 1.1.1.1 {
            key 5;
        }
        server 1.1.1.1 {
            version 4;
        }
    }
}
`)
	if got := cfg.System.NTPServers; len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("NTPServers = %v, want exactly [1.1.1.1]. Two statements naming ONE "+
			"server appended the address twice, which renders a duplicate chrony "+
			"`server` directive (#8436)", got)
	}
	opt := cfg.System.NTPServerOptions["1.1.1.1"]
	// #14596: the merged key id is stripped into NTPServerKeyIDs (the
	// renderer must never emit chrony `key` without a keyfile); the
	// conservation property is that the id survives the merge there.
	if len(cfg.System.NTPServerKeyIDs) != 1 || cfg.System.NTPServerKeyIDs[0] != 5 {
		t.Errorf("NTPServerKeyIDs = %v, want [5] — the second statement's option entry REPLACED the "+
			"first's instead of merging, so the authentication key is gone (#8436)", cfg.System.NTPServerKeyIDs)
	}
	if opt.Key != 0 {
		t.Errorf("Key = %d, want 0 after the #14596 strip", opt.Key)
	}
	if opt.Version != 4 {
		t.Errorf("Version = %d, want 4 — the second statement's own setting was lost", opt.Version)
	}
}

// THE CONTROL. Two DIFFERENT addresses must stay two servers with their own
// options.
//
// MUTATION: key the dedupe or the option merge on anything but the address —
// e.g. skip the append whenever the list is non-empty — and this reds.
func TestDistinctNTPServerBlocksStayDistinct8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    ntp {
        server 1.1.1.1 {
            key 5;
        }
        server 2.2.2.2 {
            version 4;
        }
    }
}
`)
	if got := cfg.System.NTPServers; len(got) != 2 {
		t.Fatalf("NTPServers = %v, want two entries. An over-broad merge collapses two "+
			"configured time sources into one (#8436)", got)
	}
	if len(cfg.System.NTPServerKeyIDs) != 1 || cfg.System.NTPServerKeyIDs[0] != 5 {
		t.Errorf("NTPServerKeyIDs = %v, want [5] from 1.1.1.1 only (#14596 strip)", cfg.System.NTPServerKeyIDs)
	}
	if got := cfg.System.NTPServerOptions["1.1.1.1"].Key; got != 0 {
		t.Errorf("1.1.1.1 Key = %d, want 0 after the #14596 strip", got)
	}
	if got := cfg.System.NTPServerOptions["2.2.2.2"].Version; got != 4 {
		t.Errorf("2.2.2.2 Version = %d, want 4", got)
	}
	if got := cfg.System.NTPServerOptions["1.1.1.1"].Version; got != 0 {
		t.Errorf("1.1.1.1 picked up 2.2.2.2's version (%d); the options merged across "+
			"addresses", got)
	}
}

// THE BRACKETED SPELLING is the reason the dedupe is per ADDRESS and not per
// `server` NODE. `server [ a b ]` collapses onto one node's Keys (#2419), so a
// node-level "already seen this node" check would have kept only the first
// address — turning a conservation fix into a config loss.
//
// MUTATION: dedupe per node instead of per address and this reds with one
// server where the operator wrote two.
func TestBracketedNTPServerListStillYieldsEveryAddress8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    ntp {
        server [ 1.1.1.1 2.2.2.2 3.3.3.3 ];
    }
}
`)
	got := cfg.System.NTPServers
	if len(got) != 3 {
		t.Fatalf("bracketed `server [ a b c ]` compiled %v, want three addresses. The "+
			"#8436 dedupe must be keyed on the ADDRESS: this spelling puts every "+
			"address on ONE node (#2419)", got)
	}
}

// A genuinely repeated address in ONE bracket list still collapses to one
// server — the dedupe is about the compiled result, not about which statement
// produced it.
func TestRepeatedAddressInOneBracketListCollapses8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    ntp {
        server [ 1.1.1.1 1.1.1.1 2.2.2.2 ];
    }
}
`)
	if got := cfg.System.NTPServers; len(got) != 2 {
		t.Errorf("NTPServers = %v, want two distinct addresses", got)
	}
}

// ---------- system services dynamic-dns provider ----------

func TestDuplicateDDNSProviderBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    services {
        dynamic-dns {
            provider P {
                backend nsupdate;
            }
            provider P {
                update-server ns.example.com;
            }
        }
    }
}
`)
	if cfg.System.Services == nil || cfg.System.Services.DynamicDNS == nil {
		t.Fatal("dynamic-dns did not compile")
	}
	p := cfg.System.Services.DynamicDNS.Providers["P"]
	if p == nil {
		t.Fatal("provider P did not compile")
	}
	if p.Backend != "nsupdate" {
		t.Errorf("Backend = %q, want \"nsupdate\" — the second block constructed a fresh "+
			"provider and overwrote the first, discarding its backend (#8436)", p.Backend)
	}
	if p.UpdateServer != "ns.example.com" {
		t.Errorf("UpdateServer = %q, want \"ns.example.com\" — the second block's own "+
			"setting was lost", p.UpdateServer)
	}
}

// THE CONTROL for the provider catalog.
//
// MUTATION: group on anything but the provider NAME and this reds — two
// providers collapse into one, so an interface bound to the second silently
// updates through the first's endpoint.
func TestDistinctDDNSProviderBlocksStayDistinct8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    services {
        dynamic-dns {
            provider P1 {
                backend nsupdate;
                update-server ns1.example.com;
            }
            provider P2 {
                backend nsupdate;
                update-server ns2.example.com;
            }
        }
    }
}
`)
	provs := cfg.System.Services.DynamicDNS.Providers
	if len(provs) != 2 {
		t.Fatalf("two DIFFERENT providers produced %d entries, want 2 (#8436)", len(provs))
	}
	if got := provs["P1"].UpdateServer; got != "ns1.example.com" {
		t.Errorf("P1 update-server = %q, want ns1.example.com", got)
	}
	if got := provs["P2"].UpdateServer; got != "ns2.example.com" {
		t.Errorf("P2 update-server = %q, want ns2.example.com", got)
	}
}

// A leaf named by BOTH blocks takes the later value — the ordinary
// last-statement-wins a single block already has for a repeated leaf. Stated so
// the merge's direction is a decision rather than an accident.
func TestDuplicateDDNSProviderLaterLeafWins8436(t *testing.T) {
	cfg := mustCompile8436(t, `
system {
    services {
        dynamic-dns {
            provider P {
                backend nsupdate;
                update-server first.example.com;
            }
            provider P {
                update-server second.example.com;
            }
        }
    }
}
`)
	p := cfg.System.Services.DynamicDNS.Providers["P"]
	if p == nil {
		t.Fatal("provider P did not compile")
	}
	if p.UpdateServer != "second.example.com" {
		t.Errorf("UpdateServer = %q, want \"second.example.com\" (later statement wins)",
			p.UpdateServer)
	}
	if p.Backend != "nsupdate" {
		t.Errorf("Backend = %q, want \"nsupdate\" — a leaf the second block never "+
			"mentioned must not be reset", p.Backend)
	}
}
