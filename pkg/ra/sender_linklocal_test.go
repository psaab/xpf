package ra

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"syscall"
	"testing"
)

// TestEUI64LinkLocal verifies the EUI-64 fe80::/64 derivation matches the
// canonical pattern (mac[0]^0x02, mac[1], mac[2], 0xff, 0xfe, mac[3..5]) and is
// byte-identical to the daemon's ensureRethLinkLocal computation
// (pkg/daemon/daemon_reth.go). The expected vectors are copied here on purpose:
// pkg/ra must not import pkg/daemon, so the test pins the shared byte pattern
// rather than reaching across the package boundary.
func TestEUI64LinkLocal(t *testing.T) {
	cases := []struct {
		name string
		mac  net.HardwareAddr
		want net.IP
	}{
		{
			name: "universal-bit-flip",
			// 0x00 -> 0x02 after the universal/local bit flip.
			mac:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			want: net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55},
		},
		{
			name: "reth-virtual-mac",
			// reth0 MAC: the packed index/node octet is 0 for node 0.
			mac:  net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x00, 0x00},
			want: net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0xbf, 0x72, 0xff, 0xfe, 0x01, 0x00, 0x00},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eui64LinkLocal(tc.mac)
			if !got.Equal(tc.want) {
				t.Fatalf("eui64LinkLocal(%s) = %s, want %s", tc.mac, got, tc.want)
			}
			if !got.IsLinkLocalUnicast() {
				t.Fatalf("eui64LinkLocal(%s) = %s is not a link-local unicast", tc.mac, got)
			}
		})
	}
}

// TestEUI64LinkLocalBadMAC asserts a non-6-byte MAC yields nil (so the caller
// returns an explicit "no usable MAC" error rather than synthesizing a bogus
// address). Covers the empty, short, and EUI-64 (8-byte) cases.
func TestEUI64LinkLocalBadMAC(t *testing.T) {
	for _, mac := range []net.HardwareAddr{
		nil,
		{},
		{0x00, 0x11, 0x22},
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}, // 8-byte EUI-64
	} {
		if got := eui64LinkLocal(mac); got != nil {
			t.Errorf("eui64LinkLocal(%v) = %s, want nil", mac, got)
		}
	}
}

// TestClassifyAddrAddResult is the regression for the Copilot review on #2034:
// ensureLinkLocal must not log "added link-local" when netlink.AddrAdd loses the
// list/add race and returns EEXIST. The decision is extracted into the pure
// classifyAddrAddResult helper so it is testable off-lab (the surrounding add
// performs real netlink syscalls). This test fails if the helper reverts to the
// pre-fix behavior of treating EEXIST as a logged add (logAdded=true) or as an
// error.
func TestClassifyAddrAddResult(t *testing.T) {
	cases := []struct {
		name        string
		addErr      error
		wantLog     bool
		wantErr     bool
		wantErrSame error // when non-nil, returned err must wrap/equal this
	}{
		{
			name:    "real-add",
			addErr:  nil,
			wantLog: true,
			wantErr: false,
		},
		{
			name:    "eexist-race",
			addErr:  syscall.EEXIST,
			wantLog: false, // must NOT log "added" — the address already existed
			wantErr: false, // EEXIST is a silent success
		},
		{
			name:    "eexist-wrapped",
			addErr:  fmt.Errorf("add: %w", syscall.EEXIST),
			wantLog: false,
			wantErr: false,
		},
		{
			name:        "other-failure",
			addErr:      syscall.EPERM,
			wantLog:     false,
			wantErr:     true,
			wantErrSame: syscall.EPERM,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logAdded, err := classifyAddrAddResult(tc.addErr)
			if logAdded != tc.wantLog {
				t.Errorf("classifyAddrAddResult(%v) logAdded = %v, want %v",
					tc.addErr, logAdded, tc.wantLog)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("classifyAddrAddResult(%v) err = %v, want err? %v",
					tc.addErr, err, tc.wantErr)
			}
			if tc.wantErrSame != nil && !errors.Is(err, tc.wantErrSame) {
				t.Errorf("classifyAddrAddResult(%v) err = %v, want errors.Is %v",
					tc.addErr, err, tc.wantErrSame)
			}
		})
	}
}

// TestEnsureLinkLocalNoProcfsWrites is the load-bearing regression for #2034:
// the previous implementation wrote /proc/sys/net/ipv6/conf/<if>/addr_gen_mode
// and accept_dad and did a link DOWN/UP, silently undoing the RETH
// addr_gen_mode=1 suppression contract and bouncing a live dataplane NIC. The
// fix adds the link-local purely via netlink.AddrAdd with IFA_F_NODAD. This
// test statically parses ensureLinkLocal's AST and fails if it ever reintroduces
// a procfs write (os.WriteFile), an addr_gen_mode / accept_dad reference, or a
// link DOWN/UP cycle (LinkSetDown / LinkSetUp). It complements the fsatomic
// canary, which no longer allowlists ra::ensureLinkLocal.
func TestEnsureLinkLocalNoProcfsWrites(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sender.go", nil, 0)
	if err != nil {
		t.Fatalf("parse sender.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == "ensureLinkLocal" {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("could not locate ensureLinkLocal in sender.go")
	}

	var buf bytes.Buffer
	ast.Fprint(&buf, fset, fn, ast.NotNilFilter)
	body := buf.String()

	forbidden := []string{
		"WriteFile",     // no procfs/sysfs write
		"addr_gen_mode", // must not touch the suppression contract
		"accept_dad",    // address-scoped NODAD replaces the procfs DAD knob
		"LinkSetDown",   // no out-of-band link cycle on a dataplane NIC
		"LinkSetUp",
	}
	for _, tok := range forbidden {
		if bytes.Contains([]byte(body), []byte(tok)) {
			t.Errorf("ensureLinkLocal references forbidden token %q; the #2034 fix "+
				"must not write procfs knobs or cycle the link", tok)
		}
	}
}
