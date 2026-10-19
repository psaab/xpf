package logging

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// #15697: formatStructuredMsg emitted nat-source-address="0.0.0.0" /
// nat-destination-address="::" and port "0" for untranslated NAT legs.
// Junos vSRX reports the effective post-NAT tuple, which for an
// untranslated component is the original pre-NAT address/port. Each
// component (IP, port) resolves independently: a translated IP with an
// untranslated (zero) port keeps the IP and mirrors the original port,
// and vice versa.

func natRecord15697(typ string) EventRecord {
	return EventRecord{
		Type:         typ,
		SrcAddr:      "10.0.1.5:41234",
		DstAddr:      "10.0.2.7:443",
		InZoneName:   "trust",
		OutZoneName:  "untrust",
		PolicyName:   "allow-web",
		AppName:      "junos-https",
		IngressIface: "ge-0/0/0.0",
		CloseReason:  "TCP FIN",
		SessionID:    4242,
	}
}

func assertNATParams15697(t *testing.T, msg, wantSrcIP, wantSrcPort, wantDstIP, wantDstPort string) {
	t.Helper()
	for param, want := range map[string]string{
		"nat-source-address":      wantSrcIP,
		"nat-source-port":         wantSrcPort,
		"nat-destination-address": wantDstIP,
		"nat-destination-port":    wantDstPort,
	} {
		needle := param + `="` + want + `"`
		if !strings.Contains(msg, needle) {
			t.Errorf("structured msg missing %s\n got: %s", needle, msg)
		}
	}
}

func TestStructuredRTFlowUntranslatedNATMirrorsTuple15697(t *testing.T) {
	for _, typ := range []string{"SESSION_OPEN", "SESSION_CLOSE"} {
		t.Run(typ+"_empty", func(t *testing.T) {
			rec := natRecord15697(typ)
			rec.NATSrcAddr = ""
			rec.NATDstAddr = ""
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "10.0.1.5", "41234", "10.0.2.7", "443")
			if strings.Contains(msg, `nat-source-address="0.0.0.0"`) ||
				strings.Contains(msg, `nat-destination-address="0.0.0.0"`) ||
				strings.Contains(msg, `nat-source-port="0"`) ||
				strings.Contains(msg, `nat-destination-port="0"`) {
				t.Errorf("untranslated NAT still emitted zero placeholder:\n%s", msg)
			}
		})
		t.Run(typ+"_zero_v4", func(t *testing.T) {
			// Shape the decoders produce for an absent v4 NAT slot.
			rec := natRecord15697(typ)
			rec.NATSrcAddr = "0.0.0.0:0"
			rec.NATDstAddr = "0.0.0.0:0"
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "10.0.1.5", "41234", "10.0.2.7", "443")
		})
		t.Run(typ+"_zero_v6", func(t *testing.T) {
			// Shape the decoders produce for an absent v6 NAT slot.
			rec := natRecord15697(typ)
			rec.SrcAddr = "[2001:db8::5]:41234"
			rec.DstAddr = "[2001:db8:1::7]:443"
			rec.NATSrcAddr = "[::]:0"
			rec.NATDstAddr = "[::]:0"
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "2001:db8::5", "41234", "2001:db8:1::7", "443")
			if strings.Contains(msg, `"::"`) {
				t.Errorf("untranslated v6 NAT still emitted :: placeholder:\n%s", msg)
			}
		})
	}
}

func TestStructuredRTFlowPartialNATResolvesPerComponent15697(t *testing.T) {
	for _, typ := range []string{"SESSION_OPEN", "SESSION_CLOSE"} {
		t.Run(typ+"_snat_ip_only", func(t *testing.T) {
			// SNAT rewrote the address but not the port: the wire port
			// slot is 0, so the effective post-NAT port is the original.
			rec := natRecord15697(typ)
			rec.NATSrcAddr = "172.16.1.1:0"
			rec.NATDstAddr = "0.0.0.0:0"
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "172.16.1.1", "41234", "10.0.2.7", "443")
		})
		t.Run(typ+"_dnat_port_only", func(t *testing.T) {
			// Port-only destination rewrite: IP mirrors the original,
			// translated port is preserved.
			rec := natRecord15697(typ)
			rec.NATSrcAddr = "0.0.0.0:0"
			rec.NATDstAddr = "0.0.0.0:8443"
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "10.0.1.5", "41234", "10.0.2.7", "8443")
		})
		t.Run(typ+"_fully_translated_unchanged", func(t *testing.T) {
			rec := natRecord15697(typ)
			rec.NATSrcAddr = "172.16.1.1:12345"
			rec.NATDstAddr = "10.0.2.99:8443"
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "172.16.1.1", "12345", "10.0.2.99", "8443")
		})
	}
}

func TestResolveNATAddrPort15697(t *testing.T) {
	cases := []struct {
		name         string
		nat          string
		origIP       string
		origPort     string
		wantIP, want string
	}{
		{"empty", "", "10.0.1.5", "41234", "10.0.1.5", "41234"},
		{"zero v4", "0.0.0.0:0", "10.0.1.5", "41234", "10.0.1.5", "41234"},
		{"zero v6", "[::]:0", "2001:db8::5", "41234", "2001:db8::5", "41234"},
		{"expanded zero v6", "[0:0:0:0:0:0:0:0]:0", "2001:db8::5", "41234", "2001:db8::5", "41234"},
		{"ip only", "172.16.1.1:0", "10.0.1.5", "41234", "172.16.1.1", "41234"},
		{"port only", "0.0.0.0:8443", "10.0.2.7", "443", "10.0.2.7", "8443"},
		{"translated v4", "172.16.1.1:12345", "10.0.1.5", "41234", "172.16.1.1", "12345"},
		{"translated v6", "[2001:db8::99]:12345", "2001:db8::5", "41234", "2001:db8::99", "12345"},
		{"nat64 v4 under v6", "203.0.113.7:8080", "2001:db8::5", "41234", "203.0.113.7", "8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := resolveNATAddrPort(tc.nat, tc.origIP, tc.origPort)
			if ip != tc.wantIP || port != tc.want {
				t.Errorf("resolveNATAddrPort(%q, %q, %q) = (%q, %q), want (%q, %q)",
					tc.nat, tc.origIP, tc.origPort, ip, port, tc.wantIP, tc.want)
			}
		})
	}
}

// End-to-end: a wire frame with zero NAT slots (no translation) decoded by
// DecodeRawEventRecord must render the effective tuple, not 0.0.0.0:0.
func TestDecodeRawEventUntranslatedNATStructured15697(t *testing.T) {
	for _, et := range []struct {
		name string
		typ  uint8
	}{
		{"SESSION_OPEN", eventTypeSessionOpen},
		{"SESSION_CLOSE", eventTypeSessionClose},
	} {
		t.Run(et.name, func(t *testing.T) {
			frame := extendedSessionFrame(et.typ, 4242)
			rec, ok := DecodeRawEventRecord(frame)
			if !ok {
				t.Fatalf("DecodeRawEventRecord rejected %s frame", et.name)
			}
			// Fixture tuple: 10.0.1.102:12345 -> 172.16.80.200:443, NAT slots zero.
			if rec.NATSrcAddr != "0.0.0.0:0" || rec.NATDstAddr != "0.0.0.0:0" {
				t.Fatalf("fixture NAT = %q/%q, want zero slots", rec.NATSrcAddr, rec.NATDstAddr)
			}
			msg := formatStructuredMsg(rec, 6)
			assertNATParams15697(t, msg, "10.0.1.102", "12345", "172.16.80.200", "443")
		})
	}

	t.Run("SNAT_IP_only_wire", func(t *testing.T) {
		frame := extendedSessionFrame(eventTypeSessionOpen, 4242)
		copy(frame[72:76], net.ParseIP("203.0.113.7").To4())
		binary.BigEndian.PutUint16(frame[104:106], 0) // NAT src port untranslated
		rec, ok := DecodeRawEventRecord(frame)
		if !ok {
			t.Fatal("DecodeRawEventRecord rejected SNAT frame")
		}
		msg := formatStructuredMsg(rec, 6)
		assertNATParams15697(t, msg, "203.0.113.7", "12345", "172.16.80.200", "443")
	})

	t.Run("v6_no_nat_wire", func(t *testing.T) {
		frame := make([]byte, rawEventSessionIDSize)
		frame[52] = eventTypeSessionOpen
		frame[53] = 6
		frame[55] = addrFamilyInet6
		binary.BigEndian.PutUint16(frame[40:42], 12345)
		binary.BigEndian.PutUint16(frame[42:44], 443)
		copy(frame[8:24], net.ParseIP("2001:db8::5").To16())
		copy(frame[24:40], net.ParseIP("2001:db8:1::7").To16())
		frame[rawEventLogSyslogOffset] = 1
		rec, ok := DecodeRawEventRecord(frame)
		if !ok {
			t.Fatal("DecodeRawEventRecord rejected v6 frame")
		}
		msg := formatStructuredMsg(rec, 6)
		assertNATParams15697(t, msg, "2001:db8::5", "12345", "2001:db8:1::7", "443")
		if strings.Contains(msg, `"::"`) {
			t.Errorf("v6 untranslated NAT still emitted :: placeholder:\n%s", msg)
		}
	})
}
