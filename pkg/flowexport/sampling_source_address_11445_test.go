package flowexport

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestSamplingLocalSourceAddressReachesCollector11445 exercises a configured
// local source-address through config compilation and a real UDP export.
func TestSamplingLocalSourceAddressReachesCollector11445(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split collector address: %v", err)
	}
	input := fmt.Sprintf(`interfaces {
    lo0 {
        unit 0 {
            family inet {
                address 127.0.0.2/8;
            }
        }
    }
}
forwarding-options {
    sampling {
        instance i1 {
            family inet {
                output {
                    source-address 127.0.0.2;
                    flow-server %s {
                        port %s;
                    }
                }
            }
        }
    }
}`, host, port)
	tree, parseErrs := config.NewParser(input).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse config: %v", parseErrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}

	export := BuildExportConfig(v9Svc(), &cfg.ForwardingOptions)
	if export == nil || len(export.Collectors) != 1 {
		t.Fatalf("expected one export collector, got %+v", export)
	}
	collector := export.Collectors[0]
	if collector.Address != addr {
		t.Fatalf("collector address = %q, want %q", collector.Address, addr)
	}
	if collector.SourceAddress != "127.0.0.2" {
		t.Fatalf("collector source-address = %q, want local address 127.0.0.2", collector.SourceAddress)
	}
	exporter, err := NewExporter(export)
	if err != nil {
		t.Fatalf("create exporter with local source-address: %v", err)
	}
	defer exporter.Close()
	exporter.sendRecords(mkRec())

	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set collector read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	if _, from, err := pc.ReadFrom(buf); err != nil {
		t.Fatalf("read exported flow: %v", err)
	} else if udpAddr, ok := from.(*net.UDPAddr); !ok || !udpAddr.IP.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatalf("exported datagram source = %v, want 127.0.0.2", from)
	}
}
