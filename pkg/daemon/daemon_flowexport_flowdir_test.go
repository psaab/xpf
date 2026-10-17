package daemon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// flowDirV9Config builds a NetFlow v9 sampling config with `export-extension
// flow-dir` enabled and a per-zone sampling-direction (#3270): zone "b" has
// sampling input (via eth1.0), zone "c" has sampling output (via eth2.0), zone
// "a" has none. The sampling direction is keyed by interface→zone membership,
// not by the numeric zone id (#3075 made ids a stable name-hash). rate=1 so
// every close is admitted.
func flowDirV9Config(addr string, v9Port int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"s": {
				Name:      "s",
				InputRate: 1,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: addr, Port: v9Port, Version: config.FlowServerVersion9},
					},
				},
			},
		},
	}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{
				"t": {Name: "t", ExportExtensions: []string{"flow-dir"}},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"a": {},
		"b": {Interfaces: []string{"eth1.0"}},
		"c": {Interfaces: []string{"eth2.0"}},
	}
	cfg.Interfaces = config.InterfacesConfig{
		Interfaces: map[string]*config.InterfaceConfig{
			"eth1": {Units: map[int]*config.InterfaceUnit{0: {SamplingV4Input: true}}},
			"eth2": {Units: map[int]*config.InterfaceUnit{0: {SamplingV4Output: true}}},
		},
	}
	return cfg
}

// parseV9FlowDirection parses NetFlow v9 datagrams, locates the template
// carrying fieldDirection (IE 61) and returns the flowDirection byte of the
// first data record encoded with that template. ok is false if no such record
// was seen.
func parseV9FlowDirection(datagrams [][]byte) (dir byte, ok bool) {
	const fieldDirection = 61
	type fld struct {
		typ uint16
		len uint16
	}
	templates := map[uint16][]fld{}
	// First pass: collect templates.
	for _, p := range datagrams {
		if len(p) < 20 {
			continue
		}
		off := 20
		for off+4 <= len(p) {
			setID := binary.BigEndian.Uint16(p[off : off+2])
			setLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
			if setLen < 4 || off+setLen > len(p) {
				break
			}
			body := p[off+4 : off+setLen]
			if setID == 0 { // template flowset
				bo := 0
				for bo+4 <= len(body) {
					tid := binary.BigEndian.Uint16(body[bo : bo+2])
					cnt := int(binary.BigEndian.Uint16(body[bo+2 : bo+4]))
					bo += 4
					var fields []fld
					for i := 0; i < cnt && bo+4 <= len(body); i++ {
						fields = append(fields, fld{
							typ: binary.BigEndian.Uint16(body[bo : bo+2]),
							len: binary.BigEndian.Uint16(body[bo+2 : bo+4]),
						})
						bo += 4
					}
					templates[tid] = fields
				}
			}
			off += setLen
		}
	}
	// Second pass: find a data record using a template that has IE 61.
	for _, p := range datagrams {
		if len(p) < 20 {
			continue
		}
		off := 20
		for off+4 <= len(p) {
			setID := binary.BigEndian.Uint16(p[off : off+2])
			setLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
			if setLen < 4 || off+setLen > len(p) {
				break
			}
			if setID >= 256 {
				if fields, found := templates[setID]; found {
					// Compute the IE 61 byte offset within the record body.
					fieldOff := -1
					recLen := 0
					for _, f := range fields {
						if f.typ == fieldDirection && fieldOff < 0 {
							fieldOff = recLen
						}
						recLen += int(f.len)
					}
					if fieldOff >= 0 && off+4+fieldOff < off+setLen {
						return p[off+4+fieldOff], true
					}
				}
			}
			off += setLen
		}
	}
	return 0, false
}

// TestSessionCloseFlowDirectionEgress is the #3270 end-to-end fail-on-revert
// proof: with `export-extension flow-dir` + a per-zone sampling-direction, a
// SESSION_CLOSE whose ingress zone is NOT input-sampled but whose egress zone
// IS output-sampled exports flowDirection = 1 (egress) in the NetFlow v9
// record. Reverting the daemon's sd.Direction assignment OR the encoder write
// makes the captured byte 0, flipping this RED.
func TestSessionCloseFlowDirectionEgress(t *testing.T) {
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	if !d.reconcileFlowExporters(flowDirV9Config("127.0.0.1", port)) {
		t.Fatal("flow exporter must start")
	}
	exp := d.flowBundle.Load()
	if exp == nil || exp.firstExp() == nil {
		t.Fatal("v9 exporter must be live")
	}

	// Ingress zone a (no sampling), egress zone c (sampling output) ->
	// eligible by output, direction = 1 (egress). #3075: zone ids are a stable
	// name-hash, so the SESSION_CLOSE payload must carry the hashed ids of a/c
	// (the daemon resolves them back to names via the same StableZoneID map).
	payload := buildSessionCloseRawEventV4(
		6,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{172, 16, 80, 8}, 40000,
		config.StableZoneID("a"), config.StableZoneID("c"),
	)
	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid SESSION_CLOSE payload")
	}

	// Wait for the flow record to be transmitted.
	if got := waitFlows(t, exp.firstExp().Stats); got < 1 {
		t.Fatalf("exporter exported %d flows, want >= 1", got)
	}

	// Drain datagrams (template + data) and parse the flowDirection byte.
	var datagrams [][]byte
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 2048)
	var dir byte
	var ok bool
	for time.Now().Before(deadline) {
		coll.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := coll.ReadFromUDP(buf)
		if err != nil {
			if d, found := parseV9FlowDirection(datagrams); found {
				dir, ok = d, true
				break
			}
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		datagrams = append(datagrams, cp)
		if d, found := parseV9FlowDirection(datagrams); found {
			dir, ok = d, true
			break
		}
	}
	if !ok {
		t.Fatal("no NetFlow v9 data record with flowDirection (IE 61) captured")
	}
	if dir != 1 {
		t.Fatalf("flowDirection = %d, want 1 (egress) — daemon derivation or encoder write reverted", dir)
	}
}
