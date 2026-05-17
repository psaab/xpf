package config

import (
	"strconv"
	"strings"
)

func compileFirewall(node *Node, fw *FirewallConfig) error {
	if fw.FiltersInet == nil {
		fw.FiltersInet = make(map[string]*FirewallFilter)
	}
	if fw.FiltersInet6 == nil {
		fw.FiltersInet6 = make(map[string]*FirewallFilter)
	}
	if fw.Policers == nil {
		fw.Policers = make(map[string]*PolicerConfig)
	}

	// Compile policer definitions
	for _, polInst := range namedInstances(node.FindChildren("policer")) {
		pol := &PolicerConfig{
			Name:       polInst.name,
			ThenAction: "discard", // default action
		}

		ifExceeding := polInst.node.FindChild("if-exceeding")
		if ifExceeding != nil {
			for _, child := range ifExceeding.Children {
				switch child.Name() {
				case "bandwidth-limit":
					if v := nodeVal(child); v != "" {
						pol.BandwidthLimit = parseBandwidthLimit(v)
					}
				case "burst-size-limit":
					if v := nodeVal(child); v != "" {
						pol.BurstSizeLimit = parseBurstSizeLimit(v)
					}
				}
			}
		}

		thenNode := polInst.node.FindChild("then")
		if thenNode != nil {
			for _, child := range thenNode.Children {
				switch child.Name() {
				case "discard":
					pol.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						pol.ThenAction = "loss-priority " + v
					}
				}
			}
		}

		// Check for logical-interface-policer flag
		if polInst.node.FindChild("logical-interface-policer") != nil {
			pol.LogicalInterfacePolicer = true
		}

		fw.Policers[pol.Name] = pol
	}

	// Compile three-color policer definitions
	if fw.ThreeColorPolicers == nil {
		fw.ThreeColorPolicers = make(map[string]*ThreeColorPolicerConfig)
	}
	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
		tcp := fw.ThreeColorPolicers[tcpInst.name]
		if tcp == nil {
			tcp = &ThreeColorPolicerConfig{
				Name:       tcpInst.name,
				ThenAction: "discard",
			}
			fw.ThreeColorPolicers[tcpInst.name] = tcp
		}

		singleRates := tcpInst.node.FindChildren("single-rate")
		if len(singleRates) > 0 {
			tcp.SingleRateConfigured = true
			tcp.TwoRate = false
		}
		for _, sr := range singleRates {
			if sr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if sr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range sr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "excess-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		twoRates := tcpInst.node.FindChildren("two-rate")
		if len(twoRates) > 0 {
			tcp.TwoRateConfigured = true
			tcp.TwoRate = true
		}
		for _, tr := range twoRates {
			if tr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if tr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range tr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "peak-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.PIR = parseBandwidthLimit(v)
					}
				case "peak-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		if thenNode := tcpInst.node.FindChild("then"); thenNode != nil {
			for _, child := range thenNode.Children {
				switch child.Name() {
				case "discard":
					tcp.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						tcp.ThenAction = "loss-priority " + v
					}
				}
			}
		}
	}

	for _, familyNode := range node.FindChildren("family") {
		var afNodes []*Node
		var afName string

		if len(familyNode.Keys) >= 2 {
			// Hierarchical: family inet { ... }
			afName = familyNode.Keys[1]
			afNodes = []*Node{familyNode}
		} else {
			// Set-command shape: family { inet { ... } inet6 { ... } }
			for _, child := range familyNode.Children {
				afNodes = append(afNodes, child)
			}
		}

		for _, afNode := range afNodes {
			af := afName
			if af == "" {
				af = afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					af = afNode.Keys[1]
				}
			}

			dest := fw.FiltersInet
			if af == "inet6" {
				dest = fw.FiltersInet6
			}

			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
				filter := &FirewallFilter{Name: filterInst.name}

				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
					term := &FirewallFilterTerm{
						Name:     termInst.name,
						ICMPType: -1,
						ICMPCode: -1,
					}

					fromNode := termInst.node.FindChild("from")
					if fromNode != nil {
						compileFilterFrom(fromNode, term)
					}

					thenNode := termInst.node.FindChild("then")
					if thenNode != nil {
						compileFilterThen(thenNode, term)
					}

					filter.Terms = append(filter.Terms, term)
				}

				dest[filter.Name] = filter
			}
		}
	}
	return nil
}

func compileFilterFrom(node *Node, term *FirewallFilterTerm) {
	for _, child := range node.Children {
		switch child.Name() {
		case "dscp", "traffic-class":
			if v := nodeVal(child); v != "" {
				term.DSCP = v
			}
		case "protocol":
			if v := nodeVal(child); v != "" {
				term.Protocol = v
			}
		case "source-address":
			// Can be a leaf with value or a block with address entries
			if len(child.Keys) >= 2 {
				term.SourceAddresses = append(term.SourceAddresses, child.Keys[1])
			}
			for _, addrNode := range child.Children {
				if len(addrNode.Keys) >= 1 {
					term.SourceAddresses = append(term.SourceAddresses, addrNode.Keys[0])
				}
			}
		case "destination-address":
			if len(child.Keys) >= 2 {
				term.DestAddresses = append(term.DestAddresses, child.Keys[1])
			}
			for _, addrNode := range child.Children {
				if len(addrNode.Keys) >= 1 {
					term.DestAddresses = append(term.DestAddresses, addrNode.Keys[0])
				}
			}
		case "destination-port":
			if len(child.Keys) >= 2 {
				// Can be a single port or bracket list
				for _, k := range child.Keys[1:] {
					term.DestinationPorts = append(term.DestinationPorts, k)
				}
			}
			// Flat set syntax: port value as child node
			for _, portNode := range child.Children {
				if len(portNode.Keys) >= 1 {
					term.DestinationPorts = append(term.DestinationPorts, portNode.Keys[0])
				}
			}
		case "source-prefix-list":
			// Block form: source-prefix-list { mgmt-hosts except; }
			for _, plNode := range child.Children {
				ref := PrefixListRef{Name: plNode.Keys[0]}
				if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
					ref.Except = true
				}
				term.SourcePrefixLists = append(term.SourcePrefixLists, ref)
			}
		case "destination-prefix-list":
			for _, plNode := range child.Children {
				ref := PrefixListRef{Name: plNode.Keys[0]}
				if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
					ref.Except = true
				}
				term.DestPrefixLists = append(term.DestPrefixLists, ref)
			}
		case "source-port":
			if len(child.Keys) >= 2 {
				for _, k := range child.Keys[1:] {
					term.SourcePorts = append(term.SourcePorts, k)
				}
			}
			for _, portNode := range child.Children {
				if len(portNode.Keys) >= 1 {
					term.SourcePorts = append(term.SourcePorts, portNode.Keys[0])
				}
			}
		case "icmp-type":
			v := nodeVal(child)
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					term.ICMPType = n
				}
			}
		case "icmp-code":
			v := nodeVal(child)
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					term.ICMPCode = n
				}
			}
		case "tcp-flags":
			// Can be bracket list or single value: tcp-flags "syn ack" or [ syn ack ]
			if len(child.Keys) >= 2 {
				for _, k := range child.Keys[1:] {
					term.TCPFlags = append(term.TCPFlags, k)
				}
			}
			for _, flagNode := range child.Children {
				if len(flagNode.Keys) >= 1 {
					term.TCPFlags = append(term.TCPFlags, flagNode.Keys[0])
				}
			}
		case "is-fragment":
			term.IsFragment = true
		case "flexible-match-range":
			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
				fm := &FlexMatchConfig{MatchStart: "layer-3"}
				for _, rc := range rangeInst.node.Children {
					switch rc.Name() {
					case "match-start":
						if v := nodeVal(rc); v != "" {
							fm.MatchStart = v
						}
					case "byte-offset":
						if v := nodeVal(rc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								fm.ByteOffset = uint8(n)
							}
						}
					case "bit-length":
						if v := nodeVal(rc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								fm.BitLength = uint8(n)
							}
						}
					case "range", "match-value":
						if v := nodeVal(rc); v != "" {
							// Format: "0xVALUE/0xMASK" or just "0xVALUE"
							parts := strings.SplitN(v, "/", 2)
							val, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "0x"), 16, 32)
							if err == nil {
								fm.Value = uint32(val)
							}
							if len(parts) == 2 {
								mask, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 32)
								if err == nil {
									fm.Mask = uint32(mask)
								}
							}
						}
					case "match-mask":
						if v := nodeVal(rc); v != "" {
							mask, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32)
							if err == nil {
								fm.Mask = uint32(mask)
							}
						}
					}
				}
				if fm.BitLength == 0 {
					fm.BitLength = 32 // default to 32-bit match
				}
				if fm.Mask == 0 {
					// Default mask based on bit-length
					switch fm.BitLength {
					case 8:
						fm.Mask = 0xFF
					case 16:
						fm.Mask = 0xFFFF
					default:
						fm.Mask = 0xFFFFFFFF
					}
				}
				term.FlexMatch = fm
				break // only first range supported per term
			}
		}
	}
}

func compileFilterThen(node *Node, term *FirewallFilterTerm) {
	// Handle leaf form: "then discard;" or "then accept;" produces
	// Keys=["then", "discard"] with IsLeaf=true and no children.
	if node.IsLeaf && len(node.Keys) >= 2 {
		for _, k := range node.Keys[1:] {
			switch k {
			case "accept":
				term.Action = "accept"
			case "reject":
				term.Action = "reject"
			case "discard":
				term.Action = "discard"
			case "log":
				term.Log = true
			case "syslog":
				term.Log = true
			}
		}
		return
	}

	for _, child := range node.Children {
		switch child.Name() {
		case "accept":
			term.Action = "accept"
		case "reject":
			term.Action = "reject"
		case "discard":
			term.Action = "discard"
		case "log":
			term.Log = true
		case "syslog":
			term.Log = true
		case "routing-instance":
			if len(child.Keys) >= 2 {
				term.RoutingInstance = child.Keys[1]
			}
		case "count":
			if len(child.Keys) >= 2 {
				term.Count = child.Keys[1]
			}
		case "forwarding-class":
			if len(child.Keys) >= 2 {
				term.ForwardingClass = child.Keys[1]
			}
		case "loss-priority":
			if len(child.Keys) >= 2 {
				term.LossPriority = child.Keys[1]
			}
		case "dscp", "traffic-class":
			term.DSCPRewrite = nodeVal(child)
		case "policer":
			if len(child.Keys) >= 2 {
				term.Policer = child.Keys[1]
			}
		}
	}
}
