package config

import "fmt"

// validateALGPackedTokens validates modeled class statement heads, not inert
// bodies. A packed inert head owns the remaining tokens AND children; they
// must not be interpreted as class-level statements (especially `disable`).
// parent is supplied by the schema walker, avoiding an initialization cycle.
func validateALGPackedTokens(node *Node, parent *schemaNode) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	schema := parent.children[node.Name()]
	if len(node.Keys) > 1 {
		proto := node.Keys[1]
		if ps := schema.children[proto]; ps != nil {
			return validateALGBody16814(proto, node.Keys[2:], node.Children, ps)
		}
		return nil // Unmodeled classes retain their opaque admission policy.
	}
	for _, child := range node.Children {
		if ps := schema.children[child.Name()]; ps != nil {
			if err := validateALGBody16814(child.Name(), child.Keys[1:], child.Children, ps); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateALGBody16814(proto string, tail []string, children []*Node, schema *schemaNode) error {
	for _, token := range tail {
		if token == "disable" {
			continue
		}
		if statement := schema.children[token]; statement != nil && statement.closedWorldOpaque {
			return nil // The rest is this accepted-but-inert statement's body.
		}
		if isApplyStatementKeyword(token) {
			return nil
		}
		return fmt.Errorf("unknown configuration keyword %q under ALG %q", token, proto)
	}
	for _, child := range children {
		if isApplyStatementKeyword(child.Name()) {
			continue
		}
		statement := schema.children[child.Name()]
		if statement == nil {
			return fmt.Errorf("unknown configuration keyword %q under ALG %q", child.Name(), proto)
		}
		if child.Name() == "disable" && (len(child.Keys) != 1 || len(child.Children) != 0) {
			return fmt.Errorf("ALG %q disable does not take arguments or children", proto)
		}
	}
	return nil
}

// algPackedDisable reads class-level disable flags. A recognized inert
// statement owns the remaining body, including any value named disable.
// Unknown tokens retain the old tolerant-load scan; strict admission rejects
// them before compilation.
func algPackedDisable(tail []string, children []*Node, schema *schemaNode) bool {
	for _, token := range tail {
		if token == "disable" {
			return true
		}
		if statement := schema.children[token]; statement != nil && statement.closedWorldOpaque {
			return false
		}
	}
	for _, child := range children {
		if child.Name() == "disable" {
			return true
		}
	}
	return false
}

func compileALG(node *Node, sec *SecurityConfig) error {
	if len(node.Keys) > 1 {
		compileALGProto16814(node.Keys[1], node.Keys[2:], node.Children, &sec.ALG)
		return nil
	}
	for _, child := range node.Children {
		compileALGProto16814(child.Name(), child.Keys[1:], child.Children, &sec.ALG)
	}
	return nil
}

func compileALGProto16814(proto string, tail []string, children []*Node, alg *ALGConfig) {
	var control *bool
	switch proto {
	case "dns":
		control = &alg.DNSDisable
	case "ftp":
		control = &alg.FTPDisable
	case "sip":
		control = &alg.SIPDisable
	case "tftp":
		control = &alg.TFTPDisable
	case "pptp":
		control = &alg.PPTPDisable
	default:
		alg.UnsupportedProtos = append(alg.UnsupportedProtos, proto)
		return
	}
	schema := schemaForPath("security", "alg", proto)
	*control = *control || algPackedDisable(tail, children, schema)
	record := func(keyword string) {
		if statement := schema.children[keyword]; statement != nil && statement.closedWorldOpaque {
			alg.InertSubstatements = append(alg.InertSubstatements, proto+" "+keyword)
		}
	}
	for _, token := range tail {
		if token != "disable" {
			record(token)
			return // Children belong to this packed statement, not the class.
		}
	}
	for _, child := range children {
		record(child.Name())
	}
}
