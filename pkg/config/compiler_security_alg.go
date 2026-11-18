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
	owned, err := validateALGTokens19190(proto, tail, schema)
	if err != nil || owned {
		return err // owned: the rest is an accepted-but-inert statement's body.
	}
	for _, child := range children {
		if isApplyStatementKeyword(child.Name()) {
			continue
		}
		statement := schema.children[child.Name()]
		if statement == nil {
			return fmt.Errorf("unknown configuration keyword %q under ALG %q", child.Name(), proto)
		}
		// #19190: a flag's or valued statement's own line (the flat-set
		// shape nests the rest of the line under it) is validated like a
		// packed tail: after its arity, tokens are class-level again.
		if statement.closedWorldOpaque && algInertArity19190(child.Name()) >= 0 {
			if _, err := validateALGTokens19190(proto, flattenALGNode19190(child), schema); err != nil {
				return err
			}
		}
		if child.Name() == "disable" && (len(child.Keys) != 1 || len(child.Children) != 0) {
			return fmt.Errorf("ALG %q disable does not take arguments or children", proto)
		}
	}
	return nil
}

// algInertArity19190 is an inert statement's value arity: 0 for a bodiless
// flag, 1 for a valued statement, -1 for one that owns the rest of its line
// and body (a container, or a statement whose arity is not recorded).
func algInertArity19190(statement string) int {
	switch {
	case algInertFlags19190[statement]:
		return 0
	case algInertValued19190[statement]:
		return 1
	}
	return -1
}

// algScanTokens19190 walks one ALG class line. It reports whether a
// class-level `disable` occurs, and whether an inert statement OWNS the rest
// (then any later tokens and children are that statement's body). A flag owns
// no following token and a valued statement owns exactly its value, so a
// `disable` after either is the class's (#19190). Unknown tokens keep the old
// tolerant-load scan; strict admission rejects them before compilation.
func algScanTokens19190(tokens []string, schema *schemaNode) (disable, owned bool) {
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token == "disable" {
			return true, false
		}
		statement := schema.children[token]
		if statement == nil || !statement.closedWorldOpaque {
			continue
		}
		arity := algInertArity19190(token)
		if arity < 0 {
			return false, true
		}
		i += algValueTokens19190(tokens, i, arity)
	}
	return false, false
}

// algValueTokens19190 is how many tokens after tokens[i] its statement owns:
// its arity, except that a literal `disable` is never a value. No Junos
// valued ALG statement takes `disable` as its value, so `doctoring disable`
// is a doctoring with its value omitted followed by the class's disable.
func algValueTokens19190(tokens []string, i, arity int) int {
	n := 0
	for n < arity && i+1+n < len(tokens) && tokens[i+1+n] != "disable" {
		n++
	}
	return n
}

// validateALGTokens19190 is algScanTokens19190 for strict admission: after a
// flag, or a valued statement's value, a token must be class-level again.
func validateALGTokens19190(proto string, tokens []string, schema *schemaNode) (owned bool, err error) {
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token == "disable" {
			continue
		}
		if statement := schema.children[token]; statement != nil && statement.closedWorldOpaque {
			arity := algInertArity19190(token)
			if arity < 0 {
				return true, nil
			}
			i += algValueTokens19190(tokens, i, arity)
			continue
		}
		if isApplyStatementKeyword(token) {
			return true, nil
		}
		return false, fmt.Errorf("unknown configuration keyword %q under ALG %q", token, proto)
	}
	return false, nil
}

// flattenALGNode19190 is a node's own tokens followed by its descendants',
// depth first: the flat-set shape of one packed line nests each remaining
// token under the previous statement.
func flattenALGNode19190(n *Node) []string {
	tokens := append([]string(nil), n.Keys...)
	for _, child := range n.Children {
		tokens = append(tokens, flattenALGNode19190(child)...)
	}
	return tokens
}

// algPackedDisable reads class-level disable flags: from the packed tail,
// from a `disable` child, and from the rest of a flag's or valued
// statement's line (#19190). An inert statement that owns the rest of its
// line (a container) also owns its children, as #16814 designed.
func algPackedDisable(tail []string, children []*Node, schema *schemaNode) bool {
	disable, owned := algScanTokens19190(tail, schema)
	if disable || owned {
		return disable
	}
	for _, child := range children {
		if child.Name() == "disable" {
			return true
		}
		statement := schema.children[child.Name()]
		if statement == nil || !statement.closedWorldOpaque || algInertArity19190(child.Name()) < 0 {
			continue
		}
		if d, _ := algScanTokens19190(flattenALGNode19190(child), schema); d {
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
	packedStatement := false
	for _, token := range tail {
		if token == "disable" {
			continue
		}
		packedStatement = true
		record(token)
	}
	if packedStatement {
		return // Children belong to the packed statement, not the class.
	}
	for _, child := range children {
		record(child.Name())
		// #19190: the flat-set shape nests the rest of a packed line under
		// the first statement. After a flag or a valued statement's value
		// the line is class-level again, so later inert statements on it
		// are the class's too (until a container claims the rest).
		if statement := schema.children[child.Name()]; statement != nil && statement.closedWorldOpaque && algInertArity19190(child.Name()) >= 0 {
			line := flattenALGNode19190(child)
			for i := 1 + algValueTokens19190(line, 0, algInertArity19190(child.Name())); i < len(line); i++ {
				token := line[i]
				st := schema.children[token]
				if st == nil || !st.closedWorldOpaque {
					continue
				}
				record(token)
				arity := algInertArity19190(token)
				if arity < 0 {
					break
				}
				i += algValueTokens19190(line, i, arity)
			}
		}
	}
}
