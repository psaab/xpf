package config

// policyStatementThenFromSplit12674 locates a `from` clause following the
// policy-level default `then` action. That path has no term container, so the
// SetPath schema walk otherwise nests `from` under accept/reject and the
// compiler never observes it.
func policyStatementThenFromSplit12674(path []string, grouped []bool) (thenAt, fromAt int) {
	thenSchema := policyStatementThenSchema8939()
	schema := setSchema
	thenAt = -1
	for i := 0; i < len(path); {
		child := schemaChildFor(schema, path[i])
		if child == nil {
			return -1, -1
		}
		if child == thenSchema {
			thenAt = i
			break
		}
		i = widenKeyCountToGroupEnd(grouped, i, i+1+child.args)
		schema = child
	}
	if thenAt < 0 {
		return -1, -1
	}
	for i := thenAt + 1; i < len(path); i++ {
		if path[i] == "from" {
			return thenAt, i
		}
	}
	return thenAt, -1
}

// setPolicyStatementThenFrom12674 replays a policy-level then-first line as a
// `from` clause on the policy-statement followed by its default action.
func (t *ConfigTree) setPolicyStatementThenFrom12674(path []string, quoted, grouped []bool, thenAt, fromAt int, closed ...bool) error {
	fromPath := append(append([]string(nil), path[:thenAt]...), path[fromAt:]...)
	var fromQuoted, fromGrouped []bool
	if quoted != nil {
		fromQuoted = append(append([]bool(nil), quoted[:thenAt]...), quoted[fromAt:]...)
	}
	if grouped != nil {
		fromGrouped = append(append([]bool(nil), grouped[:thenAt]...), grouped[fromAt:]...)
	}
	if err := t.SetPathQuotedGrouped(fromPath, fromQuoted, fromGrouped, closed...); err != nil {
		return err
	}
	return t.SetPathQuotedGrouped(path[:fromAt], headSpan12516(quoted, fromAt), headSpan12516(grouped, fromAt), closed...)
}
