package config

// validateAddressSetGraphDepthAndCycles12832 walks every path that contributes
// nested-set edges to literal expansion. Address-set members always traverse;
// address members traverse only when no address shadows a same-named set.
func validateAddressSetGraphDepthAndCycles12832(name string, ab *AddressBook) error {
	return validateAddressSetGraphNode12832(name, ab, make(map[string]bool), 0)
}

func validateAddressSetGraphNode12832(
	name string,
	ab *AddressBook,
	visited map[string]bool,
	depth int,
) error {
	set, err := addressSetForExpansion(name, ab, visited, depth)
	if err != nil {
		return err
	}
	visited[name] = true
	defer delete(visited, name)

	for _, member := range set.Addresses {
		if _, isAddress := ab.Addresses[member]; isAddress {
			continue
		}
		if _, isSet := ab.AddressSets[member]; !isSet {
			continue // the definedness pass reports dangling names
		}
		if err := validateAddressSetGraphNode12832(member, ab, visited, depth+1); err != nil {
			return err
		}
	}
	for _, nested := range set.AddressSets {
		if err := validateAddressSetGraphNode12832(nested, ab, visited, depth+1); err != nil {
			return err
		}
	}
	return nil
}
