package config

// compilePKI captures `security pki` (#15752, G18-01). xpf has no
// SCEP/CMPv2 enrollment, CSR generation or CRL refresh runtime, so the
// stanza is accepted-only: captured here so ValidateConfig can warn
// (compiler_validate_warn.go) instead of the gateway local-certificate
// rendering a certs = reference to an object no subsystem can define.
// Certificate/key files are operator-provisioned under the swanctl
// x509 directories; strongSwan resolves certs = by filename there.
func compilePKI(node *Node, sec *SecurityConfig) {
	if sec.PKI == nil {
		sec.PKI = &PKIConfig{CAProfiles: make(map[string]*PKICAProfile)}
	}
	if sec.PKI.CAProfiles == nil {
		sec.PKI.CAProfiles = make(map[string]*PKICAProfile)
	}
	for _, inst := range namedInstances(node.FindChildren("ca-profile")) {
		prof := sec.PKI.CAProfiles[inst.name]
		if prof == nil {
			prof = &PKICAProfile{Name: inst.name}
		}
		for _, c := range inst.node.Children {
			switch c.Name() {
			case "ca-identity":
				prof.CAIDentity = nodeVal(c)
			case "enrollment":
				for _, e := range c.Children {
					switch e.Name() {
					case "url":
						prof.EnrollmentURL = nodeVal(e)
					case "retry":
						prof.EnrollmentRetry = nodeVal(e)
					case "retry-interval":
						prof.EnrollmentRetryInterval = nodeVal(e)
					}
				}
				// Flat form: enrollment url <u> packs onto Keys.
				if len(c.Keys) >= 3 && c.Keys[1] == "url" {
					prof.EnrollmentURL = c.Keys[2]
				}
			case "revocation-check":
				for _, r := range c.Children {
					switch r.Name() {
					case "crl":
						prof.RevocationCheck = "crl"
						for _, cr := range r.Children {
							if cr.Name() == "url" {
								prof.CRLURL = nodeVal(cr)
							}
						}
						if len(r.Keys) >= 2 {
							// crl url <u> packed (handled below generically)
						}
					case "use-ocsp":
						prof.RevocationCheck = "use-ocsp"
					case "disable":
						prof.RevocationCheck = "disable"
					}
				}
				// Flat leaf form: revocation-check crl (leaf with child crl,
				// or Keys carrying the mode token).
				if len(c.Keys) >= 2 && prof.RevocationCheck == "" {
					switch c.Keys[1] {
					case "crl", "use-ocsp", "disable":
						prof.RevocationCheck = c.Keys[1]
					}
				}
				if v := nodeVal(c); prof.RevocationCheck == "" {
					switch v {
					case "crl", "use-ocsp", "disable":
						prof.RevocationCheck = v
					}
				}
			}
		}
		sec.PKI.CAProfiles[prof.Name] = prof
	}
}
