package config

// archivalConfigurationSchema8939 resolves `system archival configuration`.
func archivalConfigurationSchema8939() *schemaNode {
	sys := resolveSchemaChild(setSchema, "system")
	if sys == nil {
		return nil
	}
	arch := resolveSchemaChild(sys, "archival")
	if arch == nil {
		return nil
	}
	return resolveSchemaChild(arch, "configuration")
}

// rpmProbeTestSchema8939 resolves `services rpm probe <p> test <t>`.
func rpmProbeTestSchema8939() *schemaNode {
	svc := resolveSchemaChild(setSchema, "services")
	if svc == nil {
		return nil
	}
	rpm := resolveSchemaChild(svc, "rpm")
	if rpm == nil {
		return nil
	}
	probe := resolveSchemaChild(rpm, "probe")
	if probe == nil {
		return nil
	}
	if probe.wildcard != nil {
		probe = probe.wildcard
	}
	tst := resolveSchemaChild(probe, "test")
	if tst == nil {
		return nil
	}
	if tst.wildcard != nil {
		return tst.wildcard
	}
	return tst
}

// rpmThresholdsSchema14615 resolves `services rpm probe <p> test <t>
// thresholds` so compileRPM can expand the one-line spelling
// `thresholds successive-loss N;` through the same schema the block
// spelling is validated against (#14615).
func rpmThresholdsSchema14615() *schemaNode {
	test := rpmProbeTestSchema8939()
	if test == nil {
		return nil
	}
	return resolveSchemaChild(test, "thresholds")
}
