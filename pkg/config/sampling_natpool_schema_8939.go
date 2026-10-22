package config

// natSourcePoolSchema8939 resolves `security nat source pool <name>`.
func natSourcePoolSchema8939() *schemaNode {
	return refNATSourcePoolInstance.resolve()
}

// samplingOutputSchema8939 resolves
// `forwarding-options sampling instance <i> family inet output`. The inet and
// inet6 bodies are the same shape, so one resolution serves both readers.
func samplingOutputSchema8939() *schemaNode {
	return refSamplingOutput.resolve()
}
