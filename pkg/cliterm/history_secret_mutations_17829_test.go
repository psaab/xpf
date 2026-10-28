package cliterm

// #17829: #16794 resolved edit context only for set/edit. The remote
// executor resolves delete/activate/deactivate/copy/rename/insert/annotate
// against the same cursor, so those spellings persisted cleartext values
// for context-gated secrets (e.g. SNMP community directly under snmp).
// These rows pin every config-mutation verb through the on-disk recorder.

import "testing"

func TestHistoryMutationEditContextSecretsNotPersisted17829(t *testing.T) {
	cases := []struct {
		name     string
		editPath []string
		line     string
	}{
		{"delete community under edit snmp", []string{"snmp"}, "delete community S3cretDelete17829"},
		{"deactivate community under edit snmp", []string{"snmp"}, "deactivate community S3cretDeactivate17829"},
		{"activate community under edit snmp", []string{"snmp"}, "activate community S3cretActivate17829"},
		{"rename destination-only community under edit snmp", []string{"snmp"}, "rename version 2 to community S3cretRenameOnly17829"},
		{"copy destination-only community under edit snmp", []string{"snmp"}, "copy version 2 to community S3cretCopyOnly17829"},
		{"rename community source under edit snmp", []string{"snmp"}, "rename community S3cretOld17829 to community S3cretNew17829"},
		{"rename community destination under edit snmp", []string{"snmp"}, "rename community old17829 to community S3cretDst17829"},
		{"rename bare community destination under edit snmp", []string{"snmp"}, "rename community old17829 to S3cretBareDst17829"},
		{"copy community source under edit snmp", []string{"snmp"}, "copy community S3cretCopySrc17829 to community copy17829"},
		{"copy community destination under edit snmp", []string{"snmp"}, "copy community copy17829 to community S3cretCopyDst17829"},
		{"insert community under edit snmp", []string{"snmp"}, "insert community S3cretInsert17829 before community other17829"},
		{"insert reference-only community under edit snmp", []string{"snmp"}, "insert version 2 before community S3cretInsertRef17829"},
		{"annotate community under edit snmp", []string{"snmp"}, `annotate community S3cretAnnotate17829 "note"`},
		{"top delete community from system cursor", []string{"system"}, "top delete snmp community S3cretTopDelete17829"},
		{"top rename quoted separator to SNMP destination", []string{"system"}, `top rename version "to" 2 to snmp community S3cretTopQuoted17829`},
		{"up rename quoted separator to SNMP destination", []string{"snmp", "community", "old17829"}, `up rename version "to" 2 to community S3cretUpQuoted17829`},
		{"up delete community to snmp cursor", []string{"snmp", "community", "old17829"}, "up delete community S3cretUpDelete17829"},
		{"flat delete community control", nil, "delete snmp community S3cretFlat17829"},
		{"absolute rename community control", nil, "rename snmp community old17829 to snmp community S3cretAbs17829"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsSensitiveHistoryLineAt(tc.editPath, tc.line) {
				t.Errorf("IsSensitiveHistoryLineAt(%v, %q) = false, want true (#17829)", tc.editPath, tc.line)
			}
			if persisted16794(t, tc.editPath, tc.line) {
				t.Errorf("line %q at cursor %v persisted to history file (#17829)", tc.line, tc.editPath)
			}
		})
	}
}

func TestHistoryMutationEditContextBenignRetained17829(t *testing.T) {
	cases := []struct {
		name     string
		editPath []string
		line     string
	}{
		{"delete description under edit snmp", []string{"snmp"}, "delete description uplink"},
		{"delete policy-options community", []string{"policy-options"}, "delete community CUST17829"},
		{"rename policy-options community", []string{"policy-options"}, "rename community OLD17829 to community NEW17829"},
		{"community identity outside direct snmp child", []string{"snmp"}, "rename version 2 to community"},
		{"community keyword without a value", []string{"snmp"}, "delete community"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsSensitiveHistoryLineAt(tc.editPath, tc.line) {
				t.Errorf("IsSensitiveHistoryLineAt(%v, %q) = true, want false (#17829)", tc.editPath, tc.line)
			}
			if !persisted16794(t, tc.editPath, tc.line) {
				t.Errorf("line %q at cursor %v did not persist, want retained (#17829)", tc.line, tc.editPath)
			}
		})
	}
}

// A leading unterminated quote makes ParseConfigMutationLine lex zero
// tokens, so ConfigMutationVerb cannot see the verb. The Fields fallback
// must still fail closed for every mutation verb: the gated secret in
// the unlexed tail must be suppressed live and at seed.
func TestHistoryUnlexableMutationLineSuppressed17829(t *testing.T) {
	line := `"delete community S3cretUnlexable17829`
	if !IsSensitiveHistoryLineAt([]string{"snmp"}, line) {
		t.Errorf("IsSensitiveHistoryLineAt(snmp, %q) = false, want true (#17829)", line)
	}
	if persisted16794(t, []string{"snmp"}, line) {
		t.Errorf("unlexable mutation line %q persisted via live recorder (#17829)", line)
	}
	seedPath := writeSeedFile17798(t, []string{"configure", "edit snmp", line})
	seed, err := ReadHistorySeed(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range seed {
		if got == line {
			t.Errorf("ReadHistorySeed retained unlexable mutation line %q: %q (#17829)", line, seed)
		}
	}
}
