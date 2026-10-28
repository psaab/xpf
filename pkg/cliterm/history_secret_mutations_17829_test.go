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
		{"rename community source under edit snmp", []string{"snmp"}, "rename community S3cretOld17829 to community S3cretNew17829"},
		{"rename community destination under edit snmp", []string{"snmp"}, "rename community old17829 to community S3cretDst17829"},
		{"rename bare community destination under edit snmp", []string{"snmp"}, "rename community old17829 to S3cretBareDst17829"},
		{"copy community source under edit snmp", []string{"snmp"}, "copy community S3cretCopySrc17829 to community copy17829"},
		{"copy community destination under edit snmp", []string{"snmp"}, "copy community copy17829 to community S3cretCopyDst17829"},
		{"insert community under edit snmp", []string{"snmp"}, "insert community S3cretInsert17829 before community other17829"},
		{"annotate community under edit snmp", []string{"snmp"}, `annotate community S3cretAnnotate17829 "note"`},
		{"top delete community from system cursor", []string{"system"}, "top delete snmp community S3cretTopDelete17829"},
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
		{"positional community", []string{"snmp"}, "rename version community"},
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
