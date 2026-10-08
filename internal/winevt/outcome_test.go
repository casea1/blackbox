package winevt

import "testing"

// AU3: every Security event gets its outcome from its Audit Success or
// Audit Failure keyword; other logs record none.
func TestOutcomeFromKeywords(t *testing.T) {
	tr := NewTranslator()
	created := sec(4720, map[string]string{"TargetUserName": "tempuser", "TargetDomainName": "WS-07", "TargetSid": "S-1-5-21-1-2-3-1009",
		"SubjectUserName": "admin_jd", "SubjectDomainName": "WS-07", "SubjectUserSid": "S-1-5-21-1-2-3-1001"})
	created.Keywords = "0x8020000000000000"
	if e := tr.Translate(created); e == nil || e.Outcome != "success" {
		t.Errorf("4720 audit success: %+v", e)
	}
	failed := sec(4625, map[string]string{"TargetUserName": "jsmith", "TargetDomainName": "WS-07", "LogonType": "3",
		"IpAddress": "10.1.1.99", "Status": "0xc000006d", "SubStatus": "0xc000006a"})
	failed.Keywords = "0x8010000000000000"
	if e := tr.Translate(failed); e == nil || e.Outcome != "failure" {
		t.Errorf("4625 audit failure: %+v", e)
	}
	if r := (&Raw{Channel: "System", Keywords: "0x8020000000000000"}); r.Outcome() != "" {
		t.Errorf("a System event has no audit outcome: %q", r.Outcome())
	}
	if r := (&Raw{Channel: "Security"}); r.Outcome() != "" {
		t.Errorf("no keywords: %q", r.Outcome())
	}
}
