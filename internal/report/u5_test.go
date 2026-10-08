package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
)

// U5: OpenSSH 10 on Ubuntu 26.04 (testdata/v0.10.4, recorded live): three
// wrong passwords for the existing user bbuser, then one try each for the
// unknown names admin, oracle and postgres, and a key logon given up by
// claude. Each try is one row with the right name and reason.
func TestOpenSSH10FailedLogons(t *testing.T) {
	evs, _, err := collect.LinuxFiles([]string{"../../testdata/v0.10.4/u5-openssh10-audit-records.log"}, nil, "ubuntu-server", "", time.Unix(1791160000, 0))
	if err != nil {
		t.Fatal(err)
	}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: time.Unix(1791160000, 0)})
	got := map[string]int{}
	for _, e := range r.Events {
		if e.Action == "logon_failed" {
			got[e.User+" — "+e.Summary[strings.LastIndex(e.Summary, "— ")+len("— "):]]++
		}
	}
	want := map[string]int{
		"bbuser — wrong password or key.":          3,
		"admin — the user name does not exist.":    1,
		"oracle — the user name does not exist.":   1,
		"postgres — the user name does not exist.": 1,
		"claude — wrong password or key.":          1,
	}
	if len(got) != len(want) {
		t.Errorf("rows: %v", got)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%q: %d rows, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if !hasFinding(r, "One source tried several accounts") {
		t.Errorf("findings: %v", findingTitles(r))
	}
}

// U5: the same tries read from auth.log (no auditd) are one row each too,
// claude's given-up key logon included (LNX1).
func TestOpenSSH10FailedLogonsAuthLog(t *testing.T) {
	evs, _, err := collect.LinuxFiles(nil, []string{"../../testdata/v0.10.4/u5-openssh10-auth.log"}, "ubuntu-server", "", time.Unix(1791160000, 0))
	if err != nil {
		t.Fatal(err)
	}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: time.Unix(1791160000, 0)})
	var got []string
	for _, e := range r.Events {
		if e.Action == "logon_failed" {
			got = append(got, e.User)
		}
	}
	if strings.Join(got, ",") != "bbuser,bbuser,bbuser,admin,oracle,postgres,claude" {
		t.Errorf("rows for %v", got)
	}
}

// U15: a stop shorter than a minute is "less than a minute", not 0.
func TestRoughDurationUnderAMinute(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Second: "less than a minute", 70 * time.Second: "1 minute",
		12 * time.Minute: "12 minutes", 90 * time.Minute: "1 hour", 5 * time.Hour: "5 hours"} {
		if got := roughDuration(d); got != want {
			t.Errorf("roughDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
