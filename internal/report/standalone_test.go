package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
)

// NET1: on a computer on its own, network time sync is not applicable
// (listed, not a gap), and antivirus is updated from media.
func TestStandaloneChecks(t *testing.T) {
	rs := []check.Result{
		{Area: "Time", Item: "Windows Time service", Status: check.Fail, Have: "running, not synchronising (Type NoSync)", Fix: "Group Policy: …"},
		{Area: "Antivirus", Item: "Defender security intelligence", Status: check.Fail, Have: "40 days old",
			Fix: "Import the latest security intelligence update (mpam-fe.exe) from your update source onto this system. Group Policy: … > Define file shares for downloading security intelligence updates"},
	}
	sets := standaloneSets([]CheckSet{NewCheckSet("WS-01", time.Now(), rs)})
	got := sets[0].Results
	if got[0].Status != check.Info || got[0].Fix != "" || !strings.Contains(got[0].Have, "not applicable: a standalone computer") {
		t.Errorf("time: %+v", got[0])
	}
	if strings.Contains(got[1].Fix, "Group Policy") || !strings.Contains(got[1].Fix, "update media") || got[1].Status != check.Fail {
		t.Errorf("defender: %+v", got[1])
	}
	if sets[0].Fail != 0 {
		t.Errorf("time sync still counted as a gap: %+v", sets[0])
	}
}
