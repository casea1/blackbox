package report

import (
	"strings"

	"github.com/casea1/blackbox/internal/check"
)

// NotApplicableStandalone is what a network-only check reads on a
// computer on its own (NET1).
const NotApplicableStandalone = "not applicable: a standalone computer, with no network time source"

// standaloneSets adjusts the checks for a computer on its own: time sync
// from the network is shown as not applicable (still listed, so an auditor
// sees why), and antivirus is updated from media, not a network share.
func standaloneSets(sets []CheckSet) []CheckSet {
	out := make([]CheckSet, 0, len(sets))
	for _, cs := range sets {
		rs := append([]check.Result(nil), cs.Results...)
		for i, r := range rs {
			switch {
			case r.Area == "Time" && (r.Status == check.Fail || r.Status == check.Warn):
				rs[i].Status, rs[i].Have, rs[i].Fix = check.Info, r.Have+" ("+NotApplicableStandalone+")", ""
			case r.Item == "Defender security intelligence" && r.Fix != "":
				fix, _, _ := strings.Cut(r.Fix, " Group Policy:")
				rs[i].Fix = strings.Replace(fix, "from your update source", "from your update media", 1)
			}
		}
		n := NewCheckSet(cs.Host, cs.Time, rs)
		n.Inventory = cs.Inventory
		if n.Baseline == "" {
			n.Baseline = cs.Baseline
		}
		out = append(out, n)
	}
	return out
}
