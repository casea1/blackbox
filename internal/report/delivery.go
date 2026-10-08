package report

import (
	"fmt"
	"strings"
	"time"
)

// Delivery is how a computer's data reached this collector (DESIGN1):
// signed with its own key, pinned at its first signed delivery, or
// unsigned (a sender before 0.24). Nil for the collector itself and in
// reports that are not a collector's.
//
// Shown as: Systems, each system's page ("Delivery: signed · key
// SHA256:ab12… since 8 Oct"); Overview, Needs attention (new, changed,
// held and unsigned senders); the Verified pop-up ("All deliveries were
// signed by their computer's key").
type Delivery struct {
	Signed bool
	KeyFP  string    // the pinned key's fingerprint
	Since  time.Time // pinned (first seen, approved or rekeyed)
	// New: first seen in this report's period.
	New bool
	// Held: a new computer waiting for "blackbox senders approve".
	Held bool
	// NewKeyFP: a different key it now signs with, waiting for
	// "blackbox senders rekey" (its deliveries are not imported).
	NewKeyFP string
	// SharedWith: another computer signs with the same key (a copy).
	SharedWith string
}

// Text is the system page's line: "signed · key SHA256:ab12… since 8 Oct".
func (d *Delivery) Text(loc *time.Location) string {
	if d == nil {
		return ""
	}
	if !d.Signed {
		return "unsigned (Blackbox before 0.24: upgrade it)"
	}
	s := "signed · key " + shortFP(d.KeyFP) + " since " + d.Since.In(loc).Format("2 Jan")
	switch {
	case d.Held:
		s += " · waiting for approval (blackbox senders approve)"
	case d.NewKeyFP != "":
		s += " · now signing with another key, " + shortFP(d.NewKeyFP) + ", not imported until: blackbox senders rekey"
	}
	if d.SharedWith != "" {
		s += " · the same key as " + d.SharedWith
	}
	return s
}

func shortFP(fp string) string {
	if len(fp) <= 15 {
		return fp
	}
	return fp[:15] + "…"
}

// deliveryCheckLines are the Needs attention lines about senders' keys
// on a collector's report, or the line saying all is well.
func (r *Report) deliveryCheckLines() []CheckLine {
	if !r.Collector {
		return nil
	}
	var decide, newOnes, unsigned, shared []string
	signed := 0
	for _, s := range r.Systems {
		d := s.Delivery
		if d == nil || !s.Removed.IsZero() {
			continue
		}
		switch {
		case !d.Signed:
			unsigned = append(unsigned, s.Name)
			continue
		case d.Held:
			decide = append(decide, s.Name+" (new: blackbox senders approve "+s.Name+")")
		case d.NewKeyFP != "":
			decide = append(decide, s.Name+" (another key: blackbox senders rekey "+s.Name+" if it was reinstalled)")
		case d.New:
			newOnes = append(newOnes, s.Name+" ("+shortFP(d.KeyFP)+")")
		}
		if d.SharedWith != "" {
			shared = append(shared, s.Name+" and "+d.SharedWith)
		}
		signed++
	}
	var lines []CheckLine
	if len(decide) > 0 {
		lines = append(lines, CheckLine{Level: "bad", Icon: "fingerprint", Title: "Senders waiting for a decision",
			What: strings.Join(decide, "; ") + ". Their deliveries are not in this report", Href: "#systems"})
	}
	if len(shared) > 0 {
		lines = append(lines, CheckLine{Level: "bad", Icon: "fingerprint", Title: "Two computers, one key",
			What: strings.Join(shared, "; ") + ": one was copied from the other. On the copy, run blackbox send --new-id", Href: "#systems"})
	}
	if len(newOnes) > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "fingerprint", Title: "New senders",
			What: strings.Join(newOnes, ", ") + ": compare each key with blackbox status on that computer", Href: "#systems"})
	}
	if len(unsigned) > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "fingerprint", Title: "Unsigned senders", Who: strings.Join(unsigned, ", "),
			What: "deliver unsigned (Blackbox before 0.24): upgrade these to 0.24", Href: "#systems"})
	}
	if len(lines) == 0 && signed > 0 {
		lines = append(lines, CheckLine{Level: "ok", Icon: "fingerprint", Title: "Deliveries signed", What: fmt.Sprintf("%s signed by its own key", plural(signed, "computer")), Count: ""})
	}
	return lines
}

// deliveryVerifyLine is the Verified pop-up's line about senders' keys,
// on a collector's report.
func (r *Report) deliveryVerifyLine() (VerifyLine, bool) {
	if !r.Collector {
		return VerifyLine{}, false
	}
	var unsigned []string
	any := false
	for _, s := range r.Systems {
		if s.Delivery == nil || !s.Removed.IsZero() {
			continue
		}
		any = true
		if !s.Delivery.Signed {
			unsigned = append(unsigned, s.Name)
		}
	}
	switch {
	case !any:
		return VerifyLine{}, false
	case len(unsigned) == 0:
		return VerifyLine{Text: "All deliveries were signed by their computer's key", File: "each computer's key, pinned at its first delivery (blackbox senders)", State: "ok"}, true
	}
	return VerifyLine{Text: "Not every delivery was signed", File: fmt.Sprintf("not signed: %s (Blackbox before 0.24); every other delivery was signed by its computer's key", strings.Join(unsigned, ", ")), State: "na"}, true
}
