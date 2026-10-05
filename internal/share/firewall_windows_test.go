//go:build windows

package share

import (
	"fmt"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/hidden"
)

// N2b: the live query lists the rules for TCP 445 in the form PortOpen
// reads (Windows has the File and Printer Sharing rules, on or off).
func TestPortInQueryLive(t *testing.T) {
	out, err := hidden.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(portInQuery, SMBPort)).Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rules for TCP 445:\n%s", out)
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if len(strings.Split(strings.TrimSpace(l), "\t")) == 4 {
			n++
		}
	}
	if n == 0 {
		t.Errorf("no rule listed in the expected form:\n%s", out)
	}
}
