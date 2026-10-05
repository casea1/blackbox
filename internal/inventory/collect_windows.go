//go:build windows

package inventory

import (
	"strings"

	"github.com/casea1/blackbox/internal/hidden"
)

// Collect reads this computer's inventory.
func Collect() *Inventory {
	out, err := hidden.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WindowsQuery).Output()
	if err != nil {
		return &Inventory{Notes: []string{"the inventory could not be read: " + err.Error()}}
	}
	inv, err := ParseWindows(out)
	if err != nil {
		return &Inventory{Notes: []string{strings.TrimSpace(err.Error())}}
	}
	return inv
}
