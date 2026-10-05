//go:build linux

package inventory

import (
	"os/exec"
	"strings"
)

// Collect reads this computer's inventory.
func Collect() *Inventory {
	return Linux("/", udevSerial)
}

// udevSerial asks udev for a drive's serial number (SATA disks often have
// none in sysfs).
func udevSerial(dev string) string {
	out, err := exec.Command("udevadm", "info", "--query=property", "--name=/dev/"+dev).Output()
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, "ID_SERIAL_SHORT="); ok {
			return v
		}
	}
	return ""
}
