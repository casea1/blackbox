//go:build !windows && !linux

package inventory

// Collect is not supported on this system.
func Collect() *Inventory { return nil }
