//go:build !linux

package report

// Share is Linux only: on Windows the reports folder's own permissions
// decide who reads it.
func Share(dir, group string) error { return nil }

// Unreachable is Linux only.
func Unreachable(dir, group string) string { return "" }
