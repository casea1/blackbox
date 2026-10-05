//go:build !windows && !linux

package share

import "github.com/casea1/blackbox/internal/config"

// Destination returns the folder batches are delivered to.
func Destination(cfg *config.Config) (string, error) { return cfg.SendTo, nil }

// SMBAllowedIn is only checked on a Windows collector.
func SMBAllowedIn() (bool, error) { return true, nil }

// SSHAllowedIn is only checked on a Windows collector.
func SSHAllowedIn() (installed, open bool, err error) { return false, false, nil }
