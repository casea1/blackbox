//go:build !windows

package lan

import (
	"errors"
	"os"
	"syscall"
)

// openFlags open an inbox file without following a link or waiting on a
// pipe.
const openFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func isLinkErr(err error) bool { return errors.Is(err, syscall.ELOOP) }
