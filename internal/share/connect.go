package share

import (
	"fmt"
	"strings"
)

// Windows error codes from the mpr (network connection) calls.
const (
	errorAlreadyAssigned           = 85
	errorSessionCredentialConflict = 1219
)

// mprCalls are the Windows network-connection calls Connect makes (a fake
// in tests).
type mprCalls struct {
	add    func(root, user, password string) uintptr // WNetAddConnection2
	cancel func(name string) uintptr                 // WNetCancelConnection2, not forced
	text   func(code uintptr) string
}

// connectWith signs in to the share at path as user. Windows allows one
// account per server for a logon session: when this one (SYSTEM, for the
// scheduled runs) is already connected to the server as another account,
// a new connection fails with 1219, and the old one goes on being used,
// even after that account is deleted (SEND2). So on 1219 the existing
// connections to the server (the share and IPC$) are closed, unless files
// are open on them, and it connects again as user.
func connectWith(m mprCalls, path, user, password string) error {
	root, _ := Root(path)
	r := m.add(root, user, password)
	if r == 0 || r == errorAlreadyAssigned {
		return nil
	}
	if r == errorSessionCredentialConflict {
		server := serverOf(root)
		m.cancel(root)
		m.cancel(server + `\IPC$`)
		r = m.add(root, user, password)
		if r == 0 || r == errorAlreadyAssigned {
			return nil
		}
		if r == errorSessionCredentialConflict {
			return fmt.Errorf("already connected to %s as another account, and that connection is in use, so it can't connect as %s. "+
				"Close what has files open on %s, or as an administrator run: net use %s /delete (for the scheduled sends, as SYSTEM), then send again", server, user, server, root)
		}
	}
	return fmt.Errorf("connect to %s as %s: %s", root, user, m.text(r))
}

// serverOf is \\SERVER from \\SERVER\share.
func serverOf(root string) string {
	parts := strings.FieldsFunc(root, func(r rune) bool { return r == '\\' || r == '/' })
	if len(parts) == 0 {
		return root
	}
	return `\\` + parts[0]
}
