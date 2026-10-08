package install

import (
	"errors"
	"testing"
)

// A local folder the person running setup can't write to (one open only
// to an auditors' group) is offered for SYSTEM access where that works
// (Windows); a share, or any system where it doesn't, is unusable.
func TestCheckFolderNoAccess(t *testing.T) {
	exists := func(string) (bool, error) { return true, nil }
	denied := func(string) error { return errors.New("Access is denied") }
	local := `C:\_AuditFiles`
	if !CanGrantSystem {
		local = "/srv/audit"
	}
	c, _ := CheckFolder(local, exists, denied)
	want := FolderBad
	if CanGrantSystem {
		want = FolderNoAccess
	}
	if c != want {
		t.Errorf("local folder: %v, want %v", c, want)
	}
	if c, _ := CheckFolder(`\\server\audit`, exists, denied); c != FolderBad {
		t.Errorf("share: %v, want FolderBad", c)
	}
	if c, _ := CheckFolder(local, exists, func(string) error { return nil }); c != FolderOK {
		t.Errorf("writable: %v", c)
	}
}
