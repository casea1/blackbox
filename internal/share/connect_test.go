package share

import (
	"fmt"
	"strings"
	"testing"
)

type fakeMPR struct {
	adds     []uintptr // results of each add, in turn
	calls    int
	canceled []string
}

func (f *fakeMPR) mpr() mprCalls {
	return mprCalls{
		add: func(root, user, pw string) uintptr {
			r := f.adds[f.calls]
			f.calls++
			return r
		},
		cancel: func(name string) uintptr { f.canceled = append(f.canceled, name); return 0 },
		text:   func(c uintptr) string { return fmt.Sprintf("error %d", c) },
	}
}

// SEND2: a connection to the server under another account (1219) is closed,
// and it connects again as share_user.
func TestConnectReplacesStaleSession(t *testing.T) {
	f := &fakeMPR{adds: []uintptr{errorSessionCredentialConflict, 0}}
	if err := connectWith(f.mpr(), `\\COL\BlackboxInbox\sub`, `COL\bbsend`, "pw"); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 || strings.Join(f.canceled, ",") != `\\COL\BlackboxInbox,\\COL\IPC$` {
		t.Errorf("adds %d, canceled %v", f.calls, f.canceled)
	}
}

// SEND2: when the other connection can't be closed (files open), it says
// so, not "the user name or password is incorrect".
func TestConnectStillConflictingSaysAnotherAccount(t *testing.T) {
	f := &fakeMPR{adds: []uintptr{errorSessionCredentialConflict, errorSessionCredentialConflict}}
	err := connectWith(f.mpr(), `\\COL\BlackboxInbox`, `COL\bbsend`, "pw")
	if err == nil || !strings.Contains(err.Error(), `already connected to \\COL as another account`) {
		t.Errorf("err = %v", err)
	}
}

func TestConnectOtherErrorsAndSuccess(t *testing.T) {
	f := &fakeMPR{adds: []uintptr{1326}}
	if err := connectWith(f.mpr(), `\\COL\In`, "u", "p"); err == nil || !strings.Contains(err.Error(), "error 1326") || len(f.canceled) != 0 {
		t.Errorf("err = %v, canceled %v", err, f.canceled)
	}
	f = &fakeMPR{adds: []uintptr{errorAlreadyAssigned}}
	if err := connectWith(f.mpr(), `\\COL\In`, "u", "p"); err != nil {
		t.Error(err)
	}
}
