package gui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/install"
)

// The window asks what the console asks, in the same order.
func TestPagesFor(t *testing.T) {
	for role, want := range map[string][]page{
		install.RoleStandalone: {pWelcome, pRole, pReports, pArchive, pCollect, pScap, pSummary, pInstall},
		install.RoleCollector:  {pWelcome, pRole, pReports, pArchive, pInbox, pCollect, pScap, pSummary, pInstall},
		install.RoleSender:     {pWelcome, pRole, pSendTo, pCollect, pScap, pSummary, pInstall},
	} {
		if got := pagesFor(role); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", role, got, want)
		}
	}
	if step(install.RoleSender, pRole, 1) != pSendTo || step(install.RoleCollector, pCollect, -1) != pInbox ||
		step(install.RoleStandalone, pWelcome, -1) != pWelcome {
		t.Error("step moves to the wrong page")
	}
}

// S2, S3, S4, S6: the window's wording.
func TestSetupWording(t *testing.T) {
	if w := welcomeText("0.10.0", "0.10.0"); strings.Contains(w, "upgrade") || !strings.Contains(w, "Apply") {
		t.Errorf("same version: %q", w)
	}
	if w := welcomeText("0.9.3", "0.10.0"); !strings.Contains(w, "upgrade it to 0.10.0") {
		t.Errorf("upgrade: %q", w)
	}
	if w := welcomeText("", "0.10.0"); !strings.Contains(w, "will be installed") {
		t.Errorf("first install: %q", w)
	}
	if applyVerb("") != "Install" || applyVerb("0.10.0") != "Apply" {
		t.Error("Install on a first install (even with old settings), Apply when installed")
	}
	if finishLabel(true) != "Close" || finishLabel(false) != "Finish" {
		t.Error("Close after a failure, Finish otherwise")
	}
	if !confirmCancel(pWelcome, false, false) || confirmCancel(pInstall, false, true) || confirmCancel(pSummary, true, false) {
		t.Error("Cancel asks on every page before installing, including Welcome")
	}
}

// Owner decision: the folder-access question is Yes or No only.
func TestFolderAccessQuestion(t *testing.T) {
	q := folderAccessQuestion(`C:\ProgramData\Blackbox\reports`, `DSK1\Austin`)
	if !strings.Contains(q, `Give DSK1\Austin read access`) || strings.Contains(q, "No:") || strings.Contains(q, "Cancel") {
		t.Errorf("question: %q", q)
	}
}

// One click to upgrade: offered on an upgrade from an earlier version,
// not on a first install or when the same version is installed.
func TestQuickUpgrade(t *testing.T) {
	if !quickUpgrade("0.16.1", "0.17.0") || quickUpgrade("", "0.17.0") || quickUpgrade("0.17.0", "0.17.0") {
		t.Error("quickUpgrade")
	}
	if w := welcomeText("0.16.1", "0.17.0"); !strings.Contains(w, "Upgrade now") || !strings.Contains(w, "0.16.1") {
		t.Errorf("welcome: %s", w)
	}
}
