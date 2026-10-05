// Package gui is Blackbox's setup window and status icon on Windows (see
// docs/redesign/SETUP-SPEC.md). Elsewhere it reports that it is Windows
// only. The decisions (which pages, which icon) are kept in plain Go,
// separate from the Windows calls, so they are tested on every platform.
package gui

import "github.com/casea1/blackbox/internal/install"

// page is one step of the setup window.
type page int

const (
	pWelcome page = iota
	pRole
	pReports
	pArchive
	pInbox
	pSendTo
	pCollect
	pSummary
	pInstall
)

// pagesFor lists the pages in order for a role: the same questions the
// console setup asks, in the same order.
func pagesFor(role string) []page {
	switch role {
	case install.RoleSender:
		return []page{pWelcome, pRole, pSendTo, pCollect, pSummary, pInstall}
	case install.RoleCollector:
		return []page{pWelcome, pRole, pReports, pArchive, pInbox, pCollect, pSummary, pInstall}
	}
	return []page{pWelcome, pRole, pReports, pArchive, pCollect, pSummary, pInstall}
}

// step moves from p by delta (+1 next, -1 back) in the role's order.
func step(role string, p page, delta int) page {
	list := pagesFor(role)
	for i, x := range list {
		if x == p {
			j := i + delta
			if j < 0 {
				j = 0
			}
			if j >= len(list) {
				j = len(list) - 1
			}
			return list[j]
		}
	}
	return list[0]
}

// welcomeText is the Welcome page: a first install, an upgrade, or (from
// Change settings… or Modify) the same version already installed.
func welcomeText(installed, version string) string {
	switch installed {
	case "":
		return "Blackbox " + version + " will be installed on this computer.\n\nIt collects security events from the Windows event logs on a schedule, keeps them before the logs roll over, and produces audit reports. It checks the audit settings against the DISA STIG and reports what needs fixing; it never changes them."
	case version:
		return "Blackbox " + version + " is installed. Change any settings on the next pages, then click Apply."
	}
	return "Blackbox " + installed + " is installed. This will upgrade it to " + version + ".\n\nYour current settings are kept and shown on the next pages; change any of them, or just click Next on each page."
}

// applyVerb is the Summary button: Apply when Blackbox is installed (the
// program, not just settings left by an earlier uninstall), else Install.
func applyVerb(installed string) string {
	if installed != "" {
		return "Apply"
	}
	return "Install"
}

// finishLabel is the last button: Close after a failure, Finish otherwise.
func finishLabel(failed bool) string {
	if failed {
		return "Close"
	}
	return "Finish"
}

// confirmCancel says whether closing the window must ask first: always
// before the install starts, on every page including Welcome.
func confirmCancel(p page, running, done bool) bool {
	return !running && !done && p != pInstall
}

// folderAccessQuestion asks before giving the person's account read access
// to the reports folder (Yes or No; No changes nothing).
func folderAccessQuestion(dir, account string) string {
	return "Your account can't open reports in " + dir + " without administrator rights.\n\n" +
		"Give " + account + " read access to this folder? (This is what Explorer's Continue button does.)"
}
