package install

import (
	"runtime"
	"slices"
	"strings"
)

// NewOption is a setup question added after installs were made (UPG1):
// an upgrade from a version that did not ask it does not offer "upgrade
// now, keep current settings", so it is answered, not skipped.
type NewOption struct {
	ID, What string
	For      func(Answers) bool // whether this install is asked it
}

// NewOptions are the setup questions an older install may not have been
// asked. Add one here with every new setup question.
var NewOptions = []NewOption{
	{"network", "whether this computer is on a network",
		func(a Answers) bool { return a.Role == RoleStandalone }},
	{"tray_groups", "who sees the status icon",
		func(a Answers) bool { return runtime.GOOS == "windows" && a.Role != RoleSender }},
	{"report_group", "who can open the reports",
		func(a Answers) bool { return runtime.GOOS == "linux" && a.Role != RoleSender }},
}

// Unasked are the new questions this install has not answered.
func Unasked(a Answers) []NewOption {
	var out []NewOption
	for _, o := range NewOptions {
		if o.For(a) && !slices.Contains(a.Asked, o.ID) {
			out = append(out, o)
		}
	}
	return out
}

// UnaskedText lists them for a sentence: "who sees the status icon and ...".
func UnaskedText(list []NewOption) string {
	var w []string
	for _, o := range list {
		w = append(w, o.What)
	}
	if len(w) > 1 {
		return strings.Join(w[:len(w)-1], ", ") + " and " + w[len(w)-1]
	}
	return strings.Join(w, "")
}

// AllAsked are the IDs recorded once setup has been through its
// questions.
func AllAsked() string {
	var ids []string
	for _, o := range NewOptions {
		ids = append(ids, o.ID)
	}
	return strings.Join(ids, ", ")
}
