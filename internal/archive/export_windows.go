package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/hidden"
	"github.com/casea1/blackbox/internal/winevt"
)

// export saves each event log Blackbox reads, for [from, to), as an .evtx
// file with wevtutil (the export Event Viewer's "Save events as" uses).
func export(tmp string, from, to time.Time) ([]Source, []string) {
	const ts = "2006-01-02T15:04:05.000Z"
	query := fmt.Sprintf("/q:*[System[TimeCreated[@SystemTime>='%s' and @SystemTime<'%s']]]",
		from.UTC().Format(ts), to.UTC().Format(ts))
	var sources []Source
	var notes []string
	for _, ch := range winevt.Channels {
		name := SafeName(ch) + ".evtx"
		path := filepath.Join(tmp, name)
		out, err := hidden.Command(wevtutil(), "epl", ch, path, query, "/ow:true").CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(strings.ToLower(msg), "could not be found") {
				notes = append(notes, ch+": not on this computer")
			} else {
				notes = append(notes, fmt.Sprintf("%s: could not be exported: %v %s", ch, err, msg))
			}
			continue
		}
		sources = append(sources, Source{Name: name, Source: ch, Path: path})
	}
	return sources, notes
}

func wevtutil() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Join(root, "System32", "wevtutil.exe")
	}
	return "wevtutil.exe"
}

// LogStates reads, for each log Blackbox saves, how far back it reaches and
// whether it is full and overwriting (not set to keep events or to archive
// itself when full).
func LogStates() []LogState {
	var out []LogState
	for _, ch := range winevt.Channels {
		s, err := winevt.GetLogSettings(ch)
		if err != nil || !s.Enabled {
			continue
		}
		h, err := winevt.GetLogHistory(ch)
		if err != nil || h.Oldest.IsZero() {
			continue
		}
		wraps := !s.Retention && s.MaxSize > 0 && float64(h.FileSize) >= 0.9*float64(s.MaxSize)
		out = append(out, LogState{Source: ch, Oldest: h.Oldest, Wraps: wraps})
	}
	return out
}
