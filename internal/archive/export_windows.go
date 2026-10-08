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
// Logs skip says have nothing new are left out.
func export(tmp string, from, to time.Time, skip func(string) bool) ([]Source, []string) {
	const ts = "2006-01-02T15:04:05.000Z"
	query := fmt.Sprintf("/q:*[System[TimeCreated[@SystemTime>='%s' and @SystemTime<'%s']]]",
		from.UTC().Format(ts), to.UTC().Format(ts))
	var sources []Source
	var notes []string
	for _, ch := range winevt.Channels {
		if skip != nil && skip(ch) {
			continue
		}
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
		sources = append(sources, localeMeta(tmp, path, ch)...)
	}
	return sources, notes
}

// localeMeta adds the message text of an exported log (wevtutil al), so
// its events read the same on a computer without the programs that wrote
// them (ASSESS1). Event Viewer finds it in LocaleMetaData next to the
// .evtx. Without it the log is still complete, so a failure is not an
// error.
func localeMeta(dir, evtx, ch string) []Source {
	if err := hidden.Command(wevtutil(), "al", evtx).Run(); err != nil {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(dir, MetaDir, strings.TrimSuffix(filepath.Base(evtx), ".evtx")+"_*.MTA"))
	var out []Source
	for _, m := range matches {
		out = append(out, Source{Name: MetaDir + "/" + filepath.Base(m), Source: ch, Path: m})
	}
	return out
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
