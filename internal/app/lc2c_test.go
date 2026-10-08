package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/store"
)

// LC2c: a Windows log written to 1% of its size, cleared and collected.
// Windows truncates a cleared file, so the log does not wrap, and by
// record ID its numbers just start again: no gap was found, and the log
// was later reported as overwritten. A clear seen since the last export
// is a gap labelled as the clear whatever the log's size: status says
// "Log cleared:", and the archive's archive.json has the gap with who
// and when.
func TestClearedSmallLogIsAGap(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	st, _ := store.Open(filepath.Join(base, "data"))
	now := at(6, 0)
	// 1% full: never wraps, before or after the clear.
	states := []archive.LogState{{Source: "Security", Oldest: at(5, 0)}}
	var notes []string
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return states },
		Logf: func(f string, args ...any) { notes = append(notes, f) }}
	// As the export by record ID: the file, and after the clear the note
	// that record numbers started again, but no gap.
	var exportNotes []string
	a.Export = func(dir string, from, to time.Time, skip func(string) bool) ([]archive.Source, []string, []archive.Gap) {
		p := filepath.Join(dir, "Security.evtx")
		os.WriteFile(p, []byte("evtx "+to.Format("1504")), 0o644)
		return []archive.Source{{Name: "Security.evtx", Source: "Security", Path: p}}, exportNotes, nil
	}
	run := func(read int, first time.Time) *store.Run {
		return &store.Run{Time: now, Host: collect.LocalHost(), Channels: []store.ChannelRun{{Channel: "Security", Read: read, FirstTime: first}}}
	}
	a.saveLogPiece(st, run(10, at(5, 0)), time.Time{})

	// 06:10 cleared by claude (the 1102 is record 1 of the new log);
	// collected at 06:15.
	prev := now
	now = at(6, 15)
	states = []archive.LogState{{Source: "Security", Oldest: at(6, 10)}}
	exportNotes = []string{"Security: record numbers started again (the log was cleared or recreated); this part has all of it"}
	r := run(1, at(6, 10))
	r.Channels[0].Reset = true
	r.Channels[0].Cleared, r.Channels[0].ClearedAt, r.Channels[0].ClearedBy = true, at(6, 10), "claude"
	st.AppendRun(r)
	a.saveLogPiece(st, r, prev)
	if len(st.State.LogGaps) != 1 || st.State.LogGaps[0].Cleared == nil || st.State.LogGaps[0].Cleared.By != "claude" ||
		!st.State.LogGaps[0].From.Equal(at(6, 0)) || !st.State.LogGaps[0].To.Equal(at(6, 10)) {
		t.Fatalf("no cleared gap: %+v", st.State.LogGaps)
	}
	for _, n := range notes {
		if strings.Contains(n, "overwritten") || strings.Contains(n, "INCOMPLETE") {
			t.Errorf("logged as overwritten: %q", n)
		}
	}
	// The next export: nothing more about the clear.
	prev, now = now, at(6, 30)
	exportNotes = nil
	a.saveLogPiece(st, run(2, at(6, 20)), prev)
	if len(st.State.LogGaps) != 1 {
		t.Errorf("the clear noted twice: %+v", st.State.LogGaps)
	}
	st.Save()

	var b bytes.Buffer
	if err := a.Status(&b); err != nil || !strings.Contains(b.String(), "Log cleared:      Security was cleared by claude at 2026-10-07 06:10Z") ||
		strings.Contains(b.String(), "overwritten") || strings.Contains(b.String(), "LOGS INCOMPLETE") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}

	a.packLogs(st, true)
	list, _ := archive.List(a.pendingLogsDir())
	if len(list) != 1 {
		t.Fatalf("archives: %+v", list)
	}
	info, err := archive.Verify(list[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Gaps) != 1 || info.Gaps[0].Source != "Security" || info.Gaps[0].Cleared != "by claude at 2026-10-07 06:10Z" {
		t.Errorf("archive.json gaps: %+v", info.Gaps)
	}
}
