package archive

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// AR9: a Windows log is exported by record ID, not time: the records
// written while the clock was set back (172279-172285, stamped before the
// last export's end) are after the mark, so they are in the next piece.
// Records the log no longer holds are a gap with their numbers; a log
// cleared starts again; one with no mark yet is exported by time.
func TestRecordQuery(t *testing.T) {
	to := time.Date(2026, 10, 7, 23, 30, 0, 0, time.UTC)
	from := to.Add(-15 * time.Minute)
	mark := func(id uint64) store.ExportMark {
		return store.ExportMark{Bookmark: store.Bookmark{RecordID: id, Time: from}}
	}
	q := recordQuery("Security", mark(172278), true, 160000, 172290, from.Add(-24*time.Hour), from, to)
	if q.query != "/q:*[System[EventRecordID>172278 and EventRecordID<=172290]]" || q.next.RecordID != 172290 || len(q.gaps) != 0 {
		t.Errorf("by record ID: %+v", q)
	}
	if strings.Contains(q.query, "TimeCreated") {
		t.Error("the export depends on time")
	}
	q = recordQuery("Security", mark(172278), true, 172300, 172350, to.Add(-time.Minute), from, to)
	if len(q.gaps) != 1 || q.gaps[0].Records != "records 172279-172299" {
		t.Errorf("overwritten: %+v", q.gaps)
	}
	q = recordQuery("Security", mark(172278), true, 1, 40, to, from, to)
	if q.query != "/q:*[System[EventRecordID<=40]]" || len(q.notes) != 1 || len(q.gaps) != 0 {
		t.Errorf("cleared: %+v", q)
	}
	q = recordQuery("Security", mark(172290), true, 160000, 172290, from, from, to)
	if q.query != "" || q.next.RecordID != 172290 {
		t.Errorf("nothing new: %+v", q)
	}
	q = recordQuery("Security", store.ExportMark{}, false, 160000, 172290, from, from, to)
	if !strings.Contains(q.query, "TimeCreated[@SystemTime>='2026-10-07T23:15:00.000Z'] and EventRecordID<=172290") || q.next.RecordID != 172290 {
		t.Errorf("first: %+v", q)
	}
}
