package archive

import (
	"fmt"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// recordExport is what to export of one Windows log by record ID (AR9):
// the wevtutil query ("" for nothing), the mark once it is exported, and
// what was found missing.
type recordExport struct {
	query string
	next  store.ExportMark
	gaps  []Gap
	notes []string
}

// recordQuery works out a Windows log's export from the last record ID
// exported (m, if have) and the log's oldest and newest record IDs now
// (0, 0 when it is empty): everything after the mark up to the newest,
// whatever the records' times. With no mark yet, it is by time from
// from. Records the log no longer holds are a gap.
func recordQuery(ch string, m store.ExportMark, have bool, oldest, newest uint64, oldestAt, from, to time.Time) recordExport {
	const ts = "2006-01-02T15:04:05.000Z"
	mark := func(id uint64) store.ExportMark {
		return store.ExportMark{Bookmark: store.Bookmark{RecordID: id, Time: to}}
	}
	var r recordExport
	switch {
	case newest == 0:
		r.next = mark(0) // empty: the next record starts afresh
	case !have || m.RecordID == 0:
		r.query = fmt.Sprintf("/q:*[System[TimeCreated[@SystemTime>='%s'] and EventRecordID<=%d]]", from.UTC().Format(ts), newest)
		r.next = mark(newest)
	case newest == m.RecordID:
		r.next = mark(newest) // nothing new
	case newest < m.RecordID:
		// Record numbers went back: the log was cleared or recreated.
		// Everything in it now is new.
		r.notes = append(r.notes, ch+": record numbers started again (the log was cleared or recreated); this part has all of it")
		r.query = fmt.Sprintf("/q:*[System[EventRecordID<=%d]]", newest)
		r.next = mark(newest)
	default:
		if oldest > m.RecordID+1 {
			r.gaps = append(r.gaps, Gap{Source: ch, From: m.Time, To: oldestAt, Records: fmt.Sprintf("records %d-%d", m.RecordID+1, oldest-1)})
		}
		r.query = fmt.Sprintf("/q:*[System[EventRecordID>%d and EventRecordID<=%d]]", m.RecordID, newest)
		r.next = mark(newest)
	}
	return r
}
