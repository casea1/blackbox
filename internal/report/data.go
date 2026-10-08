package report

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The event pages and Search read the report's events from data files
// next to report.html, so the report opens without loading them. Each
// page has one file per day (data/<page>-<YYYYMMDD>.js), and the raw
// event data shown in the event panel is in a second file per day
// (…-raw.js) that is read only when a row is opened. Each file is a
// script that hands gzip-compressed JSON to the page:
//
//	BB.put("failed/20260928", "H4sI…")
//
// A script file, unlike a fetch, can be read from a file share or a local
// folder by every browser.

// MaxListed is the most events a report lists on its event pages (the size
// safeguard): above it, routine Info events beyond each page's share are
// counted and charted but not listed. High, Medium and Low events, and
// events a detection points to, are always listed.
var MaxListed = 2_000_000

// EventPage is one page of the report that lists events.
type EventPage struct {
	ID    string // used in links and data file names
	Title string
	All   string // heading of the full list, e.g. "All failed logons"
	Icon  string
	// Category is the events' category; PowerShell is selected by log.
	Category event.Category
	Total    int            // events on this page
	Omitted  int            // Info events counted but not listed (safeguard)
	BySev    map[string]int // by severity
	Days     []string       // YYYYMMDD of each data file
	Hosts    []string       `json:"-"` // computers with events on this page

	Cols      []Column // the table's columns
	KindLabel string   // the kind column's filter, e.g. "Reason"
	Top       *pageTop `json:"-"`
}

// eventPages lists the event pages in sidebar order.
func eventPages() []*EventPage {
	return []*EventPage{
		{ID: "privileged", Title: "Privileged activity", All: "All privileged actions", Icon: "key-round", Category: event.CatPrivileged},
		{ID: "usb", Title: "USB & removable", All: "All USB events", Icon: "usb", Category: event.CatRemovable},
		{ID: "failed", Title: "Failed logons", All: "All failed logons", Icon: "log-in", Category: event.CatFailedLogon},
		{ID: "accounts", Title: "Accounts & groups", All: "All account and group changes", Icon: "users", Category: event.CatAccount},
		{ID: "integrity", Title: "Audit integrity", All: "All audit integrity events", Icon: "file-warning", Category: event.CatIntegrity},
		{ID: "powershell", Title: "PowerShell", All: "All PowerShell scripts", Icon: "terminal"},
		{ID: "other", Title: "Other security", All: "All other security events", Icon: "shield", Category: event.CatOther},
		{ID: "logons", Title: "Logon activity", All: "All logons", Icon: "activity", Category: event.CatLogon},
	}
}

const powerShellLog = "Microsoft-Windows-PowerShell/Operational"

// on reports whether e belongs on page p.
func (p *EventPage) on(e *event.Event) bool {
	ps := e.Source == powerShellLog || strings.HasPrefix(e.Action, "powershell_")
	if p.ID == "powershell" {
		return ps
	}
	return e.Category == p.Category && !(p.ID == "other" && ps) // PowerShell has its own page
}

// dataFile is one file of the data folder.
type dataFile struct {
	Name string
	Body []byte
}

// chunk is the JSON in one data file. Strings that repeat (computers,
// accounts, actions, logs) are stored once in Dict and referred to by
// index; times are local clock seconds after Base (see buildData).
type chunk struct {
	Base int64    `json:"base"`
	Off  int      `json:"off"` // the report's UTC offset at the day's start, in seconds
	Dict []string `json:"dict"`
	Cols []string `json:"cols"`
	Rows [][]any  `json:"rows"`
	dict map[string]int
}

var chunkCols = []string{"i", "t", "host", "sev", "act", "user", "target", "src", "sum", "eid", "log", "proc", "cmd", "out", "flags", "kind", "x", "dz"}

func (c *chunk) ref(s string) int {
	if i, ok := c.dict[s]; ok {
		return i
	}
	c.dict[s] = len(c.Dict)
	c.Dict = append(c.Dict, s)
	return len(c.Dict) - 1
}

// buildData splits the report's events into the event pages' data files
// and fills in each page's counts.
func (r *Report) buildData() ([]*EventPage, []dataFile, error) {
	pages := eventPages()
	keep := r.listed()
	flags := map[int][]string{}
	for _, row := range r.rows {
		if len(row.Flags) > 0 {
			flags[rowIndex(row.ID)] = row.Flags
		}
	}
	var files []dataFile
	sessions := r.sessions()
	for _, p := range pages {
		spec := pageSpecs[p.ID]
		p.BySev = map[string]int{}
		type dayData struct {
			c   *chunk
			raw []any
		}
		days := map[string]*dayData{}
		hosts := map[string]bool{}
		for i, e := range r.Events {
			if !p.on(e) {
				continue
			}
			p.Total++
			if !hosts[e.Host] {
				hosts[e.Host] = true
				p.Hosts = append(p.Hosts, e.Host)
			}
			p.BySev[string(e.Severity)]++
			if !keep[i] {
				p.Omitted++
				continue
			}
			local := e.Time.In(r.Location)
			day := local.Format("20060102")
			d := days[day]
			if d == nil {
				start := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, r.Location)
				_, off := start.Zone()
				d = &dayData{c: &chunk{Base: start.Unix(), Off: off, Cols: chunkCols, dict: map[string]int{}}}
				days[day] = d
			}
			c := d.c
			// DST1: each row has its own offset. t is the local clock
			// time in seconds from the day's start (so base+t+off reads as
			// the local time), and dz is how far the row's offset is from
			// the day's: the instant is base+t-dz. On a day the clocks
			// change, rows either side of the change keep their own offset.
			_, rowOff := local.Zone()
			dz := rowOff - c.Off
			eid := ""
			if e.EventID != 0 {
				eid = fmt.Sprint(e.EventID)
			}
			c.Rows = append(c.Rows, []any{i, e.Time.Unix() + int64(dz) - c.Base, c.ref(e.Host), c.ref(string(e.Severity)), c.ref(e.Action),
				c.ref(e.User), e.Target, c.ref(e.SourceIP), e.Summary, eid, c.ref(e.Source), c.ref(e.Process), e.Command,
				c.ref(e.Outcome), strings.Join(flags[i], ","), c.ref(spec.kindOf(e)), c.ref(extra(spec, e, sessions[i])), dz})
			d.raw = append(d.raw, []any{e.Details, e.Fields, recordedAs(e), preciseTime(local)})
		}
		sort.Strings(p.Hosts)
		for day := range days {
			p.Days = append(p.Days, day)
		}
		sort.Strings(p.Days)
		for _, day := range p.Days {
			d := days[day]
			key := p.ID + "/" + day
			f, err := dataScript(key, d.c)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, dataFile{Name: p.ID + "-" + day + ".js", Body: f})
			raw, err := dataScript("raw/"+key, d.raw)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, dataFile{Name: p.ID + "-" + day + "-raw.js", Body: raw})
		}
	}
	r.fillPages(pages)
	// Inventory's accounts, read when the page needs them (UI-R1).
	if f, ok, err := r.inventoryData(); err != nil {
		return nil, nil, err
	} else if ok {
		files = append(files, f)
	}
	r.dataSums = map[string]string{}
	for _, f := range files {
		r.dataSums[f.Name] = dataSum(f.Body)
	}
	return pages, files, nil
}

// extra is the page-specific column's value for e.
func extra(spec pageSpec, e *event.Event, session string) string {
	if spec.extra != nil {
		return spec.extra(e)
	}
	return session
}

// listed marks which events (by index in r.Events) the event pages list.
// Normally all of them; above MaxListed, routine Info events are dropped
// from the newest back until the report fits, so the earliest of each day
// stay listed and every page keeps some.
func (r *Report) listed() []bool {
	keep := make([]bool, len(r.Events))
	for i := range keep {
		keep[i] = true
	}
	over := len(r.Events) - MaxListed
	if over <= 0 {
		return keep
	}
	needed := map[int]bool{}
	for _, f := range r.Findings {
		for _, id := range f.RowIDs {
			needed[rowIndex(id)] = true
		}
	}
	for _, row := range r.HighRows {
		needed[rowIndex(row.ID)] = true
	}
	for i := len(r.Events) - 1; i >= 0 && over > 0; i-- {
		if r.Events[i].Severity == event.SevInfo && !needed[i] {
			keep[i] = false
			over--
		}
	}
	return keep
}

// preciseTime is an event's time for the event panel, to the millisecond
// and with its UTC offset: "Mon 28 Sep 2026 06:02:41.338 (UTC-5)".
func preciseTime(t time.Time) string {
	_, off := t.Zone()
	z := "UTC"
	if off != 0 {
		z = fmt.Sprintf("UTC%+d", off/3600)
		if m := off % 3600 / 60; m != 0 {
			z += fmt.Sprintf(":%02d", abs(m))
		}
	}
	return t.Format("Mon 2 Jan 2006 15:04:05.000") + " (" + z + ")"
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// recordedAs says where the event came from, e.g. "Security event 4625,
// record 482007" or "auditd USER_CMD record, serial 9921".
func recordedAs(e *event.Event) string {
	if e.OS == "windows" {
		s := fmt.Sprintf("%s event %d", e.Source, e.EventID)
		if e.RecordID != 0 {
			s += fmt.Sprintf(", record %d", e.RecordID)
		}
		return s
	}
	s := strings.TrimSpace(e.Source + " " + e.RecordType)
	if e.RecordID != 0 {
		return s + fmt.Sprintf(" record, serial %d", e.RecordID)
	}
	return s + " message"
}

// rowIndex turns a row ID ("r12") back into an index into r.Events.
func rowIndex(id string) int {
	var n int
	fmt.Sscanf(id, "r%d", &n)
	return n - 1
}

// dataScript gzips v as JSON and wraps it in the BB.put call.
func dataScript(key string, v any) ([]byte, error) {
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if _, err := w.Write(js.Bytes()); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	b64 := base64.StdEncoding.EncodeToString(gz.Bytes())
	fmt.Fprintf(&out, "BB.put(%q,%q);\n", key, b64)
	return out.Bytes(), nil
}

// dataSum is the SHA-256 of a data file's payload, which the page checks
// as it loads each file (see app.js), so a changed file shows as such.
func dataSum(file []byte) string {
	s := string(file)
	i := strings.LastIndex(s, `,"`)
	j := strings.LastIndex(s, `");`)
	if i < 0 || j <= i {
		return ""
	}
	h := sha256.Sum256([]byte(s[i+2 : j]))
	return hex.EncodeToString(h[:])
}
