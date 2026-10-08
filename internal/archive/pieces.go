package archive

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/casea1/blackbox/internal/store"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The original logs are exported at every collection, while the logs
// still hold them (AR2): each export is a piece, a folder of exported
// files under the pieces folder. Once a day the pieces are packed into one
// archive (see Pack), so a busy log that rolls over within the day loses
// nothing that was there at the last collection.

// PieceInfo describes a piece; it is written last, so a folder without it
// is an export that did not finish.
const PieceInfo = "piece.json"

// LogCover is how much of one log a save holds: from the oldest record
// present (the start of the period, unless the log no longer reached back
// that far) to the end of the period, and how many events Blackbox knows
// the log overwrote before they could be saved.
type LogCover struct {
	Source      string    `json:"source"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Overwritten uint64    `json:"overwritten,omitempty"`
}

// Coverage works out, for a save of [from, to), how far back each log
// reached and what it had overwritten (lost, by log).
func Coverage(states []LogState, from, to time.Time, lost map[string]uint64) []LogCover {
	var out []LogCover
	seen := map[string]bool{}
	for _, s := range states {
		c := LogCover{Source: s.Source, From: from.UTC(), To: to.UTC(), Overwritten: lost[s.Source]}
		switch {
		case s.Oldest.After(to):
			c.From = to.UTC() // it holds none of the period
		case s.Oldest.After(from):
			c.From = s.Oldest.UTC()
		}
		seen[s.Source] = true
		out = append(out, c)
	}
	for src, n := range lost {
		if !seen[src] && n > 0 {
			out = append(out, LogCover{Source: src, From: from.UTC(), To: to.UTC(), Overwritten: n})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// MergeCover combines the coverage of consecutive saves, oldest first: a
// log is covered from the first save that holds it to the last, and the
// events it overwrote are added up.
func MergeCover(parts ...[]LogCover) []LogCover {
	by := map[string]*LogCover{}
	var order []string
	for _, p := range parts {
		for _, c := range p {
			m := by[c.Source]
			if m == nil {
				cc := c
				by[c.Source] = &cc
				order = append(order, c.Source)
				continue
			}
			if c.To.After(m.To) {
				m.To = c.To
			}
			m.Overwritten += c.Overwritten
		}
	}
	out := make([]LogCover, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out
}

// Piece is one export waiting to be packed.
type Piece struct {
	Dir  string
	Info Info
}

// ExportFunc exports the logs into dir (see Export), for [from, to) or
// by position (see ByPosition); logs skip names are left out. It returns
// the files, notes on logs that could not be exported, and the parts of
// logs found missing by position (AR8, AR9).
type ExportFunc func(dir string, from, to time.Time, skip func(string) bool) ([]Source, []string, []Gap)

// Positions is where each log's last export ended (Marks), and, once an
// export by position has run, where this one ends (Next): only logs
// exported without error are in Next, so a log that failed is exported
// from the same place next time.
type Positions struct {
	Marks map[string]store.ExportMark
	Next  map[string]store.ExportMark
}

// ByPosition exports each log from where its last export ended, whatever
// the records' times (AR8, AR9): a record stamped in the same second as
// the last export, or while the clock was set back, is in the next
// piece. A log with no mark yet (the first export, or the first after an
// upgrade) is exported for [from, to) by time, and gets a mark at its
// end.
func ByPosition(p *Positions) ExportFunc {
	if p.Next == nil {
		p.Next = map[string]store.ExportMark{}
	}
	return func(dir string, from, to time.Time, skip func(string) bool) ([]Source, []string, []Gap) {
		return exportFrom(dir, from, to, skip, p)
	}
}

// SavePiece exports the logs for info's period into a new folder under
// dir, numbered after the pieces already there. Logs skip names had
// nothing new. A piece with no files is still kept: it records the period
// and what each log covered. An export that failed for every log is an
// error, so the same period is tried again.
func SavePiece(dir string, info Info, export ExportFunc, skip func(string) bool) (Piece, error) {
	if export == nil {
		export = export0
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Piece{}, err
	}
	have, err := Pieces(dir)
	if err != nil {
		return Piece{}, err
	}
	seq := 1
	if n := len(have); n > 0 {
		seq = pieceSeq(have[n-1].Dir) + 1
	}
	pdir := filepath.Join(dir, fmt.Sprintf("%06d", seq))
	if err := os.MkdirAll(pdir, 0o750); err != nil {
		return Piece{}, err
	}
	sources, notes, gaps := export(pdir, info.From, info.To, skip)
	info.Gaps = append(info.Gaps, gaps...)
	failed := 0
	for _, n := range notes {
		if strings.Contains(n, "could not be exported") {
			failed++
		}
	}
	if len(sources) == 0 && failed > 0 {
		os.RemoveAll(pdir)
		return Piece{}, fmt.Errorf("no logs could be exported: %s", strings.Join(notes, "; "))
	}
	info.Kind = kind
	info.inUTC() // TZ1b: piece.json in UTC throughout, like archive.json
	info.Notes = append(info.Notes, notes...)
	info.Files = nil
	for _, s := range sources {
		fi := FileInfo{Name: s.Name, Source: s.Source}
		if st, err := os.Stat(s.Path); err == nil {
			fi.Bytes = st.Size()
		}
		// Hashed now, so an edit before the logs are packed is caught
		// (AR6).
		if sum, err := FileSHA256(s.Path); err == nil {
			fi.SHA256 = sum
		}
		// Exported into the piece folder already, under its own name.
		if dst := filepath.Join(pdir, filepath.FromSlash(s.Name)); filepath.Clean(s.Path) != dst {
			os.MkdirAll(filepath.Dir(dst), 0o750)
			if err := os.Rename(s.Path, dst); err != nil {
				os.RemoveAll(pdir)
				return Piece{}, err
			}
		}
		info.Files = append(info.Files, fi)
	}
	b, _ := json.MarshalIndent(info, "", "  ")
	if err := os.WriteFile(filepath.Join(pdir, PieceInfo), b, 0o640); err != nil {
		os.RemoveAll(pdir)
		return Piece{}, err
	}
	return Piece{Dir: pdir, Info: info}, nil
}

func export0(dir string, from, to time.Time, skip func(string) bool) ([]Source, []string, []Gap) {
	s, n := export(dir, from, to, skip)
	return s, n, nil
}

func pieceSeq(dir string) int {
	n, _ := strconv.Atoi(filepath.Base(dir))
	return n
}

// Pieces lists the finished pieces under dir in the order they were made,
// and removes any export that did not finish.
func Pieces(dir string) ([]Piece, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Piece
	for _, e := range entries {
		if !e.IsDir() || pieceSeq(e.Name()) == 0 {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(filepath.Join(p, PieceInfo))
		if err != nil {
			os.RemoveAll(p) // an export that did not finish
			continue
		}
		var info Info
		if err := json.Unmarshal(b, &info); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(p, PieceInfo), err)
		}
		out = append(out, Piece{Dir: p, Info: info})
	}
	sort.Slice(out, func(i, j int) bool { return pieceSeq(out[i].Dir) < pieceSeq(out[j].Dir) })
	return out, nil
}

// PackDue says whether the pieces should be packed into an archive: once
// the oldest is a day old.
func PackDue(pieces []Piece, now time.Time) bool {
	if len(pieces) == 0 {
		return false
	}
	return now.Sub(Span(pieces).From) >= Every || now.Sub(pieces[0].Info.Created) >= Every
}

// Span is the period pieces cover: from the earliest start (after the
// clock was moved back, a later piece can start earlier) to the end of
// the last one made.
func Span(pieces []Piece) Info {
	var s Info
	for _, p := range pieces {
		if s.From.IsZero() || p.Info.From.Before(s.From) {
			s.From = p.Info.From
		}
	}
	if n := len(pieces); n > 0 {
		s.To = pieces[n-1].Info.To
	}
	return s
}

// Pack writes the pieces into one archive at path, made by host on
// created, and removes them. Text logs (audit.log, syslog …) are joined in
// order into one file; each piece's .evtx files are kept as they are,
// named after the start of their piece when there is more than one.
func Pack(path, host, osName string, pieces []Piece, created time.Time) (Info, error) {
	span := Span(pieces)
	info := Info{Host: host, OS: osName, From: span.From, To: span.To, Created: created}
	if !info.From.Before(info.To) {
		return Info{}, fmt.Errorf("the pieces cover no time (%s to %s)", info.From, info.To)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".pack-")
	if err != nil {
		return Info{}, err
	}
	defer os.RemoveAll(tmp)
	var sources []Source
	names := map[string]bool{}
	joined := map[string]*os.File{}
	var covers [][]LogCover
	seenNote := map[string]bool{}
	for _, p := range pieces {
		renamed := map[string]string{} // .evtx base name → its name here
		covers = append(covers, p.Info.Logs)
		info.Gaps = append(info.Gaps, p.Info.Gaps...)
		for _, n := range p.Info.Notes {
			if !seenNote[n] {
				seenNote[n] = true
				info.Notes = append(info.Notes, n)
			}
		}
		for _, f := range p.Info.Files {
			src := filepath.Join(p.Dir, filepath.FromSlash(f.Name))
			// A file deleted or unreadable since it was exported is a gap
			// in this archive, not a reason to stop archiving (AR5); one
			// changed since is packed as found and marked (AR6).
			sum, err := FileSHA256(src)
			if err != nil {
				why := "was missing"
				if !errors.Is(err, os.ErrNotExist) {
					why = "could not be read (" + err.Error() + ")"
				}
				g := Gap{Source: f.Source, From: p.Info.From, To: p.Info.To,
					Reason: fmt.Sprintf("%s, exported for %s to %s, %s when the logs were packed", f.Name, p.Info.From.UTC().Format(time.RFC3339), p.Info.To.UTC().Format(time.RFC3339), why)}
				info.Gaps = append(info.Gaps, g)
				info.Notes = append(info.Notes, g.Reason+": its events for that time are not in this archive")
				continue
			}
			changed := f.SHA256 != "" && sum != f.SHA256
			if changed {
				info.Notes = append(info.Notes, fmt.Sprintf("%s, exported for %s to %s, was changed after it was exported (its SHA-256 no longer matches the one taken then); it is in this archive as it was found",
					f.Name, p.Info.From.UTC().Format(time.RFC3339), p.Info.To.UTC().Format(time.RFC3339)))
			}
			if strings.HasSuffix(strings.ToLower(f.Name), ".evtx") {
				// Named to the second, and never twice: two runs in one
				// minute make two pieces (AR7).
				name := f.Name
				if len(pieces) > 1 {
					name = strings.TrimSuffix(f.Name, filepath.Ext(f.Name)) + "_" + p.Info.From.UTC().Format(pieceStamp) + filepath.Ext(f.Name)
				}
				name = uniqueName(name, names)
				renamed[strings.TrimSuffix(f.Name, filepath.Ext(f.Name))] = strings.TrimSuffix(name, filepath.Ext(name))
				sources = append(sources, Source{Name: name, Source: f.Source, Path: src, Changed: changed})
				continue
			}
			// The message text of an .evtx goes with it, under its name
			// (ASSESS1): LocaleMetaData/Security_1033.MTA.
			if strings.HasPrefix(f.Name, MetaDir+"/") {
				base := strings.TrimPrefix(f.Name, MetaDir+"/")
				for old, now := range renamed {
					if strings.HasPrefix(base, old+"_") {
						base = now + strings.TrimPrefix(base, old)
						break
					}
				}
				sources = append(sources, Source{Name: uniqueName(MetaDir+"/"+base, names), Source: f.Source, Path: src, Changed: changed})
				continue
			}
			out := joined[f.Name]
			if out == nil {
				out, err = os.Create(filepath.Join(tmp, f.Name))
				if err != nil {
					return Info{}, err
				}
				defer out.Close()
				joined[f.Name] = out
				names[f.Name] = true
				sources = append(sources, Source{Name: f.Name, Source: f.Source, Path: out.Name()})
			}
			if changed {
				for i := range sources {
					if sources[i].Path == out.Name() {
						sources[i].Changed = true
					}
				}
			}
			if err := appendFile(out, src); err != nil {
				return Info{}, fmt.Errorf("%s: %w", src, err)
			}
		}
	}
	for _, f := range joined {
		if err := f.Close(); err != nil {
			return Info{}, err
		}
	}
	info.Logs = MergeCover(covers...)
	if len(sources) == 0 {
		info.Notes = append(info.Notes, "no new log records in this period")
	}
	info, err = Write(path, info, sources)
	if err != nil {
		return info, err
	}
	for _, p := range pieces {
		os.RemoveAll(p.Dir)
	}
	return info, nil
}

// MetaDir is the folder next to an .evtx holding its message text
// (wevtutil al), where Event Viewer looks for it.
const MetaDir = "LocaleMetaData"

// pieceStamp names a piece's .evtx files in an archive by its start.
const pieceStamp = "20060102-150405Z"

func appendFile(w io.Writer, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(w, in)
	return err
}
