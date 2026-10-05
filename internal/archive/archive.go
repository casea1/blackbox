// Package archive keeps the original logs. At every collection each
// computer exports the raw logs Blackbox reads, covering the time since
// its last export (see SavePiece), and once a day packs those exports into
// one zip: Windows event logs as .evtx files (open them in Event Viewer),
// Linux audit records in audit.log format (read them with ausearch -if)
// and system log lines as text.
//
// Reports show what Blackbox found in the logs; the archives are the logs
// themselves, unaltered, for an assessor or an investigation. A sender
// delivers its archives to the collector with its events.
package archive

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// InfoName is the description inside every archive.
const InfoName = "archive.json"

// Every is how often an archive is made, and FirstSpan how far back the
// first one reaches.
const (
	Every     = 24 * time.Hour
	FirstSpan = 7 * 24 * time.Hour
)

// Info describes an archive: whose logs, the period, and each file's hash.
type Info struct {
	Kind    string     `json:"kind"` // "blackbox-archive"
	Host    string     `json:"host"`
	OS      string     `json:"os"`
	From    time.Time  `json:"from"`
	To      time.Time  `json:"to"`
	Created time.Time  `json:"created"`
	Files   []FileInfo `json:"files"`
	Notes   []string   `json:"notes,omitempty"` // logs that could not be exported, and why
	// Gaps are the parts of the period a full log had already overwritten
	// before this save: those events are not in it.
	Gaps []Gap `json:"gaps,omitempty"`
	// Logs is, for each log, the part of the period it actually covers
	// and the events it overwrote before they could be saved (AR2).
	Logs []LogCover `json:"logs,omitempty"`
}

// FileInfo is one log file in an archive.
type FileInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"` // the log it came from
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

const kind = "blackbox-archive"

// Due returns the period the next archive covers, if one is due: from the
// end of the last one (or FirstSpan back, the first time) until now.
func Due(last, now time.Time) (from time.Time, due bool) {
	if last.IsZero() {
		return now.Add(-FirstSpan), true
	}
	return last, now.Sub(last) >= Every
}

const stampFormat = "20060102-1504Z"

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// SafeName makes a host or log name usable as a file name.
func SafeName(s string) string {
	s = strings.Trim(unsafeChars.ReplaceAllString(s, "-"), "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// FileName is an archive's name: HOST_FROM_TO.zip, times in UTC.
func FileName(host string, from, to time.Time) string {
	return fmt.Sprintf("%s_%s_%s.zip", SafeName(host), from.UTC().Format(stampFormat), to.UTC().Format(stampFormat))
}

// ParseFileName reads the host and period back from FileName.
func ParseFileName(name string) (host string, from, to time.Time, ok bool) {
	parts := strings.Split(strings.TrimSuffix(name, ".zip"), "_")
	if len(parts) < 3 || !strings.HasSuffix(name, ".zip") {
		return "", from, to, false
	}
	f, err1 := time.Parse(stampFormat, parts[len(parts)-2])
	t, err2 := time.Parse(stampFormat, parts[len(parts)-1])
	if err1 != nil || err2 != nil {
		return "", from, to, false
	}
	return strings.Join(parts[:len(parts)-2], "_"), f, t, true
}

// Source is one exported log waiting to go into an archive.
type Source struct {
	Name   string // file name inside the archive
	Source string // the log it came from
	Path   string // temporary file holding it
}

// Create exports this computer's logs for [from, to) and writes the
// archive to path. Logs that cannot be exported are noted in the archive
// rather than failing it; an archive with no logs at all is an error.
func Create(path, host, osName string, from, to, now time.Time, gaps []Gap) (Info, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".archive-")
	if err != nil {
		return Info{}, err
	}
	defer os.RemoveAll(tmp)
	sources, notes := export(tmp, from, to, nil)
	if len(sources) == 0 {
		if len(notes) == 0 {
			notes = []string{"no logs found"}
		}
		return Info{}, fmt.Errorf("no logs could be exported: %s", strings.Join(notes, "; "))
	}
	return Write(path, Info{Host: host, OS: osName, From: from, To: to, Created: now, Notes: notes, Gaps: gaps}, sources)
}

// Write zips the sources and a description of them, under a temporary
// name first so a half-written archive is never mistaken for a complete
// one. It returns the description as stored.
func Write(path string, info Info, sources []Source) (Info, error) {
	info.Kind, info.Files = kind, nil
	info.From, info.To, info.Created = info.From.UTC(), info.To.UTC(), info.Created.UTC()
	err := write(path, &info, sources)
	return info, err
}

func write(path string, info *Info, sources []Source) error {
	part := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".partial")
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(part)
		return err
	}
	zw := zip.NewWriter(f)
	for _, s := range sources {
		fi, err := addFile(zw, s)
		if err != nil {
			return fail(fmt.Errorf("add %s: %w", s.Name, err))
		}
		info.Files = append(info.Files, fi)
	}
	b, _ := json.MarshalIndent(info, "", "  ")
	w, err := zw.CreateHeader(&zip.FileHeader{Name: InfoName, Method: zip.Deflate, Modified: info.Created})
	if err == nil {
		_, err = w.Write(b)
	}
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return err
	}
	return os.Rename(part, path)
}

func addFile(zw *zip.Writer, s Source) (FileInfo, error) {
	in, err := os.Open(s.Path)
	if err != nil {
		return FileInfo{}, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return FileInfo{}, err
	}
	w, err := zw.CreateHeader(&zip.FileHeader{Name: s.Name, Method: zip.Deflate, Modified: st.ModTime()})
	if err != nil {
		return FileInfo{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), in)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Name: s.Name, Source: s.Source, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// Verify opens an archive and checks every file against its recorded
// hash, so a damaged or altered archive is caught before it is filed.
func Verify(path string) (Info, error) {
	var info Info
	zr, err := zip.OpenReader(path)
	if err != nil {
		return info, fmt.Errorf("not a readable zip file: %w", err)
	}
	defer zr.Close()
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	desc, ok := files[InfoName]
	if !ok {
		return info, errors.New("it has no " + InfoName)
	}
	if err := readJSON(desc, &info); err != nil {
		return info, fmt.Errorf("%s: %w", InfoName, err)
	}
	if info.Kind != kind || info.Host == "" || !info.From.Before(info.To) {
		return info, errors.New(InfoName + " does not describe a Blackbox archive")
	}
	for _, fi := range info.Files {
		f, ok := files[fi.Name]
		if !ok {
			return info, fmt.Errorf("%s is listed but missing", fi.Name)
		}
		sum, err := hashZipFile(f)
		if err != nil {
			return info, fmt.Errorf("%s: %w", fi.Name, err)
		}
		if sum != fi.SHA256 {
			return info, fmt.Errorf("%s does not match its recorded SHA-256 (damaged or altered)", fi.Name)
		}
	}
	if len(files) != len(info.Files)+1 {
		return info, errors.New("it holds files that are not listed in " + InfoName)
	}
	return info, nil
}

func readJSON(f *zip.File, v any) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	return json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(v)
}

func hashZipFile(f *zip.File) (string, error) {
	r, err := f.Open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Stored is an archive filed on a computer that makes reports.
type Stored struct {
	Host     string
	From, To time.Time
	Path     string
	Bytes    int64
}

// List returns the archives filed under dir (dir/HOST/*.zip), oldest
// first.
func List(dir string) ([]Stored, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*", "*.zip"))
	if err != nil {
		return nil, err
	}
	var out []Stored
	for _, m := range matches {
		host, from, to, ok := ParseFileName(filepath.Base(m))
		if !ok {
			continue
		}
		st, err := os.Stat(m)
		if err != nil {
			continue
		}
		out = append(out, Stored{Host: host, From: from, To: to, Path: m, Bytes: st.Size()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].From.Equal(out[j].From) {
			return out[i].From.Before(out[j].From)
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

// File moves a verified archive into dir/HOST/, named by its contents. An
// archive already filed is a duplicate and is removed.
func File(src, dir string, info Info) (string, error) {
	hostDir := filepath.Join(dir, SafeName(info.Host))
	if err := os.MkdirAll(hostDir, 0o750); err != nil {
		return "", err
	}
	dest := filepath.Join(hostDir, FileName(info.Host, info.From, info.To))
	if _, err := os.Stat(dest); err == nil {
		return dest, os.Remove(src)
	}
	if err := os.Rename(src, dest); err == nil {
		return dest, nil
	}
	// A different drive: copy, then remove the original.
	part := filepath.Join(hostDir, "."+filepath.Base(dest)+".partial")
	if err := copyFile(src, part); err != nil {
		os.Remove(part)
		return "", err
	}
	if err := os.Rename(part, dest); err != nil {
		return "", err
	}
	return dest, os.Remove(src)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Prune removes archives whose period ended more than days ago.
func Prune(dir string, days int, now time.Time) error {
	if days <= 0 {
		return nil
	}
	list, err := List(dir)
	if err != nil {
		return err
	}
	cutoff := now.AddDate(0, 0, -days)
	for _, a := range list {
		if a.To.Before(cutoff) {
			if err := os.Remove(a.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

// Bundled describes a bundle: the period it covers, its SHA-256, and
// what its daily archives say about gaps and coverage.
type Bundled struct {
	From, To time.Time
	SHA256   string
	Gaps     []Gap
	Logs     []LogCover
	Notes    []string
}

// Bundle combines one computer's daily archives into a single zip at dst,
// each day's logs (and its archive.json) in a folder named for its period,
// e.g. 20260929-1520Z_20260930-1520Z/Security.evtx. Every archive is
// verified first.
func Bundle(dst string, list []Stored) (Bundled, error) {
	var b Bundled
	part := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".partial")
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return b, err
	}
	fail := func(e error) (Bundled, error) {
		f.Close()
		os.Remove(part)
		return Bundled{}, e
	}
	zw := zip.NewWriter(f)
	var covers [][]LogCover
	for _, s := range list {
		info, err := Verify(s.Path)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", filepath.Base(s.Path), err))
		}
		b.Gaps = append(b.Gaps, info.Gaps...)
		covers = append(covers, info.Logs)
		b.Notes = append(b.Notes, info.Notes...)
		if b.From.IsZero() || s.From.Before(b.From) {
			b.From = s.From
		}
		if s.To.After(b.To) {
			b.To = s.To
		}
		folder := s.From.UTC().Format(stampFormat) + "_" + s.To.UTC().Format(stampFormat) + "/"
		if err := copyEntries(zw, s.Path, folder); err != nil {
			return fail(fmt.Errorf("%s: %w", filepath.Base(s.Path), err))
		}
	}
	if err := zw.Close(); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return Bundled{}, err
	}
	if err := os.Rename(part, dst); err != nil {
		return Bundled{}, err
	}
	b.Logs = MergeCover(covers...)
	b.SHA256, err = FileSHA256(dst)
	return b, err
}

// copyEntries copies every file of the zip at src into zw under prefix,
// still compressed.
func copyEntries(zw *zip.Writer, src, prefix string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, e := range zr.File {
		h := e.FileHeader
		h.Name = prefix + e.Name
		w, err := zw.CreateRaw(&h)
		if err != nil {
			return err
		}
		r, err := e.OpenRaw()
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, r); err != nil {
			return err
		}
	}
	return nil
}

// FileSHA256 returns the SHA-256 of a file, read in pieces so large log
// archives are not held in memory.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Contents lists what a zip holds: the archive.json of a single archive,
// or of each day's folder in a bundle (see Bundle), in order.
func Contents(path string) ([]Info, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var out []Info
	for _, f := range zr.File {
		if f.Name != InfoName && !strings.HasSuffix(f.Name, "/"+InfoName) {
			continue
		}
		var info Info
		if err := readJSON(f, &info); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From.Before(out[j].From) })
	return out, nil
}

// Export saves this computer's logs for [from, to) into dir, as the daily
// archive does, without zipping them: Windows .evtx files, or the Linux
// audit and system log lines. It returns the files and notes on any log
// that could not be saved.
func Export(dir string, from, to time.Time) ([]Source, []string) {
	return export(dir, from, to, nil)
}
