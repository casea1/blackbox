// Package lan moves collected data between Blackbox systems so one
// collector can report on a whole LAN, or on a PC and the virtual machines
// it hosts.
//
// Transport is a folder, not a network protocol: a sender copies numbered
// batch files into the collector's inbox folder, which can be a VirtualBox
// shared folder, an SMB share or any other folder both can reach. Nothing
// listens on the network, a sender that is off or cannot reach the folder
// simply catches up later, and it works the same with or without a domain.
//
// Delivery is exactly-once:
//   - A sender first writes each batch to its own outbox, then records that
//     the data was batched. A crash in between rewrites the same batch.
//   - Batches are copied to the inbox under a temporary name and renamed
//     when complete, so the collector never reads a partial file.
//   - The collector imports each sender's batches in order and ignores
//     numbers it already has, so a batch delivered twice is imported once.
//     A number that never arrives is recorded as a gap and shown in the
//     report.
package lan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

const (
	batchKind   = "blackbox-batch"
	batchFormat = 1
	batchExt    = ".bbx"

	maxBatchLines = 20000     // records per batch
	maxBatchBytes = 512 << 20 // uncompressed size accepted from a sender
	maxLineBytes  = 64 << 20
)

// Header is the first line of a batch.
type Header struct {
	Kind     string    `json:"kind"`
	Format   int       `json:"format"`
	Sender   string    `json:"sender"`    // host name of the system that wrote the batch
	SenderID string    `json:"sender_id"` // its stream ID (see store.SendState)
	Seq      uint64    `json:"seq"`
	Created  time.Time `json:"created"`
	Version  string    `json:"version,omitempty"`
	OS       string    `json:"os,omitempty"`

	// FirstSeq is the first batch this collector gets from the sender:
	// earlier ones went to Earlier, another collector, and are not
	// missing here (L13).
	FirstSeq uint64 `json:"first_seq,omitempty"`
	Earlier  string `json:"earlier,omitempty"`
	// Kept is the range of batches the sender keeps after delivery and
	// can send again (L13).
	Kept *store.SeqRange `json:"kept,omitempty"`
	// Former are names the sender's computer had before (W1b).
	Former []string `json:"former,omitempty"`
}

// record is one line after the header. Exactly one field is set.
type record struct {
	Event  json.RawMessage `json:"event,omitempty"`
	Run    json.RawMessage `json:"run,omitempty"`
	Checks json.RawMessage `json:"checks,omitempty"`
	End    *trailer        `json:"end,omitempty"`
}

// trailer is the last line: it proves the batch is complete and intact.
type trailer struct {
	Records int    `json:"records"`
	SHA256  string `json:"sha256"` // of every line before the trailer
}

// Batch is a decoded batch file.
type Batch struct {
	Header
	Events [][]byte
	Runs   [][]byte
	Checks [][]byte
}

// Records is the number of events, runs and checks in the batch.
func (b *Batch) Records() int { return len(b.Events) + len(b.Runs) + len(b.Checks) }

// Encode writes the batch as gzip-compressed JSON lines.
func (b *Batch) Encode(w io.Writer) error {
	b.Kind, b.Format = batchKind, batchFormat
	gz := gzip.NewWriter(w)
	h := sha256.New()
	out := io.MultiWriter(gz, h)
	line := func(v any) error {
		enc, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = out.Write(append(enc, '\n'))
		return err
	}
	if err := line(b.Header); err != nil {
		return err
	}
	n := 0
	for _, set := range []struct {
		lines [][]byte
		wrap  func([]byte) record
	}{
		{b.Events, func(l []byte) record { return record{Event: l} }},
		{b.Runs, func(l []byte) record { return record{Run: l} }},
		{b.Checks, func(l []byte) record { return record{Checks: l} }},
	} {
		for _, l := range set.lines {
			if !json.Valid(l) {
				return fmt.Errorf("batch record %d is not valid JSON", n+1)
			}
			if err := line(set.wrap(l)); err != nil {
				return err
			}
			n++
		}
	}
	end, _ := json.Marshal(record{End: &trailer{Records: n, SHA256: hex.EncodeToString(h.Sum(nil))}})
	if _, err := gz.Write(append(end, '\n')); err != nil {
		return err
	}
	return gz.Close()
}

// Bytes encodes the batch in memory.
func (b *Batch) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	err := b.Encode(&buf)
	return buf.Bytes(), err
}

// ErrIncomplete means a batch ended before its trailer: it was cut short.
var ErrIncomplete = errors.New("batch is incomplete (no end marker)")

// Decode reads and verifies a batch.
func Decode(r io.Reader) (*Batch, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a Blackbox batch: %w", err)
	}
	defer gz.Close()
	lr := &io.LimitedReader{R: gz, N: maxBatchBytes + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	h := sha256.New()
	b := &Batch{}
	first, n := true, 0
	for sc.Scan() {
		raw := sc.Bytes()
		if first {
			if err := json.Unmarshal(raw, &b.Header); err != nil || b.Kind != batchKind {
				return nil, errors.New("not a Blackbox batch (bad header)")
			}
			if b.Format != batchFormat {
				return nil, fmt.Errorf("batch format %d is not supported by this version of Blackbox; upgrade the collector", b.Format)
			}
			if b.SenderID == "" || b.Seq == 0 {
				return nil, errors.New("batch header has no sender ID or sequence number")
			}
			first = false
			h.Write(raw)
			h.Write([]byte{'\n'})
			continue
		}
		var rec record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("batch record %d is damaged: %v", n+1, err)
		}
		if rec.End != nil {
			if rec.End.Records != n {
				return nil, fmt.Errorf("batch should hold %d records but has %d", rec.End.Records, n)
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != rec.End.SHA256 {
				return nil, errors.New("batch contents do not match their checksum (altered or damaged)")
			}
			if sc.Scan() {
				return nil, errors.New("batch has data after its end marker")
			}
			return b, nil
		}
		h.Write(raw)
		h.Write([]byte{'\n'})
		l := append([]byte(nil), raw...)
		switch {
		case rec.Event != nil:
			b.Events = append(b.Events, []byte(rec.Event))
		case rec.Run != nil:
			b.Runs = append(b.Runs, []byte(rec.Run))
		case rec.Checks != nil:
			b.Checks = append(b.Checks, []byte(rec.Checks))
		default:
			return nil, fmt.Errorf("batch record %d is empty: %s", n+1, l)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading batch: %w", err)
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("batch is larger than %d MB", maxBatchBytes>>20)
	}
	if first {
		return nil, errors.New("batch is empty")
	}
	return nil, ErrIncomplete
}
