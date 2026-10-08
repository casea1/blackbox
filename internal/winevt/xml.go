// Package winevt reads Windows event logs and translates them into
// plain-English normalized events.
//
// Parsing and translation work on the XML form of an event, which is what
// the Windows Event Log API renders and what `wevtutil qe /f:xml` and Event
// Viewer's "Save as XML" produce. That keeps everything except the thin API
// layer (live_windows.go) testable on any OS.
package winevt

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Raw is one Windows event as recorded, before translation.
type Raw struct {
	Provider string
	EventID  int
	Version  int
	Level    int
	Task     int
	Keywords string
	Time     time.Time
	RecordID uint64
	Channel  string
	Computer string
	UserSID  string // System/Security/@UserID, when present

	// Data holds EventData/Data (by Name, or "Data0", "Data1"… when
	// unnamed) and the leaf elements of UserData.
	Data map[string]string
}

// Get returns a data value, treating "-" and blank as empty.
func (r *Raw) Get(name string) string {
	v := strings.TrimSpace(r.Data[name])
	if v == "-" {
		return ""
	}
	return v
}

// AuditFailure reports whether the Security event is an audit failure.
func (r *Raw) AuditFailure() bool { return r.keywords()&keywordAuditFailure != 0 }

// AuditSuccess reports whether the Security event is an audit success.
func (r *Raw) AuditSuccess() bool { return r.keywords()&keywordAuditSuccess != 0 }

// The Audit Success and Audit Failure keywords of Security events.
const (
	keywordAuditFailure = 0x0010000000000000
	keywordAuditSuccess = 0x0020000000000000
)

func (r *Raw) keywords() uint64 {
	k, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.Keywords)), "0x"), 16, 64)
	if err != nil {
		return 0
	}
	return k
}

// Outcome is a Security event's outcome from its Audit Success or Audit
// Failure keyword, or "" when it has neither (AU3). Only the Security log
// uses these keywords to record an outcome; other logs do not say.
func (r *Raw) Outcome() string {
	if r.Channel != "Security" && r.Provider != "Microsoft-Windows-Security-Auditing" {
		return ""
	}
	switch {
	case r.AuditFailure():
		return "failure"
	case r.AuditSuccess():
		return "success"
	}
	return ""
}

type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Version     string `xml:"Version"`
		Level       string `xml:"Level"`
		Task        string `xml:"Task"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
		Security      struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// ParseEvent parses a single <Event> element.
func ParseEvent(data []byte) (*Raw, error) {
	var xe xmlEvent
	if err := xml.Unmarshal(data, &xe); err != nil {
		return nil, fmt.Errorf("parse event xml: %w", err)
	}
	return fromXML(&xe)
}

// ParseStream calls fn for every <Event> element in r. The input may be a
// bare sequence of events (wevtutil output) or wrapped in a root element
// (Event Viewer "Save as XML").
func ParseStream(r io.Reader, fn func(*Raw) error) error {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var xe xmlEvent
		if err := dec.DecodeElement(&xe, &se); err != nil {
			return fmt.Errorf("parse event xml: %w", err)
		}
		raw, err := fromXML(&xe)
		if err != nil {
			return err
		}
		if err := fn(raw); err != nil {
			return err
		}
	}
}

func fromXML(xe *xmlEvent) (*Raw, error) {
	s := &xe.System
	id, err := strconv.Atoi(strings.TrimSpace(s.EventID))
	if err != nil {
		return nil, fmt.Errorf("bad EventID %q", s.EventID)
	}
	r := &Raw{
		Provider: s.Provider.Name,
		EventID:  id,
		Version:  atoi(s.Version),
		Level:    atoi(s.Level),
		Task:     atoi(s.Task),
		Keywords: strings.TrimSpace(s.Keywords),
		Channel:  strings.TrimSpace(s.Channel),
		Computer: strings.TrimSpace(s.Computer),
		UserSID:  s.Security.UserID,
		Data:     map[string]string{},
	}
	r.RecordID, _ = strconv.ParseUint(strings.TrimSpace(s.EventRecordID), 10, 64)
	if ts := s.TimeCreated.SystemTime; ts != "" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("bad TimeCreated %q", ts)
		}
		r.Time = t
	}
	for i, d := range xe.EventData.Data {
		name := d.Name
		if name == "" {
			name = "Data" + strconv.Itoa(i)
		}
		r.Data[name] = strings.TrimSpace(d.Value)
	}
	if len(bytes.TrimSpace(xe.UserData.Inner)) > 0 {
		flattenLeaves(xe.UserData.Inner, r.Data)
	}
	return r, nil
}

// flattenLeaves stores the text of every leaf element in inner by its
// local name (first occurrence wins).
func flattenLeaves(inner []byte, out map[string]string) {
	dec := xml.NewDecoder(bytes.NewReader(inner))
	dec.Strict = false
	var stack []string
	var text strings.Builder
	hasChild := []bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(hasChild) > 0 {
				hasChild[len(hasChild)-1] = true
			}
			stack = append(stack, t.Name.Local)
			hasChild = append(hasChild, false)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			n := len(stack) - 1
			if n < 0 {
				return
			}
			if !hasChild[n] {
				if _, seen := out[stack[n]]; !seen {
					out[stack[n]] = strings.TrimSpace(text.String())
				}
			}
			stack, hasChild = stack[:n], hasChild[:n]
			text.Reset()
		}
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
