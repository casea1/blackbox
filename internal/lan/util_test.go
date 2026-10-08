package lan

import (
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return buf.Bytes()
}

// delivered is the path of batch seq from a sender in the inbox, whatever
// random part its name has (DESIGN1).
func delivered(t *testing.T, in, host, id string, seq uint64) string {
	t.Helper()
	got, _ := filepath.Glob(filepath.Join(in, strings.TrimSuffix(InboxName(host, id, seq), batchExt)+"-*"+batchExt))
	if len(got) != 1 {
		t.Fatalf("batch %d in the inbox: %v", seq, got)
	}
	return got[0]
}
