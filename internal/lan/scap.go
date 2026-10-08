package lan

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
)

// SCAP scan results travel from a sender to its collector next to its
// batches, compressed, each file once (docs/design.md 13a).
const scapExt, scapPrefix = ".xml.gz", "scap_"

// QueueScap puts scan result files not sent before into the outbox.
func QueueScap(st *store.Store, files []string, now time.Time) (int, error) {
	if st.State.ScapSent == nil {
		st.State.ScapSent = map[string]time.Time{}
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return n, err
		}
		sum := sha256.Sum256(b)
		id := hex.EncodeToString(sum[:])
		if _, sent := st.State.ScapSent[id]; sent {
			continue
		}
		plainSum := id
		if strings.HasSuffix(strings.ToLower(f), ".gz") {
			if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
				var plain bytes.Buffer
				if _, err := plain.ReadFrom(z); err == nil {
					b = plain.Bytes()
					ps := sha256.Sum256(b)
					plainSum = hex.EncodeToString(ps[:])
				}
			}
		}
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		w.Write(b)
		w.Close()
		dir := OutboxDir(st)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return n, err
		}
		if err := store.WriteFileAtomic(filepath.Join(dir, scapPrefix+plainSum[:16]+scapExt), gz.Bytes(), 0o640); err != nil {
			return n, err
		}
		st.State.ScapSent[id] = now
		n++
	}
	return n, nil
}

// QueuedScap is the number of scan results waiting in the outbox.
func QueuedScap(st *store.Store) int {
	list, _ := listOutbox(st, scapExt)
	return len(list)
}

// DeliverScap copies waiting scan results into the collector's inbox,
// each signed as from host (DESIGN1).
func DeliverScap(st *store.Store, inbox, host string) (int, error) {
	if !IsInbox(inbox) {
		return 0, fmt.Errorf("%w: %s", ErrNoInbox, inbox)
	}
	list, err := listOutbox(st, scapExt)
	if err != nil {
		return 0, err
	}
	key, err := signingKey(st)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range list {
		src := filepath.Join(OutboxDir(st), name)
		plain, err := gzipSHA256(src)
		if err != nil {
			return sent, fmt.Errorf("SCAP result %s: %w", name, err)
		}
		sig, err := makeSig(key, src, "scap", host, st.State.Send.ID, scapWhat(plain), time.Now())
		if err != nil {
			return sent, err
		}
		base := scapPrefix + st.State.Send.ID + "_" + strings.TrimSuffix(strings.TrimPrefix(name, scapPrefix), scapExt)
		if _, err := drop(src, inbox, base, scapExt, sig); err != nil {
			return sent, fmt.Errorf("copy SCAP result %s to %s: %w", name, inbox, err)
		}
		if err := os.Remove(src); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// importScap checks a delivered scan result and files it under the
// computer it is for. Its contents must match the hash in its name
// (scap_ID_HASH_RANDOM.xml.gz; earlier senders gave no random part).
func importScap(st *store.Store, dir, name string, dirs Dirs, now time.Time) error {
	rest := strings.TrimSuffix(strings.TrimPrefix(name, scapPrefix), scapExt)
	id, sum, _ := strings.Cut(rest, "_")
	sum, _, _ = strings.Cut(sum, "_")
	sum, _, _ = strings.Cut(sum, "-")
	if st.State.Send != nil && id == st.State.Send.ID {
		return fmt.Errorf("it was sent by this computer (a system cannot send to itself)")
	}
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() > maxBatchFile {
		return fmt.Errorf("it is %d MB, larger than Blackbox accepts (%d MB)", fi.Size()>>20, maxBatchFile>>20)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	var plain bytes.Buffer
	if err == nil {
		_, err = plain.ReadFrom(io.LimitReader(z, maxBatchBytes))
	}
	if err != nil {
		if truncated(err) {
			if writing(fi, now) {
				return errWriting // its sender may still be writing it (DESIGN1)
			}
			return incomplete(err)
		}
		return fmt.Errorf("it can't be read: %v", err)
	}
	h := sha256.Sum256(plain.Bytes())
	if len(sum) < 16 || !strings.HasPrefix(hex.EncodeToString(h[:]), strings.ToLower(sum)) {
		return fmt.Errorf("its contents do not match the hash in its name (%s): altered or damaged", sum)
	}
	res, err := scap.ReadFile(path)
	if err != nil {
		return fmt.Errorf("not a SCAP result: %w", err)
	}
	host := store.SystemKey(res[0].Host)
	if host == "" {
		host = "UNKNOWN"
	}
	if !archive.UsableHost(host) {
		return fmt.Errorf("it gives the computer as %q, which is not a usable name", res[0].Host)
	}
	// Its signature, in NAME.sig, written before it (DESIGN1): the
	// computer that sent it, and the hash of the result.
	sig, pub, err := readSig(path, "scap")
	switch {
	case errors.Is(err, errSigIncomplete) && writing(fi, now):
		return errWriting
	case err != nil:
		return err
	case sig != nil && (sig.SenderID != id || sig.What != scapWhat(hex.EncodeToString(h[:]))):
		return fmt.Errorf("its signature is for sender %s %s, not this result", sig.SenderID, sig.What)
	case sig != nil && !hostIn([]string{sig.Host}, host):
		return fmt.Errorf("it is a scan of %s, but it was signed by %s", host, sig.Host)
	}
	signer := host
	if sig != nil {
		signer = sig.Host
	}
	if v, err := judge(st, delivery{host: signer, id: id, pub: pub}, dirs, now); v != accept {
		return err
	}
	dest := filepath.Join(dirs.Scap, safeName(host))
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	if err := store.WriteFileAtomic(filepath.Join(dest, name), b, 0o640); err != nil {
		return err
	}
	os.Remove(path + sigExt)
	return os.Remove(path)
}

// gzipSHA256 is the SHA-256 of a gzip file's contents.
func gzipSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(z, maxBatchBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
