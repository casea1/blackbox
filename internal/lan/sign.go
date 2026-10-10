package lan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Signed deliveries (DESIGN1). Each sender has its own signing key,
// made at install or upgrade, kept in its data folder (Administrators
// and SYSTEM only on Windows, root 0600 on Linux) and never sent
// anywhere but as its public half. It signs every delivery: a batch in
// its end marker, an original-log archive or a SCAP result in a .sig
// file written next to it, under the same unique name, before it.
//
// The algorithm is Ed25519 (FIPS 186-5). It is inside Go's FIPS 140-3
// module (crypto/internal/fips140/ed25519, module v1.0.0), and works
// with GODEBUG=fips140=only, so FIPS builds use it unchanged.
//
// The collector pins each computer to the first key it signs with
// (trust on first use), and refuses or holds what does not match: see
// trust.go.

// KeyFile is the sender's private key, in its data folder.
const KeyFile = "sender-key.pem"

// sigAlg is the only signature algorithm made or accepted.
const sigAlg = "ed25519"

// sigExt is the signature file next to an archive or SCAP result.
const sigExt = ".sig"

// Key is a sender's signing key.
type Key struct {
	priv ed25519.PrivateKey
	// Public is the public key, PKIX DER: what the collector pins.
	Public []byte
}

// Fingerprint is the key's fingerprint: SHA256: and the base64 SHA-256
// of its public key, as OpenSSH writes them.
func (k *Key) Fingerprint() string { return Fingerprint(k.Public) }

// Fingerprint of a public key (PKIX DER).
func Fingerprint(pub []byte) string {
	s := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
}

// ShortFingerprint is the start of a fingerprint, for reports:
// "SHA256:ab12cd34…".
func ShortFingerprint(fp string) string {
	if len(fp) <= 15 {
		return fp
	}
	return fp[:15] + "…"
}

// KeyPath is where a data folder keeps its signing key.
func KeyPath(dataDir string) string { return filepath.Join(dataDir, KeyFile) }

// LoadKey reads the data folder's signing key; os.ErrNotExist if it has
// none yet.
func LoadKey(dataDir string) (*Key, error) {
	b, err := os.ReadFile(KeyPath(dataDir))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a Blackbox signing key", KeyPath(dataDir))
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", KeyPath(dataDir), err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", KeyPath(dataDir))
	}
	pub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, Public: pub}, nil
}

// EnsureKey returns the data folder's signing key, making one if it has
// none. made says it was made now.
func EnsureKey(dataDir string) (k *Key, made bool, err error) {
	k, err = LoadKey(dataDir)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return k, false, err
	}
	k, err = writeNewKey(dataDir, false)
	return k, err == nil, err
}

// NewKey replaces the data folder's signing key ("blackbox send
// --new-id", for a computer cloned with its data folder). The old key is
// removed: the clone must not sign as the original.
func NewKey(dataDir string) (*Key, error) { return writeNewKey(dataDir, true) }

func writeNewKey(dataDir string, replace bool) (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := KeyPath(dataDir)
	flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
	if replace {
		// Written aside first, so a failure never leaves no key.
		tmp := path + ".new"
		os.Remove(tmp)
		if err := writeKeyFile(tmp, data, flags); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return nil, err
		}
	} else if err := writeKeyFile(path, data, flags); err != nil {
		return nil, err
	}
	return &Key{priv: priv, Public: pub}, nil
}

func writeKeyFile(path string, data []byte, flags int) error {
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return restrictKey(path)
}

// Signature is a signature on a delivery.
type Signature struct {
	Alg  string    `json:"alg"`
	Key  string    `json:"key"` // public key, PKIX DER, base64
	Time time.Time `json:"time"`
	Sig  string    `json:"sig"` // base64
}

// statement is what is signed: the kind of delivery, its content hash,
// the computer and what identifies the delivery (a batch: sender ID and
// number; an archive: its period; a SCAP result: its file hash), and the
// time it was signed. One field per line, in this order.
func statement(kind, sum, host, senderID, what string, t time.Time) []byte {
	return []byte(strings.Join([]string{
		"blackbox-delivery-1",
		"kind=" + kind,
		"sha256=" + strings.ToLower(sum),
		"host=" + host,
		"sender_id=" + senderID,
		"what=" + what,
		"time=" + t.UTC().Format(time.RFC3339Nano),
	}, "\n") + "\n")
}

func (k *Key) sign(msg []byte, t time.Time) *Signature {
	return &Signature{Alg: sigAlg, Key: base64.StdEncoding.EncodeToString(k.Public), Time: t.UTC(),
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, msg))}
}

// verify checks s over the statement, and returns the signer's public key.
func (s *Signature) verify(kind, sum, host, senderID, what string) ([]byte, error) {
	if s.Alg != sigAlg {
		return nil, fmt.Errorf("its signature uses %q, which Blackbox does not accept", s.Alg)
	}
	pub, err := base64.StdEncoding.DecodeString(s.Key)
	if err != nil {
		return nil, errors.New("its signature's key can't be read")
	}
	k, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return nil, errors.New("its signature's key can't be read")
	}
	ek, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("its signature's key is not an Ed25519 key")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil || !ed25519.Verify(ek, statement(kind, sum, host, senderID, what, s.Time), sig) {
		return nil, errors.New("its signature does not match its contents (altered, or not signed by the key it names)")
	}
	return pub, nil
}

func seqWhat(seq uint64) string { return "seq " + strconv.FormatUint(seq, 10) }

// SignBatch adds a signature to a batch file's end marker. The records
// before it are left byte for byte as they are, so the batch's hash (what
// "already imported" compares) does not change.
func SignBatch(data []byte, k *Key, now time.Time) ([]byte, error) {
	b, err := Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(zr, maxBatchBytes+1))
	if err != nil {
		return nil, err
	}
	plain = bytes.TrimSuffix(plain, []byte("\n"))
	i := bytes.LastIndexByte(plain, '\n')
	if i < 0 {
		return nil, errors.New("batch has no end marker")
	}
	var rec record
	if err := json.Unmarshal(plain[i+1:], &rec); err != nil || rec.End == nil {
		return nil, errors.New("batch has no end marker")
	}
	rec.End.Sig = k.sign(statement("batch", rec.End.SHA256, b.Sender, b.SenderID, seqWhat(b.Seq), now), now)
	end, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(plain[:i+1])
	zw.Write(append(end, '\n'))
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// verifyBatch checks a decoded batch's signature, and returns the
// signer's public key (nil for an unsigned batch).
func verifyBatch(b *Batch) ([]byte, error) {
	if b.Sig == nil {
		return nil, nil
	}
	return b.Sig.verify("batch", b.Sum, b.Sender, b.SenderID, seqWhat(b.Seq))
}

// sigFile is the .sig next to an archive or SCAP result.
type sigFile struct {
	Format   string `json:"format"` // "blackbox-sig-1"
	Kind     string `json:"kind"`   // archive | scap
	Host     string `json:"host"`
	SenderID string `json:"sender_id"`
	SHA256   string `json:"sha256"` // of the file
	What     string `json:"what"`   // archive: "FROM/TO" (UTC); SCAP: "hash " and its content's SHA-256
	Signature
}

const sigFormat = "blackbox-sig-1"

func archiveWhat(from, to time.Time) string {
	return from.UTC().Format(time.RFC3339) + "/" + to.UTC().Format(time.RFC3339)
}

func scapWhat(plainSum string) string { return "hash " + strings.ToLower(plainSum) }

// makeSig signs a file for delivery.
func makeSig(k *Key, path, kind, host, senderID, what string, now time.Time) ([]byte, error) {
	sum, err := fileSHA256(path)
	if err != nil {
		return nil, err
	}
	s := sigFile{Format: sigFormat, Kind: kind, Host: host, SenderID: senderID, SHA256: sum, What: what}
	s.Signature = *k.sign(statement(kind, sum, host, senderID, what, now), now)
	return json.MarshalIndent(s, "", "  ")
}

// readSig reads and checks the .sig next to path, if there is one: nil,
// nil when there is none. It returns what it says and the signer's key.
func readSig(path, kind string) (*sigFile, []byte, error) {
	b, _, err := readInbox(path+sigExt, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("its signature file can't be read: %v", err)
	}
	var s sigFile
	if err := json.Unmarshal(b, &s); err != nil || s.Format != sigFormat {
		return nil, nil, errSigIncomplete
	}
	if s.Kind != kind {
		return nil, nil, fmt.Errorf("its signature is for a %s, not a %s", s.Kind, kind)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(sum, s.SHA256) {
		return nil, nil, errors.New("its contents do not match its signature (altered, or cut short)")
	}
	pub, err := s.verify(kind, s.SHA256, s.Host, s.SenderID, s.What)
	if err != nil {
		return nil, nil, err
	}
	return &s, pub, nil
}

// errSigIncomplete: a .sig that can't be read whole (still being written,
// or damaged).
var errSigIncomplete = errors.New("its signature file is incomplete or damaged")

func fileSHA256(path string) (string, error) {
	f, _, err := openInbox(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReader(f)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
