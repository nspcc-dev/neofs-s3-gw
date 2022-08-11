package encryption

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	errorsStd "errors"
	"fmt"
	"io"

	"github.com/minio/sio"
)

// Params contains encryption key info.
type Params struct {
	enabled     bool
	customerKey []byte
}

// ObjectEncryption stores parsed object encryption headers.
type ObjectEncryption struct {
	Enabled   bool
	Algorithm string
	HMACKey   string
	HMACSalt  string
}

type encryptedPart struct {
	size          uint64
	encryptedSize uint64
}

// Range stores payload interval.
type Range struct {
	Start uint64
	End   uint64
}

// Decrypter allows decrypt payload of encrypted object.
type Decrypter struct {
	reader      io.Reader
	decReader   io.Reader
	parts       []encryptedPart
	currentPart int
	encryption  Params

	rangeParam *Range

	partDataRemain  uint64
	encPartRangeLen uint64

	seqNumber uint64
	decLen    uint64
	skipLen   uint64

	ln  uint64
	off uint64
}

const (
	blockSize     = 1 << 16 // 64KB
	fullBlockSize = blockSize + 32
	aes256KeySize = 32
)

// NewParams creates new params to encrypt with provided key.
func NewParams(key []byte) (Params, error) {
	var p Params
	if len(key) != aes256KeySize {
		return p, fmt.Errorf("invalid key size: %d", len(key))
	}
	p.enabled = true
	p.customerKey = make([]byte, aes256KeySize)
	copy(p.customerKey, key)
	return p, nil
}

// Key returns encryption key as slice.
func (p Params) Key() []byte {
	return p.customerKey[:]
}

// Enabled returns true if key isn't empty.
func (p Params) Enabled() bool {
	return p.enabled
}

// HMAC computes salted HMAC.
func (p Params) HMAC() ([]byte, []byte, error) {
	mac := hmac.New(sha256.New, p.Key())

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, errorsStd.New("failed to init create salt")
	}

	mac.Write(salt)
	return mac.Sum(nil), salt, nil
}

// MatchObjectEncryption checks if encryption params are valid for provided object.
func (p Params) MatchObjectEncryption(encInfo ObjectEncryption) error {
	if p.Enabled() != encInfo.Enabled {
		return errorsStd.New("invalid encryption view")
	}

	if !encInfo.Enabled {
		return nil
	}

	hmacSalt, err := hex.DecodeString(encInfo.HMACSalt)
	if err != nil {
		return fmt.Errorf("invalid hmacSalt '%s': %w", encInfo.HMACSalt, err)
	}

	hmacKey, err := hex.DecodeString(encInfo.HMACKey)
	if err != nil {
		return fmt.Errorf("invalid hmacKey '%s': %w", encInfo.HMACKey, err)
	}

	mac := hmac.New(sha256.New, p.Key())
	mac.Write(hmacSalt)
	expectedHmacKey := mac.Sum(nil)
	if !bytes.Equal(expectedHmacKey, hmacKey) {
		return errorsStd.New("mismatched hmac key")
	}

	return nil
}

// NewMultipartDecrypter creates new decrypted that can decrypt multipart object
// that contains concatenation of encrypted parts.
func NewMultipartDecrypter(p Params, decryptedObjectSize uint64, partsSizes []uint64, r *Range) (*Decrypter, error) {
	parts := make([]encryptedPart, len(partsSizes))

	for i, size := range partsSizes {
		encPartSize, err := sio.EncryptedSize(size)
		if err != nil {
			return nil, fmt.Errorf("compute encrypted size: %w", err)
		}

		parts[i] = encryptedPart{
			size:          size,
			encryptedSize: encPartSize,
		}
	}

	rangeParam := r
	if rangeParam == nil {
		rangeParam = &Range{
			End: decryptedObjectSize - 1,
		}
	}

	return newDecrypter(p, parts, rangeParam)
}

// NewDecrypter creates decrypter for regular encrypted object.
func NewDecrypter(p Params, encryptedObjectSize uint64, r *Range) (*Decrypter, error) {
	decSize, err := sio.DecryptedSize(encryptedObjectSize)
	if err != nil {
		return nil, fmt.Errorf("compute decrypted size: %w", err)
	}

	parts := []encryptedPart{{
		size:          decSize,
		encryptedSize: encryptedObjectSize,
	}}

	return newDecrypter(p, parts, r)
}

func newDecrypter(p Params, parts []encryptedPart, r *Range) (*Decrypter, error) {
	if !p.Enabled() {
		return nil, errorsStd.New("couldn't create decrypter with disabled encryption")
	}

	if r != nil && r.Start > r.End {
		return nil, fmt.Errorf("invalid range: %d %d", r.Start, r.End)
	}

	decReader := &Decrypter{
		parts:      parts,
		rangeParam: r,
		encryption: p,
	}

	decReader.initRangeParams()

	return decReader, nil
}

// DecryptedLength is actual (decrypted) length of data.
func (d Decrypter) DecryptedLength() uint64 {
	return d.decLen
}

// EncryptedLength is size of encrypted data that should be read for successful decryption.
func (d Decrypter) EncryptedLength() uint64 {
	return d.ln
}

// EncryptedOffset is offset of encrypted payload for successful decryption.
func (d Decrypter) EncryptedOffset() uint64 {
	return d.off
}

func (d *Decrypter) initRangeParams() {
	d.partDataRemain = d.parts[d.currentPart].size
	d.encPartRangeLen = d.parts[d.currentPart].encryptedSize
	if d.rangeParam == nil {
		d.decLen = d.partDataRemain
		d.ln = d.encPartRangeLen
		return
	}

	start, end := d.rangeParam.Start, d.rangeParam.End

	var sum, encSum uint64
	var partStart int
	for i, part := range d.parts {
		if start < sum+part.size {
			partStart = i
			break
		}
		sum += part.size
		encSum += part.encryptedSize
	}

	d.skipLen = (start - sum) % blockSize
	d.seqNumber = (start - sum) / blockSize
	encOffPart := d.seqNumber * fullBlockSize
	d.off = encSum + encOffPart
	d.encPartRangeLen = d.encPartRangeLen - encOffPart
	d.partDataRemain = d.partDataRemain + sum - start

	var partEnd int
	for i, part := range d.parts[partStart:] {
		index := partStart + i
		if end < sum+part.size {
			partEnd = index
			break
		}
		sum += part.size
		encSum += part.encryptedSize
	}

	payloadPartEnd := (end - sum) / blockSize
	endEnc := encSum + (payloadPartEnd+1)*fullBlockSize

	endPartEnc := encSum + d.parts[partEnd].encryptedSize
	if endPartEnc < endEnc {
		endEnc = endPartEnc
	}
	d.ln = endEnc - d.off
	d.decLen = end - start + 1

	if d.ln < d.encPartRangeLen {
		d.encPartRangeLen = d.ln
	}
	if d.decLen < d.partDataRemain {
		d.partDataRemain = d.decLen
	}
}

func (d *Decrypter) updateRangeParams() {
	d.partDataRemain = d.parts[d.currentPart].size
	d.encPartRangeLen = d.parts[d.currentPart].encryptedSize
	d.seqNumber = 0
	d.skipLen = 0
}

// Read implements io.Reader.
func (d *Decrypter) Read(p []byte) (int, error) {
	if uint64(len(p)) < d.partDataRemain {
		n, err := d.decReader.Read(p)
		if err != nil {
			return n, err
		}
		d.partDataRemain -= uint64(n)
		return n, nil
	}

	n1, err := io.ReadFull(d.decReader, p[:d.partDataRemain])
	if err != nil {
		return n1, err
	}

	d.currentPart++
	if d.currentPart == len(d.parts) {
		return n1, io.EOF
	}

	d.updateRangeParams()

	err = d.initNextDecReader()
	if err != nil {
		return n1, err
	}

	n2, err := d.decReader.Read(p[n1:])
	if err != nil {
		return n1 + n2, err
	}

	d.partDataRemain -= uint64(n2)

	return n1 + n2, nil
}

// SetReader sets encrypted payload reader that should be decrypted.
// Must be invoked before any read.
func (d *Decrypter) SetReader(r io.Reader) error {
	d.reader = r
	return d.initNextDecReader()
}

func (d *Decrypter) initNextDecReader() error {
	if d.reader == nil {
		return errorsStd.New("reader isn't set")
	}

	r, err := sio.DecryptReader(io.LimitReader(d.reader, int64(d.encPartRangeLen)),
		sio.Config{
			MinVersion:     sio.Version20,
			SequenceNumber: uint32(d.seqNumber),
			Key:            d.encryption.Key(),
			CipherSuites:   []byte{sio.AES_256_GCM},
		})
	if err != nil {
		return fmt.Errorf("couldn't create decrypter: %w", err)
	}

	if d.skipLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(d.skipLen)); err != nil {
			return fmt.Errorf("couldn't skip some bytes: %w", err)
		}
	}
	d.decReader = r

	return nil
}
