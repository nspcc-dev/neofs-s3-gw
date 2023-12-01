// Copyright 2009 The Go Authors. All rights reserved.
//
// Original is net/http/internal/chunked.go

package v4

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

const maxLineLength = 4096 // assumed <= bufio.defaultBufSize

var (
	// ErrLineTooLong appears if chunk header exceeds maxLineLength.
	ErrLineTooLong = errors.New("header line too long")

	// ErrInvalidChunkSignature appears if passed chunk signature differs from calculated.
	ErrInvalidChunkSignature = errors.New("invalid chunk signature")

	// ErrMissingSeparator appears if chunk header doesn't contain ';' separator.
	ErrMissingSeparator = errors.New("missing header separator")

	// ErrNoChunksSeparator appears if chunks not properly separated between each other.
	// They should be divided with \r\n bytes.
	ErrNoChunksSeparator = errors.New("no chunk separator")
)

// NewChunkedReader returns a new chunkedReader that translates the data read from r
// out of HTTP "chunked" format before returning it.
// The chunkedReader returns io.EOF when the final 0-length chunk is read.
func NewChunkedReader(r io.ReadCloser, streamSigner *ChunkSigner) io.ReadCloser {
	return &chunkedReader{
		r: bufio.NewReader(r),
		// bufio.Reader can't be closed, thus left link to the original reader to close it later.
		origReader:   r,
		streamSigner: streamSigner,
	}
}

type chunkedReader struct {
	chunkHash      hash.Hash
	chunkSignature string
	r              *bufio.Reader
	origReader     io.ReadCloser
	n              uint64 // unread bytes in chunk
	err            error
	buf            [2]byte
	checkEnd       bool // whether need to check for \r\n chunk footer
	streamSigner   *ChunkSigner
}

// Close implements [io.ReadCloser].
func (cr *chunkedReader) Close() (err error) {
	return cr.origReader.Close()
}

func (cr *chunkedReader) beginChunk() {
	// chunk-size CRLF
	var line, chunkSignature []byte
	line, chunkSignature, cr.err = readChunkLine(cr.r)
	if cr.err != nil {
		return
	}
	cr.n, cr.err = parseHexUint(line)
	if cr.err != nil {
		return
	}

	if err := cr.validatePreviousChunkData(); err != nil {
		cr.err = err
		return
	}

	// creating instance here to avoid validating non-existent chunk in the first validatePreviousChunkData call.
	if cr.chunkHash == nil {
		cr.chunkHash = sha256.New()
	} else {
		cr.chunkHash.Reset()
	}

	cr.chunkSignature = string(chunkSignature)

	if cr.n == 0 {
		if err := cr.validatePreviousChunkData(); err != nil {
			cr.err = err
			return
		}

		cr.err = io.EOF
	}
}

func (cr *chunkedReader) validatePreviousChunkData() error {
	if cr.chunkHash != nil {
		calculatedSignature, err := cr.streamSigner.GetSignatureByHash(cr.chunkHash)
		if err != nil {
			return fmt.Errorf("GetSignature: %w", err)
		}

		if cr.chunkSignature != hex.EncodeToString(calculatedSignature) {
			return ErrInvalidChunkSignature
		}
	}

	return nil
}

func (cr *chunkedReader) chunkHeaderAvailable() bool {
	n := cr.r.Buffered()
	if n > 0 {
		peek, _ := cr.r.Peek(n)
		return bytes.IndexByte(peek, '\n') >= 0
	}
	return false
}

// Read gets data from reader. Implements [io.ReadCloser].
func (cr *chunkedReader) Read(b []uint8) (n int, err error) {
	for cr.err == nil {
		if cr.checkEnd {
			if n > 0 && cr.r.Buffered() < 2 {
				// We have some data. Return early (per the io.Reader
				// contract) instead of potentially blocking while
				// reading more.
				break
			}
			if _, cr.err = io.ReadFull(cr.r, cr.buf[:2]); cr.err == nil {
				if string(cr.buf[:]) != "\r\n" {
					cr.err = ErrNoChunksSeparator
					break
				}
			} else {
				if cr.err == io.EOF {
					cr.err = io.ErrUnexpectedEOF
				}
				break
			}
			cr.checkEnd = false
		}
		if cr.n == 0 {
			if n > 0 && !cr.chunkHeaderAvailable() {
				// We've read enough. Don't potentially block
				// reading a new chunk header.
				break
			}
			cr.beginChunk()
			continue
		}
		if len(b) == 0 {
			break
		}
		rbuf := b
		if uint64(len(rbuf)) > cr.n {
			rbuf = rbuf[:cr.n]
		}
		var n0 int
		n0, cr.err = cr.r.Read(rbuf)
		n += n0
		b = b[n0:]
		cr.n -= uint64(n0)
		// Hashing chunk data to calculate the signature.
		// rbuf may contain payload and empty bytes, taking only payload.
		if _, err = cr.chunkHash.Write(rbuf[:n0]); err != nil {
			cr.err = err
			break
		}

		// If we're at the end of a chunk, read the next two
		// bytes to verify they are "\r\n".
		if cr.n == 0 && cr.err == nil {
			cr.checkEnd = true
		} else if cr.err == io.EOF {
			cr.err = io.ErrUnexpectedEOF
		}
	}
	return n, cr.err
}

// Read a line of bytes (up to \n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are owned by the bufio.Reader
// so they are only valid until the next bufio read.
func readChunkLine(b *bufio.Reader) ([]byte, []byte, error) {
	p, err := b.ReadSlice('\n')
	if err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		} else if errors.Is(err, bufio.ErrBufferFull) {
			err = ErrLineTooLong
		}
		return nil, nil, err
	}
	if len(p) >= maxLineLength {
		return nil, nil, ErrLineTooLong
	}

	var signaturePart []byte

	p = trimTrailingWhitespace(p)
	p, signaturePart, err = removeChunkExtension(p)
	if err != nil {
		return nil, nil, err
	}

	pos := bytes.IndexByte(signaturePart, '=')
	if pos == -1 {
		return nil, nil, errors.New("chunk header is malformed")
	}

	// even if '=' is the latest symbol, the new slice will be just empty
	return p, signaturePart[pos+1:], nil
}

func trimTrailingWhitespace(b []byte) []byte {
	for len(b) > 0 && isASCIISpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

var semi = []byte(";")

// removeChunkExtension removes any chunk-extension from p.
// For example,
//
//	"0" => "0"
//	"0;chunk-signature" => "0"
//	"0;chunk-signature=val" => "0"
//	`0;chunk-signature="quoted string"` => "0"
func removeChunkExtension(p []byte) ([]byte, []byte, error) {
	var (
		chunkSignature []byte
		found          bool
	)
	p, chunkSignature, found = bytes.Cut(p, semi)
	if !found {
		return nil, nil, ErrMissingSeparator
	}

	return p, chunkSignature, nil
}

func parseHexUint(v []byte) (n uint64, err error) {
	for i, b := range v {
		switch {
		case '0' <= b && b <= '9':
			b = b - '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, errors.New("invalid byte in chunk length")
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}
