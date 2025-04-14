// Copyright 2009 The Go Authors. All rights reserved.
//
// Original is net/http/internal/chunked.go

package v4

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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

	// ErrNoChunksSeparator appears if chunks not properly separated between each other.
	// They should be divided with \r\n bytes.
	ErrNoChunksSeparator = errors.New("no chunk separator")

	// ErrInvalidByteInChunkLength appears if chunk header has invalid encoding.
	ErrInvalidByteInChunkLength = errors.New("invalid byte in chunk length")

	errInvalidChunkEncoding = errors.New("invalid chunk encoding")
)

type readerState int

const (
	readChunkHeader readerState = iota
	readChunkPayload
	verifyChunkSignature
	readChunkCRLF
	exit
	readTrailerChunk
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
		chunkHash:    sha256.New(),
		nextState:    readChunkHeader,
	}
}

// NewChunkedReaderWithTrail returns a new chunkedReader that translates the data read from r
// out of HTTP "chunked" format before returning it. It uses trailing chunk to verify data consistency.
// The chunkedReader returns io.EOF when the final 0-length chunk is read.
func NewChunkedReaderWithTrail(r io.ReadCloser, amzTrailerHeader string) (io.ReadCloser, error) {
	checksumAlgorithm, err := detectChecksumType(amzTrailerHeader)
	if err != nil {
		return nil, err
	}

	return &chunkedReader{
		r: bufio.NewReader(r),
		// bufio.Reader can't be closed, thus left link to the original reader to close it later.
		origReader:        r,
		chunkHash:         sha256.New(),
		nextState:         readChunkHeader,
		checkSumAlgorithm: checksumAlgorithm.String(),
		checkSumWriter:    checksumWriter(checksumAlgorithm),
	}, nil
}

type chunkedReader struct {
	chunkHash         hash.Hash
	chunkSignature    string
	r                 *bufio.Reader
	origReader        io.ReadCloser
	n                 uint64 // unread bytes in chunk
	err               error
	streamSigner      *ChunkSigner
	nextState         readerState
	lastChunk         bool
	checkSumAlgorithm string
	checkSumWriter    hash.Hash
}

// Close implements [io.ReadCloser].
func (cr *chunkedReader) Close() (err error) {
	return cr.origReader.Close()
}

func (cr *chunkedReader) beginChunk() {
	// chunk-size CRLF
	var line []byte
	line, cr.err = readChunkLine(cr.r)
	if cr.err != nil {
		return
	}

	hexSize, signaturePart := removeChunkExtension(line)

	cr.n, cr.err = parseHexUint(hexSize)
	if cr.err != nil {
		return
	}

	if signaturePart != nil {
		cr.chunkSignature = string(signaturePart)
	}

	cr.chunkHash.Reset()

	if cr.n == 0 {
		cr.err = io.EOF
	}
}

func (cr *chunkedReader) validateChunkData() error {
	if cr.chunkHash != nil && cr.streamSigner != nil {
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

// Read gets data from reader. Implements [io.ReadCloser].
func (cr *chunkedReader) Read(b []uint8) (n int, err error) {
	for {
		switch cr.nextState {
		case readChunkHeader:
			cr.beginChunk()

			if cr.n == 0 && errors.Is(cr.err, io.EOF) {
				cr.nextState = readChunkCRLF
				cr.lastChunk = true
				continue
			}

			if cr.err != nil {
				return 0, cr.err
			}
			cr.nextState = readChunkPayload
		case readChunkPayload:
			// The incoming buffer is fulfilled.
			if len(b) == 0 {
				return n, nil
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
				return 0, err
			}

			if cr.checkSumWriter != nil {
				cr.checkSumWriter.Write(rbuf[:n0])
			}

			// If we're at the end of a chunk.
			if cr.n == 0 {
				cr.nextState = readChunkCRLF
			}
		case readChunkCRLF:
			err = peekCRLF(cr.r)
			isTrailingChunk := cr.n == 0 && cr.lastChunk

			if !isTrailingChunk {
				cr.err = readCRLF(cr.r)
			} else if err != nil && !errors.Is(err, errInvalidChunkEncoding) {
				cr.err = err
				return 0, errInvalidChunkEncoding
			}

			// Unsigned streaming upload.
			if cr.chunkSignature != "" {
				cr.nextState = verifyChunkSignature
			} else if cr.lastChunk {
				cr.nextState = readTrailerChunk
			} else {
				cr.nextState = readChunkHeader
			}
		case verifyChunkSignature:
			if err = cr.validateChunkData(); err != nil {
				return 0, err
			}

			if cr.lastChunk {
				cr.nextState = exit
			} else {
				cr.nextState = readChunkHeader
			}
		case readTrailerChunk:
			extractedCheckSumAlgorithm, extractedChecksum := parseChunkChecksum(cr.r)
			if extractedCheckSumAlgorithm.String() != cr.checkSumAlgorithm {
				cr.err = fmt.Errorf("request header and trailed chunk checksum algorithm mismatch. %s vs %s", extractedCheckSumAlgorithm.String(), cr.checkSumAlgorithm)
				return 0, cr.err
			}

			base64Checksum := base64.StdEncoding.EncodeToString(cr.checkSumWriter.Sum(nil))
			if string(extractedChecksum) != base64Checksum {
				cr.err = errors.New("payload checksum does not match")
				return 0, cr.err
			}

			// Reading remaining CRLF.
			for range 2 {
				cr.err = readCRLF(cr.r)
			}

			cr.nextState = exit
		case exit:
			return n, io.EOF
		}
	}
}

func readCRLF(reader io.Reader) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(reader, buf[:2]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}

		return err
	}

	if string(buf[:]) != "\r\n" {
		return ErrNoChunksSeparator
	}

	return nil
}

func peekCRLF(reader *bufio.Reader) error {
	peeked, err := reader.Peek(2)
	if err != nil {
		return err
	}
	if err = checkCRLF(peeked); err != nil {
		return err
	}
	return nil
}

func checkCRLF(buf []byte) error {
	if string(buf[:]) != "\r\n" {
		return errInvalidChunkEncoding
	}
	return nil
}

// Read a line of bytes (up to \n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are owned by the bufio.Reader
// so they are only valid until the next bufio read.
func readChunkLine(b *bufio.Reader) ([]byte, error) {
	p, err := b.ReadSlice('\n')
	if err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		} else if errors.Is(err, bufio.ErrBufferFull) {
			err = ErrLineTooLong
		}
		return nil, err
	}
	if len(p) >= maxLineLength {
		return nil, ErrLineTooLong
	}

	return p, nil
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

// removeChunkExtension removes any chunk-extension from p.
// For example,
//
//	"0" => "0"
//	"0;chunk-signature" => "0"
//	"0;chunk-signature=val" => "0"
//	`0;chunk-signature="quoted string"` => "0"
func removeChunkExtension(p []byte) ([]byte, []byte) {
	p = trimTrailingWhitespace(p)
	pos := bytes.SplitN(p, []byte(";chunk-signature="), 2)
	if len(pos) == 1 {
		return pos[0], nil
	}

	return pos[0], pos[1]
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
			return 0, ErrInvalidByteInChunkLength
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}

func parseChunkChecksum(b *bufio.Reader) (checksumType, []byte) {
	bytesRead, err := readChunkLine(b)
	if err != nil {
		return checksumNone, nil
	}

	parts := bytes.SplitN(bytesRead, []byte(":"), 2)
	if len(parts) != 2 {
		return checksumNone, nil
	}

	var (
		checksumKey   = string(parts[0])
		checksumValue = trimTrailingWhitespace(parts[1])
	)

	extractedAlgorithm, err := detectChecksumType(checksumKey)
	if err != nil {
		return checksumNone, nil
	}

	return extractedAlgorithm, checksumValue
}
