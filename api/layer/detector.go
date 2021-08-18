package layer

import (
	"io"
	"net/http"
)

type (
	detector struct {
		io.Reader
		err  error
		data []byte
	}
	errReader struct {
		data   []byte
		err    error
		offset int
	}
)

const contentTypeDetectSize = 512

func newReader(data []byte, err error) *errReader {
	return &errReader{data: data, err: err}
}

func (r *errReader) Read(b []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.offset:])
	r.offset += n
	if r.offset >= len(r.data) {
		return n, r.err
	}
	return n, nil
}

func newDetector(reader io.Reader) *detector {
	return &detector{
		data:   make([]byte, contentTypeDetectSize),
		Reader: reader,
	}
}

func (d *detector) Detect() (string, error) {
	n, err := d.Reader.Read(d.data)
	if err != nil && err != io.EOF {
		d.err = err
		return "", err
	}
	d.data = d.data[:n]
	return http.DetectContentType(d.data), nil
}

func (d *detector) MultiReader() io.Reader {
	return io.MultiReader(newReader(d.data, d.err), d.Reader)
}
