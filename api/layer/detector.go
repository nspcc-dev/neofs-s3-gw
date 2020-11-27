package layer

import (
	"io"
	"net/http"
	"sync"
)

type detector struct {
	io.Reader
	sync.Once

	contentType string
}

func newDetector(r io.Reader) *detector {
	return &detector{Reader: r}
}

func (d *detector) Read(data []byte) (int, error) {
	d.Do(func() {
		d.contentType = http.DetectContentType(data)
	})

	return d.Reader.Read(data)
}
