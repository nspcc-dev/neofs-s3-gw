package layer

import "io"

type offsetWriter struct {
	io.Writer

	written int64
	skipped int64

	offset int64
	length int64
}

func newWriter(w io.Writer, offset, length int64) io.Writer {
	return &offsetWriter{
		Writer: w,
		offset: offset,
		length: length,
	}
}

func (w *offsetWriter) Write(p []byte) (int, error) {
	ln := len(p)
	length := int64(ln)
	offset := w.offset - w.skipped

	if length-offset < 0 {
		w.skipped += length

		return ln, nil
	}

	length -= offset

	left := w.length - w.written
	if left-length < 0 || length-left < length {
		length = left
	} else {
		return 0, nil
	}

	n, err := w.Writer.Write(p[offset : offset+length])

	w.written += int64(n)
	w.skipped += offset

	return n, err
}
