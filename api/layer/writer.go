package layer

import "io"

type offsetWriter struct {
	io.Writer

	written int64
	skipped int64

	offset int64
	length int64
}

func newWriter(w io.Writer, offset, length int64) *offsetWriter {
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

	// Writer should write enough and stop writing
	// 1. When passed zero length, it should write all bytes except offset
	// 2. When the written buffer is almost filled (left < length),
	//    should write some bytes to fill up the buffer
	// 3. When the written buffer is filled, should stop to write

	if left := w.length - w.written; left == 0 && w.length != 0 {
		return 0, nil
	} else if left > 0 && left < length {
		length = left
	}

	n, err := w.Writer.Write(p[offset : offset+length])

	w.written += int64(n)
	w.skipped += offset

	return n, err
}
