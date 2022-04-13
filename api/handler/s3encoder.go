package handler

import (
	"strings"
)

type encoding int

const (
	encodePathSegment encoding = iota
	encodeQueryComponent
)

const (
	urlEncodingType = "url"
	upperhex        = "0123456789ABCDEF"
)

func shouldEscape(c byte) bool {
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}

	switch c {
	case '-', '_', '.', '/', '*':
		return false
	}
	return true
}

// s3URLEncode is based on url.QueryEscape() code
// while considering some S3 exceptions.
func s3URLEncode(s string, mode encoding) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			if c == ' ' && mode == encodeQueryComponent {
				spaceCount++
			} else {
				hexCount++
			}
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	var buf [64]byte
	var t []byte

	required := len(s) + 2*hexCount
	if required <= len(buf) {
		t = buf[:required]
	} else {
		t = make([]byte, required)
	}

	if hexCount == 0 {
		copy(t, s)
		for i := 0; i < len(s); i++ {
			if s[i] == ' ' {
				t[i] = '+'
			}
		}
		return string(t)
	}

	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' && mode == encodeQueryComponent:
			t[j] = '+'
			j++
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = upperhex[c>>4]
			t[j+2] = upperhex[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func s3QueryEncode(name string, encodingType string) (result string) {
	if encodingType == "" {
		return name
	}
	encodingType = strings.ToLower(encodingType)
	switch encodingType {
	case urlEncodingType:
		return s3URLEncode(name, encodeQueryComponent)
	}
	return name
}

func s3PathEncode(name string, encodingType string) (result string) {
	if encodingType == "" {
		return name
	}
	encodingType = strings.ToLower(encodingType)
	switch encodingType {
	case urlEncodingType:
		return s3URLEncode(name, encodePathSegment)
	}
	return name
}
