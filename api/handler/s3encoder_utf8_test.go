package handler

import "testing"

func TestS3URLEncodeMultibyte(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"медиа/фото 1.jpg", "%D0%BC%D0%B5%D0%B4%D0%B8%D0%B0/%D1%84%D0%BE%D1%82%D0%BE%201.jpg"},
		{"café.txt", "caf%C3%A9.txt"},
		{"plain/key.txt", "plain/key.txt"},
		{"a b", "a%20b"},
	} {
		if got := s3URLEncode(tc.in, encodePathSegment); got != tc.want {
			t.Errorf("s3URLEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := s3URLEncode("a b", encodeQueryComponent); got != "a+b" {
		t.Errorf("query encode: got %q", got)
	}
}
