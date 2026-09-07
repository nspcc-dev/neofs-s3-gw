package neofs

import (
	"fmt"
	"strings"
)

// nodeAddressToURI checks that a network map address in "host:port" or
// "grpc(s)://host:port" form has a supported scheme and returns it as is.
func nodeAddressToURI(addr string) (string, error) {
	if scheme, _, ok := strings.Cut(addr, "://"); ok {
		if scheme != "grpc" && scheme != "grpcs" {
			return "", fmt.Errorf("unsupported scheme %q in %q", scheme, addr)
		}
	}

	return addr, nil
}
