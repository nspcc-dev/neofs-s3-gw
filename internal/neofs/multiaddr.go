package neofs

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

func nodeAddressToURI(addr string) (string, error) {
	if strings.HasPrefix(addr, "/") {
		return multiaddrToURI(addr)
	}

	var hostPort = addr
	if scheme, rest, ok := strings.Cut(addr, "://"); ok {
		if scheme != "grpc" && scheme != "grpcs" {
			return "", fmt.Errorf("unsupported scheme %q in %q", scheme, addr)
		}

		hostPort = rest
	}

	if err := validateHostPort(hostPort); err != nil {
		return "", fmt.Errorf("invalid address %q: %w", addr, err)
	}

	return addr, nil
}

// multiaddrToURI converts a multiaddress "/dns4/host/tcp/8080" into "host:port" or "grpcs://host:port".
func multiaddrToURI(addr string) (string, error) {
	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return "", fmt.Errorf("invalid multiaddress %q: %w", addr, err)
	}

	network, host, err := manet.DialArgs(ma)
	if err != nil {
		return "", fmt.Errorf("invalid multiaddress %q: %w", addr, err)
	}

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return "", fmt.Errorf("unsupported multiaddress transport %q in %q", network, addr)
	}

	if err = validateHostPort(host); err != nil {
		return "", fmt.Errorf("invalid multiaddress %q: %w", addr, err)
	}

	if !isTLS(ma) {
		return host, nil
	}

	var u = url.URL{Scheme: "grpcs", Host: host}
	return u.String(), nil
}

func isTLS(ma multiaddr.Multiaddr) bool {
	for _, protocol := range ma.Protocols() {
		if protocol.Code == multiaddr.P_TLS {
			return true
		}
	}

	return false
}

func validateHostPort(hostPort string) error {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return err
	}

	if host == "" {
		return fmt.Errorf("missing host")
	}

	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port %q: %w", port, err)
	}

	return nil
}
