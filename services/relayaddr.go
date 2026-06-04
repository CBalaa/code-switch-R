package services

import (
	"net"
	"net/url"
	"strings"
)

const DefaultRelayBindAddr = "127.0.0.1:18100"

func RelayListenAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return DefaultRelayBindAddr
	}
	return addr
}

func RelayClientBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = DefaultRelayBindAddr
	}

	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		parsed, err := url.Parse(addr)
		if err != nil {
			return strings.TrimRight(addr, "/")
		}

		if host, port, err := net.SplitHostPort(parsed.Host); err == nil {
			if isWildcardRelayHost(host) {
				parsed.Host = net.JoinHostPort("127.0.0.1", port)
			}
		}

		return strings.TrimRight(parsed.String(), "/")
	}

	hostPort := RelayListenAddr(addr)
	if strings.HasPrefix(hostPort, ":") {
		hostPort = "127.0.0.1" + hostPort
	}

	if host, port, err := net.SplitHostPort(hostPort); err == nil {
		if isWildcardRelayHost(host) {
			host = "127.0.0.1"
		}
		hostPort = net.JoinHostPort(host, port)
	}

	return "http://" + hostPort
}

func isWildcardRelayHost(host string) bool {
	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::":
		return true
	default:
		return false
	}
}
