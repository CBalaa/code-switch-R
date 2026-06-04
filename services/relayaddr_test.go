package services

import "testing"

func TestRelayListenAddrDefaultsToLocalhost(t *testing.T) {
	if got := RelayListenAddr(""); got != "127.0.0.1:18100" {
		t.Fatalf("expected default relay bind addr 127.0.0.1:18100, got %q", got)
	}
}

func TestRelayClientBaseURLUsesLoopbackForWildcardBind(t *testing.T) {
	tests := map[string]string{
		"":                     "http://127.0.0.1:18100",
		"0.0.0.0:18100":        "http://127.0.0.1:18100",
		"http://0.0.0.0:18100": "http://127.0.0.1:18100",
		":18100":               "http://127.0.0.1:18100",
		"192.168.1.12:18100":   "http://192.168.1.12:18100",
	}

	for input, want := range tests {
		if got := RelayClientBaseURL(input); got != want {
			t.Fatalf("RelayClientBaseURL(%q) = %q, want %q", input, got, want)
		}
	}
}
