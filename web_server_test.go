package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchProviderFaviconReadsOnlyHTMLHead(t *testing.T) {
	png := []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
		0x89,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			http.NotFound(w, r)
		case "/logo.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><link rel="icon" type="image/png" href="/logo.png"></head><body>`))
			_, _ = w.Write(bytes.Repeat([]byte("x"), 300*1024))
			_, _ = w.Write([]byte(`</body></html>`))
		}
	}))
	defer server.Close()

	data, contentType, err := fetchProviderFavicon(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("fetchProviderFavicon failed: %v", err)
	}
	if contentType != "image/png" {
		t.Fatalf("contentType = %q, want image/png", contentType)
	}
	if !bytes.Equal(data, png) {
		t.Fatal("favicon data mismatch")
	}
}

func TestFetchProviderFaviconSkipsHTMLFaviconICO(t *testing.T) {
	png := []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
		0x89,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>not an icon</title></head></html>`))
		case "/static/favicon.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><link rel="icon" type="image/png" href="/static/favicon.png"></head></html>`))
		}
	}))
	defer server.Close()

	data, contentType, err := fetchProviderFavicon(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("fetchProviderFavicon failed: %v", err)
	}
	if contentType != "image/png" {
		t.Fatalf("contentType = %q, want image/png", contentType)
	}
	if !bytes.Equal(data, png) {
		t.Fatal("favicon data mismatch")
	}
}
