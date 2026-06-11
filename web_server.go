package main

import (
	"bytes"
	"codeswitch/services"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var errorType = reflect.TypeOf((*error)(nil)).Elem()

const (
	maxFaviconBytes         = 512 * 1024
	maxFaviconHTMLHeadBytes = 1024 * 1024
)

var faviconLinkPattern = regexp.MustCompile(`(?is)<link\b[^>]*>`)

type rpcRegistry struct {
	services map[string]any
}

func newRPCRegistry() *rpcRegistry {
	return &rpcRegistry{
		services: make(map[string]any),
	}
}

func (r *rpcRegistry) Register(name string, service any) {
	r.services[name] = service
}

func (r *rpcRegistry) Call(name string, args []json.RawMessage) (_ any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("rpc panic: %v", recovered)
		}
	}()

	methodSep := strings.LastIndex(name, ".")
	if methodSep <= 0 || methodSep == len(name)-1 {
		return nil, fmt.Errorf("invalid rpc name: %s", name)
	}

	serviceName := name[:methodSep]
	methodName := name[methodSep+1:]
	service, ok := r.services[serviceName]
	if !ok {
		return nil, fmt.Errorf("unknown service: %s", serviceName)
	}

	method := reflect.ValueOf(service).MethodByName(methodName)
	if !method.IsValid() {
		return nil, fmt.Errorf("unknown method: %s", name)
	}

	methodType := method.Type()
	if len(args) != methodType.NumIn() {
		return nil, fmt.Errorf("invalid argument count for %s: expected %d, got %d", name, methodType.NumIn(), len(args))
	}

	callArgs := make([]reflect.Value, methodType.NumIn())
	for i := 0; i < methodType.NumIn(); i++ {
		value, decodeErr := decodeRPCArg(args[i], methodType.In(i))
		if decodeErr != nil {
			return nil, fmt.Errorf("decode argument %d for %s: %w", i, name, decodeErr)
		}
		callArgs[i] = value
	}

	return unpackRPCResults(method.Call(callArgs))
}

func decodeRPCArg(raw json.RawMessage, targetType reflect.Type) (reflect.Value, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("null")
	}

	if bytes.Equal(raw, []byte("null")) {
		return reflect.Zero(targetType), nil
	}

	if targetType.Kind() == reflect.Interface {
		if targetType.NumMethod() > 0 {
			return reflect.Zero(targetType), fmt.Errorf("cannot decode into non-empty interface %s", targetType.String())
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return reflect.Zero(targetType), err
		}
		return reflect.ValueOf(value), nil
	}

	if targetType.Kind() == reflect.Pointer {
		value := reflect.New(targetType.Elem())
		if err := json.Unmarshal(raw, value.Interface()); err != nil {
			return reflect.Zero(targetType), err
		}
		return value, nil
	}

	value := reflect.New(targetType)
	if err := json.Unmarshal(raw, value.Interface()); err != nil {
		return reflect.Zero(targetType), err
	}
	return value.Elem(), nil
}

func unpackRPCResults(results []reflect.Value) (any, error) {
	switch len(results) {
	case 0:
		return nil, nil
	case 1:
		if results[0].Type().Implements(errorType) {
			if results[0].IsNil() {
				return nil, nil
			}
			return nil, results[0].Interface().(error)
		}
		return results[0].Interface(), nil
	default:
		last := results[len(results)-1]
		if last.Type().Implements(errorType) {
			if !last.IsNil() {
				return nil, last.Interface().(error)
			}
			if len(results) == 2 {
				return results[0].Interface(), nil
			}
			out := make([]any, 0, len(results)-1)
			for _, result := range results[:len(results)-1] {
				out = append(out, result.Interface())
			}
			return out, nil
		}

		out := make([]any, 0, len(results))
		for _, result := range results {
			out = append(out, result.Interface())
		}
		return out, nil
	}
}

type rpcCallRequest struct {
	Name string            `json:"name"`
	Args []json.RawMessage `json:"args"`
}

type rpcCallResponse struct {
	Data any `json:"data"`
}

type apiErrorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newAdminServer(rt *appRuntime) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.Use(adminSecurityMiddleware(rt.adminSecurity))

	registry := newRPCRegistry()
	rt.registerServices(registry)

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	registerAdminAuthRoutes(router, rt)

	authRequired := requireAdminSession(rt.adminAuth, rt.adminSecurity)
	originRequired := requireTrustedOrigin(rt.adminSecurity)

	router.POST("/api/wails/call", originRequired, authRequired, func(c *gin.Context) {
		var request rpcCallRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "invalid_request", Message: err.Error()},
			})
			return
		}

		result, err := registry.Call(request.Name, request.Args)
		if err != nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "rpc_error", Message: err.Error()},
			})
			return
		}

		c.JSON(http.StatusOK, rpcCallResponse{Data: result})
	})

	router.GET("/api/wails/events", authRequired, func(c *gin.Context) {
		streamEvents(c, rt.eventHub)
	})
	router.GET("/provider-favicon", authRequired, serveProviderFavicon)

	registerStaticRoutes(router, rt.staticDir)

	return &http.Server{
		Addr:              rt.adminAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func serveProviderFavicon(c *gin.Context) {
	siteURL, err := normalizeProviderSiteURL(c.Query("url"))
	if err != nil {
		c.Status(http.StatusNoContent)
		return
	}

	cachePath, err := faviconCachePath(siteURL)
	if err == nil {
		if data, readErr := os.ReadFile(cachePath); readErr == nil && len(data) > 0 {
			if contentType := detectFaviconContentType(data, cachePath, ""); contentType != "" {
				c.Header("Cache-Control", "public, max-age=604800")
				c.Data(http.StatusOK, contentType, data)
				return
			}
			_ = os.Remove(cachePath)
		}
	}

	data, contentType, err := fetchProviderFavicon(c.Request.Context(), siteURL)
	if err != nil || len(data) == 0 {
		c.Status(http.StatusNoContent)
		return
	}

	if cachePath != "" {
		if mkdirErr := os.MkdirAll(filepath.Dir(cachePath), 0o700); mkdirErr == nil {
			_ = os.WriteFile(cachePath, data, 0o600)
		}
	}

	c.Header("Cache-Control", "public, max-age=604800")
	c.Data(http.StatusOK, contentType, data)
}

func normalizeProviderSiteURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("missing host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func faviconCachePath(siteURL string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(siteURL))
	return filepath.Join(home, ".code-switch", "favicons", hex.EncodeToString(sum[:])+".bin"), nil
}

func fetchProviderFavicon(ctx context.Context, siteURL string) ([]byte, string, error) {
	parsed, err := url.Parse(siteURL)
	if err != nil {
		return nil, "", err
	}
	origin := parsed.Scheme + "://" + parsed.Host

	if data, contentType, err := fetchFaviconCandidate(ctx, origin+"/favicon.ico"); err == nil {
		return data, contentType, nil
	}

	html, err := fetchURLHeadHTML(ctx, siteURL)
	if err != nil {
		return nil, "", err
	}
	for _, href := range extractFaviconHrefs(string(html)) {
		candidate, err := resolveURL(siteURL, href)
		if err != nil {
			continue
		}
		if data, contentType, err := fetchFaviconCandidate(ctx, candidate); err == nil {
			return data, contentType, nil
		}
	}
	return nil, "", fmt.Errorf("favicon not found")
}

func fetchFaviconCandidate(ctx context.Context, candidateURL string) ([]byte, string, error) {
	data, err := fetchURLBytes(ctx, candidateURL, "image/*,*/*", maxFaviconBytes)
	if err != nil {
		return nil, "", err
	}
	contentType := detectFaviconContentType(data, candidateURL, "")
	if contentType == "" {
		return nil, "", fmt.Errorf("not an image")
	}
	return data, contentType, nil
}

func fetchURLBytes(ctx context.Context, targetURL string, accept string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "CodeSwitch/1.0 favicon fetcher")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response too large")
	}
	return data, nil
}

func fetchURLHeadHTML(ctx context.Context, targetURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("User-Agent", "CodeSwitch/1.0 favicon fetcher")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	var data []byte
	buf := make([]byte, 8192)
	for len(data) < maxFaviconHTMLHeadBytes {
		remaining := maxFaviconHTMLHeadBytes - len(data)
		readBuf := buf
		if remaining < len(readBuf) {
			readBuf = readBuf[:remaining]
		}
		n, readErr := resp.Body.Read(readBuf)
		if n > 0 {
			data = append(data, readBuf[:n]...)
			if strings.Contains(strings.ToLower(string(data)), "</head>") {
				return data, nil
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return data, nil
			}
			return nil, readErr
		}
	}
	return data, nil
}

func extractFaviconHrefs(html string) []string {
	hrefs := []string{}
	for _, tag := range faviconLinkPattern.FindAllString(html, -1) {
		rel := strings.ToLower(extractHTMLAttr(tag, "rel"))
		if !strings.Contains(rel, "icon") {
			continue
		}
		if href := strings.TrimSpace(extractHTMLAttr(tag, "href")); href != "" {
			hrefs = append(hrefs, href)
		}
	}
	return hrefs
}

func extractHTMLAttr(tag string, name string) string {
	pattern := regexp.MustCompile(`(?is)\b` + regexp.QuoteMeta(name) + `\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
	match := pattern.FindStringSubmatch(tag)
	if len(match) == 0 {
		return ""
	}
	for i := 2; i < len(match); i++ {
		if match[i] != "" {
			return match[i]
		}
	}
	return ""
}

func resolveURL(baseURL string, href string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme")
	}
	return resolved.String(), nil
}

func detectFaviconContentType(data []byte, source string, fallback string) string {
	if len(data) == 0 {
		return ""
	}
	prefixLen := len(data)
	if prefixLen > 256 {
		prefixLen = 256
	}
	trimmed := strings.TrimSpace(string(data[:prefixLen]))
	lowerPrefix := strings.ToLower(trimmed)
	lowerSource := strings.ToLower(source)
	if strings.HasPrefix(lowerPrefix, "<svg") || strings.Contains(lowerPrefix, "<svg") || strings.HasSuffix(lowerSource, ".svg") {
		return "image/svg+xml"
	}
	detected := http.DetectContentType(data)
	if strings.HasPrefix(strings.ToLower(detected), "image/") {
		return detected
	}
	if strings.HasSuffix(lowerSource, ".ico") && isICOData(data) {
		return "image/x-icon"
	}
	return fallback
}

func isICOData(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && (data[2] == 0x01 || data[2] == 0x02) && data[3] == 0x00
}

func streamEvents(c *gin.Context, hub *services.EventHub) {
	if hub == nil {
		c.JSON(http.StatusServiceUnavailable, apiErrorResponse{
			Error: apiError{Code: "events_unavailable", Message: "event hub is not initialized"},
		})
		return
	}

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, apiErrorResponse{
			Error: apiError{Code: "stream_unsupported", Message: "streaming is not supported"},
		})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	events, cancel := hub.Subscribe(32)
	defer cancel()

	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	flusher.Flush()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-keepAlive.C:
			_, _ = c.Writer.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case event, ok := <-events:
			if !ok {
				return
			}
			payload, err := json.Marshal(event.Data)
			if err != nil {
				payload = []byte(`{"error":"failed to encode event payload"}`)
			}
			_, _ = fmt.Fprintf(c.Writer, "event: %s\n", event.Name)
			_, _ = fmt.Fprintf(c.Writer, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

func registerStaticRoutes(router *gin.Engine, staticDir string) {
	indexPath := filepath.Join(staticDir, "index.html")
	staticReady := false

	if info, err := os.Stat(indexPath); err == nil && !info.IsDir() {
		staticReady = true
	}

	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/healthz" || c.Request.URL.Path == "/readyz" {
			c.JSON(http.StatusNotFound, apiErrorResponse{
				Error: apiError{Code: "not_found", Message: "route not found"},
			})
			return
		}

		if !staticReady {
			c.Header("Content-Type", "text/plain; charset=utf-8")
			c.String(http.StatusServiceUnavailable,
				"Frontend build not found at %s.\nRun `cd frontend && npm install && npm run build` before starting the web UI.",
				staticDir,
			)
			return
		}

		relativePath := strings.TrimPrefix(filepath.Clean(c.Request.URL.Path), "/")
		if relativePath != "" && relativePath != "." {
			target := filepath.Join(staticDir, relativePath)
			if info, err := os.Stat(target); err == nil && !info.IsDir() {
				setStaticAssetCacheHeaders(c, relativePath)
				c.File(target)
				return
			}
		}

		c.Header("Cache-Control", "no-store")
		c.File(indexPath)
	})
}

func setStaticAssetCacheHeaders(c *gin.Context, relativePath string) {
	if strings.HasPrefix(relativePath, "assets/") {
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	c.Header("Cache-Control", "public, max-age=3600")
}
