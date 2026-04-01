package main

import (
	"codeswitch/services"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	adminSetupTokenEnv     = "CODE_SWITCH_SETUP_TOKEN"
	adminPublicOriginEnv   = "CODE_SWITCH_PUBLIC_ORIGIN"
	adminTrustedProxiesEnv = "CODE_SWITCH_TRUSTED_PROXIES"
)

type adminSecurity struct {
	setupToken     string
	publicOrigin   string
	trustedProxies []netip.Prefix
	rateLimiter    *services.AdminRateLimiter
}

func newAdminSecurity(appSettings *services.AppSettingsService) (*adminSecurity, error) {
	publicOrigin, err := normalizeOrigin(strings.TrimSpace(os.Getenv(adminPublicOriginEnv)))
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", adminPublicOriginEnv, err)
	}

	trustedProxies, err := parseTrustedProxies(strings.TrimSpace(os.Getenv(adminTrustedProxiesEnv)))
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", adminTrustedProxiesEnv, err)
	}

	security := &adminSecurity{
		setupToken:     strings.TrimSpace(os.Getenv(adminSetupTokenEnv)),
		publicOrigin:   publicOrigin,
		trustedProxies: trustedProxies,
		rateLimiter:    services.NewAdminRateLimiter(),
	}

	config, err := appSettings.GetAdminAuthConfig()
	if err != nil {
		return nil, err
	}

	if !adminConfigInitialized(config) {
		if security.setupToken == "" {
			security.setupToken, err = generateAdminSetupToken()
			if err != nil {
				return nil, err
			}
			log.Printf("admin setup token (save it before first initialization): %s", security.setupToken)
		} else {
			log.Printf("admin setup token loaded from %s", adminSetupTokenEnv)
		}
	}

	return security, nil
}

func adminSecurityMiddleware(security *adminSecurity) gin.HandlerFunc {
	return func(c *gin.Context) {
		applyAdminSecurityHeaders(c, security)

		switch c.Request.URL.Path {
		case "/healthz", "/readyz":
			c.Next()
			return
		}

		if security == nil || security.isLocalClient(c.Request) || security.isSecureRequest(c.Request) {
			c.Next()
			return
		}

		writeAdminSecurityError(
			c,
			http.StatusForbidden,
			"https_required",
			"public admin access requires HTTPS via a trusted reverse proxy or direct local access",
		)
		c.Abort()
	}
}

func requireTrustedOrigin(security *adminSecurity) gin.HandlerFunc {
	return func(c *gin.Context) {
		if security == nil || security.isAllowedOrigin(c.Request) {
			c.Next()
			return
		}

		writeAdminSecurityError(
			c,
			http.StatusForbidden,
			"invalid_origin",
			"cross-site admin requests are not allowed",
		)
		c.Abort()
	}
}

func applyAdminSecurityHeaders(c *gin.Context, security *adminSecurity) {
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	c.Header(
		"Content-Security-Policy",
		"default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'self'; connect-src 'self';",
	)

	if security != nil && security.isSecureRequest(c.Request) {
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func writeAdminSecurityError(c *gin.Context, status int, code string, message string) {
	if strings.HasPrefix(c.Request.URL.Path, "/api/") {
		c.JSON(status, apiErrorResponse{
			Error: apiError{Code: code, Message: message},
		})
		return
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(status, message)
}

func (s *adminSecurity) isSetupAllowed(r *http.Request, providedToken string) bool {
	if s == nil {
		return true
	}
	if s.isLocalClient(r) {
		return true
	}

	providedToken = strings.TrimSpace(providedToken)
	if providedToken == "" || s.setupToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(s.setupToken)) == 1
}

func (s *adminSecurity) rateLimitSubject(r *http.Request) string {
	clientIP := s.actualClientIP(r)
	if clientIP.IsValid() {
		return clientIP.String()
	}

	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	if host != "" {
		return host
	}

	return "unknown"
}

func (s *adminSecurity) isAllowedOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}

	normalizedOrigin, err := normalizeOrigin(origin)
	if err != nil {
		return false
	}

	if expectedOrigin := s.effectiveOrigin(r); expectedOrigin != "" && normalizedOrigin == expectedOrigin {
		return true
	}

	return s.publicOrigin != "" && normalizedOrigin == s.publicOrigin
}

func (s *adminSecurity) isSecureRequest(r *http.Request) bool {
	switch s.effectiveScheme(r) {
	case "https", "wss":
		return true
	default:
		return false
	}
}

func (s *adminSecurity) isLocalClient(r *http.Request) bool {
	clientIP := s.actualClientIP(r)
	return clientIP.IsValid() && clientIP.IsLoopback()
}

func (s *adminSecurity) effectiveOrigin(r *http.Request) string {
	host := s.effectiveHost(r)
	if host == "" {
		return ""
	}

	scheme := s.effectiveScheme(r)
	if scheme == "" {
		return ""
	}

	return strings.ToLower(scheme) + "://" + strings.ToLower(host)
}

func (s *adminSecurity) effectiveScheme(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.TLS != nil {
		return "https"
	}

	if s.isTrustedProxy(s.directRemoteIP(r)) {
		if proto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			return strings.ToLower(proto)
		}
	}

	return "http"
}

func (s *adminSecurity) effectiveHost(r *http.Request) string {
	if r == nil {
		return ""
	}

	if s.isTrustedProxy(s.directRemoteIP(r)) {
		if host := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); host != "" {
			return host
		}
	}

	return strings.TrimSpace(r.Host)
}

func (s *adminSecurity) actualClientIP(r *http.Request) netip.Addr {
	directIP := s.directRemoteIP(r)
	if !s.isTrustedProxy(directIP) {
		return directIP
	}

	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}
		if ip, err := netip.ParseAddr(candidate); err == nil {
			return ip
		}
	}

	if candidate := strings.TrimSpace(r.Header.Get("X-Real-IP")); candidate != "" {
		if ip, err := netip.ParseAddr(candidate); err == nil {
			return ip
		}
	}

	return directIP
}

func (s *adminSecurity) directRemoteIP(r *http.Request) netip.Addr {
	if r == nil {
		return netip.Addr{}
	}

	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" {
		return netip.Addr{}
	}

	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

func (s *adminSecurity) isTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range s.trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func adminConfigInitialized(config services.AdminAuthConfig) bool {
	return strings.TrimSpace(config.Username) != "" && strings.TrimSpace(config.PasswordHash) != ""
}

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}

	if value == "" {
		return prefixes, nil
	}

	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
			continue
		}

		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
}

func normalizeOrigin(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("origin must include scheme and host")
	}

	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func generateAdminSetupToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate admin setup token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func firstHeaderValue(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return ""
}

func rejectWhenRateLimited(c *gin.Context, security *adminSecurity, scope string) (string, bool) {
	if security == nil || security.rateLimiter == nil {
		return "", false
	}

	subject := security.rateLimitSubject(c.Request)
	allowed, retryAfter := security.rateLimiter.Allow(scope, subject)
	if allowed {
		return subject, false
	}

	retryAfterSeconds := int(retryAfter / time.Second)
	if retryAfter%time.Second != 0 {
		retryAfterSeconds++
	}
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	c.Header("Retry-After", fmt.Sprintf("%d", retryAfterSeconds))
	c.JSON(http.StatusTooManyRequests, apiErrorResponse{
		Error: apiError{
			Code:    "rate_limited",
			Message: fmt.Sprintf("too many failed %s attempts, retry after %d seconds", scope, retryAfterSeconds),
		},
	})
	c.Abort()
	return subject, true
}

func recordRateLimitFailure(security *adminSecurity, scope string, subject string) {
	if security == nil || security.rateLimiter == nil || strings.TrimSpace(subject) == "" {
		return
	}
	security.rateLimiter.RecordFailure(scope, subject)
}

func recordRateLimitSuccess(security *adminSecurity, scope string, subject string) {
	if security == nil || security.rateLimiter == nil || strings.TrimSpace(subject) == "" {
		return
	}
	security.rateLimiter.RecordSuccess(scope, subject)
}

func adminSessionCookieSecure(r *http.Request, security *adminSecurity) bool {
	if security != nil {
		return security.isSecureRequest(r)
	}
	return r != nil && r.TLS != nil
}
