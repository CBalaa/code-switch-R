package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const codexRelayKeyHeader = "X-Code-Switch-Key"

const relayKeyIDContextKey = "relay_key_id"
const relayKeyNameContextKey = "relay_key_name"
const relayUserIDContextKey = "relay_user_id"
const providerPoolIDContextKey = "provider_pool_id"

func (prs *ProviderRelayService) claudeRelayAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if prs.codexRelayKeys == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "relay key service is unavailable"})
			c.Abort()
			return
		}

		candidate, source := extractClaudeRelayKeyWithSource(c.Request)
		match, err := prs.codexRelayKeys.ValidateKeyMatch(candidate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate relay key"})
			c.Abort()
			return
		}
		if match == nil {
			logRejectedRelayKey("claude", c, candidate, source)
			c.Header("WWW-Authenticate", "Bearer realm=\"code-switch-claude\"")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid claude relay api key",
			})
			c.Abort()
			return
		}
		if statusCode, ok := prs.rejectInvalidRelayOwner(match); !ok {
			if statusCode == http.StatusForbidden {
				c.JSON(http.StatusForbidden, gin.H{"error": "relay key owner is disabled"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "relay key owner is invalid"})
			}
			c.Abort()
			return
		}
		c.Set(relayKeyIDContextKey, match.ID)
		c.Set(relayUserIDContextKey, match.OwnerUserID)
		c.Set(relayKeyNameContextKey, match.Name)
		c.Set("relay_key_pool_bindings", match.PoolBindings)

		// 清理客户端传来的认证头，避免泄漏 relay key 给上游
		c.Request.Header.Del("Authorization")
		c.Request.Header.Del("X-Api-Key")
		c.Request.Header.Del("x-api-key")
		c.Request.Header.Del(codexRelayKeyHeader)

		c.Next()
	}
}

func extractClaudeRelayKey(req *http.Request) string {
	key, _ := extractClaudeRelayKeyWithSource(req)
	return key
}

func extractClaudeRelayKeyWithSource(req *http.Request) (string, string) {
	if req == nil {
		return "", ""
	}

	if key := strings.TrimSpace(req.Header.Get("x-api-key")); key != "" {
		return key, "x-api-key"
	}
	if key := strings.TrimSpace(req.Header.Get(codexRelayKeyHeader)); key != "" {
		return key, codexRelayKeyHeader
	}
	if auth := strings.TrimSpace(req.Header.Get("Authorization")); auth != "" {
		return extractBearerToken(auth), "Authorization"
	}

	return "", ""
}

func (prs *ProviderRelayService) codexRelayAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if prs.codexRelayKeys == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "codex relay key service is unavailable"})
			c.Abort()
			return
		}

		candidate, source := extractCodexRelayKeyWithSource(c.Request)
		match, err := prs.codexRelayKeys.ValidateKeyMatch(candidate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate codex relay key"})
			c.Abort()
			return
		}
		if match == nil {
			logRejectedRelayKey("codex", c, candidate, source)
			c.Header("WWW-Authenticate", "Bearer realm=\"code-switch-codex\"")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid codex relay api key",
			})
			c.Abort()
			return
		}
		if statusCode, ok := prs.rejectInvalidRelayOwner(match); !ok {
			if statusCode == http.StatusForbidden {
				c.JSON(http.StatusForbidden, gin.H{"error": "relay key owner is disabled"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "relay key owner is invalid"})
			}
			c.Abort()
			return
		}
		c.Set(relayKeyIDContextKey, match.ID)
		c.Set(relayUserIDContextKey, match.OwnerUserID)
		c.Set(relayKeyNameContextKey, match.Name)
		c.Set("relay_key_pool_bindings", match.PoolBindings)

		// 上游认证由 provider 配置重新注入，避免把客户端传来的 relay key 转发出去。
		c.Request.Header.Del("Authorization")
		c.Request.Header.Del(codexRelayKeyHeader)
		c.Request.Header.Del("X-API-Key")
		c.Request.Header.Del("x-api-key")

		c.Next()
	}
}

func (prs *ProviderRelayService) rejectInvalidRelayOwner(match *CodexRelayKeyMatch) (int, bool) {
	if match == nil {
		return http.StatusUnauthorized, false
	}
	ownerID := strings.TrimSpace(match.OwnerUserID)
	users := NewUserStore()
	count, err := users.CountUsers()
	if err != nil {
		fmt.Printf("[WARN] relay owner check failed: %v\n", err)
		return http.StatusUnauthorized, false
	}
	if count == 0 {
		return http.StatusOK, true
	}
	if ownerID == "" {
		return http.StatusUnauthorized, false
	}
	user, err := users.GetEnabledUserByID(ownerID)
	if err != nil {
		return http.StatusForbidden, false
	}
	if user == nil {
		return http.StatusUnauthorized, false
	}
	return http.StatusOK, true
}

func extractCodexRelayKey(req *http.Request) string {
	key, _ := extractCodexRelayKeyWithSource(req)
	return key
}

func extractCodexRelayKeyWithSource(req *http.Request) (string, string) {
	if req == nil {
		return "", ""
	}

	if key := strings.TrimSpace(req.Header.Get(codexRelayKeyHeader)); key != "" {
		return key, codexRelayKeyHeader
	}
	if key := strings.TrimSpace(req.Header.Get("X-API-Key")); key != "" {
		return key, "X-API-Key"
	}
	if auth := strings.TrimSpace(req.Header.Get("Authorization")); auth != "" {
		return extractBearerToken(auth), "Authorization"
	}

	return "", ""
}

func logRejectedRelayKey(kind string, c *gin.Context, candidate string, source string) {
	candidate = strings.TrimSpace(candidate)
	hashPrefix := ""
	suffix := ""
	if candidate != "" {
		sum := sha256.Sum256([]byte(candidate))
		hashPrefix = hex.EncodeToString(sum[:])[:16]
		if len(candidate) <= 4 {
			suffix = candidate
		} else {
			suffix = candidate[len(candidate)-4:]
		}
	}
	clientIP := ""
	path := ""
	userAgent := ""
	if c != nil {
		clientIP = c.ClientIP()
		if c.Request != nil {
			path = c.Request.URL.Path
			userAgent = c.Request.UserAgent()
		}
	}
	fmt.Printf("[WARN] invalid %s relay key: source=%s len=%d sha256=%s suffix=%s ip=%s path=%s ua=%q\n",
		kind, source, len(candidate), hashPrefix, suffix, clientIP, path, userAgent)
}

func relayKeyIDFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(relayKeyIDContextKey)
	if !ok {
		return ""
	}
	keyID, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(keyID)
}

func relayKeyNameFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(relayKeyNameContextKey)
	if !ok {
		return ""
	}
	name, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(name)
}

func relayUserIDFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(relayUserIDContextKey)
	if !ok {
		return ""
	}
	userID, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(userID)
}

func relayKeyPoolBindingsFromContext(c *gin.Context) map[string]string {
	if c == nil {
		return nil
	}
	value, ok := c.Get("relay_key_pool_bindings")
	if !ok {
		return nil
	}
	bindings, ok := value.(map[string]string)
	if !ok {
		return nil
	}
	return bindings
}

func extractBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[len("Bearer "):])
	}

	return value
}
