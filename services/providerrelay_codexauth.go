package services

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const codexRelayKeyHeader = "X-Code-Switch-Key"

func (prs *ProviderRelayService) codexRelayAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if prs.codexRelayKeys == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "codex relay key service is unavailable"})
			c.Abort()
			return
		}

		if _, err := prs.codexRelayKeys.EnsureDefaultKey(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize codex relay keys"})
			c.Abort()
			return
		}

		candidate := extractCodexRelayKey(c.Request)
		ok, err := prs.codexRelayKeys.ValidateKey(candidate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate codex relay key"})
			c.Abort()
			return
		}
		if !ok {
			c.Header("WWW-Authenticate", "Bearer realm=\"code-switch-codex\"")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid codex relay api key",
			})
			c.Abort()
			return
		}

		// 上游认证由 provider 配置重新注入，避免把客户端传来的 relay key 转发出去。
		c.Request.Header.Del("Authorization")
		c.Request.Header.Del(codexRelayKeyHeader)
		c.Request.Header.Del("X-API-Key")
		c.Request.Header.Del("x-api-key")

		c.Next()
	}
}

func extractCodexRelayKey(req *http.Request) string {
	if req == nil {
		return ""
	}

	if key := strings.TrimSpace(req.Header.Get(codexRelayKeyHeader)); key != "" {
		return key
	}
	if key := strings.TrimSpace(req.Header.Get("X-API-Key")); key != "" {
		return key
	}
	if auth := strings.TrimSpace(req.Header.Get("Authorization")); auth != "" {
		return extractBearerToken(auth)
	}

	return ""
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
